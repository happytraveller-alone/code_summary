/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    ctrlrxr.c

Abstract:

    This module implements the functions of the IPv6 Control Receiver module.

Author:

    Dave Thaler (dthaler) 4-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "ctrlrxr.tmh"
#include "ctrlv6.h"


IP_RECEIVE_DEMUX Icmpv6Demux = { Icmpv6ReceiveDatagrams,
                                 Icmpv6ReceiveControlMessage };

VOID
Icmpv6pHandleEchoReplyAndError(
    IN ULONG IcmpType,
    IN ULONG IcmpCode,
    IN ULONG IcmpParameter,
    IN PIP_REQUEST_CONTROL_DATA Args,
    IN ICMPV6_MESSAGE *ErrorIcmpv6
    );

VOID
Icmpv6pHandleEchoRequest(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Validate and Process an ICMPv6 Echo Request Message.

Arguments:

    Icmpv6 - Supplies the parsed ICMPv6 header.

    The following fields in 'Control' are relevant...

    NetBufferList - Supplies an ICMPv6 Echo Request packet,
        with the packet offset at the start of the ICMPv6 header.

    Interface - Supplies the interface over which the packet was received.

    LocalAddress - Supplies the destination address of the packet.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    IN6_ADDR Destination;
    NTSTATUS Status;
    PIP_PATH Path;
    NL_REQUEST_GENERATE_CONTROL_MESSAGE SendArgs = {0};
    PIP_LOCAL_ADDRESS SourceAddress = Control->DestLocalAddress;
    PIP_INTERFACE SourceInterface = SourceAddress->Interface;
    PUCHAR Buffer;
    SIZE_T BytesCopied;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;

    Control->NetBufferList->Status = STATUS_SUCCESS;    
    
    //
    // Take our reply's destination address from the source address
    // of the incoming packet.
    //
    // Note that the specs specifically say that we're not to reverse
    // the path on source routed packets.  Just reply directly.
    //
    // IPv6HeaderReceive should protect us from replying to most forms
    // of bogus addresses.  We ASSERT this in checked builds.
    //

    //
    // Copy out the remote address since we'll overwrite the IP header
    // when sending.
    //
    RtlCopyMemory(
        &Destination, 
        Control->SourceAddress.Address,
        sizeof(IN6_ADDR));
    ASSERT(!IppIsInvalidSourceAddress(&Ipv6Global, (PUCHAR) &Destination));

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
               "IPNG: Received ICMPv6 echo request from %!IPV6!\n", 
               (UCHAR*)&Destination);

    if (NL_ADDRESS_TYPE(SourceAddress) == NlatMulticast) {
        //
        // Do not reply to multicast or broadcast requests - drop packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv6 echo request failed: "
                   "Multicast source address %!IPV6!\n", 
                   (PUCHAR) NL_ADDRESS(SourceAddress));
        return;
    }  
    
    //
    // Get the reply route to the destination.
    // Under normal circumstances, the reply will go out
    // the incoming interface. RouteToDestination
    // will figure out the appropriate ScopeId.
    //
    Status = IppRouteToDestinationInternal(
        SourceInterface->Compartment,
        (PUCHAR)&Destination,
        SourceInterface,
        (NL_ADDRESS_TYPE(SourceAddress) == NlatUnicast)
            ? SourceAddress
            : NULL, 
        &Path);
    if (!NT_SUCCESS(Status)) {
        //
        // No route - drop the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv6 echo request failed: "
                   "No route to destination %!IPV6!\n", 
                   (UCHAR*)&Destination);
        return;
    }

    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //
    NetioAdvanceNetBuffer(Control->NetBufferList->FirstNetBuffer, 
                          sizeof(ICMPV6_MESSAGE));
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += 
        sizeof(ICMPV6_MESSAGE);

    RtlZeroMemory(&SendArgs, sizeof(SendArgs));    

    //
    // Copy the echo data to a new NetBufferList since stale data interferes 
    // with inspection modules.
    //
    
    Status =
        IppNetAllocate(
            &SendArgs.NetBufferList,
            &Buffer,
            (IP_EXTRA_DATA_BACKFILL + sizeof(IPV6_HEADER) +          
             sizeof(ICMPV6_MESSAGE)),
            NetBuffer->DataLength);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(
            NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
            "IPNG: IPv6 echo request failed: "
            "Failed to allocate echo reply packet.\n");
        return;
    }

    RtlCopyMdlToBuffer(
        NetBuffer->MdlChain,
        NetBuffer->DataOffset,
        (PUCHAR) Buffer,
        NetBuffer->DataLength,
        &BytesCopied);
    ASSERT(BytesCopied == NetBuffer->DataLength);                

    //
    // Take our reply's source address from the receiving address,
    // or use the best source address for this destination
    // if we don't have a receiving address.
    //
    SendArgs.NlLocalAddress.LocalAddress =
        (PNL_LOCAL_ADDRESS) Path->SourceAddress;
    SendArgs.RemoteAddress = (PUCHAR)&Destination;
    SendArgs.RemoteScopeId = scopeid_unspecified;
    SendArgs.Type = ICMP6_ECHO_REPLY;
    SendArgs.Parameter = Icmpv6->icmp6_data32[0]; 

    //
    // We could speed this up a bit by creating the ICMPv6 header ourselves
    // since we can compute the checksum delta, rather than recomputing
    // the whole checksum in Icmpv6pSend.  For now, we'll just do it the
    // simplest way.
    //
    IppSendControl(FALSE, &Ipv6Global, &SendArgs);

    IppDereferencePath(Path);
}

VOID
Icmpv6pHandleError(
    IN PICMPV6_MESSAGE Icmpv6,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Generic ICMPv6 error processing.  
    This takes ownership of the packet, so the caller is never
    responsible for completing it.

    Compare ICMPv6ErrorReceive in the XP IPv6 stack.

Arguments:

    Icmpv6 - Supplies the ICMP Header from the packet.

    Control - Supplies the IP packet data.

Return Value:

    None.

--*/
{
    PNLC_RECEIVE_CONTROL_MESSAGE ControlMessage;
    NLC_RECEIVE_CONTROL_MESSAGE ControlBuffer;
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    PNET_BUFFER NetBuffer = NetBufferList->FirstNetBuffer;
    IPV6_HEADER *Ipv6Header;
    IPV6_HEADER Ipv6HeaderStorage;
    PIP_RECEIVE_DEMUX Demux = NULL;
    
    //
    // First mark the packet as an ICMP error.
    // This will inhibit any generation of ICMP errors
    // as a result of this packet.
    //
    Control->IcmpError = TRUE;
    //
    // TODO: 
    // This is optimization for firewall control message hooks.
    // Need to be removed when WFP packet history
    // is properly implemented.
    //
    Control->NlcReceiveDatagram.IsIcmpError = TRUE;

    NetBufferList->Status = STATUS_SUCCESS;

    //
    // Store the copy in case we need to deliver
    // the packet to RAW.
    //
    RtlCopyMemory(
        &ControlBuffer, 
        &Control->NlcControlMessage, 
        sizeof(ControlBuffer));

    //
    // Remove the ICMP header and add the header size to the
    // NetworkLayerHeadersSize so that it can be retreated on the completion
    // path. 
    //
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV6_MESSAGE));
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += 
        sizeof(ICMPV6_MESSAGE);

    //
    // Look at the IPv6 header following the ICMP header to determine the
    // next header value. 
    //
    if (NetBuffer->DataLength < sizeof(IPV6_HEADER)) {
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Dropping ICMPv6 error with truncated IP header: "
                   "length=%d expected=%d\n", 
                   NetBuffer->DataLength, sizeof(IPV6_HEADER));
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        goto Done;
    }
    
    Ipv6Header = NetioGetDataBuffer(NetBuffer, 
                                    sizeof(IPV6_HEADER),
                                    &Ipv6HeaderStorage,
                                    __builtin_alignof(IN6_ADDR), 
                                    0);
        
    NetioAdvanceNetBuffer(NetBuffer, sizeof(IPV6_HEADER));
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(IPV6_HEADER);

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
               "IPNG: Received ICMPv6 error: type %d code %d\n", 
               Icmpv6->icmp6_type, Icmpv6->icmp6_code);
    
    //
    // Do network layer processing of the control message. For instance, for a
    // ICMP6_PACKET_TOO_BIG message, we need to update the path MTU. The errors
    // still need to be sent to the upper layer protocols which is done below. 
    //
    switch (Icmpv6->icmp6_type) {
    case ICMP6_PACKET_TOO_BIG:
        Ipv6pUpdatePathMtu(
            Control->DestLocalAddress, 
            Icmpv6, 
            Ipv6Header);
        break;
    default:
        break;
    }
    
    //
    // Send the control message to the network layer clients. 
    //
    ControlMessage = &Control->NlcControlMessage;

    ControlMessage->Type = Icmpv6->icmp6_type;
    ControlMessage->Code = Icmpv6->icmp6_code;
    ControlMessage->Parameter = Icmpv6->icmp6_data32[0];
    ControlMessage->NetBufferList = NetBufferList;
    ControlMessage->RemoteAddress = (PVOID)&Ipv6Header->DestinationAddress;
    ControlMessage->RemoteScopeId = IppGetExternalScopeId(
        Control->DestLocalAddress->Interface,
        ControlMessage->RemoteAddress);
    ControlMessage->LocalAddress = (PNL_LOCAL_ADDRESS)
        Control->DestLocalAddress;
    ControlMessage->NextHeaderValue = Ipv6Header->NextHeader;
    
    //
    // Store the original source address of the ICMP packet.
    //
    ControlMessage->SourceAddress =
        Control->SourceAddress.Address;

    //
    // Store the original source address of the ICMP packet.
    //
    ControlMessage->SourceAddress =
        Control->SourceAddress.Address;

    while (ControlMessage->NextHeaderValue != IPPROTO_NONE) {
        IppFindNlClient(
            &Ipv6Global,
            ControlMessage->NextHeaderValue,
            ControlMessage->NetBufferList,
            &Demux);
        if (Demux == NULL) {
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: No handler for ICMPv6 error next header %u\n",
                       ControlMessage->NextHeaderValue);
            NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
            goto Done;
        }
        
        IppDeliverControlToProtocol(Demux, ControlMessage);

        ASSERT(ControlMessage->NetBufferList == NULL ||
               ((ControlMessage->NetBufferList == NetBufferList) &&
                (ControlMessage->NetBufferList->Status !=
                 STATUS_PENDING)));

        if (ControlMessage->NetBufferList == NULL ||
            ControlMessage->NetBufferList->Status != STATUS_MORE_ENTRIES) {
            goto Done;
        }
    }

Done:
    if (Control->NetBufferList != NULL) {
        if (Control->NetBufferList->Status == STATUS_SUCCESS) {
            NetioDereferenceNetBufferList(Control->NetBufferList, FALSE);
            Control->NetBufferList = NULL;
        } else {
            NetioRetreatNetBuffer(
                Control->NetBufferList->FirstNetBuffer, 
                Control->NlcReceiveDatagram.NetworkLayerHeadersSize -
                    ControlBuffer.NetworkLayerHeadersSize,
                0);
            RtlCopyMemory(
                &Control->NlcControlMessage, 
                &ControlBuffer, 
                sizeof(ControlBuffer));
        }
    }
}

VOID
NTAPI
Icmpv6ReceiveDatagrams(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:
    
    This routine handles ICMPv6 messages on the receive path. 

Arguments:

    Args - Supplies the packet received. 

Return Value:

    None.

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PNET_BUFFER NetBuffer;
    ICMPV6_MESSAGE Buffer, *Icmpv6;
    UINT16 Checksum;
    IP_FILTER_ACTION Action;
    UINT8 Type;
    
    for (; Args != NULL; Args = Args->Next) {
        //
        // Each NET_BUFFER_LIST must contain exactly one NET_BUFFER.
        //
        NetBuffer = Args->NetBufferList->FirstNetBuffer;
        ASSERT((NetBuffer != NULL) && (NetBuffer->Next == NULL));

        //
        // As in XP, rather than using an interlocked operation, we
        // accept inaccuracies to get higher performance.
        //
        Ipv6Global.IcmpStatistics.InMessages++;

        //
        // Verify checksum.
        //
        Checksum = IppChecksumDatagram(
            NetBuffer,
            NetBuffer->DataLength,                  // Data Length.
            Args->NlcReceiveDatagram.RemoteAddress, // Source.
            NL_ADDRESS(Args->DestLocalAddress),     // Destination.
            sizeof(IN6_ADDR),                       // Address Length.
            IPPROTO_ICMPV6,                         // Protocol ID.
            0);                                     // Pseudo Header Checksum.
          
        if (Checksum != 0xffff) {
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Checksum failure for ICMPv6 packet\n");
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            Ipv6Global.IcmpStatistics.InErrors++;
            continue;
        }

        //
        // Parse the ICMPv6 Header.
        //
        if (NetBuffer->DataLength < sizeof(ICMPV6_MESSAGE)) {
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Received truncated ICMPv6 header: "
                       "length=%d expeceted=%d\n", 
                       NetBuffer->DataLength, sizeof(ICMPV6_MESSAGE));
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            Ipv6Global.IcmpStatistics.InErrors++;
            continue;
        }
        Icmpv6 = NetioGetDataBuffer(NetBuffer, 
                                    sizeof(ICMPV6_MESSAGE), 
                                    &Buffer,
                                    __builtin_alignof(ICMPV6_MESSAGE), 
                                    0);

        Type = Icmpv6->Header.Type;
        Ipv6Global.IcmpStatistics.InTypeCount[Type]++;

        Action = IppInspectLocalDatagramsIn(
            IPPROTO_IPV6,
            (PNL_LOCAL_ADDRESS)Args->DestLocalAddress,
            Args->NlcReceiveDatagram.RemoteAddress,
            (PNL_INTERFACE) Args->SourcePointer->Interface,            
            (Args->IsOriginLocal ? IFI_UNSPECIFIED :
             Args->SourceSubInterface->Index),
            Args->NlcReceiveDatagram.Loopback,
            IPPROTO_ICMPV6,
            (PTRANSPORT_DATA) &Icmpv6->Header.Type,
            Args->NlcReceiveDatagram.NetworkLayerHeadersSize,
            0,
            Icmpv6Demux.LocalEndpoint,
            &Args->NlcReceiveDatagram,
            Args->NetBufferList);
        if (Action >= IpFilterDrop) {
            if ((Action == IpFilterDrop) || 
                (Action == IpFilterDropAndSendIcmp)) {
                Ipv6Global.
                    PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                    InFilterDrops++;
                NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Inspection point dropped ICMPv6 packet: "
                           "Source %!IPV6! destination %!IPV6!\n", 
                           Args->NlcReceiveDatagram.RemoteAddress,
                           NL_ADDRESS(Args->DestLocalAddress));
                
                Args->NetBufferList->Status = STATUS_FWP_DROP_NOICMP;

                if ((Action == IpFilterDropAndSendIcmp) &&
                    !ICMP6_ISTYPEERROR(Type)) {
                    Args->NetBufferList->Status = STATUS_ACCESS_DENIED;  
                }
            } else {
                ASSERT(Action == IpFilterAbsorb);
            }            
            continue;
        }

        //
        // We have a separate routine to handle error messages.
        //
        if ((Type & ICMP6_INFOMSG_MASK) == 0) {
            Icmpv6pHandleError(Icmpv6, Args);
            continue;
        }

        switch (Type) {
        case ND_ROUTER_SOLICIT:
            Ipv6pHandleRouterSolicitation(Icmpv6, Args);
            break;
            
        case ND_ROUTER_ADVERT:
            Ipv6pHandleRouterAdvertisement(Icmpv6, Args);
            break;

        case ND_NEIGHBOR_SOLICIT:
            Ipv6pHandleNeighborSolicitation(Icmpv6, Args);
            break;

        case ND_NEIGHBOR_ADVERT:
            Ipv6pHandleNeighborAdvertisement(Icmpv6, Args);
            break;

        case ND_REDIRECT:
            Ipv6pHandleRedirect(Icmpv6, Args);
            break;

        case ICMP6_ECHO_REQUEST:
            Icmpv6pHandleEchoRequest(Icmpv6, Args);
            break;

        case ICMP6_ECHO_REPLY:
            Icmpv6pHandleEchoReplyAndError(Icmpv6->icmp6_type,
                                           Icmpv6->icmp6_code,
                                           Icmpv6->icmp6_pptr,
                                           Args,
                                           NULL);
            break;
            
        case ICMP6_MEMBERSHIP_QUERY:
            Ipv6pHandleMldQuery(Args);
            break;

        case ICMP6_MEMBERSHIP_REPORT:
            Ipv6pHandleMldReport(Args);
            break;

        default:
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Received unknown ICMPv6 message %u\n", 
                       Type);
            Args->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;                      
            break;
        }
    }    
}

VOID
NTAPI
Icmpv6ReceiveControlMessage(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    PNLC_RECEIVE_CONTROL_MESSAGE Control = (PNLC_RECEIVE_CONTROL_MESSAGE) Args;
    ICMPV6_MESSAGE Icmpv6Storage;
    ICMPV6_MESSAGE *ErrorIcmpv6;
    PNET_BUFFER NetBuffer;

    
    Control->NetBufferList->Status = STATUS_SUCCESS;
    NetBuffer = Control->NetBufferList->FirstNetBuffer;
    
    if (NetBuffer->DataLength < sizeof(ICMPV6_MESSAGE)) {
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE,
                   "IPNG: Dropping ICMPv6 error with truncated encapsulated"
                   "ICMPv6 header\n");
        //
        // Make this packet avaiable to RAW sockets.
        //
        Control->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    ErrorIcmpv6 = NetioGetDataBuffer(NetBuffer,
                                     sizeof(ICMPV6_MESSAGE),
                                     &Icmpv6Storage,
                                     __builtin_alignof(ICMPV6_MESSAGE),
                                     0);
    //
    // Only if this is an echo request process, otherwise continue.
    //
    if (ErrorIcmpv6->icmp6_type == ICMP6_ECHO_REQUEST &&
        ErrorIcmpv6->icmp6_code == 0) {
        Icmpv6pHandleEchoReplyAndError(Control->Type,
                                       Control->Code,
                                       Control->Parameter,
                                       (PIP_REQUEST_CONTROL_DATA) Control,
                                       ErrorIcmpv6);
    } else {
        Control->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
    }
}



VOID
Icmpv6pHandleEchoReplyAndError(
    IN ULONG IcmpType,
    IN ULONG IcmpCode,
    IN ULONG IcmpParameter,
    IN PIP_REQUEST_CONTROL_DATA Args,
    IN ICMPV6_MESSAGE *ErrorIcmpv6
    )
/*++

Routine Description:

    This routine takes an echo reply and attempts to find the ICMP request
    which generated the reply and then complete the request.

Arguments:

    Icmpv6 - Supplies the ICMP Header from the packet.

    Args - Supplies the control data for the packet.

    ErrorIcmpv6 - Supplies the ICMP message that triggered a failure if any.
       This value is NULL on the success path.
    

Return Value:

    If a matching request was found STATUS_SUCCESS, otherwise
    STATUS_UNSUCCESSFUL.
        
--*/
{
    PNET_BUFFER_LIST NetBufferList = Args->NetBufferList;
    PNET_BUFFER NetBuffer = NetBufferList->FirstNetBuffer;
    PIPV6_ECHO_REQUEST_CONTEXT EchoRequest;
    PIPV6_ECHO_REQUEST_ROD EchoRod;
    PIP_PROTOCOL Protocol = &Ipv6Global;
    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime, Frequency;
    IPV6_HEADER UNALIGNED *Ipv6Header;
    SIZE_T BytesCopied;
    ULONG EchoSequence = IcmpParameter;
    BOOLEAN SuccessPath;
    NTSTATUS Status = STATUS_SUCCESS;

    Args->NetBufferList->Status = STATUS_SUCCESS;
    SuccessPath = (ErrorIcmpv6 == NULL) ? TRUE : FALSE;

    if (!SuccessPath) {
        EchoSequence = ErrorIcmpv6->icmp6_pptr;
    }
    
    KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
    EchoRequest = (PIPV6_ECHO_REQUEST_CONTEXT)
        IppFindEchoRequestForReply(Protocol->EchoRequestTable,
                                   IP_ECHO_REQUEST_TABLE_SIZE,
                                   EchoSequence);
    if (EchoRequest == NULL) {
        KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Can not find matching echo request "
                   "for icmpv6 echo reply\n");
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    //
    // If a request has been completed, do not attempt to complete it again.
    // This also matches the behavior of the old stack.
    //
    IppRemoveEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
    KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);

    //
    // Stop the timeout timer, if we get here then the timer should still be
    // running. Otherwise RequestCompleted would have been set.
    //
    KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTimerWheelLock);
    RtlCleanupTimerWheelEntry(Protocol->EchoRequestTimerTable,
                                &EchoRequest->TimerEntry);
    KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTimerWheelLock);

    KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTableLock);

    //
    // There is only 1 net buffer on 1 net buffer list for the receive path,
    // see how much data is being indicated.
    //
    ASSERT(Args->IP != NULL);
    Ipv6Header = (IPV6_HEADER UNALIGNED*) Args->IP;

    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV6_MESSAGE));
    Args->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(ICMPV6_MESSAGE);
    
    EchoRod = (PIPV6_ECHO_REQUEST_ROD) &(EchoRequest->Rod);

    if (SuccessPath && 
        EchoRequest->Rw.ReplyBufferLength <
        (EchoRequest->Rw.ReplyBufferOffset + NetBuffer->DataLength)) {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto completion;
    }
    
    RtlCopyMemory(&EchoRod->ReplyAddress,
                  &(Ipv6Header->SourceAddress),
                  sizeof(IN6_ADDR));
    EchoRod->ReplyAddressScope = Args->SourceAddress.ScopeId;

    CurrentTime = KeQueryPerformanceCounter(&Frequency);
    
    EchoRod->Ttl = Ipv6Header->HopLimit;
    EchoRod->Tos = (Ipv6Header->VersionClassFlow & IPV6_TRAFFIC_CLASS_MASK);
    EchoRod->RoundTripTime = (UINT)
        ((1000*(CurrentTime.QuadPart - EchoRequest->StartTime.QuadPart)) /
         Frequency.QuadPart);
    if (SuccessPath) {
        EchoRod->EchoDataSize = NetBuffer->DataLength;
    } else {
        EchoRod->EchoDataSize = 0;
    }
    
    //
    // For the error path we need to pull out the icmp error.
    //
    if (!SuccessPath) {
        EchoRod->IcmpErrorSet = TRUE;
        EchoRod->IcmpType = IcmpType;
        EchoRod->IcmpCode = IcmpCode;
        Status = STATUS_UNSUCCESSFUL;
    }
    
    //
    // Finally copy all the data that is needed.
    //
    if (SuccessPath && NetBuffer->DataLength > 0) {
        RtlCopyMdlToMdl(
            NetBuffer->CurrentMdl,
            NetBuffer->CurrentMdlOffset,
            EchoRequest->ReplyMdl,
            EchoRequest->Rw.ReplyBufferOffset,
            EchoRod->EchoDataSize,
            &BytesCopied);
    }
    
  completion:

    MmUnlockPages(EchoRequest->ReplyMdl);
    IoFreeMdl(EchoRequest->ReplyMdl);
    EchoRequest->ReplyMdl = NULL;
            
    EchoRod->Status = Status;
    EchoRequest->RequestCompleted = TRUE;
    
    Status = IppNotifyEchoRequestChange((PIP_ECHO_REQUEST_CONTEXT)EchoRequest,
                                        EchoRequest->Protocol);
    if (Status == STATUS_SUCCESS) {
        EchoRequest->Deleted = TRUE;
        EchoRequest->ClientNotified = TRUE;
        KeReleaseSpinLock(&EchoRequest->Lock, OldIrql);

        IppDereferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT)
                                  EchoRequest);
    } else {
        InterlockedIncrement(&Protocol->EchoFailedNotifications);
        KeReleaseSpinLock(&EchoRequest->Lock, OldIrql);

        KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
        IppInsertEchoRequest(Protocol->EchoRequestTable,
                             IP_ECHO_REQUEST_TABLE_SIZE,
                             (PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
        KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
    }
}
