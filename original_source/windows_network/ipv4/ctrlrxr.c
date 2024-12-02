/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    ctrlrxr.c

Abstract:

    This module implements the functions of the IPv4 Control Receiver module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "ctrlrxr.tmh"
#include "ctrlv4.h"

IP_RECEIVE_DEMUX Icmpv4Demux = { Icmpv4ReceiveDatagrams,
                                 Icmpv4ReceiveControlMessage };


VOID
Icmpv4pHandleEchoReplyAndError(
    IN ULONG IcmpType,
    IN ULONG IcmpCode,
    IN ULONG IcmpParameter,
    IN PIP_REQUEST_CONTROL_DATA Args,
    IN ICMPV4_MESSAGE *ErrorIcmpv4
    );


VOID
Ipv4pHandleEchoRequest(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Validate and Process an IPv4 Echo Request Message.

Arguments:

    Icmpv4 - Supplies the parsed ICMPv4 header.

    The following fields in 'Control' are relevant...

    NetBufferList - Supplies an ICMPv4 Echo Request packet,
        with the packet offset at the start of the ICMPv4 header.    

    Interface - Supplies the interface over which the packet was received.

    LocalAddress - Supplies the destination address of the packet.
    
    ReceiveRoutingHeaderOffset -- Supplies the offset of the routing header
        if present.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    PIN_ADDR Destination;
    NTSTATUS Status;
    PIP_PATH Path;
    NL_REQUEST_GENERATE_CONTROL_MESSAGE SendArgs = {0};
    PIP_LOCAL_ADDRESS SourceAddress = Control->DestLocalAddress;
    PIP_INTERFACE SourceInterface = SourceAddress->Interface;
    PUCHAR Buffer;
    SIZE_T BytesCopied;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;
    PVOID AncillaryData = NULL;
    PIP_NEXT_HOP NextHop;
    Control->NetBufferList->Status = STATUS_SUCCESS;

    //
    // Take our reply's destination address from the source address
    // of the incoming packet.
    //
    // Ipv4pValidateNetBuffer should protect us from replying to most forms
    // of bogus addresses.  We ASSERT this in checked builds.
    //

    Destination = (PIN_ADDR) Control->SourceAddress.Address;
    ASSERT(!IppIsInvalidSourceAddress(&Ipv4Global, (PUCHAR) Destination));
    
    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
               "IPNG: Received ICMPv4 echo request from %!IPV4!\n", 
               (PUCHAR) Destination); 

    if ((NL_ADDRESS_TYPE(SourceAddress) == NlatBroadcast) || 
        (NL_ADDRESS_TYPE(SourceAddress) == NlatMulticast)) {
        //
        // Do not reply to multicast or broadcast requests - drop packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv4 echo request failed: "
                   "Broadcast/Multicast source address %!IPV4!\n", 
                   (PUCHAR) NL_ADDRESS(SourceAddress));
        return;
    }  
    
    //
    // Query and create reverse routing header if packet was source routed.
    //
    if (Control->ReceiveRoutingHeaderOffset > 0) {
        ULONG AncillaryDataSize, TemporaryAncillaryDataSize;
        PWSACMSGHDR Message;
        NL_REQUEST_REVERSE_ROUTING_HEADER ReverseRequest;

        AncillaryDataSize = 
            IppGetAncillaryDataLength(
                &Ipv4Global,
                &IcmpEchoRequestSessionState,
                Control);
        ASSERT(AncillaryDataSize > 0);
        
        AncillaryData = 
            ExAllocatePoolWithTag(
                NonPagedPool,  
                AncillaryDataSize, 
                IpGenericPoolTag);
        
        if (AncillaryData == NULL) {
            NetioTrace(
                NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
                "IPNG: IPv4 echo request failed: "
                "Failed to allocate ancillary data for echo reply packet.\n");
            return;
        }

        TemporaryAncillaryDataSize = AncillaryDataSize;
        Status = 
            IppInternalQueryAncillaryData(
                &Ipv4Global,
                Control,
                &IcmpEchoRequestSessionState,                
                &TemporaryAncillaryDataSize,
                AncillaryData
                );
        if (!NT_SUCCESS(Status)) {
            NetioTrace(
                NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
                "IPNG: IPv4 echo request failed: "
                "Failed to obtain ancillary data for echo reply packet.\n");
            goto ExitFreeAncillaryData;
        }

        Message = AncillaryData;
        ASSERT(Message != NULL);
        ASSERT(Message->cmsg_type == IP_RTHDR);
        ReverseRequest.Protocol = IPPROTO_IP;
        ReverseRequest.RoutingHeader = WSA_CMSG_DATA(Message);
        Status = IpNlpReverseRoutingHeader(&ReverseRequest);
        ASSERT(NT_SUCCESS(Status));
        
        SendArgs.AncillaryData = AncillaryData;
        SendArgs.AncillaryDataLength = AncillaryDataSize;
    }
    
    //
    // Get the reply route to the destination.
    // Under normal circumstances, the reply will go out
    // the incoming interface. RouteToDestination
    // will figure out the appropriate ScopeId.
    //
    Status = IppRouteToDestinationInternal(
        SourceInterface->Compartment,
        (PUCHAR) Destination,
        SourceInterface,
        (NL_ADDRESS_TYPE(SourceAddress) == NlatUnicast) 
            ? SourceAddress
            : NULL, 
        &Path);

    if (!NT_SUCCESS(Status)) {
        //
        // Failed to find a route; Drop the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv4 echo request failed: "
                   "No route to destination %!IPV4!\n", 
                   (PUCHAR) Destination);        
        goto ExitFreeAncillaryData;
    }

    // 
    // Do not respond with broadcast echo reply messages.
    //
    NextHop = IppGetNextHopFromPath(Path);
    if (NextHop != NULL) {
        if (IppIsNextHopLocalAddress(NextHop) && 
            NL_ADDRESS_TYPE((PIP_LOCAL_ADDRESS) NextHop) == NlatBroadcast) {
            NetioTrace(
                NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
                "IPNG: IPv4 echo request failed: "
                "Echo request packet received from broadcast source.\n");
            IppDereferenceNextHop(NextHop);
            goto ExitDereferencePath;
        }
        IppDereferenceNextHop(NextHop);
    }
    
    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV4_MESSAGE));
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += 
        sizeof(ICMPV4_MESSAGE);
    
    //
    // Copy the echo data to a new NetBufferList since stale data interferes 
    // with inspection modules.
    //
    
    Status =
        IppNetAllocate(
            &SendArgs.NetBufferList,
            &Buffer,
            (IP_EXTRA_DATA_BACKFILL + sizeof(IPV4_HEADER) 
             + sizeof(ICMPV4_MESSAGE)),
            NetBuffer->DataLength);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(
            NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
            "IPNG: IPv4 echo request failed: "
            "Failed to allocate echo reply packet.\n");
        goto ExitDereferencePath;
    }

    RtlCopyMdlToBuffer(
        NetBuffer->MdlChain,
        NetBuffer->DataOffset,
        Buffer,
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
    SendArgs.RemoteAddress = (PUCHAR) Destination;
    SendArgs.RemoteScopeId = scopeid_unspecified;
    SendArgs.Type = ICMP4_ECHO_REPLY;
    SendArgs.Parameter = Icmpv4->icmp4_data32[0]; 

    //
    // We could speed this up a bit by creating the ICMPv4 header ourselves
    // since we can compute the checksum delta, rather than recomputing
    // the whole checksum in Icmpv4pSend.  For now, we'll just do it the
    // simplest way.
    //
    IppSendControl(FALSE, &Ipv4Global, &SendArgs);

ExitDereferencePath:
    IppDereferencePath(Path);
    
ExitFreeAncillaryData:
    if (AncillaryData != NULL) {
        ExFreePool(AncillaryData);
    }        
}


VOID
Ipv4pHandleTimestampRequest(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Validate and Process an IPv4 Echo Request Message.

Arguments:

    Icmpv4 - Supplies the parsed ICMPv4 header.

    The following fields in 'Control' are relevant:

    NetBufferList - Supplies an ICMPv4 Timestamp Request packet, 
        with the packet offset at the start of the ICMPv4 header.    

    Interface - Supplies the interface over which the packet was received.

    LocalAddress - Supplies the destination address of the packet.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    PIN_ADDR Destination;
    NTSTATUS Status;
    PIP_PATH Path;
    ICMPV4_TIMESTAMP_MESSAGE UNALIGNED *TimestampMessage;    
    NL_REQUEST_SEND_DATAGRAMS SendArgs = {0};
    PIP_LOCAL_ADDRESS SourceAddress = Control->DestLocalAddress;
    PIP_INTERFACE SourceInterface = SourceAddress->Interface;
    SIZE_T BytesCopied;
    UINT32 CurrentTime;
    PIP_NEXT_HOP NextHop;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;

    Control->NetBufferList->Status = STATUS_SUCCESS;

    //
    // Take our reply's destination address from the source address
    // of the incoming packet.
    //
    // Ipv4pValidateNetBuffer should protect us from replying to most forms
    // of bogus addresses.  We ASSERT this in checked builds.
    //

    Destination = (PIN_ADDR) Control->SourceAddress.Address;
    ASSERT(!IppIsInvalidSourceAddress(&Ipv4Global, (PUCHAR) Destination));

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
               "IPNG: Received ICMPv4 timestamp request from %!IPV4!\n", 
               (PUCHAR) Destination);

    if (NL_ADDRESS_TYPE(SourceAddress) != NlatUnicast) {
        //
        // Reply only to unicast requests - drop packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv4 timestamp request failed: "
                   "Non unicast source address %!IPV4!\n", 
                   (PUCHAR) NL_ADDRESS(SourceAddress));
        return;
    }    

    if (NetBuffer->DataLength < sizeof(ICMPV4_TIMESTAMP_MESSAGE)) {        
        NetioTrace(
            NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
            "IPNG: IPv4 timestamp request failed: "
            "Invalid timestamp request packet.\n");
        return;
    }
    
    //
    // Get the reply route to the destination.
    // Under normal circumstances, the reply will go out
    // the incoming interface. RouteToDestination
    // will figure out the appropriate ScopeId.
    //
    Status = 
        IppRouteToDestinationInternal(
            SourceInterface->Compartment,
            (PUCHAR) Destination,
            SourceInterface,
            SourceAddress,
            &Path);
    if (!NT_SUCCESS(Status)) {
        //
        // No route - drop the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv4 timestamp request failed: "
                   "No route to destination %!IPV4!\n", 
                   (PUCHAR) Destination);
        return;
    }

    // 
    // Do not respond with broadcast timestamp reply messages.
    //
    NextHop = IppGetNextHopFromPath(Path);
    if (NextHop != NULL) {
        if (IppIsNextHopLocalAddress(NextHop) && 
            NL_ADDRESS_TYPE((PIP_LOCAL_ADDRESS) NextHop) == NlatBroadcast) {
            NetioTrace(
                NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
                "IPNG: IPv4 timestamp request failed: "
                "Timestamp request packet received from broadcast address.\n");
            IppDereferenceNextHop(NextHop);
            IppDereferencePath(Path);  
            return;   
        }
        IppDereferenceNextHop(NextHop);
    }
    
    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV4_MESSAGE));
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += 
        sizeof(ICMPV4_MESSAGE);    

    Status=
        IppNetAllocate(
            &SendArgs.NetBufferList,
            (PUCHAR*) &TimestampMessage,
            IP_EXTRA_DATA_BACKFILL + sizeof(IPV4_HEADER),
            sizeof(ICMPV4_TIMESTAMP_MESSAGE));
    if (!NT_SUCCESS(Status)) {
        NetioTrace(
            NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
            "IPNG: IPv4 timestamp request failed: "
            "Failed to allocate timestamp reply packet.\n");
        IppDereferencePath(Path);        
        return;
    }            
    
    TimestampMessage->icmp4_ts_type = ICMP4_TIMESTAMP_REPLY;
    TimestampMessage->icmp4_ts_code = 0;
    TimestampMessage->icmp4_ts_id = Icmpv4->icmp4_id;
    TimestampMessage->icmp4_ts_seq = Icmpv4->icmp4_seq;
    TimestampMessage->icmp4_ts_cksum = 0;

    RtlCopyMdlToBuffer(
        NetBuffer->MdlChain,
        NetBuffer->DataOffset,
        &TimestampMessage->icmp4_ts_originate,
        sizeof(TimestampMessage->icmp4_ts_originate),
        &BytesCopied);
    ASSERT(BytesCopied == sizeof(TimestampMessage->icmp4_ts_originate));

    // 
    // Fill in "Receive" and "Transmit" timestamps. The timestamps are
    // identical since we transmit almost as soon as we receive.  This
    // is the same as downlevel WS03/XP.

    CurrentTime = IppGetMillisecondsFromMidnight();
    TimestampMessage->icmp4_ts_receive = CurrentTime;
    TimestampMessage->icmp4_ts_transmit = CurrentTime;

    SendArgs.DestProtocol = IPPROTO_ICMP; 
    
    //
    // Take our reply's source address from the receiving address,
    // or use the best source address for this destination
    // if we don't have a receiving address.
    //
    SendArgs.NlLocalAddress.LocalAddress =
        (PNL_LOCAL_ADDRESS) Path->SourceAddress;
    SendArgs.RemoteAddress = (PUCHAR) Destination;
    SendArgs.RemoteScopeId = scopeid_unspecified;
    SendArgs.UlChecksumOffset =
        FIELD_OFFSET(ICMPV4_TIMESTAMP_MESSAGE, icmp4_ts_cksum);
    SendArgs.PseudoHeaderChecksum = 0;

    IppSendDatagrams(&Ipv4Global, &SendArgs);
    IppUpdateIcmpOutStatistics(&Ipv4Global, ICMP4_TIMESTAMP_REPLY);
            
    IppDereferencePath(Path);
}

VOID
Ipv4pHandleAddressMaskRequest(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Validate and Process an IPv4 Mask Request Message.

Arguments:

    Icmpv4 - Supplies the parsed ICMPv4 header.

    The following fields in 'Control' are relevant:

    NetBufferList - Supplies an ICMPv4 Address Mask Request packet, 
        with the packet offset at the start of the ICMPv4 header.    

    Interface - Supplies the interface over which the packet was received.

    LocalAddress - Supplies the destination address of the packet.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    PIN_ADDR Destination;
    NTSTATUS Status;
    PIP_PATH Path;
    ICMPV4_ADDRESS_MASK_MESSAGE UNALIGNED *AddrMaskMessage;    
    NL_REQUEST_SEND_DATAGRAMS SendArgs = {0};
    PIP_LOCAL_ADDRESS SourceAddress = Control->DestLocalAddress;
    PIP_INTERFACE SourceInterface = SourceAddress->Interface;
    ULONG AddrMask = 0;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;

    Control->NetBufferList->Status = STATUS_SUCCESS;

    //
    // Take our reply's destination address from the source address
    // of the incoming packet unless it is a unspecified address.
    //
    // Ipv4pValidateNetBuffer should protect us from replying to most forms
    // of bogus addresses. We ASSERT this in checked builds.
    //
    // TODO: A router MUST NOT respond to an Address Mask Request 
    // from unspecified source and which arrives on a physical interface
    // that has associated with it multiple logical interfaces with different
    // address masks (Rfc 1812). 
    //
    
    Destination = (PIN_ADDR) Control->SourceAddress.Address;
    ASSERT(!IppIsInvalidSourceAddress(&Ipv4Global, (PUCHAR) Destination));

    NetioTrace(
        NETIO_TRACE_RECEIVE, 
        TRACE_LEVEL_VERBOSE, 
        "IPNG: Received ICMPv4 address mask request from %!IPV4!\n", 
        (PUCHAR) Destination);

    if (!SourceInterface->Compartment->Protocol->EnableAddrMaskReply) {
        //
        // Do not reply - drop packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv4 address mask request failed: "
                   "Global setting disallows reply!\n");
        return;
    }
    
    if (NetBuffer->DataLength < sizeof(ICMPV4_ADDRESS_MASK_MESSAGE)) {        
        NetioTrace(
            NETIO_TRACE_RECEIVE, 
            TRACE_LEVEL_WARNING, 
            "IPNG: IPv4 address mask request failed: "
            "Invalid address mask request packet.\n");
        return;
    }

    //
    // If the destination is unspecified, broadcast the reply.
    //
    if (IN4_IS_UNALIGNED_ADDR_UNSPECIFIED(Destination)) {
        Destination = (PIN_ADDR) &in4addr_broadcast;
    }

    //
    // If broadcast request was received, let route lookup pick a source 
    // address.
    //
    if (NL_ADDRESS_TYPE(SourceAddress) != NlatUnicast) {
        SourceAddress = NULL;
    }
    
    //
    // Get the reply route to the destination.
    // Under normal circumstances, the reply will go out
    // the incoming interface. RouteToDestination
    // will figure out the appropriate ScopeId.
    //
    Status = 
        IppRouteToDestinationInternal(
            SourceInterface->Compartment,
            (PUCHAR) Destination,
            SourceInterface,
            SourceAddress,
            &Path);
    if (!NT_SUCCESS(Status)) {
        //
        // No route - drop the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: IPv4 address mask request failed: "
                   "No route to destination %!IPV4!\n", 
                   (PUCHAR) Destination);
        return;
    }

    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV4_MESSAGE));
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += 
        sizeof(ICMPV4_MESSAGE);    

    Status=
        IppNetAllocate(
            &SendArgs.NetBufferList,
            (PUCHAR*) &AddrMaskMessage,
            IP_EXTRA_DATA_BACKFILL + sizeof(IPV4_HEADER),
            sizeof(ICMPV4_ADDRESS_MASK_MESSAGE));
    if (!NT_SUCCESS(Status)) {
        NetioTrace(
            NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
            "IPNG: IPv4 address mask request failed: "
            "Failed to allocate address mask reply packet.\n");
        IppDereferencePath(Path);        
        return;
    }            
    
    AddrMaskMessage->Header.icmp4_type = ICMP4_MASK_REPLY;
    AddrMaskMessage->Header.icmp4_code = 0;
    AddrMaskMessage->Header.icmp4_id = Icmpv4->icmp4_id;
    AddrMaskMessage->Header.icmp4_seq = Icmpv4->icmp4_seq;
    AddrMaskMessage->Header.icmp4_cksum = 0;

    SourceAddress = (PIP_LOCAL_ADDRESS) Path->SourceAddress;

    Status = 
        ConvertLengthToIpv4Mask(Path->SourceAddress->PrefixLength, &AddrMask);
    if (!NT_SUCCESS(Status)) {
        //
        // This should not occur.
        //
        ASSERT(FALSE);
        NetioTrace(
            NETIO_TRACE_RECEIVE, TRACE_LEVEL_WARNING, 
            "IPNG: IPv4 address mask request failed: "
            "Failed to get address mask.\n");
        IppDereferencePath(Path); 
        NetioDereferenceNetBufferList(SendArgs.NetBufferList, TRUE);
        return;        
    }
    AddrMaskMessage->AddressMask = AddrMask;
    
    SendArgs.DestProtocol = IPPROTO_ICMP; 
    
    //
    // Take our reply's source address from the receiving address,
    // or use the best source address for this destination
    // if we don't have a receiving address.
    //
    SendArgs.NlLocalAddress.LocalAddress =
        (PNL_LOCAL_ADDRESS) Path->SourceAddress;
    SendArgs.RemoteAddress = (PUCHAR) Destination;
    SendArgs.RemoteScopeId = scopeid_unspecified;
    SendArgs.UlChecksumOffset =
        FIELD_OFFSET(ICMPV4_ADDRESS_MASK_MESSAGE, Header.icmp4_cksum);
    SendArgs.PseudoHeaderChecksum = 0;

    IppSendDatagrams(&Ipv4Global, &SendArgs);
    IppUpdateIcmpOutStatistics(&Ipv4Global, ICMP4_MASK_REPLY);
            
    IppDereferencePath(Path);
}

VOID
Icmpv4pHandleError(
    IN PICMPV4_MESSAGE Icmpv4,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Generic ICMPv4 error processing. 
    This takes ownership of the packet, so the caller is never
    responsible for completing it.

Arguments:

    Icmpv4 - Supplies the ICMP Header from the packet.

    Control - The IP request control data.

Return Value:

    None.
        
--*/
{
    PNLC_RECEIVE_CONTROL_MESSAGE ControlMessage;
    NLC_RECEIVE_CONTROL_MESSAGE ControlBuffer;
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    PNET_BUFFER NetBuffer = NetBufferList->FirstNetBuffer;
    IPV4_HEADER *Ipv4Header;
    UCHAR Ipv4HeaderStorage[MAX_IPV4_HLEN];
    PIP_RECEIVE_DEMUX Demux = NULL;
    ULONG Ipv4HeaderLength;

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
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV4_MESSAGE));
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += 
        sizeof(ICMPV4_MESSAGE);
    
    //
    // Look at the IPv4 header following the ICMP header to determine the
    // next header value. 
    //
    if (NetBuffer->DataLength < sizeof(IPV4_HEADER)) {
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Dropping ICMPv4 error with truncated IP header: "
                   "length=%d expected=%d\n", 
                   NetBuffer->DataLength, sizeof(IPV4_HEADER));
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        goto Done;
    }
    
    Ipv4Header = NetioGetDataBuffer(NetBuffer, 
                                    sizeof(IPV4_HEADER),
                                    Ipv4HeaderStorage,
                                    __builtin_alignof(IPV4_HEADER),
                                    0);

    Ipv4HeaderLength = Ip4HeaderLengthInBytes(Ipv4Header);
    
    if (Ipv4HeaderLength > sizeof(IPV4_HEADER)) {
        if (NetBuffer->DataLength < Ipv4HeaderLength) {
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                       "IPNG: Dropping ICMPv4 error with truncated"
                       "IP header: length=%d expected=%d\n", 
                       NetBuffer->DataLength, Ipv4HeaderLength);
            NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
            goto Done;
        }
        
        Ipv4Header = NetioGetDataBuffer(NetBuffer,
                                        Ipv4HeaderLength,
                                        Ipv4HeaderStorage,
                                        __builtin_alignof(IPV4_HEADER),
                                        0);
    }
    NetioAdvanceNetBuffer(NetBuffer, Ipv4HeaderLength);
    Control->NlcReceiveDatagram.NetworkLayerHeadersSize += Ipv4HeaderLength;

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
               "IPNG: Received ICMPv4 error: type %d code %d\n", 
               Icmpv4->icmp4_type, Icmpv4->icmp4_code);
    
    //
    // Do network layer processing of the ICMP error message. For instance, for
    // a FRAG_NEEDED message, we need to update the path MTU. The errors
    // still need to be sent to the upper layer protocols which is done below.
    //
    if ((Icmpv4->icmp4_type == ICMP4_DST_UNREACH) && 
        (Icmpv4->icmp4_code == ICMP4_UNREACH_FRAG_NEEDED)) {
        //
        // Update the path MTU.
        //
        Ipv4pUpdatePathMtu(
            Control->DestLocalAddress, 
            Icmpv4, 
            Ipv4Header);
    }
    
    //
    // Send the ICMP error message to the network layer clients. 
    //

    ControlMessage = &Control->NlcControlMessage;

    ControlMessage->Type = Icmpv4->icmp4_type;
    ControlMessage->Code = Icmpv4->icmp4_code;
    ControlMessage->Parameter = Icmpv4->icmp4_data32[0];
    ControlMessage->NetBufferList = NetBufferList;
    ControlMessage->RemoteAddress = (PVOID)&Ipv4Header->DestinationAddress;
    ControlMessage->RemoteScopeId = IppGetExternalScopeId(
        Control->DestLocalAddress->Interface,
        ControlMessage->RemoteAddress);
    ControlMessage->LocalAddress = (PNL_LOCAL_ADDRESS)
        Control->DestLocalAddress;
    ControlMessage->NextHeaderValue = Ipv4Header->Protocol;
    
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
            &Ipv4Global,
            ControlMessage->NextHeaderValue,
            NetBufferList,
            &Demux);
        if (Demux == NULL) {
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: No handler for ICMPv4 error next header %u\n",
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
Icmpv4ReceiveDatagrams(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:
    
    This routine handles ICMPv4 messages on the receive path. 

Arguments:

    Args - Supplies the packet received. 

Return Value:

    None.

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PNET_BUFFER NetBuffer;
    ICMPV4_MESSAGE Buffer, *Icmpv4;
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
        Ipv4Global.IcmpStatistics.InMessages++;

        //
        // Any packet whose size is less than sizeof(ICMPV4_MESSAGE) is
        // rejected.
        //
        if (NetBuffer->DataLength < sizeof(ICMPV4_MESSAGE)) {
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Received truncated ICMPv4 header: length %d\n", 
                       NetBuffer->DataLength);
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            Ipv4Global.IcmpStatistics.InErrors++;
            continue;
        }
 
        //
        // Verify checksum.  ICMPv4 has no pseudo-header checksum.
        //
        Checksum = IppChecksumBuffer(NetBuffer, NetBuffer->DataLength);
        if (Checksum != 0xffff) {
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Checksum failure for ICMPv4 packet\n");
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            Ipv4Global.IcmpStatistics.InErrors++;
            continue;
        }

        //
        // Parse the ICMPv4 Header.
        //
        Icmpv4 = NetioGetDataBuffer(NetBuffer, 
                                    sizeof(ICMPV4_MESSAGE), 
                                    &Buffer,
                                    __builtin_alignof(ICMPV4_MESSAGE),
                                    0);

        Type = Icmpv4->Header.Type;
        Ipv4Global.IcmpStatistics.InTypeCount[Type]++; 

        Action = IppInspectLocalDatagramsIn(
            IPPROTO_IP,
            (PNL_LOCAL_ADDRESS)Args->DestLocalAddress,
            Args->NlcReceiveDatagram.RemoteAddress,
            (PNL_INTERFACE) Args->SourcePointer->Interface,
            (Args->IsOriginLocal ? IFI_UNSPECIFIED :
             Args->SourceSubInterface->Index),
            Args->NlcReceiveDatagram.Loopback,
            IPPROTO_ICMP,
            (PTRANSPORT_DATA)&Icmpv4->Header.Type,
            Args->NlcReceiveDatagram.NetworkLayerHeadersSize,
            0,
            Icmpv4Demux.LocalEndpoint,
            &Args->NlcReceiveDatagram,
            Args->NetBufferList);
        if (Action >= IpFilterDrop) {
            if ((Action == IpFilterDrop) || 
                (Action == IpFilterDropAndSendIcmp)) {
                Ipv4Global.
                    PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                    InFilterDrops++;

                NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Inspection point dropped ICMPv4 packet: "
                           "Source %!IPV4! destination %!IPV4!\n", 
                           Args->NlcReceiveDatagram.RemoteAddress,
                           NL_ADDRESS(Args->DestLocalAddress));
                
                Args->NetBufferList->Status = STATUS_FWP_DROP_NOICMP;
                
                if ((Action == IpFilterDropAndSendIcmp) && 
                    !ICMP4_ISTYPEERROR(Type)) {
                    Args->NetBufferList->Status = STATUS_ACCESS_DENIED;
                }
                
            } else {
                ASSERT(Action == IpFilterAbsorb);
            }
            continue;
        }

        switch (Type) {
        case ICMP4_ECHO_REQUEST:
            Ipv4pHandleEchoRequest(Icmpv4, Args);
            break;
        case ICMP4_ECHO_REPLY:
            Icmpv4pHandleEchoReplyAndError(Icmpv4->icmp4_type,
                                           Icmpv4->icmp4_code,
                                           Icmpv4->icmp4_pptr,
                                           Args, NULL);
            break;
        case ICMP4_TIME_EXCEEDED:
        case ICMP4_PARAM_PROB:
        case ICMP4_DST_UNREACH:
            Icmpv4pHandleError(Icmpv4, Args);
            break;
        case ICMP4_ROUTER_ADVERT:
            Icmpv4HandleRouterAdvertisement(Icmpv4, Args);
            break;
        case ICMP4_ROUTER_SOLICIT:
            Icmpv4HandleRouterSolicitation(Icmpv4, Args);
            break;
        case ICMP4_REDIRECT:
            Ipv4pHandleRedirect(Icmpv4, Args);
            break;
        case ICMP4_TIMESTAMP_REQUEST:
            Ipv4pHandleTimestampRequest(Icmpv4, Args);
            break;
        case ICMP4_MASK_REQUEST:
            Ipv4pHandleAddressMaskRequest(Icmpv4, Args);
            break;
        default:
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Received unknown ICMPv4 message %u\n", 
                       Type);
            Args->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
            break;
        }
    }    
}

VOID
Icmpv4ReceiveControlMessage(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:

    This handles an ICMP packet - we only care if this is in response to an
    ICMP echo we generated.

Arguments:

    Args - Provides the control message structure.

Return Value:

    None.
        
--*/    
{
    PNLC_RECEIVE_CONTROL_MESSAGE Control = (PNLC_RECEIVE_CONTROL_MESSAGE) Args;
    ICMPV4_MESSAGE Icmpv4Storage;
    ICMPV4_MESSAGE *ErrorIcmpv4;
    PNET_BUFFER NetBuffer;
    
    Control->NetBufferList->Status = STATUS_SUCCESS;

    NetBuffer = Control->NetBufferList->FirstNetBuffer;
    
    if (NetBuffer->DataLength < sizeof(ICMPV4_MESSAGE)) {
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Dropping ICMPv4 error with truncated encapsulated"
                   "ICMP header\n");
        //
        // Make this packet available to RAW sockets.
        //
        Control->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    ErrorIcmpv4 = NetioGetDataBuffer(NetBuffer,
                                     sizeof(ICMPV4_MESSAGE),
                                     &Icmpv4Storage,
                                     __builtin_alignof(ICMPV4_MESSAGE),
                                     0);
    
    //
    // Only if this is an echo request process otherwise continue.
    //
    if (ErrorIcmpv4->icmp4_type == ICMP4_ECHO_REQUEST &&
        ErrorIcmpv4->icmp4_code == 0) {
        Icmpv4pHandleEchoReplyAndError(Control->Type,
                                       Control->Code,
                                       Control->Parameter,
                                       (PIP_REQUEST_CONTROL_DATA) Control,
                                       ErrorIcmpv4);
    } else {
        Control->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
    }
}


VOID
Icmpv4pHandleEchoReplyAndError(
    IN ULONG IcmpType,
    IN ULONG IcmpCode,
    IN ULONG IcmpParameter,
    IN PIP_REQUEST_CONTROL_DATA Args,
    IN ICMPV4_MESSAGE *ErrorIcmpv4
    )
/*++

Routine Description:

    This routine takes an echo reply and attempts to find the ICMP request
    which generated the reply and then complete the request.

Arguments:

    Icmpv4 - Supplies the ICMP Header from the packet.

    Args - Supplies the control data for the packet.

    ErrorIcmpv4 - Supplies the ICMP message that triggered a failure if any.
        This value is NULL on the success path.
    
Return Value:

    If a matching request was found STATUS_SUCCESS, otherwise
    STATUS_UNSUCCESSFUL.
        
--*/
{
    PNET_BUFFER_LIST NetBufferList = Args->NetBufferList;
    PNET_BUFFER NetBuffer = NetBufferList->FirstNetBuffer;
    PIPV4_ECHO_REQUEST_CONTEXT EchoRequest;
    PIPV4_ECHO_REQUEST_ROD EchoRod;
    PIP_PROTOCOL Protocol = &Ipv4Global;
    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime, Frequency;
    IPV4_HEADER UNALIGNED *Ipv4Header;
    SIZE_T BytesCopied;
    ULONG EchoSequence = IcmpParameter;
    BOOLEAN SuccessPath;
    NTSTATUS Status = STATUS_SUCCESS;

    
    NetBufferList->Status = STATUS_SUCCESS;
    SuccessPath = (ErrorIcmpv4 == NULL) ? TRUE : FALSE;
    
    if (!SuccessPath) {                                              
        EchoSequence = ErrorIcmpv4->icmp4_pptr;
    }
    
    KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
    EchoRequest = (PIPV4_ECHO_REQUEST_CONTEXT)
        IppFindEchoRequestForReply(Protocol->EchoRequestTable,
                                   IP_ECHO_REQUEST_TABLE_SIZE,
                                   EchoSequence);
    if (EchoRequest == NULL) {
        KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Can not find matching echo request "
                       "for icmpv4 echo reply\n");
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
    Ipv4Header = (IPV4_HEADER UNALIGNED *) Args->IP;
    
    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV4_MESSAGE));
    Args->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(ICMPV4_MESSAGE);
    
    //
    // Copy data into the reply buffer and fill out the rod field.
    //
    EchoRod = (PIPV4_ECHO_REQUEST_ROD) &(EchoRequest->Rod);
    
    if (SuccessPath && 
        EchoRequest->Rw.ReplyBufferLength <
        (EchoRequest->Rw.ReplyBufferOffset + 
         NetBuffer->DataLength + 
         Ip4HeaderLengthInBytes(Ipv4Header) -
         sizeof(IPV4_HEADER))) {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto completion;
    }
    
    RtlCopyMemory(&EchoRod->ReplyAddress,
                  &(Ipv4Header->SourceAddress),
                  sizeof(IN_ADDR));
    CurrentTime = KeQueryPerformanceCounter(&Frequency);
    
    EchoRod->Ttl = Ipv4Header->TimeToLive;
    EchoRod->Tos = Ipv4Header->TypeOfService;
    EchoRod->Flags.MoreFragments = (UINT8) Ipv4Header->MoreFragments;
    EchoRod->Flags.DontFragment = (UINT8) Ipv4Header->DontFragment;
    if (SuccessPath) {
        EchoRod->EchoDataSize = NetBuffer->DataLength;
        EchoRod->OptionsSize =
            (Ipv4Header->HeaderLength << 2) - sizeof(IPV4_HEADER);
    } else {
        EchoRod->EchoDataSize = 0;
        EchoRod->OptionsSize = 0;
    }
    EchoRod->RoundTripTime = (UINT)
        ((1000*(CurrentTime.QuadPart - EchoRequest->StartTime.QuadPart)) /
         Frequency.QuadPart);
    
    //
    // For the error path we need to pull out the icmp error.
    //
    if (!SuccessPath) {
        EchoRod->IcmpErrorSet = TRUE;
        EchoRod->IcmpType = IcmpType;
        EchoRod->IcmpCode = IcmpCode;
        Status = STATUS_UNSUCCESSFUL;
    } else {
        EchoRod->IcmpErrorSet = FALSE;
    }
    
    //
    // Finally copy into EchoData all the data and then copy after the data any
    // options information.
    //
    if (SuccessPath && (EchoRod->EchoDataSize > 0 ||
                        EchoRod->OptionsSize > 0)) {

        if (EchoRod->EchoDataSize > 0) {
            RtlCopyMdlToMdl(
                NetBuffer->CurrentMdl,
                NetBuffer->CurrentMdlOffset,
                EchoRequest->ReplyMdl,
                EchoRequest->Rw.ReplyBufferOffset,
                EchoRod->EchoDataSize,
                &BytesCopied);
        }
        if (EchoRod->OptionsSize > 0) {
            RtlCopyBufferToMdl(
                Ipv4Header + 1,
                EchoRequest->ReplyMdl,
                EchoRequest->Rw.ReplyBufferOffset + EchoRod->EchoDataSize,
                EchoRod->OptionsSize,
                &BytesCopied);
        }
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
        
        IppDereferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
    } else {
        InterlockedIncrement(&EchoRequest->Protocol->EchoFailedNotifications);
        KeReleaseSpinLock(&EchoRequest->Lock, OldIrql);

        KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
        IppInsertEchoRequest(Protocol->EchoRequestTable,
                             IP_ECHO_REQUEST_TABLE_SIZE,
                             (PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
        KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
    }
}
