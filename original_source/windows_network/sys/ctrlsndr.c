/*++

Copyright (c) Microsoft Corporation

Module Name:

    ctrlsndr.c

Abstract:

    This module implements version-independent functions of the
    IP Control Sender modules.

Author:

    Dave Thaler (dthaler) 22-Dec-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "ctrlsndr.tmh"

static LONG IcmpErrorCount = 0;

BOOLEAN
IppRateLimitIcmp(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    Determine if rate-limiting prevents generation of an ICMP error message
    for the specified destination.

Arguments:

    Path - Supplies the path to the destination.
    
Return Value:

    TRUE if an ICMP error should NOT be sent to this destination, FALSE o/w.

Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    ULONG Now = IppTickCount;
    BOOLEAN IsNextHopLocal = FALSE;
    PIP_NEXT_HOP NextHop = IppGetNextHopFromPath(Path);
    
    if (NextHop != NULL) {
        IsNextHopLocal = IppIsNextHopLocalAddress(NextHop);
    }

    //
    // This arithmetic will handle wraps of the timer tick counter.
    //
    if ((ULONG)(Now - Path->LastError) <= ICMP_MIN_ERROR_INTERVAL &&
        !IsNextHopLocal) {
        return TRUE;
    }
    
    Path->LastError = Now;
    return FALSE;
}


VOID
NTAPI
IppCompleteIcmpErrorChain(
    IN PNET_BUFFER_LIST NetBufferListChain,
    IN ULONG Count,
    IN BOOLEAN DispatchLevel
    )
/*++

Routine Description:

    PNETIO_NET_BUFFER_LIST_COMPLETION_ROUTINE Handler.

--*/
{
    InterlockedExchangeAdd(&IcmpErrorCount, -((LONG) Count));

    NetioCompleteNetBufferAndNetBufferListChain(
        NetBufferListChain,
        Count,
        DispatchLevel);                     
}


NTSTATUS
IppAllocateIcmpError(
    OUT PNET_BUFFER_LIST *NetBufferList,
    OUT PUCHAR *FlatBuffer,
    IN ULONG Offset,
    IN ULONG Length
    )
/*++

Routine Description:

    Allocate a NetBufferList (including NetBuffer, MDL, and Buffer) to describe
    a packet of the specified Offset + Length.  Set the NetBuffer's DataOffset
    to the specified value and return the resulting pointer within the Buffer.

Arguments:

    NetBufferList - Returns the allocated NetBufferList.
        This includes a NetBuffer, an MDL, and a Buffer.

    FlatBuffer - Returns a pointer within the Buffer at the specified offset.
        This is NULL upon failure or if Length is 0.
        Use the return value to distinguish between the two cases.

    Offset - Supplies the required offset within the allocated Buffer.

    Length - Supplies the length of the allocated buffer, starting from Offset.

Return Value:

    Returns STATUS_SUCCESS on success or some NTSTATUS error code otherwise.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;

    //
    // Never have more than a small number of ICMP errors outstanding.
    //
    if (InterlockedIncrement(&IcmpErrorCount) > ICMP_MAX_ERROR_COUNT) {
        InterlockedDecrement(&IcmpErrorCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }    

    *FlatBuffer = NULL;

    *NetBufferList =
        NetioAllocateAndReferenceNetBufferAndNetBufferList(
            IppCompleteIcmpErrorChain,
            NULL,
            NULL,
            0,
            0,
            FALSE);
    if (*NetBufferList == NULL) {
        InterlockedDecrement(&IcmpErrorCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = NetioRetreatNetBufferList(*NetBufferList, Length, Offset);
    if (!NT_SUCCESS(Status)) {
        NetioDereferenceNetBufferList(*NetBufferList, FALSE);
        *NetBufferList = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *FlatBuffer =
        NetioGetDataBuffer(
            (*NetBufferList)->FirstNetBuffer,
            Length,
            NULL,
            1,
            0);
    ASSERT((*FlatBuffer != NULL) || (Length == 0));

    return STATUS_SUCCESS;
}


NTSTATUS
IppAllocateAndFillIcmpHeader(
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_GENERATE_CONTROL_MESSAGE Args
    )
/*++

Routine Description:

    Allocate an ICMP header and fill it up with the relevant information.
    Also, fill the DestProtocol, ChecksumOffset and PseudoHeaderChecksum fields
    of the supplied args structure. 

Arguments:

    Protocol - Supplies the protocol. 

    Args - Supplies a single argument with fields as follows:

    NetBufferList - Supplies the NetBufferList to add the ICMP header to.

    Type - Supplies the ICMP Type value to place in the ICMP header.

    Code - Supplies the ICMP Code value to place in the ICMP header.

    Parameter - Supplies the parameter value to place after the Code.

    DestProtocol - Returns the destination protocol (ICMPv4 or ICMPv6).

    ChecksumOffset - Returns the offset where the checksum should be filled.

    PseudoHeaderChecksum - Returns the pseudo header checksum. 

Return Value:

    STATUS_SUCCESS or appropriate failure code.

Locks:

    None.

Caller IRQL: <= DISPATCH_LEVEL

--*/
{
    NTSTATUS Status;
    PNET_BUFFER_LIST NetBufferList = Args->NetBufferList;
    PNET_BUFFER NetBuffer;
    ICMP_MESSAGE UNALIGNED *IcmpMessage;
    
    //
    // Construct the ICMP header.
    //
    Status =
        NetioRetreatNetBufferList(
            NetBufferList,
            sizeof(ICMP_MESSAGE),
            Protocol->HeaderSize);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    for (NetBuffer = NetBufferList->FirstNetBuffer; 
         NetBuffer != NULL; 
         NetBuffer = NetBuffer->Next) {
        IcmpMessage =
            NetioGetDataBufferSafe(
                NetBuffer, 
                sizeof(ICMP_MESSAGE));

        IcmpMessage->Header.Type = (UINT8) Args->Type;
        IcmpMessage->Header.Code = (UINT8) Args->Code;
        IcmpMessage->Header.Checksum = 0;        
        IcmpMessage->Data.Data32[0] = Args->Parameter;

    }

    Args->DestProtocol =
        (IS_IPV4_PROTOCOL(Protocol)) ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    
    //
    // Let SendDatagrams take care of the ICMP checksum,
    // which covers the entire ICMP message starting with the 
    // ICMP header and without the IP pseudo-header.
    //        
    Args->UlChecksumOffset = FIELD_OFFSET(ICMP_HEADER, Checksum);
    Args->PseudoHeaderChecksum = 0;

    return STATUS_SUCCESS;
}


VOID
IppSendControl(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_GENERATE_CONTROL_MESSAGE ArgsList
    )
/*++

Routine Description:

    Common ICMP message transmission functionality is performed here.

Arguments:

    DispatchLevel - If TRUE, then IRQL must be DISPATCH level. 

    Protocol - Supplies the protocol. 

    ArgsList - Supplies a list of arguments with fields as follows:

        NlCompartment - Supplies the compartment doing the send.

        NetBufferList - Supplies the list of data to include in datagrams. 

        NlLocalAddress - Supplies the source address to use.

        RemoteAddress - Supplies the destination address to use.

        RemoteScopeId - Supplies the scope id of the destination address.

        Type - Supplies the ICMP Type value to place in the ICMP header.

        Code - Supplies the ICMP Code value to place in the ICMP header.

        Parameter - Supplies the parameter value to place after the Code.

Return Value:

    None.  Consumes the reference on the NetBufferList.

Locks:

    Assumes caller holds a reference on NlLocalAddress.

Caller IRQL:

    If DispatchLevel is TRUE, must be at DISPATCH level.
    If DispatchLevel is FALSE, may be at PASSIVE through DISPATCH level.

--*/
{
    PNL_REQUEST_GENERATE_CONTROL_MESSAGE Args, Next;
    PNET_BUFFER_LIST NetBufferList;
    IP_GENERIC_LIST SendList, CompleteList;

    if (DispatchLevel) {
        DISPATCH_CODE();
    }

    NET_BUFFER_LIST_INFO(ArgsList->NetBufferList,
                         TcpIpChecksumNetBufferListInfo) = (PVOID) NULL;
    
    IppInitializeGenericList(&SendList);
    IppInitializeGenericList(&CompleteList);

    for (Args = ArgsList; Args != NULL; Args = Next) {
        Next = Args->Next;
        Args->Next = NULL;
        NetBufferList = Args->NetBufferList;

        //
        // As in XP, rather than using an interlocked operation,
        // we accept inaccuracies to get higher performance.
        //
        Protocol->IcmpStatistics.OutMessages++;

        if ((Args->Type > 255) || (Args->Code > 255)) {
            NetioTrace(NETIO_TRACE_SEND, TRACE_LEVEL_ERROR, 
                       "IPNG: Tried to send illegal control message: "
                       "bad type/code %d %d\n", 
                       Args->Type, Args->Code);
            Protocol->IcmpStatistics.OutErrors++;
            IppAppendToGenericList(&CompleteList, NetBufferList);
            continue;
        }

        NetBufferList->Status = IppAllocateAndFillIcmpHeader(Protocol, Args);
        if (!NT_SUCCESS(NetBufferList->Status)) {
            NetioTrace(NETIO_TRACE_SEND, TRACE_LEVEL_WARNING, 
                       "IPNG: Error allocating header for ICMP message\n");
            Protocol->IcmpStatistics.OutErrors++;
            IppAppendToGenericList(&CompleteList, NetBufferList);
            continue;
        }

        Protocol->IcmpStatistics.OutTypeCount[Args->Type]++;
        IppAppendToGenericList(&SendList, Args);

        //
        // The following fields are already in the right place, and 
        // so don't need to be touched: 
        // NetBufferList, SourceAddress, DestAddress, DestScopeId.
        // DestProtocol, ChecksumOffset and PseudoHeaderChecksum are filled in
        // by AllocateAndFillIcmpHeader. 
        //
    }

    if (SendList.Head) {
        //
        // Hand the packets down to IP for transmission.
        //
        IppSendDatagrams(Protocol, SendList.Head);
    }

    if (CompleteList.Head) {
        //
        // Dereference the packets on the immediate completion list.
        //
        NetioDereferenceNetBufferListChain(CompleteList.Head, DispatchLevel);
    }
}


BOOLEAN
IppIsErrorPacket(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control
)
/*++

Routine Description:

    Determines if the final destination protocol of a packet is an ICMP error.
    This is useful in cases where the packet has only been partially parsed
    due to semantic errors, and we wish to continue parsing as long as the
    packet is well-formed.

Arguments:


    Protocol - Supplies the protocol. 

    Control - Supplies the packet.
    
Return Value:

    Returns TRUE if the packet is an ICMP error packet.  Otherwise, FALSE even
    in error cases.

--*/
{
    NTSTATUS Status;
    ULONG SkippedLength = 0;
    ICMP_MESSAGE IcmpBuffer, *Icmp;
    UINT8 DestinationProtocol;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;   
    ULONG NetworkLayerHeadersSize;
    BOOLEAN IsError = FALSE;
    
    //
    // We could be anywhere in the packet, so first retreat to the IP header.
    //
    NetworkLayerHeadersSize = 
        Control->OnSendPath
        ? 0
        : Control->NlcReceiveDatagram.NetworkLayerHeadersSize;    
        
    Status = 
        NetioRetreatNetBufferList(
            Control->NetBufferList,
            NetworkLayerHeadersSize,
            0);
    ASSERT(NT_SUCCESS(Status));

    Status = 
        Protocol->SkipNetworkLayerHeaders(
            NetBuffer, 
            NULL, 
            NULL, 
            NULL, 
            &DestinationProtocol,
            &SkippedLength);
    if (!NT_SUCCESS(Status)) {
        //
        // ASSERT: SkippedLenghth will also be set in case of error, because
        // SkipNetworkLayerHeaders may have still advanced the NBL.
        //
        
        goto exit;
    }

    //
    // We are now at the beginning of the transport layer header. 
    //
    if ((DestinationProtocol == IPPROTO_ICMP) ||
        (DestinationProtocol == IPPROTO_ICMPV6)) {
       
        if (NetBuffer->DataLength < sizeof(IcmpBuffer)) {
            goto exit;
        }
        
        Icmp =
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(IcmpBuffer),
                &IcmpBuffer, 
                __builtin_alignof(ICMP_MESSAGE), 
                0);
        if (Icmp == NULL) {
            goto exit;
        }

        //
        // Identify ICMP error messages.
        //
        IsError = 
            (DestinationProtocol == IPPROTO_ICMP)
            ? ICMP4_ISTYPEERROR(Icmp->Header.Type)
            : ICMP6_ISTYPEERROR(Icmp->Header.Type);
    }
    
exit:    
    //
    // Return the packet to the previous NetworkLayerHeadersSize location.
    //
    if (SkippedLength > NetworkLayerHeadersSize) {
        Status = 
            NetioRetreatNetBufferList(
                Control->NetBufferList,
                SkippedLength - NetworkLayerHeadersSize,
                0);
        ASSERT(NT_SUCCESS(Status));
    } else if (SkippedLength < NetworkLayerHeadersSize) {
        NetioAdvanceNetBufferList(
            Control->NetBufferList,
            NetworkLayerHeadersSize - SkippedLength);
    }
    return IsError;
}

ULONG 
IppComputeIcmpPayloadSize(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_PROTOCOL Protocol,
    IN ULONG NetworkLayerHeaderSize,
    OUT PULONG BasicHeaderLength
    )
/*++

Routine Description:

    Compute the size of the ICMP payload

Arguments:

    Control - Packet for which the ICMP is being sent. 

    Protocol - Supplies the protocol. 

    NetworkLayerHeaderSize - Total size of NL headers including IPsec headers.
    
    BasicHeaderLength - Size of the Basic IP header (includes IPv4 Options).
                        This field is updated only if IPSec headers are present.

Return Value:

    Total size of the Icmp payload.
--*/    
{
    PNET_BUFFER_LIST NetBufferList;
    PNET_BUFFER NetBuffer;
    ULONG TransportPayload = 0;
    ULONG MaxIcmpPayloadSize = 0;
    IPV4_HEADER *Ipv4Header = NULL,Ipv4HeaderBuffer;
    
    NetBufferList = Control->NetBufferList;
    NetBuffer = NetBufferList->FirstNetBuffer;    

    if (IS_IPV4_PROTOCOL(Protocol) &&
        NetworkLayerHeaderSize == 0) {
        //
        // We are already at the beginning of NL headers.
        // This can only happen if we cloned the packet
        // for RAW. We can assume no IPSec headers in the IPv4
        // case.
        //
        ASSERT(Control->IpSecHeadersPresent == FALSE);
        return NetBuffer->DataLength;
    }
    //
    // For IPv4 the header size will be read from the
    // basic IPv4 header itself. This will include 
    // options.
    //
    if (IS_IPV4_PROTOCOL(Protocol)) {
        if (NetBuffer->DataLength < sizeof(Ipv4HeaderBuffer)) {
            return NetBuffer->DataLength;
        }

        Ipv4Header =
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(Ipv4HeaderBuffer), 
                &Ipv4HeaderBuffer, 
                __builtin_alignof(IPV4_HEADER), 
                0);
        if (Ipv4Header == NULL) {
            return NetBuffer->DataLength;
        }
        *BasicHeaderLength = Ip4HeaderLengthInBytes(Ipv4Header);
    } else { 
        if (NetBuffer->DataLength < sizeof(IPV6_HEADER)) {
            return NetBuffer->DataLength;
        }
        *BasicHeaderLength = sizeof(IPV6_HEADER);       
    }

    TransportPayload = NetBuffer->DataLength - 
        NetworkLayerHeaderSize;        

    MaxIcmpPayloadSize = TransportPayload + 
        (Control->IpSecHeadersPresent
        ? *BasicHeaderLength : NetworkLayerHeaderSize);

    return min(MaxIcmpPayloadSize,
            Protocol->MaximumIcmpErrorPayloadLength);
}

VOID
IppSendError(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN UINT8 Type,
    IN UINT8 Code,
    IN ULONG ErrorParameter,
    IN BOOLEAN MulticastOverride
    )
/*++

Routine Description:

    Sends ICMP messages in response to a single received packet.

Arguments:

    DispatchLevel - If TRUE, then IRQL must be DISPATCH level. 

    Protocol - Supplies the protocol. 

    Control - Supplies a list of arguments with fields as follows:

        NetBufferList - Supplies a list of packets to reply to.

    Type - Supplies an ICMP Type value.

    Code - Supplies an ICMP Code value.

    ErrorParameter - Supplies a data value to place after the Code.

    MulticastOverride - Supplies TRUE if errors may be sent for multicasts.

Return Value:

    None. This routine may consume the reference on the NetBufferList.
    In case the reference is consumed, Control::NetBufferList is set to NULL.
    This routine never consumes the control structures. 

Caller IRQL:

    If DispatchLevel is TRUE, must be called at DISPATCH level.
    If DispatchLevel is FALSE, may be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    NL_REQUEST_GENERATE_CONTROL_MESSAGE Args = {0};
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress = NULL;
    PIP_INTERFACE Interface = NULL;
    PNET_BUFFER_LIST NetBufferList;
    PNET_BUFFER NetBuffer;
    PUCHAR Buffer;
    SIZE_T BytesCopied;
    SIZE_T BytesToCopy;
    ULONG Backfill;
    ULONG NetworkLayerHeaderSize = 0;
    ULONG IPBasicHeaderLength = 0;
    
    if (DispatchLevel) {
        DISPATCH_CODE();
    }

    Args.Type = Type;
    Args.Code = Code;
    Args.Parameter = ErrorParameter;
    
    NetBufferList = Control->NetBufferList;
    NetBuffer = NetBufferList->FirstNetBuffer;    

    //
    // We must not send an ICMP error message
    // as a result of an ICMP error.
    //
    if (Control->IcmpError || IppIsErrorPacket(Protocol, Control)) {
        NetioTrace(NETIO_TRACE_SEND, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Not responding with ICMP error for "
                   "ICMP error packet\n");
        NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    //
    // We must not send an ICMP error message as a result
    // of receiving any kind of multicast or broadcast.
    // There are a couple exceptions so we have MulticastOverride.
    //
    if (!MulticastOverride &&
        ((Control->CurrentDestinationType == NlatMulticast) ||
         (Control->CurrentDestinationType == NlatBroadcast) ||
         NBL_TEST_PROT_RSVD_FLAG(NetBufferList, NBL_LINK_LAYER_NOT_UNICAST))) {
        NetioTrace(NETIO_TRACE_SEND, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Not responding with ICMP error for "
                   "broadcast/multicast packet\n");
        NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // We must rate-limit ICMP error messages on the path for the reply.
    // 1. The reply's destination is the source address of the incoming packet.
    // 2. The reply's source is the destination address of the incoming packet
    // (if it is our unicast address).
    //

    Args.RemoteAddress = Control->SourceAddress.Address;
    
    //
    // Select a local address.
    //
    if ((Control->NextHop != NULL) && 
        IppIsNextHopLocalAddress(Control->NextHop) &&
        (NL_ADDRESS_TYPE(Control->NextHopLocalAddress) == NlatUnicast)) {
        LocalAddress = 
            (PIP_LOCAL_UNICAST_ADDRESS) Control->NextHopLocalAddress;
    } 

    //
    // Select an interface.
    //
    Interface = IppGetPacketSourceInterface(Control);

    //
    // Rate limit ICMP errors per interface.
    //
    if (InterlockedIncrement(&Interface->IcmpErrorCount) > 
            ICMP_MAX_INTERFACE_ERROR_COUNT) {
        // 
        // The count will be reset on timeout.
        //
        if (IS_IPV4_PROTOCOL(Protocol)) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                       "IPNG: [%u] SendError - rate limit %!IPV4!\n",
                       Interface->Index, Args.RemoteAddress);
        } else {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                       "IPNG: [%u] SendError - rate limit %!IPV6!\n",
                       Interface->Index, Args.RemoteAddress);
        }
        NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Find the path but be careful not to create one if it doesn't
    // exist (we call IppFindPath instead of IppRouteToDestination here).  
    // This is to avoid creating path cache entries for destinations to which 
    // no valid traffic is sent - and hence avoid DoS attacks.
    //

    //
    // There is no need to lookup the route for the unspecified destination.
    //
    
    //
    // REVIEW: Check for local address being on the arrival interface breaks 
    // weak host scenario and may be a regression from XP.
    // 
    if ((Protocol->AddressType(Args.RemoteAddress) == NlatUnspecified) ||
        ((LocalAddress != NULL) && (Interface != LocalAddress->Interface))) {
        goto FailedRoute;        
    }

    Args.Path =
        (PNL_PATH) IppFindPath(
            Interface->Compartment,
            NULL,
            Args.RemoteAddress,
            IppGetScopeId(Interface, Args.RemoteAddress),
            Interface,
            LocalAddress);    
    if (Args.Path != NULL) {
        if (IppRateLimitIcmp((PIP_PATH)Args.Path)) {
            if (IS_IPV4_PROTOCOL(Protocol)) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                           "IPNG: [%u] SendError - rate limit %!IPV4!\n",
                           Interface->Index, Args.RemoteAddress);
            } else {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                           "IPNG: [%u] SendError - rate limit %!IPV6!\n",
                           Interface->Index, Args.RemoteAddress);
            }
            NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            goto Bail;
        }        
    } else {
        PIP_NEXT_HOP NextHop;
        PIP_LOCAL_UNICAST_ADDRESS SourceAddress;
        IP_PATH_FLAGS Constrained;
        
        Status =
            IppFindNextHopAndSource(
                Interface->Compartment, 
                Interface, 
                Args.RemoteAddress, 
                IppGetScopeId(Interface, Args.RemoteAddress), 
                LocalAddress,
                &NextHop, 
                &SourceAddress,
                NULL,
                &Constrained);
            
        if (!NT_SUCCESS(Status)) {
            //
            // No route - drop the packet.
            //
FailedRoute:
            if (IS_IPV4_PROTOCOL(Protocol)) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                           "IPNG: [%u] SendError - no route %!IPV4!\n",
                           Interface->Index, Args.RemoteAddress);
            } else {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                           "IPNG: [%u] SendError - no route %!IPV6!\n",
                           Interface->Index, Args.RemoteAddress);
            }
            NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            return;
        }
        Args.NextHop = NextHop;
        Args.NlLocalAddress.LocalAddress = (PNL_LOCAL_ADDRESS) SourceAddress; 
    }        
    
    //
    // Set data buffer offset to start of IP header if on the receive path.
    // For packets on the send path, we are already at the beginning of the
    // IP header.
    //
    if (!Control->OnSendPath) {
        Status =
            NetioRetreatNetBufferList(
                NetBufferList,
                Control->NlcReceiveDatagram.NetworkLayerHeadersSize,
                0);
        NetworkLayerHeaderSize = Control->NlcReceiveDatagram.NetworkLayerHeadersSize;           
        Control->NlcReceiveDatagram.NetworkLayerHeadersSize = 0;
        ASSERT(NT_SUCCESS(Status));
    }        
    
    BytesToCopy = 
        IppComputeIcmpPayloadSize(
            Control,
            Protocol,
            NetworkLayerHeaderSize,
            &IPBasicHeaderLength);
        
    //
    // Create a new NetBufferList for the ICMP error.  This ensures two things:
    // 1. The original packet and the ICMP error can be processed independently
    // (as required for redirects).
    // 2. Stale state for the old packet does not confuse inspection modules.
    //
    Backfill =
        IP_EXTRA_DATA_BACKFILL + Protocol->HeaderSize + sizeof(ICMP_MESSAGE);

    Status =
        IppAllocateIcmpError(
            &Args.NetBufferList,
            &Buffer,
            Backfill,
            (ULONG) BytesToCopy);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(
            NETIO_TRACE_SEND, TRACE_LEVEL_WARNING, 
            "Not responding with ICMP error for "
            "packet due to allocation failure.\n");
        goto Bail;
    }

    //
    // If this is an IPSec connection copy only the 
    // basic IP header (includes options for IPv4) and the 
    // transport payload. 
    // 
    if (Control->IpSecHeadersPresent) {

        ASSERT(NetBuffer->DataLength >= IPBasicHeaderLength);
        
        RtlCopyMdlToBuffer(
            NetBuffer->MdlChain,
            NetBuffer->DataOffset,
            Buffer,
            IPBasicHeaderLength,
            &BytesCopied);
        ASSERT(IPBasicHeaderLength == BytesCopied);

        //
        // Skip over all the network layer headers
        // and copy the transport payload.
        //

        NetioAdvanceNetBuffer(NetBuffer, NetworkLayerHeaderSize);

        ASSERT(NetBuffer->DataLength >= (BytesToCopy - IPBasicHeaderLength));

        RtlCopyMdlToBuffer(
            NetBuffer->MdlChain,
            NetBuffer->DataOffset,
            Buffer + IPBasicHeaderLength,
            BytesToCopy - IPBasicHeaderLength,
            &BytesCopied);
        ASSERT(BytesCopied == (BytesToCopy - IPBasicHeaderLength));

        //
        // Fix up the next header / protocol fields if some headers 
        // were removed -IPSec case.
        //
        if (IS_IPV4_PROTOCOL(Protocol)) {
            ((PIPV4_HEADER)Buffer)->Protocol = 
                (UINT8)Control->NlcReceiveDatagram.NextHeaderValue;
        } else {
            ((PIPV6_HEADER)Buffer)->NextHeader = 
                (UINT8)Control->NlcReceiveDatagram.NextHeaderValue;
        }

    } else {
        
        RtlCopyMdlToBuffer(
            NetBuffer->MdlChain,
            NetBuffer->DataOffset,
            Buffer,
            BytesToCopy,
            &BytesCopied);
        ASSERT(BytesCopied == BytesToCopy);
    }

    IppSendControl(DispatchLevel, Protocol, &Args);

Bail:
    if (Args.Path != NULL) {
        IppDereferencePath((PIP_PATH) Args.Path);
    }
    if (Args.NextHop != NULL) {
        IppDereferenceNextHop((PIP_NEXT_HOP) Args.NextHop);
    }
    if (Args.NlLocalAddress.LocalAddress != NULL ) {
        IppDereferenceLocalUnicastAddress(
            (PIP_LOCAL_UNICAST_ADDRESS) Args.NlLocalAddress.LocalAddress);
    }
}


VOID
IppSendErrorList(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA ControlChain,
    IN UINT8 Type,
    IN UINT8 Code,
    IN ULONG ErrorParameter,
    IN BOOLEAN MulticastOverride
    )
/*++

Routine Description:

    Sends ICMP messages in response to received packets.

Arguments:

    DispatchLevel - If TRUE, then IRQL must be DISPATCH level. 

    Protocol - Supplies the protocol. 

    ControlChain - Supplies a list of arguments with fields as follows:

        NetBufferList - Supplies a list of packets to reply to.

    Type - Supplies an ICMP Type value.

    Code - Supplies an ICMP Code value.

    ErrorParameter - Supplies a data value to place after the Code.

    MulticastOverride - Supplies TRUE if errors may be sent for multicasts.

Return Value:

    None. This routine may consume the reference on the NetBufferList.
    In case the reference is consumed, Control::NetBufferList is set to NULL.
    This routine never consumes the control structures. 

Caller IRQL:

    If DispatchLevel is TRUE, must be called at DISPATCH level.
    If DispatchLevel is FALSE, may be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_REQUEST_CONTROL_DATA Control;

    if (DispatchLevel) {
        DISPATCH_CODE();
    }

    for (Control = ControlChain; Control != NULL; Control = Control->Next) {
        IppSendError(
            DispatchLevel, 
            Protocol, 
            Control,
            Type,
            Code,
            ErrorParameter, 
            MulticastOverride);
    }
}


__inline
BOOLEAN
IppDiscardReasonToIcmpError(
    IN PIP_PROTOCOL Protocol,
    IN IP_DISCARD_REASON DiscardReason,
    OUT UINT8 *IcmpType,
    OUT UINT8 *IcmpCode
    )
{
    switch (DiscardReason) {
    case IpDiscardProtocolUnreachable:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_DST_UNREACH;
            *IcmpCode = ICMP4_UNREACH_PROTOCOL;
        } else {
            *IcmpType = ICMP6_PARAM_PROB;
            *IcmpCode = ICMP6_PARAMPROB_NEXTHEADER;
        }
        return TRUE;
        
    case IpDiscardPortUnreachable:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_DST_UNREACH;
            *IcmpCode = ICMP4_UNREACH_PORT;
        } else {
            *IcmpType = ICMP6_DST_UNREACH;
            *IcmpCode = ICMP6_DST_UNREACH_NOPORT;
        }
        return TRUE;
        
    case IpDiscardBadLength: 
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_PARAM_PROB;
            *IcmpCode = 0;
        } else {
            *IcmpType = ICMP6_PARAM_PROB;
            *IcmpCode = ICMP6_PARAMPROB_HEADER;
        }
        return TRUE;

    case IpDiscardNoRoute:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_DST_UNREACH;
            *IcmpCode = ICMP4_UNREACH_NET;
        } else {
            *IcmpType = ICMP6_DST_UNREACH;
            *IcmpCode = ICMP6_DST_UNREACH_NOROUTE;
        }
        return TRUE;

    case IpDiscardBeyondScope:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_DST_UNREACH;
            *IcmpCode = ICMP4_UNREACH_NET;
        } else {
            *IcmpType = ICMP6_DST_UNREACH;
            *IcmpCode = ICMP6_DST_UNREACH_BEYONDSCOPE;
        }
        return TRUE;
        
    case IpDiscardHopLimitExceeded:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_TIME_EXCEEDED;
            *IcmpCode = ICMP4_TIME_EXCEED_TRANSIT;
        } else {
            *IcmpType = ICMP6_TIME_EXCEEDED;
            *IcmpCode = ICMP6_TIME_EXCEED_TRANSIT;
        }
        return TRUE;
        
    case IpDiscardAddressUnreachable:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_DST_UNREACH;
            *IcmpCode = ICMP4_UNREACH_HOST;
        } else {
            *IcmpType = ICMP6_DST_UNREACH;
            *IcmpCode = ICMP6_DST_UNREACH_ADDR;
        }
        return TRUE;

    case IpDiscardAdministrativelyProhibited:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            *IcmpType = ICMP4_DST_UNREACH;
            *IcmpCode = ICMP4_UNREACH_ADMIN;
        } else {
            *IcmpType = ICMP6_DST_UNREACH;
            *IcmpCode = ICMP6_DST_UNREACH_ADMIN;
        }
        return TRUE;

    default:
        ASSERT(FALSE);
        return FALSE;
    }        
}


VOID
IppSendErrorListForDiscardReason(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA ControlChain,
    IN IP_DISCARD_REASON DiscardReason,
    IN ULONG ErrorParameter
    )
/*++

Routine Description:
 
    This routine generates ICMP errors for the given error type.
    It is a wrapper around IppSendErrorList and determines the correct
    ICMP error type and code for the given "abstract" error type.
   
Arguments:

    DispatchLevel - If TRUE, then IRQL must be DISPATCH level. 

    Protocol - Supplies the protocol. 

    ControlChain - Supplies a list of arguments with fields as follows:

        NetBufferList - Supplies a list of packets to reply to.

    DiscardReason - Supplies the "abstract" type of the error.

    ErrorParameter - Supplies additional DiscardReason-specific context.

Return Value:

    None. This routine may consume the reference on the NetBufferList.
    In case the reference is consumed, Control::NetBufferList is set to NULL.
    This routine never consumes the control structures. 

Caller IRQL:

    If DispatchLevel is TRUE, must be at DISPATCH level.
    If DispatchLevel is FALSE, may be at PASSIVE through DISPATCH level.

--*/ 
{
    UINT8 IcmpType;
    UINT8 IcmpCode;
     
    if (IppDiscardReasonToIcmpError(
            Protocol,
            DiscardReason,
            &IcmpType,
            &IcmpCode)) {
        IppSendErrorList(
            DispatchLevel, 
            Protocol,
            ControlChain, 
            IcmpType, 
            IcmpCode, 
            ErrorParameter,
            FALSE);
    }
}


NTSTATUS
NTAPI
IpNlpGenerateIcmpMessage(
    IN HANDLE ProviderHandle,
    IN PNL_REQUEST_GENERATE_CONTROL_MESSAGE Args
    )
/*++

Routine Description:

    Construct ICMP messages with the data indicated, and send them.

Arguments:

    Args - Supplies a pointer to the arguments structure.

Return Value:

    Returns the status of the operation.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PROTOCOL Protocol;
    PIP_CLIENT_CONTEXT Client = IppCast(ProviderHandle, IP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;
    
    IppSendControl(FALSE, Protocol, Args);
    return Args->NetBufferList->Status;
}

NTSTATUS
NTAPI
IpGetAllIcmpParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public ICMP parameters.

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

--*/
{
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;

    ASSERT(Args->KeyStructDesc.KeyStructLength == 0);

    switch (Args->Action) {
    case NsiGetExact:
    case NsiGetFirst:
        break;

    case NsiGetNext:
        return STATUS_NO_MORE_ENTRIES;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    Args->StructDesc.RwParameterStructLength = 0;

    if (Args->StructDesc.RoDynamicParameterStruct) {
        ASSERT(Args->StructDesc.RoDynamicParameterStructLength >= 
               sizeof(NL_CONTROL_PROTOCOL_ROD));

        Args->StructDesc.RoDynamicParameterStructLength = 
            sizeof(Protocol->IcmpStatistics);

        RtlCopyMemory(
            Args->StructDesc.RoDynamicParameterStruct,
            &Protocol->IcmpStatistics,
            Args->StructDesc.RoDynamicParameterStructLength);
    }

    Args->StructDesc.RoStaticParameterStructLength = 0;

    return STATUS_SUCCESS;
}
