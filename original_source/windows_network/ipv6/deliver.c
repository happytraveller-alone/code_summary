/*++

Copyright (c) 2004-2005  Microsoft Corporation

Module Name:

    deliver.c

Abstract:

    This module contains functions of the IPv6 Next Header Processor.

Author:

    Dave Thaler (dthaler) 4-Oct-2000

Environment:

    Kernel mode only.

--*/

#include "precomp.h"

//
// Hop-by-hop options and session state for adding the router alert option to
// outgoing MLD packets. 
//

UCHAR MldHopByHopOption[] = { 
    IPPROTO_ICMPV6,             // NextHeader.
    0,                          // HopByHop-options extension header length.
                                // (in 8-byte units, not counting first 8).
    IP6OPT_ROUTER_ALERT,        // RouterAlert option type.
    2,                          // RouterAlert option length.  In bytes, - 2.
    0,                          // RouterAlert option value (hi).
    0,                          // RouterAlert option value (lo).
    IP6OPT_PADN,                // PadN option type.
    0                           // PadN option length.  In bytes, - 2.
};

IP_SESSION_STATE MldSessionState;
INET_SS EndpointSessionState;

IP_INTERNAL_RECEIVE_DATAGRAMS Ipv6pReceiveHopByHopOptions;
IP_INTERNAL_RECEIVE_DATAGRAMS Ipv6pReceiveDestinationOptions;
IP_INTERNAL_RECEIVE_DATAGRAMS Ipv6pReceiveRoutingHeader;
IP_INTERNAL_RECEIVE_CONTROL_MESSAGE Ipv6pReceiveGenericInternalHeaderControl;
IP_INTERNAL_RECEIVE_DATAGRAMS Ipv6pReceiveNoHeader;

IP_RECEIVE_DEMUX Ipv6pHopByHopOptionsDemux = { 
    Ipv6pReceiveHopByHopOptions, 
    Ipv6pReceiveGenericInternalHeaderControl, 
    Ipv6pAuthenticateOptions, 
    Ipv6pDeferredAuthenticateOptions, 
    Ipv6pAddHopByHopOptionsHeader, 
    TRUE };

IP_RECEIVE_DEMUX Ipv6pDestinationOptionsDemux = { 
    Ipv6pReceiveDestinationOptions, 
    Ipv6pReceiveGenericInternalHeaderControl, 
    Ipv6pAuthenticateOptions, 
    Ipv6pDeferredAuthenticateOptions, 
    NULL, 
    TRUE };

IP_RECEIVE_DEMUX Ipv6pRoutingHeaderDemux = {
    Ipv6pReceiveRoutingHeader,
    Ipv6pReceiveGenericInternalHeaderControl, 
    Ipv6pAuthenticateRoutingHeader,
    Ipv6pDeferredAuthenticateRoutingHeader,
    Ipv6pAddRoutingHeader, 
    TRUE };

IP_RECEIVE_DEMUX Ipv6pNoHeaderDemux = {
    Ipv6pReceiveNoHeader,
    NULL, 
    NULL,
    NULL,
    NULL, 
    TRUE };


NTSTATUS
Ipv6pStartNextHeaderProcessor(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;
    ULONG i;
    PIP_RECEIVE_DEMUX Demux = Protocol->ReceiveDemux;
    PEPROCESS Process = PsGetCurrentProcess();
    
    Status = IppInitializeReassembler(&Protocol->ReassemblySet);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    for (i = 0; i < IPPROTO_RESERVED_MAX; i++) {
        RoInitializeAsInvalid(&Demux[i].Reference);
        Demux[i].LocalEndpoint = NULL;
    }
    
    IppInitializeSessionState(&MldSessionState);
    MldSessionState.HopByHopOptionsLength = sizeof(MldHopByHopOption);
    MldSessionState.HopByHopOptions = MldHopByHopOption;

    RtlZeroMemory(&EndpointSessionState, sizeof(INET_SS));
    EndpointSessionState.SessionState = &MldSessionState;

    //
    // Add internal clients.
    // No lock required since we haven't registered our NL provider NPI yet.
    //
    Demux[IPPROTO_IPV6].InternalDeferredAuthenticateHeader = 
        Ipv6pDeferredAuthenticateIpv6Header;
    
    Demux[IPPROTO_HOPOPTS] = Ipv6pHopByHopOptionsDemux; 
    RoInitialize(&Demux[IPPROTO_HOPOPTS].Reference);

    Demux[IPPROTO_ROUTING] = Ipv6pRoutingHeaderDemux;
    RoInitialize(&Demux[IPPROTO_ROUTING].Reference);

    Demux[IPPROTO_FRAGMENT] = Ipv6FragmentDemux;
    RoInitialize(&Demux[IPPROTO_FRAGMENT].Reference);

    Demux[IPPROTO_ESP] = IpEspDemux;
    RoInitialize(&Demux[IPPROTO_ESP].Reference);

    Demux[IPPROTO_AH] = IpAhDemux;
    RoInitialize(&Demux[IPPROTO_AH].Reference);

    Demux[IPPROTO_NONE] = Ipv6pNoHeaderDemux;
    RoInitialize(&Demux[IPPROTO_NONE].Reference);
    
    Status = 
        WfpAleEndpointCreationHandler(
            NULL,
            AF_INET6,
            SOCK_DGRAM,
            IPPROTO_ICMPV6,
            Process,
            NULL,
            &EndpointSessionState,
            NULL,
            &Icmpv6Demux.LocalEndpoint);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    Demux[IPPROTO_ICMPV6] = Icmpv6Demux;
    RoInitialize(&Demux[IPPROTO_ICMPV6].Reference);

    Demux[IPPROTO_DSTOPTS] = Ipv6pDestinationOptionsDemux;
    RoInitialize(&Demux[IPPROTO_DSTOPTS].Reference);

    IppDefaultStartRoutine(Protocol, IMS_NEXT_HEADER_PROCESSOR);

    return STATUS_SUCCESS;
}


VOID
NTAPI
Ipv6pReceiveHopByHopOptions(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    PIP_RECEIVE_DEMUX Demux = Args->Compartment->Protocol->ReceiveDemux;
    PIP_REQUEST_CONTROL_DATA Control;
    PNET_BUFFER_LIST NetBufferList;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram;
    IPV6_EXTENSION_HEADER ExtensionHeaderBuffer, *ExtensionHeader;
    ULONG HeaderLength;
    
    for (Control = Args; Control != NULL; Control = Control->Next) {
        NetBufferList = Control->NetBufferList;
        ReceiveDatagram = &Control->NlcReceiveDatagram;

        if ((NetBufferList == NULL) ||
            (!NT_SUCCESS(NetBufferList->Status)) ||
            (!Demux[ReceiveDatagram->NextHeaderValue].IsExtensionHeader)) {
            //
            // Skip datagrams with errors or upper layer extension headers. 
            //
            continue;
        }
        
        if (ReceiveDatagram->NextHeaderValue != IPPROTO_HOPOPTS) {
            break;
        }

        //
        // The HopByHop Options header, when present,
        // must immediately follow the IPv6 header.
        //
        if (ReceiveDatagram->NetworkLayerHeadersSize != sizeof(IPV6_HEADER)) {
            ReceiveDatagram->NextHeaderValue = IPPROTO_NONE;
            NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;

            IppSendError(
                FALSE, 
                &Ipv6Global, 
                Control, 
                ICMP6_PARAM_PROB, 
                ICMP6_PARAMPROB_NEXTHEADER, 
                RtlUlongByteSwap(sizeof(IPV6_HEADER)),
                FALSE);
            
            continue;
        }
        
        //
        // Skip past the HopByHop options extension header.
        // It should already have been validated and processed.
        //
        ExtensionHeader =
            NetioGetDataBuffer(
                NetBufferList->FirstNetBuffer,
                sizeof(IPV6_EXTENSION_HEADER),
                &ExtensionHeaderBuffer,
                __builtin_alignof(IPV6_EXTENSION_HEADER),
                0);
        ASSERT(ExtensionHeader != NULL);

        Control->NextHeaderPosition = 
            ReceiveDatagram->NetworkLayerHeadersSize + 
            FIELD_OFFSET(IPV6_EXTENSION_HEADER, NextHeader);
    
        HeaderLength = IPV6_EXTENSION_HEADER_LENGTH(ExtensionHeader->Length);
        ASSERT(HeaderLength <= NetBufferList->FirstNetBuffer->DataLength);
        
        NetioAdvanceNetBufferList(NetBufferList, HeaderLength);
        ReceiveDatagram->NetworkLayerHeadersSize += HeaderLength;
        
        ReceiveDatagram->NextHeaderValue = ExtensionHeader->NextHeader;
        
        ASSERT(NetBufferList->Status == STATUS_MORE_ENTRIES);
    }
}

VOID
NTAPI
Ipv6pReceiveDestinationOptions(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    PIP_RECEIVE_DEMUX Demux = Args->Compartment->Protocol->ReceiveDemux;
    PIP_REQUEST_CONTROL_DATA Control;
    PNET_BUFFER_LIST NetBufferList;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram;
        
    for (Control = Args; Control != NULL; Control = Control->Next) {
        NetBufferList = Control->NetBufferList;
        ReceiveDatagram = &Control->NlcReceiveDatagram;

        if ((NetBufferList == NULL) ||
            (!NT_SUCCESS(NetBufferList->Status)) ||
            (!Demux[ReceiveDatagram->NextHeaderValue].IsExtensionHeader)) {
            //
            // Skip datagrams with errors or upper layer extension headers. 
            //
            continue;
        }
        
        if (ReceiveDatagram->NextHeaderValue != IPPROTO_DSTOPTS) {
            break;
        }

        Control->NextHeaderPosition = 
            ReceiveDatagram->NetworkLayerHeadersSize + 
            FIELD_OFFSET(IPV6_EXTENSION_HEADER, NextHeader);
        
        //
        // Validate the destination options. 
        //
        (VOID) Ipv6pProcessOptions(Control);
    }
}


VOID
NTAPI
Ipv6pReceiveRoutingHeader(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:

    Handle the IPv6 Routing Header.  
    Compare RoutingReceive() in the XP IPv6 stack.

Arguments:

    Args - Supplies a batch of packets to process.

--*/
{
    PIP_RECEIVE_DEMUX Demux = Ipv6Global.ReceiveDemux;
    PIP_REQUEST_CONTROL_DATA Control, CloneControl;
    PNET_BUFFER_LIST NetBufferList, CloneNetBufferList;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram;
    IPV6_ROUTING_HEADER RoutingHeaderBuffer, *RoutingHeader;
    PIPV6_ROUTING_HEADER ForwardRoutingHeader;

    PIP_COMPARTMENT Compartment = Args->Compartment;
    ULONG HeaderLength;
    ULONG SegmentsLeft, NumAddresses, HeaderOffset, i, BytesToCopy;

    PIP_LOCAL_ADDRESS LocalAddress;
    PIP_INTERFACE Interface;
    PIP_PATH Path;
    PIP_NEXT_HOP NextHop = NULL;
    NTSTATUS Status;

    IN6_ADDR *NewDestination, NewDestinationBuffer;
    SIZE_T BytesCopied;
    PIPV6_HEADER ForwardIpHeader;
    IP_DISCARD_REASON DiscardReason;
    BOOLEAN DispatchLevel = FALSE;
    
    for (Control = Args; Control != NULL; Control = Control->Next) {
        NetBufferList = Control->NetBufferList;
        ReceiveDatagram = &Control->NlcReceiveDatagram;
        
        if ((NetBufferList == NULL) ||
            (!NT_SUCCESS(NetBufferList->Status)) ||
            (!Demux[ReceiveDatagram->NextHeaderValue].IsExtensionHeader)) {
            //
            // Skip datagrams with errors or upper layer extension headers. 
            //
            continue;
        }
        
        if (ReceiveDatagram->NextHeaderValue != IPPROTO_ROUTING) {
            break;
        }

        if (Ipv6Global.SourceRoutingBehavior == SourceRoutingDrop) {
            goto Drop;
        }
    
        //
        // Validate the routing header.
        //
        RoutingHeader =
            NetioGetDataBuffer(
                NetBufferList->FirstNetBuffer,
                sizeof(RoutingHeaderBuffer),
                &RoutingHeaderBuffer,
                __builtin_alignof(IPV6_ROUTING_HEADER),
                0);
        if (RoutingHeader == NULL) {
            if (NetBufferList->FirstNetBuffer->DataLength <
                sizeof(*RoutingHeader)) {
                IppSendError(
                    DispatchLevel, 
                    &Ipv6Global, 
                    Control, 
                    ICMP6_PARAM_PROB, 
                    ICMP6_PARAMPROB_HEADER, 
                    RtlUlongByteSwap(FIELD_OFFSET(IPV6_HEADER, PayloadLength)),
                    FALSE);
            }
            goto Drop;
        }
        
        HeaderLength = IPV6_EXTENSION_HEADER_LENGTH(RoutingHeader->Length);
        if (NetBufferList->FirstNetBuffer->DataLength < HeaderLength) {
                IppSendError(
                    DispatchLevel, 
                    &Ipv6Global, 
                    Control, 
                    ICMP6_PARAM_PROB, 
                    ICMP6_PARAMPROB_HEADER, 
                    RtlUlongByteSwap(
                        sizeof(IPV6_HEADER) +
                        FIELD_OFFSET(IPV6_ROUTING_HEADER, Length)),
                    FALSE);
            goto Drop;
        }

        Control->ReceiveRoutingHeaderOffset = 
            (UINT8) (Control->NlcReceiveDatagram.NetworkLayerHeadersSize -
                     sizeof(IPV6_HEADER));

        Control->ReceiveRoutingHeaderLength = HeaderLength;

        Control->NextHeaderPosition = 
            ReceiveDatagram->NetworkLayerHeadersSize + 
            FIELD_OFFSET(IPV6_ROUTING_HEADER, NextHeader);

        //
        // If SegmentsLeft is zero, we proceed directly to the next header.
        // We must not check the Type value or HeaderLength.
        //
        SegmentsLeft = RoutingHeader->SegmentsLeft;
        if (SegmentsLeft == 0) {
            ReceiveDatagram->NextHeaderValue = RoutingHeader->NextHeader;
            ASSERT(NetBufferList->Status == STATUS_MORE_ENTRIES);
            NetioAdvanceNetBufferList(NetBufferList, HeaderLength);
            ReceiveDatagram->NetworkLayerHeadersSize += HeaderLength;
            continue;
        }

        //
        // Move past the routing header.
        // We need to do this now so subsequent ICMP error generation works.
        //
        NetioAdvanceNetBufferList(NetBufferList, sizeof(*RoutingHeader));
        HeaderOffset = ReceiveDatagram->NetworkLayerHeadersSize;
        ReceiveDatagram->NetworkLayerHeadersSize += sizeof(*RoutingHeader);

        //
        // If we do not recognize the Type value, generate an ICMP error.
        //
        if (RoutingHeader->RoutingType != 0) {
            IppSendError(
                DispatchLevel,
                &Ipv6Global,
                Control,
                ICMP6_PARAM_PROB,
                ICMP6_PARAMPROB_HEADER,
                RtlUlongByteSwap(
                    HeaderOffset + 
                    FIELD_OFFSET(IPV6_ROUTING_HEADER, RoutingType)),
                FALSE);
            goto Drop;
        }

        //
        // We must have an integral number of IPv6 addresses
        // in the routing header.
        //
        if (RoutingHeader->Length & 1) {
            IppSendError(
                DispatchLevel,
                &Ipv6Global,
                Control,
                ICMP6_PARAM_PROB,
                ICMP6_PARAMPROB_HEADER,
                RtlUlongByteSwap(
                    HeaderOffset + FIELD_OFFSET(IPV6_ROUTING_HEADER, Length)),
                FALSE);
            goto Drop;
        }

        NumAddresses = RoutingHeader->Length / 2;

        //
        // Sanity check SegmentsLeft.
        //
        if (SegmentsLeft > NumAddresses) {
            IppSendError(
                DispatchLevel,
                &Ipv6Global,
                Control,
                ICMP6_PARAM_PROB,
                ICMP6_PARAMPROB_HEADER,
                RtlUlongByteSwap(
                    HeaderOffset +
                    FIELD_OFFSET(IPV6_ROUTING_HEADER, SegmentsLeft)),
                FALSE);
            goto Drop;
        }

        //
        // Sanity check the destination address.
        // Packets carrying a Type 0 Routing Header must not
        // be sent to a multicast destination.
        //
        if (Control->CurrentDestinationType != NlatUnicast) {
            //
            // Just drop the packet, no ICMP error in this case.
            //
            goto Drop;
        }

        i = NumAddresses - SegmentsLeft;
        if (i > 0) {
            ULONG Offset = i * sizeof(IN6_ADDR);

            NetioAdvanceNetBufferList(NetBufferList, Offset);
            ReceiveDatagram->NetworkLayerHeadersSize += Offset;
        }
        NewDestination =
            NetioGetDataBuffer(
                NetBufferList->FirstNetBuffer,
                sizeof(NewDestinationBuffer),
                &NewDestinationBuffer,
                __builtin_alignof(IN6_ADDR),
                0);
        if (NewDestination == NULL) {
            goto Drop;
        }

        //
        // Sanity check the new destination.
        // RFC 2460 doesn't mention checking for an unspecified address,
        // but I think it's a good idea.  Similarly, for security reasons,
        // we also check the scope of the destination.  This allows
        // applications to check the scope of the eventual destination address
        // and know that the packet originated within that scope.
        // RFC 2460 says to discard the packet without an ICMP error
        // (at least when the new destination is multicast),
        // but I think an ICMP error is helpful in this situation.
        //
        if (IppIsInvalidSourceRouteDestinationAddress(
                &Ipv6Global,
                (UCHAR *) NewDestination) ||
            (Ipv6UnicastAddressScope((PUCHAR) NewDestination) <
             Ipv6UnicastAddressScope(Control->CurrentDestinationAddress))) {
            IppSendError(
                DispatchLevel,
                &Ipv6Global,
                Control,
                ICMP6_PARAM_PROB,
                ICMP6_PARAMPROB_HEADER,
                RtlUlongByteSwap(
                    HeaderOffset +
                    sizeof(IPV6_ROUTING_HEADER) + i * sizeof(IN6_ADDR)),
                FALSE);
            goto Drop;
        }

        //
        // Find a route to the new destination.  We need to constrain
        // the local address in case we end up sending an ICMP error
        // (e.g. Hop Limit Exceeded) so we respond from the address
        // the sender used.  This also ensures we don't reveal an
        // association between our temporary and public addresses.
        //
        LocalAddress = Control->DestLocalAddress;
        Interface = LocalAddress->Interface;
        if (NL_ADDRESS_TYPE(LocalAddress) != NlatUnicast) {
            LocalAddress = NULL;
        }
        
        Status =
            IppRouteToDestinationInternal(
                Compartment,
                (PUCHAR) NewDestination,
                Interface,
                LocalAddress,
                &Path);
        if (NT_SUCCESS(Status)) {
            NextHop = IppGetNextHopFromPath(Path);
            IppDereferencePath(Path);
        } else {
            NextHop = NULL;
        }

        if (NextHop == NULL) {
            IppSendError(
                DispatchLevel,
                &Ipv6Global,
                Control,
                ICMP6_DST_UNREACH,
                ICMP6_DST_UNREACH_NOROUTE,
                0,
                FALSE);

            Ipv6Global.PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                InNoRoutes += IppGetPacketCount(NetBufferList);

            goto Drop;
        }

        //
        // For security reasons, we prevent source routing
        // in some situations. Check those now.
        //
        if (Interface->Forward) {
            //
            // The interface is forwarding, so source-routing is allowed.
            //
        } else if ((Interface == NextHop->Interface) &&
                   (SegmentsLeft == 1) &&
                   IN6_ADDR_EQUAL(
                       NewDestination, 
                       (PIN6_ADDR) Control->SourceAddress.Address)) {
            //
            // Same-interface rule says source-routing is allowed,
            // because the host is not acting as a conduit
            // between two networks. See RFC 1122 section 3.3.5.
            // Furthermore, we only allow round-trip source-routing
            // because that's the only useful scenario that we know of
            // for hosts. This prevents unanticipated bad uses.
            //
        } else {
            //
            // We can not allow this use of source-routing.
            // Instead of reporting an error, we could
            // redo RouteToDestination with RTD_FLAG_STRICT
            // to constrain to the same interface.
            // However, an ICMP error is more in keeping
            // with the treatment of scoped source addresses,
            // which can produce a destination-unreachable error.
            //
            IppSendError(
                DispatchLevel,
                &Ipv6Global,
                Control,
                ICMP6_DST_UNREACH,
                ICMP6_DST_UNREACH_ADMIN,
                0,
                FALSE);
            goto Drop;
        }

        //
        // The packet has passed all our checks.
        // We can construct a revised packet for transmission.
        // First we allocate a packet, buffer, and memory.
        //
        NetioAdvanceNetBufferList(NetBufferList, sizeof(IN6_ADDR));
        ReceiveDatagram->NetworkLayerHeadersSize += sizeof(IN6_ADDR);

        CloneNetBufferList =
            NetioAllocateAndReferenceCloneNetBufferList(
                NetBufferList,
                DispatchLevel);
        if (CloneNetBufferList == NULL) {
            goto Drop;
        }

        IppCopyNetBufferListInfo(CloneNetBufferList, NetBufferList);

        //
        // Now we copy from the original packet to the new packet,
        // from the IP header up to the end of the current destination
        // address in the routing header.
        //
        BytesToCopy = ReceiveDatagram->NetworkLayerHeadersSize;
        Status =
            NetioRetreatNetBufferList(
                CloneNetBufferList, BytesToCopy, Interface->FlBackfill);
        if (!NT_SUCCESS(Status)) {
            NetioDereferenceNetBufferList(CloneNetBufferList, DispatchLevel);
            goto Drop;
        }

        (VOID) NetioRetreatNetBufferList(NetBufferList, BytesToCopy, 0);
        ReceiveDatagram->NetworkLayerHeadersSize = 0;

        RtlCopyMdlToMdl(
            NetBufferList->FirstNetBuffer->CurrentMdl,
            NetBufferList->FirstNetBuffer->CurrentMdlOffset,
            CloneNetBufferList->FirstNetBuffer->CurrentMdl,
            CloneNetBufferList->FirstNetBuffer->CurrentMdlOffset,
            BytesToCopy,
            &BytesCopied);
        if (BytesCopied < BytesToCopy) {
            NetioDereferenceNetBufferList(CloneNetBufferList, DispatchLevel);
            goto Drop;
        }

        //
        // Fix up the new packet.
        //
        ForwardIpHeader =
            NetioGetDataBuffer(
                CloneNetBufferList->FirstNetBuffer,
                BytesToCopy,
                NULL,
                __builtin_alignof(IPV6_HEADER),
                0);        

        //
        // Put in the new destination address.
        //
        ForwardIpHeader->DestinationAddress = *NewDestination;
        
        //
        // Update the routing header with the current destination and decrement
        // SegmentsLeft.
        // NB: We pass the Reserved field through unmodified!
        // This violates a strict reading of the spec,
        // but Steve Deering has confirmed that this is his intent.
        //
        ForwardRoutingHeader = (PIPV6_ROUTING_HEADER)
            (((PUCHAR) ForwardIpHeader) + HeaderOffset);

        RtlCopyMemory(
            ((PUCHAR) ForwardIpHeader) + BytesToCopy - sizeof(IN6_ADDR),
            Control->CurrentDestinationAddress,
            sizeof(IN6_ADDR));

        ForwardRoutingHeader->SegmentsLeft--;

        //
        // Create a new control data structure.
        //
        CloneControl = IppCopyPacket(&Ipv6Global, Control);
        if (CloneControl == NULL) {
            NetioDereferenceNetBufferList(CloneNetBufferList, DispatchLevel);
            goto Drop;
        }

        IppDereferenceLocalAddress(CloneControl->DestLocalAddress);
        CloneControl->NextHop = NextHop;
        IppReferenceNextHop(NextHop);

        CloneControl->CurrentDestinationAddress = 
            (PUCHAR) &ForwardIpHeader->DestinationAddress;
        CloneControl->CurrentDestinationType =
            Ipv6AddressType((PUCHAR) &ForwardIpHeader->DestinationAddress);
        CloneControl->IP = (PUCHAR) ForwardIpHeader;
        CloneControl->NetBufferList = CloneNetBufferList;

        //
        // Forward the packet. This decrements the Hop Limit and generates
        // any applicable ICMP errors (Time Limit Exceeded, Destination
        // Unreachable, Packet Too Big). Note that previous ICMP errors
        // that we generated were based on the unmodified incoming packet,
        // while from here on the ICMP errors are based on the new FwdPacket.
        //
        if (!IppForwardPackets(
                &Ipv6Global,
                Interface,
                NextHop->Interface,
                CloneControl,
                NULL,
                TRUE,
                FALSE,
                &DiscardReason)) {
            if (IppDiscardReceivedPackets(
                    &Ipv6Global,
                    DiscardReason,
                    CloneControl,                
                    NULL,
                    NULL) == IpDiscardAllowIcmp) {
                IppSendErrorListForDiscardReason(
                    FALSE,
                    &Ipv6Global,
                    CloneControl,
                    DiscardReason,
                    0);                    
             }
            IppCompleteAndFreePacketList(CloneControl, FALSE);                    
            goto Drop;
        }

        ReceiveDatagram->SourceRouted = TRUE;

        if (IppIsNextHopLocalAddress(NextHop)) {
            IppReceiveHeaders(&Ipv6Global, CloneControl);
        } else {
            IppFragmentPackets(&Ipv6Global, CloneControl);
        }
            
Drop:
        ReceiveDatagram->NextHeaderValue = IPPROTO_NONE;

        if (Control->NetBufferList != NULL) {
            Control->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        }

        if (NextHop != NULL) {
            IppDereferenceNextHop(NextHop);
            NextHop = NULL;
        }
    }
}

VOID
Ipv6pReceiveGenericInternalHeaderControl(
    IN PIP_REQUEST_CONTROL_DATA ControlMessage
    )
/*++

Routine Description:

    Generic routine to handle an ICMP error message in response to an IPv6
    extension header.

Arguments:

    ControlMessage - Supplies information about the message received.

Return Value:

    The Status in the NetBufferList is set to one of:

    STATUS_SUCCESS to drop the message.
    STATUS_MORE_ENTRIES if the caller should continue parsing past the
        extension header.

--*/
{
    IPV6_EXTENSION_HEADER *ExtensionHeader, ExtensionHeaderBuffer;
    ULONG HeaderLength;
    PNET_BUFFER_LIST NetBufferList = ControlMessage->NetBufferList;
    PNET_BUFFER NetBuffer = NetBufferList->FirstNetBuffer;
    
    //
    // Verify and advance past the extension header.
    //
    HeaderLength = sizeof(IPV6_EXTENSION_HEADER);
    if (NetBuffer->DataLength < HeaderLength) {
        //
        // Make the packet available to RAW sockets.
        //
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;     
    }            
    
    ExtensionHeader =
        NetioGetDataBuffer(
            NetBuffer, 
            HeaderLength, 
            &ExtensionHeaderBuffer, 
            1,
            0);
    HeaderLength =
        IPV6_EXTENSION_HEADER_LENGTH(ExtensionHeader->Length);
    
    if (NetBuffer->DataLength < HeaderLength) {
        //
        // Make the packet available to RAW sockets.
        //
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;     
    }            

    NetioAdvanceNetBuffer(NetBuffer, HeaderLength);
    ControlMessage->NlcControlMessage.NetworkLayerHeadersSize += HeaderLength;        
    ControlMessage->NlcControlMessage.NextHeaderValue = 
        ExtensionHeader->NextHeader;
    ControlMessage->NetBufferList->Status = STATUS_MORE_ENTRIES;
}
VOID
Ipv6pReceiveNoHeader(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    //
    // Complete all the packets with success.
    //
    PIP_REQUEST_CONTROL_DATA Control;
    for (Control = Args; Control != NULL; Control = Control->Next) {
        if (Args->NetBufferList != NULL) {
            Args->NetBufferList->Status = STATUS_SUCCESS;
        }
    }
}
