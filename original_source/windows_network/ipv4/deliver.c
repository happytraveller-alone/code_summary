/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    deliver.c

Abstract:

    This module implements the functions of the IPv4 Next Header Processor 
    module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"

//
// Hop-by-hop options and session state for adding the router alert option to
// outgoing IGMP packets. 
//

UCHAR IgmpHopByHopOption[] = { IP_OPT_ROUTER_ALERT, 4, 0, 0 };
IP_SESSION_STATE IgmpSessionState;
INET_SS IgmpEndpointSessionState;

IP_INTERNAL_RECEIVE_DATAGRAMS Ipv4pReceiveRoutingHeader;

IP_RECEIVE_DEMUX Ipv4pRoutingHeaderDemux = {
    Ipv4pReceiveRoutingHeader,
    NULL, 
    NULL,
    NULL,
    NULL, 
    TRUE 
    };

NTSTATUS
Ipv4pStartNextHeaderProcessor(
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
    
    //
    // Add internal clients.  No lock is needed since we haven't registered our
    // network layer provider interface yet.
    //
    Status = 
        WfpAleEndpointCreationHandler(
            NULL,
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_ICMP,
            Process,
            NULL,
            NULL,
            NULL,
            &Icmpv4Demux.LocalEndpoint);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }    
    Demux[IPPROTO_ICMP] = Icmpv4Demux;
    RoInitialize(&Demux[IPPROTO_ICMP].Reference);

    IppInitializeSessionState(&IgmpSessionState);
    IgmpSessionState.HopByHopOptionsLength = sizeof(IgmpHopByHopOption);
    IgmpSessionState.HopByHopOptions = IgmpHopByHopOption;

    RtlZeroMemory(&IgmpEndpointSessionState, sizeof(INET_SS));
    IgmpEndpointSessionState.SessionState = &IgmpSessionState;

    Status = 
        WfpAleEndpointCreationHandler(
            NULL,
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_IGMP,
            Process,
            NULL,
            &IgmpEndpointSessionState,
            NULL,
            &IgmpDemux.LocalEndpoint);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }    
    Demux[IPPROTO_IGMP] = IgmpDemux;
    RoInitialize(&Demux[IPPROTO_IGMP].Reference);
    

    Demux[IPPROTO_ROUTING] = Ipv4pRoutingHeaderDemux;
    RoInitialize(&Demux[IPPROTO_ROUTING].Reference);

    Demux[IPPROTO_FRAGMENT] = Ipv4FragmentDemux;
    RoInitialize(&Demux[IPPROTO_FRAGMENT].Reference);

    Demux[IPPROTO_AH] = IpAhDemux;
    RoInitialize(&Demux[IPPROTO_AH].Reference);

    Demux[IPPROTO_ESP] = IpEspDemux;
    RoInitialize(&Demux[IPPROTO_ESP].Reference);

    Demux[IPPROTO_IP].InternalDeferredAuthenticateHeader = 
        Ipv4pDeferredAuthenticateIpv4Header;

    IppDefaultStartRoutine(Protocol, IMS_NEXT_HEADER_PROCESSOR);

    return STATUS_SUCCESS;
}


VOID
NTAPI
Ipv4pReceiveRoutingHeader(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:

    Handle the IPv4 loose and strict source routing option similar to how an
    IPv6 routing header would be processed.

Arguments:

    Args - Supplies a batch of packets to process.

--*/
{
    PIP_RECEIVE_DEMUX Demux = Ipv4Global.ReceiveDemux;
    PIP_REQUEST_CONTROL_DATA Control, CloneControl;
    PNET_BUFFER_LIST NetBufferList, CloneNetBufferList;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram;
    IPV4_ROUTING_HEADER UNALIGNED *RoutingHeader;
    IPV4_ROUTING_HEADER UNALIGNED *ForwardRoutingHeader;

    PIP_COMPARTMENT Compartment = Args->Compartment;
    ULONG OptionLength;
    ULONG HeaderOffset, BytesToCopy;
    ULONG ZeroBasedPointer;

    PIP_LOCAL_ADDRESS LocalAddress;
    PIP_INTERFACE Interface;
    PIP_PATH Path;
    PIP_NEXT_HOP NextHop = NULL;
    NTSTATUS Status;

    IN_ADDR UNALIGNED *NewDestination;
    SIZE_T BytesCopied;
    IPV4_HEADER UNALIGNED *ForwardIpHeader;
    IP_DISCARD_REASON DiscardReason;
    BOOLEAN DispatchLevel = FALSE;

    UCHAR RoutingHeaderBuffer[MAX_IP_OPTIONS_LENGTH];
    IPV4_HEADER UNALIGNED *IpHeader;    
    PNET_BUFFER NetBuffer;
    ULONG BytesToRetreat;
   
    
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

        IpHeader = (PIPV4_HEADER) Control->IP;        

        if ((IpHeader->Protocol == IPPROTO_ROUTING) ||
            (ReceiveDatagram->NetworkLayerHeadersSize != 
             Ip4HeaderLengthInBytes(IpHeader))) {
            //
            // This handler must not handle wire packets with a protocol
            // of IPPROTO_ROUTING.  It only handles IPv4 packets that have
            // source routing options detected by Ipv4pProcessOptions.
            // The IPPROTO_ROUTING value either may be in the IP header 
            // itself, or as a next header in one of the encapsulation headers.
            // The header length check covers the second case.
            //
            Control->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
            continue;
        }
        
        ASSERT(Control->ReceiveRoutingHeaderOffset > 0);

        if (Ipv4Global.SourceRoutingBehavior == SourceRoutingDrop) {
            goto Drop;
        }


        
        //
        // Get the routing header.
        // 
        NetBuffer = NetBufferList->FirstNetBuffer;
        ASSERT(Control->ReceiveRoutingHeaderOffset < NetBuffer->DataOffset);
        ASSERT(Control->NlcReceiveDatagram.NetworkLayerHeadersSize >
               Control->ReceiveRoutingHeaderOffset);

        BytesToRetreat = Control->NlcReceiveDatagram.NetworkLayerHeadersSize
            - Control->ReceiveRoutingHeaderOffset;        
        
        Status = 
            NetioRetreatNetBufferList(
                NetBufferList,
                BytesToRetreat,
                0);
        ASSERT(NT_SUCCESS(Status));

        RoutingHeader =
            NetioGetDataBuffer(
                NetBuffer,
                Control->ReceiveRoutingHeaderLength,
                RoutingHeaderBuffer,
                __builtin_alignof(IPV4_ROUTING_HEADER),
                0);

        NetioAdvanceNetBufferList(NetBufferList, BytesToRetreat);

        //
        // ASSERT: The Routing header was validated as part of the IP option
        // validation.
        //
        
        OptionLength = RoutingHeader->OptionLength;
        HeaderOffset = Control->ReceiveRoutingHeaderOffset;
        ZeroBasedPointer = RoutingHeader->Pointer - 1;

        //
        // If no addresses left we proceed directly to the next header.
        // No addresses are left if the routing header length doesn't allow for
        // even one IP address, or the zero-based pointer points past the 
        // last possible address in the option.
        //
        if ((OptionLength < (sizeof(IPV4_ROUTING_HEADER) + sizeof(IN_ADDR))) ||
            (ZeroBasedPointer > OptionLength - sizeof(IN_ADDR))) {
            ASSERT(NetBufferList->Status == STATUS_MORE_ENTRIES);
            //
            // If this is a fragmented packet the next header to process is the
            // fragment header.  Otherwise process the actual protocol.
            //
            if (IPV4_IS_FRAGMENT(IpHeader)) {           
                ReceiveDatagram->NextHeaderValue = IPPROTO_FRAGMENT;
            } else {
                ReceiveDatagram->NextHeaderValue = IpHeader->Protocol;
            }
            continue;
        }

        //
        // Sanity check the destination address.
        // Packets carrying a Routing Header must not
        // be sent to a multicast destination.
        //
        if (Control->CurrentDestinationType != NlatUnicast) {
            //
            // Just drop the packet, no ICMP error in this case.
            //
            goto Drop;
        }

        NewDestination = (PIN_ADDR) 
            (((PUCHAR) RoutingHeader) + ZeroBasedPointer);
        
        //
        // Sanity check the new destination.
        // RFC 791 doesn't mention checking for an unspecified address,
        // but we think it's a good idea. Similarly, for security reasons,
        // we also check the scope of the destination. This allows
        // applications to check the scope of the eventual destination address
        // and know that the packet originated within that scope.
        // RFC 2460 (for IPv6) says to discard the packet without an ICMP error
        // (at least when the new destination is multicast),
        // but we think an ICMP error is helpful in this situation.
        //
        // (Ipv4UnicastAddressScope will align NewDestination.)
        //
        if (IppIsInvalidSourceRouteDestinationAddress(
                &Ipv4Global,  (PUCHAR) NewDestination) ||
            (Ipv4UnicastAddressScope((PUCHAR) NewDestination) <
             Ipv4UnicastAddressScope(
                 Control->CurrentDestinationAddress))) {

            IppSendError(
                DispatchLevel,
                &Ipv4Global,
                Control,
                ICMP4_PARAM_PROB,
                0,
                RtlUlongByteSwap(
                    sizeof(IPV4_HEADER) + HeaderOffset +
                    ZeroBasedPointer),
                FALSE);
            goto Drop;
        }

        //
        // Find a route to the new destination.  We need to constrain
        // the local address in case we end up sending an ICMP error
        // (e.g. Hop Limit Exceeded) so we respond from the address
        // the sender used.
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
                &Ipv4Global,
                Control,
                ICMP4_DST_UNREACH,
                ICMP4_UNREACH_SOURCEROUTE_FAILED,
                0,
                FALSE);

            Ipv4Global.PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                InNoRoutes += IppGetPacketCount(NetBufferList);

            goto Drop;
        }

        //
        // Strict source routed packets must be on a connected network.
        //
        if (Control->StrictSourceRouted) {
            PIP_UNICAST_ROUTE Route = IppGetRouteFromPath(Path);
            if ((Route == NULL) ||
                !IppIsOnLinkRoute(Route)) { 
                IppSendError(
                    DispatchLevel,
                    &Ipv4Global,
                    Control,
                    ICMP4_DST_UNREACH,
                    ICMP4_UNREACH_SOURCEROUTE_FAILED,
                    0,
                    FALSE);
                if (Route != NULL) {
                    IppDereferenceRoute((PIP_ROUTE) Route);
                }
                Ipv4Global.
                    PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                    InNoRoutes += IppGetPacketCount(NetBufferList);
                goto Drop;
            }
            if (Route != NULL) {
                IppDereferenceRoute((PIP_ROUTE) Route);
            }                    
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
                   (RoutingHeader->OptionLength - ZeroBasedPointer ==
                    sizeof(IN_ADDR)) &&
                   IN4_UNALIGNED_ADDR_EQUAL(
                       NewDestination, 
                       (PIN_ADDR) Control->SourceAddress.Address)) {
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
                &Ipv4Global,
                Control,
                ICMP4_DST_UNREACH,
                ICMP4_UNREACH_SOURCEROUTE_FAILED,
                0,
                FALSE);
            goto Drop;
        }

        //
        // The packet has passed all our checks.
        // We can construct a revised packet for transmission.
        // First we allocate a packet, buffer, and memory.
        //

        CloneNetBufferList =
            NetioAllocateAndReferenceCloneNetBufferList(
                NetBufferList,
                DispatchLevel);
        if (CloneNetBufferList == NULL) {
            goto Drop;
        }

        IppCopyNetBufferListInfo(CloneNetBufferList, NetBufferList);

        //
        // Copy the IP header from the original packet to the new packet.
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
                __builtin_alignof(IPV4_HEADER),
                0);        

        //
        // Put in the new destination address.
        //
        ForwardIpHeader->DestinationAddress = *NewDestination;
        
        //
        // Update the routing header with the current destination and increment
        // the next address pointer.
        //
        ForwardRoutingHeader = (PIPV4_ROUTING_HEADER)
            (((PUCHAR) ForwardIpHeader) + HeaderOffset);

        RtlCopyMemory(
            ((PUCHAR) ForwardRoutingHeader) + ZeroBasedPointer,
            Control->CurrentDestinationAddress,
            sizeof(IN_ADDR));

        ForwardRoutingHeader->Pointer += sizeof(IN_ADDR);

        //
        // Create a new control data structure.
        //
        CloneControl = IppCopyPacket(&Ipv4Global, Control);
        if (CloneControl == NULL) {
            NetioDereferenceNetBufferList(CloneNetBufferList, DispatchLevel);
            goto Drop;
        }
        CloneControl->ReceiveRoutingHeaderOffset = 
            Control->ReceiveRoutingHeaderOffset;
        CloneControl->StrictSourceRouted = Control->StrictSourceRouted;

        IppDereferenceLocalAddress(CloneControl->DestLocalAddress);
        CloneControl->NextHop = NextHop;
        IppReferenceNextHop(NextHop);

        CloneControl->CurrentDestinationAddress = 
            (PUCHAR) &ForwardIpHeader->DestinationAddress;
        CloneControl->CurrentDestinationType =
            Ipv4AddressType((PUCHAR) &ForwardIpHeader->DestinationAddress);
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
                &Ipv4Global,
                Interface,
                NextHop->Interface,
                CloneControl,
                NULL,
                TRUE,
                CloneControl->StrictSourceRouted,
                &DiscardReason)) {
            if (IppDiscardReceivedPackets(
                    &Ipv4Global,
                    DiscardReason,
                    CloneControl,                
                    NULL,
                    NULL) == IpDiscardAllowIcmp) {
                IppSendErrorListForDiscardReason(
                    FALSE,
                    &Ipv4Global,
                    CloneControl,
                    DiscardReason,
                    0);            
            }
            IppCompleteAndFreePacketList(CloneControl, FALSE);                    
            goto Drop;
        }

        ReceiveDatagram->SourceRouted = TRUE;

        if (IppIsNextHopLocalAddress(NextHop)) {
            //
            // If this is a fragmented packet the next header to process is the
            // fragment header.  Otherwise, receive it like a normal packet.
            //
            if ((Ip4FragmentOffset(ForwardIpHeader) != 0) || 
                ForwardIpHeader->MoreFragments) {           
                
                ReceiveDatagram->NextHeaderValue = IPPROTO_FRAGMENT;
                
                continue;
            } else {
                IppReceiveHeaders(&Ipv4Global, CloneControl);
            }           
        } else {
            IppFragmentPackets(&Ipv4Global, CloneControl);
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

