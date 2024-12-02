/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    router.c

Abstract:

    This module contains the IPv4 Router Discovery Algorithm [RFC 1256].
    
Author:

    Mohit Talwar (mohitt) Mon Aug 19 18:36:22 2002

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "router.tmh"

VOID
Ipv4pResetAutoConfiguredRoutes(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    )
/*++

Routine Description:

    Reset the lifetimes of auto configured routes. 

Arguments:

    Interface - Supplies the interface on which to reset the lifetimes.
    
    Lifetime - Supplies the new value of the lifetime.

Return Value:

    None.

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    ULONG Count;
    PREFIX_TREE_CONTEXT Context;
    PIPR_LINK Link;
    PUCHAR Key;
    USHORT KeyLength;
    PIP_UNICAST_ROUTE Route, NextRoute;
    BOOLEAN RouteDeleted = FALSE;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    //
    // Lock the route set for updating the lifetimes.
    // 
    RtlAcquireScalableWriteLock(&RouteSet->Lock, &LockHandle);
    
    //
    // Now we scan the routing table looking for routes configured via router 
    // advertisements.
    //
    RtlZeroMemory(&Context, sizeof(Context));
    Count = 1;
    
    do {
        Status = PtEnumOverTable(
            RouteSet->Tree, NULL, NULL, &Context, NULL, 0, &Count, &Link);

        if (Count == 0) {
            break;
        }

        PtGetKey(Link, &Key, &KeyLength);

        //
        // Update the lifetime of the routes and delete them if required.
        //
        Route = CONTAINING_RECORD(Link, IP_UNICAST_ROUTE, Link);
        
        //
        // Walk the chain of routes per AVL_NODE.
        //
        for (; Route != NULL; Route = NextRoute) {
            NextRoute = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
                Route->RouteLink.Flink, IP_UNICAST_ROUTE, RouteLink);
            if (PtGetData(&Route->Link) == &NextRoute->Link) {
                NextRoute = NULL;
            }
            
            if ((Route->Origin == NlroRouterAdvertisement) &&
                (Route->Interface == Interface)) {
                if (Lifetime == 0) {
                    //
                    // Delete the route. 
                    //
                    Route->ValidLifetime = 0;
                    IppDeleteUnicastRoute(Compartment, Route);
                    RouteDeleted = TRUE;
                } else {
                    IppUpdateUnicastRouteLifetimes(RouteSet, Route);
                    if (Route->ValidLifetime > Lifetime) {
                        Route->ValidLifetime = Lifetime;
                        if (Route->ValidLifetime < Route->PreferredLifetime) {
                            Route->PreferredLifetime = Route->ValidLifetime;
                        }
                        IppRefreshUnicastRoute(Compartment, Route);
                    }
                }
            }
        }
        
    } while (Status != STATUS_NO_MORE_MATCHES);

    if (RouteDeleted) {
        //
        // A route was deleted.  Invalidate all cached paths.
        //
        IppInvalidateDestinationCache(Compartment);
    }
    
    RtlReleaseScalableWriteLock(&RouteSet->Lock, &LockHandle);
}

VOID
Ipv4pResetAutoConfiguredSettings(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    )
/*++

Routine Description:

    Reset the lifetimes of auto configured routes, addresses and interface 
    parameters. 

Arguments:

    Interface - Supplies the interface on which to reset the lifetimes.
    
    Lifetime - Supplies the new value of the lifetime.

Return Value:

    None.
    
Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{  
    //
    // Remove auto-configured route lifetimes.
    //
    Ipv4pResetAutoConfiguredRoutes(Interface, Lifetime);
        
}

PICMPV4_ROUTER_ADVERT_HEADER
Ipv4pAllocateAndPrepareRouterAdvertisementHeader(
    OUT PUCHAR* Buffer,
    OUT PNET_BUFFER_LIST *NetBufferList,
    IN ULONG Offset,
    IN ULONG Length,
    IN USHORT RouterLifetime
    )
/*++

Routine Description:

    Allocate a NetBufferList (including NetBuffer, MDL, and Buffer) to describe
    a packet of the specified Offset + Length.
    Also, initialize the IPv4 router advertisement header.

Arguments:

    Buffer - On success, will have the pointer to next byte to write.
        Otherwise, NULL is returned.

    NetBufferList - On success, will have the pointer to the net buffer list
        allocated. Otherwise, NULL is returned.

    Offset - Supplies the required offset within the allocated Buffer.

    Length - Supplies the length of the allocated buffer, starting from Offset.
    
    RouterLifetime - Router life time of the router addresses we advertise.
        It should be in network byte order.

Return Value:

    On success, will return the pointer to the router advertisement header.
    Otherwise, NULL is returned.

Caller IRQL:

    Passive through Dispatch level.

Caller Lock:

    No lock is required.
--*/
{
    NTSTATUS Status;
    PICMPV4_ROUTER_ADVERT_HEADER Advertisement;
    PUCHAR NextByte;
    
    Status = IppNetAllocate(NetBufferList, &NextByte, Offset, Length);
    if (!NT_SUCCESS(Status)) {
        *Buffer = NULL;
        return NULL;
    }

    //
    // Prepare the Router Advertisement header.
    // We fill in the RouterLifetime and DefaultRouteMetric later.
    //
    ASSERT(Length >= sizeof(ICMPV4_ROUTER_ADVERT_HEADER));
    Advertisement = (ICMPV4_ROUTER_ADVERT_HEADER*) NextByte;
    RtlZeroMemory(Advertisement, sizeof(*Advertisement));
    Advertisement->RaType = ICMP4_ROUTER_ADVERT;
    // Advertisement->RaCode = 0;
    // Advertisement->RaCksum = 0;
    // Advertisement->RaNumAddr = 0;
    Advertisement->RaAddrEntrySize = 2;
    Advertisement->RaAddrLifetime = RouterLifetime;
    
    NextByte += sizeof(*Advertisement);
    *Buffer = NextByte;
    return Advertisement;
}


VOID
Icmpv4SendRouterSolicitationOnSubInterface(
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_LOCAL_UNICAST_ADDRESS Source OPTIONAL
    )
/*++

Routine Description:

    Send a Router Solicitation message.
    The solicitation is always sent to the all-routers multicast address.

Arguments:

    SubInterface - Supplies the subinterface to send the solicitation on.

    Source - Supplies the source address to use for the Router Solicitation.
        If NULL, the solicitation is sent from the unspecified address.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;
    PIP_INTERFACE Interface = SubInterface->Interface;
    USHORT Backfill = (Interface->FlBackfill + sizeof(IPV4_HEADER));
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    ICMPV4_ROUTER_SOLICIT UNALIGNED *Solicitation;
    PUCHAR NlDestination;
    
    DISPATCH_CODE();

    ASSERT(Interface->UseRouterDiscovery);

    if (Interface->UseBroadcastForRouterDiscovery) {
        NlDestination = (PUCHAR) &in4addr_broadcast;
    } else {
        NlDestination = (PUCHAR) &in4addr_allroutersonlink;
    }
    
    //
    // Allocate a packet for the Router Solicitation message.
    //
    Status =
        IppNetAllocate(
            &NetBufferList,
            &Buffer,
            Backfill,
            sizeof(ICMPV4_ROUTER_SOLICIT));
    if (!NT_SUCCESS(Status)) {
        return;
    }

    //
    // Fill the Router Solicitation header and the SLLA option.
    // 
    Solicitation = (ICMPV4_ROUTER_SOLICIT UNALIGNED *) Buffer;
    Solicitation->RsType = ICMP4_ROUTER_SOLICIT;
    Solicitation->RsCode = 0;
    Solicitation->RsCksum = 0;
    Solicitation->RsReserved = 0;

    //
    // Send the ICMPv4 Router Solicitation Message.
    //
    IppSendDirect(
        Interface, 
        SubInterface,
        NULL,
        Source,
        NlDestination, 
        IPPROTO_ICMP,                       
        NULL,                               
        FIELD_OFFSET(ICMPV4_ROUTER_SOLICIT, RsCksum),
        NetBufferList);

    IppUpdateIcmpOutStatistics(&Ipv4Global, ICMP4_ROUTER_SOLICIT);
}

VOID
Icmpv4SendRouterSolicitationOnAllSubInterfaces(
    IN PIP_INTERFACE Interface,
    IN PIP_LOCAL_UNICAST_ADDRESS Source OPTIONAL
    )
/*++

Routine Description:

    Send a Router Solicitation message.
    The solicitation is always sent to the all-routers multicast address.
    
Arguments:

    Interface - Supplies the interface to send the solicitation on.
    
    Source - Supplies the source address to use for the Router Solicitation.
        If NULL, the solicitation is sent from the unspecified address.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    IF_LUID OldLuid = {0};
    PIP_SUBINTERFACE SubInterface = NULL;

    ASSERT(Interface->UseRouterDiscovery);

    for (;;) {
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 
                                                         &OldLuid, 
                                                         SubInterface);
        if (SubInterface == NULL) {
            break;
        }
        OldLuid = SubInterface->Luid;

        Icmpv4SendRouterSolicitationOnSubInterface(SubInterface, Source);
    }
}

VOID
Icmpv4SendRouterAdvertisementOnSubInterface(
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_LOCAL_UNICAST_ADDRESS Source,
    IN CONST UCHAR *Destination
    )
/*++

Routine Description:

    Send a Router Advertisement message.

Arguments:

    SubInterface - Supplies the subinterface to send the advertisement on.

    Source - Supplies the source address to use for the Router Advertisement.

    Destination - Supplies the destination address of the Router Advertisement.

Return Value:

    None.

Caller IRQL: PASSIVE through DISPATCH level.

--*/
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    USHORT FlDataBackfill, Backfill;
    ULONG Mtu;
    BOOLEAN Forward;
    USHORT Size, AvailableSize;
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    BOOLEAN FoundDefaultRoute;
    ULONG RouterLifetime, DefaultRouteMetric; 
    ICMPV4_ROUTER_ADVERT_HEADER UNALIGNED *Advertisement;
    ICMPV4_ROUTER_ADVERT_ENTRY UNALIGNED * AdvertisementEntry;
    PREFIX_TREE_CONTEXT Context;
    PPREFIX_TREE_LINK Link;
    ULONG Count;
    PUCHAR Key;
    USHORT KeyLength;
    UINT8 PrefixLength;
    PIP_UNICAST_ROUTE Route, NextRoute, RouteList;
    NTSTATUS Status;
    PIP_LOCAL_UNICAST_ADDRESS LocalUnicastAddress = NULL;
    PIPR_LOCKED_SET RouteSet;
    KIRQL OldIrql;
    
    ASSERT(Source != NULL);
    ASSERT(Interface->UseRouterDiscovery);
    
    //
    // For consistency, capture some volatile information in locals.
    //
    FlDataBackfill = Interface->FlBackfill;
    Forward = (BOOLEAN) Interface->Forward;
    Backfill = FlDataBackfill + sizeof(IPV4_HEADER);
    Mtu = SubInterface->NlMtu;

    //
    // Determine the buffer size for the advertisement.  We typically do not
    // use the entire buffer, but briefly allocating a large buffer is okay.
    //
    Size = FlDataBackfill + Mtu;
    AvailableSize =
        max((Size - Backfill), 
            sizeof(*Advertisement) + sizeof(*AdvertisementEntry));
    
    //
    // Unless explicitly configured to advertise self as a default router,
    // we fill in the RouterLifetime and DefaultRouteMetric later.
    //
    if (Interface->AdvertiseDefaultRoute) {
        FoundDefaultRoute = TRUE;
        RouterLifetime = INFINITE_LIFETIME;
        DefaultRouteMetric = RouteMetricMedium;
    } else {
        FoundDefaultRoute = FALSE;
        RouterLifetime = 0;
        DefaultRouteMetric = (ULONG) RouteMetricInvalid;
    }
    
    //
    // Loop through the route table to obtain the
    // RouterLifetime and DefaultRouteMetric.
    //
    RouteSet = &Interface->Compartment->RouteSet;
    RtlAcquireScalableReadLock(&RouteSet->Lock, &OldIrql);
    
    RtlZeroMemory(&Context, sizeof(Context));
    Count = 1;

    do {
        Status =
            PtEnumOverTable(
                RouteSet->Tree, NULL, NULL, &Context, NULL, 0, &Count, &Link);

        if (Count == 0) {
            break;
        }

        PtGetKey(Link, &Key, &KeyLength);
        if (KeyLength <= RTL_BITS_OF(IN_ADDR)) {
            PrefixLength = (UINT8) KeyLength;
        } else {
            PrefixLength = RTL_BITS_OF(IN_ADDR);
        }

        //
        // Get router preference and router lifetime from published default
        // route on this interface.
        //
        Route = CONTAINING_RECORD(Link, IP_UNICAST_ROUTE, Link);
        RouteList = Route;
                
        //
        // Walk the chain of routes per AVL_NODE.
        //
        do {
            NextRoute = (PIP_UNICAST_ROUTE)
                CONTAINING_RECORD(
                    Route->RouteLink.Flink,
                    IP_UNICAST_ROUTE,
                    RouteLink);
        
            if ((Route->Flags.Publish) && 
                (PrefixLength == 0) && 
                (Route->Interface != Interface)) {
            
                FoundDefaultRoute = TRUE;

                if (Route->ValidLifetime > RouterLifetime) {
                    RouterLifetime = Route->ValidLifetime;
                }
                
                if (Route->Metric < DefaultRouteMetric) {
                    DefaultRouteMetric = Route->Metric;
                }
            }
            
            Route = NextRoute;
        } while (NextRoute != RouteList);        
    } while (Status != STATUS_NO_MORE_MATCHES);
    
    RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);

    //
    // If there is no default route, we will not send any router advertisement.
    //
    if (FoundDefaultRoute == FALSE) {
        return;
    }

    //
    // Allocate a packet for the Router Advertisement message.
    //
    Advertisement =
        Ipv4pAllocateAndPrepareRouterAdvertisementHeader(
            &Buffer, 
            &NetBufferList,
            Backfill, 
            AvailableSize, 
            RtlUshortByteSwap((USHORT) RouterLifetime));
    if (Advertisement == NULL) {
        return;
    }
    AvailableSize -= sizeof(*Advertisement);

    //
    // We can update the LastRouterAdvertisement now that we are past all the
    // error conditions. 
    //
    Interface->LastRouterAdvertisement = IppTickCount;

    Status = IppGetFirstUnicastAddress(Interface, &LocalUnicastAddress);
    
    while (NT_SUCCESS(Status)) {
        IN_ADDR PrevAddress;
        
        if (AvailableSize < sizeof(*AdvertisementEntry)) {
            //
            // Send out the current packet and get another
            // buffer to send the rest of addresses.
            //
            NetioTruncateNetBuffer(
                NetBufferList->FirstNetBuffer,
                NetBufferList->FirstNetBuffer->DataLength - 
                (USHORT) (Buffer - (PUCHAR)Advertisement));
            
            IppSendDirect(
                Interface, 
                SubInterface,
                NULL,
                Source,
                Destination,
                IPPROTO_ICMP,
                &Advertisement->RaType,
                FIELD_OFFSET(ICMPV4_ROUTER_ADVERT_HEADER, RaCksum),
                NetBufferList);

            IppUpdateIcmpOutStatistics(&Ipv4Global, ICMP4_ROUTER_ADVERT);
            
            //
            // Allocate another packet to send.
            //
            AvailableSize =
                max((Size - Backfill), 
                    sizeof(*Advertisement) + sizeof(*AdvertisementEntry));
            Advertisement =
                Ipv4pAllocateAndPrepareRouterAdvertisementHeader(
                    &Buffer, 
                    &NetBufferList,
                    Backfill, 
                    AvailableSize, 
                    RtlUshortByteSwap((USHORT) RouterLifetime));
            if (Advertisement == NULL) {
                IppDereferenceLocalUnicastAddress(LocalUnicastAddress);
                return;
            }
            AvailableSize -= sizeof(*Advertisement);
        }
        //
        // Fill in the entry.
        //
        AdvertisementEntry = (PICMPV4_ROUTER_ADVERT_ENTRY)Buffer;
        AdvertisementEntry->RouterAdvertAddr = 
            *((PIN_ADDR) NL_ADDRESS(LocalUnicastAddress));

        //
        // ICMPv4 router advertisement's preference level is a LONG value. 
        // Bigger value means more preferable. For route preference level,
        // smaller value is more preferable and it is a ULONG value.
        // Following does the conversion.
        //
        AdvertisementEntry->PreferenceLevel = 
            RtlUlongByteSwap(MAXLONG - DefaultRouteMetric);
        RtlCopyMemory(
            &PrevAddress,
            NL_ADDRESS(LocalUnicastAddress),
            sizeof(IN_ADDR));
        IppDereferenceLocalUnicastAddress(LocalUnicastAddress);
        
        Advertisement->RaNumAddr++;
        LocalUnicastAddress = NULL;
        AvailableSize -= sizeof(*AdvertisementEntry);
        Buffer += sizeof(*AdvertisementEntry);
        //
        // Get next local unicast address.
        //
        Status =
            IppGetNextUnicastAddress(
                Interface, 
                (CONST UCHAR*)&PrevAddress,
                &LocalUnicastAddress);            
    }

    //
    // Send out the last packet.
    //
    NetioTruncateNetBuffer(
        NetBufferList->FirstNetBuffer,
        NetBufferList->FirstNetBuffer->DataLength - 
        (USHORT) (Buffer - (PUCHAR)Advertisement));
    
    IppSendDirect(
        Interface, 
        SubInterface,
        NULL,
        Source,
        Destination,
        IPPROTO_ICMP,
        &Advertisement->RaType,
        FIELD_OFFSET(ICMPV4_ROUTER_ADVERT_HEADER, RaCksum),
        NetBufferList);

    IppUpdateIcmpOutStatistics(&Ipv4Global, ICMP4_ROUTER_ADVERT);
}

VOID
Icmpv4SendRouterAdvertisementOnAllSubInterfaces(
    IN PIP_INTERFACE Interface,
    IN PIP_LOCAL_UNICAST_ADDRESS Source,
    IN CONST IN_ADDR *Destination
    )
/*++

Routine Description:

    Send a Router Advertisement message.

Arguments:

    Interface - Supplies the interface to send the advertisement on.
    
    Source - Supplies the source address to use for the Router Advertisement.

    Destination - Supplies the destination address of the Router Advertisement.
    
Return Value:

    None.

Caller IRQL: PASSIVE through DISPATCH level.

--*/
{
    IF_LUID OldLuid = {0};
    PIP_SUBINTERFACE SubInterface = NULL;

    ASSERT(Source != NULL);
    ASSERT(Interface->UseRouterDiscovery);

    for (;;) {
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 
                                                         &OldLuid, 
                                                         SubInterface);
        if (SubInterface == NULL) {
            break;
        } 
        OldLuid = SubInterface->Luid; 
        
        Icmpv4SendRouterAdvertisementOnSubInterface(SubInterface,
                                                    Source,
                                                    (CONST UCHAR *)Destination);
    }
}

VOID
Icmpv4HandleRouterAdvertisement(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN IP_REQUEST_CONTROL_DATA *Args
    )
/*++

Routine Description:

    Validate and Process an IPv4 Router Advertisement Message.
    
    Update Default Router list.
    
Arguments:

    Icmpv4 - Supplies the parsed ICMPv4 header.
    

    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv4 Router Advertisement packet,
        with the packet offset at the start of the advertisement header.

    Interface - Supplies the interface over which the packet was received.

    RemoteAddress - Supplies the source address of the packet.
    
Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    PIP_INTERFACE Interface = Args->DestLocalAddress->Interface;
    ICMPV4_ROUTER_ADVERT_HEADER UNALIGNED *Advertisement;
    ULONG RouterLifetime;
    PIP_NEXT_HOP NextHop;
    NTSTATUS Status;
    UINT8 NumberOfAddresses;
    UINT8 AddrEntrySize;
    UINT8 Count;
    ICMPV4_ROUTER_ADVERT_ENTRY RouterAdvertEntryBuffer, *RouterAdvertEntry;
    IP_PATH_FLAGS Constrained;
    IN_ADDR RouterAddress;
    LONG PreferenceLevel;
    BOOLEAN UpdateInterface = TRUE;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    ASSERT(Icmpv4->Header.Type == ICMP4_ROUTER_ADVERT);
    ASSERT(NetBuffer->Next == NULL);
    ASSERT(Args->NetBufferList->Next == NULL);

    DISPATCH_CODE();
    
    //
    // Validate the Router Advertisement.
    // We need to validate ICMP code, Num Addrs and Addr Entry Size.
    // See RFC 1256 section 5.2.
    //

    if (Icmpv4->Header.Code != 0) {
        //
        // Bogus/corrupted Router Advertisement message.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    Advertisement = (PICMPV4_ROUTER_ADVERT_HEADER)Icmpv4;
    
    //
    // Message validation according to RFC 1256.
    //
    NumberOfAddresses = Advertisement->RaNumAddr;
    AddrEntrySize = Advertisement->RaAddrEntrySize;
    RouterLifetime = RtlUshortByteSwap(Advertisement->RaAddrLifetime);
    RouterLifetime = IppSecondsToTicks(RouterLifetime);
        
    if ((NumberOfAddresses < 1) || (AddrEntrySize < 2)) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV4_MESSAGE));
    Args->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(ICMPV4_MESSAGE);
    
    //
    // Verify this router advertisement has all the data it declared in the
    // message header.
    //
    if (NetBuffer->DataLength < 
        (NumberOfAddresses * AddrEntrySize * sizeof(UINT32))) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Ignore the advertisement if this is an advertising interface.
    // We do this early on to avoid unnecessary parsing due to DoS attack 
    // concerns.
    //
    RtlAcquireReadLockAtDpcLevel(&Interface->Lock);
    if ((Interface->Advertise) || (!Interface->UseRouterDiscovery)) {
        RtlReleaseReadLockFromDpcLevel(&Interface->Lock);
        goto Done;
    }
    RtlReleaseReadLockFromDpcLevel(&Interface->Lock);
    
    //
    // We need to parse the address and update the default router list.
    //    
    for (Count = 0; Count < NumberOfAddresses; Count++) {       
        RouterAdvertEntry = 
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(ICMPV4_ROUTER_ADVERT_ENTRY), 
                &RouterAdvertEntryBuffer,
                __builtin_alignof(ICMPV4_ROUTER_ADVERT_ENTRY),
                0);
        
        RouterAddress = RouterAdvertEntry->RouterAdvertAddr;
        PreferenceLevel = RtlUlongByteSwap(RouterAdvertEntry->PreferenceLevel);
        
        NetioAdvanceNetBuffer(
            NetBuffer, 
            AddrEntrySize * sizeof(UINT32));
        Args->NlcReceiveDatagram.NetworkLayerHeadersSize += 
            sizeof(ICMPV4_ROUTER_ADVERT_ENTRY);

        //
        // Check to make sure the advertised router address is on the same
        // subnet.  Be careful not to create a path. 
        //
        Status =
            IppFindNextHopAtDpc(
                Interface->Compartment, 
                (CONST UCHAR *) &RouterAddress,
                NULL, 
                Interface, 
                IppGetScopeId(Interface, (CONST UCHAR *) &RouterAddress),
                &NextHop,
                &Constrained,
                NULL);
        if (!NT_SUCCESS(Status)) {
            continue;
        }

        if (!IppIsNextHopNeighbor(NextHop) ||
            !IN4_ADDR_EQUAL(
                &RouterAddress, 
                (CONST IN_ADDR*)
                IP_NEIGHBOR_NL_ADDRESS((PIP_NEIGHBOR) NextHop))) {
            //
            // This address is not on the same link as this interface.
            // Ignore it.
            //
            IppDereferenceNextHop(NextHop);
            continue;
        }

        if (UpdateInterface) {
            UpdateInterface = FALSE; 
    
            RtlAcquireWriteLockAtDpcLevel(&Interface->Lock, &LockHandle);

            //
            // Make sure that the interface settings did not change. This is 
            // just a sanity check.
            //
            if ((Interface->Advertise) || (!Interface->UseRouterDiscovery)) {
                RtlReleaseWriteLockFromDpcLevel(&Interface->Lock, &LockHandle);
                goto Done;
            }

            //
            // We have a valid router. If we had just reconnected this 
            // interface, then reset the state to synchronize with the thread 
            // detecting network change. 
            //
            // This needs to be done before any changes are made due to the RA.
            //
            // If we had just reconnected this interface, then give all
            // auto-configured state a small "accelerated" lifetime.  The
            // processing below might extend accelerated lifetimes.
            //
            if (Interface->MediaReconnected) {
                Interface->MediaReconnected = FALSE;

                //
                // Reset auto-configured route lifetimes.
                //
                Ipv4pResetAutoConfiguredRoutes(
                    Interface,
                    2 * MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS);
            }
        
            //
            // Stop sending Router Solicitations for this interface.
            // Note that we should always send at least one Router 
            // Solicitation, even if we receive an unsolicited Router 
            // Advertisement first.
            //
            if ((RouterLifetime != 0) &&
                (Interface->RouterDiscoveryCount < MAX_RTR_SOLICITATIONS)) {
                Interface->RouterDiscoveryTimer = 0;
                Interface->RouterDiscoveryCount = 0;
            }

            RtlReleaseWriteLockFromDpcLevel(&Interface->Lock, &LockHandle);
        }

        //
        // Review: Updating routes without holding interface lock. This may 
        // cause a race condition in very rare scenario of interface router 
        // discovery getting disabled.
        //

        
        //
        // If we receive an address with ICMPV4_INVALID_PREFERENCE_LEVEL, 
        // check to see if we already have this address in router list. If 
        // we do, we need to delete the default route with next hop equal 
        // this router. We achieve this by setting RouterLifetime to 0.
        //
        IppUpdateAutoConfiguredRoute(
            Interface,
            (CONST UCHAR *) &RouterAddress,
            (PIP_NEIGHBOR) NextHop,
            (CONST UCHAR *) &in4addr_any,
            0,
            (PreferenceLevel == ICMPV4_INVALID_PREFERENCE_LEVEL)
            ? 0
            : RouterLifetime,
            MAXLONG - PreferenceLevel);

        IppDereferenceNextHop(NextHop);
    }

Done:
    Args->NetBufferList->Status = STATUS_SUCCESS;
}


VOID
Icmpv4HandleRouterSolicitation(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN IP_REQUEST_CONTROL_DATA *Args
    )
/*++

Routine Description:

    Validate and process an IPv4 Router Solicitation message.

Arguments:

    Icmpv4 - Supplies the parsed ICMPv4 header.


    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv6 Router Solicitation packet,
        with the packet offset at the start of the solicitation header.

    Interface - Supplies the interface over which the packet was received.
    
    RemoteAddress - Supplies the source address of the packet.
    
    LocalAddressEntry - Supplies the destination address of the packet.
    
Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    CONST IP_LOCAL_ADDRESS *LocalAddress = Args->DestLocalAddress;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    CONST IN_ADDR *RemoteAddress = 
        (PIN_ADDR) Args->NlcReceiveDatagram.RemoteAddress;
    IN_ADDR RouterAdvertisementRemoteAddress;
    PIP_LOCAL_UNICAST_ADDRESS Source = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;
    NTSTATUS Status;
    IP_PATH_FLAGS Constrained;
    PIP_NEXT_HOP NextHop;
    ICMPV4_ROUTER_SOLICIT *RouterSolicitation;
    BOOLEAN DelaySolicitedRouterAdvertisementNeeded = FALSE;
    NL_ADDRESS_TYPE AddressType = NL_ADDRESS_TYPE(LocalAddress);

    DISPATCH_CODE();
    
    //
    // Validate router solicitation. What we need to check here are:
    // IP source address should be 0 or on the same subnet of one
    // of the addresses on the received interface; ICMP code is 0;
    // ICMP length is greater than 8. Checksum should already be checked
    // by ICMP receive handler.
    //
    if (!IN4_UNALIGNED_ADDR_EQUAL(RemoteAddress, &in4addr_any)) {
        Status =
            IppFindNextHopAtDpc(
                Interface->Compartment, 
                (CONST UCHAR *) RemoteAddress,
                NULL, 
                Interface, 
                IppGetScopeId(Interface, (CONST UCHAR *) RemoteAddress),
                &NextHop,
                &Constrained,
                NULL);
        if (!NT_SUCCESS(Status)) {
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            return;
        }

        if (!IppIsNextHopNeighbor(NextHop) ||
            !IN4_UNALIGNED_ADDR_EQUAL(
                RemoteAddress, 
                (CONST IN_ADDR*)
                IP_NEIGHBOR_NL_ADDRESS((PIP_NEIGHBOR) NextHop))) {
            //
            // This address is not on the same link as this interface.
            // Ignore it.
            //
            IppDereferenceNextHop(NextHop);
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            return;
        }
        IppDereferenceNextHop(NextHop);
    }

    RouterSolicitation = (PICMPV4_ROUTER_SOLICIT)Icmpv4;
    
    //
    // Verify we have the correct code. Ignore the reserved field.
    //
    if (RouterSolicitation->RsCode != 0) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Log an error if this router solicitation is received on a broadcast
    // address.
    //
    if (AddressType == NlatBroadcast) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error processing router solicitation: "
                   "Received a broadcast router solicitation\n");
    }
    //
    // Decide the remote address we will use to send out
    // this router advertisement. The preference is: 
    // 1) Always send on the multicast address if multicast is supported
    // on this interface
    // 2) Send to sender of this solicitation if the remote address is not
    // unspecified.
    // 3) Send to broadcast address if this solicitation was received on 
    // a broadcast address.
    // 4) If none of above satisfied, return an error.
    //
    if (Interface->FlCharacteristics->Multicasts) {
        DelaySolicitedRouterAdvertisementNeeded = TRUE;
    } else if (!IN4_IS_UNALIGNED_ADDR_UNSPECIFIED(RemoteAddress)) {
        RouterAdvertisementRemoteAddress = *(PIN_ADDR UNALIGNED)RemoteAddress;
    } else if (AddressType == NlatBroadcast) {
        DelaySolicitedRouterAdvertisementNeeded = TRUE;
    } else {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Passed all the validation. Now trying to send a router advertisement.
    //
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    //
    // Ignore the solicitation unless this is an advertising interface.
    //
    if (!Interface->Advertise) {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        Args->NetBufferList->Status = STATUS_SUCCESS;
        return;
    }

    //
    // If we are sending to a unicast address, send it immediately.
    //
    if (DelaySolicitedRouterAdvertisementNeeded) {
        
        //
        // If MAX_RA_DELAY_TIME is not 1, then a RandomNumber should be used
        // generate the number of ticks.
        //
        C_ASSERT(MAX_RA_DELAY_TIME == 1);
        Interface->RouterDiscoveryTimer = 1;

        Interface->DelaySolicitedRouterAdvertisementNeeded = TRUE;
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    } else {
        //
        // Determine the source address to use for the RA.
        //
        if (AddressType == NlatUnicast) {
            //
            // The Router Solicitation was received on unicast
            // address, so use that address.  
            //
            Source = (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress;
        } else {
            Source =
                IppFindBestSourceAddressOnInterfaceUnderLock(
                    Interface, 
                    (CONST UCHAR*)&RouterAdvertisementRemoteAddress,
                    NULL);
        }
        
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

        if (Source != NULL) {
            Icmpv4SendRouterAdvertisementOnSubInterface(
                Args->SourceSubInterface,
                Source, 
                (CONST UCHAR *)&RouterAdvertisementRemoteAddress);
            if ((PIP_LOCAL_ADDRESS) Source != LocalAddress) {
                IppDereferenceLocalUnicastAddress(Source);
            }
        }
    }
    Args->NetBufferList->Status = STATUS_SUCCESS;
    
}    

BOOLEAN
Icmpv4RouterSolicitationTimeout(
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Source
    )
/*++

Routine Description:

    Process the interface's Router Solicitation timeout.
    
Arguments:

    Interface - Supplies the interface whose Router Solicitation timer fired.

    Source - Returns the source address to use for the Router Solicitation,
        if one should be sent.  Otherwise returns NULL.

Return Value:

    TRUE if a Router Solicitation should be sent, FALSE o/w.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    BOOLEAN SendRouterSolicitation = FALSE;
    
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));

    *Source = NULL;

    //
    // Ensure we have a running timer.
    //
    if (Interface->RouterDiscoveryTimer == 0) {
        return FALSE;
    }
    
    //
    // Timer is running.  Decrement and check for expiration.
    //
    if (--Interface->RouterDiscoveryTimer != 0) {
        return FALSE;
    }
    
    if (Interface->RouterDiscoveryCount != 0) {
        //
        // Re-arm the timer and generate a Router Solicitation.
        //
        Interface->RouterDiscoveryTimer = RTR_SOLICITATION_INTERVAL;
        Interface->RouterDiscoveryCount--;
        SendRouterSolicitation = TRUE;
    } else {
        //
        // If we are still in the reconnecting state, meaning we have not
        // received an Router Advertisement since reconnecting to the link,
        // remove stale auto-configured state.
        //
        if (Interface->MediaReconnected) {
            Interface->MediaReconnected = FALSE;
            
            //
            // Remove auto-configured route lifetimes.
            //
            Ipv4pResetAutoConfiguredRoutes(Interface, 0);
            
        }

        //
        // On non-multicast interfaces, such as the ISATAP interface,
        // we'll never get unsolicited Router Advertisement's.
        // Hence, we solicit periodically (but infrequently).
        //
        if (!(Interface->FlCharacteristics->Multicasts)) {
            Interface->RouterDiscoveryTimer = SLOW_RTR_SOLICITATION_INTERVAL;
            Interface->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
            SendRouterSolicitation = TRUE;
        }
    }

    if (SendRouterSolicitation) {
        *Source =
            IppFindBestSourceAddressOnInterfaceUnderLock(
                Interface,
                (CONST UCHAR*)&in4addr_allroutersonlink,
                NULL);
    }

    return SendRouterSolicitation;
}

VOID
Ipv4pRouterDiscoveryTimeout(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN ForceRouterAdvertisement
    )
/*++

Routine Description:

    Process the interface's router discovery timeout.
    Called from Ipv4pInterfaceSetTimeout.
    
Arguments:

    Interface - Supplies the interface whose router discovery timer fired.

    ForceRouterAdvertisement - Supplies TRUE to indicate that a state change
        requires that a Router Advertisement be sent on the interface.
        
Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    BOOLEAN SendRouterSolicitation = FALSE, SendRouterAdvertisement = FALSE;
    PIP_LOCAL_UNICAST_ADDRESS Source = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;

    DISPATCH_CODE();
    
    RtlAcquireWriteLockAtDpcLevel(&(Interface->Lock), &LockHandle);
    if (Interface->Advertise) {
        SendRouterAdvertisement = IppRouterAdvertisementTimeout(
            ForceRouterAdvertisement, 
            Interface, 
            (PIP_LOCAL_UNICAST_ADDRESS *) &Source);
    } else {
        SendRouterSolicitation = Icmpv4RouterSolicitationTimeout(
            Interface, 
            &Source);
    }    
    RtlReleaseWriteLockFromDpcLevel(&(Interface->Lock), &LockHandle);    

    if (SendRouterAdvertisement) {
        if (Interface->FlCharacteristics->Multicasts) {
            Icmpv4SendRouterAdvertisementOnAllSubInterfaces(
                Interface, Source, &in4addr_allnodesonlink);
        } else {
            Icmpv4SendRouterAdvertisementOnAllSubInterfaces(
                Interface, Source, &in4addr_broadcast);
        }
    } else if (SendRouterSolicitation) {
        Icmpv4SendRouterSolicitationOnAllSubInterfaces(Interface, Source);
    }

    if (Source != NULL) {
        IppDereferenceLocalUnicastAddress(Source);
    }
}

NTSTATUS
Ipv4pStartAdvertising(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is not currently advertising, makes it start advertising.
    
Arguments:

    Interface - Supplies the interface to start advertising on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    NTSTATUS Status;
    PIP_LOCAL_MULTICAST_ADDRESS GroupAddress;
    
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));
    ASSERT(Interface->UseRouterDiscovery);

    if (Interface->AdvertisingEnabled) {
        return STATUS_SUCCESS;
    }

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Starting router advertisments on interface %u\n", 
               Interface->Index);
    
    //
    // Join the all routers on link multicast group.  This may return 
    // STATUS_PENDING, but we'll keep our reference anyway.   
    // REVIEW: This means we currently ignore the failure if it's 
    // asynchronous, but fail to start advertising if it's synchronous.
    //
    Status = IppFindOrCreateLocalMulticastAddressUnderLock(
        (PUCHAR)&in4addr_allroutersonlink,
        Interface,
        NULL,
        &GroupAddress);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    //
    // A non-advertising interface is now advertising.
    //
    Interface->Advertise = TRUE;
    Interface->AdvertisingEnabled = TRUE;
    
    //
    // The reconnecting state is not useful for advertising interfaces
    // because the interface will not receive Router Advertisements.
    //
    Interface->MediaReconnected = FALSE;

    //
    // Remove routes that were auto-configured from Router Advertisement.
    // Advertising interfaces must be manually configued.  It's better to 
    // remove them now than let them time-out at some random time.
    //
    Ipv4pResetAutoConfiguredRoutes(Interface, 0);
    
    //
    // Start sending Router Advertisements if the interface supports multicast.
    // Send the first one quickly.
    //
    // REVIEW: we should probably ensure that the group join above has 
    // completed before sending the RA.  However, we'll retransmit anyway
    // so it's not fatal even if we try to send the first one before we're
    // ready to receive a reply.
    //
    if (Interface->FlCharacteristics->Multicasts) {
        Interface->RouterDiscoveryTimer = 1;
        Interface->RouterDiscoveryCount = MAX_INITIAL_RTR_ADVERTISEMENTS;
    } 

    return STATUS_SUCCESS;
}


VOID
Ipv4pStopAdvertising(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is currently advertising, makes it stop advertising.
    
Arguments:

    Interface - Supplies the interface to stop advertising on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));
    ASSERT(Interface->UseRouterDiscovery);

    if (!Interface->AdvertisingEnabled) {
        return;
    }

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Stopping router advertisements on interface %u\n", 
               Interface->Index);
    
    //
    // Leave the all routers on link multicast group.
    //
    IppFindAndDereferenceMulticastGroup(
        Interface, 
        (PUCHAR)&in4addr_allroutersonlink);
    
    //
    // Stop sending Router Advertisements.
    //
    Interface->Advertise = FALSE;
    Interface->AdvertisingEnabled = FALSE;
    //
    // Send Router Solicitations again.  Send the first one quickly.
    //
    Interface->RouterDiscoveryTimer = 1; 
    Interface->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
}

VOID
Ipv4pSendRedirect(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_NEIGHBOR Target
    )
/*++

Routine Description:

    Send a Redirect message to a neighbor, telling it to use a
    better first-hop neighbor in the future for the specified destination.
    
Arguments:

    Control - Supplies the packet triggering the redirect.
        A clone of this packet is encapsulated in the redirect message
        and the original may be forwarded once the function returns.
        
    Target - Supplies the better first-hop neighbor for its destination.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    IppSendErrorList(
        FALSE,
        &Ipv4Global,
        Control,
        ICMP4_REDIRECT,
        0,
        *((PULONG) &((PIPV4_NEIGHBOR) Target)->Ipv4Address),
        FALSE);
}


VOID
Ipv4pHandleRedirect(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:

    Validate and process an IPv4 Redirect message.

Arguments:

    Icmpv4 - Supplies the parsed ICMPv4 header.

    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv4 Redirect packet,
        with the packet offset at the start of the redirect header.

    Interface - Supplies the interface over which the packet was received.

    RemoteAddress - Supplies the source address of the packet.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    PIP_INTERFACE Interface = Args->DestLocalAddress->Interface;
    CONST NLC_RECEIVE_DATAGRAM *ReceiveDatagram = &Args->NlcReceiveDatagram;

    IPV4_HEADER Ipv4Buffer, *Ipv4;
    CONST IN_ADDR *Target, *Destination;
    
    PIP_NEIGHBOR Neighbor;
    
    //
    // Ignore the redirect if redirects have been disabled or this is a
    // forwarding interface.
    //
    if (!Ipv4Global.EnableIcmpRedirects || Interface->Forward) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Validate the Redirect.  By the time we get here, the ICMPv4
    // checksum will already have been checked.  We accept all codes, treating
    // them as host redirects (REVIEW: RFC1122 (host-requirements) requires
    // this of network and host, but not type-of-service redirects).
    //
    
    //
    // Remove the ICMP header. Also add the header size to the
    // NetworkLayerHeadersSize so that the header can be retreated on the
    // return path.
    //    
    NetioAdvanceNetBuffer(NetBuffer, sizeof(ICMPV4_MESSAGE));
    Args->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(ICMPV4_MESSAGE);
    
    //
    // Get the encapsulated IPv4 header to determine the destination.
    // We do not require the encapsulated IPv4 header to be correctly formed,
    // nor do we require that it be followed with the first 64 bits of the
    // original datagram's data (REVIEW: we are more liberal than RFC792).
    //
    if (NetBuffer->DataLength < sizeof(IPV4_HEADER)) {
        //
        // Insufficient data buffer for a minimal Redirect.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    Ipv4 =
        NetioGetDataBuffer(
            NetBuffer, 
            sizeof(IPV4_HEADER),
            &Ipv4Buffer,
            __builtin_alignof(IPV4_HEADER),
            0);
    
    //
    // Pick up the target and destination addresses.
    //
    Target = (PIN_ADDR) Icmpv4->icmp4_data32;
    Destination = &(Ipv4->DestinationAddress);
    
    //
    // Check that the destination and target addresses are valid addresses.
    // TODO: make sure target is not a subnet broadcast address.
    //
    if ((Ipv4AddressType((CONST UCHAR *) Destination) != NlatUnicast) ||
        (Ipv4AddressType((CONST UCHAR *) Target) != NlatUnicast)) {
        //
        // Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    //
    // We did not advance over the parsed buffer, so we do not need to retreat.
    // We may not have parsed the entire packet, but that's okay.
    //
    
    //
    // We have a valid redirect message (except for checking that the source of
    // the redirect is the current first-hop neighbor for the destination -
    // IppRedirectPath does that).  If IppRedirectPath doesn't invalidate the
    // redirect, then we update the neighbor cache.
    //
    Neighbor =
        IppRedirectPath(
            Args->SourceSubInterface,
            Args->DestLocalAddress,
            (CONST UCHAR *) Destination,
            (CONST UCHAR *) ReceiveDatagram->RemoteAddress,
            (CONST UCHAR *) Target);
    if (Neighbor != NULL) {
        //
        // Update the Neighbor Cache Entry for the target.  The target is a
        // router if the target and destination addresses are not identical.
        //
        if (!IN4_ADDR_EQUAL(Target, Destination)) {
            KLOCK_QUEUE_HANDLE LockHandle;
            
            RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
            Neighbor->IsRouter = TRUE;
            RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        }
        
        IppDereferenceNeighbor(Neighbor);

        Args->NetBufferList->Status = STATUS_SUCCESS;
    } else {
        Args->NetBufferList->Status = STATUS_INSUFFICIENT_RESOURCES;
    }
}
