#include "precomp.h"
#include "router.tmh"


VOID 
IppResetAutoConfiguredSettings(
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
    if (IS_IPV4_PROTOCOL(Interface->Compartment->Protocol)) {
        Ipv4pResetAutoConfiguredSettings(Interface, Lifetime);
    } else {
        Ipv6pResetAutoConfiguredSettings(Interface, Lifetime);
    }

}

VOID
IppUpdateAutoConfiguredRoute(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *NextHop OPTIONAL,
    IN PIP_NEIGHBOR Neighbor OPTIONAL,
    IN CONST UCHAR *Prefix,
    IN UCHAR PrefixLength,
    IN ULONG Lifetime,
    IN ULONG Metric
    )
/*++

Routine Description:

    Create/Update an autoconfigured route.
    
Arguments:

    Interface - Supplies the next-hop interface.

    NextHop - Supplies the next-hop.  NULL indicates an on-link route.

    Neighbor - Supplies the next-hop neighbor.  NULL indicates an onlink route.

    Prefix - Supplies the route prefix.

    PrefixLength - Supplies the route prefix length.

    Lifetime - Supplies the route lifetime in ticks.

    Metric - Supplies the route metric.
    
Return Value:

    None.
    
Caller LOCK: 

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    NL_ROUTE_RW RouteRw;
    NSI_SET_ACTION Action = (Lifetime != 0) ? NsiSetCreateOrSet : NsiSetDelete;

    NlInitializeRouteRw(&RouteRw);
    RouteRw.ValidLifetime = RouteRw.PreferredLifetime =
        IppTicksToSeconds(Lifetime);
    RouteRw.Metric = Metric;
    
    //
    // $$REVIEW: Instead of acquiring the route set lock for every prefix,
    // we should acquire it once and then call IppUpdateUnicastRouteUnderLock. 
    //
    (VOID) IppUpdateUnicastRoute(
        Action,
        Interface,
        (Neighbor == NULL) ? NULL : Neighbor->SubInterface,
        Prefix,
        PrefixLength,
        NULL,
        0,
        NlroRouterAdvertisement,
        &RouteRw,
        NextHop);
}



__inline
VOID
IppUpdateNextHop(
    IN PIP_PATH Path,
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Update the next hop for a path.
    
Arguments:

    Path - Supplies the path to update.

    Neighbor - Supplies the new next hop for the path.
    
Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    LONG RoutingEpoch = Neighbor->Interface->Compartment->RoutingEpoch;
    
    //
    // Take a reference on the neighbor, to be consumed by IppSetNextHopInPath.
    // TODO: This should pass in the current epoch stored in the path instead
    // of the routing epoch.  The reason is that the path is not necessarily
    // synchronized with the routing state. 
    //
    IppReferenceNeighbor(Neighbor);
    IppSetNextHopInPath(Path, (PIP_NEXT_HOP) Neighbor, NULL, RoutingEpoch);
}


PIP_NEIGHBOR
IppRedirectPath(
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_LOCAL_ADDRESS Source,
    IN CONST UCHAR *Destination,
    IN CONST UCHAR *NextHop,
    IN CONST UCHAR *Target
    )
/*++

Routine Description:

    Update the destination cache to reflect a redirect message.

Arguments:

    SubInterface - Supplies the incoming subinterface.

    Source - Supplies the source address of the packet that caused the
        redirect. 

    Destination - Supplies the destination address (cause of the redirect).

    NextHop - Supplies the current next-hop (source of the redirect).

    Target - Supplies the new next-hop (target of the redirect).

Return Value:

    Neighbor entry for the target if the redirect is accepted.  NULL otherwise.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;
    PIP_PATH Path, TargetPath = NULL;
    PIP_UNICAST_ROUTE TargetRoute = NULL;
    PIP_NEIGHBOR OldNeighbor, NewNeighbor = NULL;
    KIRQL OldIrql;
    PIP_LOCAL_ADDRESS LocalAddress;
    NTSTATUS Status;

    //
    // Validate that the new next-hop is not a loopback 
    // or one of our own local addresses (IppFindAddressOnInterface 
    // also identifies attached subnet broadcasts as local addresses).
    //
    if (INET_IS_ADDR_LOOPBACK(Protocol->Family, Target)) {
       return NULL;
    }
    LocalAddress = IppFindAddressOnInterface(Interface, Target);
    if (LocalAddress != NULL) {
        IppDereferenceLocalAddress(LocalAddress);
        return NULL;
    }
    
    //
    // Find the correct path but be careful not to create one if it doesn't
    // exist (we call IppFindPath instead of IppRouteToDestination here).  
    //
    Path =
        IppFindPath(
            Interface->Compartment,
            NULL,
            Destination,
            IppGetScopeId(Interface, Destination),
            Interface,
            (PIP_LOCAL_UNICAST_ADDRESS) Source);
    if (Path == NULL) {
        return NULL;
    }
    
    ASSERT((PIP_LOCAL_ADDRESS) Path->SourceAddress == Source);
    
    //
    // If the route corresponding to the target is marked dead, then mark it
    // alive since we have received a redirect to it. 
    //
    RtlAcquireScalableReadLock(&Compartment->PathSet.Lock, &OldIrql);
    if (Path->Route != NULL) {
        IppSetAllRouteState(Path->Route, RouteAlive, Target);
    }
    RtlReleaseScalableReadLock(&Compartment->PathSet.Lock, OldIrql);
    
    //
    // Ensure that the source of the redirect is the current next-hop neighbor.
    // (This is a simple sanity check -
    // it does not prevent clever neighbors from hijacking.)
    //
    OldNeighbor = IppGetNeighborFromPath(Path);
    if (OldNeighbor == NULL) {
        goto Bail;
    }
    
    if (RtlEqualMemory(
            IP_NEIGHBOR_NL_ADDRESS(OldNeighbor),
            NextHop,
            AddressLength)) {

        Status =
            IppRouteToDestinationInternal(
                Interface->Compartment,
                (PUCHAR) Target,
                Interface,
                Source,
                &TargetPath);

        if (NT_SUCCESS(Status)) {

           ASSERT(TargetPath != NULL);

           NewNeighbor = (PIP_NEIGHBOR)IppGetNextHopFromPath(TargetPath);
           if (NewNeighbor != NULL) {

              //
              // First, check if the address is from one of our subnets.
              // RFC1122/3.2.2.2, RFC2461/8.1 say we SHOULD/MUST
              // silently drop anything targeting non-local subnets.
              // For IPv6 there are some exceptions below.
              //
              TargetRoute = IppGetRouteFromPath(TargetPath);
              if ((TargetRoute == NULL) ||
                  !IppIsOnLinkRoute(TargetRoute)) { 
	          IppDereferenceNeighbor(NewNeighbor);
                 NewNeighbor = NULL;
              }
           }
        } 

        //
        // RFC2461/8.1 also prescribes that in case Target=Destination
        // we should treat the Target/Destionation as link-local, 
        // even if it is "not covered under one of the link's prefixes".
        //
        if ((NewNeighbor == NULL) && 
            (IS_IPV6_PROTOCOL(Interface->Compartment->Protocol)) &&
            RtlEqualMemory(
	        Destination,
	        Target,
	        AddressLength)) {
           NewNeighbor = 
              IppFindOrCreateNeighbor(
                 Interface,
                 SubInterface,
                 Target,
                 NlatUnicast);
        }
        if (NewNeighbor != NULL) {
           //
           // Update the destination cache to reflect this redirect.
           //
           IppUpdateNextHop(Path, NewNeighbor);
        }
    } else {
        if (IS_IPV4_PROTOCOL(Protocol)) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                       "IPNG: [%u] RedirectPath (destination %!IPV4!): "
                       "hijack from %!IPV4!\n",
                       Interface->Index, Destination, NextHop);
        } else {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                       "IPNG: [%u] RedirectPath (destination %!IPV6!): "
                       "hijack from %!IPV6!\n",
                       Interface->Index, Destination, NextHop);
        }
    }
    

    
Bail:
    if (OldNeighbor != NULL) {
       IppDereferenceNeighbor(OldNeighbor);
    }
	
    if (TargetRoute != NULL) {
       IppDereferenceRoute((PIP_ROUTE) TargetRoute);
    }

    if (TargetPath != NULL) {
       IppDereferencePath(TargetPath);
    }
	
    IppDereferencePath(Path);
    return NewNeighbor;    
}


VOID
IppSendRedirect(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_NEIGHBOR Target
    )
/*++

Routine Description:

    Consider sending a redirect if we are forwarding a packet out the
    interface on which it arrived and the packet is not being source-routed.

    We SHOULD send a Redirect, whenever
    1. The Source address of the packet specifies a neighbor, and
    2. A better first-hop resides on the same link, and
    3. The Destination address is not multicast.
    See Section 8.2 of RFC 2461.
    
Arguments:

    Control - Supplies the packet that might trigger a redirect.
        This packet is encapsulated in the redirect message.

    Target - Supplies the next-hop neighbor for the packet's destination.
    
Return Value:

    TRUE if the packet should be dropped, FALSE otherwise.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;    
    PIP_INTERFACE Interface = Target->SubInterface->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;

    NTSTATUS Status;
    PIP_PATH SourcePath;
    PIP_NEIGHBOR SourceNeighbor;

    //
    // The NetBufferList must have exactly one NetBuffer.
    //
    ASSERT((NetBufferList->FirstNetBuffer != NULL) &&
           (NetBufferList->FirstNetBuffer->Next == NULL));

    //
    // 2. We are forwarding a packet out the interface on which it arrived.
    //
    ASSERT(IppGetPacketSourceInterface(Control) == (PVOID) Interface);

    //
    // 3. The Destination address is unicast.
    //
    ASSERT(Protocol->AddressType(Control->CurrentDestinationAddress) == 
           NlatUnicast);

    //
    // Get a path for the source of this packet.
    //
    Status =
        IppRouteToDestinationInternal(
            Interface->Compartment,
            Control->SourceAddress.Address,
            Interface,
            NULL,
            &SourcePath);
    if (!NT_SUCCESS(Status)) {
        return;
    }
    
    ASSERT(SourcePath->SourceAddress->Interface == Interface);

    //
    // Rate-limiting might prevent us from sending a redirect.
    // For IPv4, this is handled inside Ipv4pSendRedirect.
    //
    if (IS_IPV6_PROTOCOL(Protocol) && IppRateLimitIcmp(SourcePath)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                   "IPNG: [%u] RedirectPath - rate limit %!IPV6!\n",
                   Interface->Index, Control->SourceAddress.Address);
        goto Bail;
    }
    
    SourceNeighbor = IppGetNeighborFromPath(SourcePath);
    if (SourceNeighbor == NULL) {
        goto Bail;
    }

    if (RtlEqualMemory(
            IP_NEIGHBOR_NL_ADDRESS(SourceNeighbor),
            Control->SourceAddress.Address,
            AddressLength) &&
        (SourceNeighbor->SubInterface == Target->SubInterface)) {

        //
        // 1. The Source address of the packet specifies a neighbor.
        //
        ULONG NetworkLayerHeadersSize =
            Control->NlcReceiveDatagram.NetworkLayerHeadersSize;
            
        //
        // Retreat to the beginning of the IP header.
        //
        (VOID) NetioRetreatNetBufferList(
            NetBufferList, NetworkLayerHeadersSize, 0);
        Control->NlcReceiveDatagram.NetworkLayerHeadersSize = 0;

        //
        // Transmit the redirect (data from packet is copied to the redirect).
        //
        Protocol->SendRedirect(Control, Target);
        
        //
        // Restore, so we can continue processing the packet.
        //
        NetioAdvanceNetBufferList(NetBufferList, NetworkLayerHeadersSize);
        Control->NlcReceiveDatagram.NetworkLayerHeadersSize =
            NetworkLayerHeadersSize;
    }   

    IppDereferenceNeighbor(SourceNeighbor);

Bail:
    IppDereferencePath(SourcePath);
}


BOOLEAN
IppRouterAdvertisementTimeout(
    IN BOOLEAN ForceRouterAdvertisement,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Source
    )
/*++

Routine Description:

    Process the interface's Router Advertisement timeout.
    
Arguments:

    ForceRouterAdvertisement - Supplies TRUE to indicate that a state change
        requires that a Router Advertisement be sent on the interface.
        
    Interface - Supplies the interface whose Router Advertisement timer fired.

    Source - Returns the source address to use for the Router Advertisement,
        if one should be sent.  Otherwise returns NULL.

Return Value:

    TRUE if a Router Advertisement should be sent, FALSE o/w.
    
Caller LOCK: Interface (Exclusive).

Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    ULONG Now;
    
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));

    *Source = NULL;

    //
    // Return FALSE if this interface does not support multicast or we do
    // not need to send out a solicited router advertisement.
    //
    if (!Interface->FlCharacteristics->Multicasts && 
        !Interface->DelaySolicitedRouterAdvertisementNeeded) {
        ASSERT(Interface->RouterDiscoveryTimer == 0);
        return FALSE;
    }
    ASSERT(Interface->RouterDiscoveryTimer != 0);
    
    if (ForceRouterAdvertisement) {
        //
        // Enter "fast" mode if a Router Advertisement is being forced.
        //
        Interface->RouterDiscoveryCount = MAX_INITIAL_RTR_ADVERTISEMENTS;
    } else if (--Interface->RouterDiscoveryTimer != 0) {
        //
        // The timer has not yet expired.
        //
        return FALSE;
    }

    //
    // Check if rate-limiting prevents us from sending a Router Advertisement.
    //
    Now = IppTickCount;
    if ((ULONG) (Now - Interface->LastRouterAdvertisement) <
        MIN_DELAY_BETWEEN_RAS) {
        //
        // We can not send a Router Advertisement quite yet.  Re-arm the timer.
        //
        Interface->RouterDiscoveryTimer = MIN_DELAY_BETWEEN_RAS -
            (ULONG) (Now - Interface->LastRouterAdvertisement);
        return FALSE;
    }

    //
    // Re-arm the timer.
    //
    if (Interface->RouterDiscoveryCount != 0) {
        //
        // We are in "fast" mode.  Send the next Router Advertisement quickly.
        //
        Interface->RouterDiscoveryTimer = MAX_INITIAL_RTR_ADVERT_INTERVAL;
        Interface->RouterDiscoveryCount--;
    }

    if (Interface->RouterDiscoveryCount == 0) {
        //
        // Dust settled.  Send periodic, low frequency Router Advertisements.
        //
        Interface->RouterDiscoveryTimer = RandomNumber(
            MIN_ROUTER_ADVERTISEMENT_INTERVAL,
            MAX_ROUTER_ADVERTISEMENT_INTERVAL);
    }
    
    *Source = IppFindLinkLocalUnicastAddress(Interface);

    //
    // TODO: Re-arm the timer if we have a "Tentative" link-local address.
    //
    if (*Source != NULL) { 
        if (Interface->DelaySolicitedRouterAdvertisementNeeded == TRUE) {
            Interface->DelaySolicitedRouterAdvertisementNeeded = FALSE;
        }
        return TRUE;
    } else {
        return FALSE;
    }
}


VOID
IppStartRouterDiscovery(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Start the router discovery process on an interface.

Arguments:

    Interface - Supplies the interface to start router discovery on.

Return Value:

    None.

Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PLIST_ENTRY Current;
    PIP_POTENTIAL_ROUTER PotentialRouter;
    
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));
    ASSERT(Interface->UseRouterDiscovery);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: [%u] Staring router discovery\n", 
               Interface->Index);
    
    //
    // Start sending Router Solicitations/Advertisements.
    // The first packet will have the required random delay,
    // because we randomize when the timeout first fires.
    //
    if (Interface->Advertise) {
        //
        // Only multicast interfaces generate periodic Router Advertisements.
        //
        if (Interface->FlCharacteristics->Multicasts) {
            //
            // Send a Router Advertisement very soon.
            //
            Interface->RouterDiscoveryTimer = 1;
            Interface->RouterDiscoveryCount = MAX_INITIAL_RTR_ADVERTISEMENTS;
        }
    } else {
        //
        // Start sending Router Solicitations.
        //
        if (Interface->FlCharacteristics->Multicasts) {
            Interface->RouterDiscoveryTimer = 1;
            Interface->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
        } else {
            for (Current = Interface->PotentialRouterList.Flink;
                 Current != &Interface->PotentialRouterList;
                 Current = Current->Flink) {
                PotentialRouter = (PIP_POTENTIAL_ROUTER) 
                    CONTAINING_RECORD(Current, IP_POTENTIAL_ROUTER, Link);
                PotentialRouter->RouterDiscoveryTimer = 1;
                PotentialRouter->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
            }
        }
    }

    //
    // Initialize timestamp to a value safely in the past, so that when/if this
    // interface first sends a Router Advertisement it is not inhibited due to
    // rate-limiting.
    //
    Interface->LastRouterAdvertisement = IppTickCount - MIN_DELAY_BETWEEN_RAS;
}


VOID
IppStopRouterDiscovery(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Stop the router discovery process on an interface.
    
Arguments:

    Interface - Supplies the interface to stop router discovery on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    PLIST_ENTRY Current;
    PIP_POTENTIAL_ROUTER PotentialRouter;

    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));
    
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: [%u] Stopping router discovery\n", 
               Interface->Index);

    //
    // Stop sending Router Solicitations/Advertisements.
    //
    if (Interface->FlCharacteristics->Multicasts) {
        Interface->RouterDiscoveryTimer = 0;
        Interface->RouterDiscoveryCount = 0;
    } else {
        for (Current = Interface->PotentialRouterList.Flink;
             Current != &Interface->PotentialRouterList;
             Current = Current->Flink) {
            PotentialRouter = (PIP_POTENTIAL_ROUTER) 
                CONTAINING_RECORD(Current, IP_POTENTIAL_ROUTER, Link);
            PotentialRouter->RouterDiscoveryTimer = 0;
            PotentialRouter->RouterDiscoveryCount = 0;
        }
    }
}


VOID
IppRouteTimeout(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route
    )
/*++

Routine Description:

    Process a timeout event for a route.

    TODO: The route might not belong to the current instance.
    
Arguments:

    Compartment - Supplies the compartment to which the route belongs.
    
    Route - Supplies the route whose timer has expired.

Return Value:

    None.

Caller LOCK: Route Set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&(Compartment->RouteSet.Lock));

    //
    // Some route types should not have a running timer!
    //
    ASSERT(!Route->Flags.Immortal);
    ASSERT(Route->ValidLifetime != 0);
    ASSERT(Route->ValidLifetime != INFINITE_LIFETIME);
    
    //
    // ValidLifetime has expired, the route is invalid and should not be used.
    // We delete invalid routes, unless they are published or well-known.
    //
    Route->ValidLifetime = 0;
    TtInitializeTimer(&Route->Timer);
    IppDeleteUnicastRoute(Compartment, Route);
    
    //
    // The route is now invalid.  Invalidate all cached paths.
    //
    IppInvalidateDestinationCache(Compartment);
}


VOID
IppRouteSetTimeout(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    Process timeouts pertaining to the compartment's route set.
    Called once every timer tick from Ipv6Timeout.

Arguments:

    Compartment - Supplies the compartment whose route set needs inspection.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    PIPR_LOCKED_SET RouteSet = &(Compartment->RouteSet);
    LIST_ENTRY FiredList;
    PIP_UNICAST_ROUTE Route;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    DISPATCH_CODE();

    if (TtIsTableEmpty(RouteSet->TimerTable)) {
        //
        // Optimize for the common case, when there are no running timers.
        // Since this check is made without holding the route set lock, there
        // is an off-chance that we will miss a timer that was just started.
        // However, that's exactly the desired behavior.
        //
        return;
    }
        
    RtlAcquireScalableWriteLockAtDpcLevel(&RouteSet->Lock, &LockHandle);

    //
    // Determine which timers fired.
    //
    (VOID) TtFireTimer(RouteSet->TimerTable, &FiredList);
    while (!IsListEmpty(&FiredList)) {
        Route = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
            RemoveHeadList(&FiredList), IP_UNICAST_ROUTE, Timer.Link);

        IppRouteTimeout(Compartment, Route);
    }

    RtlReleaseScalableWriteLockFromDpcLevel(&RouteSet->Lock, &LockHandle);
}
