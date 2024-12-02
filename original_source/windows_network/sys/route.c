/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    route.c

Abstract:

    This module implements the protocol-independent functions of the 
    Route Manager module.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "route.tmh"

#if PATH_REFHIST
PREFERENCE_HISTORY IppPathReferenceHistory;
#endif

//
// See RFC 2362 for this hash function.
//
#define ROUTE_HASH_LEVEL1(A, B) \
    (1103515245 * ((A) & (B)) + 12345)

#define ROUTE_HASH_LEVEL2(A, B) \
    ((1103515245 * ((A) ^ (B)) + 12345) & 0x7FFFFFFF)


ULONG IppPathThresholdForGc = IPP_PATH_THRESHOLD_FOR_GC_CLIENT;
ULONG IppMaxPaths = IPP_MAX_PATHS_CLIENT;
ULONG IppMaxCachedPathAge = IPP_MAX_CACHED_PATH_AGE_CLIENT;

__inline
PIP_COMPARTMENT
IppGetCompartmentFromPath(
    IN PIP_PATH Path
    )
{
    return Path->SourceAddress->Interface->Compartment;
}


__inline
PIPP_PATH_SET
IppGetPathSetFromPath(
    IN PIP_PATH Path
    )
{
    PIP_COMPARTMENT Compartment = IppGetCompartmentFromPath(Path);
    return &Compartment->PathSet;
}

__inline
VOID
IppFlushDestinationCache(
    IN PIP_COMPARTMENT Compartment
    )
{
    InterlockedIncrement(&Compartment->RoutingEpoch);
}

__inline
VOID
IppRouteTrace(
    IN ULONG Level, 
    IN CONST UCHAR *Message, 
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *DestinationPrefix, 
    IN ULONG DestinationPrefixLength, 
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *NextHopAddress
    )
{
    if (IS_IPV4_PROTOCOL(Protocol)) {
        if (NextHopAddress == NULL) {
            NetioTrace(
                NETIO_TRACE_NETWORK, Level, 
                "IPNG: [%u] %s for %!IPV4!/%d, Next hop onlink\n",
                Interface->Index,
                Message, 
                DestinationPrefix, 
                DestinationPrefixLength);
        } else {
            NetioTrace(
                NETIO_TRACE_NETWORK, Level, 
                "IPNG: [%u] %s for %!IPV4!/%d, Next hop %!IPV4!\n",
                Interface->Index,
                Message, 
                DestinationPrefix, 
                DestinationPrefixLength,
                NextHopAddress);
        }
    } else {
        if (NextHopAddress == NULL) {
            NetioTrace(
                NETIO_TRACE_NETWORK, Level, 
                "IPNG: [%u] %s for %!IPV6!/%d, Next hop onlink\n",
                Interface->Index,
                Message, 
                DestinationPrefix, 
                DestinationPrefixLength);
        } else {
            NetioTrace(
                NETIO_TRACE_NETWORK, Level, 
                "IPNG: [%u] %s for %!IPV6!/%d, Next hop %!IPV6!\n",
                Interface->Index,
                Message, 
                DestinationPrefix, 
                DestinationPrefixLength,
                NextHopAddress);
        }
    }
}

NTSTATUS
IppInitializePathSet(
    IN PIPP_PATH_SET PathSet
    )
/*++

Routine Description:

    Initialize the Path set by initializing the hash-table, the scalable
    reader/writer lock that protects the fields in the path set. 
    The state variables are set such that an enumeration over the table 
    happens at an appropriate time. 

Arguments:

    PathSet - Pointer to the path set to be initialized.

Return Value:

    Returns STATUS_SUCCESS if initialization is successful,
    STATUS_INSUFFICIENT_RESOURCES otherwise.

--*/
{
    BOOLEAN Success;
    PRTL_HASH_TABLE HashTablePointer = &PathSet->Table;
    
    RtlZeroMemory(PathSet, sizeof(IPP_PATH_SET));

    if (IppIsServerSKU) {      
        IppPathThresholdForGc = IPP_PATH_THRESHOLD_FOR_GC_SERVER;
        IppMaxPaths = IPP_MAX_PATHS_SERVER;
        IppMaxCachedPathAge = IPP_MAX_CACHED_PATH_AGE_SERVER;
    }
    
    PathSet->LastEnumerationTick = IppTickCount;
    PathSet->DelayBeforeNextEnumeration = IPP_PATHSET_ENUM_DELAY;

    Success = RtlCreateHashTable(&HashTablePointer, 0, 0);

    if (!Success) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitializeScalableMrswLock(&PathSet->Lock, 0);
    return STATUS_SUCCESS;
}

VOID
IppUninitializePathSet(
    IN PIPP_PATH_SET PathSet
    )
/*++

Routine Description:

    Cleanup the path set, by uninitializing the reader/writer lock and
    the hash-table. The routine makes sure that if an enumeration is
    in progress, that enumeration is terminated.

Arguments:

    PathSet - Pointer to the path-set to be cleaned up.

Return Value:

    None.

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireScalableWriteLock(&PathSet->Lock, &LockHandle);

    if (RtlActiveEnumeratorsHashTable(&PathSet->Table) != 0) {
        RtlEndWeakEnumerationHashTable(&PathSet->Table, &PathSet->Enumerator);
    }

    //
    // There should only be one weak-enumerator in the path-set.
    //

    ASSERT(RtlActiveEnumeratorsHashTable(&PathSet->Table) == 0);

    RtlReleaseScalableWriteLock(&PathSet->Lock, &LockHandle);

    RtlUninitializeScalableMrswLock(&PathSet->Lock);
    RtlDeleteHashTable(&PathSet->Table);
}

VOID
IppPathSetTimeout(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    Perform periodic processing on the Path Set.

    This routine periodically enumerates the Path Set and scavenges
    IP_PATHs that have not been used recently. It also restructures
    the hash-table to make sure that it's performance is optimal.

    The algorithm is as follows:
    1. If the hash-table is not being enumerated, restructure the
       hash-table for optimal performance.

    2. If an enumeration is in progress, go to Step 6.
     
    3. Check if enough time has elapsed since the last-enumeration.
       (IPP_PATHSET_ENUM_DELAY). If yes, initiate an enumeration and
       go to step 6.

    4. Even if enough time has not elapsed, but the total number of
       paths in the Path Set has exceeded a threshold 
       (IPP_PATH_THRESHOLD_FOR_GC) AND the number of paths scavenged
       during the last iteration is greater than a threshold
       (IPP_SCAVENGED_PATH_THRESHOLD_FOR_GC) initiate an enumeration
       and go to step 6.

       NOTE: The number of paths scavenged during the last enumeration is
       taken to be a rough estimate of the paths that will be scavenged
       in the next enumeration. This is a rough estimate of the amount
       of memory we can reclaim.

    5. If an enumeration is not in progress, return.

    6. Enumerate a fixed amount of entries, or until the Path Set has
       been completely enumerated. The number of entries to be enumerated
       per enumeration (IPP_PATHS_EVALUATED_PER_ITERATION) has been 
       calculated in a way that the timeout processing does not compute 
       too much CPU.

    7. If the enumeration ends, update the last-enumeration-tick and other
       state variables, and return. If the enumeration is still in progress,
       then release lock and return. The next timer-tick will pick the 
       enumeration from where it was left off.

Arguments:

    Compartment - Pointer to compartment whose Path Set needs to be processed.

Return Value:

    None.

Caller LOCK: None.
Caller IRQL: DISPATCH_LEVEL (since this called from a timer).

--*/
{
    ULONG TickCount = IppTickCount;
    PIPP_PATH_SET PathSet = &Compartment->PathSet;
    ULONG PathsEvaluated;
    KLOCK_QUEUE_HANDLE LockHandle;
    PRTL_HASH_TABLE_ENTRY PathLink;
    PIP_PATH Path;
    ULONG TotalEntries;
    ULONG DelaySinceLastEnumeration;
    ULONG NewPathsCreated = 0;
    ULONG EntriesToEnumerate = IPP_PATHS_EVALUATED_PER_ITERATION;
    DISPATCH_CODE();

    //
    // Pick up the PathSet lock in writer-mode.
    //

    RtlAcquireScalableWriteLockAtDpcLevel(&PathSet->Lock, &LockHandle);

    TotalEntries = RtlTotalEntriesHashTable(&PathSet->Table);
    if (TotalEntries > PathSet->LastIterationPathCount) {
        NewPathsCreated = TotalEntries - PathSet->LastIterationPathCount;
    }
    
    if (RtlActiveEnumeratorsHashTable(&PathSet->Table) == 0) {
        
        IppRestructureHashTableUnderLock(&PathSet->Table);
        //
        // Check if it's time to start the next enumeration.
        //
        // If the number of paths is high, and we suspect that a large number
        // of them is cached, let's begin an enumeration. Otherwise, we'll 
        // begin an enumeration when it's time.
        //
        DelaySinceLastEnumeration = TickCount - PathSet->LastEnumerationTick;
        if ((DelaySinceLastEnumeration < IPP_PATHSET_ENUM_DELAY) &&
                (NewPathsCreated < IPP_NUM_PATHS_INCREASE_THRESHOLD) && 
                ((TotalEntries < IppPathThresholdForGc) ||
                 (PathSet->CachedPathsScavenged < 
                    IPP_SCAVENGED_PATH_THRESHOLD_FOR_GC))) {

            RtlReleaseScalableWriteLockFromDpcLevel(
                &PathSet->Lock, 
                &LockHandle);

            return;
        }

        PathSet->CachedPathEstimateDuringEnumeration = 0;
        PathSet->CachedPathsScavenged = 0;
        RtlInitWeakEnumerationHashTable(&PathSet->Table, &PathSet->Enumerator);
    }

    ASSERT(RtlActiveEnumeratorsHashTable(&PathSet->Table) == 1);

    //
    // We will process atmost a certain number of paths on each timer
    // tick.
    //
    if (NewPathsCreated > IPP_PATHS_EVALUATED_PER_ITERATION) {
        EntriesToEnumerate = NewPathsCreated;
    }
    PathLink = NULL;

    for (PathsEvaluated = 0; 
         PathsEvaluated < EntriesToEnumerate;
         PathsEvaluated ++) {
        PathLink = 
            RtlWeaklyEnumerateEntryHashTable(
                &PathSet->Table,
                &PathSet->Enumerator);

        if (PathLink == NULL) {
            break;
        }

        Path = IppGetPathFromPathLink(PathLink);

        //
        // If the total number of paths is above a certain SKU-based
        // threshold, then clean up _every_ cached path, otherwise
        // only remove cached-paths above a certain age.
        //
        if (Path->ReferenceCount == 1) {
            if ((RtlTotalEntriesHashTable(&PathSet->Table) > IppMaxPaths) ||
                ((TickCount - Path->LastUsed) > IppMaxCachedPathAge)) {
                RtlRemoveEntryHashTable(&PathSet->Table, PathLink, NULL);
                IppDereferencePath(Path);

                PathSet->CachedPathsScavenged ++;
                continue;
            }

            //
            // We didn't remove the path. So account for it.
            //

            PathSet->CachedPathEstimateDuringEnumeration ++;
        }        
    }

    PathSet->LastIterationPathCount = 
        RtlTotalEntriesHashTable(&PathSet->Table);
    //
    // If the enumeration has reached its end, then update the cached-path
    // estimate.
    //

    if (PathLink == NULL) {
        RtlEndWeakEnumerationHashTable(&PathSet->Table, &PathSet->Enumerator);

        PathSet->CachedPathEstimate =
            PathSet->CachedPathEstimateDuringEnumeration;
        PathSet->CachedPathEstimateDuringEnumeration = 0;
        PathSet->LastEnumerationTick = TickCount;
        ASSERT(RtlActiveEnumeratorsHashTable(&PathSet->Table) == 0);
    }

    RtlReleaseScalableWriteLockFromDpcLevel(&PathSet->Lock, &LockHandle);
}


    
VOID
IppUpdateUnicastRouteLifetimes(
    IN PIPR_LOCKED_SET RouteSet,
    IN OUT PIP_UNICAST_ROUTE Route
    )
/*++

Routine Description:

    Update the lifetime values for a route.

Arguments:

    RouteSet - Supplies the set to which the route belongs.
    
    Route - Supplies the route whose lifetimes need to be updated.
        Returns the route with updated lifetimes.
        
Return Value:

    None.
    
Caller LOCK: Route Set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    ULONG RemainingTicks, ExpiredTicks;
    
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);

    if (Route->Flags.Immortal ||
        (Route->ValidLifetime == 0) ||
        (Route->ValidLifetime == INFINITE_LIFETIME)) {
        return;
    }    
    ASSERT(Route->ValidLifetime >= Route->PreferredLifetime);

    //
    // The timer is set to expire when ValidLifetime elapses.
    //
    RemainingTicks = 
        TtQueryTimer(RouteSet->TimerTable, &(Route->Timer));
    ASSERT(RemainingTicks <= Route->ValidLifetime);

    ExpiredTicks = Route->ValidLifetime - RemainingTicks;

    //
    // Update the lifetimes.
    //
    Route->ValidLifetime = RemainingTicks;
    if (Route->PreferredLifetime > ExpiredTicks) {
        Route->PreferredLifetime -= ExpiredTicks;
    } else {
        Route->PreferredLifetime = 0;
    }
}

__inline
VOID
IppSetRouteState(
    IN PIP_UNICAST_ROUTE Route, 
    IN IP_ROUTE_STATE State
    )
/*++

Routine Description:

    This routine sets the state of a route. 
    
Arguments:

    Route - Supplies the route whose state needs to change. 

    State - Supplies the new state.

Return Value:

    None.

Caller Lock:
    
    None.  The state is not protected by a lock. This is okay since the State
    and StateChangeTick do not have to be completely in synch.

--*/ 
{
    //
    // Update the state and the time the state was changed. 
    //
    Route->State = State;
    Route->StateChangeTick = IppTickCount;
}

__inline
IP_ROUTE_STATE
IppGetRouteState(
    IN PIP_UNICAST_ROUTE Route
    )
/*++

Routine Description:
 
    This routine returns the state of a route based.  Before returning the
    state, it updates the state based on timeouts.  For instance, a dead route
    moves into probe state after the DEAD_ROUTE_TIMEOUT.  Similarly, a route
    moves from probe to dead after the DEAD_ROUTE_PROBE_TIMEOUT. 
   
Arguments:

    Route - Supplies the route.

Return Value:

    Returns the state of the route.

Caller Lock:
    
    None.

--*/ 
{
    PIP_PROTOCOL Protocol = Route->Interface->Compartment->Protocol;
    ULONG TickCount = IppTickCount;    
    
    if (Route->State == RouteDead) {
        if ((TickCount - Route->StateChangeTick) >=
            Protocol->DeadRouteTimeout) {
            IppSetRouteState(Route, RouteProbe);
        } 
    } else if (Route->State == RouteProbe) {
        if ((TickCount - Route->StateChangeTick) >=
            Protocol->DeadRouteProbeTimeout) {
            IppSetRouteState(Route, RouteDead);
        }
    }

    return Route->State;
}


__inline
BOOLEAN
IppIsRouteDead(
    IN PIP_UNICAST_ROUTE Route
    )
/*++

Routine Description:

    This routine determines if the route should be considered dead for the
    purpose of a route lookup.  If the state of the route is RouteAlive, then
    the route is not dead.  If it is RouteDead, then the route is dead.  If the
    state is RouteProbe, then some small percentage of new connections are
    directed through this gateway. 
    
Arguments:

    Route - Supplies the route.

Return Value:

    Returns a boolean indicating whether the route is dead or not. 
    
Caller Lock:
    
    None.

--*/ 
{
    IP_ROUTE_STATE State = IppGetRouteState(Route);
    
    if (Route->Flags.Ignore) {
        return TRUE;
    }
    
    if (State == RouteProbe) {
        //
        // REVIEW: Should this be the percentage for all gateways in the probe
        // state combined or every single gateway. 
        //
        if (RandomNumber(0, 100) < 
            Route->Interface->Compartment->Protocol->
                DeadRouteProbeTrafficPercent) {
            return FALSE;
        } else {
            return TRUE;
        }
    } else if (State == RouteDead) {
        return TRUE;
    } else {
        return FALSE;
    }
}

PIP_UNICAST_ROUTE
IppFindRoute(
    IN PIP_PROTOCOL Protocol,
    IN PIP_UNICAST_ROUTE RouteList,
    IN CONST IF_LUID *InterfaceLuid OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL
    )
/*++

Routine Description:

    This function attemps to locate the route that exactly matches the
    criteria provided given a route list all with the same prefix.
    
Arguments:

    Protocol - Supplies the IP protocol information.
    
    RouteList - Supplies the head of the route list to search through.

    InterfaceLuid - Optionally supplies an interface LUID to match the route 
        against.

    NextHopAddress - Optionally supplies the next hop address to match.

Return Value:

    The route that matches the criteria exactly or NULL.

Caller LOCK: Route Set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_UNICAST_ROUTE Route;
    PUCHAR RouteNextHop;
    
    Route = RouteList;
    
    do {
        if ((InterfaceLuid == NULL) || 
            RtlEqualMemory(InterfaceLuid, 
                           &Route->Interface->Luid, 
                           sizeof(IF_LUID))) {

            if (NextHopAddress == NULL) {
                return Route;
            }
            RouteNextHop = IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route);
            
            if (RtlEqualMemory(NextHopAddress, 
                               RouteNextHop,
                               Protocol->Characteristics->AddressBytes)) {
                return Route;
            }
        }

        Route = (PIP_UNICAST_ROUTE)
            CONTAINING_RECORD(
                Route->RouteLink.Flink, IP_UNICAST_ROUTE, RouteLink);
        
    } while (Route != RouteList);

    return NULL;
}

    

VOID
IppInsertRoute(
    IN PIP_ROUTE Route
    )
/*++

Routine Description:

    Insert a route into a list of routes all sharing the same prefix.
    Should not be called to insert the first node in the list.
    
    If multiple routes share the same prefix,
    then the older route is at the beginning of the list.

Arguments:

    Route - Supplies the route to be inserted.

Return Value:

    None

Caller LOCK: Route Set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).
    
--*/
{   
    PIP_ROUTE FirstRoute;
    
    FirstRoute = (PIP_ROUTE)
        CONTAINING_RECORD(PtGetData(&Route->Link), IP_UNICAST_ROUTE, Link);

    InsertTailList(&FirstRoute->RouteLink, &Route->RouteLink);
}


VOID
IppRemoveRoute(
    IN PIP_ROUTE Route
    )
/*++

Routine Description:

    Remove a route from the route tree.
    Should not be called to remove the last node in the list.

Arguments:

    Route - Supplies the route to remove.

Return Value:

    None

Caller LOCK: Route Set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_ROUTE NextRoute;
    
    if (PtGetData(&Route->Link) == &Route->Link) {
        //
        // This is the first route the routing table entry points to,
        // we must repoint the routing table to the next entry.
        //
        NextRoute = (PIP_ROUTE)
            CONTAINING_RECORD(Route->RouteLink.Flink, IP_ROUTE, RouteLink);
        PtSetData(&Route->Link, &NextRoute->Link);
    }
    RemoveEntryList(&Route->RouteLink);
    InitializeListHead(&Route->RouteLink);
}


PIP_UNICAST_ROUTE
IppCreateUnicastRoute(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Key,
    IN USHORT KeyLength,
    IN IP_UNICAST_ROUTE *FirstRoute,
    IN PIP_INTERFACE Interface, 
    IN BOOLEAN IsLoopback, 
    IN PVOID NextHop OPTIONAL, 
    IN CONST UCHAR *NextHopAddress OPTIONAL
    )
{
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
    PIP_UNICAST_ROUTE Route;
    PIPR_LINK Link;
    NTSTATUS Status;
   
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);

    Route = (PIP_UNICAST_ROUTE) FsbAllocate(Protocol->UnicastRoutePool);
    if (Route == NULL) {
        return NULL;
    }
    RtlZeroMemory(Route, Protocol->UnicastRouteSize);
    Route->Signature = IP_ROUTE_SIGNATURE;

    //
    // One reference for the RouteSet.
    //
    Route->ReferenceCount = 1;
    
    //
    // Make the route current.
    //
    InitializeListHead(&Route->RouteLink);

    //
    // Insert in the RouteSet. First take care of the case where we have to
    // look for an existing prefix entry.
    //
    if (FirstRoute == NULL) {
        PtGetExactMatch(RouteSet->Tree, Key, KeyLength, NULL, &Link);
        if (Link != NULL) {
            FirstRoute = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
                Link, IP_UNICAST_ROUTE, Link);
        }
    }
    
    if (FirstRoute != NULL) {
        //
        // We already have a prefix entry which we should insert into.
        //
        Route->Link = FirstRoute->Link;
        IppInsertRoute((PIP_ROUTE) Route);
        Status = STATUS_SUCCESS;
    } else {
        Status =
            PtInsertEntry(
                RouteSet->Tree, 
                Key,
                KeyLength, 
                NULL,
                &(Route->Link));
    }
    
    if (!NT_SUCCESS(Status)) {
        IppDereferenceRoute((PIP_ROUTE)Route);
        return NULL;
    }

    //
    // Initialize to indicate a dormant timer.
    //
    TtInitializeTimer(&(Route->Timer));
    
    //
    // Set the interface in the route. 
    //
    if (Interface != NULL) {
        Route->Interface = Interface;
        IppReferenceInterface(Route->Interface);
    }
      
    //
    // Set the next hop entry. 
    //
    if (NextHop != NULL) {
        if (IsLoopback) {
            Route->LocalAddress = NextHop;
            IppReferenceLocalAddress(Route->LocalAddress);
        } else {
            Route->CurrentNextHop = NextHop;
            IppReferenceNeighbor(Route->CurrentNextHop);
        }
    }

    //
    // Set the next hop address. 
    //
    if (NextHopAddress != NULL) {
        RtlCopyMemory(IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route),
                      NextHopAddress, 
                      Protocol->Characteristics->AddressBytes);
    }
   
    //
    // Set the flag marking it as in the RouteSet
    //
    Route->Flags.InRouteSet = TRUE;
 
    return Route;
}


VOID
IppDeleteUnicastRoute(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route
    )
{
    PIPR_LOCKED_SET RouteSet = &(Compartment->RouteSet);
    NTSTATUS Status;
    
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);
 
    //
    // Stop any pending timers.
    //
    if (TtIsTimerActive(&Route->Timer)) {
        TtStopTimer(RouteSet->TimerTable, &Route->Timer);
        TtInitializeTimer(&Route->Timer);
    }

    //
    // If this is the only route for a prefix then remove the prefix,
    // otherwise, unlink this route from the list.
    //
    if (IsListEmpty(&Route->RouteLink)) {
        Status = PtDeleteEntry(RouteSet->Tree, &(Route->Link));
        ASSERT(NT_SUCCESS(Status));
    } else {
        IppRemoveRoute((PIP_ROUTE)Route);
    }

    Route->Flags.InRouteSet = FALSE;
    
    IppDereferenceRoute((PIP_ROUTE) Route);
}


__inline
BOOLEAN
IppIsBroadcastAddressRequiredForRoute(
    IN PIP_PROTOCOL Protocol, 
    IN PIP_UNICAST_ROUTE Route
    )
{
    return ((Route->CurrentNextHop == NULL) &&
            (Protocol->Characteristics->NetworkProtocolId == AF_INET));
}

NTSTATUS
IppCreateBroadcastAddressForRoute(
    IN CONST UCHAR *Key, 
    IN USHORT KeyLength,
    IN PIP_UNICAST_ROUTE Route
    )
/*++

Routine Description:
 
    This routine creates a broadcast address entry corresponding to an on-link
    route.  
    
Arguments:

    Key - Supplies the key. 

    KeyLength - Supplies the length of the key. 

    Route - Supplies the route for which to create the broadcast address. 

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:

    Assumes caller holds the route set exclusive lock. 
    Assumes caller holds the interface exclusive lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = Route->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIP_LOCAL_BROADCAST_ADDRESS BroadcastAddressEntry;
    IN_ADDR BroadcastAddress;
    PUCHAR DestinationPrefix;
    UINT8 DestinationPrefixLength;
    NTSTATUS Status;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Interface->Compartment->RouteSet.Lock);
    
    //
    // If this is an on-link route, create the broadcast address corresponding
    // to it. 
    // 
    if (!IppIsBroadcastAddressRequiredForRoute(Protocol, Route)) {
        return STATUS_SUCCESS;
    }
    
    Protocol->
        ParseRouteKey(
            Key, 
            KeyLength, 
            &DestinationPrefix, 
            &DestinationPrefixLength,
            NULL,
            NULL);
    //
    // Don't create or delete broadcast addresses for default routes.  The
    // broadcast address for them is created/destroyed when the interface
    // is created/deleted.  Also, don't create broadcast addresses if the
    // on-link route is a host route or it is a multicast route.
    //
    if ((DestinationPrefixLength == 0) ||
        (DestinationPrefixLength == 
         Protocol->Characteristics->AddressBytes * 8) ||
        (Protocol->AddressType(DestinationPrefix) == NlatMulticast)) {
        return STATUS_SUCCESS;
    }
    
    CreateBroadcastAddress(
        DestinationPrefix,
        DestinationPrefixLength,
        sizeof(IN_ADDR), 
        (BOOLEAN) Interface->UseZeroBroadcastAddress,
        (PUCHAR)&BroadcastAddress);
    
    //
    // We should already be holding the interface write lock (and the route set
    // lock). 
    //
    Status = IppFindOrCreateLocalBroadcastAddress(
        (CONST UCHAR*)&BroadcastAddress,
        Interface,
        ADDR_CONF_MANUAL, 
        TRUE,
        &BroadcastAddressEntry);
    if (NT_SUCCESS(Status)) {
        //
        // Remove the reference returned by
        // IppFindOrCreateLocalBroadcastAddress.
        //
        IppDereferenceLocalBroadcastAddress(BroadcastAddressEntry);
    }

    //
    // Morph the neighbor (if any) to NlatBroadcast.
    //
    IppMorphNeighborAtDpc(
        Interface, (PUCHAR) &BroadcastAddress, NlatBroadcast);
    
    return Status;
}

VOID
IppDeleteBroadcastAddressForRoute(
    IN PIP_UNICAST_ROUTE Route
    )
/*++

Routine Description:
 
    This routine creates a broadcast address entry corresponding to an on-link
    route.  
    
Arguments:

    Route - Supplies the route for which to create the broadcast address. 

Return Value:

    None.

Caller LOCK:

    Assumes caller holds the route set exclusive lock. 
    Assumes caller holds the interface exclusive lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = Route->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PUCHAR DestinationPrefix, Key;
    UINT8 DestinationPrefixLength;
    USHORT KeyLength;
    PIP_LOCAL_BROADCAST_ADDRESS LocalBroadcastAddress;
    IN_ADDR BroadcastAddress;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Interface->Compartment->RouteSet.Lock);

    //
    // If this is an on-link route, delete the broadcast address corresponding
    // to it. 
    // 
    if (!IppIsBroadcastAddressRequiredForRoute(Protocol, Route)) {
        return;
    }
    
    PtGetKey(&Route->Link, &Key, &KeyLength);
    Protocol->
        ParseRouteKey(
            Key, 
            KeyLength, 
            &DestinationPrefix, 
            &DestinationPrefixLength, 
            NULL, 
            NULL);

    //
    // Don't create or delete broadcast addresses for default routes.  The
    // broadcast address for them is created/destroyed when the interface
    // is created/deleted.  Also, don't create broadcast addresses if the
    // on-link route is a host route.
    //
    if ((DestinationPrefixLength == 0) || 
        (DestinationPrefixLength == 
         Protocol->Characteristics->AddressBytes * 8)) {
        return;
    }
    
    CreateBroadcastAddress(
        DestinationPrefix, 
        DestinationPrefixLength, 
        sizeof(IN_ADDR), 
        (BOOLEAN) Interface->UseZeroBroadcastAddress, 
        (PUCHAR)&BroadcastAddress);

    LocalBroadcastAddress =
        IppFindAddressOnInterfaceUnderLock(
            Interface, 
            (CONST UCHAR*) &BroadcastAddress);
    if (LocalBroadcastAddress != NULL) {
        //
        // Remove the address from the address set.
        //
        IppRemoveLocalAddressUnderLock(
            (PIP_LOCAL_ADDRESS) LocalBroadcastAddress, TRUE);

        //
        // Remove the reference returned by IppFindAddressOnInterface. 
        //
        IppDereferenceLocalBroadcastAddress(LocalBroadcastAddress);

        //
        // Morph the neighbor (if any) to NlatUnicast.
        //
        IppMorphNeighborAtDpc(
            Interface, (PUCHAR) &BroadcastAddress, NlatUnicast);
    }
}

VOID
IppRefreshUnicastRoute(
    IN PIP_COMPARTMENT Compartment,    
    IN PIP_UNICAST_ROUTE Route
   )
{
    PIPR_LOCKED_SET RouteSet = &(Compartment->RouteSet);
    
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);
 
    //
    // Stop any pending timers.
    //
    if (TtIsTimerActive(&(Route->Timer))) {
        TtStopTimer(RouteSet->TimerTable, &(Route->Timer));
        
    }
    
    if (!Route->Flags.Immortal &&
        (Route->ValidLifetime != 0) &&
        (Route->ValidLifetime != INFINITE_LIFETIME)) {
        TtStartTimer(
            RouteSet->TimerTable, 
            &(Route->Timer), 
            Route->ValidLifetime);
    }
}


VOID
IppFreeRoute(
    IN PIP_ROUTE *RoutePointer
    )
/*++

Routine Description:

    Frees memory and references held by a route.

Arguments:

    RoutePointer - Supplies a pointer to the route to free.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_UNICAST_ROUTE Route = (PIP_UNICAST_ROUTE) *RoutePointer;

    *RoutePointer = NULL;

    ASSERT(Route->ReferenceCount == 0);

    if (Route->Flags.Loopback) {
        if (Route->LocalAddress != NULL) {
            IppDereferenceLocalAddress(Route->LocalAddress);
        }
    } else {
        if (Route->CurrentNextHop != NULL) {
            IppDereferenceNeighbor(Route->CurrentNextHop);
        }
    }

    if (Route->Interface != NULL) {
        IppDereferenceInterface(Route->Interface);
    }

    FsbFree((PUCHAR)Route);
}

VOID
IppDereferenceRoute(
    IN PIP_ROUTE Route
    )
/*++

Routine Description:

    Releases a reference on a route entry.

Arguments:

    Route - Supplies the route entry to dereference.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ASSERT(Route->ReferenceCount > 0);
    
    if (InterlockedDecrement(&Route->ReferenceCount) == 0) {
        IppFreeRoute(&Route);
    }
}


VOID
IppDereferenceRouteForUser(
    IN PIP_UNICAST_ROUTE Route,
    IN PIP_COMPARTMENT Compartment,
    CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength
    )
/*++
Routine Description:

    Since routes have user references, this decrements the user reference and
    if 0 then actually Deletes the route.

Arguments:

    Route - Supplies the route entry to dereference.

    Compartment - Supplies the compartment for the route.

    DestinationPrefix - Supplies the destination prefix.

    DestinationPrefixLength - Supplies the length of the destination prefix.

Locks: 

    Assumes caller holds the interface and route set exclusive lock. 

Caller IRQL:

    DISPATCH level - must be holding modify lock on route.

--*/
{
    ASSERT_WRITE_LOCK_HELD(&Route->Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Compartment->RouteSet.Lock);
    
    //
    // No interlocked operation needed for the UserReferenceCount since it is
    // always changed under lock. 
    //
    Route->UserReferenceCount--;
    if (Route->UserReferenceCount > 0) {
        return;
    }

    //
    // If all user reference counts were used up then the route should be
    // deleted from the system.
    //
    ASSERT(Route->ReferenceCount > 0);

    //
    // Delete the broadcast address for the route. 
    //
    IppDeleteBroadcastAddressForRoute(Route);
    IppRouteTrace(TRACE_LEVEL_WARNING, 
                  "Deleted route", 
                  Compartment->Protocol,
                  DestinationPrefix, 
                  DestinationPrefixLength, 
                  Route->Interface,
                  (UCHAR *)(Route+1));
    
    //
    // Remove the route from the set.
    //
    IppNotifyRouteChange(Route, NsiDeleteInstance);
    IppDeleteUnicastRoute(Compartment, Route);
}


VOID
IppGarbageCollectRoutes(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    Free up space used by deleted route entries in the table, and entries
    on interfaces going away.  We do this by filling in a new instance 
    which contains only valid routes.

Arguments:

    Compartment - Supplies the compartment to clean up routes in.

Locks:

    Locks the route table.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG Count;
    PPREFIX_TREE_LINK Link;
    PIP_UNICAST_ROUTE Route, NextRoute;
    NTSTATUS EnumStatus;
    PREFIX_TREE_CONTEXT Context;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
               "IPNG: Cleaning up route table\n");

    RtlZeroMemory(&Context, sizeof(Context));
    Count = 1;

    RtlAcquireScalableWriteLock(&Compartment->RouteSet.Lock, &LockHandle);
    do {
        EnumStatus = PtEnumOverTable(
            Compartment->RouteSet.Tree,
            NULL,
            NULL,
            &Context,
            NULL,
            0,
            &Count,
            &Link);
        if (Count == 0) {
            break;
        }

        Route = CONTAINING_RECORD(Link, IP_UNICAST_ROUTE, Link);

        for (; Route != NULL; Route = NextRoute) {
            NextRoute = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
                Route->RouteLink.Flink, IP_UNICAST_ROUTE, RouteLink);
            if (PtGetData(&Route->Link) == &NextRoute->Link) {
                NextRoute = NULL;
            }

            //
            // A route is deleted if one of the following is true:
            // (1) The deleted flag is set in the route. 
            // (2) The route is using a disabled interface.
            // (3) The route is using a disabled sub-interface. 
            //
            if (Route->Flags.Deleted ||
                IppIsInterfaceDisabled(Route->Interface) ||
                (!Route->Flags.Loopback &&
                 !IppIsOnLinkRoute(Route) &&
                 (Route->CurrentNextHop->SubInterface->
                  FlDeleteComplete != NULL))) {
                
                if (!Route->Flags.Deleted) {
                    //
                    // We have not notified the user, do so now.
                    //
                    IppNotifyRouteChange(
                        (PIP_UNICAST_ROUTE) Route,
                        NsiDeleteInstance);
                }
                
                //
                // Delete the route.
                //
                IppDeleteUnicastRoute(Compartment, Route);
            }
        } 
    } while (EnumStatus != STATUS_NO_MORE_MATCHES);

    IppInvalidateDestinationCache(Compartment);
    
    RtlReleaseScalableWriteLock(&Compartment->RouteSet.Lock, &LockHandle);
}


VOID
IppRemoveSitePrefixEntry(
    IN PIP_SITE_PREFIX_ENTRY SitePrefixEntry
    )
/*++

Routine Description:
    
    This routine cleans up a site prefix entry. It removes the entry from the
    list, cleans up the reference to the interface and frees the memory
    associated with it. 
    
Arguments:

    SitePrefixEntry - Supplies the site prefix entry to clean up.

Return Value:

    None.
    
Locks:

    Caller should hold the site prefix set lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    //
    // Remove the site prefix entry from the list.
    //
    RemoveEntryList(&SitePrefixEntry->Link);
    
    //
    // Remove the reference on the interface. 
    //
    IppDereferenceInterface(SitePrefixEntry->Interface);
    
    //
    // Release the site prefix entry.
    //
    ExFreePool(SitePrefixEntry);
}

VOID
IppDeleteSitePrefixes(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
    
    This routine cleans up all site prefixes on a particular interface. 

Arguments:

    Compartment - Supplies the compartment in which to clean up the site prefix
        entries. 

    Interface - Supplies the interface for which to clean up the site prefix
        entries. 

Return Value:

    None.
    
Locks:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    KIRQL OriginalIrql;
    PIP_SITE_PREFIX_ENTRY SitePrefixEntry;
    PLIST_ENTRY Head, Next, Current;

    KeAcquireSpinLock(&Compartment->SitePrefixSet.Lock, &OriginalIrql);

    Head = &Compartment->SitePrefixSet.Set;
    for (Current = Head->Flink; Current != Head; Current = Next) {
        Next = Current->Flink;
        SitePrefixEntry = (PIP_SITE_PREFIX_ENTRY)
            CONTAINING_RECORD(Current, IP_SITE_PREFIX_ENTRY, Link);

        if (SitePrefixEntry->Interface == Interface) {
            IppRemoveSitePrefixEntry(SitePrefixEntry);
        }
    }

    KeReleaseSpinLock(&Compartment->SitePrefixSet.Lock, OriginalIrql);
}


NTSTATUS
IppStartRouteManager(
    IN PIP_PROTOCOL Protocol
    )
{
    Protocol->PathPool = FsbCreatePool(
        Protocol->PathSize, 0, IpPathPoolTag, NULL);
    if (Protocol->PathPool == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Protocol->UnicastRoutePool = FsbCreatePool(Protocol->UnicastRouteSize, 
                                               0,
                                               IpUnicastRoutePoolTag, 
                                               NULL);
    if (Protocol->UnicastRoutePool == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting route manager: "
                   "Cannot allocate unicast route pool\n");
        FsbDestroyPool(Protocol->PathPool);
        Protocol->PathPool = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IppDefaultStartRoutine(Protocol, IMS_ROUTE_MANAGER);

    return STATUS_SUCCESS;
}

VOID
IppCleanupRouteManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Cleans up all state in the route manager.

Arguments:

    Protocol - Supplies the protocol being stopped.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    FsbDestroyPool(Protocol->UnicastRoutePool);
    FsbDestroyPool(Protocol->PathPool);
}

LONG
IppCompareRoutes(
    IN PIP_UNICAST_ROUTE A,
    IN IP_NEIGHBOR_REACHABILITY AReachable,
    IN ULONG AHash,
    IN PIP_UNICAST_ROUTE B,
    IN IP_NEIGHBOR_REACHABILITY BReachable,
    IN ULONG BHash
    )
/*++

Routine Description:

    Compares the desirability of two routes.
    >0 means A is preferred,
    0 means no preference,
    <0 means B is preferred.
  
    It is very important that the comparison relation be transitive,
    to achieve predictable route selection.
  
--*/
{
    ULONG AMetric, BMetric;
    PUCHAR AKey, BKey;
    USHORT AKeyLength, BKeyLength;
    BOOLEAN ADead, BDead;
    
    //
    // Compare reachability.
    //
    if (AReachable > BReachable) {
        return 1;               // Prefer A.
    } else if (BReachable > AReachable) {
        return -1;              // Prefer B.
    }

    //
    // Compare prefix length.
    //
    PtGetKey(&A->Link, &AKey, &AKeyLength);
    PtGetKey(&B->Link, &BKey, &BKeyLength);
    if (AKeyLength > BKeyLength) {
        return 1;               // Prefer A.
    } else if (BKeyLength > AKeyLength) {
        return -1;              // Prefer B.
    }

    //
    // Compare dead gateway flag.  Gateway that has not been marked dead is
    // preferred over one that has been marked dead (even if the dead gateway
    // has a better metric, but not if the dead gateway has a longer prefix
    // length). 
    //
    ADead = IppIsRouteDead(A);
    BDead = IppIsRouteDead(B);
    if (ADead != BDead) {
        if (!ADead) {
            return 1;           // Prefer A. 
        } else {
            return -1;          // Prefer B. 
        }
    }
    
    //
    // Compare metric.
    // Route & interface metric values are restricted
    // so that these additions do not overflow.
    //
    AMetric = A->Interface->Metric + A->Metric;
    BMetric = B->Interface->Metric + B->Metric;

    if (AMetric < BMetric) {
        return 1;               // Prefer A.
    } else if (BMetric < AMetric) {
        return -1;              // Prefer B.
    }

    //
    // Compare hash.
    //
    if (AHash > BHash) {
        return 1;               // Prefer A.
    } else if (BHash > AHash) {
        return -1;              // Prefer B.
    }
    
    return 0;                   // No preference.
}


__forceinline
VOID
IppCompareAndUpdateNextHop(
    IN PIP_NEXT_HOP NextHop,
    IN PIP_UNICAST_ROUTE Route,
    IN IP_NEIGHBOR_REACHABILITY Reachable,
    IN ULONG Hash,
    IN OUT PIP_NEXT_HOP *BestNextHop,
    IN OUT PIP_UNICAST_ROUTE *BestRoute,
    IN OUT IP_NEIGHBOR_REACHABILITY *BestReachable,
    IN OUT ULONG *BestHash,
    IN OUT INT *BestCouldBeBetterReachable
    )
{
    LONG Better;

    if (*BestNextHop == NULL) {
        //
        // This is the first suitable next hop, so remember it.
        //
RememberBest:
        IppReferenceNextHop(NextHop);
        
        *BestNextHop = NextHop;
        *BestRoute = Route;
        *BestReachable = Reachable;
        *BestHash = Hash;
        
        return;
    }

    Better =
        IppCompareRoutes(
            Route, Reachable, Hash,
            *BestRoute, *BestReachable, *BestHash);
                        
    if (Better > 0) {
        //
        // This next hop looks better.
        // If the old best route is via a currently-unreachable neighbor,
        // check if it might be a better route if the neighbor were reachable.
        //
        if (*BestNextHop != NULL) {
            if (!*BestCouldBeBetterReachable &&
                (*BestReachable == NeighborUnreachable) &&
                (IppCompareRoutes(
                    Route, Reachable, 0,
                    *BestRoute, NeighborMayBeReachable, 0) < Better)) {
                *BestCouldBeBetterReachable = TRUE;
            }
            IppDereferenceNextHop(*BestNextHop);
        }

        goto RememberBest;

    } else {
        //
        // If this is a route via a currently-unreachable neighbor,
        // check if it might be a better route if the neighbor were reachable.
        //
        if (!*BestCouldBeBetterReachable &&
            (Reachable == NeighborUnreachable) &&
            (IppCompareRoutes(
                Route, NeighborMayBeReachable, 0,
                *BestRoute, *BestReachable, 0) > Better)) {
            *BestCouldBeBetterReachable = TRUE;
        }
    }    
}    

NTSTATUS
IppFindNextHopAtDpc(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Destination,
    IN CONST UCHAR *Source OPTIONAL,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN SCOPE_ID ScopeId,
    OUT PIP_NEXT_HOP *ReturnNextHop,
    OUT PIP_PATH_FLAGS ReturnConstrained,
    OUT PIP_UNICAST_ROUTE *ReturnRoute OPTIONAL
    )
/*++

Routine Description:

    Given a destination address, checks the list of routes
    using the longest-matching-prefix algorithm
    to decide if we have a route to this address.
    If so, returns the neighbor through which we should route.
  
    If the optional Interface is supplied, then this constrains the lookup
    to only use routes via the specified outgoing interface.
    If Interface is specified then ScopeId should be specified.

    If the optional ScopeId is supplied, then this constraints the lookup
    to only use routes via interfaces in the correct zone for the
    scope of the destination address.
  
    If the optional Source is supplied, then a hashing function will be used in
    selecting the best route should there be multiple routes with equal weight.
    This ensures better distribution of traffic over the routes.
    
    The ReturnConstrained parameter returns an indication of whether the
    Interface and ScopeId parameters constrained the returned neighbor.
    That is, if Interface is NULL and ScopeId is zero (for scoped 
    destinations) then Constrained is always returned as zero. If 
    Interface is non-NULL and a different neighbor is returned than would 
    have been returned if Interface were NULL, then Constrained is returned 
    with IP_PATH_FLAG_CONSTRAINED_INTERFACE set.
    Similarly, if ScopeId is non-zero and a different neighbor is returned
    than would have been returned if ScopeId were zero, then Constrained
    is returned with IP_PATH_FLAG_CONSTRAINED_SCOPEID set.

    NOTE: Any code path that changes any state used by FindNextHopHelper
    must use InvalidateDestinationCache.
  
    May be called with the RouteCacheLock held.

Return Value:

    Other than STATUS_NOT_FOUND, which is handled by IppRouteToDestination,
    the return value must be an NTSTATUS code which matches a TDI status code.

    STATUS_SUCCESS
    STATUS_INSUFFICIENT_RESOURCES
    STATUS_INVALID_PARAMETER
    STATUS_HOST_UNREACHABLE

Caller IRQL:

    Must be called at DISPATCH level.
  
--*/
{
    PIP_UNICAST_ROUTE Route, NextRoute;
    PIP_NEXT_HOP NextHop;
    PIP_NEIGHBOR Neighbor;
    PIP_LOCAL_ADDRESS LocalAddress;
    UINT MinPrefixLength;
    IP_NEIGHBOR_REACHABILITY Reachable;
    SCOPE_LEVEL Scope;
    NTSTATUS Status;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
    HANDLE Tree = RouteSet->Tree;
    UCHAR KeyBuffer[ROUTE_KEY_STORAGE_SIZE];
    PUCHAR Key;
    USHORT KeyLength;
    PPREFIX_TREE_LINK Link;
    ULONG BaseHash = 0;
    ULONG Hash = 0;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    NL_ADDRESS_TYPE AddressType = Protocol->AddressType(Destination);
    NL_ADDRESS_TYPE OriginalAddressType = AddressType;

    //
    // These variables track the best route that we can actually return,
    // subject to the Interface and ScopeId constraints.
    //
    PIP_NEXT_HOP BestNextHop = NULL;   // Holds a reference.

    //
    // Best[Route|Reachable|Hash] - Used when BestNextHop is non-NULL.
    //
    PIP_UNICAST_ROUTE BestRoute = NULL;
    IP_NEIGHBOR_REACHABILITY BestReachable = 0;
    ULONG BestHash = 0;

    //
    // These variables track the best route in the right zone.
    // They are only used if Interface != NULL.
    //
    PIP_NEXT_HOP BzoneNextHop = NULL;   // Holds a reference.

    //
    // Bzone[Route|Reachable|Hash] - Used when BzoneNextHop is non-NULL.
    //
    PIP_UNICAST_ROUTE BzoneRoute = NULL;
    IP_NEIGHBOR_REACHABILITY BzoneReachable = 0;
    ULONG BzoneHash = 0;
    
    //
    // These variables track the best unconstrained route.
    // They are only used if Interface != NULL or ScopeId != 0:
    // in other words, if there is some constraint.
    //
    PIP_NEXT_HOP BallNextHop = NULL;   // Holds a reference.

    //
    // Ball[Route|Reachable|Hash] - Used when BallNextHop is non-NULL.
    //
    PIP_UNICAST_ROUTE BallRoute = NULL;
    IP_NEIGHBOR_REACHABILITY BallReachable = 0;
    ULONG BallHash = 0;

    //
    // Keep track of whether there could be a better route
    // than the one we are returning, if a neighbor that is
    // currently unreachable were reachable instead.
    //
    INT BestCouldBeBetterReachable = FALSE;
    INT BzoneCouldBeBetterReachable = FALSE;
    INT BallCouldBeBetterReachable = FALSE;
    
    //
    // Keep track of whether the destination could be on-link to an interface.
    //
    INT CouldBeBetterOnLink = FALSE;

    DISPATCH_CODE();

    if (AddressType == NlatInvalid) {
        return STATUS_NOT_FOUND;
    }
    
    //
    // Initialize all the return values. 
    //
    ReturnConstrained->Value = 0;
    *ReturnNextHop = NULL;
    if (ReturnRoute != NULL) {
        *ReturnRoute = NULL;
    }

    //
    // Calculate the scope of the destination address.
    //
    Scope = Protocol->AddressScope(Destination);
    ASSERT((Interface == NULL) ||
           ((ScopeId.Zone != 0) && 
            (ScopeId.Zone == IppGetInterfaceScopeZone(Interface, Scope))));

    //
    // This routine can take the unspecified address as input
    // (this is to support GetBestRoute for the unspecified address).
    //
    if (AddressType == NlatMulticast) {
        if (Interface != NULL) {
            LocalAddress =
                IppFindAddressOnInterface(Interface, Destination);
        } else {
            LocalAddress =
                IppFindAddressInScope(Compartment, ScopeId, Destination);
        }

        if (LocalAddress != NULL) {
            *ReturnNextHop = (PIP_NEXT_HOP) LocalAddress;
            return STATUS_SUCCESS;
        }
    }

    //
    // Compute the base hash value once.
    //
    if (Source != NULL) {
        BaseHash =
            ROUTE_HASH_LEVEL1(
                *((ULONG UNALIGNED *) (Source + AddressBytes - 4)),
                *((ULONG UNALIGNED *) (Destination + AddressBytes - 4)));
    } else {
        BaseHash =
            ROUTE_HASH_LEVEL1(
                0xFFFFFFFF,
                *((ULONG UNALIGNED *) (Destination + AddressBytes - 4)));
    }
    
    //
    // We enforce a minimum prefix length for "on-link" addresses.
    // If we match a route that is shorter than the minimum prefix length,
    // we treat the route as if it were on-link. The net effect is
    // that a default route implies a default interface for multicast
    // and link-local destinations. This may of course be overridden
    // with the appropriate more-specific /8 or /10 route.
    //
    if (AddressType == NlatMulticast) {
        MinPrefixLength = Protocol->MinimumMulticastPrefixLength;
    } else if (Scope == ScopeLevelLink) {
        MinPrefixLength = Protocol->MinimumOnLinkPrefixLength;
    } else {
        MinPrefixLength = 0;
    }

    Protocol->
        MakeRouteKey(
            Destination, AddressBytes * 8, NULL, 0, KeyBuffer, &KeyLength);

    RtlAcquireScalableReadLockAtDpcLevel(&RouteSet->Lock);

    Status = PtGetLongestMatch(Tree, KeyBuffer, &Link);

    while (NT_SUCCESS(Status)) {
        PtGetKey(Link, &Key, &KeyLength);

        if (KeyLength < MinPrefixLength) {
            break;
        }

        Route = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(Link, IP_ROUTE, Link);
        
        //
        // Loop through all routes for the same prefix.
        //
        do {
            NextRoute = (PIP_UNICAST_ROUTE)
                CONTAINING_RECORD(Route->RouteLink.Flink, IP_ROUTE, RouteLink);

            //
            // If there is a VPN Connection then block the usage of default
            // routes. 
            //

            //
            // Assuming Key length as zero for default routes will 
            // break if we expose source prefix for route lookup. 
            // The key length will not be zero when that happens.
            //
            if (Route->Interface->DisableDefaultRoutes &&
                (KeyLength == 0)) {                
                Route = NextRoute;
                continue;
            }
            NextHop = NULL;
            Neighbor = NULL;
            LocalAddress = NULL;
            
            if ((Route->ValidLifetime > 0) && 
                ((Route->Interface->ConnectedSubInterfaces != 0) ||
                 (OriginalAddressType != NlatBroadcast))) {
                //
                // Global broadcasts we want to send out only
                // on one of the connected interfaces,
                // while other local traffic we want to be looped back on 
                // unconnected interfaces (including local unicast and local subnet
                // brodcasts - for those OriginalAddressType != AddressType).
                // TODO: for subnet broadcasts in case multiple interfaces
                // match and some of them are disconnected, we can still pick up
                // a disconnected one. We don't fix it now because the fix
                // would be more complicated than only for the global broadcasts.
                //
                // We now have a match against a potential route.
                // Get a pointer to the next hop.
                //
                if (IppIsOnLinkRoute(Route)) {
                    if (IppIsEphemeralAddressCandidate(
                            Protocol, 
                            Destination)) {
                        Status = 
                            IppFindOrCreateLocalEphemeralAddressAtDpc(
                                Destination, 
                                Route->Interface, 
                                (PIP_LOCAL_UNICAST_ADDRESS *) &LocalAddress);
                        if (!NT_SUCCESS(Status)) {
                            //
                            // Just bail out.
                            //
                            RtlReleaseScalableReadLockFromDpcLevel(
                                &RouteSet->Lock);
                            goto ReturnNoResources;
                        } 
                    } else {                        
                        //
                        // Note that in some situations we will create a 
                        // neighbor that we will end up not using. That's OK.
                        // The type of the neighbor should be up-to-date at 
                        // this point.  If the prefix length of the on-link 
                        // route < 32, then we should have a matched a 
                        // broadcast loopback route before reaching here (its 
                        // prefix length is always 32). If the prefix length 
                        // of the on-link route is 32, then the destination is
                        // not a broadcast address and we correctly use 
                        // NlatUnicast here. 
                        //
                        Neighbor =
                            IppFindOrCreateNeighborAtDpc(
                                Route->Interface, 
                                NULL, 
                                Destination, 
                                AddressType);
                        if (Neighbor == NULL) {
                            //
                            // Couldn't create a new neighbor.
                            // Just bail out now.
                            //
                            RtlReleaseScalableReadLockFromDpcLevel(
                                &RouteSet->Lock);
ReturnNoResources:
                            if (BestNextHop != NULL) {
                                IppDereferenceNextHop(BestNextHop);
                            };
                            if (BzoneNextHop != NULL) {
                                IppDereferenceNextHop(BzoneNextHop);
                            };
                            if (BallNextHop != NULL) {
                                IppDereferenceNextHop(BallNextHop);
                            };
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }
                    }
                } else if (!Route->Flags.Loopback) {
                    Neighbor = Route->CurrentNextHop;
                    IppReferenceNeighbor(Neighbor);
                } else {
                    LocalAddress = Route->LocalAddress;
                    IppReferenceLocalAddress(LocalAddress);
                    //
                    // Update the type of the neighbor based on the local
                    // address pointer.  This is needed for broadcast addresses
                    // so that if needed, we create a neighbor for the address
                    // with the correct address type. 
                    //
                    AddressType = NL_ADDRESS_TYPE(LocalAddress);
                }
            
                if (Neighbor != NULL) {
                    //
                    // Note that reachability state transitions
                    // must invalidate the route cache.
                    //
                    Reachable = IppGetNeighborReachability(Neighbor);
                } else {
                    //
                    // For loopback routes, assume the next hop is reachable.
                    //
                    Reachable = NeighborMayBeReachable;
                }

                Hash =
                    ROUTE_HASH_LEVEL2(
                        BaseHash,
                        *((PULONG)
                          ((IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route)) +
                           AddressBytes - 4)));

                NextHop = (Neighbor != NULL)
                    ? (PIP_NEXT_HOP) Neighbor
                    : (PIP_NEXT_HOP) LocalAddress;
                
                //
                // Track the best route that we can actually return,
                // subject to the Interface and ScopeId constraints.
                //
                if ((Interface == NULL)
                    ? ((ScopeId.Zone == 0) || 
                       (ScopeId.Zone ==
                        IppGetInterfaceScopeZone(Route->Interface, Scope)))
                    : (Interface == Route->Interface)) {
    
                    if (IppIsOnLinkRoute(Route)) {
                        CouldBeBetterOnLink = TRUE;
                    }

                    IppCompareAndUpdateNextHop(
                        NextHop,
                        Route,
                        Reachable,
                        Hash,
                        &BestNextHop,
                        &BestRoute,
                        &BestReachable,
                        &BestHash,
                        &BestCouldBeBetterReachable);                    
                }
    
                //
                // Track the best route in the right zone if 
                // the interface constraint is present. Otherwise this
                // is the same as the previous lookup.
                // This ignores the IF constraint.
                //
                if ((Interface != NULL) &&
                    ((ScopeId.Zone == 0) ||
                    (ScopeId.Zone == 
                     IppGetInterfaceScopeZone(Route->Interface, Scope)))) {
    
                    IppCompareAndUpdateNextHop(
                        NextHop,
                        Route,
                        Reachable,
                        Hash,
                        &BzoneNextHop,
                        &BzoneRoute,
                        &BzoneReachable,
                        &BzoneHash,
                        &BzoneCouldBeBetterReachable);                
                } 
                
                //
                // Track the best route matching the destination.
                // This ignores both IF and ScopeId constraints only 
                // if they are present.
                //
                if (ScopeId.Zone != 0) {
                    IppCompareAndUpdateNextHop(
                        NextHop,
                        Route,
                        Reachable,
                        Hash,
                        &BallNextHop,
                        &BallRoute,
                        &BallReachable,
                        &BallHash,
                        &BallCouldBeBetterReachable);
                } 
            
                if (Neighbor != NULL) {
                    IppDereferenceNeighbor(Neighbor);
                } else {
                    IppDereferenceLocalAddress(LocalAddress);
                }
            }
            
            Route = NextRoute;
        } while (Link != &Route->Link);

        //
        // This is an optimization. If we already have a route that is 
        // reachable, we will never throw it away for a route with shorter 
        // prefix match.
        //
        if (BestReachable >= NeighborMayBeReachable) {
            MinPrefixLength = KeyLength;
            break;
        }            
        //
        // Move on to the next route.
        //
        Status = PtGetNextShorterMatch(Tree, Link, &Link);
    }

    //
    // If Interface is not specified then BzoneNextHop and BestNextHop
    // should be the same. If scope id is not specified then BzoneNextHop
    // and BallNextHop should be same.
    // Since there is randomness in IppCompareAndUpdateNextHop 
    // the results returned are not deterministic. If we know we 
    // are going to get the same results, the result is copied here
    // deterministically.
    //
    if (Interface == NULL) {
        if (BestNextHop != NULL) {
            IppReferenceNextHop(BestNextHop);               
            ASSERT(BzoneNextHop == NULL);
            BzoneNextHop = BestNextHop;
            BzoneRoute = BestRoute;
            BzoneReachable = BestReachable;
            BzoneHash = BestHash;
            BzoneCouldBeBetterReachable = BestCouldBeBetterReachable;
        }
    }
    if (ScopeId.Zone == 0) {
        if (BzoneNextHop != NULL) {
            IppReferenceNextHop(BzoneNextHop);               
            ASSERT(BallNextHop == NULL);
            BallNextHop = BzoneNextHop;
            BallRoute = BzoneRoute;
            BallReachable = BzoneReachable;
            BallHash = BzoneHash;
            BallCouldBeBetterReachable = BzoneCouldBeBetterReachable;
        }
    }

    //
    // If the destination could be on-link and we actually selected
    // an on-link route, then we are OK. Otherwise, we need to check
    // if the destination could be on-link to the interface
    // that we selected. This implements one aspect of RFC 2461's
    // conceptual sending algorithm - the Prefix List is consulted
    // before the Default Router List. Note that RFC 2461 does not
    // consider multi-interface hosts and we only enforce a preference for
    // on-link routes within the context of a single interface.
    // If we choose a router on an interface when we could have chosen
    // on-link to the interface, the router would presumably just
    // Redirect us, so it's better to just send on-link even if the
    // destination is not reachable on-link. If the destination
    // is on-link but not reachable via one interface,
    // then we are happy to send off-link via another interface.
    // This may or may not succeed in reaching the destination,
    // but at least it has a chance of succeeding.
    // The CouldBeBetterReachable code will periodically probe
    // the destination's on-link reachability.
    //
    if (CouldBeBetterOnLink && 
        (IppIsOnLinkRoute(BestRoute) || BestRoute->Flags.Loopback)) {
        CouldBeBetterOnLink = FALSE;
    }

    if (BestCouldBeBetterReachable || 
        BzoneCouldBeBetterReachable ||
        BallCouldBeBetterReachable ||
        CouldBeBetterOnLink) {
        //
        // Make a second pass over the routes.
        //
        Status = PtGetLongestMatch(Tree, KeyBuffer, &Link);

        while (NT_SUCCESS(Status)) {
            PtGetKey(Link, &Key, &KeyLength);

            if (KeyLength < MinPrefixLength) {
                break;
            }

            Route = (PIP_UNICAST_ROUTE)CONTAINING_RECORD(Link, IP_ROUTE, Link);

            //
            // Again, loop through all routes with the same prefix.
            //
            do {
                NextRoute = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
                    Route->RouteLink.Flink, IP_ROUTE, RouteLink);
                //
                // If there is a VPN Connection then block the usage of default
                // routes.
                //
                if (Route->Interface->DisableDefaultRoutes &&
                    (KeyLength == 0)) {                    
                    Route = NextRoute;
                    continue;
                }
                //
                // Check our interface/scope-id constraints.
                //
                if (Route->ValidLifetime > 0) {
                    //
                    // Would this be a better route 
                    // than the one we are tracking 
                    // if the neighbor were reachable?
                    //
                    if ((BallCouldBeBetterReachable &&
                         IppCompareRoutes(
                             Route, NeighborMayBeReachable, 0,
                             BallRoute, BallReachable, 0) > 0) ||

                        (((ScopeId.Zone == 0) ||
                          (ScopeId.Zone ==
                           IppGetInterfaceScopeZone(
                               Route->Interface, Scope))) &&
                         BzoneCouldBeBetterReachable &&
                         (IppCompareRoutes(
                             Route, NeighborMayBeReachable, 0,
                             BzoneRoute, BzoneReachable, 0) > 0)) ||

                        (((Interface == NULL)
                          ? ((ScopeId.Zone == 0) ||
                             (ScopeId.Zone ==
                              IppGetInterfaceScopeZone(
                                  Route->Interface, Scope)))
                          : (Interface == Route->Interface)) &&
                         BestCouldBeBetterReachable &&
                         IppCompareRoutes(
                             Route, NeighborMayBeReachable, 0,
                             BestRoute, BestReachable, 0) > 0)) {
                        //
                        // OK, we want to know if this neighbor becomes
                        // reachable, because if it does we should change our
                        // routing.
                        //
                        if (IppIsOnLinkRoute(Route)) {
                            Neighbor =
                                IppFindOrCreateNeighborAtDpc(
                                    Route->Interface,
                                    NULL, 
                                    Destination, 
                                    AddressType);
                        } else if (!Route->Flags.Loopback) {
                            Neighbor = Route->CurrentNextHop;
                            IppReferenceNeighbor(Neighbor);
                        } else {
                            Neighbor = NULL;
                        }
                        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
                                   "FindRoute: CBBReachable: "
                                   "BestRoute %p BestNeighbor %p "
                                   "Route %p Neighbor %p\n",
                                   BestRoute, BestNextHop, Route, Neighbor);
                        if (Neighbor != NULL) {
                            IppProbeNeighborReachability(Neighbor);
                            IppDereferenceNeighbor(Neighbor);
                        }
                    }
                    
                    //
                    // Is this an on-link route on the same interface
                    // that we chosen to use off-link?
                    //
                    if (((Interface == NULL)
                         ? ((ScopeId.Zone == 0) ||
                            (ScopeId.Zone ==
                             IppGetInterfaceScopeZone(
                                 Route->Interface, Scope)))
                         : (Interface == Route->Interface)) &&
                        CouldBeBetterOnLink &&
                        IppIsOnLinkRoute(Route) && 
                        (Route->Interface == BestRoute->Interface)) {
                        //
                        // OK, we want to send directly to this destination.
                        // Switch to the on-link neighbor.
                        //
                        Neighbor =
                            IppFindOrCreateNeighborAtDpc(
                                Route->Interface,
                                NULL, 
                                Destination, 
                                AddressType);
                        if (Neighbor == NULL) {
                            RtlReleaseScalableReadLockFromDpcLevel(
                                &RouteSet->Lock);
                            goto ReturnNoResources;
                        }
                        
                        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
                                   "FindRoute: CBBOnLink: "
                                   "BestRoute %p BestNeighbor %p "
                                   "Route %p Neighbor %p\n",
                                   BestRoute, BestNextHop, Route, Neighbor);
                        if (BallNextHop == BestNextHop) {
                            if (BallNextHop != NULL) {
                                IppDereferenceNextHop(BallNextHop);
                            };
                            IppReferenceNeighbor(Neighbor);
                            BallNextHop = (PIP_NEXT_HOP) Neighbor;
                        }
                        if (BzoneNextHop == BestNextHop) {
                            if (BzoneNextHop != NULL) {
                                IppDereferenceNextHop(BzoneNextHop);
                            };
                            IppReferenceNeighbor(Neighbor);
                            BzoneNextHop = (PIP_NEXT_HOP) Neighbor;
                        }

                        if (BestNextHop != NULL) {
                            IppDereferenceNextHop(BestNextHop);
                        };
                        BestNextHop = (PIP_NEXT_HOP) Neighbor;
                        BestRoute = Route;
                        CouldBeBetterOnLink = FALSE;
                    }
                }

                Route = NextRoute;
            } while (Link != &Route->Link);

            Status = PtGetNextShorterMatch(RouteSet, Link, &Link);
        }
    }

    if ((ReturnRoute != NULL) && (BestRoute != NULL)) {
        IppReferenceRoute((PIP_ROUTE) BestRoute);
    }
    
    //
    // We can drop the lock and still do comparisons
    // against BallNextHop and BzoneNextHop.
    //
    RtlReleaseScalableReadLockFromDpcLevel(&RouteSet->Lock);

    ASSERT((BallNextHop != NULL) || (BzoneNextHop == NULL));
    ASSERT((ScopeId.Zone != 0) || (BallNextHop == BzoneNextHop));
    ASSERT((BzoneNextHop != NULL) || (BestNextHop == NULL));
    ASSERT((Interface != NULL) || (BzoneNextHop == BestNextHop));

    //
    // OK, we've consulted the routing table.
    // But what if we didn't find a route?
    // RFC 2461 Section 5.2 specifies "If the Default Router List
    // is empty, the sender assumes that the destination is on-link."
    // There has been an internet draft
    // draft-ietf-v6ops-onlinkassumption-*.txt
    // which proposes the removal of this assumption due to various concerns
    // and we are adopting that draft. There are special cases we would like
    // to handle for compatibility of behavior and these are the sending
    // to a link local address and sending to a multicast address cases.
    //


    if (Scope != ScopeLevelLink && AddressType != NlatMulticast) {
        goto Done;
    }
    
    if (BallNextHop == NULL) {
        PIP_INTERFACE ScopeInterface;
        SCOPE_ID BallScopeId = scopeid_unspecified;
        
        BallScopeId.Level = ScopeId.Level;
        
        //
        // Check if there is a default interface for this scope.
        //
        ScopeInterface =
            IppFindDefaultInterfaceForZone(Compartment, BallScopeId);
        if (ScopeInterface != NULL) {
            BallNextHop = (PIP_NEXT_HOP)
                IppFindOrCreateNeighborWithoutTypeAtDpc(
                    ScopeInterface,
                    NULL,
                    Destination);
            IppDereferenceInterface(ScopeInterface);

            if (BallNextHop == NULL) {
ReturnNoResourcesAfterLock:
                if ((ReturnRoute != NULL) && (BestRoute != NULL)) {
                    IppDereferenceRoute((PIP_ROUTE) BestRoute);
                }
                goto ReturnNoResources;
            }
        }
    }

    if (BzoneNextHop == NULL) {
        if (ScopeId.Zone != 0) {
            PIP_INTERFACE ScopeInterface;

            //
            // Check if there is a default interface for the zone.
            //
            ScopeInterface =
                IppFindDefaultInterfaceForZone(Compartment, ScopeId);
            if (ScopeInterface != NULL) {
                BzoneNextHop = (PIP_NEXT_HOP)
                    IppFindOrCreateNeighborWithoutTypeAtDpc(
                        ScopeInterface,
                        NULL,
                        Destination);
                IppDereferenceInterface(ScopeInterface);
    
                if (BzoneNextHop == NULL) {
                    goto ReturnNoResourcesAfterLock;
                }
            }
        } else if (BallNextHop != NULL) {
            //
            // Use the default interface for the scope.
            //
            IppReferenceNextHop(BallNextHop);
            BzoneNextHop = BallNextHop;
        }
    }

    if (BestNextHop == NULL) {
        if (Interface != NULL) {
            //
            // Use the constraining interface.
            //
            BestNextHop = (PIP_NEXT_HOP)
                IppFindOrCreateNeighborWithoutTypeAtDpc(
                    Interface,
                    NULL,
                    Destination);
            if (BestNextHop == NULL) {
                goto ReturnNoResourcesAfterLock;
            }
        } else if (BzoneNextHop != NULL) {
            //
            // Use the default interface for the zone.
            //
            IppReferenceNextHop(BzoneNextHop);
            BestNextHop = BzoneNextHop;
        }
    }

  Done:
    
    //
    // We can release BzoneNCE and BallNCE and still compare against them.
    //
    if (BallNextHop != NULL) {
        IppDereferenceNextHop(BallNextHop);
    };
    if (BzoneNextHop != NULL) {
        IppDereferenceNextHop(BzoneNextHop);
    };

    //
    // Determine the constrained flags.  This is done independent of whether
    // the route lookup was successful or not.  Even if the route lookup
    // failed, we want to set the correct flags in the path. 
    //
    if (BestNextHop == BallNextHop) {
        //
        // The IF and ScopeId arguments did not
        // affect our BestNeighbor choice.
        //
    } else if (BestNextHop == BzoneNextHop) {
        //
        // The IF argument did not affect our BestNeighbor choice, but
        // the ScopeId argument did because BzoneNextHop != BallNextHop.
        //
        ReturnConstrained->ConstrainedScopeId = TRUE;
    } else {
        //
        // The IF argument affected our BestNeighbor choice.
        //
        ReturnConstrained->ConstrainedInterface = TRUE;
    }

    if (BestNextHop != NULL) {
        *ReturnNextHop = BestNextHop;

        if (ReturnRoute != NULL) {
            *ReturnRoute = BestRoute;
        }
        return STATUS_SUCCESS;
    } else if ((ScopeId.Zone != 0) && (BzoneNextHop == NULL)
               && (Interface != NULL)) {
        //
        // The ScopeId was invalid.
        //
        return STATUS_INVALID_ADDRESS_COMPONENT;
    } else {
        //
        // Didn't find a suitable next hop.
        //
        return STATUS_NOT_FOUND;
    }
}


PIP_UNICAST_ROUTE
IppFindNextBestRouteAtDpc(
    IN PIP_UNICAST_ROUTE OriginalRoute, 
    OUT PIP_UNICAST_ROUTE *ReturnBestRoute, 
    OUT ULONG *TotalPaths
    )
/*++

Routine Description:

    This routine finds the next best route given a current route.  This routine
    only looks at routes with the same prefix as the current route.  

    It is used by the dead gateway detection algorithm to determine what route
    to use when the destination is not reachable using the current one. 
    
Arguments:

    OriginalRoute - Supplies the current route.

    ReturnBestRoute - Returns the best route.  This only returns a pointer
        without a reference, so it can only be used for comparisons. 

    TotalPaths - Returns the total number of paths using any route in the
        list. 

Return Value:

    Returns the next best route.

Caller LOCK:

    The caller holds the current next update lock for the path. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PLIST_ENTRY CurrentLink;
    BOOLEAN WrappedAround = FALSE;
    LONG Better;
    PIP_UNICAST_ROUTE CurrentRoute, FirstRoute;
    PIP_UNICAST_ROUTE BestRoute = NULL, ReturnRoute = NULL;
    IP_NEIGHBOR_REACHABILITY CurrentReachability, ReturnReachability = 0, 
        OriginalReacability, BestReachability = 0;
    PIPR_LOCKED_SET RouteSet =
        &OriginalRoute->Interface->Compartment->RouteSet;

    DISPATCH_CODE();
    
    OriginalReacability =
        IppGetNeighborReachability(OriginalRoute->CurrentNextHop);

    *TotalPaths = OriginalRoute->PathCount;
    BestRoute = OriginalRoute;
    BestReachability = OriginalReacability;
    
    RtlAcquireScalableReadLockAtDpcLevel(&RouteSet->Lock);
    
    FirstRoute = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
        PtGetData(&OriginalRoute->Link), IP_UNICAST_ROUTE, Link);
    
    for (CurrentLink = OriginalRoute->RouteLink.Flink; 
         CurrentLink != &OriginalRoute->RouteLink; 
         CurrentLink = CurrentLink->Flink) {
        CurrentRoute = (PIP_UNICAST_ROUTE)
            CONTAINING_RECORD(CurrentLink, IP_UNICAST_ROUTE, RouteLink);
    
        if (CurrentRoute == FirstRoute) {
            WrappedAround = TRUE;
        }

        //
        // Ignore if the route is loopback or on-link.
        //
        if (CurrentRoute->Flags.Loopback || IppIsOnLinkRoute(CurrentRoute)) {
            continue;
        }
    
        *TotalPaths += CurrentRoute->PathCount;
        
        CurrentReachability =
            IppGetNeighborReachability(CurrentRoute->CurrentNextHop);
        
        //
        // Keep track of the best route so far. 
        //
        if (BestRoute == NULL) {
RememberBest:
            BestRoute = CurrentRoute;
            BestReachability = CurrentReachability;
        } else {
            Better =
                IppCompareRoutes(
                    CurrentRoute, CurrentReachability, 0,
                    BestRoute, BestReachability, 0);
            if (Better > 0) {
                goto RememberBest;
            }
        }

        //
        // Keep track of the route to return.  
        // (1) If the current route is better than the original route, then we
        // ignore it since we have probably already chosen it before and found
        // that it does not work.  Our goal is to find the "next best route". 
        // (2) Similarly if a route is the same as the original route but
        // occurs earlier in the list, it is ignored. 
        // (3) Otherwise, if the route is better than our current estimate,
        // then use it as the current estimate.
        //

        //
        // First compare to the original route to check for 1 and 2 above. 
        //
        Better =
            IppCompareRoutes(
                CurrentRoute, CurrentReachability, 0,
                OriginalRoute, OriginalReacability, 0);
        if ((Better > 0) || ((Better == 0) && WrappedAround))  {
            continue;
        }
        
        //
        // This route is not better than the original route.  Compare to the
        // current best route and use this route if it is better than the
        // current best route.  
        //
        if (ReturnRoute == NULL) {
RememberReturn:
            ReturnRoute = CurrentRoute;
            ReturnReachability = CurrentReachability;
        } else{
            Better =
                IppCompareRoutes(
                    CurrentRoute, CurrentReachability, 0,
                    ReturnRoute, ReturnReachability, 0);
            if (Better > 0) {
                goto RememberReturn;
            }
        }
    }

    if (ReturnRoute != NULL) {
        IppReferenceRoute((PIP_ROUTE) ReturnRoute);
    } else if (BestRoute != OriginalRoute) {
        IppReferenceRoute((PIP_ROUTE) BestRoute);
        ReturnRoute = BestRoute;
    } else {
        ReturnRoute = NULL;
    }

    RtlReleaseScalableReadLockFromDpcLevel(&RouteSet->Lock);

    *ReturnBestRoute = BestRoute;
    
    return ReturnRoute;
}


VOID
IppSetAllRouteState(
    IN PIP_UNICAST_ROUTE Route, 
    IN IP_ROUTE_STATE State, 
    IN CONST UCHAR *NextHop OPTIONAL
    )
/*++

Routine Description:

    This routine sets the state of all routes in a list whose next hop matches
    a value. 
       
Arguments:

    Route - Supplies the route list. 

    State - Supplies the new state. 

    NextHop - Optionally supplies the next hop of the route for which to change
        the state.  If NULL, then the state of all the routes in the list is
        changed.  Note this makes it impossible to set the state only on
        on-link routes because they all have their NextHop as NULL.  
        However, this is fine because IppSetAllRouteState is called in response
        to redirects in which case we have a NextHop and by 
        IpNlpSuspectPathReachability which changes all routes.
        

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:

    Caller should hold the path cache lock. 
    
Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_COMPARTMENT Compartment = Route->Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
    PLIST_ENTRY CurrentLink;
    PIP_UNICAST_ROUTE CurrentRoute;

    DISPATCH_CODE();
    ASSERT_ANY_SCALABLE_LOCK_HELD(&Compartment->PathSet.Lock);
    
    RtlAcquireScalableReadLockAtDpcLevel(&RouteSet->Lock);

    CurrentLink = Route->RouteLink.Flink; 

    do {
        CurrentRoute = (PIP_UNICAST_ROUTE)
            CONTAINING_RECORD(CurrentLink, IP_UNICAST_ROUTE, RouteLink);

        if ((NextHop == NULL) ||
            ((!CurrentRoute->Flags.Loopback) && !IppIsOnLinkRoute(CurrentRoute)
             && (RtlEqualMemory(
                     IP_NEIGHBOR_NL_ADDRESS(CurrentRoute->CurrentNextHop),
                     NextHop,
                     Protocol->Characteristics->AddressBytes)))) {
            IppSetRouteState(CurrentRoute, State);
        }
        CurrentLink = CurrentLink->Flink;

    } while (CurrentLink != &Route->RouteLink);

    RtlReleaseScalableReadLockFromDpcLevel(&RouteSet->Lock);
}


NTSTATUS
IppFindNextHopAndSourceAtDpc(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_INTERFACE ConstrainInterface OPTIONAL,
    IN CONST UCHAR *Destination,
    IN SCOPE_ID ScopeId,
    IN PIP_LOCAL_UNICAST_ADDRESS ConstrainSourceAddress OPTIONAL, 
    OUT PIP_NEXT_HOP *ReturnNextHop, 
    OUT PIP_LOCAL_UNICAST_ADDRESS *ReturnSourceAddress,
    OUT PIP_UNICAST_ROUTE *ReturnRoute OPTIONAL,
    OUT PIP_PATH_FLAGS ReturnConstrained OPTIONAL
    )
/*++

Routine Description:

    Calculate the next hop to use for the destination as well as the source
    address. This routine just calls IppFindNextHopAtDpc for the next hop and
    FindBestSourceAddress for the source address. It also sets the constrained
    flag appropriately. For instance, if FindBestSourceAddress returns an
    address different from the constrained source address, then the
    ConstrainedSource flag is set.

Arguments:
    
    Compartment - Supplies a pointer to the compartment.

    ConstrainInterface - Optionally supplies the constrained source interface. 

    Destination - Supplies the destination address to route to.

    ScopeId - Supplies the scope id for Destination (0 if non-scoped).

    ConstrainSourceAddress - Optionally supplies the constrained source 
        address. Returns the source address actually being used.

    ReturnNextHop - Returns the NextHop.
        Neighbor if the destination is remote, LocalAddress if it is local.

    ReturnSourceAddress - Returns the source address. 

    ReturnRoute - Returns the best route if non-NULL. 

    ReturnConstrained - Returns an indication of whether the Interface and 
        ScopeId parameters constrained the returned Neighbor.

Return Value:

    Other than STATUS_NOT_FOUND, which is handled by IppRouteToDestination,
    the return value must be an NTSTATUS code which matches a TDI status code.

    STATUS_SUCCESS
    STATUS_HOST_UNREACHABLE
    Other values as returned by IppFindNextHopAtDpc.

Caller IRQL:

    Must be called at DISPATCH level.

--*/
{
    NTSTATUS Status;
    PIP_NEXT_HOP NextHop;
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress;
    PIP_INTERFACE Interface;
    IP_PATH_FLAGS Constrained;
    NL_ADDRESS_TYPE AddressType = NlatUnspecified;

    ASSERT((ConstrainInterface == NULL) ||
           ((ScopeId.Value != 0) && 
            (ScopeId.Zone == 
             IppGetInterfaceScopeZone(ConstrainInterface, ScopeId.Level))));
    ASSERT((ConstrainSourceAddress == NULL) || 
           ((ConstrainInterface != NULL) && 
            (ConstrainInterface == ConstrainSourceAddress->Interface)));
    
    //
    // Choose the outgoing interface for the route lookup.  If forwarding is
    // enabled, we do an unconstrained lookup.  Otherwise, the outgoing
    // interface should match the source interface. 
    //
    Interface = ConstrainInterface;
    if ((Interface != NULL) &&
        ((Interface->Forward) || (Interface->WeakHostSend))) {
        AddressType = Compartment->Protocol->AddressType(Destination);    
        if ((AddressType != NlatMulticast) &&
            (AddressType != NlatBroadcast)) {
            Interface = NULL;
        } 
    }
    
Retry:
    Constrained.Value = 0;

    //
    // Do a route lookup. 
    //
    Status =
        IppFindNextHopAtDpc(
            Compartment,
            Destination,
            ConstrainSourceAddress != NULL
            ? NL_ADDRESS(ConstrainSourceAddress)
            : NULL, 
            Interface,
            ScopeId, 
            &NextHop,
            &Constrained,
            ReturnRoute);

    if (ReturnConstrained != NULL) {
        *ReturnConstrained = Constrained;
    }
    
    if (!NT_SUCCESS(Status)) {
        //
        // If the route lookup failed because we did an unconstrained lookup
        // and the caller constrained the interface, then retry allowing the
        // destination to be considered on-link to the constrained interface. 
        //
        if ((Status == STATUS_NOT_FOUND) && 
            (Interface == NULL) && (ConstrainInterface != NULL)) {
            Interface = ConstrainInterface;
            goto Retry;
        }
        
        //
        // The route lookup failed.  If we are validating an existing path
        // (ConstrainSourceAddress != NULL), then the constrained flag in the
        // path needs to be set correctly.  
        // (1) If the constrained source address is not the best source address
        // on the constrained interface, then the path is source constrained.
        // (2) Otherwise, it is interface constrained.
        // 
        if (ConstrainSourceAddress != NULL && ReturnConstrained != NULL) {
            SourceAddress =
                IppFindBestSourceAddressOnInterface(
                    ConstrainInterface,
                    Destination,
                    NULL);
            if (SourceAddress != ConstrainSourceAddress) {
                ReturnConstrained->ConstrainedSource = TRUE;
            } else {
                ReturnConstrained->ConstrainedInterface = TRUE;
            }
            if (SourceAddress != NULL) {
                IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) SourceAddress);
            }
        }

        goto Error;
    }else {
        //
        // If we did an unconstrained lookup and the interface was actually 
        // constrained and the route lookup returned a broadcast address
        // on a different interface, ie.
        // (1) Source address was constrained (implies interface contraint) AND
        // (2) Forwarding/weakhost is enabled AND
        // (3) Route lookup returned a broadcast address
        // on an interface different from the source interface
        // 
        // Do another route lookup with the source address constrained.
        // This time we will pick the route returned if it is also a broadcast
        // route on the constrained interface.
        //
        if ((ConstrainInterface != NULL) &&
            IppIsNextHopLocalAddress(NextHop) &&
            (NL_ADDRESS_TYPE((PIP_LOCAL_ADDRESS)NextHop) == NlatBroadcast) &&
            (((PIP_LOCAL_ADDRESS)NextHop)->Interface != ConstrainInterface)) {

            AddressType = NlatBroadcast;
            IppDereferenceNextHop(NextHop);
            if ((ReturnRoute != NULL) && (*ReturnRoute != NULL)) {
                IppDereferenceRoute((PIP_ROUTE) (*ReturnRoute));
            }
            Interface = ConstrainSourceAddress->Interface;
            goto Retry;
        }

        if (AddressType == NlatBroadcast) {
            //
            // We are expecting a broadcast host route. If we got something
            // else fail the send.
            //
            if (!IppIsNextHopLocalAddress(NextHop) ||
                (((PIP_LOCAL_ADDRESS)NextHop)->Type != NlatBroadcast)) {

                IppDereferenceNextHop(NextHop);
                if ((ReturnRoute != NULL) && (*ReturnRoute != NULL)) {
                    IppDereferenceRoute((PIP_ROUTE) (*ReturnRoute));
                }
                Status = STATUS_HOST_UNREACHABLE;
                goto Error;                                
            }
        }
    }

    //
    // If the destination is a subnet broadcast we need to restrict
    // the source address selection to the NextHop interface.
    //
    if (IppIsNextHopLocalAddress(NextHop) &&
         (NL_ADDRESS_TYPE((PIP_LOCAL_ADDRESS)NextHop) == NlatBroadcast)) { 
        ConstrainInterface = NextHop->Interface;
    }
    //
    // Determine the outgoing interface that the route lookup returned.  This
    // can be different from the constrained interface iff we did removed the
    // constraint because the interface was forwarding. 
    //
    ASSERT((Interface == NULL) || (Interface == NextHop->Interface));
    Interface = NextHop->Interface;

    //
    // Determine the source address to use.
    //
    if (ConstrainSourceAddress != NULL) {
        SCOPE_LEVEL ConstrainScopeLevel;

        //
        // The source address is constrained.  
        // We will choose the constrained source address as the source address
        // but first determine the constrained flags.  
        // (1) If the constrained source address is not the best source address
        // on the constrained interface, then the path is source constrained. 
        // (2) If the constrained source address is the best one on the
        // constrained interface, but the constrained interface is different
        // from the outgoing interface, then the path is interface
        // constrained. 
        // (3) If the constrained interface is the same as the outgoing
        // interface, then IppFindNextHopAtDpc should have set the flags
        // correctly. 
        //
        if (ReturnConstrained != NULL) {
            SourceAddress =
                IppFindBestSourceAddressOnInterface(
                    ConstrainInterface,
                    Destination,
                    NextHop);
            if (SourceAddress != ConstrainSourceAddress) {
                ReturnConstrained->ConstrainedSource = TRUE;
            } else if (ConstrainInterface != Interface) {
                ReturnConstrained->ConstrainedInterface = TRUE;
            }

            if (SourceAddress != NULL) {
                IppDereferenceLocalUnicastAddress(SourceAddress);
            }

        }
        
        //
        // Reference the constrained source address (that we are going to use). 
        //
        IppReferenceLocalUnicastAddress(ConstrainSourceAddress);

SetConstrainSourceAddress:
        //
        // At this point, we have decided to choose the constrained source
        // address as our source address.  We have a reference on the
        // constrained source address. 
        //
        SourceAddress = ConstrainSourceAddress;

        //
        // Verify that the constrained source address does not cross
        // scope boundaries between the orginating interface and the outgoing
        // interface (Interface is the outgoing interface and
        // ConstrainInterface is the originating interface).  If it does, then
        // retry the route lookup with the client specified interface
        // constraint.  Note that this can only happen if we ignored the
        // interface constraint in the first place (which will happen if we
        // are doing a weak host send, or have forwarding on). 
        //
        ConstrainScopeLevel = NL_ADDRESS_SCOPE_LEVEL(ConstrainSourceAddress);
        if (IppGetInterfaceScopeZone(
                Interface, ConstrainScopeLevel) != 
            IppGetInterfaceScopeZone(
                ConstrainInterface, ConstrainScopeLevel)) {
            IppDereferenceNextHop(NextHop);
            if ((ReturnRoute != NULL) && (*ReturnRoute != NULL)) {
                IppDereferenceRoute((PIP_ROUTE) (*ReturnRoute));
            }
            ASSERT(
                (ConstrainInterface != Interface) &&
                (ConstrainInterface->Forward ||
                 ConstrainInterface->WeakHostSend));
            Interface = ConstrainInterface;
            goto Retry;
        }
    } else if (ConstrainInterface != NULL) {
        //
        // Interface constraint but no source constraint.  Choose the best
        // source address on the constrained interface. 
        //
        ConstrainSourceAddress =
            IppFindBestSourceAddressOnInterface(
                ConstrainInterface,
                Destination,
                NextHop);
        if (ConstrainSourceAddress == NULL) {
            goto ErrorNoSource;
        }
        
        //
        // This cannot be source constrained since we are using the best source
        // address on the constrained interface. 
        // (1) If the constrained interface is different than the outgoing
        // interface, then this is interface constrained. 
        // (2) Otherwise IppFindNextHopAtDpc should have set the flags
        // correctly. 
        //
        if (ConstrainInterface != Interface && ReturnConstrained != NULL) {
            ReturnConstrained->ConstrainedInterface = TRUE;
        }
        goto SetConstrainSourceAddress;
    } else {
        //
        // No interface or source address constraint.  The source address is
        // the best source address on the outgoing interface.  The constrained
        // flags are set correctly by IppFindNextHopAtDpc. 
        //
        SourceAddress = 
            IppFindBestSourceAddressOnHost(Interface, Destination, NextHop);
        if (SourceAddress == NULL) {
            goto ErrorNoSource;
        }
    }
    
    *ReturnSourceAddress = (PIP_LOCAL_UNICAST_ADDRESS) SourceAddress;
    *ReturnNextHop = NextHop;
    
    return STATUS_SUCCESS;

ErrorNoSource:
    Status = STATUS_HOST_UNREACHABLE;            
    IppDereferenceNextHop(NextHop);
    if ((ReturnRoute != NULL) && (*ReturnRoute != NULL)) {
        IppDereferenceRoute((PIP_ROUTE) (*ReturnRoute));
    }
    
Error:
    *ReturnSourceAddress = NULL;
    *ReturnNextHop = NULL;
    if (ReturnRoute != NULL) {
        *ReturnRoute = NULL;
    }

    return Status;
}


__inline
NTSTATUS
IppFindNextHopAndSource(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN CONST UCHAR *Destination,
    IN SCOPE_ID ScopeId,
    IN PIP_LOCAL_UNICAST_ADDRESS ConstrainSourceAddress OPTIONAL,
    OUT PIP_NEXT_HOP *ReturnNextHop,
    OUT PIP_LOCAL_UNICAST_ADDRESS *ReturnSourceAddress,
    OUT PIP_UNICAST_ROUTE *ReturnRoute OPTIONAL,
    OUT PIP_PATH_FLAGS ReturnConstrained OPTIONAL
    )
/*++

Routine Description:

    Calculate the next hop to use for the destination.
    This is a simple wrapper around IppFindNextHopAndSourceAtDpc.

Arguments:

    Compartment - Supplies a pointer to the compartment.

    Interface - Optionally supplies the outgoing interface. 

    Destination - Supplies the destination address to route to.

    ScopeId - Supplies the scope id for Destination (0 if non-scoped).

    ConstrainSourceAddress - Optionally supplies the constrained source 
        address. Returns the source address actually being used.

    ReturnNextHop - Returns the NextHop.
        Neighbor if the destination is remote, LocalAddress if it is local.

    ReturnSourceAddress - Returns the source address to use for the
        destination.

    ReturnConstrained - Returns an indication of whether the Interface and 
        ScopeId parameters constrained the returned Neighbor.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    KIRQL OldIrql = DISPATCH_LEVEL;
    NTSTATUS Status;

    OldIrql = KeRaiseIrqlToDpcLevel();

    Status =
        IppFindNextHopAndSourceAtDpc(
            Compartment, 
            Interface, 
            Destination,
            ScopeId, 
            ConstrainSourceAddress,
            ReturnNextHop,
            ReturnSourceAddress,
            ReturnRoute,
            ReturnConstrained);

    KeLowerIrql(OldIrql);
    
    return Status;
}


VOID
IppCleanupPathForReuse(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    Frees references held by a path so that the memory can be reused. 

Arguments:

    Path - Supplies the path to cleanup.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    if (Path->Route != NULL) {
        IppDereferenceRoute((PIP_ROUTE) Path->Route);
        Path->Route = NULL;
    }
    
    if (Path->CurrentNextHop != NULL) {
        IppDereferenceNextHop(Path->CurrentNextHop);
        Path->CurrentNextHop = NULL;
    }
    
    if (Path->SourceAddress != NULL) {
        IppDereferenceLocalUnicastAddress(Path->SourceAddress);
    }
    KeUninitializeSpinLock(&Path->Bandwidth.SpinLock);
}


VOID
IppCleanupPathPrimitive(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    Frees memory and references held by a path.

Arguments:

    Path - Supplies the path to free.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IppCleanupPathForReuse(Path);

#ifdef _IP_OFFLOAD_LOGGING
    if (Path->OffloadLog != NULL) {
        ExFreePoolWithTag(Path->OffloadLog, IpOffloadLogPoolTag);
    }        
#endif // _IP_OFFLOAD_LOGGING
    
    FsbFree((PUCHAR)Path);
}


NETIO_INLINE
ULONG
IppComputePathSetKey(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST UCHAR *DestinationAddress
    ) 
{
    return 
        IppComputeHashKeyFromAddress(Compartment, DestinationAddress);
}

VOID
IppUpdateRoutesWithLocalAddressAsNextHopUnderLock(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
/*++

Routine Description:

    Update the routing table to make sure that none of the default routes have 
    a next hop address same as a valid address on the interface. This can 
    happen if route got added before the address becomes usable. While this is 
    highly discouraged, there happen to be deployments that run into it.

    TODO: This is being done only for default routes to limit any perf impact 
    in the common case. To be sure, this sanity check may be needed for
    all routes on the interface.
    
Arguments:

    LocalAddress - Supplies the recently added local unicast address. 

Return Value:
    

Caller LOCK: Exclusive RouteSet Lock held.
Caller IRQL: DISPATCH_LEVEL (since a lock is held). 

--*/ 
{
    UCHAR Key[ROUTE_KEY_STORAGE_SIZE];
    USHORT KeyLength = 0;
    PIP_UNICAST_ROUTE Route, NextRoute;
    NTSTATUS Status;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    ULONG AddressBytes = Compartment->Protocol->Characteristics->AddressBytes;
    
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Compartment->RouteSet.Lock);
    
    NetioTrace(
        NETIO_TRACE_NETWORK, 
        TRACE_LEVEL_VERBOSE, 
        "IPNG: [%u] Checking if any route NextHop equals local address\n",
        Interface->Index);

    //
    // Make route key for the default route.
    //
    Compartment->Protocol->MakeRouteKey(
        (UCHAR *) &in6addr_any, 
        0,
        NULL, 
        0,
        Key, 
        &KeyLength);

    Status = 
        IppFindUnicastRouteUnderLock(
            Key,
            KeyLength,
            Compartment,
            Interface,
            NL_ADDRESS(LocalAddress),
            &Route);

    if (NT_SUCCESS(Status)) {
        ASSERT(Route != NULL);
        if (IppIsNextHopNeighbor((PIP_NEXT_HOP)Route->CurrentNextHop)) {                    
            //
            // Check if another on-link default route exists. 
            //
            Status = 
                IppFindUnicastRouteUnderLock(
                    Key,
                    KeyLength,
                    Compartment,
                    Interface,
                    (UCHAR *) &in6addr_any,
                    &NextRoute);

            if (NT_SUCCESS(Status)) {
                //
                // There already is a on-link default route. So no need to do 
                // anything. The next hop of this route will be found 
                // unreachable and traffic should switch over to using the 
                // onlink route in that case.
                //
                IppDereferenceRoute((PIP_ROUTE) NextRoute);
            } else {
                //
                // No other such route. Fix this one.
                //
                IppRouteTrace(
                    TRACE_LEVEL_INFORMATION,
                    "Clearing NextHop of route",
                    Compartment->Protocol,
                    (UCHAR *)&in6addr_any,
                    0,
                    Interface,
                    IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route));

                IppDereferenceNextHop(Route->CurrentNextHop);
                Route->CurrentNextHop = NULL;
                RtlZeroMemory(
                    IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route),
                    AddressBytes);
                IppInvalidateDestinationCache(Compartment);
            }
        }
        IppDereferenceRoute((PIP_ROUTE) Route);
    }
}

PIP_LOCAL_UNICAST_ADDRESS
IppFindAndUpdateLocalAddressInPathCacheAtDpcLevel(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST UCHAR *RemoteAddress, 
    IN CONST UCHAR *LocalAddress, 
    IN PIP_INTERFACE ArrivalInterface, 
    IN ULONG ReferenceIncrement
    )
/*++

Routine Description:
 
    This routine looks up a local address pointer in the path cache.  When a
    packet arrives from 'RemoteAddress' to 'LocalAddress', then
    typically (especially for TCP traffic) a path exists from
    LocalAddress to RemoteAddress in the local path cache.  This routine
    looks up the path cache to find such a path and then returns the source
    address in the path to the caller.  This is a way of converting the
    LocalAddress to the corresponding local address pointer. 

Arguments:

    Compartment - Supplies the compartment.

    RemoteAddress - Supplies the remote address. This is provided
        by the source address field of an incoming IP packet. The routine
        tries to find a path in the path cache with this as the destination. 

    LocalAddress - Supplies the local address. This is provided 
        by the destination address field of an incoming IP packet. The
        routine tries to find the local address pointer corresponding to this 
        address. 

    ArrivalInterface - Supplies the interface on which the packet arrived.

Return Value:
    
    Returns the local address corresponding to LocalAddress or NULL if
    not found.  A reference is taken on the returned address if found.

Caller LOCK:
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    ULONG Key;
    PRTL_HASH_TABLE_ENTRY Current;
    PIP_PATH Path;
    SCOPE_ID PathScopeId;
    ULONG AddressBytes = Compartment->Protocol->Characteristics->AddressBytes;
    RTL_HASH_TABLE_CONTEXT LookupContext;
    PIPP_PATH_SET PathSet;
    PIP_LOCAL_UNICAST_ADDRESS ReturnLocalAddress = NULL;

    ASSERT(ReferenceIncrement > 0);

    //
    // Find the bucket index in which the path exists.  This is based on the
    // source address in the packet since we are trying to find a path from
    // LocalAddress to RemoteAddress.  Note that we could have gone
    // through all the paths in the path cache to find the local address
    // pointer.  This is just an optimization because there is a high
    // likelihood of a path from LocalAddress to RemoteAddress existing in
    // the path cache. 
    //
    Key = IppComputePathSetKey(Compartment, RemoteAddress);
    PathSet = &Compartment->PathSet;

    RtlAcquireScalableReadLockAtDpcLevel(&Compartment->PathSet.Lock);

    RtlInitHashTableContext(&LookupContext);

    for (Current = 
            RtlLookupEntryHashTable(&PathSet->Table, Key, &LookupContext);
         Current != NULL;
         Current = RtlGetNextEntryHashTable(&PathSet->Table, &LookupContext)) {

        Path = IppGetPathFromPathLink(Current);
        
        if (!RtlEqualMemory(
                NL_ADDRESS(Path->SourceAddress),
                LocalAddress,
                AddressBytes)) {
            continue;
        }
        
        //
        // The destination address of the incoming packet has already been
        // matched to the source address of the path.  So, the scope level is
        // also guaranteed to be the same.  All we need to compare is the scope
        // zone of the path source address and that of the incoming packet's
        // destination address. 
        //
 
        PathScopeId = NL_ADDRESS_SCOPE_ID(Path->SourceAddress);
        if (PathScopeId.Zone != 
            IppGetInterfaceScopeZoneInline(
                ArrivalInterface, PathScopeId.Level)) {
            continue;
        }

        if (Path->SourceAddress->Deleted) {
            continue;
        }

        //
        // Return the local address pointer.  
        //
        IppReferenceLocalAddressEx(
            (PIP_LOCAL_ADDRESS) Path->SourceAddress, ReferenceIncrement);

        ReturnLocalAddress = Path->SourceAddress;
        break;
    }
   
    RtlReleaseHashTableContext(&LookupContext); 
    RtlReleaseScalableReadLockFromDpcLevel(&Compartment->PathSet.Lock);

    return ReturnLocalAddress;
}

PIP_PATH
IppFindPathUnderLock(
    IN PIP_COMPARTMENT Compartment,
    IN ULONG Key,
    IN CONST UCHAR *DestinationAddress,
    IN SCOPE_ID DestinationScopeId,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN CONST IP_LOCAL_UNICAST_ADDRESS *SourceAddress, 
    IN ULONG AddressBytes,
    IN BOOLEAN ValidationAllowed
    )
/*++

Routine Description:

    Check for an existing path entry.  The caller can constrain the source
    address, the interface or the destination scope id.  

    If the source address is not constrained, then we look for a path with
    ConstrainedSource set to FALSE. 

    Similarly, if the interface is not constrained, then we use a path that
    does not have the interface constrained.  The interface constraint is for
    the interface on which the source address exists and not the outgoing
    interface.  In case of forwarding, the two might be different and so
    specifying an interface constraint does not guarantee that the returned
    path will use it as the outgoing interface. 

    Compare code in FindOrCreateRoute in the XP IPv6 stack.

Called by: IppFindOrCreatePath

Locks:

    Caller holds the path set lock (read or write).  If the caller holds the
    read lock, then ValidationAllowed is set to FALSE since the routine cannot
    validate the path. 
    Caller is responsible for dereferencing returned Path.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PATH Path = NULL;
    PRTL_HASH_TABLE_ENTRY Curr;
    PIP_INTERFACE PathInterface;
    PIP_LOCAL_UNICAST_ADDRESS PathSourceAddress;
    BOOLEAN IsPathValid;
    RTL_HASH_TABLE_CONTEXT LookupContext;
    PIPP_PATH_SET PathSet;
    
    ASSERT((Interface == NULL) ||
           ((DestinationScopeId.Value != 0) && 
            (DestinationScopeId.Zone == 
             IppGetInterfaceScopeZone(Interface, DestinationScopeId.Level))));
    ASSERT((SourceAddress == NULL) || 
           ((Interface != NULL) && (Interface == SourceAddress->Interface)));
    ASSERT_ANY_SCALABLE_LOCK_HELD(&Compartment->PathSet.Lock);
    
    PathSet = &Compartment->PathSet;
    RtlInitHashTableContext(&LookupContext);
 
    for (Curr = RtlLookupEntryHashTable(&PathSet->Table, Key, &LookupContext);
         Curr != NULL;
         Curr = RtlGetNextEntryHashTable(&PathSet->Table, &LookupContext)) { 

        Path = IppGetPathFromPathLink(Curr);

        ASSERT(IppGetCompartmentFromPath(Path) == Compartment);

        //
        // We want a path to the requested destination, obviously.
        //
        if (!RtlEqualMemory(Path->DestinationAddress, 
                            DestinationAddress, 
                            AddressBytes)) {
            continue;
        }

        PathSourceAddress = Path->SourceAddress;
        PathInterface = PathSourceAddress->Interface;
        IsPathValid = IS_PATH_VALID(Path, Compartment);
        
        //
        // Check for caller-imposed source constraint.  
        //
        if (SourceAddress == NULL) {
            //
            // We are not constrained to a particular source. So there might
            // be multiple paths to choose from.  Don't pick a constrained
            // path. 
            //
            if (Path->Flags.ConstrainedSource) {
                //
                // If this path is invalid, the ConstrainedSource might be
                // stale information. Just try to revalidate the path. But
                // before that we need to make sure that the interface
                // constraints are valid as well.
                //
                if (IsPathValid) {
                    continue;
                }
            }

            //
            // Check for a caller-imposed interface constraint.
            //
            if (Interface == NULL) {
                //
                // We're not constrained to a particular interface, so
                // there may be multiple routes to this destination in
                // the cache to choose from.  Don't pick a constrained path. 
                //
                if (Path->Flags.ConstrainedInterface) {
                    //
                    // If this path is invalid, then ConstrainedInterface
                    // might be stale information. We do not want to pass
                    // by this path and then later create another path
                    // for the same interface/destination pair.
                    //
                    if (IsPathValid) {
                        continue;
                    }
                }
                
                //
                // Check for a ScopeId constraint.
                //
                if (DestinationScopeId.Zone == 0) {
                    //
                    // We're not constrained to a particular zone, so
                    // there may be multiple routes to this destination in
                    // the cache to choose from.  Don't pick a constrained     
                    // path. 
                    //
                    if (Path->Flags.ConstrainedScopeId) {
                        //
                        // If this path is invalid, ConstrainedScopeId
                        // might be stale information. We do not want to pass
                        // by this path and then later create another path
                        // for the same interface/destination pair.
                        //
                        if (IsPathValid) {
                            continue;
                        }
                    }
                } else {
                    //
                    // We're constrained to a particular zone.
                    // If this path uses a different one, keep looking.
                    //
                    if (DestinationScopeId.Zone != IppGetInterfaceScopeZone(
                            PathInterface, 
                            DestinationScopeId.Level)) {
                        continue;
                    }
                }
            } else {
                //
                // We're constrained to a particular interface.
                // If this route uses a different one, keep looking.
                //
                if (Interface != PathInterface) {
                    continue;
                }
                
                ASSERT((DestinationScopeId.Zone != 0) && 
                       (DestinationScopeId.Zone == IppGetInterfaceScopeZone(
                           PathInterface, DestinationScopeId.Level)));
            }

            //
            // If the source-address was not constrained, but the Path's
            // source-address has SkipAsSource set, then skip this path.
            //

            if (PathSourceAddress->SkipAsSource) {
                continue;
            }
        } else {
            //
            // We're constrained to a particular source.
            // If this route uses a different one, keep looking.
            //
            if (SourceAddress != PathSourceAddress) {
                continue;
            }
        }
                
        //
        // At this point, we have a path that matches our criteria.
        // As long as the path is still valid, we're done.
        //
        if (IsPathValid) {
            IppReferencePath(Path);
            RtlReleaseHashTableContext(&LookupContext);
            return Path;
        } else if (!ValidationAllowed) {
            //
            // Validation is not allowed since we don't hold the right lock.
            // Just ignore this path for now and we will look at it again if
            // required when the routine is called with the right lock. 
            //
            continue;
        }

        //
        // Something has changed in the routing state since the last
        // time this path was validated.  Attempt to revalidate it.
        //
        ASSERT((SourceAddress == NULL) || 
               (SourceAddress == PathSourceAddress));
        ASSERT((Interface == NULL) || (Interface == PathInterface));

        IppValidatePathUnderLock(Path);
        
        //
        // We need to check again that the path meets the criteria.  The source
        // address in the path can not change.  So, if a source
        // address/interface/scope ID constraint was specified and it matched
        // earlier, it is going to match even now.  But, we may have checked
        // the path validity because the path appeared to be constrained and we
        // need an unconstrained path.  In that case, we need to check the
        // constrained flags again.
        // NB: ScopeId == 0 implies Interface == NULL.
        //     Interface == NULL implies SourceAddress == NULL.
        //
        if (((DestinationScopeId.Value == 0) && 
             (Path->Flags.Constrained != 0)) ||
            ((Interface == NULL) && 
             (Path->Flags.ConstrainedInterface || 
              Path->Flags.ConstrainedSource)) ||
            ((SourceAddress == NULL) &&
             (Path->Flags.ConstrainedSource))) {
            continue;
        } else {
            IppReferencePath(Path);
            RtlReleaseHashTableContext(&LookupContext);
            return Path;
        } 
    }

    RtlReleaseHashTableContext(&LookupContext);
    return NULL;
}

PIP_PATH
IppFindPath(
    IN PIP_COMPARTMENT Compartment,
    IN OUT ULONG *KeyPointer OPTIONAL,
    IN CONST UCHAR *DestinationAddress,
    IN SCOPE_ID DestinationScopeId,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN CONST IP_LOCAL_UNICAST_ADDRESS *ConstrainSourceAddress OPTIONAL
    )
/*++

Routine Description:

    Look for an existing path entry.

Arguments:

    Compartment - Supplies a pointer to the compartment.

    BucketIndexPointer - Optionally supplies a precomputed bucket index, or
        IP_PATH_BUCKET_UNKNOWN if unknown.

    DestinationScopeId - Supplies the scope id of the destination address.

    DestinationAddress - Supplies the destination address.

    Interface - Optionally supplies the interface to use as the source of
        the path.

    ConstrainSourceAddress - Optionally supplies the source address to use as
        the source of the path.

Return Value:

    Returns a pointer to the path entry found, or NULL if the path cannot be
        found.

Locks:

    Assumes caller holds a reference on SourceAddress.
    May take a lock on a path bucket.
Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG Key;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    KIRQL OldIrql;
    PIP_PATH Path;

    ASSERT(ScopeLevel(DestinationScopeId) == 
           Protocol->AddressScope(DestinationAddress));

    Key = IppComputePathSetKey(Compartment, DestinationAddress);

    RtlAcquireScalableReadLock(&Compartment->PathSet.Lock, &OldIrql);
    Path =
        IppFindPathUnderLock(
            Compartment, 
            Key, 
            DestinationAddress,
            DestinationScopeId, 
            Interface, 
            ConstrainSourceAddress, 
            AddressBytes,
            FALSE);

    RtlReleaseScalableReadLock(&Compartment->PathSet.Lock, OldIrql);

    if (KeyPointer != NULL) {
        *KeyPointer = Key;
    }

    return Path;
}

NTSTATUS
IppFindOrCreatePath(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *DestinationAddress,
    IN SCOPE_ID DestinationScopeId,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN PIP_LOCAL_UNICAST_ADDRESS ConstrainSourceAddress OPTIONAL,
    OUT PIP_PATH *PathPointer
    )
/*++

Routine Description:

    Helper function for RouteToDestination and RedirectRouteCache.
    Compare FindOrCreateRoute in the XP IPv6 stack.
  
Arguments:

    DestinationScopeId - Supplies the scope id of the destination address.

    DestinationAddress - Supplies the destination address.

    Interface - Optionally supplies the interface to use as the source of 
        the path.

    ConstrainSourceAddress - Optionally supplies the source address to use as
        the source of the path. 

    PathPointer - Returns a pointer to the path entry found or created.
        Returns NULL if the path cannot be created.

Return Value:

    See the RouteToDestination description of return codes.
    STATUS_NOT_FOUND can only be returned if Interface is NULL or if
    ConstrainSourceAddress is NULL and the SourceAddress has the SkipAsSource
    flag set.
    RouteToDestination may retry IppFindOrCreatePath with a non-null 
    Interface when it gets STATUS_NOT_FOUND.

Locks:

    Assumes caller holds a reference on SourceAddress.
    May take a lock on a path bucket.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PATH Path;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PIPP_PATH_SET PathSet = &Compartment->PathSet;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_NEXT_HOP NextHop = NULL;
    PIP_UNICAST_ROUTE Route;
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress = NULL;
    IP_PATH_FLAGS Constrained;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG RoutingEpoch;
    ULONG Key;

    //
    // First try to find the path without taking the write lock. 
    //
    Path =
        IppFindPath(
            Compartment, 
            &Key,
            DestinationAddress,
            DestinationScopeId,
            Interface,
            ConstrainSourceAddress);
    if (Path != NULL) {
        goto ReturnPath;
    }

    RoutingEpoch = Compartment->RoutingEpoch;
    
    //
    // No existing path found. Before creating a new path, we determine a 
    // next-hop and a best source address for this destination. The order is
    // important: we want to avoid allocating a new path if we will just get
    // an error anyway. This prevents a denial-of-service attack.
    //
    // Need to call IppFindNextHopAndSource outside PathSet->Lock write lock
    // because it acquires and release Interface->lock, thus violating the
    // locking hierachy where the interface is acquired before the 
    // PathSet->Lock.
    //

    Status =
        IppFindNextHopAndSource(
            Compartment, 
            Interface, 
            DestinationAddress, 
            DestinationScopeId, 
            ConstrainSourceAddress,
            &NextHop, 
            &SourceAddress,
            &Route,
            &Constrained);

    if (!NT_SUCCESS(Status)) {
        if (IS_IPV4_PROTOCOL(Protocol)) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Route lookup failed for address %!IPV4!, "
                       "ConstrainSourceAddress %p, "
                       "Interface %d\n",
                       DestinationAddress,
                       ConstrainSourceAddress, 
                       (Interface == NULL) ? -1 : Interface->Index);
        } else {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Route lookup failed for address %!IPV6!, "
                       "ConstrainSourceAddress %p, "
                       "Interface %d\n",
                       DestinationAddress,
                       ConstrainSourceAddress, 
                       (Interface == NULL) ? -1 : Interface->Index);
        }
        
        goto ReturnPath;
    }

    ASSERT((NextHop != NULL) &&
           (SourceAddress != NULL) &&
           ((ConstrainSourceAddress == NULL) ||
            (ConstrainSourceAddress == SourceAddress)));           
    
    if (ConstrainSourceAddress == NULL) {
        ASSERT((SourceAddress != NULL) && (!SourceAddress->SkipAsSource));
    }

    //
    // Acquire the path set write lock since we are going to add a new path. 
    //
    RtlAcquireScalableWriteLock(&PathSet->Lock, &LockHandle);

    Path =
        IppFindPathUnderLock(
            Compartment, 
            Key,
            DestinationAddress, 
            DestinationScopeId, 
            Interface, 
            ConstrainSourceAddress, 
            AddressBytes,
            TRUE);

    if (Path != NULL) {    
        IppDereferenceLocalUnicastAddress(SourceAddress);
        IppDereferenceNextHop(NextHop);
        if (Route != NULL) {
            IppDereferenceRoute((PIP_ROUTE) Route);
        }       
        goto UnlockReturnPath;
    }

    Path = (PIP_PATH) FsbAllocate(Protocol->PathPool);

    if (Path == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Failure allocating path\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        IppDereferenceLocalUnicastAddress(SourceAddress);
        IppDereferenceNextHop(NextHop);
        if (Route != NULL) {
            IppDereferenceRoute((PIP_ROUTE) Route);
        }
        goto UnlockReturnPath;
    }

    RtlZeroMemory(Path, sizeof(IP_PATH));
    //
    // One reference is held by the cache, one for our caller.
    //
    Path->ReferenceCount = 1;
    IppReferencePath(Path);

    Path->Signature = IP_PATH_SIGNATURE;

    //
    // One reference is held by the path we point to.
    //
    Path->SourceAddress = SourceAddress;
    Path->DestinationAddress = (PUCHAR)(Path + 1);
    RtlCopyMemory(
        (PUCHAR) Path->DestinationAddress, DestinationAddress, AddressBytes);
    Path->ScopeId =
        IppGetScopeId(SourceAddress->Interface, DestinationAddress);
    InitializeSListHead(&Path->OffloadRequestQueue);
    InitializeSListHead(&Path->OffloadedBlocks);

    //
    // FindOrCreateNeighbor/FindRoute (called from IppFindNextHop) gave
    // us a reference for the neighbor.  We donate that reference to the path.
    // Similarly, FindBestSourceAddress gave us a reference
    // for the local address and we donate the reference to the path.
    //
    Path->Flags.Constrained = Constrained.Constrained;

    //
    // Start with a value safely in the past.
    //
    Path->LastError = IppTickCount - ICMP_MIN_ERROR_INTERVAL - 1;
    
    Path->CurrentNextHop = NextHop;
    if (IppIsNextHopNeighbor(NextHop)) {
        PIP_NEIGHBOR Neighbor = (PIP_NEIGHBOR) NextHop;
        Path->PathMtu = Neighbor->SubInterface->NlMtu;
    } else {
        Path->PathMtu = LOOPBACK_MTU;
    }
    Path->PathMtuLastSet = 0; // PMTU timer not running.
    // Path->ScopeId = DestinationScopeId;

    Path->RoutingEpoch = RoutingEpoch;
    Path->PathEpoch = 1;
    Path->LastConfirmation = IppTickCount - 1;
    KeInitializeSpinLock(&Path->Bandwidth.SpinLock);
    
    Path->IsReachable = TRUE;
    
    IppSetRouteInPath(Path, Route);

    RtlInsertEntryHashTable(
        &Compartment->PathSet.Table,
        &Path->Link,
        Key,
        NULL);
        
UnlockReturnPath:
    RtlReleaseScalableWriteLock(&PathSet->Lock, &LockHandle);

ReturnPath:
    if (NT_SUCCESS(Status)) {
        ASSERT(DestinationScopeId.Level == Path->ScopeId.Level);
        ASSERT((DestinationScopeId.Zone == 0) ||
               (DestinationScopeId.Zone == Path->ScopeId.Zone) ||
               (Compartment->RoutingEpoch != Path->RoutingEpoch));
        ASSERT((ConstrainSourceAddress != NULL) ||
               (!Path->SourceAddress->SkipAsSource));
        *PathPointer = Path;
    } else {
        *PathPointer = NULL;
    }
    return Status;
}

VOID
NTAPI
IpNlpLeavePath(
    IN PNL_REQUEST_LEAVE_PATH Args
    )
{
    PIP_PATH Path = IppCast(Args->Path, IP_PATH);

    IppDereferencePath(Path);
}

NTSTATUS
IppGetRouteKey(
    IN PIP_UNICAST_ROUTE Route,
    OUT PNL_ROUTE_KEY Key
    )
/*++

Routine description:

    Validates that the Route still resides in the Compartment's RouteSet,
    and then retrieves the Key information.

Arguments:

    Route - Supplies the route to inspect.

    Key - Returns the route key information.

Return Value:

    STATUS_SUCCESS if Route is still in RouteSet.
    STATUS_NOT_FOUND otherwise.

Caller IRQL:
 
    May be called at PASSIVE through DISPATCH level.

Caller Lock:

    Must NOT hold RouteSet lock.

--*/
{
    KIRQL OldIrql;
    NTSTATUS Status;
    UINT8 DestinationPrefixLength, SourcePrefixLength;
    PUCHAR InternalKey, DestinationPrefix, SourcePrefix;
    USHORT InternalKeyLength;
    IF_LUID SubInterfaceLuid = {0};
    PIP_COMPARTMENT Compartment = Route->Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;

    //
    // Route->Link can only be dereferenced under the route-set lock.
    //
    RtlAcquireScalableReadLock(&RouteSet->Lock, &OldIrql);  
    

    if (Route->Flags.InRouteSet) {
        Status = STATUS_SUCCESS;

        if (!Route->Flags.Loopback && (Route->CurrentNextHop != NULL)) {
            SubInterfaceLuid = Route->CurrentNextHop->SubInterface->Luid;
        } else {
            SubInterfaceLuid = Route->Interface->Luid;
        }
        
        PtGetKey(&Route->Link, &InternalKey, &InternalKeyLength);

        Protocol->
            ParseRouteKey(
                InternalKey, 
                InternalKeyLength, 
                &DestinationPrefix, 
                &DestinationPrefixLength, 
                &SourcePrefix,
                &SourcePrefixLength);

        if (IS_IPV4_PROTOCOL(Protocol)) {
            PIPV4_ROUTE_KEY Ipv4Key = (PIPV4_ROUTE_KEY) Key;
            
            Ipv4Key->DestinationPrefix = *((PIN_ADDR) DestinationPrefix);
            Ipv4Key->DestinationPrefixLength = DestinationPrefixLength;
            Ipv4Key->SourcePrefix = *((PIN_ADDR) SourcePrefix);
            Ipv4Key->SourcePrefixLength = SourcePrefixLength;
            Ipv4Key->InterfaceLuid = Route->Interface->Luid;

            Ipv4Key->SubInterfaceLuid = SubInterfaceLuid;
            Ipv4Key->NextHopAddress =
                *((PIN_ADDR) IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route));
        } else {
            PIPV6_ROUTE_KEY Ipv6Key = (PIPV6_ROUTE_KEY) Key;
            
            Ipv6Key->DestinationPrefix = *((PIN6_ADDR) DestinationPrefix);
            Ipv6Key->DestinationPrefixLength = DestinationPrefixLength;
            Ipv6Key->SourcePrefix = *((PIN6_ADDR) SourcePrefix);
            Ipv6Key->SourcePrefixLength = SourcePrefixLength;
            Ipv6Key->InterfaceLuid = Route->Interface->Luid;
            
            Ipv6Key->SubInterfaceLuid = SubInterfaceLuid;
            Ipv6Key->NextHopAddress =
                *((PIN6_ADDR) IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route));
        }
    } else {
        Status = STATUS_NOT_FOUND;
    }

    RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);
    
    return Status;
}

PIP_ROUTE
IppGetNextRoute(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST UCHAR *Key, 
    IN ULONG KeyLength,
    IN PIF_LUID InterfaceLuid OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL
    )
/*++

Routine Description:

    Finds the next route after the specified key.

Arguments:

    Compartment - Supplies the compartment to look in.

    Key - Supplies the internal route key.

    KeyLength - Supplies the internal route key length.

    InterfaceLuid - Optionally specifies the interface LUID of the key.

    NextHopAddress - Optionally specifies the next hop address of the key.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
    PIP_ROUTE FirstRoute, Route;
    KIRQL OldIrql;
    PIPR_LINK Link[2];
    ULONG Count = 2;
    PREFIX_TREE_CONTEXT Context;
    
    RtlAcquireScalableReadLock(&RouteSet->Lock, &OldIrql);

    //
    // If Key is not NULL then we are starting with a known route.
    // First try to locate the exact route and see if there are any other
    // routes in the queue. If not then enumerate over the route table.
    //
    if ((Key != NULL) &&
        (PtGetExactMatch(
            RouteSet->Tree, 
            (PUCHAR) Key,
            (USHORT) KeyLength, 
            &Context, 
            Link) == STATUS_SUCCESS)) {

        FirstRoute = (PIP_ROUTE)CONTAINING_RECORD(Link[0], IP_ROUTE, Link);

        Route = (PIP_ROUTE)
            IppFindRoute(
                Compartment->Protocol,
                (PIP_UNICAST_ROUTE) FirstRoute,
                InterfaceLuid,
                NextHopAddress);
        //
        // Since we just looked for the exact match, if the entry happens to be
        // the last one on the current next hop list we should enumerate over
        // the route table.
        //
        if ((Route != NULL) &&
            (Route->RouteLink.Flink != &FirstRoute->RouteLink)) {
            Route = (PIP_ROUTE) CONTAINING_RECORD(
                Route->RouteLink.Flink, IP_ROUTE, RouteLink);
            IppReferenceRoute(Route);
            goto Done;
        }
    }
    
    Status = PtEnumOverTable(RouteSet->Tree,
                             (PUCHAR)Key,
                             (PUSHORT)&KeyLength,
                             NULL,
                             NULL,
                             0,
                             &Count,
                             Link);

    if ((Count == 0) || ((Count == 1) && (Key != NULL))) {
        Route = NULL;
    } else if (Key == NULL) {
        Route = (PIP_ROUTE)CONTAINING_RECORD(Link[0], IP_ROUTE, Link);
        IppReferenceRoute(Route);
    } else {
        Route = (PIP_ROUTE)CONTAINING_RECORD(Link[1], IP_ROUTE, Link);
        IppReferenceRoute(Route);
    }

  Done:
    RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);

    return Route;
}

NTSTATUS
IppFindUnicastRouteUnderLock(
    IN CONST UCHAR *Key,
    IN USHORT KeyLength,
    IN PIP_COMPARTMENT Compartment,
    IN CONST IP_INTERFACE *Interface OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL,
    OUT PIP_UNICAST_ROUTE *RoutePointer
    )
/*++

Routine Description:

    This routine performs an exact-match lookup on a (dest,source) pair.

Arguments:

    Key - Supplies the structure containing the key fields.

    KeyLength - Supplies the number of significant bits in the key.

    Compartment - Supplies a pointer to a compartment.

    Interface - Optionally supplies a pointer to an interface.

    NextHopAddress - Optionally supplies the next-hop address.

    RoutePointer - Receives a pointer to the longest matching route, if found.

Return Value:

    STATUS_SUCCESS if found.
    STATUS_NOT_FOUND if not found.

Locks:

    Assumes caller has a reference on Interface.
    Caller holds RouteSet lock.
    Caller is responsible for dereferencing the route on success.
 
Caller IRQL:

    DISPATCH level (Since a lock is held)

--*/
{
    NTSTATUS Status;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
    PIP_UNICAST_ROUTE Route, RouteFound;
    PIPR_LINK Link;

    DISPATCH_CODE();
    ASSERT_ANY_SCALABLE_LOCK_HELD(&RouteSet->Lock);

    *RoutePointer = NULL;    
    Status = PtGetExactMatch(RouteSet->Tree, Key, KeyLength, NULL, &Link);
    if (!NT_SUCCESS(Status)) {
        Status = STATUS_NOT_FOUND;
    } else {
        Route = 
            (PIP_UNICAST_ROUTE)CONTAINING_RECORD(Link, IP_UNICAST_ROUTE, Link);
        
        RouteFound =
            IppFindRoute(
                Compartment->Protocol, 
                Route,
                &Interface->Luid, 
                NextHopAddress);
        
        if (RouteFound != NULL) {
            IppReferenceRoute((PIP_ROUTE) RouteFound);
            *RoutePointer = RouteFound;
        } else {
            Status = STATUS_NOT_FOUND;
        }
    }

    return Status;
}

NTSTATUS
IppFindUnicastRoute(
    IN CONST UCHAR *Key,
    IN USHORT KeyLength,
    IN PIP_COMPARTMENT Compartment,
    IN CONST IP_INTERFACE *Interface OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL,
    OUT PIP_UNICAST_ROUTE *RoutePointer
    )
/*++

Routine Description:

    This routine performs an exact-match lookup on a (dest,source) pair.

Arguments:

    Key - Supplies the structure containing the key fields.

    KeyLength - Supplies the number of significant bits in the key.

    Compartment - Supplies a pointer to a compartment.

    Interface - Optionally supplies a pointer to an interface.

    NextHopAddress - Optionally supplies the next-hop address.

    RoutePointer - Receives a pointer to the longest matching route, if found.

Return Value:

    STATUS_SUCCESS if found.
    STATUS_NOT_FOUND if not found.

Locks:

    Assumes caller has a reference on Interface.
    Caller is responsible for dereferencing the route on success.
    Internally locks a route table instance for reading.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
    KIRQL OldIrql;
    
    RtlAcquireScalableReadLock(&RouteSet->Lock, &OldIrql);
    Status = 
        IppFindUnicastRouteUnderLock(
            Key,
            KeyLength,
            Compartment,
            Interface,
            NextHopAddress,
            RoutePointer);
    RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);

    return Status;
}

NTSTATUS
IppRouteToDestination(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Destination,
    IN SCOPE_ID DestinationScopeId,
    IN PIP_INTERFACE ConstrainInterface OPTIONAL,
    IN CONST IP_LOCAL_ADDRESS *ConstrainLocalAddress OPTIONAL,
    OUT PIP_PATH *PathPointer
    )
/*++

Routine Description:

    Finds an existing, or creates a new, route cache entry for
    a particular destination.  Note the destination address may
    only be valid in a particular scope.
    Compare RouteToDestination in the XP IPv6 stack.  The only differnce is
    that the scope ID is assumed to be canonicalized.

Arguments:
  
    Compartment - Supplies the compartment.

    Destination - Supplies the destination to route to. 

    DestinationScopeId - Supplies the scope ID of the destination.  The scope
        ID is assumed to be canonicalized. 

    ConstrainInterface - Optionally supplies the interface that should be used
        to reach the destination.

    ConstrainLocalAddress - Optionally supplies the source address that should
        be used to reach the destination.

    PathPointer - Returns the path to the destination. 

Return Value:

    The return value must be an NTSTATUS code which matches a TDI status code.

    STATUS_SUCCESS                   Succeeded.
    STATUS_INSUFFICIENT_RESOURCES    Couldn't allocate memory.
    STATUS_INVALID_ADDRESS_COMPONENT Illegal LocalAddress/Destination/ScopeId.
    STATUS_INVALID_PARAMETER         Illegal interface constraint.
    STATUS_HOST_UNREACHABLE          No way to reach the destination; can
                                     only be returned if ConstrainInterface 
                                     and LocalAddress are NULL.

    NB: The return code values and situations in which they are used
    in RouteToDestination and its helper functions must be carefully
    considered, both for RouteToDestination's own correctness
    and for the correctness of callers.

--*/
{
    NTSTATUS ReturnValue;

    ReturnValue = 
        IppValidateRouteLookup(
            Compartment,
            Destination,
            &DestinationScopeId,
            ConstrainInterface,
            ConstrainLocalAddress);

    if (!NT_SUCCESS(ReturnValue)) {
        return ReturnValue;
    }
    
    if (ConstrainLocalAddress != NULL) {
        ConstrainInterface = ConstrainLocalAddress->Interface;
    }

    ReturnValue =
        IppFindOrCreatePath(
            Compartment, 
            Destination,
            DestinationScopeId,
            ConstrainInterface, 
            (PIP_LOCAL_UNICAST_ADDRESS) ConstrainLocalAddress,
            PathPointer);

    ASSERT((*PathPointer != NULL) == NT_SUCCESS(ReturnValue));

    
    if (ReturnValue == STATUS_NOT_FOUND) {
        //
        // Map status to something more reasonable for the client.
        //
        ReturnValue = STATUS_NETWORK_UNREACHABLE;
    }

    return ReturnValue;
}

__inline 
VOID
IppInvalidateDestinationCache(
    IN PIP_COMPARTMENT Compartment
    )
{
    InterlockedIncrement(&Compartment->RoutingEpoch);
}

__inline
VOID
IppInvalidatePath(
    IN PIP_PATH Path
    )
{
    InterlockedDecrement(&Path->RoutingEpoch);
}

PIP_NEXT_HOP
IppGetNextHopFromPathUnderLock(
    IN PIP_PATH Path
    )
/*++

Routine Description:
    
    Return the current NextHop for a Path.
    The NextHop must be a Neighbor or a LocalAddress.
    
Arguments:

    Path - Supplies the path.

Return Value:

    A referenced NextHop or NULL.
    Caller is responsible for releasing the reference on the NextHop.
    
Caller LOCK: Compartment's path set (Shared).
Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_NEXT_HOP NextHop;
    
    ASSERT_ANY_SCALABLE_LOCK_HELD(&IppGetPathSetFromPath(Path)->Lock);
    
    NextHop = Path->CurrentNextHop;
    if (NextHop != NULL) {
        IppReferenceNextHop(NextHop);
        ASSERT(IppIsNextHopNeighbor(NextHop) ||
               IppIsNextHopLocalAddress(NextHop));
    }

    return NextHop;
}

PIP_NEXT_HOP
IppGetNextHopFromPath(
    IN PIP_PATH Path
    )
{
    KIRQL OldIrql;
    PIP_NEXT_HOP NextHop;
    PIPP_PATH_SET PathSet = IppGetPathSetFromPath(Path);
    
    RtlAcquireScalableReadLock(&PathSet->Lock, &OldIrql);
    NextHop = IppGetNextHopFromPathUnderLock(Path);
    RtlReleaseScalableReadLock(&PathSet->Lock, OldIrql);

    return NextHop;
}

PNL_NEXT_HOP
NTAPI
IpNlpGetNextHopFromPath(
    IN CONST NL_PATH *NlPath
    )
{
    PIP_PATH Path = (PIP_PATH) NlPath;
    PIP_COMPARTMENT Compartment = Path->SourceAddress->Interface->Compartment;

    if (!IS_PATH_VALID(Path, Compartment)) {
        IppValidatePath(Path);
    }
        
    return IppGetNextHopFromPath(Path);
}

PIP_NEIGHBOR
IppGetNeighborFromPathUnderLock(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    Return the NextHop for a Path if the NextHop is a Neighbor.
    If there is no NextHop, or if the NextHop is a LocalAddress, return NULL.
    
Arguments:

    Path - Supplies the path.
    
Return Value:

    A referenced Neighbor or NULL.
    Caller is responsible for releasing the reference on the Neighbor.
    
Caller LOCK: Compartment's path set (Shared).
Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    ASSERT_ANY_SCALABLE_LOCK_HELD(&IppGetPathSetFromPath(Path)->Lock);
    
    if ((Path->CurrentNextHop != NULL) && 
        (IppIsNextHopNeighbor(Path->CurrentNextHop))) {
        IppReferenceNextHop(Path->CurrentNextHop);
        return (PIP_NEIGHBOR) Path->CurrentNextHop;
    }
    return NULL;
}


PIP_NEIGHBOR
IppGetNeighborFromPath(
    IN PIP_PATH Path
    )
{
    KIRQL OldIrql;
    PIP_NEIGHBOR Neighbor;
    PIPP_PATH_SET PathSet = IppGetPathSetFromPath(Path);
    
    RtlAcquireScalableReadLock(&PathSet->Lock, &OldIrql);
    Neighbor = IppGetNeighborFromPathUnderLock(Path);
    RtlReleaseScalableReadLock(&PathSet->Lock, OldIrql);

    return Neighbor;
}


BOOLEAN
IppSetNextHopInPathUnderLock(
    IN PIP_PATH Path,
    IN PIP_NEXT_HOP NextHop OPTIONAL,
    IN PIP_UNICAST_ROUTE Route OPTIONAL,
    IN LONG RoutingEpoch
    )
/*++

Routine Description:
 
    This routine sets the next hop in a path to a particular neighbor or local
    address. This can be used, for instance by the redirect code to change the
    path on receiving a redirect. This routine consumes the reference on the
    Neighbor or LocalAddress.
   
Arguments:

    Path - Supplies the path to update. 

    NextHop - Supplies the NextHop (Neighbor/LocalAddress) to set in the path.
        This can be NULL.  

    Route - Supplies the route to set in the path. 

    RoutingEpoch - Supplies the routing epoch to set in the path in case the
        update succeeds. 

Return Value:

    Returns a boolean indicating whether the path was updated or not.  

Caller LOCK:

    Caller holds path cache write lock.

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    IP_PATH_FLAGS NewFlags;

    ASSERT_SCALABLE_WRITE_LOCK_HELD(&IppGetPathSetFromPath(Path)->Lock);
    
    //
    // Update the route pointer.  
    //
    IppSetRouteInPath(Path, Route);

    //
    // Get the next hop currently stored in the path. Only if the next hop
    // information has changed do we update the path.
    //
    if (Path->CurrentNextHop == NextHop) {
        //
        // The next hop hasn't changed. No need to update. 
        // Remove the references that we were given. 
        // Also update the routing epoch in the path since it is now
        // sycnhronized with the routing state but no need to change the path
        // epoch since the path hasn't changed. 
        //
        if (NextHop != NULL) {
            IppDereferenceNextHop(NextHop);
        }
        Path->RoutingEpoch = RoutingEpoch;
        return FALSE;
    } 


    //
    // Start with a value safely in the past.
    //
    Path->LastError = IppTickCount - ICMP_MIN_ERROR_INTERVAL - 1;

    if (Path->CurrentNextHop != NULL) {
        IppDereferenceNextHop(Path->CurrentNextHop);
    }
    Path->CurrentNextHop = NextHop;

    //
    // Reset a few flags.
    // Since Path->Flags can be read without holding any locks,
    // it is imperative to reset both the flags in an atomic
    // operation using a temporary variable (NewFlags).
    //
    // Note however that the flags can only be updated while
    // holding the PathSet lock, so we are assured that there
    // are no other updates going on.
    //

    NewFlags = Path->Flags;

    NewFlags.ForceFragment = FALSE;
    NewFlags.LastPathMtuChangeWasDecrease = FALSE;

    Path->Flags.Value = NewFlags.Value;

    if (NextHop != NULL && IppIsNextHopNeighbor(NextHop)) {
        PIP_NEIGHBOR Neighbor = (PIP_NEIGHBOR) NextHop;
        Path->PathMtu = Neighbor->SubInterface->NlMtu;
    } else {
        Path->PathMtu = LOOPBACK_MTU;
    }

    Path->PathMtuLastSet = 0; // PMTU timer not running.
  
    //
    // Reset the RTT estimator, as well as the bandwidth estimator.
    // 

    Path->RttLastSample = 0;

    //
    // We don't want to acquire/release the lock if the Bandwidth 
    // estimators are not set up.
    //

    if (Path->Bandwidth.In != NULL || Path->Bandwidth.Out != NULL) {
        KIRQL OldIrql;

        KeAcquireSpinLock(&Path->Bandwidth.SpinLock, &OldIrql);

        if (Path->Bandwidth.In != NULL) {
            Path->Bandwidth.In->LastSample = 0;
        }

        if (Path->Bandwidth.Out != NULL) {
            Path->Bandwidth.Out->LastSample = 0;
        }

        KeReleaseSpinLock(&Path->Bandwidth.SpinLock, OldIrql);
    }

     
    //
    // The validation has completed -- the path is completely in sync with
    // the routing state.  So update the routing epoch. 
    //
    Path->RoutingEpoch = RoutingEpoch;

    //
    // Reset path-reachability information.
    //
    Path->LastConfirmation = IppTickCount - 1;

    //
    // Invalidate any path cached information. 
    // Incrementing PathEpoch will do that.
    //
    IppInvalidatePathCachedInformation(Path);

    //
    // 1. Mark the path as dirty. 
    // 2. Update path offload state. 
    //
    IppMarkPathDirty(Path);
    IppDeferUpdatePathOffloadState(Path);

    return TRUE;
}

VOID
IppSetNextHopInPath(
    IN PIP_PATH Path, 
    IN PIP_NEXT_HOP NextHop OPTIONAL, 
    IN PIP_UNICAST_ROUTE Route OPTIONAL,
    IN LONG RoutingEpoch
    )
/*++

Routine Description:
 
    This routine sets the next hop in a path to a particular neighbor or local
    address.  This is just a wrapper around IppSetNextHopInPathUnderLock. 

--*/ 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    BOOLEAN Updated;
    PIPP_PATH_SET PathSet = IppGetPathSetFromPath(Path);
    
    RtlAcquireScalableWriteLock(&PathSet->Lock, &LockHandle);

    Updated =
        IppSetNextHopInPathUnderLock(
            Path, 
            NextHop,
            Route, 
            RoutingEpoch);
    
    RtlReleaseScalableWriteLock(&PathSet->Lock, &LockHandle);
}


PIP_UNICAST_ROUTE
IppGetRouteFromPath(
    IN PIP_PATH Path
    )
/*++

Routine Description:
    
    Return the current Route for a Path.
    
Arguments:

    Path - Supplies the path.

Return Value:

    A referenced Route or NULL.
    Caller is responsible for releasing the reference on the Route.
    
Caller LOCK: None.

--*/ 
{
    KIRQL OldIrql;
    PIP_UNICAST_ROUTE Route;
    PIPP_PATH_SET PathSet = IppGetPathSetFromPath(Path);
    
    RtlAcquireScalableReadLock(&PathSet->Lock, &OldIrql);
    Route = Path->Route;
    if (Route != NULL) {
        IppReferenceRoute((PIP_ROUTE) Route);
    }
    RtlReleaseScalableReadLock(&PathSet->Lock, OldIrql);
    return Route;
}


VOID
IppValidatePathUnderLock(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    This routine validates an existing path entry.  Checks if the path is still
    valid and if not, does a route lookup.  If the new next hop matches the old
    next hop it returns.  Otherwise it updates the next hop in the path. 

    Note: In case of failure, the next hop is set to NULL.

Arguments: 

    Path - Supplies the path to be validated. 

Return Value: 

    None.
    
--*/
{
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress;
    CONST UCHAR *DestinationAddress = Path->DestinationAddress;
    PIP_INTERFACE Interface = Path->SourceAddress->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    LONG RoutingEpoch;
    IP_PATH_FLAGS Constrained;
    PIP_NEXT_HOP NextHop = NULL;
    PIP_UNICAST_ROUTE Route = NULL;

    //
    // The Path's Flags should always be updated with the path-set lock
    // held in write-mode.
    //
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Compartment->PathSet.Lock);
    
    RoutingEpoch = Compartment->RoutingEpoch;

    //
    // Update the scope ID in the path to the current scope ID.  This is
    // required since the zone indices might have been updated. 
    //
    Path->ScopeId = IppGetScopeId(Interface, DestinationAddress);

    if (!IsLocalUnicastAddressValid(Path->SourceAddress)) {
        Path->Flags.ConstrainedSource = TRUE;
        IppSetNextHopInPathUnderLock(Path, NULL, NULL, RoutingEpoch);
        return;
    }

    //
    // Find the new next hop for the path.  Ignore the return value.  On
    // failure, we just set the next hop appropriately to NULL.
    //    
    (VOID) IppFindNextHopAndSource(
        Compartment, 
        Interface,
        DestinationAddress, 
        Path->ScopeId, 
        Path->SourceAddress,
        &NextHop,
        &SourceAddress,
        &Route,
        &Constrained);
    if (SourceAddress != NULL) {
        IppDereferenceLocalUnicastAddress(SourceAddress);
    }

    //
    // At this point, we have computed the source and next hop. Update the
    // constrained flag based on these. Note that we update the constrained
    // flag even if the validation fails below (because the atomic set update
    // lock operation failed). The reason is that we don't want a new path to
    // be created with the same source and destination even if the validation
    // fails here. 
    //
    Path->Flags.Constrained = Constrained.Constrained;
    
    //
    // Set the next hop in the path.
    // This consumes the references on the NextHop.
    //
    IppSetNextHopInPathUnderLock(Path, NextHop, Route, RoutingEpoch);
}

VOID
IppValidatePath(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    This routine validates an existing path entry.  Checks if the path is still
    valid and if not, does a route lookup.  If the new next hop matches the old
    next hop it returns.  Otherwise it updates the next hop in the path. 

Arguments: 

    Path - Supplies the path to be validated. 

Return Value: 

    None.
    
--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_COMPARTMENT Compartment = IppGetCompartmentFromPath(Path);
    
    if (IS_PATH_VALID(Path, Compartment)) {
        return;
    }
    
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
    IppValidatePathUnderLock(Path);
    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

}

VOID
IppValidatePaths(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    This routine validates all the paths in a compartment. Returns the number
    of paths for which validation failed. This is computationally intensive and
    should be called sparingly. Currently this is called only when a
    sub-interface is getting deleted.
    
Arguments:

    Compartment - Supplies the compartment.

Return Value:

    None.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_PATH Path;
    PRTL_HASH_TABLE_ENTRY Curr;
    KLOCK_QUEUE_HANDLE LockHandle;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIPP_PATH_SET PathSet;
    
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

    PathSet = &Compartment->PathSet;
    RtlInitEnumerationHashTable(&PathSet->Table, &Enumerator);

    for (Curr = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator)) {

        //
        // Now go over all the paths in the bucket and validate them.
        //
        Path = IppGetPathFromPathLink(Curr);

        ASSERT(IppGetCompartmentFromPath(Path) == Compartment);

        if (!IS_PATH_VALID(Path, Compartment)) {
            IppValidatePathUnderLock(Path);
        }
    }

    RtlEndEnumerationHashTable(&PathSet->Table, &Enumerator);

    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
}

VOID
IppGarbageCollectPaths(
    IN PIP_COMPARTMENT Compartment
    )
{
    PRTL_HASH_TABLE_ENTRY Curr;
    PIP_PATH Path;
    KLOCK_QUEUE_HANDLE LockHandle;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIPP_PATH_SET PathSet;
    
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
       
    PathSet = &Compartment->PathSet;
    RtlInitEnumerationHashTable(&PathSet->Table, &Enumerator);

    for (Curr = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator)) {
 
        Path = IppGetPathFromPathLink(Curr);

        ASSERT(IppGetCompartmentFromPath(Path) == Compartment);
     
        if (IppIsInterfaceDisabled(Path->SourceAddress->Interface)) {
            RtlRemoveEntryHashTable(&PathSet->Table, Curr, NULL);
            IppDereferencePath(Path);
        }
    }

    RtlEndEnumerationHashTable(&PathSet->Table, &Enumerator);

    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
}


VOID
IppFlushPaths(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_INTERFACE Interface OPTIONAL, 
    IN CONST UCHAR *Destination OPTIONAL,
    IN CONST IP_LOCAL_ADDRESS *Source OPTIONAL
    )
/*++

Routine Description:

    Flush all paths that match the arguments.
    Compare FlushRouteCache in the XP IPv6 stack.

Arguments:

    Compartment - Supplies a pointer to a compartment.

    Interface - Optionally supplies a pointer to a specific interface.

    Destination - Optionally supplies a specific destination address.

    Source - Optionally supplies a specific source address.

Locks:

    Internally locks each bucket in turn for reading.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
    
--*/
{
    //
    // This function does two things:
    //
    // 1. Any path that is cached (ref-count is 1) is removed from
    //    the Path Cache and dereferenced, effectively cleaning it up.
    //
    // 2. For every other path, we reset the Path MTU and a few flags.
    //
    
    PRTL_HASH_TABLE_ENTRY Curr;
    PIP_PATH Path;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG AddressBytes = 
            Compartment->Protocol->Characteristics->AddressBytes;
    PIPP_PATH_SET PathSet;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
       
    PathSet = &Compartment->PathSet;
 
    RtlAcquireScalableWriteLock(&PathSet->Lock, &LockHandle); 

    RtlInitEnumerationHashTable(&PathSet->Table, &Enumerator);

    for (Curr = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator)) {

        Path = IppGetPathFromPathLink(Curr);

        if (Interface != NULL) {
            if (Interface != Path->SourceAddress->Interface) {
                continue;
            }

            if ((Destination != NULL) &&
                !RtlEqualMemory(Path->DestinationAddress,
                                Destination,
                                AddressBytes)) {
                continue;
            }

            if ((Source != NULL) &&
                (Source != (PIP_LOCAL_ADDRESS) Path->SourceAddress)) {
                continue;
            }
        }

        //
        // Is the ref-count 1? If yes, deref it and remove it from the
        // path-cache. This will result in the path being deleted.
        //

        if (Path->ReferenceCount == 1) {
            RtlRemoveEntryHashTable(&PathSet->Table, Curr, NULL);
            IppDereferencePath(Path);
            continue;
        }

        //
        // Otherwise, simply invalidate the path.
        //

        IppInvalidatePath(Path);
    }

    RtlEndEnumerationHashTable(&PathSet->Table, &Enumerator);

    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
}

NTSTATUS
IppAddBandwidthListenerUnderLock(
    IN PIP_PATH Path,
    IN OUT PIP_PATH_BANDWIDTH_DIRECTION * Direction
    )
{
    if (*Direction == NULL) {
        
        //
        // This type of bandwidth estimation is not currently enabled on the
        // path.  Create the necessary state to start estimation, take a
        // reference on the estimation and the path itself, and invalidate the
        // cached path information so that it is queried immediately by clients
        // on next use.
        //

        *Direction =
            ExAllocatePoolWithTag(
                NonPagedPool, sizeof(**Direction), IpPathBandwidthPoolTag);
        
        if (*Direction == NULL) {
            return STATUS_NO_MEMORY;
        }

        //
        // Take a reference on the path to prevent the path from disappearing
        // while clients still care about the aggregate bandwidth across it.
        //

        IppReferencePath(Path);

        RtlZeroMemory(*Direction, sizeof(**Direction));
        (*Direction)->ReferenceCount = 1;

        IppInvalidatePathCachedInformation(Path);

    } else {

        //
        // Bandwidth estimation is already in progress for this path so we
        // simply increment our estimation reference count to prevent us from
        // exiting estimation while this client is still listening.
        //

        ++(*Direction)->ReferenceCount;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IppRemoveBandwidthListenerUnderLock(
    IN OUT PIP_PATH Path,
    IN OUT PIP_PATH_BANDWIDTH_DIRECTION *Direction
    )
{
    if ((*Direction != NULL) && ((--(*Direction)->ReferenceCount) == 0)) {

        //
        // The last client listening for this path bandwidth estimate has now
        // cancelled the estimation.  In this case, we free the state that we
        // had been using to track the bandwidth and release our reference to
        // the path.
        //

        ExFreePool(*Direction);
        *Direction = NULL;
        IppDereferencePath(Path);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IppAddOrRemoveBandwidthListeners(
    IN PIP_PATH Path,
    IN PIP_PATH_BANDWIDTH Bandwidth,
    IN NL_BANDWIDTH_FLAG Outbound,
    IN NL_BANDWIDTH_FLAG Inbound
    )
{
    KIRQL OriginalIrql;
    NTSTATUS Status = STATUS_SUCCESS;

    ASSERT(Bandwidth != NULL);

    //
    // Return quickly (without acquiring any lock) in the case that we have
    // not been asked to do anything.
    //
    
    if ((Outbound == NlbwUnchanged) && (Inbound == NlbwUnchanged)) {
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&Bandwidth->SpinLock, &OriginalIrql);

    //
    // Update the outbound estimation state if necessary.
    //

    if (Outbound == NlbwEnabled) {
        Status = IppAddBandwidthListenerUnderLock(Path, &Bandwidth->Out);
    } else if (Outbound == NlbwDisabled) {
        Status = IppRemoveBandwidthListenerUnderLock(Path, &Bandwidth->Out);
    }
    
    if (!NT_SUCCESS(Status)) {
        KeReleaseSpinLock(&Bandwidth->SpinLock, OriginalIrql);
        return Status;
    }

    //
    // Update the inbound estimation state if necessary.  If any of these
    // operations fail, we should try to undo the operation performed on the
    // outbound estimation state before returning.
    //
    // N.B. "Undoing" the removal of an outbound estimation listener may cause
    //      unexpected behavior if that removal had caused estimation on the
    //      connection to cease.  In that case, re-adding the listener will
    //      cause estimation to start anew.  This is probably OK because the
    //      caller has just tried to stop estimation; thus, it is unlikely to
    //      be reliant on estimates in the near future.
    //

    if (Inbound == NlbwEnabled) {
        Status = IppAddBandwidthListenerUnderLock(Path, &Bandwidth->In);
    } else if (Inbound == NlbwDisabled) {
        Status = IppRemoveBandwidthListenerUnderLock(Path, &Bandwidth->In);
    }

    if (!NT_SUCCESS(Status)) {
        if (Outbound == NlbwEnabled) {
            IppRemoveBandwidthListenerUnderLock(Path, &Bandwidth->Out);
        } else if (Outbound == NlbwDisabled) {
            IppAddBandwidthListenerUnderLock(Path, &Bandwidth->Out);
        }
    }

    KeReleaseSpinLock(&Bandwidth->SpinLock, OriginalIrql);
    return Status;

}

__inline
BOOLEAN
IppIsTooOld(
    IN ULONG Mean, 
    IN ULONG Deviation, 
    IN ULONG LastSampleTick,
    IN ULONG CurrentTick
    )
/*++

Routine Description:

    Determine whether our information is too old.

Arguments:

    Mean - Supplies our estimated mean of a given parameter.

    Deviation - Supplies the mean deviation of a given parameter.

    LastSampleTick - Supplies the time at which we last got a sample.

    CurrentTick - Supplies the current time.

--*/
{
    UNREFERENCED_PARAMETER(Mean);
    UNREFERENCED_PARAMETER(Deviation);

    //
    // Currently, we do not base this decision on the path's RTT.  Instead we
    // time-out all values older than a fixed number of seconds.
    //
    return (
        IP_PATH_INFO_MAX_AGE < CurrentTick - LastSampleTick ||
        LastSampleTick == 0);
}

VOID
IppFillPathBandwidthInformation(
    IN PIP_PATH_BANDWIDTH_DIRECTION IpBandwidth,
    IN ULONG64 FallbackLinkSpeed,
    OUT PNL_PATH_BANDWIDTH NlBandwidth
    )
/*++

Routine Description:

    This routine fills in the NL_PATH_BANDWIDTH structure based on a given
    IP_PATH_BANDWIDTH_DIRECTION structure.  This is called when filling general
    information about a path.

Arguments:

    IpBandwidth - Supplies the private IP path bandwidth information.  This may
        be NULL.

    FallbackLinkSpeed - Supplies the physical link speed in the appropriate
        direction (transmit or receive) for this path.  If bandwidth estimates
        are not available because of a transport layer limitation, the physical
        link speed will be used as the bandwidth estimate.

    NlBandwidth - The publicly visible NL path bandwidth structure to be filled.
        This must be non-NULL.

--*/
{
    if (IpBandwidth != NULL) {

        //
        // Initialize the bandwidth estimate to the link speed.  The link speed
        // is used an upper bound for path-based bandwidth estimates and as a
        // substitute when no such estimates are available.
        //
        
        NlBandwidth->IsEnabled = TRUE;
        NlBandwidth->Bandwidth = FallbackLinkSpeed;

        if (!!IpBandwidth->EstimateUnavailable && IpBandwidth->Bandwidth == 0) {
            //
            // We have no aggregated bandwidth estimate and the transport layer
            // has indicated that estimation may be unavailable for this block.
            //
            NlBandwidth->Instability = 0;
            NlBandwidth->BandwidthPeaked = 1;
        } else {
            //
            // If the aggregated bandwidth estimate is less than the link speed,
            // use it as our best bandwidth estimate.
            //
            if (IpBandwidth->Bandwidth < NlBandwidth->Bandwidth) {
                NlBandwidth->Bandwidth = IpBandwidth->Bandwidth;
            }
            NlBandwidth->Instability = IpBandwidth->Instability;
            NlBandwidth->BandwidthPeaked = IpBandwidth->BandwidthPeaked;
        }

        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE,
            "NL: Bandwidth queried: Link=%I64ubps, Bw=%I64ubps, Var=%I64ubps, "
            "Peaked=%u\n", FallbackLinkSpeed, NlBandwidth->Bandwidth,
            NlBandwidth->Instability,
            NlBandwidth->BandwidthPeaked ? 1 : 0);
        
    } else {
        NlBandwidth->IsEnabled = FALSE;
        NlBandwidth->Bandwidth = 0;
        NlBandwidth->Instability = 0;
        NlBandwidth->BandwidthPeaked = FALSE;
    }
}

VOID
IppFillPathInformation(
    IN PIP_PATH Path,
    IN PIP_SESSION_STATE State OPTIONAL,
    OUT PNL_PATH_INFO PathInformation,
    OUT PULONG IpOptionLength OPTIONAL
    )
/*++

Routine Description:

    Fill the NL_PATH_INFO structure for a given path.
    
    Called just before notifying the network layer client about a path update
    or when a network layer client queries for path information. 

Arguments:

    Path - Supplies the path queried/updated. 

    State - Optionally supplies the session options, some of which may affect
        the Path->UlMtu returned.

    PathInformation, relevant fields only - 

        DataBackfill - Returns the amount of data backfill the client should 
            use for packets sent on this path.

        RequestControlBackfill - Returns the amount of control backfill the 
            client should use for packets sent on this path.

        UlMtu - Returns the maximum transmission unit, in bytes, for upper
            layer protocol data.

        RttMean - Returns an estimate of the mean round-trip time, based on 
            samples provided via SetPathInfo.

        RttDeviation - Returns an estimate of the round-trip time deviation, 
            based on samples provided via SetPathInfo.

        BandwidthOut - Returns an estimate of the end-to-end outbound speed, 
            based on samples provided via SetPathInfo.

        BandwidthIn - Returns an estimate of the end-to-end inbound speed, 
            based on samples provided via SetPathInfo.        

        LinkTransmitSpeed - Returns the current speed of the outbound link.

        LinkReceiveSpeed - Returns the current speed of the inbound link.

    IpOptionLength - Returns the total length of IP options.

--*/
{
    ULONG NlHeadersSize;
    PIP_NEXT_HOP NextHop;
    PIP_INTERFACE Interface = Path->SourceAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    
    NlHeadersSize = Protocol->HeaderSize;
    if (Path->Flags.ForceFragment && IS_IPV6_PROTOCOL(Protocol)) {
        NlHeadersSize += sizeof(IPV6_FRAGMENT_HEADER);
    }

    if (State != NULL) {
        if (IpOptionLength != NULL) {
            *IpOptionLength = State->HopByHopOptionsLength + 
                              State->RoutingHeaderLength;
        }

        NlHeadersSize += State->HopByHopOptionsLength + 
                         State->RoutingHeaderLength;
    } else if (IpOptionLength != NULL) {
        *IpOptionLength = 0;
    }

    PathInformation->DataBackfill = (USHORT)
        ALIGN_UP(
            IpSecGetOverheadEstimate() + NlHeadersSize + Interface->FlBackfill,
            ULONG);

    PathInformation->RequestControlBackfill =
        Protocol->Characteristics->DefaultRequestControlBackfill;

    //
    // Calculate the path MTU for upper layers.  Note that IPSec headers affect
    // the MTU but this is determined by the TL using a direct call to IPSec.
    //
    PathInformation->UlMtu = Path->PathMtu - NlHeadersSize;
    ASSERT(Protocol->MinimumMtu > NlHeadersSize);
    PathInformation->MinimumUlMtu = Protocol->MinimumMtu - NlHeadersSize;
    
    if (IppIsTooOld(
            Path->RttMean, 
            Path->RttDeviation, 
            Path->RttLastSample,
            IppTickCount)) {
        PathInformation->RttMean = IppMilliseconds(3 * SECONDS);
        PathInformation->RttDeviation = 0;
    } else {
        PathInformation->RttMean = Path->RttMean;
        PathInformation->RttDeviation = Path->RttDeviation;
    }

    NextHop = PathInformation->NextHop;
    if (NextHop != NULL) {
        PathInformation->InterfaceIndex = NextHop->Interface->Index;

        if (IppIsNextHopNeighbor(NextHop)) {
            PIP_NEIGHBOR Neighbor = (PIP_NEIGHBOR) NextHop;
            
            PathInformation->LinkTransmitSpeed =
                Neighbor->SubInterface->FlCharacteristics->TransmitSpeed;
            PathInformation->LinkReceiveSpeed =
                Neighbor->SubInterface->FlCharacteristics->ReceiveSpeed;
            PathInformation->OperationalStatus =
                Neighbor->SubInterface->OperationalStatus;
            PathInformation->IsNextHopLocal = FALSE;
        } else {
            ASSERT(IppIsNextHopLocalAddress(NextHop));
            PathInformation->LinkTransmitSpeed = 0;
            PathInformation->LinkReceiveSpeed = 0;
            PathInformation->OperationalStatus = IfOperStatusUp;
            PathInformation->IsNextHopLocal = TRUE;
        }
    } else {
        PathInformation->IsNextHopLocal = FALSE;
    }

    PathInformation->ForceFragment = Path->Flags.ForceFragment;
    
    IppFillPathBandwidthInformation(
        Path->Bandwidth.Out,
        PathInformation->LinkTransmitSpeed, &PathInformation->BandwidthOut);
    IppFillPathBandwidthInformation(
        Path->Bandwidth.In,
        PathInformation->LinkReceiveSpeed, &PathInformation->BandwidthIn);
    PathInformation->BlackHoleNotLikely = Path->Flags.BlackHoleNotLikely;

}

VOID
IppFillPathRw(
    IN PIP_PATH Path,
    OUT PNL_PATH_RW Rw
    )
/*++

Routine Description:

    Fill in an NSI path RW structure with relevant values from the path.  This
    routine is common between IPv4 and IPv6.

Arguments:

    Path - Supplies a pointer to the path.

    Rw - The RW struct to be filled on return.

--*/
{
    Rw->EstimateBandwidthIn = (Path->Bandwidth.In != NULL);
    Rw->EstimateBandwidthOut = (Path->Bandwidth.Out != NULL);
}

VOID
IppFillPathRod(
    IN ULONG AddressBytes,
    IN PIP_PATH Path,
    OUT PNL_PATH_ROD Rod
    )
/*++

Routine Description:

    Fill in NSI path data.  This routine is common between
    IPv4 and IPv6, and can be used for both Gets and Enumerates.

Arguments:

    AddressBytes - Supplies the size in bytes of an IP address.

    Path - Supplies a pointer to a path.

    Rod - Returns read-only dynamic parameters.

--*/
{
    KIRQL OldIrql;
    PIPP_PATH_SET PathSet = IppGetPathSetFromPath(Path);

    RtlAcquireScalableReadLock(&PathSet->Lock, &OldIrql);
    IppFillPathRodUnderLock(AddressBytes, Path, Rod);
    RtlReleaseScalableReadLock(&PathSet->Lock, OldIrql);
}
    
VOID
IppFillPathRodUnderLock(
    IN ULONG AddressBytes,
    IN PIP_PATH Path,
    OUT PNL_PATH_ROD Rod
    )
/*++

Routine Description:

    Fill in NSI path data.  This routine is common between
    IPv4 and IPv6, and can be used for both Gets and Enumerates.

Arguments:

    AddressBytes - Supplies the size in bytes of an IP address.

    Path - Supplies a pointer to a path.

    Rod - Returns read-only dynamic parameters.

Caller LOCK: Compartment's path set (Shared).
Caller IRQL: DISPATCH_LEVEL.    
    
--*/
{
    NL_PATH_INFO PathInfo;
    PIP_NEXT_HOP NextHop;

    ASSERT_ANY_SCALABLE_LOCK_HELD(&IppGetPathSetFromPath(Path)->Lock);
    
    PathInfo.NextHop = NextHop = IppGetNextHopFromPathUnderLock(Path);

    IppFillPathInformation(Path, NULL, &PathInfo, NULL);

    //
    // The NL_PATH_ROD structure is not zeroed out. It will be
    // completely intialized in the code below.
    // If new fields are added to this structure, it becomes the
    // responsibility of the caller to zero the structure out.
    //

    Rod->NlMtu = Path->PathMtu;
    Rod->UlMtu = PathInfo.UlMtu;
    Rod->RttMean = PathInfo.RttMean;
    Rod->RttDeviation = PathInfo.RttDeviation;

    //
    // Report the LastReachable value in milliseconds.
    //
    Rod->LastReachable =
        IppTicksToMilliseconds(IppTickCount - Path->LastReachable);
    Rod->IsReachable = Path->IsReachable;
    Rod->ConnectionFailed = Path->Flags.ConnectionFailed;
    
    Rod->BandwidthOut.Bandwidth = PathInfo.BandwidthOut.Bandwidth;
    Rod->BandwidthOut.Instability = PathInfo.BandwidthOut.Instability;
    Rod->BandwidthOut.BandwidthPeaked = PathInfo.BandwidthOut.BandwidthPeaked;

    Rod->BandwidthIn.Bandwidth = PathInfo.BandwidthIn.Bandwidth;
    Rod->BandwidthIn.Instability = PathInfo.BandwidthIn.Instability;
    Rod->BandwidthIn.BandwidthPeaked = PathInfo.BandwidthIn.BandwidthPeaked;

    Rod->LinkTransmitSpeed = PathInfo.LinkTransmitSpeed;
    Rod->LinkReceiveSpeed = PathInfo.LinkReceiveSpeed;

    Rod->ActiveTcpConnectionCount = Path->ActiveConnectionCount;

    if (NextHop != NULL) {
        CONST UCHAR *NextHopAddress;

        if (IppIsNextHopNeighbor(NextHop)) {
            NextHopAddress = IP_NEIGHBOR_NL_ADDRESS((PIP_NEIGHBOR) NextHop);
        } else {
            NextHopAddress = NL_ADDRESS((PIP_LOCAL_ADDRESS) NextHop);
        };

        RtlCopyMemory(&Rod->NextHopAddress, NextHopAddress, AddressBytes);

        IppDereferenceNextHop(NextHop);
    }
}


VOID
IppUpdatePathMtu(
    IN PIP_PATH Path,
    IN ULONG NewMtu
    )
/*++

Routine Description:

    This routine updates the path MTU to a new value. It is responsible for
    setting the time of the update as well as recording if the update was an
    increase or a decrease. The caller should ensure that the new MTU is not
    greater than the link MTU.
    
Arguments:

    Path - Supplies the path that needs to be updated. 

    NewMtu - Supplies the new MTU for the path. 

Return Value:

    None.

Caller LOCK:

    The caller should hold the bucket lock. 

Caller IRQL: = DISPATCH_LEVEL because the bucket lock is held. 

--*/ 
{
    //
    // The PathSet lock needs to be held in write-mode since any changes in
    // Flags of any path are protected by the Path-Set lock.
    //

    ASSERT_SCALABLE_WRITE_LOCK_HELD(&IppGetPathSetFromPath(Path)->Lock);
     
    if (Path->PathMtu > NewMtu) {
        Path->Flags.LastPathMtuChangeWasDecrease = TRUE;
    } else if (Path->PathMtu > 0) {
        Path->Flags.LastPathMtuChangeWasDecrease = FALSE;
    } 
    Path->PathMtu = NewMtu;
    Path->PathMtuLastSet = IppTickCount;
    IppInvalidatePathCachedInformation(Path);
    
    //
    // Need to defer the update because we might be holding a lock. 
    //
    IppDeferUpdatePathOffloadState(Path);
}

VOID
IppUpdatePathNotificationAtPassiveLevel(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_PATH Path
    )
/*++

Routine Description:

    This routine notifies all the network layer clients about a update in a
    path. This is always called at PASSIVE_LEVEL either from a worker thread or
    directly when we want to send a path update notification to network layer
    clients. 
    
Arguments:

    Compartment - Supplies the compartment in which the updated path exists. 
  
    Path - Supplies the path for which a notification needs to be sent to the
        network layer clients.

Return Value:

    None.

Caller LOCK:

    None.

Caller IRQL: == PASSIVE_LEVEL.

--*/ 
{
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PIP_INTERFACE Interface = Path->SourceAddress->Interface;
    PLIST_ENTRY Next, Head;
    PIP_CLIENT_CONTEXT Client;
    PIP_NEXT_HOP NextHop;
    NL_INDICATE_UPDATE_PATH Indicate;
    KIRQL OldIrql;

    PASSIVE_CODE();
    //
    // The heavy-weight WorkerLock protects this code against
    // multiple instantiations of itself without raising IRQL.
    //
    KeWaitForSingleObject(&Interface->WorkerLock,
                          Executive,
                          KernelMode,
                          FALSE,
                          NULL);

    //
    // Send update path notification to the transport layer.
    //
    Head = &Protocol->NlClientSet.Set;
    RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        //
        // The client is left in its set upon deletion and cleaned up with the
        // client set lock held.  Hence we can access Next without a reference.
        // Also, because new clients are only added at the head of the list,
        // we can unlock the list during our traversal
        // and know that the traversal will terminate properly.
        //
        Client = (PIP_CLIENT_CONTEXT)
            CONTAINING_RECORD(Next, IP_CLIENT_CONTEXT, Link);

        if ((Client->Npi.Dispatch->UpdatePathNotification == NULL) ||
            !IppReferenceNlClient(Client)) {
            //
            // We must be careful to not reference a deleted client.
            // c.f. IppInterfaceCleanup.
            //
            continue;
        }
        RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);

        //
        // Now that we have released all locks, we can provide the indication.
        //
        Indicate.ClientHandle = Client->Npi.ProviderHandle;
        Indicate.PathInfo.NextHop = NextHop = IppGetNextHopFromPath(Path);
        IppFillPathInformation(Path, NULL, &Indicate.PathInfo, NULL);
        Client->Npi.Dispatch->UpdatePathNotification(&Indicate);
       
        if (NextHop != NULL) {
            IppDereferenceNextHop(NextHop);
        }
 
        //
        // We dereference the client after acquiring the client set lock.
        // Since we hold a reference on the client, it must belong to its set.
        //
        RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
        IppDereferenceNlClient(Client);
    }
    RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);

    KeReleaseMutex(&Interface->WorkerLock, FALSE);
}

VOID
IppUpdatePathNotificationWorker(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    Worker function for calling IppUpdatePathNotificationAtPassiveLevel.

Arguments:

    DeviceObject - Unused.  Wish they passed the WorkItem instead.

    Context - Supplies an IP_WORK_QUEUE_ITEM struct.

Locks:

    The work item holds a reference on the path which we release on exit. 

Caller IRQL:

    Called at PASSIVE level from a work item.

--*/
{
    PIP_WORK_QUEUE_ITEM MyContext = Context;
    PIP_PATH Path = MyContext->Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoFreeWorkItem(MyContext->WorkQueueItem);
    ExFreePool(MyContext);

    IppUpdatePathNotificationAtPassiveLevel(
        IppGetCompartmentFromPath(Path),
        Path);

    IppDereferencePath(Path);
}

VOID
IppUpdatePathNotification(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_PATH Path
    )
/*++

Routine Description:

    This routine is called to notify network layer clients about path
    changes. If the thread is executing at PASSIVE_LEVEL, it calls
    IppUpdatePathNotificationAtPassiveLevel, otherwise it schedules a work item
    for completing the notification.
    
Arguments:

    Compartment - Supplies the compartment in which the updated path exists. 
  
    Path - Supplies the path for which a notification needs to be sent to the
        network layer clients.

Return Value:

    None.

Caller LOCK:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_WORK_QUEUE_ITEM Context;
    PIO_WORKITEM WorkItem;
    
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        IppUpdatePathNotificationAtPassiveLevel(Compartment, Path);
        return;
    }
    
    //
    // We're not at PASSIVE, so we need to queue a work item.
    //
    Context = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(IP_WORK_QUEUE_ITEM),
                                    IpGenericPoolTag);
    if (Context == NULL) {
        //
        // REVIEW: Should we do anything on failure?  The XP IPv6
        // stack doesn't.
        //
        return;
    }

    WorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (WorkItem == NULL) {
        ExFreePool(Context);
        return;
    }

    Context->WorkQueueItem = WorkItem;
    IppReferencePath(Path);
    Context->Context = Path;

    IoQueueWorkItem(WorkItem,
                    IppUpdatePathNotificationWorker,
                    DelayedWorkQueue,
                    Context);
}


NTSTATUS
IppParseAncillaryDataForSourceAndInterface(
    IN PIP_COMPARTMENT Compartment,
    IN SIZE_T BufferLength, 
    IN PUCHAR Buffer, 
    IN OUT NL_INTERFACE_ARG *NlInterface, 
    IN OUT NL_LOCAL_ADDRESS_ARG *NlSourceAddress, 
    OUT PIP_LOCAL_UNICAST_ADDRESS *UnspecifiedAddress
    )
/*++

Routine Description:

    This routine parses the ancillary data and returns the source address
    and/or interface in the IP_PKTINFO to the caller. 
    
Arguments:

    Compartment - Supplies the compartment. 

    BufferLength - Supplies the length of the ancillary data. 

    Buffer - Supplies the ancillary data. 

    NlInterface - Returns the interface index from the ancillary data. Remains 
        unmodified if the ancillary data does not contain the IP_PKTINFO
        option.  Also remains unmodified if the argument already specifies an
        interface. 

    NlSourceAddress - Returns the source address from the ancillary
        data. Remains unmodified if the ancillary data does not contain the
        IP_PKTINFO option.  Also remains unmodified if the argument already
        specifies an source address. 

    UnspecifiedSource - Returns the unspecified source in case the caller
        supplied the unspecified source in the ancillary data.  If a non-NULL
        value is returned the caller is supposed to remove the reference on the
        UnspecifiedSource.  

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCMSGHDR Object;
    PUCHAR Data;
    SIZE_T DataLength;
    ULONG InterfaceIndex;
    PUCHAR Address;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PIP_INTERFACE Interface;
    
    ASSERT(BufferLength > 0);

    *UnspecifiedAddress = NULL;
    
    while (BufferLength >= CMSG_SPACE(0)) {
        Object = (PCMSGHDR) Buffer;
        if (Object->cmsg_len < CMSG_SPACE(0)) {
            goto Done;
        }
        
        Data = WSA_CMSG_DATA(Object);
        DataLength = Object->cmsg_len - CMSG_SPACE(0);

        if (BufferLength < CMSG_SPACE(DataLength)) {
            goto Done;
        }
    
        Buffer += CMSG_SPACE(DataLength);
        BufferLength -= CMSG_SPACE(DataLength);
    
        if (Object->cmsg_type != IP_PKTINFO) {
            continue;
        }

        if (Object->cmsg_level != Protocol->Level) {
            Status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
    
        if ((Protocol->Level == IPPROTO_IPV6) && 
            (DataLength >= sizeof(IN6_PKTINFO))) {
            IN6_PKTINFO *pktinfo = (IN6_PKTINFO*)Data;
            
            InterfaceIndex = pktinfo->ipi6_ifindex;
            Address = (PUCHAR)&pktinfo->ipi6_addr;
        } else if ((Protocol->Level == IPPROTO_IP) &&
                   (DataLength >= sizeof(IN_PKTINFO))) {
            IN_PKTINFO *pktinfo = (IN_PKTINFO*)Data;
            
            InterfaceIndex = pktinfo->ipi_ifindex;
            Address = (PUCHAR)&pktinfo->ipi_addr;
        } else {
            Status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
        
        if ((NlInterface->Index == IFI_UNSPECIFIED) &&
            (NlInterface->Interface == NULL)) {
            NlInterface->Index = InterfaceIndex;
        }
        
        //
        // Change the source address if it was unspecified and the source
        // address in the ancillary data was specified.  
        //
        if ((NlSourceAddress->Address != NULL) ||
            (NlSourceAddress->LocalAddress != NULL) ||
            (Address == NULL)) {
            goto Done;
        }
        
        //
        // First get a handle on the interface so that we can compute the scope
        // ID of the address. 
        //
        if ((NlInterface->Index == IFI_UNSPECIFIED) &&
            (NlInterface->Interface == NULL)) {
            //
            // We need to find an interface if it is not specified. 
            //
            Interface = IppFindInterfaceByAddress(Compartment, Address);
        } else {
            Interface = IppGetInterface(Compartment, NlInterface);
        }
        if (Interface == NULL) {
            Status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
            
        NlSourceAddress->Address = Address;
        NlSourceAddress->ScopeId = IppGetExternalScopeId(Interface, Address);
        
        //
        // Treat the unspecified address specially.  If the client
        // specifies the unspecified address in the ancillary data, we
        // return the unspecified address to the callee.  Since the
        // unspecified address can only be specified through the ancillary
        // data, this is the best place to return the address pointer. 
        //
        if (Protocol->AddressType(Address) == NlatUnspecified) {
            Status = IppFindOrCreateLocalUnspecifiedAddress(
                Interface, 
                UnspecifiedAddress);
        }
        IppDereferenceInterface(Interface);
        
        //
        // We have parsed IP_PKTINFO completely. So we are done here. 
        //
        goto Done;
    }

Done:
    return Status;
}


NTSTATUS
IppJoinPath(
    IN PIP_PROTOCOL Protocol, 
    IN PNL_REQUEST_JOIN_PATH Args
    )
/*++

Routine Description:

    Create a path entry (i.e. a route with both a destination and a source
    address) and return a referenced pointer to the caller.

Arguments:

    Protocol - Supplies the protocol. 

    Args - Supplies a pointer to an arguments structure containing:

    NlCompartment - Supplies information identifying a compartment.

    RemoteAddress - Supplies the address of a remote correspondent, typically
        the destination address of the path.

    DestinationAddress - If present, supplies a group address of which
        the remote address is a member.

    NlLocalAddress - If present, supplies information identifying
        the preferred source address.  Receives information identifying
        the actual source address chosen.

    NlInterface - If present, supplies a handle to the interface which
        must be used.

    UlSecurityInformation - If present, supplies a blob of opaque information
        to be passed to the NL security system.

    UlSecurityInformationSize - Supplies the size in bytes of the blob.

    NlSecurityContext - Receives a security handle that can be used with
        subsequent send operations.

    Path - If non-NULL, receives a pointer to a path to reference.
        Returns a referenced pointer to a path that can be used with 
        subsequent send operations.

Return Value:

    Returns the status of the operation.
    The return value must be an NTSTATUS code which matches a TDI status code.

Locks:

    Caller is responsible for calling the LeavePath function, if we return
    success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PATH Path = NULL;
    SCOPE_ID RemoteScopeId;
    NTSTATUS Status;
    PIP_COMPARTMENT ReferencedCompartment = NULL, Compartment;
    PIP_INTERFACE Interface = NULL, ConstrainIf;
    PIP_LOCAL_ADDRESS SourceAddress = NULL, PreferredSourceAddress;
    ULONG IpsecHeaderSize;
    KIRQL OldIrql;
    
    if (Args->Path != NULL) {
        IppReferencePath((PIP_PATH)Args->Path);
        return STATUS_SUCCESS;
    }

    if (Args->DestinationAddress != NULL) {
        //
        // TODO: Remove the unused DestinationAddress field.
        //
        return STATUS_INVALID_PARAMETER;
    }

    PreferredSourceAddress = 
        (PIP_LOCAL_ADDRESS)Args->NlLocalAddress.LocalAddress;
    if (PreferredSourceAddress != NULL) {
        ConstrainIf = PreferredSourceAddress->Interface;
        Compartment = ConstrainIf->Compartment;
    } else {
        Compartment = ReferencedCompartment = 
            IppGetCompartment(Protocol, &Args->NlCompartment);
        if (Compartment == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        ConstrainIf = (PIP_INTERFACE) Args->NlInterface.Interface;
        
        //
        // If the user did not specify an interface and/or a preferred source 
        // address and there is ancillary data, try to get the interface and/or
        // source address from the anciliary data. 
        //
        if ((Args->AncillaryDataLength > 0) &&
            (((Args->NlInterface.Index == IFI_UNSPECIFIED) &&
              (ConstrainIf == NULL)) ||
             ((Args->NlLocalAddress.Address == NULL) &&
              (PreferredSourceAddress == NULL)))) {
            Status =
                IppParseAncillaryDataForSourceAndInterface(
                    Compartment, 
                    Args->AncillaryDataLength, 
                    Args->AncillaryData, 
                    &Args->NlInterface,
                    &Args->NlLocalAddress, 
                    (PIP_LOCAL_UNICAST_ADDRESS *)&SourceAddress);
            if (!NT_SUCCESS(Status)) {
                goto Done;
            }
            PreferredSourceAddress = SourceAddress;
        }
        
        if ((Args->NlSessionState != NULL) && 
            (ConstrainIf == NULL) && 
            (Args->NlInterface.Index == IFI_UNSPECIFIED)) {
            PIP_SESSION_STATE State = Args->NlSessionState;
            
            //
            // We'll first see (outside of a lock) whether we need to
            // worry about an interface constraint.  If so, we'll take 
            // a lock and reference the specified interface so we can
            // safely use it.
            //
            if (Compartment->Protocol->AddressType(Args->RemoteAddress) == 
                NlatMulticast) {
                if (State->MulticastInterface != NULL) {
                    KeAcquireSpinLock(&State->SpinLock, &OldIrql);
                    if ((State->MulticastInterface != NULL) &&
                        (!State->MulticastInterface->DisallowMulticastRoutes)) {
                        ConstrainIf = Interface = State->MulticastInterface;
                        IppReferenceInterface(Interface);
                    }
                    KeReleaseSpinLock(&State->SpinLock, OldIrql);
                }
            } else {
                if (State->UnicastInterface != NULL) {
                    KeAcquireSpinLock(&State->SpinLock, &OldIrql);
                    if (State->UnicastInterface != NULL) {
                        ConstrainIf = Interface = State->UnicastInterface;
                        IppReferenceInterface(Interface);
                    }
                    KeReleaseSpinLock(&State->SpinLock, OldIrql);
                }
            }
        }
    
        //
        // Find the interface on which to join, if constrained.
        // Note that the MULTICAST_IF session option doesn't affect this. 
        //
        if ((ConstrainIf == NULL) && 
            (Args->NlInterface.Index != IFI_UNSPECIFIED)) {
            ConstrainIf = Interface = 
                IppGetInterface(Compartment, &Args->NlInterface);
            if (ConstrainIf == NULL) {
                Status = STATUS_INVALID_PARAMETER;
                goto Done;
            }
        }
    
        if ((PreferredSourceAddress == NULL) &&
            (Args->NlLocalAddress.Address != NULL)) {
            PreferredSourceAddress = SourceAddress = 
                IppFindLocalAddress(
                    Compartment,
                    &Args->NlLocalAddress);
            if (PreferredSourceAddress == NULL) {
                Status = STATUS_INVALID_ADDRESS_COMPONENT;
                goto Done;
            }
        }
    }
    
    RemoteScopeId = Args->RemoteScopeId;
    if (!IppCanonicalizeScopeId(Compartment, 
                                Args->RemoteAddress,
                                &RemoteScopeId)) {
        Status = STATUS_INVALID_ADDRESS_COMPONENT;
        goto Done;
    }
    
    //
    // Search destination cache for a matching entry, constrained
    //    by interface index and/or local address if requested
    // If not found,
    //    do a longest match route lookup to select currnexthop,srcaddr,if
    //    create a destination cache entry (aka path)
    // Refcount the destination cache entry
    //
    Status =
        IppRouteToDestination(
            Compartment,
            Args->RemoteAddress,
            RemoteScopeId,
            ConstrainIf,
            PreferredSourceAddress,
            &Path);
    
Done:
    if (Interface != NULL) {
        IppDereferenceInterface(ConstrainIf);
    }

    if (SourceAddress != NULL) {
        IppDereferenceLocalAddress(SourceAddress);
    }

    if (ReferencedCompartment != NULL) {
        IppDereferenceCompartment(ReferencedCompartment);
    }

    //
    // Return the handle to the caller.
    //
    if (NT_SUCCESS(Status)) {
        Args->Path = (PNL_PATH)Path;
        Args->NlSecurityContext = NULL;
        Args->ControlBackfill =
            Protocol->Characteristics->DefaultRequestControlBackfill;

        IpsecHeaderSize = IpSecGetOverheadEstimate();

        Args->DataBackfill = Protocol->HeaderSize + IpsecHeaderSize +
            Path->SourceAddress->Interface->FlBackfill;
    }
    
    return Status;
}


NTSTATUS
NTAPI
IpNlpJoinPath(
    IN HANDLE ProviderHandle,
    IN PNL_REQUEST_JOIN_PATH Args
    )
{
    PIP_CLIENT_CONTEXT Client = IppCast(ProviderHandle, IP_CLIENT_CONTEXT);
    
    return IppJoinPath(Client->Protocol, Args);
}

NTSTATUS
IpNlpSetPathBandwidthInfo(
    IN PNL_REQUEST_SET_PATH_BANDWIDTH_INFO Args,
    OUT PIP_PATH_BANDWIDTH_DIRECTION IpBandwidth
    )
/*++

Routine Description:

    Updates the bandwidth estimation statistics for a given path based on a
    sample provided by a client.
    
Arguments:

    Args - Supplies the bandwidth sample statistics to be applied to the path.

    IpBandwidth - The IP_PATH_BANDWIDTH_DIRECTION structure to be updated based
        on Args.

Return Value:

    Returns ERROR_NOT_SUPPORTED if the specified IpBandwidth pointer is NULL.
    Otherwise, returns STATUS_SUCCESS.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    LONG64 InstabilityDeviation;
    
    if (IpBandwidth == NULL) {

        //
        // The specified type of bandwidth estimation has been disabled on this
        // path. Return an appropriate status to indicate this fact to the
        // caller.
        //
        return STATUS_NOT_SUPPORTED;
    }

    //
    // If the transport layer is indicating that bandwidth estimation is
    // unavailable, we mark our bandwidth block accordingly but do not update
    // any of the other statistics.  The EstimateUnavailable field will be
    // interpreted only when these estimates are queried.
    //
    if (Args->BandwidthSample == TCP_BW_ESTIMATION_UNAVAILABLE) {
        IpBandwidth->EstimateUnavailable = TRUE;
        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE,
            "NL: TCP indicated BW unavailable.  Path BW=%I64ubps\n",
            IpBandwidth->Bandwidth);
        return STATUS_SUCCESS;
    }

    //
    // Smooth the instability metric with an exponentially-weighted
    // moving average with a gain of 1/8.  This instability is always updated,
    // regardless of the bandwidth value.
    //
    InstabilityDeviation =
        Args->InstabilitySample - IpBandwidth->Instability;                
    IpBandwidth->Instability += (InstabilityDeviation >> 3);

    //
    // Maintain the maximum bandwidth, only updating the most recent
    // sample time when a new maximum occurs or the old maximum becomes too old.
    //
    if ((IP_BANDWIDTH_INFO_MAX_AGE < IppTickCount - IpBandwidth->LastSample) ||
        (IpBandwidth->Bandwidth <= Args->BandwidthSample)) {
        IpBandwidth->Bandwidth = Args->BandwidthSample;
        IpBandwidth->BandwidthPeaked = Args->BandwidthPeaked;
        IpBandwidth->EstimateUnavailable = FALSE;
        IpBandwidth->LastSample = IppTickCount;
        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE,
            "NL: Path BW updated.  BW=%I64ubps, Var=%I64ubps, Peaked=%u, "
            "EstAvailable=%u\n", IpBandwidth->Bandwidth,
            IpBandwidth->Instability,
            IpBandwidth->BandwidthPeaked ? 1 : 0,
            IpBandwidth->EstimateUnavailable ? 0 : 1);
    } else {
        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE,
            "NL: Path BW not updated (not max). BW=%I64ubps, Var=%I64ubps, "
            "Peaked=%u, EstAvailable=%u\n", IpBandwidth->Bandwidth,
            IpBandwidth->Instability,
            IpBandwidth->BandwidthPeaked ? 1 : 0,
            IpBandwidth->EstimateUnavailable ? 0 : 1);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IpNlpSetPathInfo(
    IN NL_REQUEST_SET_PATH_INFO *Args
    )
/*++

Routine Description:

    Updates information for a given path based on upper-layer protocol
    knowledge.

Arguments:

    Path - Supplies a pointer to a path for which to set information.

    Flags - Supplies flags indicating which of the remaining fields are valid:
        NL_SET_PATH_FLAG_RTT indicates RttSample is valid.
        NL_SET_PATH_FLAG_BANDWIDTH_OUT indicates BandwidthOut is valid.
        NL_SET_PATH_FLAG_BANDWIDTH_IN indicates BandwidthIn is valid.

    RttSample - Supplies a sample of the round-trip time.  

    BandwidthOut - Supplies a set of information about a client's estimate
        of the end-to-end outbound bandwidth achievable along this path.

    BandwidthIn - Supplies a set of information about a client's estimate
        of the end-to-end inbound bandwidth achievable along this path.

    SymmetricReachability - If TRUE, indicates that symmetric reachability 
        is confirmed.  If FALSE, indicates that symmetric reachability is 
        in doubt.

    RateLimiting - Supplies the new value for the path's RateLimiting flag.
        On output, contains the original value of the flag.

Return Value:

    Returns the status of the operation.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PROTOCOL Protocol;
    ULONG CurrentTick;
    PIP_COMPARTMENT Compartment;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_PATH Path = IppCast(Args->Path, IP_PATH);

    Compartment = IppGetCompartmentFromPath(Path);
    Protocol = Compartment->Protocol;
    CurrentTick = IppTickCount;

    if (Args->Flags & NL_SET_PATH_FLAG_RTT) {
        ULONG Sample = Args->RttSample;

        if (IppIsTooOld(Path->RttMean, 
                        Path->RttDeviation, 
                        Path->RttLastSample,
                        CurrentTick)) {
            Path->RttMean = Sample;
            Path->RttDeviation = Sample / 2;
        } else {
            LONG Deviation = Sample - Path->RttMean;

            //
            // Use a gain of 1/8, per "TCP/IP Illustrated, Vol. 1" page 300.
            //
            Path->RttMean += (Deviation >> 3);

            //
            // Use a gain of 1/4, per "TCP/IP Illustrated, Vol. 1" page 300.
            //
            if (Deviation < 0) {
                Deviation = -Deviation;
            }
            Path->RttDeviation += 
                ((Deviation - Path->RttDeviation) >> 2);
        }

        Path->RttLastSample = CurrentTick;
    }

    if (Args->Flags & NL_SET_PATH_FLAG_BANDWIDTH_OUT) {
        NTSTATUS TempStatus;
        KIRQL OldIrql;
        
        KeAcquireSpinLock(&Path->Bandwidth.SpinLock, &OldIrql);
        TempStatus =
            IpNlpSetPathBandwidthInfo(&Args->BandwidthOut, Path->Bandwidth.Out);
        if (NT_SUCCESS(Status)) {
            Status = TempStatus;
        }
        KeReleaseSpinLock(&Path->Bandwidth.SpinLock, OldIrql);

        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
            "PATH: %p: New outbound bandwidth stats recorded.\n", Path);
    }

    if (Args->Flags & NL_SET_PATH_FLAG_BANDWIDTH_IN) {
        NTSTATUS TempStatus;
        KIRQL OldIrql;
        
        KeAcquireSpinLock(&Path->Bandwidth.SpinLock, &OldIrql);
        TempStatus =
            IpNlpSetPathBandwidthInfo(&Args->BandwidthIn, Path->Bandwidth.In);
        if (NT_SUCCESS(Status)) {
            Status = TempStatus;
        }
        KeReleaseSpinLock(&Path->Bandwidth.SpinLock, OldIrql);

        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
            "PATH: %p: New inbound bandwidth stats recorded.\n", Path);
    }


    if (Args->Flags & NL_SET_PATH_NO_BH_CONFIRMATION) {
        
        KLOCK_QUEUE_HANDLE LockHandle;
        
        ASSERT(Args->NextHop != NULL);
        RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
        if (Args->NextHop == Path->CurrentNextHop) {
            Path->Flags.BlackHoleNotLikely = TRUE;
        }
        RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);    
    }

    if (Args->Flags & NL_SET_PATH_CONNECTION_FAILED) {
        KLOCK_QUEUE_HANDLE LockHandle;
        
        ASSERT(Args->NextHop != NULL);
        RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
        if (Args->NextHop == Path->CurrentNextHop) {
            Path->Flags.ConnectionFailed = TRUE;
        }
        RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle); 
    }
    return Status;
}


VOID
NTAPI
IpNlpConfirmForwardReachability(
    IN CONST NL_PATH *NlPath, 
    IN CONST NL_NEXT_HOP *NlNextHop
    )
/*++

Routine Description:
    
    This routine is called by the transport layer to confirm forward
    reachability for the path.  This confirms that the destination is reachable
    using the path and also that the neighbor is reachable. 

Arguments:

    NlPath - Supplies the path.

    NlNextHop - Supplies the next hop being used by TCP.

Return Value:

    None.

Caller LOCK: None.
Caller IRQL: < DISPATCH_LEVEL.

--*/ 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_PATH Path = (PIP_PATH) NlPath;
    PIP_NEIGHBOR Neighbor = (PIP_NEIGHBOR) NlNextHop;
    PIP_UNICAST_ROUTE Route;
    IP_ROUTE_STATE State;
    PIP_COMPARTMENT Compartment = IppGetCompartmentFromPath(Path);
    
    //
    // Confirm reachability of the neighbor. 
    //
    ASSERT(Neighbor->Signature == IP_NEIGHBOR_SIGNATURE);

    (VOID) IppConfirmNeighborReachability(Neighbor, 0);

    //
    // Confirm reachability for the path.  For this first acquire the current
    // next hop spin lock of the path.
    //
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

    //
    // If the next hop being used by the transport layer is different from the
    // next hop in the path, then ignore the notification.  This can happen if
    // the next hop in the path has already been updated.
    //
    if (NlNextHop != Path->CurrentNextHop) {
        goto Done;
    }

    //
    // Update the time and type of the last notification from the transport
    // layer.  
    //
    Path->LastConfirmation = Path->LastReachable = IppTickCount;
    Path->IsReachable = TRUE;

    //
    // If the connection failed flag is set on this path, clear it now.
    //
    if (Path->Flags.ConnectionFailed == TRUE) {
        Path->Flags.ConnectionFailed = FALSE;
    }
    //
    // If the route that the path is using is in probe state, then update its
    // state to alive. 
    //
    Route = Path->Route;
    if (Route != NULL) {
        State = IppGetRouteState(Route); 
        if (State == RouteProbe) {
            IppSetRouteState(Route, RouteAlive);
            IppInvalidateDestinationCache(Compartment);
        }
    }

Done:
    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
}


VOID
NTAPI
IpNlpSuspectNeighborReachability(
    IN CONST NL_NEXT_HOP *NlNextHop
    )
/*++

Routine Description:
    
    This routine is called by the transport layer when it suspects neighbor
    reachability.  This is done on the first retransimission timeout.

Arguments:

    NlNextHop - Supplies the next hop being used by TCP.

Return Value:

    None.

Caller LOCK: None.
Caller IRQL: < DISPATCH_LEVEL.

--*/ 
{
    PIP_NEIGHBOR Neighbor = (PIP_NEIGHBOR) NlNextHop;

    ASSERT(Neighbor->Signature == IP_NEIGHBOR_SIGNATURE);

    IppSuspectNeighborReachability(Neighbor);
}

VOID
NTAPI
IpNlpSuspectPathReachability(
    IN CONST NL_PATH *NlPath, 
    IN CONST NL_NEXT_HOP *NlNextHop
    )
/*++

Routine Description:

    This routine is called by the transport layer when it suspects that the
    router is reachable but the routers connectivity to the rest of the world
    is broken.  On the first retransmission timeout, TCP calls
    IpNlpSuspectNeighborReachability.  This should trigger unreachability
    detection on the neighbor.  If the neighbor is dead, the path should shift
    to a new router.  However, if there are more retransmission timeouts, then
    it indicates that the problem is not with the first hop router.  In that
    case, IpNlpSuspectPathReachability is called by TL.
    
Arguments:

    NlPath - Supplies the path.

    NlNextHop - Supplies the next hop being used by TCP.

Return Value:

    None.

Caller LOCK: None.
Caller IRQL: < DISPATCH_LEVEL.

--*/ 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG TotalPaths;
    PIP_PATH Path = (PIP_PATH) NlPath;
    PIP_UNICAST_ROUTE OldRoute, NewRoute, BestRoute;
    PIP_COMPARTMENT Compartment = IppGetCompartmentFromPath(Path);
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG TickCount = IppTickCount;

    //
    // We are potentially going to update the next hop in the path.  So acquire
    // the path update lock.  The lock also protects other fields like
    // the number of times IpNlpSuspectPathReachability has been called for
    // this path. 
    //
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

    //
    // Move the LastConfirmation to a value in the past, to force a call
    // down to IpNlpConfirmForwardReachability the next time the transport 
    // layer wants to confirm path reachability.
    //

    Path->LastConfirmation = IppTickCount - 1;

    //
    // If the next hop being used by the transport layer is different from the
    // next hop in the path, then ignore the notification.  This can happen if
    // the next hop in the path has already been updated.
    //
    if (NlNextHop != Path->CurrentNextHop) {
        goto Done;
    }

    //
    // Ignore if we don't have the route or the route is loopback or on-link. 
    //
    OldRoute = Path->Route;
    if ((OldRoute == NULL) ||
        OldRoute->Flags.Loopback ||
        IppIsOnLinkRoute(OldRoute)) {
        goto Done;
    }

    //
    // Decide if we need to start using a different gateway for this path.  The
    // gateway is changed if two unreachable notifications were received in
    // quick succession. 
    //
    if ((Path->ReferenceCount > 2) &&
        (Path->IsReachable ||
         ((TickCount - Path->LastUnreachable) >
          Protocol->PathUnreachableTimeout))) {
        //
        // Not yet time to update the gateway being used by the path.
        // Update the time of last notification. 
        //
        Path->LastUnreachable = TickCount;
        Path->IsReachable = FALSE;
        goto Done;
    } else {
        Path->LastUnreachable = TickCount;
        Path->IsReachable = FALSE;
    }

    NewRoute = IppFindNextBestRouteAtDpc(OldRoute, &BestRoute, &TotalPaths);
    if (NewRoute == NULL) {
        goto Done;
    }

    //
    // Below, we reset the route used by the path,
    // hence we reset any unreachability information associated with the path.
    //
    Path->LastUnreachable = TickCount - Protocol->PathUnreachableTimeout - 1;
    Path->IsReachable = TRUE;
    Path->Flags.BlackHoleNotLikely = FALSE;
    
    if (NewRoute != OldRoute) {
        if ((BestRoute == OldRoute) &&
            ((OldRoute->PathCount - 1) * 100 / TotalPaths <= 25)) {
            //
            // The OldRoute is currently the best route.  However, 75% of the
            // paths have already moved away from it, so we mark it dead.
            // Now, if the next best route (NewRoute) is dead as well it would
            // imply that all routes are marked dead.  If so, we mark all of
            // them alive since the dead flag does not help us choose one over
            // the other.
            //
            if (NewRoute->State != RouteAlive) {
                IppSetAllRouteState(OldRoute, RouteAlive, NULL);
            } else {
                IppSetRouteState(OldRoute, RouteDead);
            }

            //
            // Invalidate the destination cache.
            // Path validation will automatically switch routes.
            //
            IppInvalidateDestinationCache(OldRoute->Interface->Compartment);
        } else {
            //
            // Revalidate the path, ignoring the old route during lookup.
            //
            OldRoute->Flags.Ignore = TRUE;

            IppInvalidatePath(Path);
            IppValidatePathUnderLock(Path);

            OldRoute->Flags.Ignore = FALSE;
        }
    }
    IppDereferenceRoute((PIP_ROUTE) NewRoute);

Done:
    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
}


BOOLEAN
IppIsPathMtuInvalid(
    IN CONST NL_PATH *NlPath
    )
/*++

Routine Description:

    Tests whether a path MTU may have changed for the worse.  That is,
    tests whether the path requires revalidating before a send will succeed.

Arguments:

    NlPath - Supplies the path to test.

Return Value:

    Returns TRUE if the path requires revalidation, FALSE if not.

--*/
{
    PIP_PATH Path = IppCast(NlPath, IP_PATH);

    //
    // A non-matching bucket epoch can't change the MTU, but a non-matching
    // path set epoch.  We also don't check for MTU increases, only
    // an invalidation which may decrease the MTU and thus cause packet
    // loss.
    //
    return (IppGetCompartmentFromPath(Path)->RoutingEpoch != Path->RoutingEpoch);
}

NTSTATUS
NTAPI
IpNlpQueryPathInfomation(
    IN OUT PNL_REQUEST_QUERY_PATH_INFORMATION Args
    )
/*++

Routine Description:

    Retrieve extra information associated with a path.  This is an expensive
    operation since it retrieves the next hop from the path.  TCP uses a
    private API to determine when this API should be called. 
    TODO: Optimize UDP so this is not called on every packet send.

    NL maintains a global "routing epoch". Each path maintains a
    "routing epoch" and a "path epoch". Every TCB maintains a
    "path epoch". The "routing epoch" is used for synchronizing
    paths with the routing state (it gets updated when the route table,
    neighbor cache, or address list changes). The "path epoch" is meant to 
    synchronize the cached state in the TCB with the path (it gets changed when
    the next hop, MTU or any other path characteristic that TCP is interested
    in changes).  TCP calls this routine only when the path is out of sync with
    the global routing state or the TCB cached state is out of sync with the
    path state. 

Arguments:

    Args - Supplies the path to query information about.  Returns information
        about the path.

Return Value:

    Returns the status of the operation.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    LONG PathEpoch;
    PIP_PATH Path;
    PIP_NEXT_HOP NextHop;
    PNL_PATH_INFO PathInformation = Args->PathInformation;
    
    Path = IppCast(Args->NlPath, IP_PATH);    
    
    //
    // Synchronize the global routing state with the path state.  This might
    // cause the next hop in the path to get updated. 
    //
    IppValidatePath(Path);

    //
    // Synchronize the path information with the cached information that the NL
    // client has. 
    //
    PathEpoch = Path->PathEpoch;
    if (PathInformation->NextHop != NULL) {
        IppDereferenceNextHop((PIP_NEXT_HOP) PathInformation->NextHop);
    }
    
    NextHop = IppGetNextHopFromPath(Path);
    if ((NextHop != NULL) && IppIsNextHopNeighbor(NextHop)) {
        PIP_NEIGHBOR Neighbor = (PIP_NEIGHBOR) NextHop;
            
        //
        // Process a PMTU timeout so the MTU is refreshed before access.
        // Only update the PMTU for non-loopback paths.
        //
        if (Neighbor->SubInterface->OperationalStatus == IfOperStatusUp) {
            NextHop->Interface->Compartment->Protocol->
                PathMtuDiscoveryTimeout(
                    Path,
                    Path->SourceAddress->Interface,
                    Neighbor->SubInterface);
        } else {
            IppDereferenceNextHop(NextHop);
            NextHop = NULL;
        }
    }
    PathInformation->NextHop = NextHop;
    IppFillPathInformation(
        Path,
        (PIP_SESSION_STATE) Args->NlSessionState,
        PathInformation, 
        &Args->IpOptionLength);
    PathInformation->PathEpoch = PathEpoch;
    
    return STATUS_SUCCESS;
}

BOOLEAN
IppDetectGatewayReachability(
    IN PIP_INTERFACE Interface
    ) 
/*++

Routine Description:

    This function probes all the default gateways on a given interface. 
    Typically this is invoked after an interface operational status change to 
    determine if the network has changed.

Arguments:

    Interface - Supplies the interface that had its operational status change.
    
Return Value:

    Returns TRUE if any of the gateways responded. FALSE ow.

Caller IRQL:

    PASSIVE.
    
--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIPR_LOCKED_SET RouteSet = &Interface->Compartment->RouteSet;
    PIPR_LINK Link;
    UCHAR Key[ROUTE_KEY_STORAGE_SIZE];
    USHORT KeyLength = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_UNICAST_ROUTE Route = NULL, NextRoute;
    PIP_NEIGHBOR *NeighborList = NULL, Neighbor;
    ULONG NumGateways = 0, i = 0, trynum;
    BOOLEAN Reachable = TRUE;
    KIRQL OldIrql;
    LARGE_INTEGER Time;    

    PASSIVE_CODE();
    //
    // Make route key for the default route.
    //
    Protocol->MakeRouteKey(
        (UCHAR *) &in6addr_loopback, 
        0,
        NULL, 
        0,
        Key, 
        &KeyLength);

    RtlAcquireScalableReadLock(&RouteSet->Lock, &OldIrql);

    Status = PtGetExactMatch(RouteSet->Tree, Key, KeyLength, NULL, &Link);
    
    if (NT_SUCCESS(Status)) {
        Route = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(Link, IP_ROUTE, Link);
        
        //
        // Loop through all routes for the same prefix.
        //
        do {
            NextRoute = (PIP_UNICAST_ROUTE)
                CONTAINING_RECORD(Route->RouteLink.Flink, IP_ROUTE, RouteLink);

            if (RtlEqualMemory(
                    &Interface->Luid, 
                    &Route->Interface->Luid, 
                    sizeof(IF_LUID))) {
                //
                // This is default route.
                //
                if (!IppIsOnLinkRoute(Route) && !Route->Flags.Loopback) {
                    NumGateways++;                
                }
            }
            
            Route = NextRoute;
        } while (Link != &Route->Link);        
    }

    if (NumGateways == 0) {
        RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);
        goto ExitSilentlyOnFailure;
    }
    
    NeighborList =
        ExAllocatePoolWithTagPriority(
            NonPagedPool,
            NumGateways * (sizeof(PIP_NEIGHBOR)),
            IpGenericPoolTag,
            LowPoolPriority);

    if (NeighborList == NULL) {
        //
        // Fail silently.
        //
        RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);
        goto ExitSilentlyOnFailure;
    }
    
    //
    // Loop again to get list of gateways.
    //
    Status = PtGetExactMatch(RouteSet->Tree, Key, KeyLength, NULL, &Link);
    i = 0;

    //
    // As RouteSet lock is held, it should always succeed.
    //    
    if (!NT_SUCCESS(Status)) {
        ASSERT(FALSE);
        RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);
        goto ExitSilentlyOnFailure;        
    }

    Route = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(Link, IP_ROUTE, Link);
    
    //
    // Loop through all routes for the same prefix.
    //
    do {
        NextRoute = (PIP_UNICAST_ROUTE)
            CONTAINING_RECORD(Route->RouteLink.Flink, IP_ROUTE, RouteLink);

        if (RtlEqualMemory(
                &Interface->Luid, 
                &Route->Interface->Luid, 
                sizeof(IF_LUID))) {
            //
            // This is default route.
            //
            if (!IppIsOnLinkRoute(Route) && !Route->Flags.Loopback) {
                ASSERT(i < NumGateways);
                NeighborList[i] = Route->CurrentNextHop;
                IppReferenceNeighbor(NeighborList[i]);
                i++;
            }
        }
        
        Route = NextRoute;
    } while (Link != &Route->Link);        

    ASSERT(i == NumGateways);
    RtlReleaseScalableReadLock(&RouteSet->Lock, OldIrql);

    //
    // ASSERT so we catch callers attempting this at elevated IRQLs.
    //
    PASSIVE_CODE();
        
    //
    // Resolve the list of neighbors. We need to determine failure, so send two 
    // ND solicitations 0.5s apart.
    // 
    Reachable = FALSE;

    //
    // Reset the neighbor cache entries for the gateways.
    // As this is invoked only on media reconnect, the neighbors should already 
    // have been reset.
    //

    //
    // NOTE: Currently ResolveNeighbor will rate limit the solicitation 
    // to 1 per second. Need to call SendSolicitation here.
    //
    // Force sending of a ND solicitation.
    //
    for (i = 0; i < NumGateways; i++) {
        IppSendNeighborProbe(NeighborList[i]);
    }
        
    for (trynum = 0; trynum < 2; trynum++) {        
        //
        // Wait for the solicitation to be processed.
        //
        //
        // Sleep 500ms before checking status. 
        //
        Time.QuadPart = -(500 * 10000);

        KeDelayExecutionThread(KernelMode, FALSE, &Time); 
        
        for (i = 0; i < NumGateways; i++) {
            Neighbor = NeighborList[i];
            
            //
            // If the mapping has been updated, we are done.
            //
            if (IppResolveNeighbor(Neighbor, NULL)) {
                Reachable = TRUE;
                goto Done;
            }
        }               
    }

Done:  
    for (i = 0; i < NumGateways; i++) {
        IppDereferenceNeighbor(NeighborList[i]);
    }
    

ExitSilentlyOnFailure:
    if (NeighborList != NULL) {
        ExFreePool(NeighborList);
    }
    return Reachable;
}

NTSTATUS
IppValidateSetAllRouteParameters(
    IN NSI_SET_ACTION SetAction,
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength, 
    CONST UCHAR *SourcePrefix, 
    IN UINT8 SourcePrefixLength, 
    IN NL_ROUTE_ORIGIN Origin,
    IN CONST NL_ROUTE_RW *RouteRw OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL,
    IN PIP_LOCAL_ADDRESS LocalAddress OPTIONAL, 
    OUT PVOID *ProviderTransactionContext
    )
/*++

Routine Description:

    This function validates an operation on the route table. 

Arguments:

    SetAction - Supplies the action to be performed for the route
        (e.g. add/delete etc). 

    Interface - Supplies a pointer to the interface.  
        TODO: Support "remote" next-hop routes where Interface is NULL,
        since the route is not tied to any specific interface.

    SubInterface - Supplies a pointer to the sub-interface. 

    DestinationPrefix - Supplies the destination prefix.

    DestinationPrefixLength - Supplies the destination prefix length.

    SourcePrefix - Supplies the source prefix.

    SourcePrefixLength - Supplies the source prefix length.

    Origin - Supplies the route origin value.

    RouteRw - Supplies the initial read-write route information, including:

        ValidLifetime - Supplies the valid lifetime.  Note that the
            ValidLifetime may be INFINITE_LIFETIME, whereas Neighbor Discovery
            does not allow an infinite value for router lifetimes on the wire.

    NextHopAddress - Supplies the next-hop address.  A local unicast address,
        or the unspecified address is treated as a NULL next-hop address.

    LocalAddress - Supplies the local destination address for the route. 

    Note: The type of route is determined as follows...
        if (NextHopAddress != NULL) { Destination = Offlink }
        else if (LocalAddress != NULL) { Destination = Loopback }
        else { Destination = OnLink }
    
    ProviderTransactionContext - Returns the transaction context. 

Return Value:

    If the function is successfully completed, then a success status is
    returned. Otherwise, a failure status is returned.

Locks:

    Assumes caller holds a reference on the compartment.
    Assumes caller holds a reference on the subinterface, if non-NULL.
    Assumes caller holds at least a read lock on the interface.
    Assumes caller holds a write lock on the route set.

Caller IRQL:

    Must be called at DISPATCH level, since a lock is held.

--*/
{
    PIP_UNICAST_ROUTE Route = NULL, FirstRoute = NULL;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    BOOLEAN IsLoopback;
    NL_ADDRESS_TYPE DestinationType, NextHopType;
    UCHAR Key[ROUTE_KEY_STORAGE_SIZE];
    USHORT KeyLength;
    PIPR_LINK Link;
    PIP_NEIGHBOR Neighbor = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Both NextHopAddress and LocalAddress should not be specified.
    //
    ASSERT((NextHopAddress == NULL) || (LocalAddress == NULL));
    
    ASSERT_ANY_LOCK_HELD(&Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Compartment->RouteSet.Lock);

    //
    // We cannot add a route on an interface that does not support routes. 
    //
    DestinationType = Protocol->AddressType(DestinationPrefix);
    if (((DestinationType == NlatUnicast) &&
         Interface->DisallowUnicastRoutes) ||
        ((DestinationType == NlatMulticast) &&
         Interface->DisallowMulticastRoutes)) {
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Validate the RW parameters. 
    //
    if (RouteRw != NULL) {
        if (RouteRw->PreferredLifetime > RouteRw->ValidLifetime) {
            return STATUS_INVALID_PARAMETER;
        }
        
        if (RouteRw->SitePrefixLength != (UCHAR) -1) {
            if ((RouteRw->SitePrefixLength > DestinationPrefixLength) ||
                (RouteRw->SitePrefixLength >
                 (Compartment->Protocol->Characteristics->AddressBytes * 8))) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        if ((RouteRw->Metric != (ULONG) -1) &&
            (RouteRw->Metric > NL_MAX_METRIC_COMPONENT)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    
    //
    // Validate the NextHopAddress.
    //
    if (NextHopAddress != NULL) {
        PIP_LOCAL_ADDRESS LocalInterfaceAddress;
        
        NextHopType =
            IppUpdateAddressTypeUnderLock(
                Interface,
                NextHopAddress,
                Protocol->AddressType(NextHopAddress));

        //
        // REVIEW - Sanity check that the specified next-hop address
        // is reasonably on-link to the specified interface?
        // Perhaps only allow link-local next-hop addresses,
        // and other next-hops would imply recursive routing lookups?
        // However, not all interfaces (e.g. 6to4) have link-local addresses.
        // So the best we can do is attempt to match an onlink prefix.
        //
        if (IppIsInvalidSourceAddress(Protocol, NextHopAddress)) {
            return STATUS_INVALID_PARAMETER;
        }

        if ((IS_LOOPBACK_INTERFACE(Interface)) &&
            INET_IS_ADDR_LOOPBACK(Protocol->Family, NextHopAddress)) {
            return STATUS_INVALID_PARAMETER;
        }

        LocalInterfaceAddress = 
            IppFindAddressOnInterfaceUnderLock(
                Interface, 
                NextHopAddress);
        if (LocalInterfaceAddress != NULL) {
            //
            // If the NextHop is local, treat it as a NULL NextHopAddress.
            //
            NextHopAddress = NULL;
            IppDereferenceLocalAddress(LocalInterfaceAddress);
        } else if (NextHopType == NlatUnspecified) {
            //
            // If the NextHop is unspecied, treat it as a NULL NextHopAddress.
            //
            NextHopAddress = NULL;
        }

        //
        // If NextHopAddress is a neighbor, get the neighbor entry.
        //
        if (NextHopAddress != NULL) {
            Neighbor =
                IppFindOrCreateNeighborAtDpc(
                    Interface, SubInterface, NextHopAddress, NextHopType);
            if (Neighbor == NULL) {
                Protocol->PerProcessorStatistics
                    [KeGetCurrentProcessorNumber()].RoutingDiscards++;
                return STATUS_INSUFFICIENT_RESOURCES; 
            }
        }
    
        IsLoopback = FALSE;
    } else {
        IsLoopback = (LocalAddress != NULL);
    }
    
    //
    // Make the key. 
    //
    Protocol->
        MakeRouteKey(
            DestinationPrefix,
            DestinationPrefixLength,
            SourcePrefix, 
            SourcePrefixLength, 
            Key, 
            &KeyLength);
    
    //
    // Search for an existing Route Table Entry.
    //
    PtGetExactMatch(Compartment->RouteSet.Tree, Key, KeyLength, NULL, &Link);
    
    if (Link != NULL) {
        //
        // Search to see if we have an exact match in the list of routes.
        //
        FirstRoute = CONTAINING_RECORD(Link, IP_UNICAST_ROUTE, Link);
        Route =
            IppFindRoute(
                Protocol, FirstRoute, &Interface->Luid, NextHopAddress);
    }
    
    if (Route == NULL) {
        //
        // No existing entry for this prefix, create one.
        //
        switch (SetAction) {
        case NsiSetCreateOnly:
        case NsiSetCreateOrSet:
        case NsiSetCreateOrSetWithReference:
            Route =
                IppCreateUnicastRoute(
                    Compartment, 
                    Key,
                    KeyLength,
                    FirstRoute,
                    Interface,
                    IsLoopback,
                    IsLoopback ? (PVOID) LocalAddress : (PVOID) Neighbor,
                    NextHopAddress);
            if (Route == NULL) {
                IppRouteTrace(TRACE_LEVEL_WARNING, 
                              "Failed to allocate route",
                              Compartment->Protocol, 
                              DestinationPrefix, 
                              DestinationPrefixLength,
                              Interface,
                              NextHopAddress);
                Protocol->
                    PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                    RoutingDiscards++;
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            Route->Origin = Origin;

            Route->SitePrefixLength = 0;
            Route->CreationTime = IppTickCount;
            Route->ValidLifetime = INFINITE_LIFETIME;
            Route->PreferredLifetime = INFINITE_LIFETIME;
            Route->Metric = RouteMetricMedium;
            Route->Flags.Loopback = IsLoopback;
            Route->Flags.AutoconfigureAddress = TRUE;
            Route->Protocol = RouteProtocolNetMgmt;
            
            //
            // Create the route in deleted state
            // (meaning that activation is required).
            //
            Route->Flags.Deleted = 1;
             
            //
            // Create a broadcast address for the route. 
            // 
            IppCreateBroadcastAddressForRoute(Key, KeyLength, Route);
           
            IppReferenceRouteForUser(Route);            

            //
            // Add a user reference for the transaction. 
            //
            IppReferenceRoute((PIP_ROUTE) Route);
            *ProviderTransactionContext = Route;
            
            break;

        case NsiSetDelete:
        case NsiSetDefault:
            Status = STATUS_NOT_FOUND;
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
    } else {
        //
        // We have an existing route.
        //
        switch (SetAction) {
        case NsiSetCreateOrSetWithReference:
            if (Route->UserReferenceCount == 0) {
                //
                // This is not a user created route, should not be referenced.
                //
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            IppReferenceRouteForUser(Route);
            
        case NsiSetDefault:
        case NsiSetDelete:
        case NsiSetCreateOrSet:
            if (Route->SystemCritical) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }
            if ((Origin == NlroRouterAdvertisement) && 
                (Route->Origin != Origin)) {
                //
                // For Ipv4, update the route only if it was initially added by
                // an RA. (rfc 1256). 
                // For Ipv6, update a non-RA configured route only if the new 
                // lifetime = 0. (rfc 2461)
                //
                if (IS_IPV4_PROTOCOL(Protocol) || 
                    (RouteRw != NULL && RouteRw->ValidLifetime != 0)) {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }      
            }
            IppReferenceRoute((PIP_ROUTE) Route);
            *ProviderTransactionContext = Route;
            break;

        case NsiSetCreateOnly:
            Status = STATUS_DUPLICATE_OBJECTID;
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    
    if (Neighbor != NULL) {
        IppDereferenceNeighbor(Neighbor);
    }

    return Status;
}


VOID
IppCommitSetAllRouteParameters(
    IN NSI_SET_ACTION SetAction,
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route, 
    IN CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength, 
    IN CONST NL_ROUTE_RW *RouteRw
    )
/*++

Routine Description:

    This function commits an operation on the route table. 
    Compare RouteTableUpdate() in the XP IPv6 stack.

Arguments:

    SetAction - Supplies the action to be performed for the route
        (e.g. add/delete etc). 

    Compartment - Supplies a pointer to the compartment data.

    Route - Supplies the route on which to commit the operation.         

    DestinationPrefix - Supplies the destination prefix.

    DestinationPrefixLength - Supplies the destination prefix length.

    RouteRw - Supplies the initial read-write route information, including:

        ValidLifetime - Supplies the valid lifetime.  Note that the 
                        ValidLifetime may be INFINITE_LIFETIME, whereas 
                        Neighbor Discovery does not allow an infinite value 
                        for router lifetimes on the wire.

Return Value:

    Nine. 

Locks:

    Assumes caller holds a reference on the compartment.
    Assumes caller holds a reference on the subinterface, if non-NULL.
    Assumes caller holds a write lock on the interface.
    Assumes caller holds a write lock on the route set.

Caller IRQL:

    Must be called at DISPATCH level, since a lock is held.

--*/
{
    BOOLEAN ParameterChanged = FALSE;

    ASSERT_WRITE_LOCK_HELD(&Route->Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Compartment->RouteSet.Lock);

    switch (SetAction) {
    case NsiSetCreateOnly:
    case NsiSetCreateOrSet:
    case NsiSetCreateOrSetWithReference:
    case NsiSetDefault:
        if (RouteRw != NULL) {
            if ((RouteRw->SitePrefixLength != (UCHAR) -1) && 
                (Route->SitePrefixLength != RouteRw->SitePrefixLength)) {
                Route->SitePrefixLength = RouteRw->SitePrefixLength;
                ParameterChanged = TRUE;
            }

            //
            // Do not notify route change if lifetime changed as this can occur
            // quite often due to Router Advertisements.
            //
            Route->ValidLifetime =
                IppSecondsToTicks(RouteRw->ValidLifetime);
            Route->PreferredLifetime =
                IppSecondsToTicks(RouteRw->PreferredLifetime);
            
            if (Route->ValidLifetime == 0) {
                ParameterChanged = TRUE;
            }

            if ((RouteRw->Metric != -1) &&
                (Route->Metric != RouteRw->Metric)){
                Route->Metric = RouteRw->Metric;
                ParameterChanged = TRUE;
            }

            if ((RouteRw->Protocol != -1) &&
                (Route->Protocol != RouteRw->Protocol)) {
                Route->Protocol = RouteRw->Protocol;
                ParameterChanged = TRUE;
            }
            
            if ((RouteRw->Flags.AutoconfigureAddress != (BOOLEAN) -1) && 
                (Route->Flags.AutoconfigureAddress !=
                 RouteRw->Flags.AutoconfigureAddress)) {
                Route->Flags.AutoconfigureAddress =
                    RouteRw->Flags.AutoconfigureAddress;
                ParameterChanged = TRUE;
            }
            
            if ((RouteRw->Flags.Publish != (BOOLEAN) -1) && 
                (Route->Flags.Publish != RouteRw->Flags.Publish)) {
                Route->Flags.Publish = RouteRw->Flags.Publish;
                ParameterChanged = TRUE;

                Compartment->ForceRouterAdvertisement = TRUE;                
            }
            
            if ((RouteRw->Flags.Immortal != (BOOLEAN) -1) && 
                (Route->Flags.Immortal != RouteRw->Flags.Immortal)) {
                Route->Flags.Immortal = RouteRw->Flags.Immortal;
                ParameterChanged = TRUE;
            }            
        }

        IppRefreshUnicastRoute(Compartment, Route);

        if (Route->Flags.Deleted) {
            IppRouteTrace(TRACE_LEVEL_WARNING, 
                          "Created route", 
                          Compartment->Protocol, 
                          DestinationPrefix, 
                          DestinationPrefixLength, 
                          Route->Interface, 
                          IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route));

            IppNotifyRouteChange(Route, NsiAddInstance);
        } else if (ParameterChanged) {
            IppNotifyRouteChange(Route, NsiParameterNotification);
        }
        break;

    case NsiSetDelete:
        IppDereferenceRouteForUser(
            Route, Compartment, DestinationPrefix, DestinationPrefixLength);
        break;
        
    default:
        ASSERT(FALSE);
        break;
    }

    IppInvalidateDestinationCache(Compartment);
    
    Route->Flags.Deleted = 0;

    //
    // Remove the reference added in the validation phase.
    //
    IppDereferenceRoute((PIP_ROUTE)Route);
}


VOID
IppCancelSetAllRouteParameters(
    IN NSI_SET_ACTION SetAction,
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route, 
    IN CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength
    )
/*++

Routine Description:

    This function will cancel a validated transaction operation.

Arguments:

Arguments:

    SetAction - Supplies the action to be performed for the route
        (e.g. add/delete etc). 

    Compartment - Supplies a pointer to the compartment data.

    Route - Supplies the route on which to commit the operation.         

    DestinationPrefix - Supplies the destination prefix.

    DestinationPrefixLength - Supplies the destination prefix length.

Return Value:

    None.

Locks:

    Assumes caller holds a write lock on the interface.
    Assumes caller holds a write lock on the route set.

Caller IRQL:

    Must be called at DISPATCH level, since a lock is held.

--*/
{
    ASSERT_WRITE_LOCK_HELD(&Route->Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Compartment->RouteSet.Lock);

    switch (SetAction) {
    case NsiSetCreateOnly:
    case NsiSetCreateOrSet:
        if (Route->Flags.Deleted) {
            IppDereferenceRouteForUser(Route, 
                                       Compartment, 
                                       DestinationPrefix,
                                       DestinationPrefixLength);
        }
        break;

    case NsiSetCreateOrSetWithReference:
        IppDereferenceRouteForUser(Route, 
                                   Compartment, 
                                   DestinationPrefix,
                                   DestinationPrefixLength);
        break;

    default:
        break;
    }
    
    Route->Flags.Deleted = 0;
    //
    // Remove the reference added in the validation phase.
    //
    IppDereferenceRoute((PIP_ROUTE)Route);
}


NTSTATUS
IppUpdateUnicastRouteUnderLock(
    IN NSI_SET_ACTION SetAction,
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength, 
    IN CONST UCHAR *SourcePrefix, 
    IN UINT8 SourcePrefixLength, 
    IN NL_ROUTE_ORIGIN Origin,
    IN CONST NL_ROUTE_RW *RouteRw OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL,
    IN PIP_LOCAL_ADDRESS LocalAddress OPTIONAL
    )
/*++

Routine Description:
    
    This function updates a single route in the routing table.
    Multiple routes may be updated atomically by using the code
    in this routine as an example, calling IppLockRouteTableForUpdate,
    then calling IppUpdateUnicastRouteUnderLock multiple times,
    and then ending with IppCommitAtomicSetChanges.

Arguments:

    SetAction - Supplies the action to be performed for the route
        (e.g. add/delete etc). 

    Compartment - Supplies a pointer to the compartment data.

    Interface - Supplies a pointer to the interface.

    SubInterface - Supplies a pointer to the sub-interface.  

    DestinationPrefix - Supplies the destination prefix.

    DestinationPrefixLength - Supplies the destination prefix length.

    SourcePrefix - Supplies the source prefix.

    SourcePrefixLength - Supplies the source prefix length.

    Origin - Supplies the route origin value.

    RouteRw - Supplies the initial read-write route information.

    NextHopAddress - Supplies the next-hop address.  A local unicast address,
        or the unspecified address is treated as a NULL next-hop address.

    LocalAddress - Supplies the local destination address for the route. 

    Note: The type of route is determined as follows...
        if (NextHopAddress != NULL) { Destination = Offlink }
        else if (LocalAddress != NULL) { Destination = Loopback }
        else { Destination = OnLink }    
    
Return Value:

    If the function is successfully completed, then a success status is
    returned. Otherwise, a failure status is returned.

Locks:

    Assumes caller holds a reference on the compartment.
    Assumes caller holds a reference on the subinterface, if non-NULL.
    Assumes caller holds a write lock on the interface.
    Assumes caller holds a write lock on the route set.

Caller IRQL: = DISPATCH.

--*/
{
    NTSTATUS Status;
    PIP_UNICAST_ROUTE Route;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
     
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&Compartment->RouteSet.Lock);

    Status =
        IppValidateSetAllRouteParameters(
            SetAction, 
            Interface,
            SubInterface, 
            DestinationPrefix, 
            DestinationPrefixLength, 
            SourcePrefix, 
            SourcePrefixLength, 
            Origin, 
            RouteRw, 
            NextHopAddress, 
            LocalAddress,
            &Route);
    if (NT_SUCCESS(Status)) {
        IppCommitSetAllRouteParameters(
            SetAction, 
            Compartment, 
            Route, 
            DestinationPrefix, 
            DestinationPrefixLength, 
            RouteRw);
    }
    
    return Status;
}

NTSTATUS
IppUpdateUnicastRoute(
    IN NSI_SET_ACTION SetAction,
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength, 
    IN CONST UCHAR *SourcePrefix, 
    IN UINT8 SourcePrefixLength, 
    IN NL_ROUTE_ORIGIN Origin,
    IN CONST NL_ROUTE_RW *RouteRw OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL
    )
/*++

Routine Description:
    
    This function updates a single route in the routing table.
    Multiple routes may be updated atomically by using the code
    in this routine as an example, calling IppLockRouteTableForUpdate,
    then calling IppUpdateUnicastRouteUnderLock multiple times,
    and then ending with IppCommitAtomicSetChanges.

Arguments:

    SetAction - Supplies the action to be performed for the route
        (e.g. add/delete etc). 

    Compartment - Supplies a pointer to the compartment data.

    Interface - Supplies a pointer to the interface.

    SubInterface - Supplies a pointer to the sub-interface.  

    DestinationPrefix - Supplies the destination prefix.

    DestinationPrefixLength - Supplies the destination prefix length.

    SourcePrefix - Supplies the source prefix.

    SourcePrefixLength - Supplies the source prefix length.

    Origin - Supplies the route origin value.

    RouteRw - Supplies the initial read-write route information.

    NextHopAddress - Supplies the next-hop address.  A local unicast address,
        or the unspecified address is treated as a NULL next-hop address
        (meaning that it indicates an on-link route).

Return Value:

    If the function is successfully completed, then a success status is
    returned. Otherwise, a failure status is returned.

Locks:

    Assumes caller holds a reference on the compartment.
    Assumes caller holds a reference on the subinterface, if non-NULL.
    None.    

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    KLOCK_QUEUE_HANDLE InterfaceLockHandle, RouteSetLockHandle;
    
    RtlAcquireWriteLock(&Interface->Lock, &InterfaceLockHandle);
    RtlAcquireScalableWriteLockAtDpcLevel(
        &Compartment->RouteSet.Lock, &RouteSetLockHandle);
    
    Status =
        IppUpdateUnicastRouteUnderLock(
            SetAction, 
            Interface,
            SubInterface, 
            DestinationPrefix, 
            DestinationPrefixLength, 
            SourcePrefix, 
            SourcePrefixLength, 
            Origin, 
            RouteRw, 
            NextHopAddress, 
            NULL);
    
    RtlReleaseScalableWriteLockFromDpcLevel(
        &Compartment->RouteSet.Lock, &RouteSetLockHandle);    
    RtlReleaseWriteLock(&Interface->Lock, &InterfaceLockHandle);

    return Status;
}

VOID
IppNotifyRouteChangeAtPassive(
    IN PVOID Context
    )
/*++

Routine Description:

    This function makes the route change notification to NSI.

Arguments:
    Relevant fields of Context:
    
    Object - Supplies an IP_ROUTE_NOTIFY_CONTEXT struct. The object 
        contains a pointer to the Route. And immediately following it is the 
        route key structure.

    NotificationType - Supplies the type of notification we will make to NSI.

    ParameterDescription - Supplies the parameter that changed.

Locks:

    Must be called with no locks held.
    Assumes caller holds a reference to the route.

Caller IRQL:

    Called at PASSIVE level.

--*/
{
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem = 
        (PIP_NOTIFICATION_WORK_QUEUE_ITEM) Context;
    NM_INDICATE_PARAMETER_CHANGE NsiArgs = {0};
    PIP_ROUTE_NOTIFY_CONTEXT RouteContext = 
        (PIP_ROUTE_NOTIFY_CONTEXT) WorkItem->Object;
    PIP_INTERFACE Interface = RouteContext->UnicastRoute->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PNMP_CLIENT_CONTEXT ClientContext = Protocol->NmClientContext;
    PNMP_NOTIFICATION_CONTEXT NotificationContext = 
        &ClientContext->RouteNotificationContext;
    NL_ROUTE_PROTOCOL RouteProtocol;
    
    PASSIVE_CODE();

    //
    // WorkerQueue is serialized so we don't need to get a lock here.
    //
    
    //
    // Create the Nsi notification structure. Force the client to have to query
    // down to see what has changed.
    //
    RtlZeroMemory(&NsiArgs, sizeof(NsiArgs));
    
    NsiArgs.ProviderHandle = ClientContext->Npi.ProviderHandle;
    NsiArgs.ObjectIndex = NlRouteObject;

    if (IS_IPV4_PROTOCOL(Protocol)) {
        NsiArgs.KeyStructDesc.KeyStructLength = sizeof(IPV4_ROUTE_KEY);
        NsiArgs.KeyStructDesc.KeyStruct = (PUCHAR)(&RouteContext->Ipv4Key);
    } else {
        NsiArgs.KeyStructDesc.KeyStructLength = sizeof(IPV6_ROUTE_KEY);
        NsiArgs.KeyStructDesc.KeyStruct = (PUCHAR)(&RouteContext->Ipv6Key);
    }
    
    NsiArgs.NotificationType = WorkItem->NotificationType;
    NsiArgs.ParamDesc.StructType = NsiStructRw; 
    
    if (NsiArgs.NotificationType == NsiDeleteInstance) {
        RouteProtocol = RouteContext->UnicastRoute->Protocol;
        NsiArgs.ParamDesc.ParameterLength = sizeof(NL_ROUTE_PROTOCOL);
        NsiArgs.ParamDesc.ParameterOffset = 
            FIELD_OFFSET(NL_ROUTE_RW, Protocol);
        NsiArgs.ParamDesc.Parameter = (PUCHAR)&RouteProtocol;        
    }

    ClientContext->Npi.Dispatch->ParameterChange(&NsiArgs);
    
    if (RoDereference(&NotificationContext->ReferenceObject)) {
        KeSetEvent(&NotificationContext->DeregisterCompleteEvent, 0, FALSE);
    }
    IppDereferenceNsiClientContext(Protocol);
    IppDereferenceRoute((PIP_ROUTE) RouteContext->UnicastRoute);
    ExFreePoolWithTag(WorkItem, IpGenericPoolTag);
}

VOID
IppNotifyRouteChange(
    IN PIP_UNICAST_ROUTE UnicastRoute,
    IN NSI_NOTIFICATION NotificationType
    )
/*++

Routine Description:

    Tell clients about the current status of a unicast route.
    This function will call the protocol specific code to perform the necessary
    tasks.

Arguments:

    UnicastRoute - Supplies the route to notify clients about.

    NotificationType - Type of notification (add/delete/parameter change).
    
Locks:

    Assumes caller holds a reference on UnicastRoute.
    Caller can hold any number of locks - the work is deferred to an workitem.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_INTERFACE Interface = UnicastRoute->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem;
    PNMP_NOTIFICATION_CONTEXT NotificationContext;
        
    ASSERT(UnicastRoute != NULL);
    
    //
    // Take a reference on the attachment.  If this succeeds,
    // then we can safely access the NmClientContext.
    //
    if (!RoReference(&Protocol->NmClientReferenceObject)) {
        return;
    }

    NotificationContext = 
        &Protocol->NmClientContext->RouteNotificationContext;

    //
    // Take a reference on the notification registration.
    // This prevents deregistration from completing until we're done.
    //
    if (!RoReference(&NotificationContext->ReferenceObject)) {
        //
        // There's no one to notify.
        //
        IppDereferenceNsiClientContext(Protocol);
        return;
    }

    WorkItem = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            sizeof(*WorkItem) + sizeof(IP_ROUTE_NOTIFY_CONTEXT), 
            IpGenericPoolTag);

    if (WorkItem == NULL) {
        RoDereference(&NotificationContext->ReferenceObject);
        IppDereferenceNsiClientContext(Protocol);
        return;
    }

    WorkItem->Object = (PVOID)(WorkItem + 1);
    WorkItem->WorkerRoutine = IppNotifyRouteChangeAtPassive;
    WorkItem->NotificationType = NotificationType;

    IppReferenceRoute((PIP_ROUTE) UnicastRoute);
    
    Protocol->NotifyRouteChange(
        UnicastRoute,
        NotificationType,
        (PIP_ROUTE_NOTIFY_CONTEXT) WorkItem->Object);
    
    NetioInsertWorkQueue(&Interface->Compartment->WorkQueue, &WorkItem->Link);
}

NTSTATUS
NTAPI
IpRegisterRouteChangeNotification(
    IN PNM_REQUEST_REGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Enable route change notifications via the NSI.

Arguments:

    Request - Supplies a request to enable notifications.

Return Value:

    STATUS_DELETE_PENDING if we're trying to deregister with the NSI.
    STATS_SUCCESS on success.

--*/
{
    PNMP_CLIENT_CONTEXT ClientContext = 
        (PNMP_CLIENT_CONTEXT) Request->ProviderHandle;
    PNMP_NOTIFICATION_CONTEXT NotificationContext =
        &ClientContext->RouteNotificationContext;

    //
    // Take a reference on the attachment.
    //
    if (!RoReference(&ClientContext->Protocol->NmClientReferenceObject)) {
        return STATUS_DELETE_PENDING;
    }

    RoInitialize(&NotificationContext->ReferenceObject);

    return STATUS_SUCCESS;
}


VOID
NTAPI
IpDeregisterRouteChangeNotification(
    IN PNM_REQUEST_DEREGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Disable route change notifications via the NSI.

Arguments:

    Request - Supplies a request to disable notifications.

Caller IRQL:

    Must be called at IRQL <= APC level.

--*/
{
    PNMP_CLIENT_CONTEXT ClientContext = 
        (PNMP_CLIENT_CONTEXT) Request->ProviderHandle;
    PNMP_NOTIFICATION_CONTEXT NotificationContext = 
        &ClientContext->RouteNotificationContext;

    PAGED_CODE();

    //
    // Initialize an event we can wait on until deregistering is complete.
    //
    KeInitializeEvent(&NotificationContext->DeregisterCompleteEvent, 
                      NotificationEvent, 
                      FALSE);

    if (!RoUnInitialize(&NotificationContext->ReferenceObject)) {
        //
        // Wait for notifications in progress to complete.
        //
        KeWaitForSingleObject(&NotificationContext->DeregisterCompleteEvent, 
                              UserRequest, 
                              KernelMode, 
                              FALSE, 
                              NULL);
    }

    KeUninitializeEvent(&NotificationContext->DeregisterCompleteEvent);

    //
    // Release the reference on the attachment.
    //
    IppDereferenceNsiClientContext(ClientContext->Protocol);
}

NTSTATUS
IppFillUnicastRouteData(
    IN PIP_PROTOCOL Protocol,
    IN PIP_UNICAST_ROUTE Route,
    OUT PNL_ROUTE_KEY Key OPTIONAL,
    OUT PNL_ROUTE_RW Rw OPTIONAL,
    OUT PNL_ROUTE_ROD Rod OPTIONAL,
    OUT PNL_ROUTE_ROS Ros OPTIONAL
    )
/*++

Routine Description:

    Fill in NSI unicast route data.  This routine is common between
    IPv4 and IPv6, and can be used for both Gets and Enumerates.

Arguments:

    Protocol - Supplies the protocol.

    Route - Supplies the route. 

    Key - Optionally returns key parameters.
    
    Rw - Optionally returns read-write parameters.

    Rod - Optionally returns read-only dynamic parameters.

    Ros - Optionally returns read-only static parameters.
    
--*/
{
    NTSTATUS Status;
    
    if (Key != NULL) {
        Key->CompartmentId = Route->Interface->Compartment->CompartmentId;
            
        Status = IppGetRouteKey(Route, Key);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }
    
    if (Rw != NULL) {
        PIPR_LOCKED_SET RouteSet = &Route->Interface->Compartment->RouteSet;
        KLOCK_QUEUE_HANDLE LockHandle;
        
        //
        // Lock the route set for updating the lifetimes.
        //
        RtlAcquireScalableWriteLock(&RouteSet->Lock, &LockHandle);
        
        IppUpdateUnicastRouteLifetimes(RouteSet, Route);

        RtlReleaseScalableWriteLock(&RouteSet->Lock, &LockHandle);
    
        RtlZeroMemory(Rw, sizeof(*Rw));

        Rw->SitePrefixLength = Route->SitePrefixLength;
        Rw->ValidLifetime = IppTicksToSeconds(Route->ValidLifetime);
        Rw->PreferredLifetime = IppTicksToSeconds(Route->PreferredLifetime);
        Rw->Metric = Route->Metric;
        Rw->Protocol = Route->Protocol;
        Rw->Flags.Loopback = Route->Flags.Loopback;
        Rw->Flags.AutoconfigureAddress = Route->Flags.AutoconfigureAddress;
        Rw->Flags.Publish = Route->Flags.Publish;
        Rw->Flags.Immortal = Route->Flags.Immortal;
    }

    if (Rod != NULL) {
        RtlZeroMemory(Rod, sizeof(*Rod));

        Rod->Age = IppTicksToSeconds(IppTickCount - Route->CreationTime);
    
        RtlCopyMemory(
            Rod->FirstHopAddress,
            IppGetFirstHopAddress(Route),
            Protocol->Characteristics->AddressBytes);
    }

    if (Ros != NULL) {
        RtlZeroMemory(Ros, sizeof(*Ros));

        Ros->InterfaceIndex = Route->Interface->Index;
        Ros->Origin = Route->Origin;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IppGetAllBestRouteParameters(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId, 
    IN CONST UCHAR *Source, 
    IN SCOPE_ID SourceScopeId, 
    IN NET_LUID *SourceInterfaceLuid OPTIONAL,
    IN CONST UCHAR *Destination, 
    IN SCOPE_ID DestinationScopeId, 
    OUT PUCHAR Rod OPTIONAL
    )
/*++

Routine Description:

    This function looks up the best route for a given destination.

Arguments:

    Protocol - Supplies the protocol. 

    CompartmentId - Supplies the compartment ID. 
    
    Source - Supplies the source address for the best route lookup. 

    SourceScopeId - Supplies the scope ID of the source. 

    Destination - Supplies the destination for the lookup. 

    DestinationScopeId - Supplies the destination scope ID. 

    Rod - Optionally returns the best route data.

Return Value:

    Status of the operation.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_COMPARTMENT Compartment;
    PIP_LOCAL_UNICAST_ADDRESS ConstrainAddress = NULL, SourceAddress = NULL;
    PIP_INTERFACE ConstrainInterface = NULL;
    PIP_PATH Path = NULL;
    PIP_NEXT_HOP NextHop = NULL;
    PIP_UNICAST_ROUTE Route = NULL;
    ULONG ScopeZone;
    IP_PATH_FLAGS ConstrainFlags;
    
    //
    // Get a pointer to the compartment. 
    //
    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        return STATUS_NOT_FOUND;
    }
    
    //
    // Canonicalize the destination scope ID. 
    //
    if (!IppCanonicalizeScopeId(
            Compartment, Destination, &DestinationScopeId)) {
        Status = STATUS_INVALID_PARAMETER;
        goto Done;
    }
    
    //
    // If the source address is specified,
    // get a handle on the source address for the route lookup. 
    //
    if (Protocol->AddressType(Source) != NlatUnspecified) {
        if (!IppCanonicalizeScopeId(Compartment, Source, &SourceScopeId)) {
            Status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
        
        ConstrainAddress = (PIP_LOCAL_UNICAST_ADDRESS) 
            IppFindAddressInScope(Compartment, SourceScopeId, Source);
        if (ConstrainAddress == NULL) {
            Status = STATUS_NOT_FOUND;
            goto Done;
        }
        
        if (ConstrainAddress->Type != NlatUnicast) {
            Status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
        
        //
        // We constrain the interface based on the source address
        // (even if the source address is on a forwarding interface). 
        //
        ConstrainInterface = ConstrainAddress->Interface;
        IppReferenceInterface(ConstrainInterface);
        
    } else if (SourceInterfaceLuid != NULL) {
        //
        // Get the source interface.
        //         
        ConstrainInterface = 
            IppFindInterfaceByLuid(Protocol, SourceInterfaceLuid);
        if (ConstrainInterface == NULL) {
            Status = STATUS_NOT_FOUND;
            goto Done;
        }           
    }

    if (ConstrainInterface != NULL) {
        ScopeZone =
            IppGetInterfaceScopeZone(
                ConstrainInterface, DestinationScopeId.Level);
        if (DestinationScopeId.Zone == 0) {
            DestinationScopeId.Zone = ScopeZone;
        } else if (DestinationScopeId.Zone != ScopeZone) {
            Status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
    }

    //
    // IppRouteToDestination does not support the unspecified address,
    // and so we avoid calling it and fall back to IppFindNextHopAndSource.
    //
    if (Compartment->Protocol->AddressType(Destination) != NlatUnspecified) {
        Status =
            IppRouteToDestination(
                Compartment,
                Destination,
                DestinationScopeId,
                ConstrainInterface,
                (PIP_LOCAL_ADDRESS) ConstrainAddress,
                &Path);
        if (!NT_SUCCESS(Status)) {
            goto Done;
        }

        Route = IppGetRouteFromPath(Path);
    }
    
    if (Route != NULL) {
        //
        // Select the source address from the path.
        //
        SourceAddress = Path->SourceAddress;
        IppReferenceLocalUnicastAddress(SourceAddress);
    } else {
        //
        // The path did not return a route; we must perform a route lookup.
        //
        Status =
            IppFindNextHopAndSource(
                Compartment,
                ConstrainInterface,
                Destination,
                DestinationScopeId,
                ConstrainAddress,
                &NextHop,
                &SourceAddress, 
                &Route, 
                &ConstrainFlags);
        if (!NT_SUCCESS(Status)) {
            goto Done;
        }
    }
    
    if (Rod == NULL) {
        goto Done;
    }
    
    if (IS_IPV4_PROTOCOL(Protocol)) {
        PIPV4_BEST_ROUTE_ROD Ipv4Rod = (PIPV4_BEST_ROUTE_ROD) Rod;

        RtlZeroMemory(Ipv4Rod, sizeof(*Ipv4Rod));
        
        if (Route != NULL) {
            //
            // Fill route information.
            //
            Status =
                IppFillUnicastRouteData(
                    Protocol,
                    (PIP_UNICAST_ROUTE) Route,
                    (PNL_ROUTE_KEY) &Ipv4Rod->RouteKey,
                    (PNL_ROUTE_RW) &Ipv4Rod->RouteRw,
                    (PNL_ROUTE_ROD) &Ipv4Rod->RouteRod,
                    (PNL_ROUTE_ROS) &Ipv4Rod->RouteRos);
        }

        //
        // Fill source information.
        //
        Ipv4Rod->SourceScopeId =
            IppGetExternalScopeId(
                SourceAddress->Interface, NL_ADDRESS(SourceAddress));

        RtlCopyMemory(
            &Ipv4Rod->SourceAddress, 
            NL_ADDRESS(SourceAddress),
            sizeof(Ipv4Rod->SourceAddress));
    } else {
        PIPV6_BEST_ROUTE_ROD Ipv6Rod = (PIPV6_BEST_ROUTE_ROD) Rod;

        RtlZeroMemory(Ipv6Rod, sizeof(*Ipv6Rod));
        
        if (Route != NULL) {
            //
            // Fill route information.
            //
            Status =
                IppFillUnicastRouteData(
                    Protocol,
                    (PIP_UNICAST_ROUTE) Route,
                    (PNL_ROUTE_KEY) &Ipv6Rod->RouteKey,
                    (PNL_ROUTE_RW) &Ipv6Rod->RouteRw,
                    (PNL_ROUTE_ROD) &Ipv6Rod->RouteRod,
                    (PNL_ROUTE_ROS) &Ipv6Rod->RouteRos);
        }
        
        //
        // Fill source information.
        //
        Ipv6Rod->SourceScopeId =
            IppGetExternalScopeId(
                SourceAddress->Interface, NL_ADDRESS(SourceAddress));

        RtlCopyMemory(
            &Ipv6Rod->SourceAddress, 
            NL_ADDRESS(SourceAddress),
            sizeof(Ipv6Rod->SourceAddress));
    }
    
Done:
    IppDereferenceCompartment(Compartment);
    if (ConstrainAddress != NULL) {
        IppDereferenceLocalUnicastAddress(ConstrainAddress);
    }
    if (ConstrainInterface != NULL) {
        IppDereferenceInterface(ConstrainInterface);
    }
    if (Path != NULL) {
        IppDereferencePath((PIP_PATH) Path);
    }    
    if (Route != NULL) {
        IppDereferenceRoute((PIP_ROUTE) Route);
    }
    if (SourceAddress != NULL) {
        IppDereferenceLocalUnicastAddress(SourceAddress);
    }
    if (NextHop != NULL) {
        IppDereferenceNextHop(NextHop);
    }
    
    return Status;
}

NTSTATUS
NTAPI
IpGetAllRouteParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a given route.

Arguments:

    Args - Supplies a structure describing the operation to be performed.

Return Value:

    Status of the operation.

--*/
{
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    USHORT AddressBytes = Protocol->Characteristics->AddressBytes;
    ULONG AddressBits = AddressBytes * 8;

    UCHAR InternalKey[ROUTE_KEY_STORAGE_SIZE];
    USHORT InternalKeyLength;
    PUCHAR DestinationPrefix, SourcePrefix;
    UINT8 DestinationPrefixLength, SourcePrefixLength;
    PIF_LUID InterfaceLuid;
    PUCHAR NextHopAddress;
    PIP_UNICAST_ROUTE Route = NULL;
    
    PNL_ROUTE_KEY Key = (PNL_ROUTE_KEY) Args->KeyStructDesc.KeyStruct;

    COMPARTMENT_ID CompartmentId;
    PIP_COMPARTMENT Compartment;
    PIP_INTERFACE Interface;
    NTSTATUS Status;

    if (IS_IPV4_PROTOCOL(Protocol)) { 
        PIPV4_ROUTE_KEY Ipv4Key = (PIPV4_ROUTE_KEY) Key;
            
        DestinationPrefix = (PUCHAR) &Ipv4Key->DestinationPrefix;
        DestinationPrefixLength = Ipv4Key->DestinationPrefixLength;
        SourcePrefix = (PUCHAR) &Ipv4Key->SourcePrefix;
        SourcePrefixLength = Ipv4Key->SourcePrefixLength;
        InterfaceLuid = &Ipv4Key->InterfaceLuid;

        NextHopAddress = (PUCHAR) &Ipv4Key->NextHopAddress;
    } else {  
        PIPV6_ROUTE_KEY Ipv6Key = (PIPV6_ROUTE_KEY) Key;
        
        DestinationPrefix = (PUCHAR) &Ipv6Key->DestinationPrefix;
        DestinationPrefixLength = Ipv6Key->DestinationPrefixLength;
        SourcePrefix = (PUCHAR) &Ipv6Key->SourcePrefix;
        SourcePrefixLength = Ipv6Key->SourcePrefixLength;
        InterfaceLuid = &Ipv6Key->InterfaceLuid;
        
        NextHopAddress = (PUCHAR) &Ipv6Key->NextHopAddress;
    }
    
    
    switch (Args->Action) {
    case NsiGetExact:
        if ((SourcePrefixLength > 0) &&
            (DestinationPrefixLength != AddressBits)) {
            return STATUS_INVALID_PARAMETER;
        }

        Interface = IppFindInterfaceByLuid(Protocol, InterfaceLuid);
        if (Interface == NULL) {
            return STATUS_NOT_FOUND;
        }
        Compartment = Interface->Compartment;
        CompartmentId = Compartment->CompartmentId;

        //
        // Make sure the interface is in the specified compartment.
        //
        if ((Key->CompartmentId != 0) &&
            (Key->CompartmentId != CompartmentId)) {
            IppDereferenceInterface(Interface);
            return STATUS_NOT_FOUND;
        }

        Protocol->
            MakeRouteKey(
                DestinationPrefix, 
                DestinationPrefixLength,
                SourcePrefix, 
                SourcePrefixLength,
                InternalKey, 
                &InternalKeyLength);
        
        Status =
            IppFindUnicastRoute(
                InternalKey, 
                InternalKeyLength,
                Compartment,
                Interface,
                NextHopAddress,
                &Route);

        IppDereferenceInterface(Interface);

        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        break;

    case NsiGetFirst:
        Compartment = IppGetFirstCompartment(Protocol);
        if (Compartment == NULL) {
            return STATUS_NO_MORE_ENTRIES;
        }

        for (;;) {
            Route = (PIP_UNICAST_ROUTE)
                IppGetNextRoute(Compartment, NULL, 0, NULL, NULL);

            CompartmentId = Compartment->CompartmentId;
            IppDereferenceCompartment(Compartment);

            if (Route != NULL) {
                Status = STATUS_SUCCESS;
                break;
            }

            Compartment = IppGetNextCompartment(Protocol, CompartmentId);
            if (Compartment == NULL) {
                return STATUS_NO_MORE_ENTRIES;
            }
        }

        break;

    case NsiGetNext:
        if ((SourcePrefixLength > 0) &&
            (DestinationPrefixLength != AddressBits)) {
            return STATUS_INVALID_PARAMETER;
        }
        
        CompartmentId = Key->CompartmentId;
        Compartment = IppFindCompartmentById(Protocol, CompartmentId);
        if (Compartment != NULL) {
            Protocol->
                MakeRouteKey(
                    DestinationPrefix, 
                    DestinationPrefixLength,
                    SourcePrefix, 
                    SourcePrefixLength,
                    InternalKey, 
                    &InternalKeyLength);
        
            Route = (PIP_UNICAST_ROUTE)
                IppGetNextRoute(
                    Compartment,
                    InternalKey,
                    InternalKeyLength,
                    InterfaceLuid,
                    NextHopAddress);

            IppDereferenceCompartment(Compartment);

            if (Route != NULL) {
                Status = STATUS_SUCCESS;
                break;
            }
        }
        
        for (;;) {
            Compartment = IppGetNextCompartment(Protocol, CompartmentId);
            if (Compartment == NULL) {
                return STATUS_NO_MORE_ENTRIES;
            }

            Route = (PIP_UNICAST_ROUTE)
                IppGetNextRoute(Compartment, NULL, 0, NULL, NULL);

            CompartmentId = Compartment->CompartmentId;
            IppDereferenceCompartment(Compartment);

            if (Route != NULL) {
                Status = STATUS_SUCCESS;
                break;
            }
        }
        break;
        
    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (Route == NULL) {
        return STATUS_NOT_FOUND;
    }
    
    Status =
        IppFillUnicastRouteData(
            Protocol,
            (PIP_UNICAST_ROUTE) Route,
            (Args->Action == NsiGetExact) ? NULL : Key,
            (PNL_ROUTE_RW) Args->StructDesc.RwParameterStruct,
            (PNL_ROUTE_ROD) Args->StructDesc.RoDynamicParameterStruct,
            (PNL_ROUTE_ROS) Args->StructDesc.RoStaticParameterStruct);

    IppDereferenceRoute((PIP_ROUTE) Route);

    return Status;
}

 
VOID
NTAPI
IpNlpReferenceNextHop(
    IN PNL_NEXT_HOP NextHop
    )
{
    IppReferenceNextHop((PIP_NEXT_HOP) NextHop);
}

VOID
NTAPI
IpNlpDereferenceNextHop(
    IN PNL_NEXT_HOP NextHop
    )
{
    IppDereferenceNextHop((PIP_NEXT_HOP) NextHop);
}


VOID
IpInvalidatePathCachedInformation(
    IN UINT8 ProtocolId,
    IN COMPARTMENT_ID CompartmentId,
    IN CONST UCHAR *SourceAddress,
    IN SCOPE_ID SourceScopeId,
    IN CONST UCHAR *DestinationAddress,
    IN SCOPE_ID DestinationScopeId
    )
/*++

Routine Description:

    Invalidate cached information for the matching path.

Arguments:

    ProtocolId - Supplies the protocol ID (IPPROTO_IP or IPPROTO_IPV6).

    CompartmentId - Supplies the compartment ID.
        Use UNSPECIFIED_COMPARTMENT_ID for the default compartment.

    SourceAddress - Supplies the source address.

    SourceScopeId - Supplies the source scope-id.
        Use SCOPEID_UNSPECIFIED_INIT for unambiguous addresses or for the 
        scope ID to be automatically determined by finding the source
        address that matches the input SourceAddress when scope ID is ignored.
    
    DestinationAddress - Supplies the destination address.

    DestionationScopeId - Supplies the destination scope-id.
        Use SCOPEID_UNSPECIFIED_INIT for unambiguous addresses or if the scope
        ID should be automatically determined based.
        

Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_PROTOCOL Protocol =
        (ProtocolId == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;    
    PIP_COMPARTMENT Compartment = NULL;
    PIP_LOCAL_ADDRESS LocalAddress = NULL;
    PIP_PATH Path = NULL;

    ASSERT(Protocol->Level == ProtocolId);

    if (!Protocol->Installed) {
        return;
    }
    
    //
    // Determine the compartment.
    //
    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        return;
    }
    
    //
    // Note: This routine is invoked by external clients.
    // Hence, we need to canonicalize the supplied ScopeIds before first use.
    //
    if (!IppCanonicalizeScopeId(
            Compartment, DestinationAddress, &DestinationScopeId)) {
        goto Bail;
    }
    
    //
    // Determine the local address.
    //
    if (!IppCanonicalizeScopeId(Compartment, SourceAddress, &SourceScopeId)) {
        goto Bail;
    }

    LocalAddress =
        IppFindAddressInScope(Compartment, SourceScopeId, SourceAddress);
    if ((LocalAddress == NULL) || (LocalAddress->Type != NlatUnicast)) {
        goto Bail;
    }

    //
    // For link-local addresses that don't have a zone specified, derive the
    // zone from the source interface.  This is possible, because in general
    // the zone of the  destination interface for a given address scope,
    // must match the zone of the the source interface for the same address
    // scope.
    // NTRaid-Issue-Windows OS Bugs 1686873: In future we should force callers
    // to specify both source and destination scope IDs fully.
    //
    if (((DestinationScopeId.Level == ScopeLevelSite) ||
         (DestinationScopeId.Level == ScopeLevelLink)) && 
        (DestinationScopeId.Zone == 0)) {
         DestinationScopeId.Zone =
             IppGetInterfaceScopeZone(
                LocalAddress->Interface,
                DestinationScopeId.Level);
    }
    
    //
    // Find the correct path but don't bother creating one if none exists
    // (we call IppFindPath instead of IppRouteToDestination here).
    //
    Path =
        IppFindPath(
            Compartment,
            NULL,
            DestinationAddress,
            DestinationScopeId,
            LocalAddress->Interface,
            (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress);
    if (Path == NULL) {
        goto Bail;
    }

    //
    // Finally, invalidate the path cached information.
    // This will cause upper-layers to requery.
    //
    IppInvalidatePathCachedInformation(Path);
    
Bail:
    if (Path != NULL) {
        IppDereferencePath(Path);
    }
    
    if (LocalAddress != NULL) {
        IppDereferenceLocalAddress(LocalAddress);
    }
    
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);
    }    
}

PIP_SITE_PREFIX_ENTRY
IppFindSitePrefixEntryUnderSpinLock(
    IN PIP_COMPARTMENT Compartment,
    IN PIPV6_SITEPREFIX_KEY Key,
    OUT PIPV6_SITEPREFIX_KEY NextKey,
    OUT PNL_SITEPREFIX_ROD NextRod
    )
/*++

Routine Description:

    This function find the site prefix under a spin lock and fill the next key 
        and next rod if the next entry exists.

Arguments:

    Compartment - Supplies the compartment.

    Key - Supplies the SitePrefix Key to look up.

    NextKey - Returns the next SitePrefix Key.

    NextRod - Returns the next SitePrefix Rod.

Return Value:

    STATUS_SUCCESS on success, STATUS_NO_MORE_ENTRIES if there's no site
        prefixes.

--*/
{
    PLIST_ENTRY Head, Current, Next;
    PIP_SITE_PREFIX_ENTRY SitePrefixEntry, NextEntry;
    
    Head = &Compartment->SitePrefixSet.Set;
    for (Current = Head->Flink; Current != Head; Current = Next) {
        Next = Current->Flink;
        SitePrefixEntry = (PIP_SITE_PREFIX_ENTRY)
            CONTAINING_RECORD(Current, IP_SITE_PREFIX_ENTRY, Link);

        if (!IN6_ADDR_EQUAL(&SitePrefixEntry->Prefix, &Key->Prefix)) {
            continue;
        }

        if (SitePrefixEntry->Interface->Luid.Value != 
            Key->InterfaceLuid.Value) {
            continue;
        }

        if (SitePrefixEntry->PrefixLength != Key->PrefixLength) {
            continue;
        }
        
        if (NextKey != NULL) {
            //
            // Info of next siteprefix required.
            //
            if (Next != Head) {
                NextEntry = (PIP_SITE_PREFIX_ENTRY)
                    CONTAINING_RECORD(Next, IP_SITE_PREFIX_ENTRY, Link);
                ASSERT(NextEntry->Interface != NULL);
                NextKey->InterfaceLuid = NextEntry->Interface->Luid;
                NextKey->Prefix = NextEntry->Prefix;
                NextKey->PrefixLength = NextEntry->PrefixLength;
                if (NextRod != NULL) {
                    NextRod->ValidLifetime = NextEntry->ValidLifetime;
                }
            } else {
                //
                // There is no more entries in the compartment.
                //
                NextKey->InterfaceLuid.Value = 0;
            }
        }
        return SitePrefixEntry;
    }  
    return NULL;
}

NTSTATUS
IppGetFirstCompartmentSitePrefix(
    IN PIP_COMPARTMENT Compartment,
    OUT PIPV6_SITEPREFIX_KEY Key,
    OUT PNL_SITEPREFIX_ROD Rod
    )
/*++

Routine Description:

    This function gets the first site prefix entry in a compartment.

Arguments:

    Compartment - Supplies the compartment.

    Key - Returns the SitePrefix Key.

    Rod - Returns the SitePrefix Rod.

Return Value:

    STATUS_SUCCESS on success, STATUS_NO_MORE_ENTRIES if there's no site
        prefixes.

--*/
{
    KIRQL OriginalIrql;
    PLIST_ENTRY Head;
    PIP_SITE_PREFIX_ENTRY Entry;
    NTSTATUS Status = STATUS_SUCCESS;

    ASSERT(Key != NULL);
    
    KeAcquireSpinLock(&Compartment->SitePrefixSet.Lock, &OriginalIrql);

    Head = &Compartment->SitePrefixSet.Set;
    if (Head != Head->Flink) {
        Entry = (PIP_SITE_PREFIX_ENTRY)
            CONTAINING_RECORD(Head->Flink, IP_SITE_PREFIX_ENTRY, Link);

        ASSERT(Entry->Interface != NULL);
        
        Key->InterfaceLuid = Entry->Interface->Luid;
        Key->Prefix = Entry->Prefix;
        Key->PrefixLength = Entry->PrefixLength;
        if (Rod != NULL) {
            Rod->ValidLifetime = Entry->ValidLifetime;
        }
                
    } else {
        Status = STATUS_NO_MORE_ENTRIES;
    }

    KeReleaseSpinLock(&Compartment->SitePrefixSet.Lock, OriginalIrql);
    return Status;
}

NTSTATUS
IppFindSitePrefix(
    IN PIP_COMPARTMENT Compartment,
    IN PIPV6_SITEPREFIX_KEY Key,
    OUT PNL_SITEPREFIX_ROD Rod
    )
/*++

Routine Description:

    This function gets the first site prefix entry in a compartment.

Arguments:

    Compartment - Supplies the compartment.

    Key - Returns the SitePrefix Key.

    Rod - Returns the SitePrefix Rod.

Return Value:

    STATUS_SUCCESS on success, STATUS_NO_MORE_ENTRIES if there's no site
        prefixes.

--*/
{
    KIRQL OriginalIrql;
    PIP_SITE_PREFIX_ENTRY SitePrefixEntry;
    NTSTATUS Status = STATUS_NOT_FOUND;

    ASSERT(Key != NULL);
    
    KeAcquireSpinLock(&Compartment->SitePrefixSet.Lock, &OriginalIrql);
    SitePrefixEntry = 
        IppFindSitePrefixEntryUnderSpinLock(Compartment, Key, NULL, NULL);
    if (SitePrefixEntry != NULL) {
        Status = STATUS_SUCCESS;
        if (Rod != NULL) {
            Rod->ValidLifetime = SitePrefixEntry->ValidLifetime;
        }
    }
    
    KeReleaseSpinLock(&Compartment->SitePrefixSet.Lock, OriginalIrql);
    return Status;
}

NTSTATUS
IppGetNextSitePrefix(
    IN PIP_COMPARTMENT Compartment,
    IN PIPV6_SITEPREFIX_KEY Key,
    OUT PIPV6_SITEPREFIX_KEY NextKey,
    OUT PNL_SITEPREFIX_ROD NextRod
    )
/*++

Routine Description:

    This function gets the first site prefix entry in a compartment.

Arguments:

    Compartment - Supplies the compartment.

    Key - Returns the SitePrefix Key.

    Rod - Returns the SitePrefix Rod.

Return Value:

    STATUS_SUCCESS on success, STATUS_NO_MORE_ENTRIES if there's no site
        prefixes.

--*/
{
    KIRQL OriginalIrql;
    PLIST_ENTRY Head;
    PIP_SITE_PREFIX_ENTRY SitePrefixEntry;
    NTSTATUS Status;

    ASSERT(Key != NULL);
    ASSERT(NextKey != NULL);
    
    Head = &Compartment->SitePrefixSet.Set;
    KeAcquireSpinLock(&Compartment->SitePrefixSet.Lock, &OriginalIrql);
    SitePrefixEntry = 
        IppFindSitePrefixEntryUnderSpinLock(
            Compartment, 
            Key, 
            NextKey,
            NextRod); 
    if (SitePrefixEntry == NULL) {
        Status = STATUS_NOT_FOUND;
    } else if (NextKey->InterfaceLuid.Value == 0) {
        Status = STATUS_NO_MORE_ENTRIES;
    } else {
        Status = STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&Compartment->SitePrefixSet.Lock, OriginalIrql);
    return Status;
}
    

NTSTATUS
NTAPI
IpGetAllSitePrefixParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a given site prefix.

Arguments:

    Args - Supplies a structure describing the operation to be performed.

Return Value:

    Status of the operation.

--*/
{
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    COMPARTMENT_ID CompartmentId = UNSPECIFIED_COMPARTMENT_ID;
    PIP_COMPARTMENT Compartment;
    NTSTATUS Status;
    IPV6_SITEPREFIX_KEY NextKey = {0};
    PIPV6_SITEPREFIX_KEY Key;
    PNL_SITEPREFIX_ROD Rod;
    
    ASSERT(IS_IPV6_PROTOCOL(Protocol)) ;
    Key = (PIPV6_SITEPREFIX_KEY) Args->KeyStructDesc.KeyStruct;
    Rod = (PNL_SITEPREFIX_ROD) Args->StructDesc.RoDynamicParameterStruct;

    Compartment = IppGetFirstCompartment(Protocol);
    
    switch (Args->Action) {
    case NsiGetExact:        
        Status = STATUS_NOT_FOUND;
        for (; Compartment != NULL; ) {
            Status = IppFindSitePrefix(Compartment, Key, Rod);
            CompartmentId = Compartment->CompartmentId;
            IppDereferenceCompartment(Compartment);            
            if (NT_SUCCESS(Status)) {
                break;
            }
            Compartment = IppGetNextCompartment(Protocol, CompartmentId);
        }
        break;
        
    case NsiGetNext:
        Status = STATUS_NO_MORE_ENTRIES;
        
        for (; Compartment != NULL; ) {
            Status = 
                IppGetNextSitePrefix(
                    Compartment,
                    Key,
                    &NextKey, 
                    Rod);

            CompartmentId = Compartment->CompartmentId;
            IppDereferenceCompartment(Compartment);           
            if (NT_SUCCESS(Status) || Status == STATUS_NO_MORE_ENTRIES) {
                break;
            }
            Compartment = IppGetNextCompartment(Protocol, CompartmentId);
        }

        if (NT_SUCCESS(Status)) {
            RtlCopyMemory(Key, &NextKey, sizeof(NextKey));
            return Status;
        } else if (Status == STATUS_NOT_FOUND) {
            //
            // Can't find the entry, it might be deleted after last query.
            //
            return STATUS_NO_MORE_ENTRIES;
        } else {
            //
            // Previous entry is the last in the current compartment.
            // Get the first entry of next compartment.
            // Fall over.
            //
            Compartment = IppGetNextCompartment(Protocol, CompartmentId);
        }

    case NsiGetFirst:
        Status = STATUS_NO_MORE_ENTRIES;
        for (; Compartment != NULL; ) {
            Status = 
                IppGetFirstCompartmentSitePrefix(
                    Compartment,
                    Key, 
                    Rod);

            CompartmentId = Compartment->CompartmentId;
            IppDereferenceCompartment(Compartment);

            if (NT_SUCCESS(Status)) {
                break;
            }
            
            Compartment = IppGetNextCompartment(Protocol, CompartmentId);
        }
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }
    
    return Status;
}

NTSTATUS
IppConfigureIscsiTargetAndDefaultRoutes(
    IN PIP_INTERFACE Interface,
    IN PISCSI_BOOT_NIC TcpipIscsiBootParameters,
    IN ULONG NumberTargets,
    IN PUCHAR Gateway
    )
{
    NTSTATUS Status;
    ULONG i;
    UCHAR RouteKey[ROUTE_KEY_STORAGE_SIZE];
    USHORT RouteKeyLength;
    PIP_UNICAST_ROUTE TargetRoute;
    IP_ADDRESS_STORAGE Destination = {0};
    
    PISCSI_BOOT_TARGET Targets = (PISCSI_BOOT_TARGET)
        ((PUCHAR)TcpipIscsiBootParameters + sizeof(ISCSI_BOOT_NIC));
    
    USHORT DestinationLength = 
        Interface->Compartment->Protocol->Characteristics->AddressBytes;
    UINT8 DestinationLengthinBits = (UINT8)DestinationLength * 8;
            
    Status = IppUpdateUnicastRoute(
        NsiSetCreateOrSet,
        Interface,
        NULL,
        (PUCHAR)&Destination,
        0,
        NULL,
        0,
        NlroManual,
        NULL,
        Gateway
        );        

    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: ISCSI boot: Error adding default gateway for iscsi interface: "
                   "Status %d NIC index = %d",
                   Status, TcpipIscsiBootParameters->Header.Index);        
    }
    
    //
    // Add a host specific route for the target as well. Mark this route 
    // as system critical. We will not allow this route to be deleted.
    //        

    for (i = 0; i < NumberTargets; i++) {
        if (IS_IPV4_PROTOCOL(Interface->Compartment->Protocol) != 
            IN6_IS_ADDR_V4MAPPED((IN6_ADDR*)(&Targets[i].IpAddress))) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: ISCSI boot: Invalid Target NIC association: "
                   "Target index = %d",
                   Targets[i].Header.Index);
            continue;
        }

        __analysis_assume(sizeof(Destination) >= DestinationLength);
        
        RtlCopyMemory(
            (PUCHAR)&Destination,
            IS_IPV4_PROTOCOL(Interface->Compartment->Protocol) ?
            IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)(&Targets[i].IpAddress)) :
            Targets[i].IpAddress,
            DestinationLength);
    
        Status = IppUpdateUnicastRoute(
            NsiSetCreateOrSet,
            Interface,
            NULL,
            (PUCHAR)&Destination,
            DestinationLengthinBits,
            NULL,
            0,
            NlroManual,
            NULL,
            Gateway);
        
        if (NT_SUCCESS(Status)) {
            Interface->Compartment->Protocol->
                MakeRouteKey(
                    (PUCHAR)&Destination, 
                    DestinationLengthinBits,
                    NULL, 
                    0,
                    RouteKey, 
                    &RouteKeyLength);

            Status =
                IppFindUnicastRoute(
                    RouteKey, 
                    RouteKeyLength,
                    Interface->Compartment,
                    Interface,
                    Gateway,
                    &TargetRoute);

            if (NT_SUCCESS(Status)) {
                TargetRoute->SystemCritical = TRUE;
                IppDereferenceRoute((PIP_ROUTE)TargetRoute);
            }
        }
    }        
    return STATUS_SUCCESS;
}
