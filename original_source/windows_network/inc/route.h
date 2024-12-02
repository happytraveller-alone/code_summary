/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    route.h

Abstract:

    This module contains declarations for the network layer module's
    route management.

Author:

    Mohit Talwar (mohitt) Tue Nov 19 09:57:14 2002

Environment:

    Kernel mode only.

--*/

#ifndef _ROUTE_
#define _ROUTE_

#pragma once

//
// Timeout after which path MTU is increased (default: 10 minutes).
//
#define PATH_MTU_DISCOVERY_TIMEOUT (IppMilliseconds(10 * MINUTES)) 

#define IP_PATH_BUCKET_UNKNOWN  0xFFFFFFFF

#define IS_PATH_VALID(Path, Compartment) \
     ((Compartment)->RoutingEpoch == (Path)->RoutingEpoch)

//
// Constants related to dead gateway detection. 
//

//
// Time for which a dead gateway stays in the probe state.  If the gateway does
// not get any positive reacability notification during this time, then the
// gateway moves back to the dead state.  If the gateway
// gets a positive reachability notification, it moves into alive state.
// If it receives a negative notification, it moves into dead state. 
//
#define DEAD_ROUTE_PROBE_TIMEOUT IppTimerTicks(5 * MINUTES)

//
// Time for which a dead gateway stays in the dead state before moving into the
// probe state. 
//
#define DEAD_ROUTE_TIMEOUT IppTimerTicks(5 * MINUTES)

//
// The time for which a path unreachability notification from the transport
// layer is valid.  If two or more such notifications are received from the
// transport layer within the timeout, then the path is changed to use a new
// gateway. 
//
#define PATH_UNREACHABLE_TIMEOUT IppTimerTicks(1 * MINUTES)

//
// The percentage of new connections that are directed to a dead gateway in the
// probe state.
//
#define DEAD_ROUTE_PROBE_TRAFFIC_PERCENT 10 

//
// Default limit on the number of cached paths. 
//
#define IP_DEFAULT_PATH_CACHE_LIMIT 128 

//
// IPR_LINK
//
// Define the network layer route set link.
// Routes are stored in an atomic prefix tree.
//

typedef PREFIX_TREE_LINK IPR_LINK, *PIPR_LINK;

//
// IPR_LOCKED_SET
//
// Define the network layer route set state.
//
// Tree::SpinLock protects RouteSet::TimerTable and Route::Timer as well.
//

typedef struct _IPR_LOCKED_SET {
    RTL_SCALABLE_MRSW_LOCK Lock;
    HANDLE Tree;
    PTIMER_TABLE TimerTable;    // Priority queue of route timeout events. 
} IPR_LOCKED_SET, *PIPR_LOCKED_SET;


__inline
NTSTATUS
IppInitializeIprLockedSet(
    IN PIPR_LOCKED_SET RouteSet,
    IN ULONG KeySize 
    )
{
    NTSTATUS Status;
    
    Status = PtCreateTable(KeySize * RTL_BITS_OF(CHAR), &RouteSet->Tree);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RouteSet->TimerTable = TtCreateTable(16, FALSE);
    if (RouteSet->TimerTable == NULL) {
        PtDestroyTable(&RouteSet->Tree);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitializeScalableMrswLock(&RouteSet->Lock, 0);

    return STATUS_SUCCESS;
}

__inline
VOID
IppUninitializeIprLockedSet(
    PIPR_LOCKED_SET RouteSet
    )
{
    RtlUninitializeScalableMrswLock(&RouteSet->Lock);
    
    TtDestroyTable(RouteSet->TimerTable);
    RouteSet->TimerTable = NULL;

    PtDestroyTable(&RouteSet->Tree);
}


//
// Next hop related routines. 
//

typedef struct _IP_NEXT_HOP {
    ULONG Signature;
    LONG ReferenceCount;
    PIP_INTERFACE Interface;
} IP_NEXT_HOP, *PIP_NEXT_HOP;

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR, ReferenceCount) ==
         FIELD_OFFSET(IP_LOCAL_ADDRESS, ReferenceCount));
         
C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR, Interface) ==
         FIELD_OFFSET(IP_LOCAL_ADDRESS, Interface));
         
__inline
VOID
IppCleanupNextHop(
    IN PIP_NEXT_HOP NextHop
    )
{
    switch(NextHop->Signature) {
    case IP_NEIGHBOR_SIGNATURE:
        IppCleanupNeighbor((PIP_NEIGHBOR) NextHop);
        return;
    case IP_LOCAL_ADDRESS_SIGNATURE:
        IppCleanupLocalAddress((PIP_LOCAL_ADDRESS) NextHop);
        return;
    default:
        ASSERT(FALSE);
    }
}

#if (NEIGHBOR_REFHIST || ADDRESS_REFHIST)

#define IppDereferenceNextHop(NextHop) \
{ \
    switch((NextHop)->Signature) { \
    case IP_NEIGHBOR_SIGNATURE: \
        IppDereferenceNeighbor((PIP_NEIGHBOR) (NextHop)); \
        break; \
    case IP_LOCAL_ADDRESS_SIGNATURE: \
        IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) (NextHop)); \
        break; \
    default: \
        ASSERT(FALSE); \
    } \
}

#define IppReferenceNextHop(NextHop) \
{ \
    switch((NextHop)->Signature) { \
    case IP_NEIGHBOR_SIGNATURE: \
        IppReferenceNeighbor((PIP_NEIGHBOR) (NextHop)); \
        break; \
    case IP_LOCAL_ADDRESS_SIGNATURE: \
        IppReferenceLocalAddress((PIP_LOCAL_ADDRESS) (NextHop)); \
        break; \
    default: \
        ASSERT(FALSE); \
    } \
}

#define IppReferenceNextHopEx(NextHop, Count) \
{ \
    switch((NextHop)->Signature) { \
    case IP_NEIGHBOR_SIGNATURE: \
        IppReferenceNeighborEx((PIP_NEIGHBOR) (NextHop), (Count)); \
        break; \
    case IP_LOCAL_ADDRESS_SIGNATURE: \
        IppReferenceLocalAddressEx((PIP_LOCAL_ADDRESS) (NextHop), (Count)); \
        break; \
    default: \
        ASSERT(FALSE); \
    } \
}

#else  // (NEIGHBOR_REFHIST || ADDRESS_REFHIST)

#define IppCleanupNextHopPrimitive IppCleanupNextHop

DEFINE_REFERENCE_ROUTINES(PIP_NEXT_HOP, NextHopPrimitive, Ipp)

//
// A special-cased version of IppDereferenceLocalAddress is required to 
// handle dereferencing of local multicast addresses.
//
#define IppDereferenceNextHop(NextHop) \
{ \
    switch((NextHop)->Signature) { \
    case IP_LOCAL_ADDRESS_SIGNATURE: \
        IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) (NextHop)); \
        break; \
    default: \
        ASSERT((NextHop)->Signature == IP_NEIGHBOR_SIGNATURE); \
        IppDereferenceNeighbor((PIP_NEIGHBOR) (NextHop)); \
    } \
}

#define IppReferenceNextHop IppReferenceNextHopPrimitive
#define IppReferenceNextHopEx IppReferenceNextHopPrimitiveEx
#endif // (NEIGHBOR_REFHIST || ADDRESS_REFHIST)
    
__inline
BOOLEAN
IppIsNextHopNeighbor(PIP_NEXT_HOP NextHop) {
    return (NextHop->Signature == IP_NEIGHBOR_SIGNATURE);
}

__inline
BOOLEAN
IppIsNextHopLocalAddress(PIP_NEXT_HOP NextHop) {
    return (NextHop->Signature == IP_LOCAL_ADDRESS_SIGNATURE);
}

NL_PROVIDER_REFERENCE_NEXT_HOP IpNlpReferenceNextHop;
NL_PROVIDER_DEREFERENCE_NEXT_HOP IpNlpDereferenceNextHop;
NL_PROVIDER_GET_NEXTHOP_FROM_PATH IpNlpGetNextHopFromPath;

__inline
IF_INDEX
IppGetNextHopSubInterfaceIndex(PIP_NEXT_HOP NextHop) 
{
    switch(NextHop->Signature) {
    case IP_NEIGHBOR_SIGNATURE:
        return ((PIP_NEIGHBOR) NextHop)->SubInterface->Index;
    case IP_LOCAL_ADDRESS_SIGNATURE:
        return IFI_UNSPECIFIED;
    default:
        ASSERT(FALSE);
        return IFI_UNSPECIFIED;
    }
}

__inline
ULONG
IppGetMtuFromNextHop(PIP_NEXT_HOP NextHop) 
{
    switch(NextHop->Signature) {
    case IP_NEIGHBOR_SIGNATURE:
        return ((PIP_NEIGHBOR) NextHop)->SubInterface->NlMtu;
    case IP_LOCAL_ADDRESS_SIGNATURE:
        return (ULONG) -1;
    default:
        ASSERT(FALSE);
        return 0;
    }
}

__inline
PUCHAR 
IppAddressFromNextHop(
    IN PIP_NEXT_HOP NextHop
    )
{
    static IP_ADDRESS_STORAGE ZeroAddress = {0};
    
    switch(NextHop->Signature) {
    case IP_NEIGHBOR_SIGNATURE:
        return (PUCHAR) IP_NEIGHBOR_NL_ADDRESS((PIP_NEIGHBOR) NextHop);
    case IP_LOCAL_ADDRESS_SIGNATURE:
        return (PUCHAR) NL_ADDRESS((PIP_LOCAL_ADDRESS) NextHop);
    default:
        ASSERT(FALSE);
    return (PUCHAR) &ZeroAddress;
    }
}

//
// Add a new type of structure called IPP_PATH_SET.
//
typedef struct _IPP_PATH_SET {
    RTL_SCALABLE_MRSW_LOCK Lock;
    ULONG LastEnumerationTick;
    ULONG DelayBeforeNextEnumeration;
    ULONG LastIterationPathCount;
    ULONG CachedPathEstimate;
    ULONG CachedPathsScavenged;
    ULONG CachedPathEstimateDuringEnumeration;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    RTL_HASH_TABLE Table;
} IPP_PATH_SET, *PIPP_PATH_SET;

#define IPP_PATHSET_ENUM_DELAY              IppTimerTicks(30)
#define IPP_PATHS_EVALUATED_PER_ITERATION   5000
#define IPP_NUM_PATHS_INCREASE_THRESHOLD    IPP_PATHS_EVALUATED_PER_ITERATION
#define IPP_SCAVENGED_PATH_THRESHOLD_FOR_GC 500
#define IPP_MAX_CACHED_PATHS                500

#define IPP_PATH_THRESHOLD_FOR_GC_SERVER    50000
#define IPP_MAX_PATHS_SERVER                100000
#define IPP_MAX_CACHED_PATH_AGE_SERVER      IppTimerTicks(60)

#define IPP_PATH_THRESHOLD_FOR_GC_CLIENT    10000
#define IPP_MAX_PATHS_CLIENT                20000
#define IPP_MAX_CACHED_PATH_AGE_CLIENT      IppTimerTicks(10)

NTSTATUS
IppInitializePathSet(
    IN PIPP_PATH_SET PathSet
    );

VOID
IppUninitializePathSet(
    IN PIPP_PATH_SET PathSet
    );

VOID
IppPathSetTimeout(
    IN PIP_COMPARTMENT Compartment
    );


//
// NL_ROUTE_FLAGS
//
// Define route flags.
//
// The Publish flag indicates that the route can be visible
// when sending Router Advertisements.  That is, it is a "public" route.
// The Immortal flag indicates that the route's lifetime
// does not age or countdown. It is useful in PUBLISHed routes,
// where the route's lifetime affects the lifetime in RAs.
// In non-Published routes it is equivalent to an infinite lifetime.
// The AutoconfigureAddress flag indicates that the route should be used for
// autonomous address configuration.  It is only relevant for Published routes.
//

typedef union _NL_ROUTE_FLAGS {
    ULONG Value;
    struct {
        BOOLEAN Loopback : 1;       // Next hop is a local address.

        //
        // Flags used when sending router-advertisements.
        //
        BOOLEAN Publish : 1;
        BOOLEAN Immortal : 1;
        BOOLEAN AutoconfigureAddress : 1;

        BOOLEAN Deleted : 1;        // Marked for deletion.
        BOOLEAN Ignore : 1;         // Marked to be ignored.
        BOOLEAN InRouteSet : 1;     // Route exists in the set.
    };
} NL_ROUTE_FLAGS, *PNL_ROUTE_FLAGS;

typedef struct _IP_ROUTE {
    IPR_LINK Link; // Linkage in prefix tree.
    
    //
    // Linkage for multiple routes to the same destination.
    //
    LIST_ENTRY RouteLink; 

    ULONG Signature;
    NL_ROUTE_FLAGS Flags;
    LONG ReferenceCount;
    LONG UserReferenceCount;
    NL_ROUTE_ORIGIN Origin;
    PIP_INTERFACE Interface;
} IP_ROUTE, *PIP_ROUTE;

typedef enum _IP_ROUTE_STATE {
    RouteAlive = 0,  // Route is alive and usable. 
    RouteDead,       // Route is dead. 
    RouteProbe       // Route is in probe state.  A small percentage of the
                     // connections use this route.
} IP_ROUTE_STATE;

typedef struct _IP_UNICAST_ROUTE {
    IP_ROUTE;
    UCHAR SitePrefixLength;
    TIMER_ENTRY Timer;
    ULONG CreationTime;         // In timer ticks.
    ULONG ValidLifetime;        // In timer ticks.
    ULONG PreferredLifetime;    // In timer ticks.
    ULONG Metric;
    NL_ROUTE_PROTOCOL Protocol;

    //
    // Number of paths using this route.  Used for dead gateway detection.
    //
    ULONG PathCount;

    //
    // Dead gateway state for the route and time when the state last changed. 
    // 
    IP_ROUTE_STATE State;
    ULONG StateChangeTick;

    //
    // This route is system critical - used to boot from a remote disk.
    //
    BOOLEAN SystemCritical;
    
    union {
        PIP_LOCAL_ADDRESS LocalAddress;

        //
        // Neighbor, may be NULL for an on-link route.
        //
        PIP_NEIGHBOR CurrentNextHop;
    };
} IP_UNICAST_ROUTE, *PIP_UNICAST_ROUTE;

//
// The next hop's address is stored past the base structure.
// See IPV6_UNICAST_ROUTE & IPV4_UNICAST_ROUTE.
//
// The following macro returns the next hop address to the calling function. 
// Once we support remote next hops, the next hop address saved on the route
// is not the same as the CurrentNextHop's address.  It is valid to create a 
// route where the next hop address is actually more than 1 hop away.  In 
// such case, a recursive lookup will be performed until the actual next hop 
// is located.
//
#define IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route) \
    ((PUCHAR) (((PIP_UNICAST_ROUTE) (Route)) + 1))

NM_PROVIDER_REGISTER_CHANGE_NOTIFICATION IpRegisterRouteChangeNotification;
NM_PROVIDER_DEREGISTER_CHANGE_NOTIFICATION IpDeregisterRouteChangeNotification;

__inline
CONST
UCHAR *
IppGetFirstHopAddress(
    IN PIP_UNICAST_ROUTE Route
    )
{    
    if (Route->Flags.Loopback) {
        //
        // First hop is a local address (unicast or broadcast).
        //
        return NL_ADDRESS(Route->LocalAddress);
    } else if (Route->CurrentNextHop != NULL) {
        //
        // First hop is in the neighbor entry.
        // Not necessarily the same as the next hop (e.g. remote next hop).
        //
        return IP_NEIGHBOR_NL_ADDRESS(Route->CurrentNextHop);
    } else {
        //
        // There is no neighbor entry, hence return the NextHopAddress.
        // REVIEW: Should we instead force a recursive lookup?
        //
        return IP_UNICAST_ROUTE_NEXT_HOP_ADDRESS(Route);
    }
}


VOID
IppSetAllRouteState(
    IN PIP_UNICAST_ROUTE Route, 
    IN IP_ROUTE_STATE State, 
    IN CONST UCHAR *NextHop OPTIONAL
    );

typedef struct _IP_ROUTE_NOTIFY_CONTEXT {
    PIP_UNICAST_ROUTE UnicastRoute;
    union {
        IPV4_ROUTE_KEY Ipv4Key;
        IPV6_ROUTE_KEY Ipv6Key;
        UCHAR RouteKey;
    };
} IP_ROUTE_NOTIFY_CONTEXT, *PIP_ROUTE_NOTIFY_CONTEXT;

VOID
IppNotifyRouteChangeAtPassive(
    IN PVOID Context
    );

VOID
IppNotifyRouteChange(
    IN PIP_UNICAST_ROUTE UnicastRoute,
    IN NSI_NOTIFICATION NotificationType
    );


#define IP_PATH_INFO_MAX_AGE    (IppSecondsToTicks(30))
#define IP_BANDWIDTH_INFO_MAX_AGE (IppSecondsToTicks(2))

typedef struct _IP_PATH_BANDWIDTH_DIRECTION {
    //
    // Number of clients listening to this bandwidth estimation.
    //
    ULONG ReferenceCount;

    //
    // Estimated achievable bandwidth, in bits per second.
    //
    ULONG64 Bandwidth;

    //
    // A measure of the variation in recent bandwidth samples, in bits per
    // second.
    //
    ULONG64 Instability;

    //
    // Time (tick count) of the last bandwidth maximum.
    //
    ULONG LastSample;

    //
    // Our best guess at whether or not the bandwidth estimate has peaked.
    // Until the peak has been achieved, we cannot guarantee that the true
    // available bandwidth is not higher than the estimate.  However, we can
    // almost always be sure that the available bandwidth is not less than the
    // estimate.
    //
    BOOLEAN BandwidthPeaked;

    //
    // Whether we've received any indication from the transport layer that good
    // bandwidth estimation is not achievable.  This is usually caused by
    // certain connection properties (e.g. the RTT being too small).
    //
    BOOLEAN EstimateUnavailable;
} IP_PATH_BANDWIDTH_DIRECTION, *PIP_PATH_BANDWIDTH_DIRECTION;

typedef struct _IP_PATH_BANDWIDTH {
    //
    // For memory efficiency, only a single spinlock is used to synchronize
    // access to both bandwidth estimation blocks.  If the bandwidth estimation
    // path becomes heavily used and contention becomes a problem, alternate
    // mechanisms should be considered (including a spinlock per block, or 
    // RoReference control of each block).
    //
    KSPIN_LOCK SpinLock;

    //
    // Tracking state for outbound bandwidth estimation if enabled on the path.
    // When not enabled, this pointer is null.
    //
    PIP_PATH_BANDWIDTH_DIRECTION Out;

    //
    // Tracking state for inbound bandwidth estimation if enabled on the path.
    // When not enabled, this pointer is null.
    //
    PIP_PATH_BANDWIDTH_DIRECTION In;
} IP_PATH_BANDWIDTH, *PIP_PATH_BANDWIDTH;

typedef struct _IP_PATH {
    //
    // Immutable fields: The following fields are immutable.    
    // They do not change during the lifetime of the path and can be safely
    // accessed without validating them. The SourceAddress and
    // DestinationAddress fields define the key of the path (they can never
    // change and they uniquely define a path).  In XP IPv6, these fields were
    // in the TCB/AO structures, but now we can share them among multiple
    // connections to save space.
    //
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress;
    SCOPE_ID ScopeId;
    PUCHAR DestinationAddress;

    //
    // Validation counter values.
    //
    LONG RoutingEpoch;
    LONG PathEpoch;
    ULONG LastConfirmation; // Timestamp of last confirmation (in timer ticks).
    //
    // Count of active connections maintained by ALE.
    //
    ULONG ActiveConnectionCount;

    //
    // These flags are protected by the path set lock.
    // They are always written while holding the write lock.
    // They might be read without the lock while searching for a path.
    //
    IP_PATH_FLAGS Flags;

    //
    // If adding any fields before this point, make sure to change NL_PATH and
    // IP_PATH_PRIVATE to match the field order.  Also inform test group to
    // update their data structure.
    //
    
    //
    // Pending offload requests of all types.
    //
    SLIST_HEADER OffloadRequestQueue;

    //
    // Offload block structures, if offloaded.
    // These allow terminates to complete without requiring an allocation.
    //
    SLIST_HEADER OffloadedBlocks;
    
    //
    // Returned by the NIC during an offload or an upload,
    // Supplied to the NIC in other requests such as update.
    //
    NDIS_OFFLOAD_HANDLE OffloadHandle;

    //
    // Current position in the offload state machine, as controlled by the NL.
    //
    IP_OFFLOAD_OBJECT Offload;

    //
    // If offloaded, a pointer to the neighbor the NIC has.
    //
    PIP_NEIGHBOR OffloadedNeighbor;

    //
    // Mutable fields: 
    // The following fields can change over time. 
    //

    //
    // Link for linking into the path cache hash table. 
    //

    RTL_HASH_TABLE_ENTRY Link;
    
    //
    // Boolean indicating whether the last forward reachability indication from
    // the transport layer indicated whether the path was reachable or not.
    // Protected by the path set lock.
    //
    BOOLEAN IsReachable;
    
    ULONG Signature;

    //
    // Reference count. This is a mutable field but is here to ensure packing
    // of the structure. 
    //
    ULONG ReferenceCount;

    //
    // Timestamp in ticks (when is the last time this path was referenced). 
    //
    ULONG LastUsed;
    
    //
    // Time of last ICMP error (in timer ticks).
    //
    ULONG LastError;
    
    //
    // MTU of path to destination. Includes the IP header length.
    //
    ULONG PathMtu;

    //
    // Time (tick count) of last PMTU reduction.
    //
    ULONG PathMtuLastSet;

    //
    // Estimated mean RTT.
    //
    ULONG RttMean;

    //
    // Mean deviation of RTT.
    //
    ULONG RttDeviation;

    //
    // Time (tick count) of last RTT sample.
    //
    ULONG RttLastSample;

    //
    // Tracking and synchronization state for estimation of the available
    // fair-share bandwidth across this path.
    //
    IP_PATH_BANDWIDTH Bandwidth;

    //
    // Timestamp (in ticks) when the last reachable or unreachable notification
    // was received from the transport layer.
    // Protected by the path set lock.
    //
    union {
        ULONG LastReachable;
        ULONG LastUnreachable;
    };
     
    //
    // The current route used, mainly required for dead gateway detection.
    // This can change over the lifetime of a path.
    // Note: The route can be NULL even though the next hop is not NULL if,
    // for instance, the next hop was set by a redirect.
    // Protected by the path set lock.
    //
    PIP_UNICAST_ROUTE Route;
     
    //
    // The current next hop.  This can change over the lifetime of a path. 
    // Protected by the path set lock.
    //
    PIP_NEXT_HOP CurrentNextHop;

#ifdef _IP_OFFLOAD_LOGGING
    PIP_OFFLOAD_LOG OffloadLog;
#endif // _IP_OFFLOAD_LOGGING
} IP_PATH, *PIP_PATH;

C_ASSERT(FIELD_OFFSET(NL_PATH, SourceAddress) ==
         FIELD_OFFSET(IP_PATH, SourceAddress));
C_ASSERT(FIELD_OFFSET(NL_PATH, ScopeId) ==
         FIELD_OFFSET(IP_PATH, ScopeId));
C_ASSERT(FIELD_OFFSET(NL_PATH, DestinationAddress) ==
         FIELD_OFFSET(IP_PATH, DestinationAddress));

#ifndef _IP_OFFLOAD_LOGGING
C_ASSERT(sizeof(IP_PATH) < PAGE_SIZE/16);
#endif // _IP_OFFLOAD_LOGGING

C_ASSERT(FIELD_OFFSET(IP_PATH_PRIVATE, RoutingEpoch) ==
         FIELD_OFFSET(IP_PATH, RoutingEpoch));

C_ASSERT(FIELD_OFFSET(IP_PATH_PRIVATE, PathEpoch) ==
         FIELD_OFFSET(IP_PATH, PathEpoch));

C_ASSERT(FIELD_OFFSET(IP_PATH_PRIVATE, LastConfirmation) ==
         FIELD_OFFSET(IP_PATH, LastConfirmation));

C_ASSERT(FIELD_OFFSET(IP_PATH_PRIVATE, ActiveConnectionCount) ==
         FIELD_OFFSET(IP_PATH, ActiveConnectionCount));

C_ASSERT(FIELD_OFFSET(IP_PATH_PRIVATE, Flags) ==
         FIELD_OFFSET(IP_PATH, Flags));

//
// IP_SITE_PREFIX_SET
//
// Set of site prefixes stored in every compartment. 
//
typedef SPIN_LOCKED_LIST IP_SITE_PREFIX_SET, *PIP_SITE_PREFIX_SET;

//
// IP_SITE_PREFIX_ENTRY.
// 
// Define a structure for storing site prefixes received in router
// advertisments. Each entry contains a single site prefix and site prefix
// length received from a router. There is also a valid lifetime associated
// with it and the entry is removed after the lifetime expires. There is no
// explicit timeout for this, though. Every time we traverse the site prefix
// list (on receiving a new router advertisment or for accessing the site
// prefix data), we check to make sure if an entry is invalid and if it is, we
// remove it. 
//
typedef struct _IP_SITE_PREFIX_ENTRY {
    NLI_LINK Link;
    PIP_INTERFACE Interface;
    ULONG LifetimeBaseTime;
    ULONG ValidLifetime;
    UCHAR PrefixLength;
    IN6_ADDR Prefix;
} IP_SITE_PREFIX_ENTRY, *PIP_SITE_PREFIX_ENTRY;
    
//
// Internal Route Manager functions
//
NTSTATUS
IppStartRouteManager(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopRouteManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupRouteManager(
    IN PIP_PROTOCOL Protocol
    );

NL_PROVIDER_JOIN_PATH IpNlpJoinPath;
NL_PROVIDER_LEAVE_PATH IpNlpLeavePath;
NL_PROVIDER_INITIATE_OFFLOAD IpNlpInitiatePathOffload;
NL_PROVIDER_TERMINATE_OFFLOAD IpNlpTerminatePathOffload;
NL_PROVIDER_UPDATE_OFFLOAD IpNlpUpdatePathOffload;
NL_PROVIDER_QUERY_PATH_INFORMATION IpNlpQueryPathInfomation;
NL_PROVIDER_SET_PATH_INFO IpNlpSetPathInfo;
NL_PROVIDER_SUSPECT_PATH_REACHABILITY IpNlpSuspectPathReachability;
NL_PROVIDER_SUSPECT_NEIGHBOR_REACHABILITY IpNlpSuspectNeighborReachability;
NL_PROVIDER_CONFIRM_FORWARD_REACHABILITY IpNlpConfirmForwardReachability;

NTSTATUS
IppJoinPath(
    IN PIP_PROTOCOL Protocol, 
    IN PNL_REQUEST_JOIN_PATH Args
    );

VOID
IppFillPathInformation(
    IN PIP_PATH Path,
    IN PIP_SESSION_STATE State OPTIONAL,
    OUT PNL_PATH_INFO PathInformation,
    OUT PULONG IpOptionLength
    );

VOID
IppFreeRoute(
    IN PIP_ROUTE *RoutePointer
    );

__inline
VOID
IppReferenceRoute(
    IN PIP_ROUTE Route
    )
{
    ASSERT(Route->ReferenceCount > 0);
    InterlockedIncrement(&Route->ReferenceCount);
}

__inline
VOID
IppReferenceRouteForUser(
    IN PIP_UNICAST_ROUTE Route
    )
{
    //
    // The route table is always locked for edit when this is called, thus
    // there is no need to interlock.
    //
    Route->UserReferenceCount++;
}

VOID
IppGarbageCollectRouteTable(
    IN PIP_COMPARTMENT Compartment
    );

VOID
IppUpdateUnicastRouteLifetimes(
    IN PIPR_LOCKED_SET RouteSet,
    IN OUT PIP_UNICAST_ROUTE Route
    );

NTSTATUS
IppFindUnicastRouteUnderLock(
    IN CONST UCHAR *Key,
    IN USHORT KeyLength,
    IN PIP_COMPARTMENT Compartment,
    IN CONST IP_INTERFACE *Interface OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL,
    OUT PIP_UNICAST_ROUTE *RoutePtr
    );

NTSTATUS
IppFindUnicastRoute(
    IN CONST UCHAR *Key,
    IN USHORT KeyLength,
    IN PIP_COMPARTMENT Compartment,
    IN CONST IP_INTERFACE *Interface OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL,
    OUT PIP_UNICAST_ROUTE *RoutePtr
    );


VOID
IppDeleteUnicastRoute(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route
    );


NTSTATUS
IppUpdateUnicastRoute(
    IN NSI_SET_ACTION SetAction,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength, 
    CONST UCHAR *SourcePrefix, 
    IN UINT8 SourcePrefixLength, 
    IN NL_ROUTE_ORIGIN Origin,
    IN CONST NL_ROUTE_RW *RouteRw OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL
    );

NTSTATUS
IppUpdateUnicastRouteUnderLock(
    IN NSI_SET_ACTION SetAction,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength, 
    CONST UCHAR *SourcePrefix, 
    IN UINT8 SourcePrefixLength, 
    IN NL_ROUTE_ORIGIN Origin,
    IN CONST NL_ROUTE_RW *RouteRw OPTIONAL,
    IN CONST UCHAR *NextHopAddress OPTIONAL,
    IN PIP_LOCAL_ADDRESS LocalAddress OPTIONAL
    );

NTSTATUS
IppRouteToDestination(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *DestinationAddress,
    IN SCOPE_ID DestinationScopeId,
    IN PIP_INTERFACE ConstrainInterface OPTIONAL,
    IN CONST IP_LOCAL_ADDRESS *LocalAddress OPTIONAL,
    OUT PIP_PATH *PathPointer
    );

__inline
NTSTATUS
IppRouteToDestinationInternal(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *DestinationAddress,
    IN PIP_INTERFACE ConstrainInterface,
    IN CONST IP_LOCAL_ADDRESS *LocalAddress OPTIONAL,
    OUT PIP_PATH *PathPointer
    )
/*++

Routine Description:
   
    This routine looks up the route to the destination.  This is similar to
    IppRouteToDestination except that the contrained interface is not
    optional. So the scope ID can be computed from the address and the
    interface and there is no need to specify the scope ID.  This routine is
    mostly used for internal network layer components (for instance, for
    sending ND, IGMP packets etc).

--*/ 
{
    return IppRouteToDestination(
        Compartment, 
        DestinationAddress, 
        IppGetScopeId(ConstrainInterface, DestinationAddress), 
        ConstrainInterface, 
        LocalAddress, 
        PathPointer);
}

VOID
IppRemoveSitePrefixEntry(
    IN PIP_SITE_PREFIX_ENTRY SitePrefixEntry
    );

VOID
IppDeleteSitePrefixes(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_INTERFACE Interface
    );

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
    );

PIP_PATH
IppFindPath(
    IN PIP_COMPARTMENT Compartment,
    IN OUT ULONG *BucketIndexPointer,
    IN CONST UCHAR *DestinationAddress,
    IN SCOPE_ID DestinationScopeId,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN CONST IP_LOCAL_UNICAST_ADDRESS *ConstrainSourceAddress OPTIONAL
    );

PIP_PATH
IppFindNextPathUnderLock(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_PATH Path
    );

NTSTATUS
IppFindOrCreatePath(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *DestinationAddress,
    IN SCOPE_ID DestinationScopeId,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN PIP_LOCAL_UNICAST_ADDRESS ConstrainSourceAddress OPTIONAL,
    OUT PIP_PATH *PathPointer
    );

PIP_LOCAL_UNICAST_ADDRESS
IppFindAndUpdateLocalAddressInPathCacheAtDpcLevel(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *RemoteAddress,
    IN CONST UCHAR *LocalAddress,
    IN PIP_INTERFACE ArrivalInterface,
    IN ULONG ReferenceIncrement
    );

ULONG
IppGetMtuFromPath(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_PATH Path,
    IN PIP_NEIGHBOR Neighbor
    );

VOID
IppUpdatePathMtu(
    IN PIP_PATH Path, 
    IN ULONG NewMtu
    );

PIPP_PATH_SET
IppGetPathSetFromPath(
    IN PIP_PATH Path
    );


VOID
IppUpdatePathNotification(
    IN PIP_COMPARTMENT Compartment, 
    IN PIP_PATH Path
    );

VOID
IppDereferenceRoute(
    IN PIP_ROUTE Route
    );


VOID
IppCleanupPathPrimitive(
    IN PIP_PATH Path
    );

#if PATH_REFHIST
extern PREFERENCE_HISTORY IppPathReferenceHistory;

DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_PATH, PathPrimitive, Ipp, IppPathReferenceHistory)
#else

DEFINE_REFERENCE_ROUTINES(PIP_PATH, PathPrimitive, Ipp)

#endif


NETIO_INLINE
ULONG 
IppDereferencePath(
    IN PIP_PATH Path
    )
{
    ULONG ReferenceCount;
    Path->LastUsed = IppTickCount;
#if PATH_REFHIST
    ReferenceCount = _IppDereferencePathPrimitive((Path), __LINE__, __FILE__);
#else
    ReferenceCount = IppDereferencePathPrimitive((Path));
#endif
    return ReferenceCount;
}

NETIO_INLINE
ULONG
IppReferencePath(
    IN PIP_PATH Path
    )
{
    ULONG ReferenceCount;
#if PATH_REFHIST
    ReferenceCount =  _IppReferencePathPrimitive((Path), __LINE__, __FILE__);
#else
    ReferenceCount =  IppReferencePathPrimitive((Path));
#endif
    Path->LastUsed = IppTickCount;
    return ReferenceCount;
}


VOID
IppGarbageCollectRoutes(
    IN PIP_COMPARTMENT Compartment
    );

VOID
IppRefreshUnicastRoute(
    IN PIP_COMPARTMENT Compartment,    
    IN PIP_UNICAST_ROUTE Route
    );

VOID
IppGarbageCollectPaths(
    IN PIP_COMPARTMENT Compartment
    );

VOID
IppValidatePathUnderLock(
    IN PIP_PATH Path
    );

VOID
IppValidatePath(
    IN PIP_PATH Path
    );

VOID
IppValidatePaths(
    IN PIP_COMPARTMENT Compartment
    );

VOID
IppFlushPaths(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN CONST UCHAR *Destination OPTIONAL,
    IN CONST IP_LOCAL_ADDRESS *Source OPTIONAL
    );

NTSTATUS
IppAddOrRemoveBandwidthListeners(
    IN PIP_PATH Path,
    IN PIP_PATH_BANDWIDTH Bandwidth,
    IN NL_BANDWIDTH_FLAG Outbound,
    IN NL_BANDWIDTH_FLAG Inbound
    );

VOID
IppFillPathRw(
    IN PIP_PATH Path,
    OUT PNL_PATH_RW Rw
    );

VOID
IppFillPathRod(
    IN ULONG AddressBytes,
    IN PIP_PATH Path,
    OUT PNL_PATH_ROD Rod
    );

VOID
IppFillPathRodUnderLock(
    IN ULONG AddressBytes,
    IN PIP_PATH Path,
    OUT PNL_PATH_ROD Rod
    );

VOID
IppInvalidateDestinationCache(
    IN PIP_COMPARTMENT Compartment
    );


__inline
VOID
IppInvalidatePathCachedInformation(
    IN PIP_PATH Path
    )
{
    InterlockedIncrement(&Path->PathEpoch);
}
    
NETIO_INLINE
PIP_PATH
IppGetPathFromPathLink(
    PRTL_HASH_TABLE_ENTRY Link
    )
/*++

Routine Description:

    This routine returns the path pointer from a link pointer embedded within
    the path structure which is used to link the path in a list.  

Arguments:

    Link - Supplies a pointer to the link.

Return Value:

    Returns a pointer to the IP_PATH structure corresponding to the link. 

--*/ 
{
    return CONTAINING_RECORD(Link, IP_PATH, Link);
}

PIP_NEXT_HOP
IppGetNextHopFromPathUnderLock(
    IN PIP_PATH Path
    );

PIP_NEXT_HOP
IppGetNextHopFromPath(
    IN PIP_PATH Path
    );

PIP_NEIGHBOR
IppGetNeighborFromPathUnderLock(
    IN PIP_PATH Path
    );

PIP_NEIGHBOR
IppGetNeighborFromPath(
    IN PIP_PATH Path
    );

VOID
IppSetNextHopInPath(
    IN PIP_PATH Path, 
    IN PIP_NEXT_HOP NextHop OPTIONAL, 
    IN PIP_UNICAST_ROUTE Route OPTIONAL,
    IN LONG RoutingEpoch
    );


__inline
BOOLEAN
IppIsPathOffloadable(
    IN PIP_PATH Path,
    IN PIP_NEIGHBOR Neighbor
    )
{
    //
    // Snapshot the offloaded neighbor.
    //
    PIP_NEIGHBOR OffloadedNeighbor = Path->OffloadedNeighbor;
    PIP_SUBINTERFACE SubInterface;

    //
    // Don't offload the path if the ForceFragment flag is set which means that
    // the fragment header should always be included.
    //
    if ((Path == NULL) || Path->Flags.ForceFragment || (Neighbor == NULL)) {
        return FALSE;
    }

    SubInterface = Neighbor->SubInterface;
    if ((OffloadedNeighbor != NULL) &&
        (OffloadedNeighbor->SubInterface != SubInterface)) {
        //
        // The path no longer goes out the same interface.
        //
        return FALSE;
    }

    //
    // The FL module must have an InitiateOffload handler.
    //
    return ((SubInterface->Interface->FlModule->Npi.Dispatch->
                InitiateOffload != NULL));
}


PIP_UNICAST_ROUTE
IppGetRouteFromPath(
    IN PIP_PATH Path
    );

__inline
VOID
IppSetRouteInPath(
    IN PIP_PATH Path, 
    IN PIP_UNICAST_ROUTE Route
    )
/*++

Routine Description:

    This routine sets the route in a path.  If the path already points to a
    route, the old route is dereferenced.  Also, the PathCount in the routes is
    updated appropriately. 
       
Arguments:

    Path - Supplies the path in which to update the route. 

    Route - Supplies the route.  Consumes a reference to the route. 

Return Value:

    None.

--*/ 
{
    ASSERT_ANY_SCALABLE_LOCK_HELD(&IppGetPathSetFromPath(Path)->Lock);
    
    if (Path->Route != NULL) {
        InterlockedDecrement(&Path->Route->PathCount);
        IppDereferenceRoute((PIP_ROUTE) Path->Route);
    }
    Path->Route = Route;
    if (Path->Route != NULL) {
        InterlockedIncrement(&Route->PathCount);
    }
}

__inline
BOOLEAN
IppIsOnLinkRoute(
    CONST IP_UNICAST_ROUTE *Route
    )
{
    return (Route->CurrentNextHop == NULL);
}

VOID
IppUpdatePathOffloadState(
    IN PIP_PATH Path
    );

VOID
IppDeferUpdatePathOffloadState(
    IN PIP_PATH Path
    );

BOOLEAN
IppDetectGatewayReachability(
    IN PIP_INTERFACE Interface
    ); 
    
IP_OFFLOAD_OBJECT
IppMarkPathDirty(
    IN PIP_PATH Path
    );

NTSTATUS
IppValidateSetAllRouteParameters(
    IN NSI_SET_ACTION SetAction,
    IN PIP_INTERFACE Interface OPTIONAL,
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
    );

VOID
IppCommitSetAllRouteParameters(
    IN NSI_SET_ACTION SetAction,
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route, 
    IN CONST UCHAR *DestinationPrefix, 
    IN UCHAR DestinationPrefixLength, 
    IN CONST NL_ROUTE_RW *RouteRw
    );

VOID
IppCancelSetAllRouteParameters(
    IN NSI_SET_ACTION SetAction,
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route, 
    IN CONST UCHAR *DestinationPrefix, 
    IN UINT8 DestinationPrefixLength
    );

NTSTATUS
IppFillUnicastRouteData(
    IN PIP_PROTOCOL Protocol,
    IN PIP_UNICAST_ROUTE Route,
    OUT PNL_ROUTE_KEY Key OPTIONAL,
    OUT PNL_ROUTE_RW Rw OPTIONAL,
    OUT PNL_ROUTE_ROD Rod OPTIONAL,
    OUT PNL_ROUTE_ROS Ros OPTIONAL
    );

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
    OUT PUCHAR BestRouteRod OPTIONAL
    );

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllRouteParameters;
NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllSitePrefixParameters;

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
    OUT PIP_PATH_FLAGS ReturnConstrained
    );

VOID
IppUpdateRoutesWithLocalAddressAsNextHopUnderLock(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    );
    
NTSTATUS
IppConfigureIscsiTargetAndDefaultRoutes(
    IN PIP_INTERFACE Interface,
    IN PISCSI_BOOT_NIC TcpipIscsiBootParameters,
    IN ULONG NumberTargets,
    IN PUCHAR Gateway
    );
    
//
// Route Key.
//

typedef struct _IPV4P_ROUTE_KEY {
    IN_ADDR DestinationPrefix;
    IN_ADDR SourcePrefix;
} IPV4P_ROUTE_KEY, *PIPV4P_ROUTE_KEY;

typedef struct _IPV6P_ROUTE_KEY {
    IN6_ADDR DestinationPrefix;
    IN6_ADDR SourcePrefix;
} IPV6P_ROUTE_KEY, *PIPV6P_ROUTE_KEY;

#define ROUTE_KEY_STORAGE_SIZE \
    max(sizeof(IPV4P_ROUTE_KEY), sizeof(IPV6P_ROUTE_KEY))

typedef
VOID
(IP_INTERNAL_MAKE_ROUTE_KEY)(
    IN CONST UCHAR *DestinationPrefix,
    IN UINT8 DestinationPrefixLength,
    IN CONST UCHAR *SourcePrefix OPTIONAL,
    IN UINT8 SourcePrefixLength,
    OUT PUCHAR Key,
    OUT PUSHORT KeyLength
    );
typedef IP_INTERNAL_MAKE_ROUTE_KEY *PIP_INTERNAL_MAKE_ROUTE_KEY;

IP_INTERNAL_MAKE_ROUTE_KEY Ipv4pMakeRouteKey;
IP_INTERNAL_MAKE_ROUTE_KEY Ipv6pMakeRouteKey;

typedef
VOID
(IP_INTERNAL_PARSE_ROUTE_KEY)(
    IN CONST UCHAR *KeyBuffer,
    IN USHORT KeyLength,
    OUT PUCHAR *DestinationPrefix,
    OUT UINT8 *DestinationPrefixLength,
    OUT PUCHAR *SourcePrefix,
    OUT UINT8 *SourcePrefixLength
    );
typedef IP_INTERNAL_PARSE_ROUTE_KEY *PIP_INTERNAL_PARSE_ROUTE_KEY;

IP_INTERNAL_PARSE_ROUTE_KEY Ipv4pParseRouteKey;
IP_INTERNAL_PARSE_ROUTE_KEY Ipv6pParseRouteKey;

#endif // _ROUTE_
