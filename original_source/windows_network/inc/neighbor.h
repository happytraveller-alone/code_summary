/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    neighbor.h
    
Abstract:

    This module contains declarations for the network layer module's
    neighbor management.

Author:

    Mohit Talwar (mohitt) Mon Nov 18 18:40:19 2002

Environment:

    Kernel mode only.

--*/

#ifndef _NEIGHBOR_
#define _NEIGHBOR_

#pragma once

//
// Neighbor Discovery.
// Various constants from the IPv6 RFCs which define them.
//

#define REACHABLE_TIME              IppMilliseconds(30 * SECONDS)
#define MAX_REACHABLE_TIME          IppMilliseconds(1 * HOURS)

#define RETRANS_TIMER               IppTimerTicks(1 * SECONDS)
#define UNICAST_PROBING_TIME        IppTimerTicks(60 * SECONDS)
#define DELAY_FIRST_PROBE_TIME      IppTimerTicks(5 * SECONDS)
#define MIN_RANDOM_FACTOR           50  // Percentage of base value.
#define MAX_RANDOM_FACTOR           150 // Percentage of base value.
#define RECALC_REACHABLE_INTERVAL   IppTimerTicks(3 * HOURS)
#define UNREACH_SOLICIT_INTERVAL    IppTimerTicks(1 * MINUTES)
#define MAX_ANYCAST_DELAY_TIME      (1 * SECONDS)

#define MAX_MULTICAST_SOLICIT       3 // # transmissions before giving up.
#define MAX_UNICAST_SOLICIT         3 // # transmissions before giving up.
#define MAX_UNREACH_SOLICIT         1 // # transmissions before giving up.


//
// Router Discovery.
// Various constants from the IPv6 RFCs which define them.
//

#define MAX_RTR_SOLICITATIONS               3
//      MAX_RTR_SOLICITATION_DELAY          IPP_TIMEOUT is used instead.
#define RTR_SOLICITATION_INTERVAL           IppTimerTicks(4 * SECONDS)
#define SLOW_RTR_SOLICITATION_INTERVAL      IppTimerTicks(15 * MINUTES)

#define MAX_INITIAL_RTR_ADVERT_INTERVAL     IppTimerTicks(16 * SECONDS)
#define MAX_INITIAL_RTR_ADVERTISEMENTS      3 // Produces 3 quick RAs.
#define MAX_FINAL_RTR_ADVERTISEMENTS        3
#define MIN_DELAY_BETWEEN_RAS               IppTimerTicks(3 * SECONDS)
#define MAX_RA_DELAY_TIME                   1
#define MIN_ROUTER_ADVERTISEMENT_INTERVAL   IppTimerTicks(200 * SECONDS)
#define MAX_ROUTER_ADVERTISEMENT_INTERVAL   IppTimerTicks(600 * SECONDS)

//
// RFC 2461 sec 6.2.1. ND_RA_DEFAULT_PREFIX_ADVVALID_LIFETIME defaults to 30 days.
// ND_RA_DEFAULT_PREFIX_ADVPREFERRED_LIFETIME defaults to 7 days.
//
#define ND_RA_DEFAULT_PREFIX_ADVVALID_LIFETIME  RtlUlongByteSwap(2592000)
#define ND_RA_DEFAULT_PREFIX_ADVPREFERRED_LIFETIME  RtlUlongByteSwap(604800)

//
// REVIEW: Modify the neighbor set to use a Hash Table (optimize searches)?
// This set is currently a circular doubly-linked list.
//

typedef struct _IP_NEIGHBOR *PIP_NEIGHBOR;


//
// IP_NEIGHBOR_LINK
//
// Define the network layer neighbor set link.
//

typedef LIST_ENTRY IP_NEIGHBOR_LINK, *PIP_NEIGHBOR_LINK;

#define IPP_NEIGHBORSET_ENUM_DELAY          IppTimerTicks(30 * SECONDS)

//
// IP_NEIGHBOR_SET
//
// Define the network layer neighbor set state.
//
// Neighbor Caching:
// Goal: Maintain a small cache of neighbors for performance reasons. Also 
// limit the number of entries in the cache to avoid attacks. 
//
// CacheSize is an estimate of the number of cached entried in the 
// set. It is maintained as a running counter and is set to exact value when 
// the set is enumerated.
// The mechanic of maintaining CacheSize: On Dereference, if refcount drops to
// 1, CacheSize is incremented. It is decremented when the neighbor is looked
// up from the neighbor set. 
// 
// The cache is part of the main set and gets flushed either periodically or 
// when the CacheSize reaches a threshold.
//

typedef struct _IP_NEIGHBOR_SET {
    RTL_HASH_TABLE Table;               // Neighbor Set.
    ULONG LastEnumerationTick;
    ULONG CacheSize;                    // # neighbor entries kept cached.
    PIP_REQUEST_CONTROL_DATA DropQueue; // Queue of packets to drop.
    PTIMER_TABLE EventTable;            // Priority queue of neighbor timeouts.
} IP_NEIGHBOR_SET, *PIP_NEIGHBOR_SET;


//
// IP_NEIGHBOR_REACHABILITY
//
// Enumerate the neighbor reachability states.
//

typedef enum {
    NeighborInterfaceDisconnected = 0,  // Interface is disconnected -
                                        // definitely not reachable.
    NeighborUnreachable = 1,            // ND failed - probably not reachable.
    NeighborMayBeReachable = 2          // ND succeeded, or has not concluded.
} IP_NEIGHBOR_REACHABILITY, *PIP_NEIGHBOR_REACHABILITY;


//
// IP_NEIGHBOR
//
// Define the network layer neighbor state.
//
// We keep address translation and unreachability detection state
// for each of our neighbors that we're in communication with.
//
// Note: The UNREACHABLE state is entered when neighbor discovery fails.
// Note: The DELAY state is merged with the PROBE state.
//
// In the INCOMPLETE & UNREACHABLE states, the LinkAddress is not valid.
// In all other states, LinkAddress may be used to send packets.
// WaitQueue is only non-NULL in the INCOMPLETE state.
//
// If someone tries to send to an UNREACHABLE neighbor, then we transit to the
// INCOMPLETE state and start soliciting the link address.  If the solicitation
// fails then any waiting packets are discarded and we reset to UNREACHABLE.
// (Of course, with the next use of this neighbor we start solicitation again.)
//
// In the UNREACHABLE state IppProbeNeighborUnreachability sends a neighbor
// solicitation to probe the neighbor to determine whether it is now reachable.
//
// The IsUnreachable flag tracks separately whether the neighbor is *known* to
// be unreachable.  For example, a new neighbor will be in in the INCOMPLETE
// state, but IsUnreachable is FALSE because we don't know yet whether the
// neighbor is unreachable.  Similarly, when we receive passive information
// from a neighbor for whom neighbor discovery had previously failed, we enter
// the STALE state; however, if neighbor discovery had failed more than once in
// succession, we preserve the IsUnreachable flag to indicate that we might
// only have one-way connectivity with the neighbor.
// Since the flag is used by FindRoute, code paths that change this flag must
// call IppInvalidateDestinationCache.
//
// The WasReachable flag tracks whether we had bidirectional connectivity to
// the neighbor before it went offline.  This ensures that the first indication
// that the neighbor has come back online will make IsUnreachable FALSE and
// hence invalidate the destination cache.
// FindRoute will then not shy from using this neighbor.
//
// IP_INTERFACE::Lock protects all neighbors for that set.
//
// The following objects hold references for a neighbor
// 1. The IP_NEIGHBOR_SET of which the neighbor is a member.
//    - Referenced in IppInsertNeighbor.
//    - Dereferenced in IppDeleteNeigbor.
// 2. Threads using the neighbor actively.
//    - Referenced in IppFindOrCreateNeighbor.
//    - Dereferenced when the operation is done.
// 3. Paths.
// 4. Multicast Forwarding Entries (Mfes).
//
// A lone reference count indicates a cached neighbor.
//
// Neighbors with a non-zero reference count hold a reference for their
// subinterface, and hence an indirect reference on their interface.  This
// implies that if you hold a reference for a neighbor, you can always safely
// access and dereference Neighbor->SubInterface and Neighbor->Interface.
//
// Datalink layer address length is constant for a framing layer.
// Hence it is not stored in the neighbor state.
//

typedef struct _IP_NEIGHBOR {
    ULONG Signature;                // IP_NEIGHBOR_SIGNATURE

    LONG ReferenceCount;            // # References - Interlocked.

    PIP_INTERFACE Interface;        // Holds an indirect reference.
    PIP_SUBINTERFACE SubInterface;  // Over which the neighbor resides.

    //
    // Timestamps (in timer ticks).
    //
    ULONG LastConfirmation;

    ULONG LastUsed;

    union {                         // Depending on State, one of...
        ULONG LastReachable;
        ULONG LastUnreachable;
        ULONG LastReachability;
    };

    NL_ADDRESS_TYPE AddressType;    // Type of network layer address.
    
    //
    // Link for linking into the neighbor set hash table. 
    //
    RTL_HASH_TABLE_ENTRY Link;

    NL_NEIGHBOR_STATE State;        // Neighbor Discovery State.

    union {
        struct {
            UCHAR IsConfigured : 1; // Is this a user-configured neighbor?
            UCHAR IsRouter : 1;     // Is the neighbor a router?
            UCHAR WasReachable : 1; // Did ND indicate reachability?
            UCHAR IsUnreachable : 1;// Does ND indicate unreachability?
            UCHAR IsInSet : 1;      // Is the neighbor in neighbor set? 
        };
        UCHAR Flags;
    };

    UCHAR EventCount;               // Count number of various timeouts.
    TIMER_ENTRY EventTimer;         // Timeout state.    

    //
    // Queue of packets waiting for neighbor discovery to complete.
    // These do not hold a reference on the neighbor.
    //
    PIP_REQUEST_CONTROL_DATA WaitQueue;

    //
    // Link-layer source-route.
    //
    union {
        SOURCEROUTE_HEADER DlSourceRoute;
        UCHAR DlSourceRouteBuffer[SOURCEROUTE_SIZE_MAXIMUM];
    };
    
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

#ifdef _IP_OFFLOAD_LOGGING
    PIP_OFFLOAD_LOG OffloadLog;
#endif // _IP_OFFLOAD_LOGGING
} IP_NEIGHBOR, *PIP_NEIGHBOR;

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, Signature) ==
         FIELD_OFFSET(IP_NEIGHBOR, Signature));

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, ReferenceCount) ==
         FIELD_OFFSET(IP_NEIGHBOR, ReferenceCount));

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, Interface) ==
         FIELD_OFFSET(IP_NEIGHBOR, Interface));

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, SubInterface) ==
         FIELD_OFFSET(IP_NEIGHBOR, SubInterface));

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, LastConfirmation) ==
         FIELD_OFFSET(IP_NEIGHBOR, LastConfirmation));

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, LastUsed) ==
         FIELD_OFFSET(IP_NEIGHBOR, LastUsed));

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, LastReachability) ==
         FIELD_OFFSET(IP_NEIGHBOR, LastReachability));

C_ASSERT(FIELD_OFFSET(IP_NEIGHBOR_PRIVATE, AddressType) ==
         FIELD_OFFSET(IP_NEIGHBOR, AddressType));


//
// The neighbor's network layer address is stored past its base structure.
// The neighbor's datalink layer address follows its network layer address.
// See IPV6_NEIGHBOR & IPV4_NEIGHBOR.
//
#define IP_NEIGHBOR_NL_ADDRESS(Neighbor)                    \
    ((PUCHAR) (((PIP_NEIGHBOR) (Neighbor)) + 1))
#define IP_NEIGHBOR_DL_ADDRESS(Neighbor, AddressLength)     \
    ((PUCHAR) (IP_NEIGHBOR_NL_ADDRESS(Neighbor) + (AddressLength)))


//
// IppNeighborCacheLimit is the upper-bound on NeighborCacheSize.
//
// REVIEW: What is a reasonable value for NeighborCacheLimit?
// Should probably be sized based on physical memory and link characteristics.
//
// We cache & reclaim neighbors on a per-interface basis.  Theoretically it
// would be better to use a global LRU list.  However this would introduce
// added overhead (making neighbors bigger) and locking.
//
// Another thought - it's much more important to support many RCEs than it is
// to support many neighbors.
//

extern ULONG IppNeighborCacheLimit;


//
// Neighbor Management Routines.
//
    
NTSTATUS
IppInitializeNeighborSet(
    OUT PIP_NEIGHBOR_SET NeighborSet,
    IN USHORT BucketCount
    );

VOID
IppUninitializeNeighborSet(
    IN OUT PIP_NEIGHBOR_SET NeighborSet
    );

VOID
IppDeleteNeighborSet(
    IN PIP_INTERFACE Interface
    );

VOID
IppCleanupNeighbor(
    IN PIP_NEIGHBOR Neighbor
    );

#if NEIGHBOR_REFHIST
extern PREFERENCE_HISTORY IppNeighborReferenceHistory;
DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_NEIGHBOR, Neighbor, Ipp, IppNeighborReferenceHistory)
#define IppDereferenceNeighbor(Neighbor) \
    IppDereferenceNeighborWithHistory((Neighbor), __LINE__, __FILE__)
#define IppReferenceNeighbor(Neighbor) \
    _IppReferenceNeighbor((Neighbor), __LINE__, __FILE__)
#define IppReferenceNeighborEx(Neighbor, Count) \
    _IppReferenceNeighborEx((Neighbor), Count, __LINE__, __FILE__)

VOID
IppDereferenceNeighborWithHistory(
    IN PIP_NEIGHBOR Neighbor,
    IN ULONG Line,
    IN PCHAR File
    );

#else  // NEIGHBOR_REFHIST

#define IppCleanupNeighborPrimitive IppCleanupNeighbor
DEFINE_REFERENCE_ROUTINES(PIP_NEIGHBOR, NeighborPrimitive, Ipp)

#define IppReferenceNeighbor IppReferenceNeighborPrimitive
#define IppReferenceNeighborEx IppReferenceNeighborPrimitiveEx

VOID
IppDereferenceNeighbor(
    IN PIP_NEIGHBOR Neighbor
    );

#endif // NEIGHBOR_REFHIST
    
PIP_NEIGHBOR
IppFindOrCreateNeighborUnderLock(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    );

PIP_NEIGHBOR
IppFindOrCreateNeighborAtDpc(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    );

PIP_NEIGHBOR
IppFindOrCreateNeighbor(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    );

PIP_NEIGHBOR
IppFindOrCreateNeighborWithoutTypeAtDpc(
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address
    );

PIP_NEIGHBOR
IppFindOrCreateNeighborWithoutType(
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address
    );

VOID
IppResetNeighborsUnderLock(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN BOOLEAN ResetConfigured
    );

VOID
IppResetNeighborsAtDpc(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN BOOLEAN ResetConfigured
    );

VOID
IppMorphNeighborAtDpc(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    );

VOID
IppDeleteNeighborsUnderLock(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL
    );

ULONG
IppNeighborReachableTicks(
    IN ULONG BaseReachableTime
    );

VOID
IppSuspectNeighborReachability(
    IN PIP_NEIGHBOR Neighbor
    );

ULONG
IppConfirmNeighborReachability(
    IN PIP_NEIGHBOR Neighbor,
    IN ULONG ElapsedTicks
    );

VOID
IppProbeNeighborReachability(
    IN PIP_NEIGHBOR Neighbor
    );

IP_NEIGHBOR_REACHABILITY
IppGetNeighborReachability(
    IN PIP_NEIGHBOR Neighbor
    );

VOID
IppDeferUpdateNeighborOffloadState(
    IN PIP_NEIGHBOR Neighbor
    );

NTSTATUS
IppSetAllNeighborParametersHelper(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *Address,
    IN PNL_NEIGHBOR_RW Data,
    IN NSI_SET_ACTION Action
    );

VOID
IppUpdateNeighborAddress(
    IN OUT PIP_NEIGHBOR Neighbor,
    IN CONST UCHAR *DlAddress,    
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN USHORT NlAddressLength,
    IN USHORT DlAddressLength
    );

PIP_REQUEST_CONTROL_DATA
IppUpdateNeighbor(
    IN OUT PIP_NEIGHBOR Neighbor,
    IN CONST UCHAR *DlAddress,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute OPTIONAL,
    IN BOOLEAN Solicited,
    IN BOOLEAN Override,
    IN BOOLEAN IsDAD
    );

VOID
IppNeighborSetTimeout(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN RecalculateReachableTime
    );

NETIO_INLINE
VOID
IppRefreshNeighbor(
    IN PIP_NEIGHBOR Neighbor
    );

BOOLEAN
IppDoesNeighborNeedResolution(
    IN PIP_NEIGHBOR Neighbor,
    IN PIP_INTERFACE Interface
    );

BOOLEAN
IppResolveNeighbor(
    IN PIP_NEIGHBOR Neighbor,    
    IN PIP_REQUEST_CONTROL_DATA Control
    );

PIP_LOCAL_ADDRESS
IppHandleNeighborSolicitation(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *DlSourceAddress,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN CONST UCHAR *NlSourceAddress,
    IN CONST UCHAR *NlTargetAddress
    );

VOID
IppHandleNeighborAdvertisement(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *DlSourceAddress,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN CONST UCHAR *NlSourceAddress,
    IN IPV6_NEIGHBOR_ADVERTISEMENT_FLAGS Flags
    );

VOID 
IppSendNeighborProbe(
    IN PIP_NEIGHBOR Neighbor
    );
    
VOID
IppSendNeighborSolicitation(
    IN BOOLEAN DispatchLevel,
    IN PIP_NEIGHBOR Neighbor,
    IN PIP_LOCAL_UNICAST_ADDRESS Source
    );

VOID
IppSendDadSolicitation(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    );

VOID
IppSendUnsolicitedNeighborAdvertisement(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    );

typedef
PIP_LOCAL_UNICAST_ADDRESS
(IP_INTERNAL_GET_SOLICITATION_SOURCE)(
    IN PIP_NEIGHBOR Neighbor
    );

typedef IP_INTERNAL_GET_SOLICITATION_SOURCE
    *PIP_INTERNAL_GET_SOLICITATION_SOURCE;

typedef
VOID
(IP_INTERNAL_SEND_NEIGHBOR_SOLICITATION)(
    IN BOOLEAN DispatchLevel,
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_NEIGHBOR Neighbor OPTIONAL,
    IN PIP_LOCAL_UNICAST_ADDRESS SourceAddress OPTIONAL,
    IN CONST UCHAR *DestinationAddress OPTIONAL,
    IN CONST UCHAR *TargetAddress
    );

typedef IP_INTERNAL_SEND_NEIGHBOR_SOLICITATION
    *PIP_INTERNAL_SEND_NEIGHBOR_SOLICITATION;

typedef
VOID
(IP_INTERNAL_SEND_NEIGHBOR_ADVERTISEMENT)(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *SolicitationSourceDlAddress OPTIONAL,
    IN CONST SOURCEROUTE_HEADER *SolicitationSourceDlRoute OPTIONAL,
    IN CONST UCHAR *SolicitationSourceAddress,
    IN PIP_LOCAL_ADDRESS LocalTarget
    );

typedef IP_INTERNAL_SEND_NEIGHBOR_ADVERTISEMENT
    *PIP_INTERNAL_SEND_NEIGHBOR_ADVERTISEMENT;

//
// Framing Layer Client Handlers.
//

FL_CLIENT_INITIATE_OFFLOAD_COMPLETE IpFlcInitiateNeighborOffloadComplete;
FL_CLIENT_TERMINATE_OFFLOAD_COMPLETE IpFlcTerminateNeighborOffloadComplete;
FL_CLIENT_UPDATE_OFFLOAD_COMPLETE IpFlcUpdateNeighborOffloadComplete;
FL_CLIENT_INVALIDATE_OFFLOAD_COMPLETE IpFlcInvalidateNeighborOffloadComplete;
FL_CLIENT_QUERY_NEIGHBOR_REACHABILITY IpFlcQueryNeighborReachability;
FL_CLIENT_SUSPECT_NEIGHBOR_REACHABILITY IpFlcSuspectNeighborReachability;
FL_CLIENT_INDICATE_OFFLOAD_EVENT IpFlcIndicateOffloadEvent;


//
// Network Layer Management Provider Handlers.
//

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllNeighborParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllNeighborParameters;
NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllResolveNeighborParameters;

#endif // _NEIGHBOR_
