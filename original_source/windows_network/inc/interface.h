/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    interface.h
    
Abstract:

    This module contains declarations for the network layer module's
    interface management.
    
Author:

    Mohit Talwar (mohitt) Mon Nov 18 15:38:52 2002

Environment:

    Kernel mode only.

--*/

#ifndef _INTERFACE_
#define _INTERFACE_

#pragma once

#include "multicast.h"
#include "md5.h"
#include <workqueue.h>

typedef enum {
    IpUpdateInterfaceEvent = 0,
    IpAddInterfaceEvent,
    IpDeleteInterfaceEvent,
    IpCleanupInterfaceEvent
} IP_INTERFACE_CHANGE_EVENT;

//
// TODO: Change this to a BBT.
//
typedef LIST_ENTRY NLI_SET, *PNLI_SET;
typedef LIST_ENTRY NLI_LINK, *PNLI_LINK;
typedef LOCKED_LIST NLI_LOCKED_SET, *PNLI_LOCKED_SET;

//
// IP_SUBINTERFACE_STATISTICS
//
// Define statistics kept for each subinterface.
//
// We use 64-bit counters for values which may wrap around within an hour
// (e.g. Transmit and Receive count for interfaces with speed > 20 Mbps).
// These cannot be updated atomically with interlocked operations.  Also, 
// to avoid that performance hit we accept inaccuracies in 32-bit counters.
//

typedef struct CACHE_ALIGN _IP_SUBINTERFACE_STATISTICS {
    ULONG64 InReceives;
    ULONG64 InOctets;
    ULONG64 OutTransmits;
    ULONG64 OutOctets;
    ULONG InHeaderErrors;
    ULONG InTruncatedPackets;
    ULONG InDiscards;
    ULONG FragmentOks;
    ULONG FragmentFailures;
    ULONG FragmentsCreated;
} IP_SUBINTERFACE_STATISTICS, *PIP_SUBINTERFACE_STATISTICS;
C_ASSERT(sizeof(IP_SUBINTERFACE_STATISTICS) % MAX_CACHE_LINE_SIZE == 0);

//
// IP_ROUTER_DISCOVERY_TIMER
//
// Define a structure for a router discovery timer.  Contains the number of
// outstanding requests to be sent and the timer for the next request. 
//

typedef struct _IP_ROUTER_DISCOVERY_TIMER {
    ULONG RouterDiscoveryCount; // # Router Discovery packets to send.
    ULONG RouterDiscoveryTimer; // Router Discovery Timer.
} IP_ROUTER_DISCOVERY_TIMER, *PIP_ROUTER_DISCOVERY_TIMER;

#define IP_GET_ROUTER_DISCOVERY_TIMER(A) \
    ((PIP_ROUTER_DISCOVERY_TIMER)&(A)->RouterDiscoveryCount)
    
//
// IP_POTENTIAL_ROUTER
//
// Define a structure for a potential router.  This is used for non-multicast
// non-advertising interfaces. 
//

typedef struct _IP_POTENTIAL_ROUTER {
    LIST_ENTRY Link;
    IP_ROUTER_DISCOVERY_TIMER;
} IP_POTENTIAL_ROUTER, *PIP_POTENTIAL_ROUTER;
    
//
// IP_INTERFACE_STATISTICS
//
// Define statistics kept for each interface.
//

typedef struct CACHE_ALIGN _IP_INTERFACE_STATISTICS {
    ULONG ReassemblyRequireds;
    ULONG ReassemblyOks;
    ULONG ReassemblyFailures;
} IP_INTERFACE_STATISTICS, *PIP_INTERFACE_STATISTICS;
C_ASSERT(sizeof(IP_INTERFACE_STATISTICS) % MAX_CACHE_LINE_SIZE == 0);

//
// IP_INTERFACE
//
// Define the structure of a network layer interface.
//
// The following objects hold references for an interface:
// 1. Self (creation).
// 2. SubInterfaces.
// 3. LocalAddresses.
// 4. Routes.
// 5. Network-Layer Clients (some).
//
// The lock acquisition order is:
//      PathBucket->Bucket->SpinLock before
//      Compartment->InterfaceSet.Lock before
//      Interface->Lock before
//      RouteSet->Lock before
//      MfeSet->Lock before
//      Interface->NeighborSetLock before
//      LoopbackEphemeralAddressSet->Lock.
//
typedef struct _IP_INTERFACE {
    //
    // Read-only fields visible to clients.
    //
    PIP_COMPARTMENT Compartment;
    IF_INDEX Index;
    IF_LUID Luid;
    
    //
    // Private fields between TCP and IP.
    //
    PVOID TcpContext;
    //
    // Number of connected subinterfaces in the SubInterfaceSet.
    // Modifying this field requires holding both these locks:
    // 1. Interface::NeighborSetLock.
    // 2. Interface::Lock.
    //
    ULONG ConnectedSubInterfaces;
    
    //
    // Read-only private fields between TCP and IP.
    //
    CONST FL_INTERFACE_CHARACTERISTICS *FlCharacteristics;

    //
    // This stores the power state of the NIC
    //
    BOOLEAN LowPowerMode;

    //
    // Read-only internal fields.
    //
    ULONG Signature;
    PVOID FlContext;
    PFL_PROVIDER_CONTEXT FlModule;
    NL_INTERFACE_OFFLOAD_ROD TransmitOffload;
    NL_INTERFACE_OFFLOAD_ROD ReceiveOffload;
    USHORT FlBackfill;
    GUID Guid;
    
    //
    // Set once, upon deletion.
    //
    PFL_PROVIDER_DELETE_INTERFACE_COMPLETE FlDeleteComplete;
    PIO_WORKITEM WorkItem;    
    
    LONG ReferenceCount;        // Interlocked.

    NLI_LINK GlobalLink;        // Protected by global interface set lock.
    NLI_LINK CompartmentLink;   // Protected by compartment interface set lock.

    KMUTEX WorkerLock;          // Serializes worker thread operations.

    //
    // Handles work items for an interface at PASSIVE level.
    //
    NETIO_WORK_QUEUE WorkQueue; 

    //
    // The neighbor set lock protects the fields below between here and 
    // the "Lock" field.
    // REVIEW: We should probably rename this lock.
    //
    RTL_MRSW_LOCK NeighborSetLock;
    IP_NEIGHBOR_SET NeighborSet;
    NLI_SET SubInterfaceSet;

    //
    // Minimum MTU among all subinterfaces.  This field can be read without 
    // taking the lock.
    //
    ULONG MinimumNlMtu;

    //
    // The interface lock protects the remaining (non-interlocked) fields,
    // as well as ConnectedSubInterfaces, above.
    //
    RTL_MRSW_LOCK Lock;

    //
    // UseNeighborUnreachabilityDetection implies use of ND packets to probe
    // neighbor reachability.  SupportsNeighborDiscovery implies use of ND
    // packets to resolve neighbor addresses, it indirectly implies use of NUD.
    //
    // Advertise implies that the interface is configured to advertise.
    // AdvertisingEnabled implies that the interface is already advertising.
    //
    union {
        struct {
            BOOLEAN Disabled : 1;
            BOOLEAN Advertise : 1;
            BOOLEAN AdvertisingEnabled : 1;
            BOOLEAN AdvertiseDefaultRoute : 1;
            BOOLEAN Forward : 1;
            BOOLEAN WeakHostSend : 1;
            BOOLEAN WeakHostReceive : 1;
            BOOLEAN UseNeighborUnreachabilityDetection : 1;
            BOOLEAN ManagedAddressConfiguration : 1;
            BOOLEAN OtherStatefulConfiguration : 1;
            BOOLEAN MediaReconnected : 1;
            BOOLEAN UseRouterDiscovery : 1;
            BOOLEAN DhcpRouterDiscoveryEnabled : 1;
            BOOLEAN AutoMetric : 1;
            BOOLEAN UseBroadcastForRouterDiscovery : 1;
            BOOLEAN UseZeroBroadcastAddress : 1;
            BOOLEAN DisallowMulticastRoutes : 1;
            BOOLEAN DisallowUnicastRoutes : 1;
            BOOLEAN MulticastWorkItemScheduled : 1;
            BOOLEAN ForwardMulticast : 1;
            BOOLEAN OffloadSet : 1;
            BOOLEAN SettingOffload : 1;
            BOOLEAN OffloadDeleted : 1;
            BOOLEAN DelaySolicitedRouterAdvertisementNeeded : 1;
            BOOLEAN NetworkCategory : 2;
            BOOLEAN DisableDefaultRoutes : 1;
            BOOLEAN SendUnsolicitedNeighborAdvertisementOnDad : 1;
            BOOLEAN TlDatagramFastPathCompatible : 1;
        };
        ULONG Flags;
    };
    
    NL_ROUTER_DISCOVERY_BEHAVIOR RouterDiscoveryBehavior;
    
    LONG FragmentId;            // Interlocked.
    ULONG IpPromiscuousCount;   // Interlocked.
    ULONG FlPromiscuousCount;   // Interlocked.
    ULONG IpAllMulticastCount;  // Interlocked.
    ULONG FlAllMulticastCount;  // Interlocked.

    ULONG Metric;               // Interface metric.
    
    ULONG BaseReachableTime;    // Base for random ReachableTime (in ms).
    ULONG ReachableTicks;       // Reachable timeout (in ticks).
    ULONG RetransmitTicks;      // Neighbor Solicitation timeout (in ticks).

    ULONG PathMtuDiscoveryTicks; // Path MTU discovery timeout (in ticks).

    UCHAR CurrentHopLimit;      // Default hop-limit for unicast.
    UCHAR MulticastForwardingHopLimit; // Hop Limit for Multicast Forwarding.
    
    UCHAR DefaultSitePrefixLength; // Default Site Prefix Length for RAs.

    UCHAR MinimumReceivedHopCount;
    
    LIST_ENTRY PotentialRouterList; // List of potential routers (used for
                                    // non-multicast interfaces e.g. ISATAP).
    IP_ROUTER_DISCOVERY_TIMER;
    ULONG LastRouterAdvertisement; // Last Router Advertisement (in ticks).

    ULONG DadTransmits;         // DupAddrDetectTransmits from RFC 2462.
    ULONG DadFailures;          // Number of consecutive DAD failures.
 
    //
    // This gets incremented when the interface gets reconnected.
    //
    ULONG LinkEpoch;

    //
    // Rate limiting ICMP errors.
    //
    ULONG IcmpErrorCount;
    
    //
    // Interface identifier, upto 8 bytes long.
    //
    UCHAR Identifier[MAX_INTERFACE_IDENTIFIER_LENGTH];
    
    //
    // State for link-local address configuration. 
    //
    NL_LINK_LOCAL_ADDRESS_BEHAVIOR LinkLocalAddressBehavior;
    ULONG LinkLocalAddressTimeout; // Timeout value (in ticks).
    ULONG LinkLocalAddressTimer;   // Remaining ticks for timeout. 
    IP_ADDRESS_STORAGE LinkLocalAddress; // Autogenerated Link local address.

    // 
    // State for temporary addresses.
    //
    UCHAR TemporaryState[MD5DIGESTLEN];
    ULONG TemporaryStateCreationTime;

    IP_PROXY_NEIGHBOR_SET ProxyNeighborSet;

    //
    // Number of valid unicast addresses in the address set.
    //
    ULONG ValidLocalUnicastAddressCount;
    
    NLA_SET LocalUnicastAddressSet;
    NLA_SET LocalAnycastAddressSet;
    NLA_SET LocalBroadcastAddressSet;
    NLA_SET LocalMulticastAddressSet;
    
    PIP_LOCAL_UNICAST_ADDRESS UnspecifiedAddress;
    
    //
    // Table of unicast address DAD events.
    //
    PTIMER_TABLE UnicastAddressEventTable; 
    
    //
    // Table for deferred anycast address neighbor advertisements. 
    //
    PTIMER_TABLE AnycastAdvertisementTimerTable;
    
    //
    // Table for multicast discovery timers (trigerred by membership changes).  
    //
    PTIMER_TABLE MulticastReportTimerTable; 

    //
    // Table for multicast general queries. 
    //
    PTIMER_TABLE MulticastGeneralQueryTimerTable;  

    //
    // Timer table for group and group-and-source specific queries. 
    //
    PTIMER_TABLE MulticastSpecificQueryTimerTable; 
    PIO_WORKITEM MulticastWorkItem;
    MULTICAST_DISCOVERY_VERSION MulticastDiscoveryVersion;
    ULONG MulticastQuerierPresent[MULTICAST_DISCOVERY_VERSION3];
    ULONG RobustnessVariable;

    //
    // This stores zone indices starting from ScopeLevelLink to
    // (ScopeLevelGlobal - 1). Zone for ScopeLevelGlobal is always 1 currently.
    // The Zone for ScopeLevelInterface and lower is the interface index. 
    //
    SCOPE_ID ZoneIndices[ScopeLevelGlobal - ScopeLevelLink];

    //
    // This store the segmentation offload capabilities that this interface
    // advertises to TCP.
    //
    NDIS_TCP_LARGE_SEND_OFFLOAD_V1 Lso;
    NDIS_TCP_LARGE_SEND_OFFLOAD_V2 Gso;

    PIP_INTERFACE_STATISTICS *PerProcessorStatistics;

} IP_INTERFACE, *PIP_INTERFACE;


C_ASSERT(FIELD_OFFSET(NL_INTERFACE, Compartment) ==
         FIELD_OFFSET(IP_INTERFACE, Compartment));
C_ASSERT(FIELD_OFFSET(NL_INTERFACE, Luid) ==
         FIELD_OFFSET(IP_INTERFACE, Luid));
C_ASSERT(FIELD_OFFSET(NL_INTERFACE, Index) ==
         FIELD_OFFSET(IP_INTERFACE, Index));
C_ASSERT(FIELD_OFFSET(IP_INTERFACE_PRIVATE, TcpContext) ==
         FIELD_OFFSET(IP_INTERFACE, TcpContext));
C_ASSERT(FIELD_OFFSET(IP_INTERFACE_PRIVATE, ConnectedSubInterfaces) ==
         FIELD_OFFSET(IP_INTERFACE, ConnectedSubInterfaces));

//
// The received hop count mask should be contiguous.
//
#define RECEIVED_HOP_COUNT_MASK 0x1f
C_ASSERT(IS_POWER_OF_TWO(RECEIVED_HOP_COUNT_MASK + 1));


//
// IP_SUBINTERFACE
//
// Define the structure of a network layer interface.
//
// The following objects hold references for an interface:
// 1. Self (creation).
// 2. Neighbors.
//

typedef struct _IP_SUBINTERFACE {
    //
    // Read-only fields.
    //
    ULONG Signature;             // IP_SUBINTERFACE_SIGNATURE
    LONG ReferenceCount;        // Interlocked.
    PIP_INTERFACE Interface;

    IF_LUID Luid;
    IF_INDEX Index;
    PVOID FlContext;
    CONST FL_SUBINTERFACE_CHARACTERISTICS *FlCharacteristics;

    //
    // Set once, upon deletion.
    //
    PFL_PROVIDER_DELETE_SUBINTERFACE_COMPLETE FlDeleteComplete;
    PIO_WORKITEM WorkItem;    
    

    //
    // The following three fields are protected by the interface's neighbor
    // set lock.
    //
    NLI_LINK Link;
    ULONG NlMtu;                // Manually configured or received from RAs.
    IF_OPER_STATUS OperationalStatus;
    
    PIP_SUBINTERFACE_STATISTICS *PerProcessorStatistics;    
} IP_SUBINTERFACE, *PIP_SUBINTERFACE;

C_ASSERT(FIELD_OFFSET(IP_SUBINTERFACE, Signature) == 0);

NTSTATUS
IppStartInterfaceManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupInterfaceManager(
    IN PIP_PROTOCOL Protocol
    );

__inline
NTSTATUS
IppInitializeNliSet(
    PNLI_SET Set
    )
{
    InitializeListHead(Set);
    return STATUS_SUCCESS;
}

__inline
VOID
IppUninitializeNliSet(
    PNLI_SET Set
    )
{
    UninitializeListHead(Set);
}

__inline
NTSTATUS
IppInitializeNliLockedSet(
    PNLI_LOCKED_SET Set
    )
{
    IppInitializeLockedList(Set);
    return STATUS_SUCCESS;
}

__inline
VOID
IppUninitializeNliLockedSet(
    PNLI_LOCKED_SET Set
    )
{
    IppUninitializeLockedList(Set);
}

//
// Internal Interface Management Routines.
//

VOID
IppCleanupInterface(
    IN PIP_INTERFACE Interface
    );

#if INTERFACE_REFHIST
extern PREFERENCE_HISTORY IppInterfaceReferenceHistory;
DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_INTERFACE, Interface, Ipp, IppInterfaceReferenceHistory)
#define IppDereferenceInterface(Interface) \
    _IppDereferenceInterface((Interface), __LINE__, __FILE__)
#define IppReferenceInterface(Interface) \
    _IppReferenceInterface((Interface), __LINE__, __FILE__)
#else  // INTERFACE_REFHIST
DEFINE_REFERENCE_ROUTINES(PIP_INTERFACE, Interface, Ipp)
#endif // INTERFACE_REFHIST    

__inline
BOOLEAN
IppIsInterfaceDisabled(
    PIP_INTERFACE Interface
    )
{
    return (Interface->Disabled ? TRUE : FALSE);
}

__inline
BOOLEAN
IppIsRouterDiscoveryEnabled(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
 
    This routine determines if router discovery is enabled on the interface or
    not.  

Arguments:

    Interface - Supplies the interface.

Return Value:

    Returns TRUE if router discovery should be used. FALSE otherwise. 

--*/ 
{
    return (Interface->FlCharacteristics->DiscoversRouters &&
            ((Interface->RouterDiscoveryBehavior == RouterDiscoveryEnabled) ||
             ((Interface->RouterDiscoveryBehavior == RouterDiscoveryDhcp) &&
              (Interface->DhcpRouterDiscoveryEnabled))));
}

#define IS_LINK_UNCHANGED(Interface, Epoch) ((Interface)->LinkEpoch == (Epoch))
     
__inline
VOID
IppSetInterfaceType(
    IN PIP_INTERFACE Interface, 
    IN NL_TYPE_OF_INTERFACE Type
    )
{
    Interface->DisallowUnicastRoutes = Type & 0x1;
    Interface->DisallowMulticastRoutes = (Type & 0x2) >> 1;
}

__inline
NL_TYPE_OF_INTERFACE
IppGetInterfaceType(
    IN PIP_INTERFACE Interface
    )
{
    return ((Interface->DisallowUnicastRoutes) | 
            (Interface->DisallowMulticastRoutes << 1));
}

PIP_INTERFACE
IppFindInterfaceByLuidUnderLock(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *Luid
    );

PIP_INTERFACE
IppFindInterfaceByLuid(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *Luid
    );

PIP_INTERFACE
IppFindInterfaceByIndexUnderLock(
    IN PIP_COMPARTMENT Compartment,
    IN IF_INDEX Index
    );

PIP_INTERFACE
IppFindInterfaceByIndex(
    IN PIP_COMPARTMENT Compartment,
    IN IF_INDEX Index
    );

PIP_INTERFACE
IppFindInterfaceByAddress(
    IN PIP_COMPARTMENT Compartment,
    IN PUCHAR Address
    );

PIP_INTERFACE
IppGetInterface(
    IN PIP_COMPARTMENT Compartment,
    IN PNL_INTERFACE_ARG Args
    );

PIP_INTERFACE
IppGetFirstInterface(
    IN PIP_PROTOCOL Protocol
    );

PIP_INTERFACE
IppGetNextInterface(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *Luid
    );

ULONG
IppGetInterfaceScopeZone(
    IN CONST IP_INTERFACE *Interface,
    IN SCOPE_LEVEL Level
    );

NTSTATUS
IppSetInterfaceScopeZone(
    IN PIP_INTERFACE Interface,
    IN SCOPE_LEVEL Level,
    IN ULONG ScopeId
    );

BOOLEAN
IppIsInterfaceInScope(
    IN PIP_INTERFACE Interface,
    IN SCOPE_ID ScopeId
    );

PIP_INTERFACE
IppFindDefaultInterfaceForZone(
    IN PIP_COMPARTMENT Compartment,
    IN SCOPE_ID ScopeId
    );

VOID
IppStartNud(
    IN PIP_INTERFACE Interface
    );

VOID
IppStopNud(
    IN PIP_INTERFACE Interface
    );

VOID
IppStartForwarding(
    IN PIP_INTERFACE Interface
    );

VOID
IppStopForwarding(
    IN PIP_INTERFACE Interface
    );

NTSTATUS
IppAddPromiscuousReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    );

NTSTATUS
IppRemovePromiscuousReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    );

NTSTATUS
IppAddFlAllMulticastReferenceUnderLock(
    IN PIP_INTERFACE Interface,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    );

NTSTATUS
IppAddAllMulticastReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    );

NTSTATUS
IppRemoveFlAllMulticastReferenceUnderLock(
    IN PIP_INTERFACE Interface,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    );

NTSTATUS
IppRemoveAllMulticastReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    );

VOID
IppUpdateInterfaceConfigurationFlags(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN ManagedAddressConfigurationSupported,
    IN BOOLEAN OtherStatefulConfigurationSupported
    );

VOID
IppUpdateInterface(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN Advertise,
    IN BOOLEAN AdvertiseDefaultRoute,
    IN BOOLEAN ManagedAddressConfigurationSupported,
    IN BOOLEAN OtherStatefulConfigurationSupported,    
    IN BOOLEAN Forward,
    IN BOOLEAN WeakHostSend,
    IN BOOLEAN WeakHostReceive,
    IN BOOLEAN ForwardMulticast,
    IN BOOLEAN UseNud,
    IN BOOLEAN RandomizeIdentifier
    );

VOID
IppUpdateInterfaceMtuUnderLock(
    IN PIP_INTERFACE Interface
    );

//
// Internal Sub-Interface Management Routines.
//

VOID
IppCleanupSubInterface(
    IN PIP_SUBINTERFACE SubInterface
    );

VOID
IppDeleteSubInterface(
    IN PIP_SUBINTERFACE SubInterface
    );

#if INTERFACE_REFHIST
extern PREFERENCE_HISTORY IppSubInterfaceReferenceHistory;
DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_SUBINTERFACE, SubInterface, Ipp, IppSubInterfaceReferenceHistory)
#define IppDereferenceSubInterface(SubInterface) \
    _IppDereferenceSubInterface((SubInterface), __LINE__, __FILE__)
#define IppReferenceSubInterface(SubInterface) \
    _IppReferenceSubInterface((SubInterface), __LINE__, __FILE__)
#define IppReferenceSubInterfaceEx(SubInterface, Count) \
    _IppReferenceSubInterfaceEx((SubInterface), Count, __LINE__, __FILE__)
#else  // INTERFACE_REFHIST
DEFINE_REFERENCE_ROUTINES(PIP_SUBINTERFACE, SubInterface, Ipp)
#endif // INTERFACE_REFHIST

__inline
BOOLEAN
IppIsSubInterfaceDisabled(
    PIP_SUBINTERFACE SubInterface
    )
{
    return (SubInterface->FlDeleteComplete != NULL);
}

PIP_SUBINTERFACE
IppFindSubInterfaceByLuid(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *InterfaceLuid,
    IN CONST IF_LUID *SubInterfaceLuid
    );

PIP_SUBINTERFACE
IppFindSubInterfaceOnInterfaceByIndexUnderLock(
    IN PIP_INTERFACE Interface,
    IN IF_INDEX SubInterfaceIndex
    );

PIP_SUBINTERFACE
IppFindSubInterfaceByIndexUnderLock(
    IN PIP_COMPARTMENT Compartment,
    IN CONST IF_INDEX InterfaceIndex,
    IN CONST IF_INDEX SubInterfaceIndex
    );

PIP_SUBINTERFACE
IppGetFirstSubInterface(
    IN PIP_PROTOCOL Protocol
    );

PIP_SUBINTERFACE
IppGetNextSubInterface(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *InterfaceLuid,
    IN CONST IF_LUID *SubInterfaceLuid
    );

PIP_SUBINTERFACE
IppGetNextSubInterfaceOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST IF_LUID *SubInterfaceLuid OPTIONAL,
    PIP_SUBINTERFACE StartSubInterface OPTIONAL
    );

#define IppGetFirstSubInterfaceOnInterface(Interface) \
    IppGetNextSubInterfaceOnInterface(Interface, NULL, NULL)

__inline
PIP_SUBINTERFACE
IppGetAnySubInterfaceOnInterfaceUnderLock(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Return any subinterface in the list for an interface.
    The pointer is NOT referenced.

Arguments:

    Interface - Supplies the interface in question.

Return Value:

    SubInterface.

Caller LOCK: Interface neighbor set (Shared).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PNLI_SET Head = &Interface->SubInterfaceSet;

    ASSERT_ANY_LOCK_HELD(&Interface->NeighborSetLock);

    if (IsListEmpty(Head)) {
        return NULL;

    }
    return CONTAINING_RECORD(Head->Flink, IP_SUBINTERFACE, Link);
}

__inline
PIP_SUBINTERFACE
IppFindAnySubInterfaceOnInterfaceUnderLock(
    IN PIP_INTERFACE Interface
    )
{
    PIP_SUBINTERFACE SubInterface;

    SubInterface = IppGetAnySubInterfaceOnInterfaceUnderLock(Interface);
    IppReferenceSubInterface(SubInterface);
    return SubInterface;
}

__inline
PIP_SUBINTERFACE
IppFindAnySubInterfaceOnInterface(
    IN PIP_INTERFACE Interface
    )
{
    PIP_SUBINTERFACE SubInterface;
    KIRQL OldIrql;
    
    RtlAcquireReadLock(&Interface->NeighborSetLock, &OldIrql);
    SubInterface = IppFindAnySubInterfaceOnInterfaceUnderLock(Interface);
    RtlReleaseReadLock(&Interface->NeighborSetLock, OldIrql);

    return SubInterface;
}

__inline
BOOLEAN
IppInterfaceDadEnabled(
    IN PIP_INTERFACE Interface
    )
{
    return ((Interface->DadTransmits != 0) && 
            Interface->FlCharacteristics->DiscoversNeighbors);
}

VOID
IppReconnectSubInterface(
    IN PIP_SUBINTERFACE SubInterface,
    IN BOOLEAN LogEvent
    );

VOID
IppAddGlobalOffloadStatistics(
    IN PIP_PROTOCOL Protocol,
    IN OUT PNL_GLOBAL_ROD Rod
    );

VOID
IppSetDhcpOperationalStatus(
    IN PIP_PROTOCOL Protocol, 
    IN BOOLEAN DisableMediaSense
    );

BOOLEAN
IppRandomizeIdentifier(
    IN PIP_INTERFACE Interface
    );

VOID
IppInterfaceDelayedWorker(
    IN PSINGLE_LIST_ENTRY WorkQueueHead
    );

NTSTATUS
IppInterfaceListProcessorAddRemoveHandler(
    IN PIP_PROTOCOL Protocol,
    IN ULONG ProcessorIndex,
    IN BOOLEAN ProcessorAdded
    );

//
// Network Layer Provider Handlers.
//
    
NL_PROVIDER_QUERY_INTERFACE IpNlpQueryInterface;
NL_PROVIDER_SET_INTERFACE IpNlpSetInterface;
NL_PROVIDER_QUERY_INTERFACE_PROPERTY IpNlpQueryInterfaceProperty;
NL_PROVIDER_SET_INTERFACE_PROPERTY IpNlpSetInterfaceProperty;
NL_PROVIDER_REFERENCE_INTERFACE IpNlpReferenceInterface;
NL_PROVIDER_DEREFERENCE_INTERFACE IpNlpDereferenceInterface;


//
// Framing Layer Client Handlers.
//

FL_CLIENT_ADD_INTERFACE IpFlcAddInterface;
FL_CLIENT_DELETE_INTERFACE IpFlcDeleteInterface;
FL_CLIENT_UPDATE_INTERFACE IpFlcUpdateInterface;

FL_CLIENT_ADD_SUBINTERFACE IpFlcAddSubInterface;
FL_CLIENT_DELETE_SUBINTERFACE IpFlcDeleteSubInterface;
FL_CLIENT_UPDATE_SUBINTERFACE IpFlcUpdateSubInterface;

FL_CLIENT_PNP_EVENT IpFlcPnpEvent;


//
// Network Layer Management Provider Handlers.
//
    
NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllInterfaceParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllInterfaceParameters;

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllSubInterfaceParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllSubInterfaceParameters;

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllInterfaceHopParameters;

NM_PROVIDER_REGISTER_CHANGE_NOTIFICATION
    IpRegisterInterfaceChangeNotification;
NM_PROVIDER_DEREGISTER_CHANGE_NOTIFICATION 
    IpDeregisterInterfaceChangeNotification;

NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllWakeUpPatternParameters;


//
// Network layer pnp event provider handler.
//
NL_PNP_EVENT_PROVIDER_COMPLETE IpNlpPnpEventCompleteInterface;

#endif // _INTERFACE_
