/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    protocol.h

Abstract:

    This module contains declarations for the network layer module's
    protocol management.

Author:

    Mohit Talwar (mohitt) Tue Nov 19 10:20:42 2002

Environment:

    Kernel mode only.

--*/

#ifndef _PROTOCOL_
#define _PROTOCOL_

#pragma once

#define IP_ECHO_REQUEST_TABLE_SIZE  7

//
// IP_GLOBAL_STATISTICS
//
// Define statistics kept for each protocol.
//
// We use 64-bit counters for values which may wrap around within an hour
// (e.g. Transmit and Receive count for interfaces with speed > 20 Mbps).
// These cannot be updated atomically with interlocked operations.  Also, 
// to avoid that performance hit we accept inaccuracies in 32-bit counters.
//

typedef struct CACHE_ALIGN _IP_GLOBAL_STATISTICS {
    ULONG64 InReceives;
    ULONG64 InOctets;
    ULONG64 InForwardedDatagrams;
    ULONG64 InDelivers;
    ULONG64 OutRequests;
    ULONG64 OutForwardedDatagrams;
    ULONG64 OutTransmits;
    ULONG64 OutOctets;
    ULONG64 InMulticastPackets;
    ULONG64 InMulticastOctets;
    ULONG64 OutMulticastPackets;
    ULONG64 OutMulticastOctets;
    ULONG64 InBroadcastPackets;
    ULONG64 OutBroadcastPackets;

    ULONG InHeaderErrors;
    ULONG InNoRoutes;
    ULONG InAddressErrors;
    ULONG InUnknownProtocols;
    ULONG InTruncatedPackets;
    ULONG ReassemblyRequireds;
    ULONG ReassemblyOks;
    ULONG ReassemblyFailures;
    ULONG InDiscards;
    ULONG OutNoRoutes;
    ULONG OutDiscards;

    ULONG FragmentOks;
    ULONG FragmentFailures;
    ULONG FragmentsCreated;
    ULONG RoutingDiscards;

    ULONG OutFilterDrops;
    ULONG InFilterDrops;

    ULONG OutIpsecErrors;
    ULONG InIpsecEspOverUdpPackets;
    ULONG OutIpsecEspOverUdpPackets;
} IP_GLOBAL_STATISTICS, *PIP_GLOBAL_STATISTICS;
C_ASSERT(sizeof(IP_GLOBAL_STATISTICS) % MAX_CACHE_LINE_SIZE == 0);

#define IP_DEFAULT_HOP_LIMIT 0x80

#define IP_DEFAULT_MULTICAST_HOP_LIMIT 1

typedef struct _IP_PROTOCOL {
    //
    // Protocol constants
    //

    //
    // Set once, during initialization.
    //
    BOOLEAN Installed;
    NL_DISABLED_COMPONENTS DisabledComponents;
    
    CONST UCHAR *TraceString;
    CONST NL_PROVIDER_CHARACTERISTICS *Characteristics;
    IPPROTO Level;
    ADDRESS_FAMILY Family;
    PNPI_MODULEID ModuleId;
    USHORT MinimumMtu;
    USHORT HeaderSize;
    USHORT HeaderAlignment;
    USHORT TtlOffset;
    USHORT RouteKeySize;
    USHORT UnicastRouteSize;
    USHORT PathSize;
    USHORT SessionMulticastSourceSize;
    USHORT LocalMulticastSourceSize;
    BOOLEAN DefaultDhcpEnabled;
    NL_ROUTER_DISCOVERY_BEHAVIOR DefaultRouterDiscoveryBehavior;
    ULONG MaximumIcmpErrorPayloadLength;
    ULONG MinimumOnLinkPrefixLength;
    ULONG MinimumMulticastPrefixLength;
    
    OFFLOAD_STATE_TYPE PathOffloadFullStateType;
    OFFLOAD_STATE_TYPE PathOffloadCachedStateType;
    OFFLOAD_STATE_TYPE PathOffloadDelegatedStateType;
    PIP_INTERNAL_VALIDATE_NET_BUFFER ValidateNetBuffer;
    PIP_INTERNAL_ADDRESS_INTERFACE AddressInterface;
    PIP_INTERNAL_ADD_LINK_LAYER_SUFFIX_ADDRESSES AddLinkLayerSuffixAddresses;
    PIP_INTERNAL_UNADDRESS_INTERFACE UnAddressInterface;
    PIP_INTERNAL_INITIALIZE_SUBINTERFACE InitializeSubInterface;
    PIP_INTERNAL_ADD_ADDRESS_HELPER AddressCreationHelper;
    PIP_INTERNAL_DELETE_ADDRESS_HELPER AddressDeletionHelper;
    PIP_INTERNAL_START_ADVERTISING StartAdvertising;
    PIP_INTERNAL_STOP_ADVERTISING StopAdvertising;
    PIP_INTERNAL_ADDRESS_SCOPE AddressScope;
    PIP_INTERNAL_ADDRESS_TYPE AddressType;
    PIP_INTERNAL_MAKE_ROUTE_KEY MakeRouteKey;
    PIP_INTERNAL_PARSE_ROUTE_KEY ParseRouteKey;
    PIP_INTERNAL_NOTIFY_ROUTE_CHANGE NotifyRouteChange;
    PIP_INTERNAL_FRAGMENT_PACKET_HELPER FragmentPacketHelper;
    PIP_INTERNAL_IS_FRAGMENT IsFragment;
    PIP_INTERNAL_REASSEMBLY_TIMEOUT ReassemblyTimeout;
    PIP_INTERNAL_VALIDATE_HOP_BY_HOP_OPTIONS_FOR_SEND 
        ValidateHopByHopOptionsForSend;
    PIP_INTERNAL_FILL_HEADER_INCLUDE_PROTOCOL_HEADER
        FillHeaderIncludeProtocolHeader;
    PIP_INTERNAL_FILL_PROTOCOL_HEADER FillProtocolHeader;
    PIP_INTERNAL_UPDATE_PROTOCOL_HEADER UpdateProtocolHeader;
    PIP_INTERNAL_SKIP_NETWORK_LAYER_HEADERS SkipNetworkLayerHeaders;
    PIP_INTERNAL_CREATE_MULTICAST_REPORT CreateMulticastDiscoveryReport;
    PIP_INTERNAL_IS_MULTICAST_DISCOVERY_ALLOWED IsMulticastDiscoveryAllowed;
    PIP_INTERNAL_PATH_MTU_TIMEOUT PathMtuDiscoveryTimeout;
    PIP_INTERNAL_SEND_REDIRECT SendRedirect;
    PIP_INTERNAL_GET_SOLICITATION_SOURCE GetSolicitationSource;
    PIP_INTERNAL_SEND_NEIGHBOR_SOLICITATION SendNeighborSolicitation;
    PIP_INTERNAL_SEND_NEIGHBOR_ADVERTISEMENT SendNeighborAdvertisement;
    PIP_INTERNAL_VALIDATE_ROUTING_HEADER_FOR_SEND ValidateRoutingHeaderForSend;
    PIP_INTERNAL_INTERFACE_SET_TIMEOUT InterfaceSetTimeout;

    //
    // Multicast discovery report header sizes. 
    //
    USHORT MulticastHeaderSize;
    USHORT MulticastReportHeaderSize;
    USHORT MulticastRecordHeaderSize;

    //
    // Network Layer Provider State.
    //
    NPI_PROVIDER_CHARACTERISTICS NlProviderNotify;
    HANDLE NlProviderHandle;
    CONST NL_PROVIDER_DISPATCH *NlProviderDispatch;
    LOCKED_LIST NlClientSet;

    IP_RECEIVE_DEMUX ReceiveDemux[IPPROTO_RESERVED_MAX];

    //
    // Framing Layer Client State. 
    //
    NPI_CLIENT_CHARACTERISTICS FlClientNotify;
    HANDLE FlClientHandle;
    CONST FL_CLIENT_DISPATCH *FlClientDispatch;
    
    //
    // NSI Module Provider State.
    //
    NPI_PROVIDER_CHARACTERISTICS NsiProviderNotify;
    HANDLE NsiProviderHandle;
    CONST NM_PROVIDER_DISPATCH *NsiProviderDispatch;

    //
    // Temporary address configuration.
    //
    NL_TEMPORARY_ADDRESS_MODE UseTemporaryAddresses;
    ULONG MaxTemporaryValidLifetime;        // in ticks.
    ULONG MaxTemporaryPreferredLifetime;    // in ticks.
    ULONG MaxTemporaryDadAttempts;
    ULONG TemporaryRegenerateAdvance;       // in ticks.
    ULONG MaxTemporaryDesyncFactor;         // in ticks.
    ULONG TemporaryDesyncFactor;            // in ticks.

    //
    // Parameters related to dead-gateway detection. 
    //
    ULONG DeadRouteProbeTimeout;            // in ticks.
    ULONG DeadRouteTimeout;                 // in ticks.
    ULONG PathUnreachableTimeout;           // in ticks.
    ULONG DeadRouteProbeTrafficPercent;

    //
    // Link local address configuration.
    //
    NL_LINK_LOCAL_ADDRESS_BEHAVIOR LinkLocalAddressBehavior;
    ULONG LinkLocalAddressTimeout;          // in ticks.
    //
    // Global prefix to use when autogenerating an IPV4 address.
    //
    IP_ADDRESS_STORAGE LinkLocalAddressPrefix; 
    //
    // Global prefix length to use when autogenerating IPV4 address.
    //
    ULONG LinkLocalAddressPrefixLength; 

    //
    // Other configurable global parameters.
    //
    UINT8 DefaultHopLimit;
    ULONG PathCacheLimit;
    NL_SOURCE_ROUTING_BEHAVIOR SourceRoutingBehavior;
    NL_MLD_LEVEL MldLevel;
    MULTICAST_DISCOVERY_VERSION MaximumMldVersion;
    ULONG DadTransmits;
    NL_COMPARTMENT_FORWARDING EnableForwarding;
    BOOLEAN EnableIcmpRedirects;
    BOOLEAN EnableAddrMaskReply;    
    BOOLEAN DisableTaskOffload;
    BOOLEAN EnableNonUnicastDatalinkAddresses;
    BOOLEAN DisableMediaSense;
    BOOLEAN DisableMediaSenseEventLog;
    BOOLEAN EnableMulticastForwarding;
    BOOLEAN GroupForwardedFragments;
    BOOLEAN RandomizeIdentifiers;
    BOOLEAN OverrideDefaultAddressSelection;    
    
    //
    // Modules. 
    //
    CONST NL_MODULE *Modules;
    ULONG ModuleCount;
    LONG ModuleStatus;

    //
    // Ping request variables.
    //
    LIST_ENTRY EchoRequestTable[IP_ECHO_REQUEST_TABLE_SIZE];
    KSPIN_LOCK EchoRequestTableLock;
    PRTL_TIMER_WHEEL EchoRequestTimerTable;
    KSPIN_LOCK EchoRequestTimerWheelLock;
    ULONG EchoRequestTimerTableInitialized;
    ULONG EchoRequestSequence;
    ULONG EchoFailedNotifications;
    BOOLEAN EchoShutdown;
    KEVENT EchoShutdownEvent;
    
    LOCKED_LIST FlProviderSet;
    LIST_ENTRY FlProviderDetachingList;
    LOCKED_LIST CompartmentSet;
    LOCKED_LIST GlobalInterfaceSet;
    BLOCK_TYPE LocalAddressIdentifierBlockType;
    BLOCK_TYPE LocalUnicastAddressBlockType;
    BLOCK_TYPE LocalBroadcastAddressBlockType;
    BLOCK_TYPE LocalAnycastAddressBlockType;
    HANDLE LocalMulticastAddressPool;
    NDIS_HANDLE UnicastRoutePool;
    NDIS_HANDLE PathPool;
    NDIS_HANDLE ControlPool;
    RTL_MRSW_LOCK ZoneUpdateLock;

    IP_GENERIC_LIST LoopbackQueue;
    KSPIN_LOCK LoopbackQueueLock;
    PIO_WORKITEM LoopbackWorkItem;
    BOOLEAN IsLoopbackTransmitScheduled;
    
    NL_CONTROL_PROTOCOL_ROD IcmpStatistics;

    PIP_GLOBAL_STATISTICS PerProcessorStatistics;

    //
    // Cumulative offload statistics for interfaces that no longer exist.
    //
    FAST_MUTEX OffloadStatsMutex;
    IP_OFFLOAD_STATS OffloadStats;

    PNMP_CLIENT_CONTEXT NmClientContext;
    REFERENCE_OBJECT NmClientReferenceObject;

    PPNP_EVENT_CLIENT_CONTEXT PnpClientContext;
    REFERENCE_OBJECT PnpClientReferenceObject;
    
    REASSEMBLY_SET ReassemblySet;
} IP_PROTOCOL, *PIP_PROTOCOL;

extern IP_PROTOCOL Ipv4Global;
extern IP_PROTOCOL Ipv6Global;

__inline
VOID
IppDereferenceNsiClientContext(
    IN PIP_PROTOCOL Protocol
    )
{
    if (RoDereference(&Protocol->NmClientReferenceObject)) {
        NmrProviderDetachClientComplete(
            Protocol->NmClientContext->PendingDetachBindingHandle);
    }
}


__inline
BOOLEAN
IppReferencePnpEventClientContext(
    IN PIP_PROTOCOL Protocol
    )
{
    return RoReference(&Protocol->PnpClientReferenceObject);
}

__inline
VOID
IppDereferencePnpEventClientContext(
    IN PIP_PROTOCOL Protocol
    )
{     
    if (RoDereference(&Protocol->PnpClientReferenceObject)) {
        NmrProviderDetachClientComplete(
            Protocol->PnpClientContext->PendingDetachBindingHandle);
    }
}

VOID 
IppInitializeProtocolSettings(
    PIP_PROTOCOL Protocol
    );

//
// Bits of ModuleStatus field
//
#define IMS_NL_PROVIDER             0x0001
#define IMS_FL_CLIENT               0x0002
#define IMS_COMPARTMENT_MANAGER     0x0004
#define IMS_NSI_PROVIDER            0x0008
#define IMS_NA_CLIENT               0x0010
#define IMS_ECHO_REQUEST_MANAGER    0x0020
#define IMS_PREFIX_POLICY           0x0040
#define IMS_NEXT_HEADER_PROCESSOR   0x0100
#define IMS_VALIDATER               0x0200
#define IMS_TIMER                   0x0400
#define IMS_ROUTE_MANAGER           0x0800
#define IMS_ADDRESS_MANAGER         0x1000
#define IMS_INTERFACE_MANAGER       0x2000
#define IMS_LOOPBACK_MANAGER        0x4000
#define IMS_PNP_EVENT_PROVIDER      0x8000

#define IMS_TIMER_REQUIRED_MODULES ( \
    IMS_COMPARTMENT_MANAGER | \
    IMS_INTERFACE_MANAGER | \
    IMS_ADDRESS_MANAGER | \
    IMS_ROUTE_MANAGER | \
    IMS_VALIDATER | \
    IMS_NEXT_HEADER_PROCESSOR | \
    IMS_ECHO_REQUEST_MANAGER \
    )

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllGlobalParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllGlobalParameters;

#endif // _PROTOCOL_
