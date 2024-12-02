/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    ipv6p.h

Abstract:

    This module contains the private (internal) definitions and structures
    for IPv6.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#ifndef _IPV6P_
#define _IPV6P_

#include "ipngp.h"
#include "ip6def.h"

//
// IPv6 Global Variables.
//
extern LOCKED_LIST Ipv6NlClientSet;
extern IP_RECEIVE_DEMUX Ipv6HeaderDemux;
extern IP_RECEIVE_DEMUX Icmpv6Demux;
extern IP_RECEIVE_DEMUX Ipv6FragmentDemux;

//
// Various constants from the IPv6 RFCs...
//
#define PREFIX_LIFETIME_SAFETY          IppTimerTicks(2 * HOURS) // 2 hours.
#define MLD_UNSOLICITED_REPORT_INTERVAL IppTimerTicks(10 * SECONDS)  // 10 secs.
#define MLD_QUERY_INTERVAL              IppTimerTicks(125 * SECONDS) // 125 sec.
#define MLD_NUM_INITIAL_REPORTS         2
#define MAX_TEMPORARY_DAD_ATTEMPTS      5
#define MAX_TEMPORARY_PREFERRED_LIFETIME IppTimerTicks(24 * HOURS)  // 1 day.
#define MAX_TEMPORARY_VALID_LIFETIME    (7 * MAX_TEMPORARY_PREFERRED_LIFETIME)
#define TEMPORARY_REGENERATE_ADVANCE    IppTimerTicks(5 * SECONDS)  // 5 secs.
#define MAX_TEMPORARY_DESYNC_FACTOR     IppTimerTicks(10 * MINUTES) // 10 mins.
#define MAX_IPV6_PAYLOAD                65535

//
// Address structures.
//

typedef struct _IPV6_ADDRESS_IDENTIFIER {
    IP_ADDRESS_IDENTIFIER;
    IN6_ADDR Ipv6Address;
} IPV6_ADDRESS_IDENTIFIER, *PIPV6_ADDRESS_IDENTIFIER;

C_ASSERT(FIELD_OFFSET(IPV6_ADDRESS_IDENTIFIER, Ipv6Address) == 
         sizeof(IP_ADDRESS_IDENTIFIER));

//
// Structure for holding information about deferred neighbor advertisements for
// anycast addresses. 
//

typedef struct _IPV6_ANYCAST_ADVERTISEMENT {
    IP_ANYCAST_ADVERTISEMENT;
    
    IN6_ADDR SourceAddress;
} IPV6_ANYCAST_ADVERTISEMENT, *PIPV6_ANYCAST_ADVERTISEMENT;

typedef struct _IPV6_SESSION_MULTICAST_SOURCE {
    IP_SESSION_MULTICAST_SOURCE;
    IN6_ADDR Ipv6Address;
} IPV6_SESSION_MULTICAST_SOURCE, *PIPV6_SESSION_MULTICAST_SOURCE;

typedef struct _IPV6_LOCAL_MULTICAST_SOURCE {
    IP_LOCAL_MULTICAST_SOURCE;
    IN6_ADDR Ipv6Address;
} IPV6_LOCAL_MULTICAST_SOURCE, *PIPV6_LOCAL_MULTICAST_SOURCE;

//
// IPV6_NEIGHBOR
//
// Define the IPv6 neighbor state.
//

typedef struct _IPV6_NEIGHBOR {
    IP_NEIGHBOR;                // Base structure.
    IN6_ADDR Ipv6Address;       // IPv6 address of neighboring interface.
    UCHAR DlAddress[0];         // Datalink address corresponding to above.
} IPV6_NEIGHBOR, *PIPV6_NEIGHBOR;

C_ASSERT((sizeof(IPV6_NEIGHBOR) + DL_ADDRESS_LENGTH_MAXIMUM) < PAGE_SIZE / 16);
C_ASSERT(FIELD_OFFSET(IPV6_NEIGHBOR, Ipv6Address) == sizeof(IP_NEIGHBOR));

typedef struct _IPV6_UNICAST_ROUTE {
    IP_UNICAST_ROUTE;
    IN6_ADDR NextHopAddress; // if not a directly-attached subnet route.
    HANDLE32 CurrentCareOfAddressRouteHandle;
} IPV6_UNICAST_ROUTE, *PIPV6_UNICAST_ROUTE;

C_ASSERT(FIELD_OFFSET(IPV6_UNICAST_ROUTE, NextHopAddress) ==
         sizeof(IP_UNICAST_ROUTE));


//
// IPV6_POTENTIAL_ROUTER. 
// 
// Defines an entry for the potential router list. 
//

typedef struct _IPV6_POTENTIAL_ROUTER {
    IP_POTENTIAL_ROUTER;
    IN6_ADDR Address;
} IPV6_POTENTIAL_ROUTER, *PIPV6_POTENTIAL_ROUTER;

PIPV6_POTENTIAL_ROUTER
Ipv6pFindPotentialRouterUnderLock(
    IN PIP_INTERFACE Interface, 
    IN CONST IN6_ADDR *RouterAddress
    );

//
// Offload functions. 
//
FL_CLIENT_QUERY_OFFLOAD_COMPLETE Ipv6QueryOffloadComplete;

//
// Internal Address Manager functions.
//
NTSTATUS
Ipv6pStartAddressManager(
    IN PIP_PROTOCOL Protocol
    );

IP_INTERNAL_ADDRESS_INTERFACE Ipv6pAddressInterface;
IP_INTERNAL_ADD_LINK_LAYER_SUFFIX_ADDRESSES Ipv6pAddLinkLayerSuffixAddresses;
IP_INTERNAL_INITIALIZE_SUBINTERFACE Ipv6pInitializeSubInterface;
IP_INTERNAL_IS_LOOPBACK_ADDRESS Ipv6pIsLoopbackAddress;

VOID
Ipv6pUnAddressInterface(
    IN PIP_INTERFACE Interface
    );

IP_INTERNAL_ADD_ADDRESS_HELPER Ipv6pFindOrCreateSolicitedNodeGroup;
IP_INTERNAL_DELETE_ADDRESS_HELPER Ipv6pFindAndReleaseSolicitedNodeGroup;


//
// Neighbor Discovery functions.
//

BOOLEAN
Ipv6pParseTlvOption(
    IN PNET_BUFFER NetBuffer,
    OUT PUCHAR Type,
    OUT PUSHORT Length
    );

VOID
Ipv6pHandleAnycastAdvertisementTimeout(
    IN PIP_INTERFACE Interface
    );

VOID
Ipv6pHandleNeighborSolicitation(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    );

VOID
Ipv6pHandleNeighborAdvertisement(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    );

__inline
PIP_LOCAL_UNICAST_ADDRESS
Ipv6pGetSolicitationSource(
    IN PIP_NEIGHBOR Neighbor
    )
{
    //
    // Try the interface's link-local address.
    //
    return IppFindLinkLocalUnicastAddress(Neighbor->SubInterface->Interface);
}

IP_INTERNAL_SEND_NEIGHBOR_SOLICITATION Ipv6pSendNeighborSolicitation;

IP_INTERNAL_SEND_NEIGHBOR_ADVERTISEMENT Ipv6pSendNeighborAdvertisement;

//
// Router Discovery functions.
//
VOID
Ipv6pRouterDiscoveryTimeout(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN ForceRouterAdvertisement
    );

VOID
Ipv6pHandleRouterSolicitation(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    );

VOID
Ipv6pHandleRouterAdvertisement(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    );

VOID
Ipv6pHandleRedirect(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    );

IP_INTERNAL_SEND_REDIRECT Ipv6pSendRedirect;

IP_INTERNAL_START_ADVERTISING Ipv6pStartAdvertising;
IP_INTERNAL_STOP_ADVERTISING Ipv6pStopAdvertising;


//
// Internal Route Manager functions
//

typedef struct _IPV6_PATH {
    IP_PATH;
    IN6_ADDR Ipv6DestinationAddress;
} IPV6_PATH, *PIPV6_PATH;

//
// TODO: currently the path structure is bigger than PAGE_SIZE / 16
//       should fix then uncomment line below.
//
//C_ASSERT(sizeof(IPV6_PATH) < (PAGE_SIZE / 16));

C_ASSERT(sizeof(IPV6_PATH) < (PAGE_SIZE / 8));

NTSTATUS
Ipv6pGetNeighborFromUnicastRoute(
    IN PIPV6_UNICAST_ROUTE Route,
    OUT PIP_NEIGHBOR *Neighbor
    );

IP_INTERNAL_NOTIFY_ROUTE_CHANGE Ipv6pNotifyRouteChange;

NM_PROVIDER_GET_ALL_PARAMETERS Ipv6GetAllPathParameters;
NM_PROVIDER_SET_ALL_PARAMETERS Ipv6SetAllPathParameters;
NM_PROVIDER_ENUMERATE_OBJECTS_ALL_PARAMETERS Ipv6EnumerateAllPaths;

NM_PROVIDER_SET_ALL_PARAMETERS Ipv6SetAllRouteParameters;
NM_PROVIDER_GET_ALL_PARAMETERS Ipv6GetAllBestRouteParameters;

NM_PROVIDER_GET_ALL_PARAMETERS Ipv6GetAllPotentialRouters;
NM_PROVIDER_SET_ALL_PARAMETERS Ipv6SetAllPotentialRouters;
NM_PROVIDER_GET_ALL_PARAMETERS Ipv6GetAllEchoRequestParameters;
NM_PROVIDER_SET_ALL_PARAMETERS Ipv6SetAllEchoRequestParameters;

NM_PROVIDER_GET_ALL_PARAMETERS Ipv6GetAllMulticastForwardingParameters;
NM_PROVIDER_SET_ALL_PARAMETERS Ipv6SetAllMulticastForwardingParameters;

__inline
VOID
Ipv6pInvalidateRouter(
    IN PIPV6_NEIGHBOR Neighbor
    )
{
    DBG_UNREFERENCED_PARAMETER(Neighbor);

    // TODO: STATUS_NOT_IMPLEMENTED
    ASSERT(FALSE);
}

//
// Multicast discovery functions. 
//
IP_INTERNAL_CREATE_MULTICAST_REPORT MldpCreateMulticastDiscoveryReport;
IP_INTERNAL_IS_MULTICAST_DISCOVERY_ALLOWED MldpIsMulticastDiscoveryAllowed;

VOID
Ipv6pHandleMldQuery(
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    );

VOID
Ipv6pHandleMldReport(
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    );

//
// Path MTU discovery timeout function.
//
IP_INTERNAL_PATH_MTU_TIMEOUT Ipv6pPathMtuDiscoveryTimeout;

//
// Internal Packetizer functions.
//
IP_INTERNAL_VALIDATE_HOP_BY_HOP_OPTIONS_FOR_SEND 
    Ipv6pValidateHopByHopOptionsForSend;
IP_INTERNAL_FILL_HEADER_INCLUDE_PROTOCOL_HEADER
    Ipv6pFillHeaderIncludeProtocolHeader;
IP_INTERNAL_FILL_PROTOCOL_HEADER Ipv6pFillProtocolHeader;
IP_INTERNAL_UPDATE_PROTOCOL_HEADER Ipv6pUpdateProtocolHeader;
IP_INTERNAL_SKIP_NETWORK_LAYER_HEADERS Ipv6pSkipNetworkLayerHeaders;

IP_INTERNAL_ADD_HEADER Ipv6pAddHopByHopOptionsHeader;
IP_INTERNAL_ADD_HEADER Ipv6pAddRoutingHeader;

//
// Internal Validater functions.
//
IP_DISCARD_REASON
Ipv6pProcessOptions(
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    );

IP_INTERNAL_VALIDATE_NET_BUFFER Ipv6pValidateNetBuffer;

IP_INTERNAL_VALIDATE_ROUTING_HEADER_FOR_SEND Ipv6pValidateRoutingHeaderForSend;

//
// Internal Fragmenter functions.
//
IP_INTERNAL_FRAGMENT_PACKET_HELPER Ipv6pFragmentPacketHelper;

//
// Internal Reassembler functions.
//
IP_INTERNAL_IS_FRAGMENT Ipv6pIsFragment;
IP_INTERNAL_REASSEMBLY_TIMEOUT Ipv6pReassemblyTimeout;

//
// Internal Next Header Processor functions.
//
IP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER Ipv6pDeferredAuthenticateIpv6Header;
IP_INTERNAL_AUTHENTICATE_HEADER Ipv6pAuthenticateOptions;
IP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER Ipv6pDeferredAuthenticateOptions;
IP_INTERNAL_AUTHENTICATE_HEADER Ipv6pAuthenticateRoutingHeader;
IP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER Ipv6pDeferredAuthenticateRoutingHeader;

NTSTATUS
Ipv6pStartNextHeaderProcessor(
    IN PIP_PROTOCOL Protocol
    );

//
// Internal timer functions
//

IP_INTERNAL_INTERFACE_SET_TIMEOUT Ipv6pInterfaceSetTimeout;

//
// Internal Control Receiver functions
//
IP_INTERNAL_RECEIVE_DATAGRAMS Icmpv6ReceiveDatagrams;
IP_INTERNAL_RECEIVE_CONTROL_MESSAGE Icmpv6ReceiveControlMessage;
IP_INTERNAL_RECEIVE_CONTROL_MESSAGE Ipv6pReceiveFragmentControl;

//
// Path MTU discovery functions. 
//
NTSTATUS
Ipv6pUpdatePathMtu(
    IN PIP_LOCAL_ADDRESS LocalAddress,
    IN PICMPV6_MESSAGE Icmpv6,
    IN PIPV6_HEADER Ipv6Header
    );

NETIO_INLINE
BOOLEAN
Ipv6pPathMtuTimeoutFired(
    IN PIP_PATH Path,
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    This routine checks the condition for increasing the path MTU. The timeout
    should happen at least 10 minutes (this is configurable using the interface
    RW parameters and can be said to infinity) after the last MTU
    decrease. Also, there is no need to go any further if we are currently at
    the link MTU; we cannot increase the MTU beyond the link MTU. 

Arguments:

    Path - Supplies the path for which the condition need to be checked. 

    Interface - Supplies the interface on which the path exists. 

    SubInterface - Supplies the sub-interface of the outgoing interface. 

Return Value:

    Returns a boolean which is TRUE if the MTU needs to be increased; FALSE
    otherwise. 

Caller LOCK:

    Can be called with or without the bucket lock held.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    return ((Path->PathMtu < SubInterface->NlMtu) &&
            ((IppTickCount - Path->PathMtuLastSet) >= 
             Interface->PathMtuDiscoveryTicks));
}

NETIO_INLINE
ULONG
Ipv6pGetMtuFromPath(
    IN PIP_PATH Path,
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    Get the Path MTU from a Path. This routine also lazily calls the timeout
    function to increase the path MTU if needed. 

    Note that Path MTU is volatile unless the PathSet is locked.

Arguments: 

    Path - Supplies the path from which to get the MTU. 

    Interface - Supplies the interface on which the path exists. 

    SubInterface - Supplies the sub-interface of the outgoing interface. 

--*/
{
    //
    // We lazily check to see if it's time to probe for an increased Path
    // MTU as this is perceived to be cheaper than routinely running through
    // all our Paths looking for one whose PMTU timer has expired. Also, the
    // check is done without the bucket lock so that on the fast path, we don't
    // acquire any locks. In order to prevent multiple timeouts from firing at
    // the same time, we check the condition again after acquiring the lock
    // (inside Ipv6pPathMtuTimeoutFired).
    //
    if (Ipv6pPathMtuTimeoutFired(Path, Interface, SubInterface)) {
        Ipv6pPathMtuDiscoveryTimeout(Path, Interface, SubInterface);
    }

    return Path->PathMtu;
}

//
// Some handy functions for working with IPv6 addresses.
//

__inline IN6_ADDR *
AlignAddr(IN6_ADDR UNALIGNED *Addr)
{
    //
    // IPv6 addresses only have char & short members,
    // so they need 2-byte alignment.
    // In practice addresses in headers are always
    // appropriately aligned.
    //
    ASSERT(((UINT_PTR)Addr % __builtin_alignof(IN6_ADDR)) == 0);
    return (IN6_ADDR *) Addr;
}

extern IP_SESSION_STATE IcmpEchoRequestSessionState;
#endif // _IPV6P_
