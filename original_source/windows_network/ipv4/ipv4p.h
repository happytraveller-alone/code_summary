/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    ipv4p.h

Abstract:

    This module contains the private (internal) definitions and structures
    for IPv4.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#ifndef _IPV4P_
#define _IPV4P_

#include "ipngp.h"
#include "ip4def.h"

//
// IPv4 Global Variables.
//
extern LOCKED_LIST Ipv4NlClientSet;
extern IP_RECEIVE_DEMUX Icmpv4Demux;
extern IP_RECEIVE_DEMUX IgmpDemux;
extern IP_RECEIVE_DEMUX Ipv4FragmentDemux;

//
// Various constants from the IPv4 RFCs...
//
#define MAX_IPV4_PACKET 65535

//
// Per RFC 791, a router "must be able to forward a datagram of 68 octets 
// without fragmentation". This is our minimum legal MTU value.
//
#define IPV4_MINIMUM_LEGAL_MTU 68

//
// We use a minimum valid MTU of 596.  The path MTU can not go below this
// value.  However, if we do detect that the path MTU is lower, then we clear
// the don't fragment bit in all packets that use the path (even though the
// path MTU still remains >= IPV4_MINIMUM_VALID_MTU). 
//

#define IPV4_MINIMUM_VALID_MTU 596

//
// Default link-local address configuration timeout.  This is the time we wait
// for DHCP/static addresses to be added before adding an link-local address. 
// Default is 6.5 seconds (3 seconds for DHCP + 3 seconds for DAD + 0.5
// seconds fudge factor). 
//
#define IPV4_LINK_LOCAL_CONFIGURATION_TIMEOUT \
    ((ULONG) IppTimerTicks(6.5 * SECONDS))

//
// Address strucutures.
//

typedef struct _IPV4_ADDRESS_IDENTIFIER {
    IP_ADDRESS_IDENTIFIER;
    IN_ADDR Ipv4Address;
} IPV4_ADDRESS_IDENTIFIER, *PIPV4_ADDRESS_IDENTIFIER;

C_ASSERT(FIELD_OFFSET(IPV4_ADDRESS_IDENTIFIER, Ipv4Address) == 
         sizeof(IP_ADDRESS_IDENTIFIER));

typedef struct _IPV4_SESSION_MULTICAST_SOURCE {
    IP_SESSION_MULTICAST_SOURCE;
    IN_ADDR Ipv4Address;
} IPV4_SESSION_MULTICAST_SOURCE, *PIPV4_SESSION_MULTICAST_SOURCE;

typedef struct _IPV4_LOCAL_MULTICAST_SOURCE {
    IP_LOCAL_MULTICAST_SOURCE;
    IN_ADDR Ipv4Address;
} IPV4_LOCAL_MULTICAST_SOURCE, *PIPV4_LOCAL_MULTICAST_SOURCE;

//
// IPV4_NEIGHBOR
//
// Define the IPv4 neighbor state.
//

typedef struct _IPV4_NEIGHBOR {
    IP_NEIGHBOR;                // Base structure.
    IN_ADDR Ipv4Address;        // IPv4 address of neighboring interface.
    UCHAR DlAddress[0];         // Datalink address corresponding to above.
} IPV4_NEIGHBOR, *PIPV4_NEIGHBOR;

C_ASSERT((sizeof(IPV4_NEIGHBOR) + DL_ADDRESS_LENGTH_MAXIMUM) < PAGE_SIZE / 16);
C_ASSERT(FIELD_OFFSET(IPV4_NEIGHBOR, Ipv4Address) == sizeof(IP_NEIGHBOR));

typedef struct _IPV4_UNICAST_ROUTE {
    IP_UNICAST_ROUTE;
    IN_ADDR NextHopAddress; // if not a directly-attached subnet route.
    HANDLE32 CurrentCareOfAddressRouteHandle;
} IPV4_UNICAST_ROUTE, *PIPV4_UNICAST_ROUTE;

C_ASSERT(FIELD_OFFSET(IPV4_UNICAST_ROUTE, NextHopAddress) ==
         sizeof(IP_UNICAST_ROUTE));


//
// Offload functions.
//
FL_CLIENT_QUERY_OFFLOAD_COMPLETE Ipv4QueryOffloadComplete;

//
// Internal Address Manager functions
//
NTSTATUS
Ipv4pStartAddressManager(
    IN PIP_PROTOCOL Protocol
    );

IP_INTERNAL_ADDRESS_INTERFACE Ipv4pAddressInterface;
IP_INTERNAL_ADD_LINK_LAYER_SUFFIX_ADDRESSES Ipv4pAddLinkLayerSuffixAddresses;
IP_INTERNAL_INITIALIZE_SUBINTERFACE Ipv4pInitializeSubInterface;
IP_INTERNAL_IS_LOOPBACK_ADDRESS Ipv4pIsLoopbackAddress;


VOID
Ipv4pUnAddressInterface(
    IN PIP_INTERFACE Interface
    );

//
// Internal Route Manager functions
//
typedef struct _IPV4_PATH {
    IP_PATH;
    IN_ADDR Ipv4DestinationAddress;
} IPV4_PATH, *PIPV4_PATH;

//
// TODO: currently the path structure is bigger than PAGE_SIZE / 16
//       should fix then uncomment line below.
//
//C_ASSERT(sizeof(IPV4_PATH) < (PAGE_SIZE / 16));

C_ASSERT(sizeof(IPV4_PATH) < (PAGE_SIZE / 8));

NTSTATUS
Ipv4pGetNeighborFromUnicastRoute(
    IN PIPV4_UNICAST_ROUTE Route,
    OUT PIP_NEIGHBOR *Neighbor
    );

IP_INTERNAL_NOTIFY_ROUTE_CHANGE Ipv4pNotifyRouteChange;

NM_PROVIDER_GET_ALL_PARAMETERS Ipv4GetAllPathParameters;
NM_PROVIDER_SET_ALL_PARAMETERS Ipv4SetAllPathParameters;
NM_PROVIDER_ENUMERATE_OBJECTS_ALL_PARAMETERS Ipv4EnumerateAllPaths;

NM_PROVIDER_SET_ALL_PARAMETERS Ipv4SetAllRouteParameters;
NM_PROVIDER_GET_ALL_PARAMETERS Ipv4GetAllBestRouteParameters;

NM_PROVIDER_GET_ALL_PARAMETERS Ipv4GetAllEchoRequestParameters;
NM_PROVIDER_SET_ALL_PARAMETERS Ipv4SetAllEchoRequestParameters;

NM_PROVIDER_GET_ALL_PARAMETERS Ipv4GetAllMulticastForwardingParameters;
NM_PROVIDER_SET_ALL_PARAMETERS Ipv4SetAllMulticastForwardingParameters;

//
// Neighbor Discovery functions.
//

FL_CLIENT_RECEIVE_NEIGHBOR_SOLICITATION Ipv4FlcReceiveNeighborSolicitation;

FL_CLIENT_RECEIVE_NEIGHBOR_ADVERTISEMENT Ipv4FlcReceiveNeighborAdvertisement;

__inline
PIP_LOCAL_UNICAST_ADDRESS
Ipv4pGetSolicitationSource(
    IN PIP_NEIGHBOR Neighbor
    )
{
    //
    // Select the best source address for the destination.
    //
    return
        IppFindBestSourceAddressOnInterfaceUnderLock(
            Neighbor->SubInterface->Interface,
            IP_NEIGHBOR_NL_ADDRESS(Neighbor),
            NULL);
}

IP_INTERNAL_SEND_NEIGHBOR_SOLICITATION Ipv4pSendNeighborSolicitation;

IP_INTERNAL_SEND_NEIGHBOR_ADVERTISEMENT Ipv4pSendNeighborAdvertisement;

//
// Router Discovery functions.
//

VOID
Ipv4pHandleRedirect(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN PIP_REQUEST_CONTROL_DATA Args
    );

IP_INTERNAL_SEND_REDIRECT Ipv4pSendRedirect;

IP_INTERNAL_START_ADVERTISING Ipv4pStartAdvertising;
IP_INTERNAL_STOP_ADVERTISING Ipv4pStopAdvertising;

//
// Multicast discovery functions.
//
IP_INTERNAL_CREATE_MULTICAST_REPORT IgmppCreateMulticastDiscoveryReport;
IP_INTERNAL_IS_MULTICAST_DISCOVERY_ALLOWED IgmppIsMulticastDiscoveryAllowed;

//
// Path MTU timeout discovery function. 
//
IP_INTERNAL_PATH_MTU_TIMEOUT Ipv4pPathMtuDiscoveryTimeout;

//
// Internal Packetizer functions.
//
IP_INTERNAL_VALIDATE_HOP_BY_HOP_OPTIONS_FOR_SEND
    Ipv4pValidateHopByHopOptionsForSend;
IP_INTERNAL_FILL_HEADER_INCLUDE_PROTOCOL_HEADER
    Ipv4pFillHeaderIncludeProtocolHeader;
IP_INTERNAL_FILL_PROTOCOL_HEADER Ipv4pFillProtocolHeader;
IP_INTERNAL_UPDATE_PROTOCOL_HEADER Ipv4pUpdateProtocolHeader;
IP_INTERNAL_SKIP_NETWORK_LAYER_HEADERS Ipv4pSkipNetworkLayerHeaders;

//
// Internal Validater functions.
//
IP_INTERNAL_VALIDATE_NET_BUFFER Ipv4pValidateNetBuffer;
IP_INTERNAL_VALIDATE_ROUTING_HEADER_FOR_SEND Ipv4pValidateRoutingHeaderForSend;

//
// Internal Fragmenter functions.
//
IP_INTERNAL_FRAGMENT_PACKET_HELPER Ipv4pFragmentPacketHelper;

//
// Internal Reassembler functions.
//
IP_INTERNAL_IS_FRAGMENT Ipv4pIsFragment;
IP_INTERNAL_REASSEMBLY_TIMEOUT Ipv4pReassemblyTimeout;

NTSTATUS
Ipv4pStartNextHeaderProcessor(
    IN PIP_PROTOCOL Protocol
    );

IP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER Ipv4pDeferredAuthenticateIpv4Header;

VOID
NTAPI
Ipv4pReceiveFragment(
    IN PIP_REQUEST_CONTROL_DATA Args
    );

//
// Internal timer functions.
//

IP_INTERNAL_INTERFACE_SET_TIMEOUT Ipv4pInterfaceSetTimeout;

//
// Internal Control Receiver functions
//
IP_INTERNAL_RECEIVE_DATAGRAMS Icmpv4ReceiveDatagrams;
IP_INTERNAL_RECEIVE_DATAGRAMS IgmpReceiveDatagrams;
IP_INTERNAL_RECEIVE_CONTROL_MESSAGE Icmpv4ReceiveControlMessage;

//
// Path MTU discovery functions. 
//
NTSTATUS
Ipv4pUpdatePathMtu(
    IN PIP_LOCAL_ADDRESS LocalAddress, 
    IN PICMPV4_MESSAGE Icmpv4,
    IN PIPV4_HEADER Ipv4Header
    );

NETIO_INLINE
BOOLEAN
Ipv4pPathMtuTimeoutFired(
    IN PIP_PATH Path,
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    This routine checks the condition for increasing the path MTU. The timeout
    should happen at least 10 minutes (this is configurable using the interface
    RW parameters and can be set to infinity) after the last MTU decrease and 2
    minutes after the last increase. Also, there is no need to go any further
    if we are currently at the link MTU; we cannot increase the MTU beyond the 
    link MTU. 

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
             (Path->Flags.LastPathMtuChangeWasDecrease ? 
              Interface->PathMtuDiscoveryTicks :
              IPV4_PATH_MTU_INCREASE_TIME)));
}

NETIO_INLINE
ULONG
Ipv4pGetMtuFromPath(
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
    // (inside Ipv4pPathMtuTimeoutFired).
    //
    if (Ipv4pPathMtuTimeoutFired(Path, Interface, SubInterface)) {
        Ipv4pPathMtuDiscoveryTimeout(Path, Interface, SubInterface);
    }

    return Path->PathMtu;
}

//
// ICMP router discovery routines.
//
VOID
Icmpv4HandleRouterAdvertisement(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN IP_REQUEST_CONTROL_DATA *Args
    );

VOID
Icmpv4HandleRouterSolicitation(
    IN CONST ICMPV4_MESSAGE *Icmpv4,
    IN IP_REQUEST_CONTROL_DATA *Args
    );

VOID
Ipv4pRouterDiscoveryTimeout(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN ForceRouterAdvertisement
    );

NETIO_INLINE
VOID
Ipv4pFillPacketChecksum(
    IN PNET_BUFFER Packet
    );
extern IP_SESSION_STATE IcmpEchoRequestSessionState;
#endif // _IPV4P_
