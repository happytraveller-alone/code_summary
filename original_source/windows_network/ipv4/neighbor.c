/*++

Copyright (c) 2003-2004  Microsoft Corporation

Module Name:

    neighbor.c

Abstract:

    This module contains IPv4 Neighbor Discovery Algorithm, based off RFC 2461.

Author:

    Mohit Talwar (mohitt) Thu Jun 17 15:56:43 2004

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "neighbor.tmh"

VOID
Ipv4pSendNeighborAdvertisement(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *SolicitationSourceDlAddress OPTIONAL,
    IN CONST SOURCEROUTE_HEADER *SolicitationSourceDlRoute OPTIONAL,
    IN CONST UCHAR *SolicitationSourceAddress,
    IN PIP_LOCAL_ADDRESS LocalTarget
    )
/*++

Routine Description:

    Construct and send a neighbor advertisement for a local target.

Arguments:

    SubInterface - Supplies the subinterface over which the neighbor 
        advertisement should be sent.

    SolicitationSourceDlAddress - Supplies the datalink-layer source address
        of the corresponding neighbor solicitation.

    SolicitationSourceDlRoute - Supplies the datalink-layer source-route
        of the corresponding neighbor solicitation.

    SolicitationSourceAddress - Supplies the source address of the 
        corresponding neighbor solicitation.

    LocalTarget - Supplies the target address of the corresponding 
        neighbor solicitation.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    FL_REQUEST_SEND_NEIGHBOR_DISCOVERY Request = {0};
    PIP_INTERFACE Interface = SubInterface->Interface;
      
    Request.ProviderSubInterfaceHandle = SubInterface->FlContext;
    Request.NlSourceAddress = NL_ADDRESS(LocalTarget);
    Request.NlTargetAddress = SolicitationSourceAddress;
    Request.DlTargetAddress = SolicitationSourceDlAddress;
    Request.DlSourceRoute = SolicitationSourceDlRoute;
    Interface->FlModule->Npi.Dispatch->SendNeighborAdvertisement(&Request);
}


VOID
Ipv4FlcReceiveNeighborSolicitation(
    IN HANDLE ClientSubInterfaceHandle,
    IN CONST UCHAR *DlSourceAddress,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN CONST UCHAR *NlSourceAddress,
    IN CONST UCHAR *NlTargetAddress
    )
/*++

Routine Description:
    
    Process an ARP request message.
    
Arguments:

    SubInterface - Supplies the subinterface over which the
        ARP request was received.

    DlSourceAddress - Supplies the datalink-layer address of the sender.
    
    DlSourceRoute - Supplies the link-layer source-route of the sender.
                    
    NlSourceAddress - Supplies the network-layer address of the sender.

    NlTargetAddress - Supplies the network-layer address being resolved.

Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_SUBINTERFACE SubInterface =
        (PIP_SUBINTERFACE) ClientSubInterfaceHandle;
    PIP_LOCAL_ADDRESS LocalTarget;

    if (IN4_UNALIGNED_ADDR_EQUAL(
            (PIN_ADDR) NlSourceAddress,
            (PIN_ADDR) NlTargetAddress)) {
        //
        // Some platforms fill in the SenderProtocolAddress field with the
        // TargetProtocolAddress instead of in4addr_any.  In doing so, however,
        // they can break our connectivity by polluting the ARP cache of other
        // devices like learning bridges.  To restore our connectivity, we'll
        // datalink-layer broadcast the response so the other devices can get
        // the correct information again.
        //
        DlSourceAddress = NULL;
        NlSourceAddress = (CONST UCHAR *) &in4addr_any;
    }

    LocalTarget =
        IppHandleNeighborSolicitation(
            SubInterface,
            DlSourceAddress,
            DlSourceRoute,
            NlSourceAddress,
            NlTargetAddress);
    if (LocalTarget == NULL) {
        //
        // The neighbor solicitation is not targetted for a local address.
        //
        return;
    }

    ASSERT(RtlEqualMemory(
               NlTargetAddress,
               NL_ADDRESS(LocalTarget),
               sizeof(IN_ADDR)));
    
    //
    // Send a neighbor advertisement for the target back to the source.
    //
    Ipv4pSendNeighborAdvertisement(
        SubInterface,
        DlSourceAddress,
        DlSourceRoute,
        NlSourceAddress,
        LocalTarget);

    IppDereferenceLocalAddress(LocalTarget);
}


VOID
Ipv4FlcReceiveNeighborAdvertisement(
    IN HANDLE ClientSubInterfaceHandle,
    IN CONST UCHAR *DlSourceAddress,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN CONST UCHAR *NlSourceAddress,
    IN BOOLEAN Directed
    )
/*++

Routine Description:
    
    Process an ARP response message.
    
Arguments:

    SubInterface - Supplies the subinterface over which the
        ARP response was received.

    DlSourceAddress - Supplies the datalink-layer address of the sender.
    
    DlSourceRoute - Supplies the link-layer source-route of the sender.
                    
    NlSourceAddress - Supplies the network-layer address of the sender.

    Directed - Supplies TRUE if the ARP response was directed to the
        interface's datalink-layer address, or FALSE otherwise.

Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_SUBINTERFACE SubInterface =
        (PIP_SUBINTERFACE) ClientSubInterfaceHandle;
    IPV6_NEIGHBOR_ADVERTISEMENT_FLAGS Flags = {0};

    if (IN4_IS_UNALIGNED_ADDR_MULTICAST((PIN_ADDR) NlSourceAddress)) {
        //
        // A packet containing a multicast source address is quickly dropped.
        //
        return;
    }

    //
    // An ARP response is considered to be solicited if it was directed to the
    // interface's datalink-layer address.  It is always considered overriding.
    // It has no information on whether the responder is a router.
    //
    Flags.Solicited = Directed;
    Flags.Override = TRUE;
    Flags.Router = FALSE;
    
    IppHandleNeighborAdvertisement(
        SubInterface,
        DlSourceAddress,
        DlSourceRoute,
        NlSourceAddress,
        Flags);
}


VOID
Ipv4pSendNeighborSolicitation(
    IN BOOLEAN DispatchLevel,
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_NEIGHBOR Neighbor OPTIONAL,
    IN PIP_LOCAL_UNICAST_ADDRESS SourceAddress OPTIONAL,
    IN CONST UCHAR *DestinationAddress OPTIONAL,
    IN CONST UCHAR *TargetAddress
    )
/*++

Routine Description:
    
    Low-level version of IppSendNeighborSolicitation -
    uses explicit source/destination/target addresses.

    Compare NeighborSolicitSend0 in the XP IPv6 stack.

Arguments:

    DispatchLevel - Supplies TRUE if IRQL is known to be at DISPATCH level.
    
    Interface - Supplies the interface over which to send a solicitation.
    
    SubInterface - Supplies the sub-interface over which to send the solicit.
    
    Neighbor - Supplies the neighbor to which to send the solicitation.

    SourceAddress - Supplies the source address for the solicitation.
        If NULL, solicitation is sent with the unspecified address. 

    DestinationAddress - Supplies the destination address for the solicitation.
        If NULL, solicitation is sent to the broadcast address.

    TargetAddress - Supplies the target address for the solicitation.

Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    CONST UCHAR *NlSourceAddress;
    CONST UCHAR *DlTargetAddress;
    CONST SOURCEROUTE_HEADER *DlSourceRoute;
    
    FL_REQUEST_SEND_NEIGHBOR_DISCOVERY Request = {0};

    UNREFERENCED_PARAMETER(DispatchLevel);
    UNREFERENCED_PARAMETER(Interface);
    UNREFERENCED_PARAMETER(DestinationAddress);
    
    NlSourceAddress = (SourceAddress != NULL)
        ? NL_ADDRESS(SourceAddress)
        : (PUCHAR) &in4addr_any;
    
    if (Neighbor != NULL) {
        ASSERT(DestinationAddress != NULL);
        ASSERT(SubInterface == Neighbor->SubInterface);
        
        DlTargetAddress = IP_NEIGHBOR_DL_ADDRESS(Neighbor, sizeof(IN_ADDR));
        DlSourceRoute = &Neighbor->DlSourceRoute;
    } else {
        ASSERT(DestinationAddress == NULL);
        
        DlTargetAddress = NULL;
        DlSourceRoute = NULL;
    }
    
    Request.ProviderSubInterfaceHandle = SubInterface->FlContext;
    Request.NlSourceAddress = NlSourceAddress;
    Request.NlTargetAddress = TargetAddress;
    Request.DlTargetAddress = DlTargetAddress;
    Request.DlSourceRoute = DlSourceRoute;
    
    SubInterface->Interface->FlModule->Npi.Dispatch->
        SendNeighborSolicitation(&Request);
}
