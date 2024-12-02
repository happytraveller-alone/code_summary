/*++

Copyright (c) Microsoft Corporation

Module Name:

    select.h

Abstract:

    This module contains declarations for the network layer module's
    source address selection.

Author:

    Dave Thaler (dthaler) 17-Aug-2001

Environment:

    Kernel mode only

--*/

PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnInterfaceUnderLock(
    IN IP_INTERFACE *Interface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop    
    );

PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnInterfaceAtDpc(
    IN IP_INTERFACE *Interface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop    
    );

PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnInterface(
    IN IP_INTERFACE *Interface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop    
    );

PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnHost(
    IN IP_INTERFACE *OutgoingInterface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop    
    );

SCOPE_ID
Ipv6SitePrefixMatch(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST IN6_ADDR *Address
    );

VOID
IppQualifySiteLocalAddresses(
    IN PIP_COMPARTMENT Compartment,
    IN OUT ULONG *AddressCount,
    IN OUT PSOCKADDR_IN6 Addresses,
    IN OUT PNL_ADDRESS_PAIR_INDICES Key    
    );

NTSTATUS
IppSortDestinationAddresses(
    IN PIP_COMPARTMENT Ipv6Compartment,
    IN CONST SOCKET_ADDRESS_LIST *InputAddressList,
    OUT SOCKET_ADDRESS_LIST *OutputAddressList
    );

NTSTATUS
NTAPI
IpGetAllSortedAddressParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    );
