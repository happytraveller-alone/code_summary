/*++

Copyright (c) 2003-2004  Microsoft Corporation

Module Name:

    proxy.h

Abstract:

    This module contains declarations for proxy neighbor management.
    
Author:

    Mohit Talwar (mohitt) Tue Jul 01 11:56:03 2003

Environment:

    Kernel mode only.

--*/

#ifndef _PROXY_
#define _PROXY_

#pragma once

//
// IP_PROXY_NEIGHBOR_LINK
//
// Define the network layer proxy neighbor set link.
//

typedef LIST_ENTRY IP_PROXY_NEIGHBOR_LINK, *PIP_PROXY_NEIGHBOR_LINK;


//
// IP_PROXY_NEIGHBOR_SET
//
// Define the network layer proxy neighbor set state.
//

typedef struct _IP_PROXY_NEIGHBOR_SET {
    LIST_ENTRY Head;            // Proxy Neighbor Set.
} IP_PROXY_NEIGHBOR_SET, *PIP_PROXY_NEIGHBOR_SET;


//
// IP_PROXY_NEIGHBOR
//
// Define the network layer proxy neighbor state.
//

typedef struct _IP_PROXY_NEIGHBOR {
#if DBG
    ULONG Signature;            // IP_PROXY_NEIGHBOR_SIGNATURE
#endif // DBG
    IP_PROXY_NEIGHBOR_LINK Link;// Link into the proxy neigbor set.
    UINT8 PrefixLength;         // Proxy prefix length (in bits).
} IP_PROXY_NEIGHBOR, *PIP_PROXY_NEIGHBOR;

//
// The proxy neighbor's prefix is stored past its base structure.
//
#define IP_PROXY_NEIGHBOR_PREFIX(ProxyNeighbor) \
    ((PUCHAR) (((PIP_PROXY_NEIGHBOR) (ProxyNeighbor)) + 1))

#define SIZEOF_IP_PROXY_NEIGHBOR(Protocol) \
    (sizeof(IP_PROXY_NEIGHBOR) + (Protocol)->Characteristics->AddressBytes)


//
// Proxy Neighbor Management Routines.
//
    
VOID
IppInitializeProxyNeighborSet(
    OUT PIP_PROXY_NEIGHBOR_SET ProxyNeighborSet
    );

VOID
IppUninitializeProxyNeighborSet(
    IN OUT PIP_PROXY_NEIGHBOR_SET ProxyNeighborSet
    );

PIP_LOCAL_ADDRESS
IppGetProxyLocalAddress(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    );


//
// Network Layer Management Provider Handlers.
//
    
NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllProxyNeighborParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllProxyNeighborParameters;

#endif // _PROXY_
