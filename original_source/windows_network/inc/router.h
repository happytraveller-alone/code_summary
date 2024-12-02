/*++

Copyright (c) 2005-2006  Microsoft Corporation

Module Name:

    router.h

Abstract:

    This module contains internal router-discovery functions.

Author:

    Mohit Talwar (mohitt) Tue Nov 01 17:46:07 2005

Environment:

    Kernel mode only.

--*/

#ifndef _ROUTER_
#define _ROUTER_

#pragma once

//
// Internal Router Discovery functions.
//

VOID
IppStartRouterDiscovery(
    IN PIP_INTERFACE Interface
    );

VOID
IppStopRouterDiscovery(
    IN PIP_INTERFACE Interface
    );

BOOLEAN
IppRouterAdvertisementTimeout(
    IN BOOLEAN ForceRouterAdvertisement,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Source
    );

VOID
IppRouteTimeout(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_UNICAST_ROUTE Route
    );

VOID
IppRouteSetTimeout(
    IN PIP_COMPARTMENT Compartment
    );

PIP_NEIGHBOR
IppRedirectPath(
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_LOCAL_ADDRESS Source,
    IN CONST UCHAR *Destination,
    IN CONST UCHAR *NextHop,
    IN CONST UCHAR *Target
    );

VOID
IppSendRedirect(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_NEIGHBOR Target
    );

VOID
IppUpdateAutoConfiguredRoute(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *NextHop OPTIONAL,
    IN PIP_NEIGHBOR Neighbor OPTIONAL,
    IN CONST UCHAR *Prefix,
    IN UCHAR PrefixLength,
    IN ULONG Lifetime,
    IN ULONG Metric
    );

VOID 
IppResetAutoConfiguredSettings(
    IN PIP_INTERFACE Interface,
    IN ULONG LifeTime
    );

VOID
Ipv6pResetAutoConfiguredSettings(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    );

VOID
Ipv4pResetAutoConfiguredSettings(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    );

VOID
Ipv4pResetAutoConfiguredRoutes(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    );

VOID
Ipv6pResetAutoConfiguredParameters(
    IN PIP_INTERFACE Interface
    );

VOID
Ipv6pResetAutoConfiguredAddresses(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    );

VOID
Ipv6pResetAutoConfiguredRoutes(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    );

#endif // _ROUTER_
