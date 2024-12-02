/*++

Copyright (c) 2003-2004  Microsoft Corporation

Module Name:

    prefixpolicy.h

Abstract:

    This module contains generic prefix policy management functions.

    There is a single prefix policy table, common across IPv4 and IPv6 modules.
    IPv4 addresses are represented as IPv6 (v4-mapped) addresses.
    
Author:

    Mohit Talwar (mohitt) Wed Feb 04 11:43:15 2004

Environment:

    Kernel mode only.

--*/

#ifndef _PREFIXPOLICY_
#define _PREFIXPOLICY_

#pragma once

NTSTATUS
IppStartPrefixPolicyModule(
    IN PIP_PROTOCOL Protocol
    );

VOID 
IppCleanupPrefixPolicyModule(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppLookupPrefixPolicy(
    IN CONST UCHAR *Address,
    IN ULONG AddressBytes,
    OUT PNL_PREFIX_POLICY_RW Data
    );

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllPrefixPolicyParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllPrefixPolicyParameters;

#endif // _PREFIXPOLICY_
