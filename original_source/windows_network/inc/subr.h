/*++

Copyright (c) Microsoft Corporation

Module Name:

    subr.h

Abstract:

    This module contains the private (internal) definitions and structures
    for subr.c.

Author:

    Dave Thaler (dthaler) 3-June-2002

Environment:

    Kernel mode only

--*/

#ifndef _SUBR_
#define _SUBR_

extern UINT32 g_37HashSeed;

NTSTATUS
IppRegQueryDwordValue(
    IN CONST WCHAR *KeyName,
    IN CONST WCHAR *ValueName,
    PULONG ValueData
    );

DL_ADDRESS_TYPE
IppDatalinkAddressType(
    IN CONST UCHAR *Address,
    IN CONST IP_INTERFACE *Interface
    );

VOID
IppSeedRandom(
    VOID
    );

ULONG
RandomNumber(
    IN ULONG Min,
    IN ULONG Max
    );

BOOLEAN
IppValidatePrefix(
    IN CONST UCHAR *Prefix,
    IN ULONG PrefixLength,
    IN ULONG AddressBytes
    );

BOOLEAN
HasPrefix(
    IN CONST UCHAR *Address,
    IN CONST UCHAR *Prefix,
    IN ULONG PrefixLength
    );

VOID
CopyPrefix(
    __out_ecount(AddressBytes) UCHAR *Address, 
    __in CONST UCHAR *Prefix,
    __in_range(0, AddressBytes * 8) ULONG PrefixLength, 
    __in ULONG AddressBytes
    );

ULONG
CommonPrefixLength(
    IN CONST UCHAR *Address1,
    IN CONST UCHAR *Address2,
    IN ULONG Size
    );

VOID
CreateBroadcastAddress(
    __in CONST UCHAR *Prefix,
    __in_range(0, AddressBytes * 8) ULONG PrefixLength, 
    __in ULONG AddressBytes,
    __in BOOLEAN UseZeroBroadcastAddress, 
    __out_ecount(AddressBytes) UCHAR *BroadcastAddress
    );


BOOLEAN
IppInitSharedHashContext(
    VOID
    );

VOID
IppCleanupSharedHashContext(
    VOID
    );

#endif // _SUBR_
