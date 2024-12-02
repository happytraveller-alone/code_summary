/*++

Copyright (c) Microsoft Corporation

Module Name:

    ah.c

Abstract:

    This is a dummy module containing stubs for functions relating to
    Authentication Headers.  The IPsec team owns the actual module.

--*/

#include "precomp.h"

NTSTATUS
IpSecAhInitInbound(
    IN PVOID PacketHandle,
    IN IPPROTO IpProtocol,
    IN AUTHENTICATION_HEADER UNALIGNED *AuthenticationHeader,
    IN ULONG AhHeaderBufferLength,
    IN ULONG PacketLength,
    IN CONST UCHAR* SourceAddress,
    IN CONST UCHAR* DestAddress,
    IN CONST IF_LUID* incomingInterface,
    OUT PULONG AuthenticationDataLength,
    OUT PULONG PaddingLength
    )
{
    DBG_UNREFERENCED_PARAMETER(AuthenticationHeader);
    DBG_UNREFERENCED_PARAMETER(AhHeaderBufferLength);
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(PacketLength);
    DBG_UNREFERENCED_PARAMETER(IpProtocol);
    DBG_UNREFERENCED_PARAMETER(PaddingLength);
    DBG_UNREFERENCED_PARAMETER(SourceAddress);
    DBG_UNREFERENCED_PARAMETER(DestAddress);
    DBG_UNREFERENCED_PARAMETER(incomingInterface);
    *AuthenticationDataLength = DUMMY_AUTHENTICATION_DATA_SIZE;

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecAhProcessAuthenticationData(
    IN PVOID PacketHandle,
    IN ULONG AuthDataLength
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(AuthDataLength);

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecAhProcessData(
    IN PVOID PacketHandle,
    IN CONST VOID *DataBuffer,
    IN ULONG DataLength
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(DataBuffer);
    DBG_UNREFERENCED_PARAMETER(DataLength);

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecAhCompleteInbound(
    IN PVOID PacketHandle,
    IN PVOID AuthenticationData
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(AuthenticationData);

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecAhInitOutbound(
    IN PVOID PacketHandle,
    IN PAUTHENTICATION_HEADER AuthenticationHeader
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);

    AuthenticationHeader->PayloadLength = 2;
    AuthenticationHeader->Reserved = 0;
    AuthenticationHeader->Spi = 1;
    AuthenticationHeader->SequenceNumber = 0;

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecAhCompleteOutbound(
    IN PVOID PacketHandle,
    OUT PVOID AuthenticationData
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);

    RtlZeroMemory(AuthenticationData, DUMMY_AUTHENTICATION_DATA_SIZE);

    return STATUS_SUCCESS;
}
