/*++

Copyright (c) Microsoft Corporation

Module Name:

    esp.c

Abstract:

    This is a dummy module containing stubs for functions relating to
    ESP packets.  The IPsec team owns the actual module.

--*/

#include "precomp.h"

NTSTATUS
IpSecEspInitInbound(
    IN PVOID PacketHandle,
    IN IPPROTO IpProtocol,
    IN ESP_HEADER UNALIGNED *EspHeader,
    IN ULONG EspHeaderBufferLength,
    IN ULONG PacketLength,    
    IN CONST UCHAR* SourceAddress,
    IN CONST UCHAR* DestAddress,
    IN CONST IF_LUID* incomingInterface,
    OUT PULONG AuthenticationDataLength,
    OUT PESP_PROCESSING_TYPE ProcessingType,
    OUT PULONG BlockSize,
    OUT PULONG ivLength
    )
{
    DBG_UNREFERENCED_PARAMETER(EspHeader);
    DBG_UNREFERENCED_PARAMETER(EspHeaderBufferLength);
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(PacketLength);
    DBG_UNREFERENCED_PARAMETER(IpProtocol);
    DBG_UNREFERENCED_PARAMETER(SourceAddress);
    DBG_UNREFERENCED_PARAMETER(DestAddress);
    DBG_UNREFERENCED_PARAMETER(incomingInterface);
    
    *AuthenticationDataLength = DUMMY_AUTHENTICATION_DATA_SIZE;
    ProcessingType->Authentication = TRUE;
    ProcessingType->Confidentiality = TRUE;
    *BlockSize = DUMMY_BLOCK_SIZE;
    *ivLength = 0;

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecEspAuthInbound(
    IN PVOID PacketHandle,
    IN PVOID DataBuffer,
    IN ULONG DataLength
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(DataBuffer);
    DBG_UNREFERENCED_PARAMETER(DataLength);

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecEspAuthCompleteInbound(
    IN PVOID PacketHandle,
    IN PVOID AuthenticationData
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(AuthenticationData);

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecEspDecryptInbound(
    IN PVOID PacketHandle,
    IN PVOID InputDataBuffer,
    __out_bcount(DataLength) PVOID OutputDataBuffer,
    IN ULONG DataLength
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
   
    if (InputDataBuffer != OutputDataBuffer) {
        RtlCopyMemory(OutputDataBuffer, InputDataBuffer, DataLength);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecEspDecryptCompleteInbound(
    IN PVOID PacketHandle,
    IN PVOID Padding,
    IN UINT8 PaddingLength
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(Padding);
    DBG_UNREFERENCED_PARAMETER(PaddingLength);

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecEspInitOutbound(
    IN PVOID PacketHandle,
    OUT PESP_HEADER Header,
    OUT PUCHAR Padding
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(Padding);

    Header->Spi = 1;
    Header->SequenceNumber = 0;

    return STATUS_SUCCESS;
}

VOID
IpSecEspLsoPacketProcessing(
   IN PVOID PacketHandle,
   IN ULONG NumPackets,
   IN ULONG Mss,
   IN ULONG TcpHeaderLength,
   IN ULONG PayloadLength
)
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(NumPackets);
    DBG_UNREFERENCED_PARAMETER(Mss);
    DBG_UNREFERENCED_PARAMETER(TcpHeaderLength);
    DBG_UNREFERENCED_PARAMETER(PayloadLength);
}

VOID
IpSecEspFillPadding(
    IN PVOID PacketHandle,
    IN PUCHAR Padding
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);
    DBG_UNREFERENCED_PARAMETER(Padding);
}

NTSTATUS
IpSecEspProcessOutbound(
    IN PVOID PacketHandle,
    IN PVOID InputDataBuffer,
    __out_bcount(DataLength) PVOID OutputDataBuffer,
    IN ULONG DataLength
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);

    if (InputDataBuffer != OutputDataBuffer) {
        RtlCopyMemory(OutputDataBuffer, InputDataBuffer, DataLength);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IpSecEspCompleteOutbound(
    IN PVOID PacketHandle,
    OUT PVOID AuthenticationData
    )
{
    DBG_UNREFERENCED_PARAMETER(PacketHandle);

    RtlZeroMemory(AuthenticationData, DUMMY_AUTHENTICATION_DATA_SIZE);

    return STATUS_SUCCESS;
}
