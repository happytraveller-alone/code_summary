/*++

Copyright (c) Microsoft Corporation

Module Name:

    ah.c

Abstract:

    This module implements functions relating to an Authentication Header.

--*/

#include "precomp.h"

NTSTATUS
Ipv4pDeferredAuthenticateIpv4Header(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PUCHAR Data,
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    This routine handles processing the AH authentication algorithm over
    the IPv4 header once we know which header logically follows it.
    See section 3.3.3.1.1.1 of RFC 2402.

--*/
{
    IPV4_HEADER Ip;
    USHORT PacketLength;
    NTSTATUS Status;
    UCHAR HeaderLength;
    IPV4_OPTION_TYPE OptionType;
    UINT8 OptionLength;
    ULONG Position;
    PNET_BUFFER_LIST Nbl = Packet->NetBufferList;
    ULONG AmountSkipped = Packet->SkippedHeaderLength;

    //
    // Cache IPv4 header so we can give it to IpSecAhProcessData as a single
    // chunk and avoid multiple calls.
    //
    RtlCopyMemory(&Ip, Data, sizeof(Ip));

    //
    // The packet length needs to be altered to reflect the lack of those 
    // headers which aren't included in the authentication check.
    //
    PacketLength = RtlUshortByteSwap(Ip.TotalLength);
    Ip.TotalLength = RtlUshortByteSwap(PacketLength - AmountSkipped);

    Ip.Protocol = NextHeader;

    //
    // Zero mutable fields.
    //
    Ip.TypeOfService = 0;
    Ip.FlagsAndOffset = 0;
    Ip.TimeToLive = 0;
    Ip.HeaderChecksum = 0;

    Status = IpSecAhProcessData(Nbl, &Ip, sizeof(Ip));
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    HeaderLength = Ip4HeaderLengthInBytes(&Ip);
    if (HeaderLength == sizeof(Ip)) {
        return STATUS_SUCCESS;
    }

    //
    // Process IP options.
    //
    for (Position = sizeof(Ip); 
         Position < HeaderLength; 
         Position += OptionLength) {

        OptionType = Data[Position];

        if (OptionType <= IP_OPT_NOP) {
            OptionLength = 1;
        } else {
            //
            // TODO (bug# 840047): The IPv4 header validation code needs to be
            // updated to ensure the asserts below.
            //
            ASSERT(Position + 1 < HeaderLength);

            OptionLength = Data[Position + 1];

            ASSERT((OptionLength >= 2) &&
                   (Position + OptionLength <= HeaderLength));
        }

        switch (OptionType) {
        case IP_OPT_EOL:
        case IP_OPT_NOP:
        case IP_OPT_SECURITY:
        case IP_OPT_ROUTER_ALERT:
        case IP_OPT_MULTIDEST:
            //
            // The option is immutable.  Pass the actual bytes.
            //
            Status = IpSecAhProcessData(Nbl, &Data[Position], OptionLength);

        default:
            //
            // The option is mutable.  Pass zeroes.
            //
            Status = IpSecAhProcessData(Nbl, Zero, OptionLength);
        }

        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    return STATUS_SUCCESS;
}
