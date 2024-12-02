/*++

Copyright (c) Microsoft Corporation

Module Name:

    ah.c

Abstract:

    This module implements functions relating to an Authentication Header.

--*/

#include "precomp.h"

NTSTATUS
Ipv6pDeferredAuthenticateIpv6Header(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PUCHAR Data,
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    This routine handles processing the AH authentication algorithm over
    the IPv6 header once we know which header logically follows it.

--*/
{
    IPV6_HEADER Ip;

    //
    // Cache IPv6 header so we can give it to Operate as a single
    // chunk and avoid all multiple calls.
    //
    RtlCopyMemory(&Ip, Data, sizeof(Ip));

    //
    // In VersClassFlow, only the IP version is immutable.
    //
    Ip.VersionClassFlow = IPV6_VERSION;

    //
    // For non-jumbograms, the payload length needs to be altered to
    // reflect the lack of those headers which aren't included in the
    // authentication check.
    //
    if (Ip.PayloadLength != 0) {
        USHORT PayloadLength = RtlUshortByteSwap(Ip.PayloadLength);

        Ip.PayloadLength = 
            RtlUshortByteSwap(PayloadLength - Packet->SkippedHeaderLength);
    }

    Ip.NextHeader = NextHeader;

    //
    // Hop Limit is mutable.
    //
    Ip.HopLimit = 0;

    return IpSecAhProcessData(Packet->NetBufferList, &Ip, sizeof(Ip));
}

VOID
Ipv6pAuthenticateRoutingHeader(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PNET_BUFFER Buffer,
    IN OUT PUINT8 NextHeaderPointer,
    IN OUT PUINT8 DeferredHeaderPointer,
    IN OUT PUCHAR *DeferredDataPointer,
    IN OUT BOOLEAN *FreeData
    )
/*++

Routine Description:

    Do AH processing over a correctly-formed Routing Header.

    Compare the IP_PROTOCOL_ROUTING case of AuthenticationHeaderReceive() 
    in the XP IPv6 stack.

Return Value:

    Returns a pointer to the deferred data buffer, or NULL on failure.  
    If *FreeData is TRUE, the caller is responsible for freeing 
    the buffer.

--*/
{
    IPV6_ROUTING_HEADER *Header, HeaderBuffer;
    ULONG HeaderLength;

    //
    // This header is not skipped, so process the header
    // logically preceeding this one.  Its NextHeader field
    // will contain the Protocol value for this header.
    //
    IppPerformDeferredAhProcessing(&Ipv6Global,
                                   Packet,
                                   *DeferredDataPointer, 
                                   *FreeData,
                                   *DeferredHeaderPointer,
                                   IPPROTO_ROUTING);

    //
    // Remember this header for deferred processing.
    //
    *DeferredHeaderPointer = IPPROTO_ROUTING;

    //
    // Get the extension header and all the options pulled up
    // into one nice contiguous chunk.
    //
    Header = (IPV6_ROUTING_HEADER *) NetioGetDataBuffer(
                    Buffer,
                    sizeof(*Header),
                    &HeaderBuffer,
                    __builtin_alignof(IPV6_ROUTING_HEADER),
                    0);

    *NextHeaderPointer = Header->NextHeader;
    HeaderLength = IPV6_EXTENSION_HEADER_LENGTH(Header->Length);

    Header = (IPV6_ROUTING_HEADER *) NetioGetDataBuffer(
                    Buffer,
                    HeaderLength,
                    NULL,
                    1,
                    0);

    //
    // If the header is not in contiguous memory, Header will be NULL.
    //
    *FreeData = FALSE;
    if ((Header == NULL) || (Header->SegmentsLeft > 0)) {
        PIPV6_ROUTING_HEADER NewHeader;

        //
        // REVIEW: the XP IPv6 stack allocates memory when the header
        // was originally parsed, and then finds it in a list here.
        // We copied used a stack buffer when parsing, so we need to
        // allocate now.  It's not clear whether it's faster to copy
        // or search a list.
        //
        NewHeader = ExAllocatePoolWithTagPriority(NonPagedPool,
                                                  HeaderLength,
                                                  IpGenericPoolTag,
                                                  LowPoolPriority);

        if (NewHeader == NULL) {
            goto Done;
        }
        *FreeData = TRUE;

        if (Header != NULL) {
            RtlCopyMemory(NewHeader, Header, HeaderLength);
        } else {
            (VOID) NetioGetDataBuffer(Buffer,
                                      HeaderLength,
                                      NewHeader,
                                      1,
                                      0);
        }

        if (NewHeader->SegmentsLeft > 0) {
            //
            // Since the buffer is in sender-format, we need to convert 
            // it to receiver-format for authentication.
            // Compare IPSecAdjustMutableFields in the XP IPv6 stack.
            //
        
            //
            // Shift all the addresses down.
            //
            RtlMoveMemory(((PUCHAR) (NewHeader + 1)) + sizeof(IN6_ADDR),
                          (PUCHAR) (NewHeader + 1),
                          (NewHeader->SegmentsLeft - 1) * sizeof(IN6_ADDR));

            //
            // Copy the IP destination address to the first routing address.
            //
            RtlCopyMemory((PUCHAR) (NewHeader + 1),
                          Packet->CurrentDestinationAddress,
                          sizeof(IN6_ADDR));

            NewHeader->SegmentsLeft = 0;
        }
    }

Done:
    //
    // Remember where this header starts for deferred processing.
    //
    *DeferredDataPointer = (PUCHAR) Header;

    NetioAdvanceNetBuffer(Buffer, HeaderLength);
}

NTSTATUS
Ipv6pDeferredAuthenticateRoutingHeader(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PUCHAR Data,
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    This routine handles processing the AH authentication algorithm over
    a Routing Header (in receiver format) once we know which header 
    logically follows it.

    Compare the IP_PROTOCOL_ROUTING case of PerformDeferredAHProcessing() 
    in the XP IPv6 stack.

--*/
{
    IPV6_ROUTING_HEADER UNALIGNED *Header;
    ULONG HeaderLength;
    NTSTATUS Status;
    PNET_BUFFER_LIST Nbl = Packet->NetBufferList;

    //
    // The routing header has the NextHeader field as the first byte.
    //
    C_ASSERT(FIELD_OFFSET(IPV6_ROUTING_HEADER, NextHeader) == 0);

    //
    // First feed the NextHeader field into the algorithm.
    // We use the one that logically follows, not the one in the header.
    //
    Status = IpSecAhProcessData(Nbl, &NextHeader, sizeof(NextHeader));
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Now feed the rest of this header into the algorithm.
    // It's all immutable.
    //
    Header = (IPV6_ROUTING_HEADER UNALIGNED *)Data;
    HeaderLength = 
        IPV6_EXTENSION_HEADER_LENGTH(Header->Length) - sizeof(NextHeader);
    Data++;
    return IpSecAhProcessData(Nbl, Data, HeaderLength);
}

VOID
Ipv6pAuthenticateOptions(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PNET_BUFFER Buffer,
    IN OUT PUINT8 NextHeaderPointer,
    IN OUT PUINT8 DeferredHeaderPointer,
    IN OUT PVOID *DeferredDataPointer,
    IN OUT BOOLEAN *FreeData
    )
/*++

Routine Description:

    Do AH processing over a correctly-formed Hop-by-Hop Options or
    Destination Options Header.

    Compare the IP_PROTOCOL_HOP_BY_HOP/IP_PROTOCOL_DEST_OPTS case of
    AuthenticationHeaderReceive() in the XP IPv6 stack.

Return Value:

    Returns a pointer to the deferred data buffer, or NULL on failure.
    If *FreeData is TRUE, the caller is responsible for freeing
    the buffer.

--*/
{
    IPV6_EXTENSION_HEADER *Header, HeaderBuffer;
    ULONG HeaderLength;

    //
    // These headers are not skipped, so process the header
    // logically preceeding this one.  Its NextHeader field
    // will contain the Protocol value for this header.
    //
    IppPerformDeferredAhProcessing(&Ipv6Global,
                                   Packet, 
                                   *DeferredDataPointer,
                                   *FreeData,
                                   *DeferredHeaderPointer,
                                   *NextHeaderPointer);

    //
    // Remember this header for deferred processing.
    //
    *DeferredHeaderPointer = *NextHeaderPointer;

    //
    // Get the extension header and all the options pulled up
    // into one nice contiguous chunk.
    //
    Header = (IPV6_EXTENSION_HEADER *) NetioGetDataBuffer(
                       Buffer,
                       sizeof(*Header),
                       &HeaderBuffer,
                       __builtin_alignof(IPV6_EXTENSION_HEADER), 
                       0);

    *NextHeaderPointer = Header->NextHeader;
    HeaderLength = IPV6_EXTENSION_HEADER_LENGTH(Header->Length);

    Header = (IPV6_EXTENSION_HEADER *) NetioGetDataBuffer(
                       Buffer,
                       HeaderLength,
                       NULL,
                       1,
                       0);
    *FreeData = FALSE;

    //
    // If the header is not in contiguous memory, Header will be NULL.
    //
    if (Header == NULL) {
        PUCHAR Space;

        //
        // The AH is split across MDLs, so we need to allocate a
        // contiguous buffer for it.  This ought to be very rare
        // so we'll just use ExAllocate... like the XP IPv6 stack does.
        //
        // REVIEW: the XP IPv6 stack allocates memory when the header
        // was originally parsed, and then finds it in a list here.
        // We copied used a stack buffer when parsing, so we need to
        // allocate now.  It's not clear whether it's faster to copy
        // or search a list.
        //
        Space = ExAllocatePoolWithTagPriority(NonPagedPool,
                                              sizeof(*Header),
                                              IpGenericPoolTag,
                                              LowPoolPriority);

        if (Space != NULL) {
            Header = (IPV6_EXTENSION_HEADER *) 
                NetioGetDataBuffer(Buffer, HeaderLength, Space, 1, 0);

            *FreeData = TRUE;
        }
    }

    NetioAdvanceNetBuffer(Buffer, HeaderLength);

    //
    // Return where this header starts for deferred processing.
    //
    *DeferredDataPointer = Header;
}

NTSTATUS
Ipv6pDeferredAuthenticateOptions(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PUCHAR Data,
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    This routine handles processing the AH authentication algorithm over
    a Hop-by-Hop Options or Destination Options Header once we know which 
    header logically follows it.

    Compare the IP_PROTOCOL_HOP_BY_HOP/IP_PROTOCOL_DEST_OPTS case of
    PerformDeferredAHProcessing() in the XP IPv6 stack.

--*/
{
    IPV6_EXTENSION_HEADER UNALIGNED *Header;
    ULONG HeaderLength, Amount, Dummy;
    UCHAR *Start, *Current;
    NTSTATUS Status;
    PNET_BUFFER_LIST Nbl = Packet->NetBufferList;
    ULONG AmountSkipped = Packet->SkippedHeaderLength;

    //
    // The options headers have the NextHeader field as the first byte.
    //
    C_ASSERT(FIELD_OFFSET(IPV6_EXTENSION_HEADER, NextHeader) == 0);

    //
    // First feed the NextHeader field into the algorithm.
    // We use the one that logically follows, not the one in the header.
    //
    Status = IpSecAhProcessData(Nbl, &NextHeader, sizeof(NextHeader));
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Now feed the rest of this header into the algorithm.
    // This includes the remainder of the base header and any
    // non-mutable options.  For mutable options, we feed the
    // algorithm with the equivalent number of zeroes.
    //
    Header = (IPV6_EXTENSION_HEADER UNALIGNED *)Data;
    HeaderLength = IPV6_EXTENSION_HEADER_LENGTH(Header->Length);
    Start = (PUCHAR)Data + 1;
    Current = (PUCHAR)Data + sizeof(*Header);
    HeaderLength -= sizeof(*Header);
    while (HeaderLength != 0) {

        if (*Current == IP6OPT_PAD1) {
            //
            // This is the special one byte pad option.  Immutable.
            //
            Current++;
            HeaderLength--;
            continue;
        }

        if ((*Current == IP6OPT_JUMBO) && (AmountSkipped != 0 )) {
            //
            // Special case for jumbo payload option where we have to
            // update the payload length to reflect skipped headers.
            //

            //
            // First feed in everything up to the option data.
            //
            Amount = (ULONG)(Current - Start) + sizeof(IPV6_OPTION_HEADER);
            Status = IpSecAhProcessData(Nbl, Start, Amount);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            //
            // Adjust the payload length before feeding it in.
            //
            Current += sizeof(IPV6_OPTION_HEADER);
            Dummy = RtlUlongByteSwap(
                RtlUlongByteSwap(*(ULONG *)Current) - AmountSkipped);
            Status = IpSecAhProcessData(Nbl, &Dummy, sizeof(UINT32));
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            HeaderLength -= sizeof(IPV6_OPTION_HEADER) + sizeof(ULONG);
            Current += sizeof(ULONG);
            Start = Current;
            continue;
        }

        if (IP6OPT_ISMUTABLE(*Current)) {
            //
            // This option's data is mutable.  Everything preceeding
            // the option data is not.
            //
            Amount = (ULONG)(Current - Start) + 2;  // Immutable amount.
            Status = IpSecAhProcessData(Nbl, Start, Amount);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            Current++;  // Now on option data length byte.
            Amount = *Current;  // Mutable amount.
            Status = IpSecAhProcessData(Nbl, Zero, Amount);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            HeaderLength -= Amount + 2;
            Current += Amount + 1;
            Start = Current;

        } else {

            //
            // This option's data is not mutable.
            // Just skip over it.
            //
            Current++;  // Now on option data length byte.
            Amount = *Current;
            HeaderLength -= Amount + 2;
            Current += Amount + 1;
        }
    }
    if (Start != Current) {
        //
        // Option block ends with an immutable region.
        //
        Amount = (ULONG)(Current - Start);
        Status = IpSecAhProcessData(Nbl, Start, Amount);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    return STATUS_SUCCESS;
}
