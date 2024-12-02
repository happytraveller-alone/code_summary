/*++

Copyright (c) 2005-2006  Microsoft Corporation

Module Name:

    esp.c

Abstract:

    This module implements functions relating to an ESP header and trailer.

Environment:

    Kernel mode only.

--*/

#include "precomp.h"

IP_INTERNAL_RECEIVE_DATAGRAMS IppReceiveEspList;
IP_INTERNAL_AUTHENTICATE_HEADER IppAuthenticateEspHeader;
IP_INTERNAL_ADD_HEADER IppAddEspHeader;

IP_RECEIVE_DEMUX IpEspDemux = {
    IppReceiveEspList, 
    IppReceiveEspControl, 
    IppAuthenticateEspHeader,
    NULL,
    IppAddEspHeader,
    TRUE
};

NTSTATUS
IppEspProcessPacket(
    IN PIPSEC_ESP_PROCESS_DATA Process,
    IN PNET_BUFFER_LIST Nbl,
    IN OUT PNET_BUFFER Buffer,
    IN ULONG BlockSize,
    IN ULONG BytesLeft
    )
/*++

Routine Description:

    Make a pass through the input packet.  The packet is assumed to
    be positioned at the end of the ESP header when we're called,
    and we return with it positioned at the start of the authentication
    data at the end of the ESP trailer.

Arguments:

    Process - Supplies a function to call for each chunk.
    
    Nbl - Supplies the net buffer list being operated on.

    Buffer - Supplies the net buffer being operated on.  The data must
        be writable.

    BlockSize - Supplies the block size.  We need to call IPsec with
        integral multiples of this size. However if the packet length is not
        a multiple of blockSize (which can happen for certain IPSec crypto 
        algorithms), then the last call to IPsec will be for the remainder 
        chunk of data (of length packetLen % blockSize).

    BytesLeft - Supplies the number of bytes to cover.  This need not
        be a multiple of BlockSize.

    UpdateBuffer - Returns TRUE if we wrote to the output buffer.

Return Value: 

    STATUS_SUCCESS or appropriate failure code. 
    TODO: In the failure case, the NetworkLayerHeadersSize does not match
    the amount of header space advanced. 

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;
    ULONG ContiguousBytes, Remainder, MdlByteOffset;
    ULONG FlatBufferLength;
    PUCHAR FlatBuffer;
    UCHAR BlockBuffer[MAX_IPSEC_BLOCK_SIZE];
    PMDL Mdl;

    while (BytesLeft > 0) {
        //
        // Figure out how many contiguous bytes are available in the
        // buffer.
        //
        Mdl = Buffer->CurrentMdl;
        MdlByteOffset = Buffer->CurrentMdlOffset;
        ContiguousBytes = MmGetMdlByteCount(Mdl) - MdlByteOffset;
        FlatBufferLength = min(ContiguousBytes, BytesLeft);

        //
        // We need to pass chunks of contiguous bytes in multiples
        // of the requested block size, so split the length into
        // a multiple of the block size, and a remainder.
        //
        Remainder = FlatBufferLength % BlockSize;
        FlatBufferLength -= Remainder;

        if (FlatBufferLength > 0) {
            //
            // We have flat buffers that're already contiguous.
            //
            FlatBuffer = MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority);
            if (FlatBuffer == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            FlatBuffer += MdlByteOffset;

            Status =
                (*Process)(
                    Nbl, 
                    FlatBuffer, 
                    FlatBuffer, 
                    FlatBufferLength);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            NetioAdvanceNetBuffer(Buffer, FlatBufferLength);

            BytesLeft -= FlatBufferLength;
        }

        if (Remainder > 0) {
            SIZE_T BytesCopied;            

            //
            // BytesLeft may be less than BlockSize for certain IPsec crypto 
            // algorithms. Hence use the minimum of the 2.
            //
            FlatBufferLength = min(BlockSize, BytesLeft);

            //
            // The block is split across multiple MDLs so we'll copy one
            // block into our local buffers.
            //
            FlatBuffer =
                NetioGetDataBuffer(
                    Buffer,
                    FlatBufferLength,
                    BlockBuffer,
                    1,
                    0);

            Status =
                (*Process)(
                    Nbl, 
                    FlatBuffer, 
                    FlatBuffer, 
                    FlatBufferLength);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            RtlCopyBufferToMdl(
                FlatBuffer,
                Buffer->CurrentMdl,
                Buffer->CurrentMdlOffset,
                FlatBufferLength,
                &BytesCopied);

            ASSERT(BytesCopied == FlatBufferLength);

            NetioAdvanceNetBuffer(Buffer, FlatBufferLength);

            BytesLeft -= FlatBufferLength;
        }
    }

    return STATUS_SUCCESS;
}


VOID
NTAPI
IppReceiveEsp(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    Process an Encapsulating Security Payload header, next header value of 50.
    Compare EncapsulatingSecurityPayloadReceive in the XP IPv6 stack.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
    |               Security Parameters Index (SPI)                 | ^Auth.
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
    |                      Sequence Number                          | |erage
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
    |                    Payload Data* (variable)                   | |   ^
    ~                                                               ~ |   |
    |                                                               | |Conf.
    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
    |               |     Padding (0-255 bytes)                     | |erage
    +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
    |                               |  Pad Length   | Next Header   | v   v
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
    |                 Authentication Data (variable)                |
    ~                                                               ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
Arguments:

    Packet - Supplies an IP packet.
  
--*/
{
    NTSTATUS Status;
    UCHAR EspHeaderBuffer[sizeof(ESP_HEADER) + MAX_IPSEC_IV_LENGTH];
    ULONG EspHeaderBufferLength = 0;
    ESP_HEADER UNALIGNED *Esp;
    PNET_BUFFER_LIST Nbl = Packet->NetBufferList;
    PNET_BUFFER Buffer = Nbl->FirstNetBuffer;
    ESP_PROCESSING_TYPE ProcessingType;
    ULONG BlockSize, IvLength = 0;
    ESP_TRAILER TrailerBuffer;
    ESP_TRAILER UNALIGNED *EspTrailer;
    PMDL Mdl;
    ULONG BytesLeft, MdlByteOffset;
    PUCHAR FlatBuffer, AuthenticationData;
    ULONG FlatBufferLength, AuthenticationDataLength;
    UCHAR AuthenticationDataBuffer[MAX_IPSEC_AUTHENTICATION_DATA_LENGTH];
    ULONG PaddingBuffer[256];
    ULONG OriginalOffset;
    PIP_PROTOCOL Protocol = Packet->Compartment->Protocol;

    //
    // Verify that we have enough contiguous data to overlay an Encapsulating
    // Security Payload Header structure on the incoming packet.  Since the
    // authentication check covers the ESP header, we don't skip over it yet.
    //
    if (Buffer->DataLength < sizeof(*Esp)) {
        if (IppDiscardReceivedPackets(
                Protocol, 
                IpDiscardBadLength, 
                Packet,
                NULL,
                NULL) == IpDiscardAllowIcmp) {
            IppSendErrorListForDiscardReason(
                FALSE,
                Protocol,
                Packet,
                IpDiscardBadLength,
                0);
        }            
        if (Packet->NetBufferList != NULL) {
            Packet->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        }
        goto Failed;
    }

    //
    // There may be an IV immediately following the ESP header. Always pass
    // it on to IPsec if present. 
    //
    EspHeaderBufferLength = 
      min((sizeof(ESP_HEADER) + MAX_IPSEC_IV_LENGTH), Buffer->DataLength);
    
    Esp = (ESP_HEADER UNALIGNED *)
        NetioGetDataBuffer(Buffer, EspHeaderBufferLength, EspHeaderBuffer, 1, 0);
    if (Esp == NULL) {
        //
        // Drop the packet.
        //
        Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Failed; 
    }

    //
    // Initialize this particular algorithm.  IPSec is also responsible 
    // for  verifying that the DataLength is long enough to hold an
    // ESP header, an ESP trailer, and Authentication Data.
    //
    Status =
        IpSecEspInitInbound(
            Nbl,
            Protocol->Level,
            Esp,
            EspHeaderBufferLength,
            Buffer->DataLength,
            Packet->SourceAddress.Address,
            Packet->CurrentDestinationAddress,
            &(Packet->SourcePointer->Interface->Luid),
            &AuthenticationDataLength,
            &ProcessingType,
            &BlockSize,
            &IvLength);
    if (!NT_SUCCESS(Status)) {
        Nbl->Status = Status;
        goto Failed;
    }
    ASSERT(BlockSize <= MAX_IPSEC_BLOCK_SIZE);

    //
    // Get the Authentication Data and truncate the packet to no 
    // longer include it.
    //
    if (AuthenticationDataLength > 0) {
        ULONG Delta;

        Delta = Buffer->DataLength - AuthenticationDataLength;

        NetioAdvanceNetBuffer(Buffer, Delta);

        AuthenticationData =
            NetioGetDataBuffer(
                Buffer, 
                AuthenticationDataLength,
                AuthenticationDataBuffer,
                1,
                0);

        (VOID) NetioRetreatNetBuffer(Buffer, Delta, 0);

        NetioTruncateNetBuffer(Buffer, AuthenticationDataLength);
    } else {
        AuthenticationData = NULL;
    }

    if (ProcessingType.Authentication) {
        //
        // Run algorithm over packet data.
        //
        Mdl = Buffer->CurrentMdl;
        if (Mdl == NULL) {
            IpSecDropInboundPacket(Nbl);
            Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
            goto Failed;
        }

        //
        // ESP authenticates everything beginning with the ESP Header and
        // ending just prior to the Authentication Data.  Since we've
        // already truncated the packet, this means we'll cover the rest
        // of the packet.
        //
        BytesLeft = Buffer->DataLength;

        //
        // First process the remainder of the current MDL.
        //
        MdlByteOffset = Buffer->CurrentMdlOffset;
        FlatBuffer = MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority);
        if (FlatBuffer == NULL) {
            IpSecDropInboundPacket(Nbl);
            Nbl->Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Failed;
        }
        FlatBuffer += MdlByteOffset;
        
        FlatBufferLength =
            min(BytesLeft, MmGetMdlByteCount(Mdl) - MdlByteOffset);
        ASSERT(FlatBufferLength != 0);
        
        IpSecEspAuthInbound(Nbl,
                            FlatBuffer,
                            FlatBufferLength);

        BytesLeft -= FlatBufferLength;

        //
        // Each subsequent MDL is processed as a unit, starting from the 
        // first byte.
        //
        while (BytesLeft != 0) {
            Mdl = Mdl->Next;

            FlatBufferLength = min(BytesLeft, MmGetMdlByteCount(Mdl));

            FlatBuffer = MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority);
            if (FlatBuffer == NULL) {
                IpSecDropInboundPacket(Nbl);
                Nbl->Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Failed;
            }
                
            IpSecEspAuthInbound(Nbl, FlatBuffer, FlatBufferLength);

            BytesLeft -= FlatBufferLength;
        }

        //
        // Let IPSEC get the final result from the algorithm and
        // compare it to the Authentication Data.
        //
        Status = IpSecEspAuthCompleteInbound(Nbl, AuthenticationData);
        if (!NT_SUCCESS(Status)) {
            Nbl->Status = Status;
            goto Failed;
        }
        ASSERT(Status != STATUS_PENDING);
    }

    //
    // We can consume the ESP Header + IvLength now since it isn't
    // covered by confidentiality.
    //
    NetioAdvanceNetBuffer(Buffer, (sizeof(*Esp) + IvLength));

    //
    // Save the current offset so we can restore it afterwards.
    //
    OriginalOffset = Buffer->DataOffset;

    //
    // Decrypt Packet if confidentiality has been selected.
    //
    if (ProcessingType.Confidentiality) {
        //
        // ESP decrypts everything after the ESP Header + IV Length and before the 
        // Authentication Data.  Since we've already truncated the packet, 
        // this means we'll cover the rest of the packet.
        //
        BytesLeft = Buffer->DataLength;
        Status =
            IppEspProcessPacket(
                IpSecEspDecryptInbound, 
                Nbl, 
                Buffer, 
                BlockSize,
                BytesLeft);
        if (!NT_SUCCESS(Status)) {
            IpSecDropInboundPacket(Nbl);
            Nbl->Status = Status;
            goto Failed;
        }

        //
        // The packet is now positioned at the start of the authentication
        // data.  We want to back up and get the ESP trailer.
        //
        (VOID) NetioRetreatNetBuffer(Buffer, sizeof(*EspTrailer), 0);
    } else {
        //
        // The ESP trailer is placed at the end of the packet, just
        // before the authentication data.
        //
        NetioAdvanceNetBuffer(
            Buffer,
            Buffer->DataLength - sizeof(*EspTrailer));
    }

    //
    // We can now get the ESP trailer.  This must be done after decryption, 
    // since the ESP trailer itself is encrypted.
    //
    EspTrailer = (ESP_TRAILER UNALIGNED *) 
        NetioGetDataBuffer(
            Buffer,
            sizeof(*EspTrailer),
            &TrailerBuffer,
            1,
            0);
    if (EspTrailer->PadLength > (Buffer->DataOffset - OriginalOffset)) {
        //
        // PadLength impossibly large.
        //
        IpSecDropInboundPacket(Nbl);
        Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Failed;
    }

    //
    // Remember offset to this header's NextHeader field.
    //
    Packet->NextHeaderPosition = 
        Packet->NlcReceiveDatagram.NetworkLayerHeadersSize + 
        (USHORT)sizeof(ESP_HEADER) + 
        (Buffer->DataOffset - OriginalOffset) +
        FIELD_OFFSET(ESP_TRAILER, NextHeader);

    //
    // Remove padding (if any).  Note that padding may appear
    // even in the no-encryption case in order to align the Authentication
    // Data on a four byte boundary.
    //

    (VOID) NetioRetreatNetBuffer(Buffer, EspTrailer->PadLength, 0);

    if (ProcessingType.Confidentiality) {
        PUCHAR Padding =
            NetioGetDataBuffer(
                Buffer, 
                EspTrailer->PadLength, 
                PaddingBuffer,
                1,
                0);

        //
        // Let IPSec finish the algorithm.
        //
        Status = IpSecEspDecryptCompleteInbound(
                     Nbl, 
                     Padding, 
                     EspTrailer->PadLength);
        if (!NT_SUCCESS(Status)) {
            Nbl->Status = Status;
            goto Failed;
        }
        ASSERT(Status != STATUS_PENDING);
    }

    //
    // Now restore the offset back to the end of the ESP header, but
    // after the IV, if any.
    //
    (VOID) NetioRetreatNetBuffer(
        Buffer, 
        Buffer->DataOffset - OriginalOffset,
        0);

    //
    // Truncate the buffer.  We need to do this after the retreat since
    // the truncate function can't handle truncation to length 0.
    //
    NetioTruncateNetBuffer(Buffer, EspTrailer->PadLength + sizeof(*EspTrailer));
    
    Packet->NlcReceiveDatagram.NextHeaderValue = EspTrailer->NextHeader;
    Packet->NlcReceiveDatagram.NetworkLayerHeadersSize += 
        sizeof(ESP_HEADER) + IvLength;
    ASSERT(Nbl->Status == STATUS_MORE_ENTRIES);

    if (IS_IPV4_PROTOCOL(Protocol)) {
        Status = 
            IpSecTranslateInboundSecureUdpEspPacket(
                (IPPROTO)Packet->NlcReceiveDatagram.NextHeaderValue,
                Packet->NlcReceiveDatagram.NetBufferList
                );
        if (NT_SUCCESS(Status)) {
            ASSERT(Nbl->Status == STATUS_MORE_ENTRIES);
        } else {
            Nbl->Status = Status;
            goto Failed;
        }
    }
    return;

Failed:
    //
    // TODO: In the failure case, the NetworkLayerHeadersSize does not match
    // the amount of header space advanced. 
    //
    Packet->NlcReceiveDatagram.NextHeaderValue = IPPROTO_NONE;
}


VOID
NTAPI
IppReceiveEspList(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    PIP_REQUEST_CONTROL_DATA Curr;
    PIP_RECEIVE_DEMUX Demux = Args->Compartment->Protocol->ReceiveDemux;

    for (Curr = Args; Curr != NULL; Curr = Curr->Next) {
        if ((Curr->NetBufferList == NULL) ||
            (!NT_SUCCESS(Curr->NetBufferList->Status)) ||
            (!Demux[Curr->NlcReceiveDatagram.NextHeaderValue].
                IsExtensionHeader)) {
            //
            // Skip datagrams with errors or upper layer extension headers. 
            //
            continue;
        }
        
        if (Curr->NlcReceiveDatagram.NextHeaderValue != IPPROTO_ESP) {
            break;
        }
        Curr->IpSecHeadersPresent = TRUE;
        IppReceiveEsp(Curr);
    }
}


VOID
IppReceiveEspControl(
    IN PIP_REQUEST_CONTROL_DATA ControlMessage
    )
/*++

Routine Description:

    Handle an ICMP error message in response to an AH we sent.

Arguments:

    ControlMessage - Supplies information about the message received.

Return Value:

    The Status in the NetBufferList is set to one of:

    STATUS_SUCCESS to drop the message.
    STATUS_MORE_ENTRIES if the caller should continue parsing past the
        authentication header.

--*/
{
    UNREFERENCED_PARAMETER(ControlMessage);

    //
    // REVIEW: If the ESP was used for authentication only, we could
    // conceivably continue parsing.  For now, we'll just drop the
    // packet, which is what the XP IPv6 stack does.
    // RAW sockets will see the packet though.
    //
    ControlMessage->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
}


VOID
IppAuthenticateEspHeader(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PNET_BUFFER Buffer,
    IN OUT PUINT8 NextHeaderPointer,
    IN OUT PUINT8 DeferredHeaderPointer,
    IN OUT PUCHAR *DeferredDataPointer,
    IN OUT BOOLEAN *FreeData
    )
/*++

Routine Description:

    Do AH processing over a correctly-formed ESP Header
    encapsulating the AH we are currently processing.

    We don't include other IPSec headers in the integrity check
    as per AH spec section 3.3.  So just skip over this.  The tricky
    part is that the NextHeader was in the ESP trailer which we've
    already thrown away at this point.

--*/
{
    UNREFERENCED_PARAMETER(Packet);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(DeferredHeaderPointer);
    UNREFERENCED_PARAMETER(DeferredDataPointer);
    UNREFERENCED_PARAMETER(FreeData);

    //
    // We don't currently support receiving a packet with an AH following
    // an ESP.
    //
    *NextHeaderPointer = IPPROTO_NONE;
}

NTSTATUS
IppIpSecLsoProcessPacket(
    IN PIP_REQUEST_CONTROL_DATA ControlData,
    IN PNET_BUFFER_LIST NetBufferList,
    IN PNET_BUFFER Buffer,
    IN ULONG PayloadLength
    )
/*++

Routine Description:
    

Arguments:

    NetBufferList - Supplies the net buffer list being operated on.

    Buffer - Supplies a NetBuffer which alligned to the begining of ESP
    payload (after ESP header and IV)

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO NblInfo;
    TCP_HDR TcpBuffer, *Tcp;
    UINT32 PacketCount, Mss, TcpHeaderLength;

    NblInfo.Value = NET_BUFFER_LIST_INFO(
                        NetBufferList, 
                        TcpLargeSendNetBufferListInfo);

    if (0 == NblInfo.Value) {
        return Status;
    }

    ASSERT(IPPROTO_TCP == ControlData->DestinationProtocol);
#ifndef DBG
    UNREFERENCED_PARAMETER(ControlData);
#endif

    if (Buffer->DataLength < sizeof(TcpBuffer)) {
        return Status;
    }

    Tcp = NetioGetDataBuffer(
                Buffer, 
                sizeof(TcpBuffer),
                &TcpBuffer,
                __builtin_alignof(TCP_HDR), 
                0);

    //
    // MSS is same length for both LSO v1 and v2
    //
   
    Mss = NblInfo.LsoV2Transmit.MSS;
    TcpHeaderLength = Tcp->th_len << 2;
    PacketCount = IppGetSegmentationOffloadPacketCount(NetBufferList);
   
    IpSecEspLsoPacketProcessing(
            NetBufferList, 
            PacketCount, 
            Mss, 
            TcpHeaderLength, 
            PayloadLength
            );

    return Status;
}

NTSTATUS
IppAddEspHeader(
    IN PIP_REQUEST_CONTROL_DATA ControlData,
    IN PNET_BUFFER Buffer,
    IN UINT8 NextHeader,
    IN PIP_PACKETIZE_DATA Data
    )
/*++

Routine Description:

    Add an ESP header and trailer to an outgoing packet.
    If encryption is desired, we'll also clone and encrypt.

Arguments:

    ControlData - Supplies the packet metadata.

    Buffer - Supplies a NetBuffer which already contains space at the end of
        the payload for the padding, trailer, and authentication data.  If we
        need confidentiality, then the payload must already be writable.

    NextHeader - Supplies the NextHeader value to place in the ESP trailer.

    Data - Supplies metadata about the packetization operation.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PESP_TRAILER Trailer;
    PVOID Padding, AuthenticationData;
    NTSTATUS Status;
    UCHAR HeaderBuffer[sizeof(ESP_HEADER) + MAX_IPSEC_IV_LENGTH];
    ULONG HeaderLength = sizeof(ESP_HEADER) + Data->EspIvLength;
    ULONG EspPayloadLength;
    SIZE_T BytesCopied;
    ULONG AuthenticationDataLength = Data->EspAuthenticationDataLength;
    ULONG BlockSize = Data->EspBlockSize;
    UINT8 PadLength = Data->EspPadLength;
    PNET_BUFFER_LIST Nbl = ControlData->NetBufferList;

    //
    // Make sure we won't overrun the header buffer.
    //
    ASSERT(Data->EspIvLength <= MAX_IPSEC_IV_LENGTH);

    //
    // The "payload" is everything after the ESP header (and IV) and before 
    // the rest of the authentication data, i.e. including the padding and 
    // ESP trailer.
    //
    ASSERT(Buffer->DataLength >= (AuthenticationDataLength + HeaderLength));
    EspPayloadLength =
        Buffer->DataLength - (AuthenticationDataLength + HeaderLength);

    //
    // Fill in the padding.  We need to do this before making feeding
    // blocks to the data processor, since the padding is covered as well,
    // and it's easier to handle the blocking all in one shot.
    //
    ASSERT(Buffer->DataLength >= 
           (HeaderLength + EspPayloadLength - sizeof(*Trailer) - PadLength));
    NetioAdvanceNetBuffer(
        Buffer,
        HeaderLength + EspPayloadLength - sizeof(*Trailer) - PadLength);
    Padding = NetioGetDataBuffer(Buffer, PadLength, NULL, 1, 0);
    ASSERT((Padding != NULL) || (PadLength == 0));
    
    Status = IpSecEspInitOutbound(Nbl, (PESP_HEADER) HeaderBuffer, Padding);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Fill in the ESP trailer.
    //
    NetioAdvanceNetBuffer(Buffer, PadLength);
    Trailer = NetioGetDataBufferSafe(Buffer, sizeof(*Trailer));
    Trailer->PadLength = PadLength;
    Trailer->NextHeader = NextHeader;

    //
    // Back up to the end of the ESP header and IV.
    //
    Status =
        NetioRetreatNetBuffer(Buffer, EspPayloadLength - sizeof(*Trailer), 0);
    ASSERT(NT_SUCCESS(Status));
    
#ifndef DISABLE_LSO_IPSEC
    // Account for headers of multiple packets if LSO packet.
    IppIpSecLsoProcessPacket(ControlData, Nbl, Buffer, EspPayloadLength);
#endif
    //
    // Make a pass over the original payload.
    //
    Status =
        IppEspProcessPacket(
            IpSecEspProcessOutbound, 
            Nbl, 
            Buffer,
            BlockSize,
            EspPayloadLength);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // The offset is now at the start of the authentication data.
    // Fill it in.
    //
    AuthenticationData =
        NetioGetDataBuffer(
            Buffer, 
            AuthenticationDataLength, 
            NULL, 
            1, 
            0);
    Status = IpSecEspCompleteOutbound(Nbl, AuthenticationData);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Finally, back up and fill in the ESP header and IV.
    //
    (VOID) NetioRetreatNetBuffer(
        Buffer,
        HeaderLength + EspPayloadLength,
        0);

    RtlCopyBufferToMdl(
        HeaderBuffer,
        Buffer->MdlChain,
        Buffer->DataOffset,
        HeaderLength,
        &BytesCopied);

    ASSERT(BytesCopied == HeaderLength);

    return STATUS_SUCCESS;
}
