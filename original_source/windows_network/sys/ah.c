/*++

Copyright (c) Microsoft Corporation

Module Name:

    ah.c

Abstract:

    This module implements functions relating to an Authentication Header.

--*/

#include "precomp.h"

IP_INTERNAL_RECEIVE_DATAGRAMS IppReceiveAhList;
IP_INTERNAL_AUTHENTICATE_HEADER IppAuthenticateAuthenticationHeader;
IP_INTERNAL_ADD_HEADER IppAddAuthenticationHeader;

IP_RECEIVE_DEMUX IpAhDemux = { IppReceiveAhList, 
                               IppReceiveAhControl, 
                               IppAuthenticateAuthenticationHeader,
                               NULL,
                               IppAddAuthenticationHeader,
                               TRUE };

CONST UCHAR Zero[ max(MAXUCHAR, MAX_IPSEC_AUTHENTICATION_DATA_LENGTH) ] = {0};

NTSTATUS
IppPerformDeferredAhProcessing(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PVOID Data,
    IN BOOLEAN FreeData,
    IN UINT8 ThisHeader,
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    Helper routine for IppReceiveAuthenticationHeader.

    This routine handles processing the AH authentication algorithm over
    a given extension header once we know which header logically follows it.

Arguments:

    Protocol - Supplies a pointer to global protocol information.

    Packet - Supplies a pointer to packet metadata.

    Data - Supplies a flat buffer containing the header we're currently 
        processing.

    FreeData - Supplies a boolean indicating whether the flat data buffer
        needs to be freed.

    ThisHeader - Supplies the NextHeader value of the header we're 
        currently processing.

    NextHeader - Supplies the NextHeader value of the header logically 
        following this one.

--*/
{
    PIP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER Function;
    NTSTATUS Status;

    Function =
        Protocol->ReceiveDemux[ThisHeader].InternalDeferredAuthenticateHeader;

    //
    // Unrecognized header.
    // The only way this ASSERT can fire is if somebody adds code
    // to IppReceiveAuthenticationHeader to call this function for a
    // new header and neglects to add a corresponding handler for that
    // header type.
    //
    ASSERT(Function != NULL);

    Status = (*Function)(Packet,
                         Data, 
                         NextHeader);

    if (FreeData) {
        ExFreePool(Data);
    }

    return Status;
}

NTSTATUS
IppAhProcessPacket(
    IN PIP_PROTOCOL Protocol, 
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PNET_BUFFER Buffer, 
    IN ULONG AuthenticationDataLength,
    IN ULONG PaddingLength
    )
/*++

Routine Description:

    Compute the authentication data value for a packet.  The buffer is 
    assumed to be positioned at the start of the IP header, and is left 
    positioned at the start of the header following the AH.

Arguments:

    Protocol - Supplies a pointer to the IP global data.

    Packet - Supplies a pointer to packet metadata.

    Buffer - Supplies the packet buffer.

    AhLength - Supplies the length in bytes of the Authentication Header.

    AuthenticationDataLength - Supplies the length in bytes of the
        authentication data.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

    TODO: In the failure path, IppAhProcessPacket should return with the
    DataOffset in a deterministic position.  Currently, it does not restore the
    net buffer on failure. 

--*/
{
    PNET_BUFFER_LIST Nbl = Packet->NetBufferList;
    PUCHAR DeferredData;
    UINT8 NextHeader, DeferredHeaderType;
    BOOLEAN FreeData;
    PMDL Mdl;
    PUCHAR FlatBuffer;
    ULONG FlatBufferLength;
    ULONG BytesLeft;
    NTSTATUS Status;
    IP_HEADER_STORAGE HeaderStorage;   
    
    //
    // Define a buffer large enough to hold a maximum size IPv4 header
    // with options.
    //
    UCHAR StackBuffer[60];
    //
    // Run algorithm over packet data.  We start with the IP header that
    // encapsulates this AH.  We proceed through the end of the
    // packet, skipping over certain headers which are not part of the
    // logical packet being secured.  We also treat any mutable fields
    // as zero for the purpose of the algorithm calculation.
    //
    // Note: We only search for mutable fields in Destination Options
    // headers that appear before this AH header.  While the spec doesn't
    // explicitly spell this out anywhere, this is the behavior that makes
    // the most sense and we've verified this interpretation in the working
    // group.  However, because of this, our interpretation fails a TAHI test.
    // TAHI will hopefully fix their test, if they haven't already.
    //

    //
    // Start by getting the IP header and seeing which header physically
    // follows it.  This must be contiguous.
    //
    DeferredHeaderType = Protocol->Level;
    FreeData = FALSE;
    if (DeferredHeaderType == IPPROTO_IPV6) {
        IPV6_HEADER UNALIGNED *Ip = (IPV6_HEADER UNALIGNED *) 
            NetioGetDataBuffer(Buffer, sizeof(*Ip), &HeaderStorage, 1, 0);
        NetioAdvanceNetBuffer(Buffer, sizeof(*Ip));
        NextHeader = Ip->NextHeader;

        //
        // Defer processing of this header until after we've determined
        // whether or not we'll be skipping the following header.  This 
        // allows us to use the correct NextHeader field value when 
        // running the algorithm.
        //
        DeferredData = (PUCHAR) Ip;
    } else {
        ULONG HeaderLength;
        IPV4_HEADER UNALIGNED *Ip = (IPV4_HEADER UNALIGNED *) 
            NetioGetDataBuffer(Buffer, sizeof(*Ip), &HeaderStorage, 1, 0);

        HeaderLength = Ip4HeaderLengthInBytes(Ip);
        if (HeaderLength > sizeof(*Ip)) {
            ASSERT(HeaderLength <= sizeof(StackBuffer));

            Ip = (IPV4_HEADER UNALIGNED *) 
                NetioGetDataBuffer(Buffer, HeaderLength, StackBuffer, 1, 0);
        }

        NetioAdvanceNetBuffer(Buffer, HeaderLength);
        
        ASSERT(Protocol->Level == IPPROTO_IP);

        NextHeader = Ip->Protocol;

        //
        // Defer processing of this header until after we've determined
        // whether or not we'll be skipping the following header.  This 
        // allows us to use the correct NextHeader field value when 
        // running the algorithm.
        //
        DeferredData = (PUCHAR) Ip;
    }

    //
    // Continue over the various extension headers until we reach the
    // Authentication Header for which we're running this authentication 
    // algoritm.  We've already parsed this far, so we know these headers 
    // are legit.
    //

    while (NextHeader != IPPROTO_AH) {
        PIP_INTERNAL_AUTHENTICATE_HEADER Function;

        Function = 
            Protocol->ReceiveDemux[NextHeader].InternalAuthenticateHeader;

        if (Function != NULL) {
            (*Function)(Packet, 
                        Buffer, 
                        &NextHeader, 
                        &DeferredHeaderType,
                        &DeferredData,
                        &FreeData);
        } else {
            //
            // Unrecognized header.
            //
            Status = STATUS_DATA_NOT_ACCEPTED;

            if (FreeData) {
                ExFreePool(DeferredData);
            }
            return Status;
        }
    }

    //
    // This is the Authentication Header that we're currently processing,
    // and we include it in its own integrity check.  But first we
    // need to process the header logically preceeding this one (which
    // we previously deferred).  Its NextHeader field will contain the
    // Protocol value for this header.
    //
    {
        ULONG AhLength;
        AUTHENTICATION_HEADER *Ah, AhBuffer;

        Status = IppPerformDeferredAhProcessing(Protocol,
                                                Packet,
                                                DeferredData, 
                                                FreeData,
                                                DeferredHeaderType,
                                                IPPROTO_AH);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        //
        // Now process this Authentication Header.  We do not need to defer 
        // processing of this header, since everything following it is 
        // included in the check.  The Authentication Data is mutable, 
        // the rest of the Authentication Header is not.
        //
        Ah = NetioGetDataBuffer(Buffer, sizeof(*Ah), &AhBuffer, 1, 0);
        AhLength = (Ah->PayloadLength + 2) * 4;

        Status = IpSecAhProcessData(Nbl, (PUCHAR) Ah, sizeof(*Ah));
        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        // Call IPsec to do special processing of the AuthenticationData.
        Status = IpSecAhProcessAuthenticationData(Nbl, AuthenticationDataLength);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
        
        NetioAdvanceNetBuffer(
            Buffer, 
            sizeof(*Ah) + AuthenticationDataLength);
    }

    //
    // Everything inside this AH header is treated as immutable.
    //
    if (Buffer->DataLength > 0) {
        ULONG MdlByteOffset;

        //
        // First process the remainder of the current MDL.
        //
        Mdl = Buffer->CurrentMdl;
        MdlByteOffset = Buffer->CurrentMdlOffset;
        FlatBuffer = MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority);
        if (FlatBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        FlatBuffer += MdlByteOffset;
        BytesLeft = Buffer->DataLength;
        FlatBufferLength = min(BytesLeft, 
                               MmGetMdlByteCount(Mdl) - MdlByteOffset);
        if (FlatBufferLength > 0) {
            Status = IpSecAhProcessData(Nbl, FlatBuffer, FlatBufferLength);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }
    
            BytesLeft -= FlatBufferLength;
        }

        //
        // Subsequent MDLs are processed starting with the first byte.
        //
        while (BytesLeft != 0) {
            Mdl = Mdl->Next;

            FlatBufferLength = min(BytesLeft, MmGetMdlByteCount(Mdl));

            if (FlatBufferLength == 0) {
                //
                // Skip 0-byte MDLs.
                //
                continue;
            }

            FlatBuffer = MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority);
            if (FlatBuffer == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            Status = IpSecAhProcessData(Nbl,
                                        FlatBuffer, 
                                        FlatBufferLength);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }
    
            BytesLeft -= FlatBufferLength;
        }
    }

    //
    // Advance by the padded bytes. In the send case the pad bytes will be 
    // zero. In the receive case the padded bytes can be any arbitrary data.
    // In the receive case we want to advance the NB beyond the pad bytes.
    // This is done here to ensure that we are at the end of NL header 
    // processed so far when we return.
    //
    NetioAdvanceNetBuffer(
            Buffer, 
            PaddingLength);

    return STATUS_SUCCESS;
}

VOID
NTAPI
IppReceiveAuthenticationHeader(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    Handle an IPv6 AH header.  This is the routine called to process an 
    Authentication Header, next header value of 51.

    Compare AuthenticationHeaderReceive in the XP IPv6 stack.
  
Arguments:

    Packet - Supplies IP packet data.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
  
--*/
{
    NTSTATUS Status;
    UCHAR AuthenticationDataBuffer[MAX_IPSEC_AUTHENTICATION_DATA_LENGTH];
    PUCHAR AuthenticationData;
    ULONG AuthenticationDataLength;
    ULONG PaddingLength = 0;
    UCHAR AhHeaderBuffer[sizeof(AUTHENTICATION_HEADER) + MAX_IPSEC_IV_LENGTH];
    ULONG AhHeaderBufferLength = 0;
    AUTHENTICATION_HEADER UNALIGNED *Ah;
    USHORT AhLength;
    PNET_BUFFER_LIST Nbl = Packet->NetBufferList;
    PNET_BUFFER Buffer = Nbl->FirstNetBuffer;
    PIP_PROTOCOL Protocol = Packet->Compartment->Protocol;
    ULONG NBDataOffset = 0;
    //
    // Verify that we have enough contiguous data to overlay an Authentication
    // Header structure on the incoming packet.  Then do so and skip over it.
    //
    if (Buffer->DataLength < sizeof(*Ah)) {
        Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Failed; 
    }

    //
    // There may be an IV immediately following the AH header. Always pass
    // it on to IPsec if present. 
    //
    AhHeaderBufferLength = 
      min((sizeof(AUTHENTICATION_HEADER) + MAX_IPSEC_IV_LENGTH), Buffer->DataLength);
    
    Ah = (AUTHENTICATION_HEADER UNALIGNED *) NetioGetDataBuffer(
                                                    Buffer,
                                                    AhHeaderBufferLength,
                                                    AhHeaderBuffer,
                                                    1,
                                                    0);
    if (Ah == NULL) {
        Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Failed; 
    }

    Packet->NextHeaderPosition = 
        Packet->NlcReceiveDatagram.NetworkLayerHeadersSize + 
        FIELD_OFFSET(AUTHENTICATION_HEADER, NextHeader);
        
    //
    // Ensure that the amount of Authentication Data claimed to exist
    // in this packet by the Authentication Header's PayloadLength field 
    // is large enough to contain the amount that is required.
    //
    AhLength = (Ah->PayloadLength + 2) * 4;
    if ((AhLength < sizeof(*Ah)) || (AhLength > Buffer->DataLength)) {
        Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Failed; 
    }

    //
    // Initialize this particular algorithm.   IPsec will also verify 
    // that AhLength >= sizeof(*Ah) + AuthenticationDataLength.
    //
    Status = IpSecAhInitInbound(Nbl,
                                Protocol->Level,
                                Ah,
                                AhHeaderBufferLength,
                                Buffer->DataLength,                                
                                Packet->SourceAddress.Address,
                                Packet->CurrentDestinationAddress,
                                &(Packet->SourcePointer->Interface->Luid),
                                &AuthenticationDataLength,
                                &PaddingLength);
    if (!NT_SUCCESS(Status)) {
        Nbl->Status = Status;
        goto Failed;
    }

    ASSERT(AhLength >= sizeof(*Ah) + AuthenticationDataLength);

    NetioAdvanceNetBuffer(Buffer, sizeof(*Ah));
    Packet->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(*Ah);

    AuthenticationData = NetioGetDataBuffer(Buffer,
                                            AuthenticationDataLength,
                                            AuthenticationDataBuffer,
                                            1,
                                            0);
    if (AuthenticationData == NULL) {
        IpSecDropInboundPacket(Nbl);
        Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Failed;
    }
    
    //
    // AH authenticates everything (expect mutable fields) starting from
    // the previous IP header.  Stash away our current position (so we can
    // restore it later) and backup to the previous IP header.
    //    
    (VOID) NetioRetreatNetBuffer(
            Buffer, 
            Packet->NlcReceiveDatagram.NetworkLayerHeadersSize,
            0);          
    Packet->NlcReceiveDatagram.NetworkLayerHeadersSize = 0;            
    NBDataOffset = NET_BUFFER_DATA_OFFSET(Buffer);           
    Status = IppAhProcessPacket(Protocol, 
                                Packet, 
                                Buffer, 
                                AuthenticationDataLength,
                                PaddingLength);
    //
    // Network layer header size is the data advanced by this function.
    // Code review and fix this part. This is not clean. 
    //
    Packet->NlcReceiveDatagram.NetworkLayerHeadersSize = 
        NET_BUFFER_DATA_OFFSET(Buffer) - NBDataOffset;
    
    if (!NT_SUCCESS(Status)) {
        IpSecDropInboundPacket(Nbl);
        Nbl->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Failed;
    }

    //
    // Get final result from the algorithm and verify authentication data
    // in packet.
    //
    Status = IpSecAhCompleteInbound(Nbl, AuthenticationData);
    if (!NT_SUCCESS(Status)) {
        Nbl->Status = Status;
        goto Failed;
    }
    ASSERT(Status != STATUS_PENDING);

    Packet->NlcReceiveDatagram.IpsecAuthenticated = TRUE; 

    //
    // Nested AH headers don't include this one in their calculations.
    //
    Packet->SkippedHeaderLength += AhLength;

    Packet->NlcReceiveDatagram.NextHeaderValue = Ah->NextHeader;
    ASSERT(Nbl->Status == STATUS_MORE_ENTRIES);
    return;

Failed:
    Packet->NlcReceiveDatagram.NextHeaderValue = IPPROTO_NONE;
}

VOID
NTAPI
IppReceiveAhList(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    PIP_REQUEST_CONTROL_DATA Curr;
    PIP_PROTOCOL Protocol = Args->Compartment->Protocol;

    for (Curr = Args; Curr != NULL; Curr = Curr->Next) {
        if ((Curr->NetBufferList == NULL) ||
            (!NT_SUCCESS(Curr->NetBufferList->Status)) ||
            (!Protocol->ReceiveDemux[Curr->NlcReceiveDatagram.NextHeaderValue].
            IsExtensionHeader)) {
            //
            // Skip datagrams with errors or upper layer extension headers. 
            //
            continue;
        }
        
        if (Curr->NlcReceiveDatagram.NextHeaderValue != IPPROTO_AH) {
            break;
        }
        Curr->IpSecHeadersPresent = TRUE;
        
        IppReceiveAuthenticationHeader(Curr);
    }
}

VOID
IppReceiveAhControl(
    IN PIP_REQUEST_CONTROL_DATA ControlMessage
    )
/*++

Routine Description:

    Handle an ICMP error message in response to an AH we sent.

    Compare AH case of ExtHdrControlReceive in the XP IPv6 stack.

Arguments:

    ControlMessage - Supplies information about the message received.

Return Value:

    The Status in the NetBufferList is set to one of:

    STATUS_SUCCESS to drop the message.
    STATUS_MORE_ENTRIES if the caller should continue parsing past the
        authentication header.

--*/
{
    AUTHENTICATION_HEADER AhBuffer;
    AUTHENTICATION_HEADER UNALIGNED *Ah;
    PNET_BUFFER_LIST NetBufferList;
    PNET_BUFFER NetBuffer;

    NetBufferList = ControlMessage->NetBufferList;
    NetBuffer = NetBufferList->FirstNetBuffer;

    if (NetBuffer->DataLength < sizeof(*Ah)) {
        //
        // Packet too small.  Drop it, but allow RAW delivery.
        //
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    Ah = (AUTHENTICATION_HEADER UNALIGNED *) 
               NetioGetDataBuffer(NetBuffer, sizeof(*Ah), &AhBuffer, 1, 0);

    NetioAdvanceNetBuffer(NetBuffer, sizeof(*Ah));
    ControlMessage->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(*Ah);

    ControlMessage->NlcReceiveDatagram.NextHeaderValue = Ah->NextHeader;
    ControlMessage->NetBufferList->Status = STATUS_MORE_ENTRIES;
}

VOID
IppAuthenticateAuthenticationHeader(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PNET_BUFFER Buffer,
    IN OUT PUINT8 NextHeaderPointer,
    IN OUT PUINT8 DeferredHeaderPointer,
    IN OUT PUCHAR *DeferredDataPointer,
    IN OUT BOOLEAN *FreeData
    )
/*++

Routine Description:

    Do AH processing over another correctly-formed Authentication Header 
    encapsulating the one we are currently processing.  We don't include 
    it in the integrity check as per AH spec section 3.3.

--*/
{
    AUTHENTICATION_HEADER AhBuffer;
    AUTHENTICATION_HEADER UNALIGNED *Ah;
    ULONG AhLength;

    UNREFERENCED_PARAMETER(Packet);
    UNREFERENCED_PARAMETER(DeferredHeaderPointer);
    UNREFERENCED_PARAMETER(DeferredDataPointer);
    UNREFERENCED_PARAMETER(FreeData);

    Ah = (AUTHENTICATION_HEADER UNALIGNED *)
               NetioGetDataBuffer(Buffer, sizeof(*Ah), &AhBuffer, 1, 0);

    AhLength = IP_AUTHENTICATION_HEADER_LENGTH(Ah->PayloadLength);

    *NextHeaderPointer = Ah->NextHeader;

    NetioAdvanceNetBuffer(Buffer, AhLength);
}

NTSTATUS
IppAddAuthenticationHeader(
    IN PIP_REQUEST_CONTROL_DATA ControlData,
    IN PNET_BUFFER NetBuffer,
    IN UINT8 NextHeader,
    IN OUT PIP_PACKETIZE_DATA Data
    )
/*++

Routine Description:

    Add an Authentication Header to an outgoing packet.

    Compare IPSecInsertHeaders in the XP IPv6 stack.

Arguments:

    ControlData - Supplies the packet metadata.

    NetBuffer - Supplies the net buffer.

    NextHeader - Supplies the NextHeader value to place in the AH.

    Data - Returns metadata about the packetization operation.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    AUTHENTICATION_HEADER Ah;
    SIZE_T BytesCopied;
    NTSTATUS Status;

    Status = IpSecAhInitOutbound(ControlData->NetBufferList, &Ah);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Ah.NextHeader = NextHeader;

    //
    // IPSec gives us an AuthenticationDataLength that includes
    // padding to give a payload length that will be a multiple of 4.
    //
    ASSERT(
        ((Data->AhAuthenticationDataLength + 
          sizeof(AUTHENTICATION_HEADER)) % 4) == 0);

    Ah.PayloadLength = (UINT8) 
        IP_AUTHENTICATION_HEADER_BLOCKS(Data->AhAuthenticationDataLength);

    //
    // We can't make a pass over the packet and fill in the auth data
    // until we've finished packetization, so we'll do that later.
    //
    RtlCopyBufferToMdl(
        &Ah,
        NetBuffer->MdlChain,
        NetBuffer->DataOffset,
        sizeof(Ah),
        &BytesCopied);

    ASSERT(BytesCopied == sizeof(Ah));

    Data->AhHeaderPresent = TRUE;
    return STATUS_SUCCESS;
}


NTSTATUS
IppAuthenticatePacket(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PNET_BUFFER NetBuffer,
    IN PIP_PACKETIZE_DATA Data
    )
/*++

Routine Description:

    Fill AuthenticationData into Authentication Header if needed.
    We assume the NetBuffer is positioned at the start of the IP header,
    and leave it that way if we return success.

    Compare IPSecAuthenticatePacket in the XP IPv6 stack.

Arguments:

    Protocol - Supplies the protocol.
    
    Control - Supplies the control structure.

    NetBuffer - Supplies the NetBuffer to fill in authentication data for.

    Data - Supplies the AH parameters to use.

--*/
{
    NTSTATUS Status;
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    UCHAR AuthenticationData[MAX_IPSEC_AUTHENTICATION_DATA_LENGTH];
    ULONG AuthenticationDataLength = Data->AhAuthenticationDataLength;
    ULONG IpOffset = NetBuffer->DataOffset;
    SIZE_T BytesCopied;

    //
    // Confirm that IppAddAuthenticationHeader has been called and
    // therefore IpSecAhInitOutbound has been called for this NetBuffer.
    //
    ASSERT(Data->AhHeaderPresent);
    
    Status = 
        IppAhProcessPacket(
            Protocol,
            Control,
            NetBuffer,
            AuthenticationDataLength,
            0); // We don't know the padding.
    if (!NT_SUCCESS(Status)) {
        IpSecCleanupSessionInformation(NetBufferList);
        return Status;
    }

    Status = IpSecAhCompleteOutbound(NetBufferList, AuthenticationData);
    if (!NT_SUCCESS(Status)) {
        IpSecCleanupSessionInformation(NetBufferList);
        return Status;
    }

    //
    // Back up to position of authentication data, and copy it in.
    //
    Status = NetioRetreatNetBuffer(NetBuffer, AuthenticationDataLength, 0);
    ASSERT(NT_SUCCESS(Status));

    RtlCopyBufferToMdl(
        AuthenticationData,
        NetBuffer->CurrentMdl,
        NetBuffer->CurrentMdlOffset,
        AuthenticationDataLength,
        &BytesCopied);

    ASSERT(BytesCopied == AuthenticationDataLength);

    //
    // Restore the offset to the start of the IP header.
    //
    Status =
        NetioRetreatNetBuffer(NetBuffer, NetBuffer->DataOffset - IpOffset, 0);
    ASSERT(NT_SUCCESS(Status));

    return STATUS_SUCCESS;
}
