/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    packetize.c

Abstract:

    This module implements the functions of the IPv4 packetizer module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"


NETIO_INLINE
UINT16
Ipv4pGenerateNextFragmentId(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
    
    Generate a unique fragment identifier for the interface.

Arguments:

    Interface - Supplies the interface.

Return Value:

    Returns the fragment identifier in the network byte order. The host stack
    uses only the bottom half of the fragment Id space.

Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    return RtlUshortByteSwap(
        (USHORT)(InterlockedExchangeAdd(&Interface->FragmentId, 1) & 0x7FFF));
}


NETIO_INLINE
UINT16
Ipv4pGenerateMultipleFragmentIds(
    IN PIP_INTERFACE Interface,
    IN ULONG FragmentCount,
    IN ULONG SegmentationOffloadType
    )
/*++

Routine Description:
    
    Generate a range of fragment identifiers for the interface.

Arguments:

    Interface - Supplies the interface.

    FragmentCount - Number of fragment identifiers required.
    
Return Value:

    Returns the first fragment identifier for the requested range in the
    network byte order. The host stack uses only the bottom half of the 
    fragment Id space.

Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ULONG FragmentId;

    ASSERT(FragmentCount < MAX_FRAGMENTS_IN_TCP_LARGE_SEND_OFFLOAD);
    UNREFERENCED_PARAMETER(SegmentationOffloadType);

    //
    // The top half of the framgment ID space is reserved for offload targets.
    //
    
    do {
        FragmentId = 
            InterlockedExchangeAdd(&Interface->FragmentId, FragmentCount);
        FragmentId &= 0x7FFF;
    } while ((FragmentId + FragmentCount) > 0x7FFF);   
    return RtlUshortByteSwap((USHORT)FragmentId);
}


VOID
Ipv4pFillHeaderIncludeProtocolHeader(
    IN OUT PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader, 
    IN PNET_BUFFER NetBuffer,
    IN ULONG HeaderLength, 
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    Fill the IPv4 header.
    Called for the 1st NetBuffer in a NetBufferList for header-include sends.

Arguments:

    Control - Supplies the control structure.
        Returns with an updated IP-header, source, and destination pointers.

    IpHeader - Returns the IP header.

    NetBuffer - Supplies the NetBuffer used for the packet.

    HeaderLength - Supplies the length of the header.
    
    NextHeader - Supplies the protocol value to store in the header.

Return Value:

    None.

--*/
{
    PIPV4_HEADER Ipv4Header = (PIPV4_HEADER) IpHeader;
    
    UNREFERENCED_PARAMETER(HeaderLength);

    //
    // If we performed IPSec then we'd have added ESP or AH after the
    // IP header in the header include header.  Therefore, 
    // update the header with the correct Protocol value.
    // Otherwise leave the Protcol value in the header intact.
    // ISSUE: If the header-include also has existing IPSec (AH/ESP) headers
    // included in it, we should be updating the last header's NextHeader
    // value; however we do not support IPSec headers specified in the
    // header-include header together with IPSec headers required by configured
    // policy--we expect the packet will be discarded by the receiver.
    //
    if (Control->Flags.UseIpSec) { 
        Ipv4Header->Protocol = NextHeader;
    }        
    
    Ipv4pUpdateProtocolHeader(Control, IpHeader, NetBuffer);
    
    //
    // Update the source, destination and IP header pointers.
    //
    Control->IP = IpHeader;
    Control->SourceAddress.Address =
        (PUCHAR) &Ipv4Header->SourceAddress;
    Control->CurrentDestinationAddress = 
        (PUCHAR) &Ipv4Header->DestinationAddress;
}

VOID
Ipv4ShiftRoutingHeader(
    IN PIPV4_ROUTING_HEADER OldHeader,
    OUT PIPV4_ROUTING_HEADER NewHeader,
    IN PIN_ADDR FinalDestinationAddress,
    OUT PUCHAR CurrentDestinationAddress
    )
/*++

Routine Description:

    Shifts all the address entries in OldHeader one address down and moves
    the displaced entry into CurrentDestinationAddress.  It also replaces
    the available slot introduced by the shift with FinalDestinationAddress.

Arguments:

    OldHeader - Supplies the routing header to be shifted.

    NewHeader - Returns the shifted routing header.

    FinalDestinationAddress - Supplies the final destination address to place
        in the shifted address list.  This is the ultimate destination the
        source routed packet should reach.

    CurrentDestinationAddress - Returns the displaced address from the
        shifted address list.  This should be used as the initial destination
        in the IP header.

Return Value:

    None.

--*/    
{
    ULONG AddressBytes;

    //
    // Do nothing if the routing header is not complete.
    //
    if (OldHeader->OptionLength < sizeof(IPV4_ROUTING_HEADER)) {
        return;
    }        
    
    NewHeader->OptionType = OldHeader->OptionType;
    NewHeader->OptionLength = OldHeader->OptionLength;
    NewHeader->Pointer = sizeof(IPV4_ROUTING_HEADER) + 1;

    //
    // Initialize only header if the routing header doesn't 
    // contain at least one address.
    //
    if (OldHeader->OptionLength < 
        (sizeof(IPV4_ROUTING_HEADER) + sizeof(IN_ADDR))) {
        return;
    }        
        
    //
    // Remember the first hop address,
    // which will become the initial destination in the IP header.
    //
    CurrentDestinationAddress = (PUCHAR) (OldHeader + 1); 

    //
    // Shift the list forward.
    //
    AddressBytes = 
        OldHeader->OptionLength - sizeof(IPV4_ROUTING_HEADER) 
        - sizeof(IN_ADDR);
    if (AddressBytes > 0) {
        RtlCopyMemory(
            NewHeader + 1,
            ((PIN_ADDR) (OldHeader + 1)) + 1,
            AddressBytes);
    }        

    //
    // Put the final destination address at the end.
    //
    *((IN_ADDR UNALIGNED *) (((PUCHAR) (NewHeader + 1)) + AddressBytes)) =
        *FinalDestinationAddress;
}

NTSTATUS
Ipv4pFillProtocolHeader(
    IN OUT PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader,
    IN PNET_BUFFER NetBuffer,
    IN ULONG HeaderLength, 
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    Fill the IPv4 header (including options).
    Called for the first NetBuffer in a NetBufferList on the send path
    (except for header-include sends).

Arguments:

    Control - Supplies the control structure.
        Returns with an updated IP-header, source, and destination pointers.

    IpHeader - Returns the IP header.

    NetBuffer - Supplies the NetBuffer used for the packet.

    HeaderLength - Supplies the length of the header.

    NextHeader - Supplies the protocol value to store in the header.

Return Value:

    STATUS_SUCCESS or some NT failure code.

--*/
{
    PIPV4_HEADER Ipv4Header = (PIPV4_HEADER) IpHeader;
    UINT16 FragmentId;
    BOOLEAN OptionsHaveSourceRouting = FALSE;
    PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO NblInfo;
    PNETIO_NET_BUFFER_CONTEXT Context;
    ULONG PacketLength;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ChecksumInfo;

    Context = (PNETIO_NET_BUFFER_CONTEXT) 
        NET_BUFFER_PROTOCOL_RESERVED(NetBuffer);
    PacketLength = NetBuffer->DataLength;
    
    //
    // Fill in IP header.
    //
    Ipv4Header->VersionAndHeaderLength = IPV4_DEFAULT_VERHLEN;
    if (HeaderLength != sizeof(*Ipv4Header)) {
        UINT8 Type, OptionLength;
        PUCHAR Old, New;
        ULONG Padding, OptionLengthWithoutPadding, BytesLeft;
    
        ASSERT((HeaderLength % sizeof(UINT32) == 0) && 
               (HeaderLength >= 
                (sizeof(*Ipv4Header) + Control->HopByHopOptionsLength
                 + Control->RoutingHeaderLength)));
        
        Ipv4Header->HeaderLength = (UINT8) (HeaderLength / sizeof(UINT32));
        
        OptionLengthWithoutPadding = 
            Control->HopByHopOptionsLength + Control->RoutingHeaderLength;
        Padding =
            HeaderLength - sizeof(*Ipv4Header) - OptionLengthWithoutPadding;
        
        //
        // Convert each option to receiver format.
        // We have previously validated that the input options are well-formed.
        //
        BytesLeft = Control->HopByHopOptionsLength;       
        Old = Control->HopByHopOptions;
        New = IpHeader + sizeof(*Ipv4Header);
        while (BytesLeft > 0) {
            Type = Old[0];
            if ((Type == IP_OPT_NOP) || (Type == IP_OPT_EOL)) {
                *New++ = *Old++;
                BytesLeft--;
                continue;
            }
            
            OptionLength = Old[1];
            
            if ((Type == IP_OPT_SSRR) || (Type == IP_OPT_LSRR)) {


                Ipv4ShiftRoutingHeader(
                    (PIPV4_ROUTING_HEADER) Old,
                    (PIPV4_ROUTING_HEADER) New,
                    &(Control->FinalDestinationAddress.Ipv4),
                    (PUCHAR) Control->CurrentDestinationAddress);
                
                OptionsHaveSourceRouting = TRUE;
            } else {
                RtlCopyMemory(New, Old, OptionLength);
            }
            New += OptionLength;
            Old += OptionLength;
            BytesLeft -= OptionLength;

        }

        //
        // Copy routing header (i.e. source routing option), iff the options
        // didn't already specify them.
        //
        if (!OptionsHaveSourceRouting && 
            Control->RoutingHeader != NULL) {
            ASSERT(New == IpHeader + sizeof(*Ipv4Header) 
                + Control->HopByHopOptionsLength);

            //
            // First make sure addition of source routing options doesn't
            // is not more than MAX_IP_OPTIONS_LENGTH.
            //
            if ((Control->HopByHopOptionsLength + Control->RoutingHeaderLength)
                >  MAX_IP_OPTIONS_LENGTH) {
                return STATUS_INVALID_PARAMETER;
            }                
                
            Ipv4ShiftRoutingHeader(
                (PIPV4_ROUTING_HEADER) Control->RoutingHeader,
                (PIPV4_ROUTING_HEADER) New,
                &(Control->FinalDestinationAddress.Ipv4),
                (PUCHAR) Control->CurrentDestinationAddress);

            New += Control->RoutingHeaderLength;
        }        
        
        if (Padding > 0) {
            RtlCopyMemory(New, Zero, Padding);
        }
    }

    Ipv4Header->TypeOfService = (UINT8) Control->TypeOfService;    
    Ipv4Header->EcnField = (UINT8) Context->EcnField;
    Ipv4Header->TotalLength = RtlUshortByteSwap(PacketLength);

    //
    // For segmentation offload sends, get the count of packet that would 
    // be generated.
    // We only support a single NetBuffer within such NetBufferLists.
    //
    NblInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)(
        &NET_BUFFER_LIST_INFO(
            Control->NetBufferList, 
            TcpLargeSendNetBufferListInfo));
            
    if (NblInfo->Value != 0) {
        ASSERT(Control->NetBufferList->FirstNetBuffer->Next == NULL);
        FragmentId = 
            Ipv4pGenerateMultipleFragmentIds(
                Control->SourceLocalAddress->Interface,
                IppGetSegmentationOffloadPacketCount(Control->NetBufferList),
                NblInfo->Transmit.Type);
        if (NblInfo->Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE) {
            //
            // Fill in the TCPHeaderOffset based on the length of the IP Header
            //
            NblInfo->LsoV2Transmit.TcpHeaderOffset += HeaderLength;                
        }
        if (NblInfo->Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE) {
            //
            // Fill in the TCPHeaderOffset based on the length of the IP Header
            //
            NblInfo->LsoV1Transmit.TcpHeaderOffset += HeaderLength;
        }


    } else {
        FragmentId =
            Ipv4pGenerateNextFragmentId(
                Control->SourceLocalAddress->Interface);
    }
    //
    // If we are offloading TCPChecksum set the TcpHeaderOffset.    
    //    
    ChecksumInfo.Value = (PVOID) (ULONG_PTR)
        NET_BUFFER_LIST_INFO(Control->NetBufferList,TcpIpChecksumNetBufferListInfo);

    if (ChecksumInfo.Transmit.TcpChecksum) {
        ChecksumInfo.Transmit.TcpHeaderOffset = HeaderLength;
                
        NET_BUFFER_LIST_INFO(Control->NetBufferList, TcpIpChecksumNetBufferListInfo) =
            (PVOID) (ULONG_PTR) ChecksumInfo.Value;                 
                        
    }

    Ipv4Header->Identification = FragmentId;
    Ipv4Header->FlagsAndOffset = 0;
    if (Control->Flags.DontFragment) {
        Ipv4Header->DontFragment = TRUE;
    }
    Ipv4Header->TimeToLive = (UINT8) Control->HopLimit;
    Ipv4Header->Protocol = NextHeader;
    Ipv4Header->HeaderChecksum = 0;
    Ipv4Header->SourceAddress = 
        *((PIN_ADDR) NL_ADDRESS(Control->SourceLocalAddress));
    Ipv4Header->DestinationAddress = 
        *((IN_ADDR UNALIGNED *)Control->CurrentDestinationAddress);

    //
    // Update the source, destination and IP header pointers.
    //
    Control->IP = IpHeader;
    Control->SourceAddress.Address =
        (PUCHAR) &Ipv4Header->SourceAddress;
    Control->CurrentDestinationAddress = 
        (PUCHAR) &Ipv4Header->DestinationAddress;

    return STATUS_SUCCESS;
}


VOID
Ipv4pUpdateProtocolHeader(
    IN PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader,
    IN PNET_BUFFER NetBuffer
    )
/*++

Routine Description:

    Update an already filled in IPv4 header.
    Called for all (except 1st) NetBuffers in a NetBufferList on the send path.
    Called for the 1st NetBuffer in a NetBufferList for header-include sends.
    Updates fields such as the TotalLength, EcnField and Identifier.

Arguments:

    Control - Supplies the control structure.

    IpHeader - Supplies an already filled in IP header.  Returns an update.

    NetBuffer - Supplies the NetBuffer used for the packet.

Return Value:

    None.

--*/
{
    PIPV4_HEADER Ipv4Header = (PIPV4_HEADER) IpHeader;
    PNETIO_NET_BUFFER_CONTEXT Context;
    ULONG PacketLength;
    
    Context = (PNETIO_NET_BUFFER_CONTEXT) 
        NET_BUFFER_PROTOCOL_RESERVED(NetBuffer);
    PacketLength = NetBuffer->DataLength;
    
    Ipv4Header->TotalLength = RtlUshortByteSwap(PacketLength);

    //
    // Fill in the fragment ID, only if it is not a header include packet,
    // or the ID has been requested by setting the existing ID to 0.
    //
    if (!Control->HeaderIncludeHeader || (Ipv4Header->Identification == 0)) {
        Ipv4Header->Identification =
            Ipv4pGenerateNextFragmentId(
                Control->SourceLocalAddress->Interface);
    }        

    Ipv4Header->EcnField = (UINT8) Context->EcnField;
}



NTSTATUS
Ipv4pValidateRoutingHeaderForSend(
    IN CONST UCHAR *Buffer,
    IN ULONG BufferLength,
    OUT PUSHORT BytesToCopy
    )
/*++

Routine Description:

    Validate a client-supplied routing header buffer.

Arguments:

    Buffer - Supplies the buffer to validate.

    BufferLength - Supplies the length in bytes of the buffer.

    BytesToCopy - Returns the number of bytes in the routing header.

Return Value:

    STATUS_INVALID_PARAMETER if invalid.
    STATUS_SUCCESS if valid.

--*/
{
    PIPV4_ROUTING_HEADER Header;

    if (BufferLength == 0) {
        return STATUS_SUCCESS;
    }

    if ((BufferLength < sizeof(*Header)) ||
        (BufferLength > MAX_IP_OPTIONS_LENGTH)) {
        return STATUS_INVALID_PARAMETER;
    }
    Header = (PIPV4_ROUTING_HEADER) Buffer;

    if ((Header->OptionLength > BufferLength) ||
         (Header->OptionLength < sizeof(IPV4_ROUTING_HEADER)) ||
         ((Header->OptionLength - sizeof(IPV4_ROUTING_HEADER)) 
           % sizeof(IN_ADDR) != 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // The buffer should have enough data for the length specified in the
    // extension header.
    //
    *BytesToCopy = Header->OptionLength;
    if (BufferLength < *BytesToCopy) {
        return STATUS_INVALID_PARAMETER;
    }
    BufferLength = *BytesToCopy;

    if (Header->Pointer != 4) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // No multicast addresses may appear in the hop list.
    //
    Buffer += sizeof(*Header);
    BufferLength -= sizeof(*Header);
    while (BufferLength >= sizeof(IN_ADDR)) {
        if (IppIsInvalidSourceRouteDestinationAddress(
            &Ipv4Global, Buffer)) {
            return STATUS_INVALID_PARAMETER;
        }
        
        Buffer += sizeof(IN_ADDR);
        BufferLength -= sizeof(IN_ADDR);
    }

    return STATUS_SUCCESS;
}

__inline
ULONG
Ipv4pMapOptionsToBits (
    IN IPV4_OPTION_TYPE Type
    )
/*++

Routine Description:

    Given options passed in by the client map them to a bit map so which
    options have already been seen can easily be tracked.

Arguments:

    Type - Supplies the option type to map.

Return Value:

    Return a ULONG containing the appropriate bit to reflect the option.

--*/
{
    switch(Type) {
    case IP_OPT_EOL:
        return 0x00000001;
    case IP_OPT_NOP:
        return 0x00000002;
    case IP_OPT_SECURITY:
        return 0x00000004;
    case IP_OPT_LSRR:
        return 0x00000008;
    case IP_OPT_TS:
        return 0x00000010;
    case IP_OPT_RR:
        return 0x00000020;
    case IP_OPT_SSRR:
        return 0x00000040;
    case IP_OPT_SID:
        return 0x00000080;
    case IP_OPT_ROUTER_ALERT:
        return 0x00000100;
    case IP_OPT_MULTIDEST:
        return 0x00000200;
    default:
        return 0;
    }
}


NTSTATUS
Ipv4pValidateHopByHopOptionsForSend(
    IN CONST UCHAR *OptionsBuffer,
    IN ULONG OptionsLength,
    OUT PUSHORT FirstHopOffset,
    OUT PUSHORT BytesToCopy
    )
/*++

Routine Description:

    This verifies the options buffer passed in by the client contains valid
    information.

Arguments:

    OptionsBuffer - Supplies the buffer containing IPv4 options information.

    OptionsLength - Supplies the length of the buffer passed in.

    FirstHopOffset - Returns the offset of the first hop address in a 
        source route, if any.  Returns 0 if none.

    BytesToCopy - Returns the number of bytes to actually copy.

Return Value:

    STATUS_SUCCESS if the buffer is valid.
    STATUS_INVALID_PARAMETER if not.

--*/
{
    ULONG OptionsSeen = 0;
    ULONG OriginalOptionsLength = OptionsLength;
    PIPV4_OPTION_HEADER Option;
    PIPV4_TIMESTAMP_OPTION TSOption;
    ULONG OptionDataLength, TSEntrySize;
    ULONG MinRoutingHeaderSize, MinTimestampHeaderSize;

    *FirstHopOffset = 0;
    *BytesToCopy = 0;
    
    if (OptionsLength == 0) {
        return STATUS_SUCCESS;
    }
    
    if ((OptionsLength < sizeof(IPV4_OPTION_HEADER)) ||
        (OptionsLength > MAX_IP_OPTIONS_LENGTH)) {
        return STATUS_INVALID_PARAMETER;
    }

    while (OptionsLength > 0) {
        //
        // Handle any options smaller than IPV4_OPTION_HEADER first.
        //
        if (*OptionsBuffer == IP_OPT_NOP) {
            OptionsBuffer++;
            OptionsLength--;
            continue;
        }    

        if (*OptionsBuffer == IP_OPT_EOL) {
            OptionsBuffer++;
            OptionsLength--;
            break;
        }

        if (OptionsLength < sizeof(*Option)) {
            return STATUS_INVALID_PARAMETER;
        }

        Option = (PIPV4_OPTION_HEADER) OptionsBuffer;

        if (OptionsLength < Option->OptionLength) {
            //
            // The buffer should have enough data for the length specified
            // in the option.
            //
            return STATUS_INVALID_PARAMETER;
        }

        //
        // Perform any additional type-specific validation.
        //
        switch(Option->OptionType) {

        case IP_OPT_SSRR:
        case IP_OPT_LSRR:
            MinRoutingHeaderSize = sizeof(*Option) + 1;
            if (OptionsSeen & (Ipv4pMapOptionsToBits(IP_OPT_LSRR) |
                               Ipv4pMapOptionsToBits(IP_OPT_SSRR))) {
                return STATUS_INVALID_PARAMETER;
            }

            if (Option->OptionLength < MinRoutingHeaderSize) {
                return STATUS_INVALID_PARAMETER;                
            }

            //
            // The list must contain an integral, non-zero number of 
            // addresses.
            //
            OptionDataLength = Option->OptionLength - MinRoutingHeaderSize;
            if ((OptionDataLength < sizeof(IN_ADDR)) ||
                ((OptionDataLength % sizeof(IN_ADDR)) != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            //
            // The pointer should be at least 4 (point to the beginning of the 
            // first address), and must be a multiple of 4, and must not go
            // beyond the end of the options buffer.
            //
             if ((OptionsBuffer[2] < MinRoutingHeaderSize + 1) ||
                ((OptionsBuffer[2] % sizeof(IN_ADDR)) != 0) ||
                (OptionDataLength < 
                    (OptionsBuffer[2] - MinRoutingHeaderSize - 1))) {
                return STATUS_INVALID_PARAMETER;
            }

            //
            // We liberally allow sending a source route with the 
            // "pointer" pointing not to the first entry, but elsewhere.
            // In any case we should pick the next hop only if it is 
            // actually available.
            //
            if (OptionDataLength > 
                    (OptionsBuffer[2] - MinRoutingHeaderSize - 1)) {
                *FirstHopOffset = OptionsBuffer[2] - 1 +
                    (OriginalOptionsLength - OptionsLength);
            }
			
            //
            // TODO: No multicast addresses may appear in the hop list.
            //
            
            break;
            
        case IP_OPT_TS:
            MinTimestampHeaderSize = sizeof(*Option) + 2;

            if (Option->OptionLength < MinTimestampHeaderSize) {
                return STATUS_INVALID_PARAMETER;                
            }

            TSOption = (PIPV4_TIMESTAMP_OPTION) Option;
			
            if ((TSOption->Flags == IP_OPTION_TIMESTAMP_ADDRESS) ||
                 (TSOption->Flags == IP_OPTION_TIMESTAMP_SPECIFIC_ADDRESS)) {
                TSEntrySize = sizeof(UINT32) + sizeof(IN_ADDR);
            } else if (TSOption->Flags == IP_OPTION_TIMESTAMP_ONLY) {
                TSEntrySize = sizeof(UINT32);
            } else {
                return STATUS_INVALID_PARAMETER;
            }

            //
            // The list must have space for an integral, non-zero number of 
            // entries.
            //
            OptionDataLength = Option->OptionLength - MinTimestampHeaderSize;
            if ((OptionDataLength < TSEntrySize) ||
                 ((OptionDataLength % TSEntrySize) != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            //
            // The pointer should be at least 5, aligned as required by the flags
            // and must not go beyond the end of the options buffer.
            //
            if ((OptionsBuffer[2] < MinTimestampHeaderSize + 1) ||
                 (((OptionsBuffer[2] - MinTimestampHeaderSize - 1) 
                    % TSEntrySize) != 0) ||
                 (OptionDataLength < 
                    (OptionsBuffer[2] - MinTimestampHeaderSize - 1))) {
                return STATUS_INVALID_PARAMETER;
            }
	    
            break;

        case IP_OPT_RR:
            MinRoutingHeaderSize = sizeof(*Option) + 1;

            if (Option->OptionLength < MinRoutingHeaderSize) {
                return STATUS_INVALID_PARAMETER;                
            }

            //
            // The list must have space for an integral, non-zero number of 
            // addresses.
            //
            OptionDataLength = Option->OptionLength - MinRoutingHeaderSize;
            if ((OptionDataLength < sizeof(IN_ADDR)) ||
                ((OptionDataLength % sizeof(IN_ADDR)) != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            //
            // The pointer should be at least 4 (point to the space for the 
            // first address), and must be a multiple of 4, and must not go
            // beyond the end of the options buffer.
            //
             if ((OptionsBuffer[2] < MinRoutingHeaderSize + 1) ||
                ((OptionsBuffer[2] % sizeof(IN_ADDR)) != 0) ||
                (OptionDataLength < 
                    (OptionsBuffer[2] - MinRoutingHeaderSize - 1))) {
                return STATUS_INVALID_PARAMETER;
            }
            
            break;

        case IP_OPT_ROUTER_ALERT:
            if (Option->OptionLength != sizeof(UINT32)) {
                return STATUS_INVALID_PARAMETER;
            }
            break;
            
        default:
            return STATUS_INVALID_PARAMETER;
        }

        //
        // Each multibyte option can only occur once.
        //
        if (OptionsSeen & (Ipv4pMapOptionsToBits(Option->OptionType))) {
            return STATUS_INVALID_PARAMETER;
        }
        OptionsSeen |= Ipv4pMapOptionsToBits(Option->OptionType);

        OptionsBuffer += Option->OptionLength;
        OptionsLength -= Option->OptionLength;
    }

    *BytesToCopy = OriginalOptionsLength - OptionsLength;
    return STATUS_SUCCESS;
}


NTSTATUS
Ipv4pSkipNetworkLayerHeaders(
    IN PNET_BUFFER NetBuffer, 
    OUT PUCHAR SourceAddress OPTIONAL, 
    OUT PUCHAR CurrentDestinationAddress OPTIONAL, 
    OUT PUCHAR FinalDestinationAddress OPTIONAL, 
    OUT UINT8 *TransportLayerProtocol, 
    OUT ULONG *SkippedLength
    )
/*++

Routine Description:

    Skip all network layer headers in a NetBuffer until we reach a transport
    layer header.  Return the source and destination addresses, the transport
    layer header type and the length of data skipped.
    
Arguments:

    NetBuffer - Supplies the NetBuffer in which to skip network layer headers.

    SourceAddress - Returns the source from IPV4_HEADER. 

    CurrentDestinationAddress - Returns the destination from IPV4_HEADER. 

    FinalDestinationAddress - Returns the final destination address.
    
    TransportLayerProtocol - Returns the transport layer header type
        (e.g. IPPROTO_TCP). 

    SkippedLength - Returns the length of network layer headers skipped. 

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    IPV4_HEADER *Ipv4Header, Ipv4HeaderBuffer;
    AUTHENTICATION_HEADER *AuthenticationHeader, AuthenticationHeaderBuffer;
    ULONG HeaderLength;
    UINT8 NextHeader;
    
    //
    // Get the IPv4 header and parse it. 
    //
    if (NetBuffer->DataLength < sizeof(Ipv4HeaderBuffer)) {
        return STATUS_DATA_NOT_ACCEPTED;
    }

    Ipv4Header =
        NetioGetDataBuffer(
            NetBuffer, 
            sizeof(Ipv4HeaderBuffer), 
            &Ipv4HeaderBuffer, 
            __builtin_alignof(IPV4_HEADER), 
            0);
    if (Ipv4Header == NULL) {
        //
        // This can happen on the send path because Winsock doesn't necessarily
        // map the MDLs before sending them down to us.  Therefore 
        // NetioGetDataBuffer's call to MmGetSystemAddressForMdlSafe can fail.
        //
        return STATUS_INSUFFICIENT_RESOURCES;    
    }

    if (SourceAddress != NULL) {
        RtlCopyMemory(
            SourceAddress, 
            &Ipv4Header->SourceAddress, 
            sizeof(Ipv4Header->SourceAddress));
    }        

    if (CurrentDestinationAddress != NULL) {
        RtlCopyMemory(
            CurrentDestinationAddress, 
            &Ipv4Header->DestinationAddress, 
            sizeof(Ipv4Header->DestinationAddress));
    }        

    //
    // TODO: Fill FinalDestinationAddress from any LSRR or SSRR option.
    //
    if (FinalDestinationAddress != NULL) {
        RtlCopyMemory(
            FinalDestinationAddress, 
            &Ipv4Header->DestinationAddress, 
            sizeof(Ipv4Header->DestinationAddress));
    }

    NextHeader = Ipv4Header->Protocol;
    
    HeaderLength = Ip4HeaderLengthInBytes(Ipv4Header);

    if (HeaderLength < sizeof(IPV4_HEADER)) {
        return STATUS_DATA_NOT_ACCEPTED;
    }
    
    if (NetBuffer->DataLength < HeaderLength) {
        return STATUS_DATA_NOT_ACCEPTED;
    }
    //
    // Advance past the IPv4 header. 
    //    
    NetioAdvanceNetBuffer(NetBuffer, HeaderLength);
    *SkippedLength = HeaderLength;
    
    while (NextHeader == IPPROTO_AH) {
        if (NetBuffer->DataLength < sizeof(AUTHENTICATION_HEADER)) {
            return STATUS_DATA_NOT_ACCEPTED;
        }
        
        AuthenticationHeader =
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(AUTHENTICATION_HEADER), 
                &AuthenticationHeaderBuffer, 
                1, 
                0);
        NextHeader = AuthenticationHeader->NextHeader;
        HeaderLength = (AuthenticationHeader->PayloadLength + 1) * 8;

        if (NetBuffer->DataLength < HeaderLength) {
            return STATUS_DATA_NOT_ACCEPTED;
        }
        NetioAdvanceNetBuffer(NetBuffer, HeaderLength);
        *SkippedLength += HeaderLength;
    }
    
    *TransportLayerProtocol = NextHeader;
    
    return STATUS_SUCCESS;
}

