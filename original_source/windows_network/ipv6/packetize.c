/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    packetize.c

Abstract:

    This module implements the functions of the IPv6 Packetizer module.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"


VOID
Ipv6pFillHeaderIncludeProtocolHeader(
    IN OUT PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader, 
    IN PNET_BUFFER NetBuffer,
    IN ULONG HeaderLength, 
    IN UINT8 NextIpsecHeader
    )
/*++

Routine Description:

    Fill the IPv6 header.
    Called for the 1st NetBuffer in a NetBufferList for header-include sends.

Arguments:

    Control - Supplies the control structure.
        Returns with an updated IP-header, source, and destination pointers.

    IpHeader - Returns the IP header.

    NetBuffer - Supplies the NetBuffer used for the packet.

    HeaderLength - Supplies the length of the header.

    NextHeader - Supplies the Ipsec header value to store in the header.

Return Value:

    None.

--*/
{
    PIPV6_HEADER Ipv6Header = (PIPV6_HEADER) IpHeader;
    UINT8 NextHeader;
    
    UNREFERENCED_PARAMETER(HeaderLength);

    //
    // If we performed IPSec then we'd have added ESP or AH after the IP
    // header or the extension headers in header include.  Therefore, find and
    // update the last-but-one header with the correct NextHeader value.
    //
    // Otherwise leave the NextHeader value in the last-but-one header intact.
    //
    // ISSUE: We are modifying the NextHeader value of the AH header if it
    // exists which will invalidate the ICV calculated; however we do
    // not support IPSec headers specified in the header-include header 
    // together with IPSec headers required by configured policy--we expect
    // the packet will be discarded by the receiver.
    //
    // The code is very similar to Ipv6pSkipNetworkLayerHeaders, however
    // we expect to remove it if IPV6_HDRINCL is deperecated when we support
    // the advanced sockets API (RFC 3542).
    //
    if (Control->Flags.UseIpSec) { 
        PIPV6_EXTENSION_HEADER ExtensionHeader = NULL;
        ULONG SkippedLength;
        IPV6_FRAGMENT_HEADER *FragmentHeader = NULL;        
        NextHeader = Ipv6Header->NextHeader;
        
        //
        // Advance past the IPv6 header. 
        //
        NetioAdvanceNetBuffer(NetBuffer, sizeof(IPV6_HEADER));
        SkippedLength = sizeof(IPV6_HEADER);        
        while ((NextHeader == IPPROTO_HOPOPTS) || 
               (NextHeader == IPPROTO_ROUTING) ||
               (NextHeader == IPPROTO_FRAGMENT) ||
               (NextHeader == IPPROTO_DSTOPTS) ||
               (NextHeader == IPPROTO_AH)) {

            switch (NextHeader) {
            case IPPROTO_FRAGMENT: 
                HeaderLength = sizeof(IPV6_FRAGMENT_HEADER);
                
                FragmentHeader =
                    NetioGetDataBufferSafe(NetBuffer, HeaderLength);

                NextHeader = FragmentHeader->NextHeader;
                break;

            default:
                HeaderLength = sizeof(IPV6_EXTENSION_HEADER);
                ExtensionHeader =
                    NetioGetDataBufferSafe(NetBuffer, HeaderLength);

                HeaderLength = (NextHeader == IPPROTO_AH)
                    ? IP_AUTHENTICATION_HEADER_LENGTH(ExtensionHeader->Length)
                    : IPV6_EXTENSION_HEADER_LENGTH(ExtensionHeader->Length);

                NextHeader = ExtensionHeader->NextHeader;
                break;
            }
            NetioAdvanceNetBuffer(NetBuffer, HeaderLength);
            SkippedLength += HeaderLength;
        }
        if (ExtensionHeader != NULL) {
            ExtensionHeader->NextHeader = NextIpsecHeader;
        } else if (FragmentHeader != NULL) {
            FragmentHeader->NextHeader = NextIpsecHeader;
        } else {
            Ipv6Header->NextHeader = NextIpsecHeader;
        }            
        NetioRetreatNetBuffer(NetBuffer, SkippedLength, 0);
    }        
    
    Ipv6pUpdateProtocolHeader(Control, IpHeader, NetBuffer);
    
    //
    // Update the source, destination and IP header pointers.
    //
    Control->IP = IpHeader;
    Control->SourceAddress.Address =
        (PUCHAR) &Ipv6Header->SourceAddress;
    Control->CurrentDestinationAddress = 
        (PUCHAR) &Ipv6Header->DestinationAddress;
}


UINT32
Ipv6pGetVersionClassEcnFlow(
    IN UINT8 Class,
    IN UINT8 EcnField
    )
{
    //
    // IPv6 Version, Traffic Class, ECN Field and Flow Label fields in host
    // byte order.
    //
    union {
        struct {
            UINT32 Flow : 20;
            UINT32 EcnField : 2;
            UINT32 Class : 6;
            UINT32 Version : 4; // Most significant bits.
        };
        UINT32 Value;
    } VersionClassEcnFlow = {0};

    VersionClassEcnFlow.Version = 6;
    VersionClassEcnFlow.Class = Class;
    VersionClassEcnFlow.EcnField = EcnField;
    return RtlUlongByteSwap(VersionClassEcnFlow.Value);
}


NTSTATUS
Ipv6pFillProtocolHeader(
    IN OUT PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader, 
    IN PNET_BUFFER NetBuffer,
    IN ULONG HeaderLength, 
    IN UINT8 NextHeader
    )
/*++

Routine Description:

    Fill the IPv6 header.
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

    Always returns STATUS_SUCCESS; the IPv4 version of this routine can return
    a failure code.

--*/
{
    PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO NblInfo;
    PIPV6_HEADER Ipv6Header = (PIPV6_HEADER) IpHeader;
    PNETIO_NET_BUFFER_CONTEXT Context;
    ULONG PacketLength = NetBuffer->DataLength;
    ULONG PayloadLength = PacketLength - sizeof(*Ipv6Header);
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ChecksumInfo;

    UNREFERENCED_PARAMETER(HeaderLength);    
    ASSERT(HeaderLength == sizeof(*Ipv6Header));
        
    Context = (PNETIO_NET_BUFFER_CONTEXT) 
        NET_BUFFER_PROTOCOL_RESERVED(NetBuffer);
    
    //
    // Fill the IPv6 header. 
    //
    Ipv6Header->VersionClassFlow =
        (Control->TypeOfService == 0 && 
         Context->EcnField == NlEcnCodepointNotEct)
        ? IPV6_VERSION
        : Ipv6pGetVersionClassEcnFlow(
              (UINT8) Control->TypeOfService, (UINT8) Context->EcnField);    

    Ipv6Header->PayloadLength = 
        (PayloadLength <= MAX_IPV6_PAYLOAD)
        ? Ipv6Header->PayloadLength = RtlUshortByteSwap(PayloadLength)
        : 0;

    Ipv6Header->NextHeader = NextHeader;
    Ipv6Header->HopLimit = (UINT8) Control->HopLimit;
    Ipv6Header->SourceAddress = 
        *((PIN6_ADDR) NL_ADDRESS(Control->SourceLocalAddress));
    Ipv6Header->DestinationAddress =
        *((PIN6_ADDR) Control->CurrentDestinationAddress);
    
    //
    // Update the source, destination and IP header pointers.
    //
    Control->IP = IpHeader;
    Control->SourceAddress.Address =
        (PUCHAR) &Ipv6Header->SourceAddress;
    Control->CurrentDestinationAddress = 
        (PUCHAR) &Ipv6Header->DestinationAddress;

    NblInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)(
        &NET_BUFFER_LIST_INFO(
            Control->NetBufferList, 
            TcpLargeSendNetBufferListInfo));
    if (NblInfo->Value != 0) {
        ASSERT(Control->NetBufferList->FirstNetBuffer->Next == NULL);

        //
        // Fill in the TCPHeaderOffset based on the length of the IP Header
        //
        if (NblInfo->Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE) {
            NblInfo->LsoV2Transmit.TcpHeaderOffset += 
                HeaderLength + 
                Control->RoutingHeaderLength + 
                Control->HopByHopOptionsLength + 
                Control->JumbogramHopByHopOptionsLength;
        }
    }        

    //
    // If we are offloading TCPChecksum set the TcpHeaderOffset.    
    //    
    ChecksumInfo.Value = (PVOID) (ULONG_PTR)
        NET_BUFFER_LIST_INFO(Control->NetBufferList,TcpIpChecksumNetBufferListInfo);

    if (ChecksumInfo.Transmit.TcpChecksum) {
        ChecksumInfo.Transmit.TcpHeaderOffset = 
                HeaderLength + 
                Control->RoutingHeaderLength + 
                Control->HopByHopOptionsLength + 
                Control->JumbogramHopByHopOptionsLength;
                
        NET_BUFFER_LIST_INFO(Control->NetBufferList, TcpIpChecksumNetBufferListInfo) =
            (PVOID) (ULONG_PTR) ChecksumInfo.Value;                 
                        
        
    }        
    
    return STATUS_SUCCESS;    
}


VOID
Ipv6pUpdateProtocolHeader(
    IN PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader, 
    IN PNET_BUFFER NetBuffer
    )
/*++

Routine Description:

    Update an already filled in IPv6 header.
    Called for all (except 1st) NetBuffers in a NetBufferList on the send path.
    Called for the 1st NetBuffer in a NetBufferList for header-include sends.
    Updates fields such as the PayloadLength.

Arguments:

    Control - Supplies the control structure.

    IpHeader - Supplies an already filled in IP header.  Returns an update.

    NetBuffer - Supplies the NetBuffer used for the packet.

Return Value:

    None.

--*/
{
    PIPV6_HEADER Ipv6Header = (PIPV6_HEADER) IpHeader;
    PNETIO_NET_BUFFER_CONTEXT Context;
    ULONG PacketLength = NetBuffer->DataLength;    
    ULONG PayloadLength = PacketLength - sizeof(*Ipv6Header);

    UNREFERENCED_PARAMETER(Control);
    
    Context = (PNETIO_NET_BUFFER_CONTEXT) 
        NET_BUFFER_PROTOCOL_RESERVED(NetBuffer);

    if (PayloadLength > MAX_IPV6_PAYLOAD) {
        PayloadLength = 0;
    }
    Ipv6Header->PayloadLength = RtlUshortByteSwap((UINT16) PayloadLength);
    
    Ipv6Header->VersionClassFlow &= ~IPV6_ECN_MASK;
    Ipv6Header->VersionClassFlow |= (Context->EcnField << IPV6_ECN_SHIFT);    
}


NTSTATUS
Ipv6pValidateRoutingHeaderForSend(
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
    PIPV6_ROUTING_HEADER Header;

    if (BufferLength == 0) {
        return STATUS_SUCCESS;
    }

    if ((BufferLength < sizeof(*Header)) ||
        (BufferLength > MAX_IPV6_EXTENSION_HEADER_LENGTH)) {
        return STATUS_INVALID_PARAMETER;
    }
    Header = (PIPV6_ROUTING_HEADER) Buffer;

    //
    // The buffer should have enough data for the length specified in the
    // extension header.
    //
    *BytesToCopy = IPV6_EXTENSION_HEADER_LENGTH(Header->Length);
    if (BufferLength < *BytesToCopy) {
        return STATUS_INVALID_PARAMETER;
    }
    BufferLength = *BytesToCopy;

    //
    // SegmentsLeft should be the total list length.
    // The list must contain an integral, non-zero number of addresses,
    // each of which shows up as 2 (quad words) in Header->Length.
    //
    if ((Header->SegmentsLeft == 0) ||
        (Header->SegmentsLeft * 2 != Header->Length)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // No multicast addresses may appear in the hop list.
    //
    Buffer += sizeof(*Header);
    BufferLength -= sizeof(*Header);
    while (BufferLength >= sizeof(IN6_ADDR)) {
        if (IN6_IS_ADDR_MULTICAST((PIN6_ADDR) Buffer)) {
            return STATUS_INVALID_PARAMETER;
        }
        
        Buffer += sizeof(IN6_ADDR);
        BufferLength -= sizeof(IN6_ADDR);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
Ipv6pValidateHopByHopOptionsForSend(
    IN CONST UCHAR *OptionsBuffer,
    IN ULONG OptionsLength,
    OUT PUSHORT FirstHopOffset,
    OUT PUSHORT BytesToCopy
    )
/*++

Routine Description:

    Validate a client-supplied hop-by-hop options extension header buffer.

Arguments:

    Buffer - Supplies the buffer to validate.

    BufferLength - Supplies the length in bytes of the buffer.

    FirstHopOffset - Always returns 0, since IPv6 does not use hop-by-hop
        options for source routing.

    BytesToCopy - Returns the number of bytes in the extension header.

Return Value:

    STATUS_INVALID_PARAMETER if invalid.
    STATUS_SUCCESS if valid.

--*/
{
    PIPV6_EXTENSION_HEADER Header;
    PIPV6_OPTION_HEADER Option;

    *FirstHopOffset = 0;

    if (OptionsLength == 0) {
        *BytesToCopy = 0;
        return STATUS_SUCCESS;
    }

    if ((OptionsLength < sizeof(*Header)) ||
        (OptionsLength > MAX_IPV6_EXTENSION_HEADER_LENGTH)) {
        return STATUS_INVALID_PARAMETER;
    }
    Header = (PIPV6_EXTENSION_HEADER) OptionsBuffer;

    //
    // The buffer should have enough data for the length specified in the
    // extension header.
    //
    *BytesToCopy = IPV6_EXTENSION_HEADER_LENGTH(Header->Length);
    if (OptionsLength < *BytesToCopy) {
        return STATUS_INVALID_PARAMETER;
    }

    OptionsBuffer += sizeof(*Header);
    OptionsLength -= sizeof(*Header);

    while (OptionsLength > 0) {
        //
        // Handle any options smaller than IPV6_OPTION_HEADER first.
        //
        if (*OptionsBuffer == IP6OPT_PAD1) {
            OptionsBuffer++;
            OptionsLength--;
            continue;
        }

        if (OptionsLength < sizeof(*Option)) {
            return STATUS_INVALID_PARAMETER;
        }
        Option = (PIPV6_OPTION_HEADER) OptionsBuffer;
        OptionsBuffer += sizeof(*Option);
        OptionsLength -= sizeof(*Option);

        if (OptionsLength < Option->DataLength) {
            //
            // The buffer should have enough data for the length specified
            // in the option.
            //
            return STATUS_INVALID_PARAMETER;
        }
        
        //
        // Perform any additional type-specific validation.
        //
        switch(Option->Type) {
        case IP6OPT_JUMBO:
            //
            // This option cannot be specified by a user.
            //
            return STATUS_INVALID_PARAMETER;

        default:
            break;
        }

        OptionsBuffer += Option->DataLength;
        OptionsLength -= Option->DataLength;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
Ipv6pAddHopByHopOptionsHeader(
    IN PIP_REQUEST_CONTROL_DATA ControlData,
    IN PNET_BUFFER NetBuffer,
    IN UINT8 NextHeader,
    IN PIP_PACKETIZE_DATA Data
    )
/*++

Routine Description:

    Fill in an IPv6 Hop-by-Hop Options extension header.

Arguments:

    ControlData - Supplies the packets to which to add IPv6 Hop-by-Hop
        Options.  If the HopByHopOptionsLength in the control data is NULL,
        then it implies that the jumbogram option needs to be added to the
        packet.  Otherwise the hop-by-hop option specified in HopByHopOptions
        is added.
        
    Buffer - Supplies the net buffer to use.

    NextHeader - Supplies the NextHeader value to place in the hop-by-hop
        header. 

    Data - Supplies metadata about the packetization operation.

Locks:

    None.

Caller IRQL:

    Callable at PASSIVE through DISPATCH.

--*/
{
    UCHAR Buffer[sizeof(IPV6_EXTENSION_HEADER)+sizeof(IPV6_OPTION_JUMBOGRAM)];
    PIPV6_EXTENSION_HEADER ExtensionHeader;
    PIPV6_OPTION_JUMBOGRAM JumbogramOption;
    ULONG ExtensionHeaderLength;
    SIZE_T BytesCopied;
    
    UNREFERENCED_PARAMETER(Data);
    
    ExtensionHeader = ControlData->HopByHopOptions;
    ExtensionHeaderLength = ControlData->HopByHopOptionsLength;

    //
    // Check to see what if any stack-supplied options need to be added.
    //
    if (ExtensionHeader == NULL) {
        ASSERT(ExtensionHeaderLength == 0);

        ExtensionHeader = (PIPV6_EXTENSION_HEADER) Buffer;
        ExtensionHeaderLength =
            sizeof(IPV6_EXTENSION_HEADER) + sizeof(IPV6_OPTION_JUMBOGRAM);

        JumbogramOption = (PIPV6_OPTION_JUMBOGRAM) (ExtensionHeader + 1);
        JumbogramOption->Header.Type = IP6OPT_JUMBO;
        JumbogramOption->Header.DataLength =
            sizeof(IPV6_OPTION_JUMBOGRAM) - sizeof(IPV6_OPTION_HEADER);
        *((UINT32 UNALIGNED *) JumbogramOption->JumbogramLength) = 
            RtlUlongByteSwap(NetBuffer->DataLength);
    }

    ExtensionHeader->NextHeader = NextHeader;
    ExtensionHeader->Length =
        IPV6_EXTENSION_HEADER_BLOCKS(ExtensionHeaderLength);

    RtlCopyBufferToMdl(
        ExtensionHeader,
        NetBuffer->CurrentMdl,
        NetBuffer->CurrentMdlOffset,
        ExtensionHeaderLength,
        &BytesCopied);

    return STATUS_SUCCESS;
}


NTSTATUS
Ipv6pSkipNetworkLayerHeaders(
    IN PNET_BUFFER NetBuffer, 
    OUT PUCHAR SourceAddress OPTIONAL, 
    OUT PUCHAR CurrentDestinationAddress OPTIONAL, 
    OUT PUCHAR FinalDestinationAddress OPTIONAL, 
    OUT UINT8 *TransportLayerHeader,
    OUT ULONG *SkippedLength
    )
/*++

Routine Description:

    Skip all network layer headers in a NetBuffer until we reach a transport
    layer header.  Return the source and destination addresses, the transport
    layer header type and the length of data skipped.
    
Arguments:

    NetBuffer - Supplies the NetBuffer in which to skip network layer headers.

    SourceAddress - Returns the source from IPV6_HEADER.

    CurrentDestinationAddress - Returns the destination from IPV6_HEADER. 

    FinalDestinationAddress - Returns the final destination address.
    
    TransportLayerProtocol - Returns the transport layer header type
        (e.g. IPPROTO_TCP). 

    SkippedLength - Returns the length of network layer headers skipped. 

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    UINT8 NextHeader;
    ULONG HeaderLength;
    IPV6_HEADER *Ipv6Header, Ipv6HeaderBuffer;
    IPV6_FRAGMENT_HEADER *FragmentHeader, FragmentHeaderBuffer;
    IPV6_EXTENSION_HEADER *ExtensionHeader, ExtensionHeaderBuffer;
    
    //
    // Get the IPv6 header and parse it. 
    //
    if (NetBuffer->DataLength < sizeof(Ipv6HeaderBuffer)) {
        return STATUS_DATA_NOT_ACCEPTED;
    }

    Ipv6Header =
        NetioGetDataBuffer(
            NetBuffer, 
            sizeof(Ipv6HeaderBuffer), 
            &Ipv6HeaderBuffer, 
            __builtin_alignof(IPV6_HEADER), 
            0);
    if (Ipv6Header == NULL) {
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
            &Ipv6Header->SourceAddress, 
            sizeof(Ipv6Header->SourceAddress));
    }        

    if (CurrentDestinationAddress != NULL) {
        RtlCopyMemory(
            CurrentDestinationAddress, 
            &Ipv6Header->DestinationAddress, 
            sizeof(Ipv6Header->DestinationAddress));
    }        

    //
    // TODO: Fill FinalDestinationAddress from any RoutingHeader.
    //
    if (FinalDestinationAddress != NULL) {
        RtlCopyMemory(
            FinalDestinationAddress, 
            &Ipv6Header->DestinationAddress, 
            sizeof(Ipv6Header->DestinationAddress));
    }        
    
    NextHeader = Ipv6Header->NextHeader;
    
    //
    // Advance past the IPv6 header. 
    //
    NetioAdvanceNetBuffer(NetBuffer, sizeof(IPV6_HEADER));
    *SkippedLength = sizeof(IPV6_HEADER);
    
    while ((NextHeader == IPPROTO_HOPOPTS) || 
           (NextHeader == IPPROTO_ROUTING) ||
           (NextHeader == IPPROTO_FRAGMENT) ||
           (NextHeader == IPPROTO_DSTOPTS) ||
           (NextHeader == IPPROTO_AH)) {
        switch (NextHeader) {
        case IPPROTO_FRAGMENT: 
            HeaderLength = sizeof(FragmentHeaderBuffer);
            if (NetBuffer->DataLength < HeaderLength) {
                return STATUS_DATA_NOT_ACCEPTED;
            }
            
            FragmentHeader =
                NetioGetDataBuffer(
                    NetBuffer, 
                    HeaderLength, 
                    &FragmentHeaderBuffer, 
                    1,
                    0);

            NextHeader = FragmentHeader->NextHeader;
            break;

        default:
            HeaderLength = sizeof(IPV6_EXTENSION_HEADER);
            if (NetBuffer->DataLength < HeaderLength) {
                return STATUS_DATA_NOT_ACCEPTED;
            }
            
            ExtensionHeader =
                NetioGetDataBuffer(
                    NetBuffer, 
                    HeaderLength, 
                    &ExtensionHeaderBuffer, 
                    1,
                    0);

            HeaderLength = (NextHeader == IPPROTO_AH)
                ? IP_AUTHENTICATION_HEADER_LENGTH(ExtensionHeader->Length)
                : IPV6_EXTENSION_HEADER_LENGTH(ExtensionHeader->Length);

            NextHeader = ExtensionHeader->NextHeader;
            break;
        }
        
        if (NetBuffer->DataLength < HeaderLength) {
            return STATUS_DATA_NOT_ACCEPTED;
        }
        NetioAdvanceNetBuffer(NetBuffer, HeaderLength);
        *SkippedLength += HeaderLength;
    }
    
    *TransportLayerHeader = NextHeader;

    return STATUS_SUCCESS;
}


NTSTATUS
Ipv6pAddRoutingHeader(
    IN PIP_REQUEST_CONTROL_DATA ControlData,
    IN PNET_BUFFER NetBuffer,
    IN UINT8 NextHeader,
    IN OUT PIP_PACKETIZE_DATA Data
    )
/*++

Routine Description:

    Fill in an IPv6 Routing Header.

Arguments:

    ControlData - Supplies the packet metadata.

    NetBuffer - Supplies the packets to which to add an IPv6 Routing Header.
        The packet is already positioned where we should place it.
        
    NextHeader - Supplies the value to use for the next header field.

    Data - UNUSED.

Locks:

    None.

Caller IRQL:

    Callable at PASSIVE through DISPATCH.

--*/

{
    PIPV6_ROUTING_HEADER Header, NewHeader;
    ULONG HeaderLength, ListLength;
    SIZE_T BytesCopied;

    UNREFERENCED_PARAMETER(Data);

    Header = ControlData->RoutingHeader;
    HeaderLength = ControlData->RoutingHeaderLength;

    Header->NextHeader = NextHeader;
    Header->Length =
        IPV6_EXTENSION_HEADER_BLOCKS(HeaderLength);
    Header->SegmentsLeft = 0;

    //
    // Create a new header in sender-format.  This is how it appears on
    // the wire, whereas apps, IPsec, and the IP stack at the final destination
    // all see it in receiver-format.
    //

    NewHeader = ExAllocatePoolWithTagPriority(NonPagedPool,
                                              HeaderLength,
                                              IpGenericPoolTag,
                                              LowPoolPriority);
    if (NewHeader == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy the original header except with all segments left.
    //
    RtlCopyMemory(NewHeader, Header, sizeof(*Header)); 
    NewHeader->SegmentsLeft = Header->Length / 2;

    //
    // Remember the first hop address, which will become the initial
    // destination in the IP header.
    //
    ControlData->CurrentDestinationAddress = (PUCHAR) (Header + 1);

    ASSERT(NewHeader->SegmentsLeft > 0);
    ListLength = (NewHeader->SegmentsLeft - 1) * sizeof(IN6_ADDR);

    //
    // Shift the list forward, where the entry that was first will 
    // become the initial destination in the IP header.
    //
    RtlCopyMemory(((PUCHAR) (NewHeader + 1)),
                  ((PUCHAR) (Header + 1)) + sizeof(IN6_ADDR),
                  ListLength);

    //
    // Put the final destination address at the end.
    //
    RtlCopyMemory(((PUCHAR) (NewHeader + 1)) + ListLength,
                  &ControlData->FinalDestinationAddress.Ipv6,
                  sizeof(IN6_ADDR));

    RtlCopyBufferToMdl(NewHeader,
                       NetBuffer->CurrentMdl,
                       NetBuffer->CurrentMdlOffset,
                       HeaderLength,
                       &BytesCopied);

    ExFreePool(NewHeader);

    return STATUS_SUCCESS;
}
