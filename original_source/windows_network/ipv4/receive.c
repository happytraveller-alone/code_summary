/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    receive.c

Abstract:

    This module implements the functions of the IPv4 Packet Validater module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "receive.tmh"

__inline
BOOLEAN
Ipv4pInvalidOptionLength(
    IN PUCHAR Pointer,
    IN ULONG OptionLength,
    IN ULONG OptionHeaderLength
    )
{
    //
    // Validate OptionLength vis-a-vis OptionHeaderLength.
    // 1. OptionLength must be greater than OptionHeaderLength.
    // 2. OptionLength - OptionHeaderLength must be an integral multiple of 4.
    //
    if ((OptionLength < OptionHeaderLength) ||
        (((OptionLength - OptionHeaderLength) % sizeof(UINT32)) != 0)) {
        return TRUE;
    }
    
    //
    // Validate Pointer vis-a-vis OptionLength and OptionHeaderLength.
    // 1. Pointer value must be at most one past the OptionLength.
    // 2. Pointer value must be greater than the OptionHeaderLength.
    // 3. Pointer value must be aligned.
    //
    if (((*Pointer) > (OptionLength + 1)) ||
        ((*Pointer) < (OptionHeaderLength + 1)) ||
        ((((*Pointer) - (OptionHeaderLength + 1)) % sizeof(UINT32)) != 0)) {
        return TRUE;
    }

    //
    // OptionLength and Pointer are both valid.
    //
    return FALSE;
}

BOOLEAN
Ipv4pProcessTimestampOption(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN OUT PUCHAR OptionBuffer,
    OUT BOOLEAN* OptionChanged
    )
/*++

Routine Description:

    Records timestamp information in the options portion of a packet.

Arguments:

    Control - Supplies the packet to timestamp.

    OptionBuffer - Supplies the type of timestamp request.  Returns the 
        Timestamp.

    OptionChanged - Returns whether the OptionBuffer was modified with a 
        timestamp.

Return Value: 
 
    TRUE on success; FALSE otherwise.
    
*/    
{
    PIPV4_TIMESTAMP_OPTION TimestampOption = 
        (PIPV4_TIMESTAMP_OPTION) OptionBuffer;
    ULONG Pointer = TimestampOption->Pointer;
    ULONG Length = TimestampOption->OptionLength;
    ULONG Now = RtlUlongByteSwap(IppGetMillisecondsFromMidnight());
    PIP_LOCAL_ADDRESS LocalAddress;

    //
    // Pointer is a 1-based index.
    //
    if (Pointer <= sizeof(IPV4_TIMESTAMP_OPTION)) {
        goto Error;
    }
    Pointer--;
    
    if (Pointer < Length) {
        OptionBuffer += Pointer;
        switch (TimestampOption->Flags) {
        case IP_OPTION_TIMESTAMP_ONLY:
            if ((Length - Pointer) < sizeof(UINT32)) {
                goto Overflow;            
            }                
            RtlCopyMemory(OptionBuffer, &Now, sizeof(UINT32));
            break;
            
        case IP_OPTION_TIMESTAMP_ADDRESS:
            if ((Length - Pointer) < (sizeof(UINT32) + sizeof(IN_ADDR))) {
                goto Overflow;            
            }
            //
            // We use the first/primary address on the interface in the
            // as in the timestamp.
            //
            if (NT_SUCCESS(IppGetFirstUnicastAddress(
                               Control->SourcePointer->Interface,
                               (PIP_LOCAL_UNICAST_ADDRESS *) &LocalAddress))) {
            
                RtlCopyMemory(
                    OptionBuffer, 
                    NL_ADDRESS(LocalAddress),
                    sizeof(IN_ADDR));
                IppDereferenceLocalAddress(LocalAddress);
            } else {
                //
                // Addresses may have been deleted after receiving the packet.
                // So, do a best-effort attempt to record timestamp.
                //
                RtlZeroMemory(OptionBuffer, sizeof(IN_ADDR));
            }
            OptionBuffer += sizeof(IN_ADDR);

            RtlCopyMemory(OptionBuffer, &Now, sizeof(UINT32));
            break;
            
        case IP_OPTION_TIMESTAMP_SPECIFIC_ADDRESS:
            if ((Length - Pointer) < (sizeof(UINT32) + sizeof(IN_ADDR))) {
                goto Overflow;            
            }              

            //
            // Should we respond to this address? Note that this is not a
            // non-aligned access since Pointer is a multiple of four and
            // OptionsBuffer is 32-bit aligned.
            //
            LocalAddress = 
                (PIP_LOCAL_ADDRESS) IppFindAddressOnInterface(
                    Control->SourcePointer->Interface,
                    OptionBuffer);
            if (LocalAddress != NULL) {
                if (NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast) {
                    OptionBuffer += sizeof(IN_ADDR);
                    RtlCopyMemory(OptionBuffer, &Now, sizeof(UINT32));
                }
                IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) LocalAddress);
            }                
            break;
            
        default:
            goto Error;
        }    
        *OptionChanged = TRUE;
        return TRUE;
    }
    
Overflow:
        if (TimestampOption->Overflow < 0xf) {
            TimestampOption->Overflow++;
            *OptionChanged = TRUE;
            return TRUE;
        } else {
Error:        
            return FALSE;
        }            
}

    
IP_DISCARD_REASON
Ipv4pProcessOptions(
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN ULONG AvailableOptionLength, 
    OUT BOOLEAN* HeaderChanged
    )

/*++

Routine Description:

    This routine processes options in the IP header.

Arguments:

    Control - Supplies the packet whose options to process.
        The data offset is set at the start of the options.
    
    AvailableOptionLength - Supplies the length of the options.
        The packet is guaranteed to be large enough to contain the option.

    HeaderChanged - Returns whether the IP header was modified.
        The checksum should be recomputed if TRUE.
        
Return Value:

    IpDiscardReceivePathMax on success, discard reason on failure.
    
Caller IRQL:

    <= DISPATCH_LEVEL.

--*/
{
    IP_DISCARD_REASON DiscardReason = IpDiscardMalformedHeader;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram = &Control->NlcReceiveDatagram;
    UCHAR *Options;
    PIPV4_OPTION_HEADER OptionHeader;
    ULONG OptionLength, BytesParsed;
    BOOLEAN SendIcmpError = TRUE, Eol = FALSE, OptionChanged = FALSE;
    ULONG OriginalOptionLength = AvailableOptionLength;

    //
    // Get all the options in one shot.
    //
    ASSERT(AvailableOptionLength <= MAX_IP_OPTIONS_LENGTH);    

    //
    // The FL provider and lower layers guarantee that the IPv4 header 
    // including the options is in contiguous memory, so we don't need any 
    // local storage space and this call should always succeed.  
    //
    Options = NetioGetDataBufferSafe(NetBuffer, AvailableOptionLength);
    ASSERT(Options != NULL);

    BytesParsed = 0;

    while (AvailableOptionLength > 0) {
        //
        // First we check the option length and ensure that it fits.
        //
        OptionHeader = (PIPV4_OPTION_HEADER) Options;
        
        ASSERT(RTL_SIZEOF_THROUGH_FIELD(IPV4_OPTION_HEADER, OptionType) == 1);
        
        if ((OptionHeader->OptionType == IP_OPT_NOP) ||
            (OptionHeader->OptionType == IP_OPT_EOL)) {
            //
            // This is a special pad option which is just a one byte field,
            // i.e. it has no length or data field.
            //
            OptionLength = 1;
        } else {
            //
            // This is a multi-byte option.
            //
            if ((AvailableOptionLength < sizeof(IPV4_OPTION_HEADER)) ||
                (AvailableOptionLength < OptionHeader->OptionLength)) {
                goto BadOptionLength;
            }
            
            OptionLength = OptionHeader->OptionLength;
        }
        
        //
        // Fail if any option past an IP_OPT_EOL option is not also IP_OPT_EOL.
        //
        if (Eol && (OptionHeader->OptionType != IP_OPT_EOL)) {
            goto BadOptionType;
        }

        switch (OptionHeader->OptionType) {

        case IP_OPT_EOL:
            Eol = TRUE;
            break;

        case IP_OPT_NOP:
            break;

        case IP_OPT_SECURITY:
            if (OptionLength != SIZEOF_IP_OPT_SECURITY) {
                goto BadOptionLength;
            }

            //
            // Appears at most once.  But we are liberal.
            //
            break;
            
        case IP_OPT_SSRR:
            Control->StrictSourceRouted = TRUE;            

        case IP_OPT_LSRR:            
            if (Ipv4pInvalidOptionLength(
                    (PUCHAR) (OptionHeader + 1),
                    OptionLength,
                    SIZEOF_IP_OPT_ROUTING_HEADER)) {
                goto BadOptionLength;
            }

            Control->ReceiveRoutingHeaderOffset = 
               (UINT8) (sizeof(IPV4_HEADER) + OriginalOptionLength - 
                AvailableOptionLength);

            Control->ReceiveRoutingHeaderLength = OptionLength;

            //
            // Appears at most once.  But we are liberal and use the last
            // instance.
            //
            break;
        
        case IP_OPT_RR:
            if (Ipv4pInvalidOptionLength(
                    (PUCHAR) (OptionHeader + 1),
                    OptionLength,
                    SIZEOF_IP_OPT_ROUTING_HEADER)) {
                goto BadOptionLength;
            }

            if (Ipv4Global.SourceRoutingBehavior == SourceRoutingDrop) {
                SendIcmpError = FALSE;
                goto BadOptionType;
            }

            //
            // Appears at most once.  But we are liberal.
            //
            break;
            
        case IP_OPT_SID:
            if (OptionLength != SIZEOF_IP_OPT_STREAMIDENTIFIER) {
                goto BadOptionLength;
            }

            //
            // Appears at most once.  But we are liberal.
            //
            break;

        case IP_OPT_TS:
            if (Ipv4pInvalidOptionLength(
                    (PUCHAR) (OptionHeader + 1),
                    OptionLength,
                    SIZEOF_IP_OPT_TIMESTAMP_HEADER)) {
                goto BadOptionLength;
            }

            if (!Ipv4pProcessTimestampOption(
                    Control,
                    Options,
                    &OptionChanged)) {
                goto BadOption;
            }

            //
            // Appears at most once.  But we are liberal.
            //
            break;
            
        case IP_OPT_MULTIDEST:
            if (OptionLength < sizeof(IPV4_OPTION_HEADER)) {
                goto BadOptionLength;
            }
            //
            // Accept option of reasonable length.
            //
            break;

        case IP_OPT_ROUTER_ALERT:
            if (OptionLength != SIZEOF_IP_OPT_ROUTERALERT) {
                goto BadOptionLength;
            }
            Control->RouterAlert = TRUE;
            break;

        default:
            goto BadOptionType;
        }

        Options += OptionLength;
        BytesParsed += OptionLength;
        AvailableOptionLength -= OptionLength;
        *HeaderChanged = *HeaderChanged || OptionChanged;
        OptionChanged = FALSE;
    }

    ASSERT(AvailableOptionLength == 0);
    
    return IpDiscardReceivePathMax;
    
BadOptionLength:
    BytesParsed += sizeof(UINT8);

BadOption:
BadOptionType:
    NetioAdvanceNetBuffer(NetBuffer, BytesParsed);
    ReceiveDatagram->NetworkLayerHeadersSize += BytesParsed;
    ReceiveDatagram->NextHeaderValue = IPPROTO_NONE;
    Control->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
               "IPNG: Validation of IPv4 packet failed : "
               "Bad options\n");

    if ((IppDiscardReceivedPackets(
            &Ipv4Global, 
            DiscardReason,
            Control, 
            NULL, 
            NULL) == IpDiscardAllowIcmp) &&
        SendIcmpError) {
            IppSendErrorList(
                TRUE,
                &Ipv4Global,
                Control,
                ICMP4_PARAM_PROB,
                0,
                RtlUlongByteSwap(ReceiveDatagram->NetworkLayerHeadersSize),
                FALSE);
    }

    return DiscardReason;
}


NTSTATUS
Ipv4pValidateNetBuffer(
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN PNDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo
    )
/*++

Routine Description:

    Validate and process an IPv4 header.
    Retrieve pointers to source and destination addresses and the IPv4 header.

    This is the equivalent of IPv6HeaderReceive() in XP.

Arguments:

    Control - Supplies a packet to validate.
        Returns the source and destination addresses and the IPv4 header.
    
    ChecksumInfo - The checksum offload information for the NetBuffer.
    
Return Value:

    STATUS_SUCCESS if the packet is valid.
    STATUS_BUFFER_TOO_SMALL if the packet is too short.
    STATUS_DATA_NOT_ACCEPTED if the packet is not valid for any other reason.

Caller IRQL:

    <= DISPATCH_LEVEL.
    
--*/
{
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    PNET_BUFFER NetBuffer = NetBufferList->FirstNetBuffer;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram = &Control->NlcReceiveDatagram;    
    IPV4_HEADER *Header;
    ULONG HeaderLength, PacketLength;
    PUCHAR SourceAddress, DestinationAddress;
    IP_DISCARD_REASON DiscardReason;
    
    //
    // Ensure we have enough bytes for an IPv4 header.
    //
    if (NetBuffer->DataLength < sizeof(IPV4_HEADER)) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv4 packet failed - "
                   "Packet too small (%d bytes) to contain IPv4 header\n",
                   NetBuffer->DataLength);

        (VOID) IppDiscardReceivedPackets(
            &Ipv4Global, 
            IpDiscardBadLength,
            NULL,
            Control->SourceSubInterface, 
            NetBufferList);
        
        return (NetBufferList->Status = STATUS_BUFFER_TOO_SMALL);
    }

    //
    // The FL provider and lower layers guarantee that the IPv4 header is in
    // contiguous memory, so we don't need any local storage space and this
    // call should always succeed.  They also guarantees 2-byte alignment.
    //
    Header = NetioGetDataBufferSafe(NetBuffer, sizeof(IPV4_HEADER));
    ASSERT(Header != NULL);

    //
    // We use a separate pointer to refer to the source and destination
    // addresses so that later options can change them.
    //
    Control->IP = (PUCHAR) Header;

    Control->CurrentDestinationAddress = DestinationAddress = 
        (PUCHAR) &Header->DestinationAddress;
    Control->CurrentDestinationType =
        Ipv4AddressType(DestinationAddress);

    Control->SourceAddress.Address = SourceAddress = 
        (PUCHAR) &Header->SourceAddress;

    //
    // Protect against attacks that use bogus source addresses.
    //
    if (IppIsInvalidSourceAddress(&Ipv4Global, SourceAddress) ||
        IN4_IS_UNALIGNED_ADDR_LOOPBACK((PIN_ADDR) SourceAddress)) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv4 packet failed : "
                   "Bad source address\n");
        DiscardReason = IpDiscardBadSourceAddress;
        NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Discard;
    }

    //
    // Before processing any headers,
    // check that the amount of payload the IPv4 header thinks is present
    // can actually fit inside the packet data area that the link handed us.
    //
    PacketLength = RtlUshortByteSwap(Header->TotalLength);
    if ((PacketLength < sizeof(IPV4_HEADER)) ||
        (PacketLength > NetBuffer->DataLength)) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv4 packet failed - "
                   "Length in header (%d) greater than actual length (%d)\n",
                   PacketLength, NetBuffer->DataLength);
        DiscardReason = IpDiscardBadLength;
        NetBufferList->Status = STATUS_BUFFER_TOO_SMALL;
        goto Discard;
    }

    //
    // Truncate if extra bytes exist at the end.
    //
    NetioTruncateNetBuffer(NetBuffer, NetBuffer->DataLength - PacketLength);

    // 
    // Check if the IP version is correct.
    // We specifically do NOT check HopLimit.
    // HopLimit is only checked when forwarding.
    //
    HeaderLength = sizeof(IPV4_HEADER);
    if (Header->VersionAndHeaderLength != IPV4_DEFAULT_VERHLEN) {
        if (Header->Version != IPV4_VERSION) {
            //
            // Silently discard the packet.
            //
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                       "IPNG: Validation of IPv4 packet failed - "
                       "Bad version (%d)\n",
                       Header->Version);

            (VOID) IppDiscardReceivedPackets(
                &Ipv4Global, 
                IpDiscardMalformedHeader,
                NULL,
                Control->SourceSubInterface, 
                NetBufferList);
            
            return (NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED);
        }

        HeaderLength = Ip4HeaderLengthInBytes(Header);
        ASSERT((HeaderLength % 4) == 0);
        if ((HeaderLength < sizeof(IPV4_HEADER)) ||
            (HeaderLength > PacketLength)) {
            
            //
            // Silently discard the packet.
            //
            NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                       "IPNG: Validation of IPv4 packet failed - "
                       "Bad header length (%d)\n",
                       HeaderLength);
            DiscardReason = IpDiscardBadLength;
            NetBufferList->Status = STATUS_BUFFER_TOO_SMALL;
            goto Discard;
        }
    }

    //
    // Copy out the ECN Field into the NETIO_NET_BUFFER_CONTEXT for use by TL.
    //
    ((PNETIO_NET_BUFFER_CONTEXT) 
        NET_BUFFER_PROTOCOL_RESERVED(NetBuffer))->EcnField = Header->EcnField;
        
    //
    // Verify the header checksum (if not already done in hardware).
    //
    if (!ChecksumInfo->Receive.NdisPacketIpChecksumSucceeded &&
        (ChecksumInfo->Receive.NdisPacketIpChecksumFailed ||
            IppChecksum(Header, HeaderLength) != 0xffff)) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv4 packet failed : "
                   "Checksum failed\n");
        DiscardReason = IpDiscardMalformedHeader;
        NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Discard;
    }
    ChecksumInfo->Receive.NdisPacketIpChecksumSucceeded = 0;

    //
    // Process any options.
    // Note that the header checksum may need to be updated.
    //
    if (HeaderLength != sizeof(IPV4_HEADER)) {
        BOOLEAN UpdateChecksum = FALSE;
        //
        // Advance past the IPv4 header and validate the options. 
        //
        ReceiveDatagram->NetworkLayerHeadersSize += sizeof(IPV4_HEADER);
        NetioAdvanceNetBuffer(
            NetBuffer, ReceiveDatagram->NetworkLayerHeadersSize);

        DiscardReason =
            Ipv4pProcessOptions(
                Control, 
                HeaderLength - sizeof(IPV4_HEADER), 
                &UpdateChecksum);

        NetioRetreatNetBuffer(
            NetBuffer, ReceiveDatagram->NetworkLayerHeadersSize, 0);
        ReceiveDatagram->NetworkLayerHeadersSize -= sizeof(IPV4_HEADER);

        if (DiscardReason != IpDiscardReceivePathMax) {
            //
            // The packet had bad options.  Drop it.  Ipv4pProcessOptions
            // would have called IppDiscardReceivedPackets.
            //
            ASSERT(NetBufferList->Status == STATUS_DATA_NOT_ACCEPTED);
            return STATUS_DATA_NOT_ACCEPTED;
        }

        //
        // An alternative is to use ones-complement arithmetic to update the 
        // checksum when updating the header. This however is simpler. 
        //
        if (UpdateChecksum) {
            Header->HeaderChecksum = 0;
            Header->HeaderChecksum = ~IppChecksum(Header, HeaderLength);
        }
    }

    return STATUS_SUCCESS;
    
Discard:
    {
        NTSTATUS Status = NetBufferList->Status;
        
        //
        // Silently discard the packet.
        //
        (VOID) IppDiscardReceivedPackets(
            &Ipv4Global, 
            DiscardReason,
            Control, 
            NULL, 
            NULL);

        return Status;
    }
}
