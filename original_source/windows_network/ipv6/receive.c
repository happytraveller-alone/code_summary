/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    receive.c

Abstract:

    This module implements the functions of the IPv6 Packet Validater module.

Author:

    Dave Thaler (dthaler) 7-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "receive.tmh"

IP_DISCARD_REASON
Ipv6pProcessOptions(
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    This routine processes options in an extension header.

Arguments:

    Control - Supplies the packet whose options to process.
        The data offset is set at the start of the extension header.
    
Return Value:

    IpDiscardReceivePathMax on success, discard reason on failure.
    
Caller IRQL:

    <= DISPATCH_LEVEL.

--*/
{
    IP_DISCARD_REASON DiscardReason = IpDiscardMalformedHeader;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram = &Control->NlcReceiveDatagram;
    IPV6_EXTENSION_HEADER ExtensionHeaderBuffer, *ExtensionHeader;
    IPV6_OPTION_HEADER OptionHeaderBuffer, *OptionHeader;
    IPV6_OPTION_JUMBOGRAM JumbogramBuffer, *Jumbogram;    
    ULONG ExtensionHeaderLength, AvailableOptionLength, OptionLength;
    ULONG BytesParsed, JumbogramLength, ErrorOffset;
    BOOLEAN SendIcmpError = TRUE, MulticastOverride = FALSE;
    UINT8 IcmpCode = ICMP6_PARAMPROB_HEADER;
    
    //
    // Ensure that the packet is large enough for the extension-header header.
    //
    if (NetBuffer->DataLength < sizeof(IPV6_EXTENSION_HEADER)) {
        DiscardReason = IpDiscardBadLength;
        ErrorOffset = FIELD_OFFSET(IPV6_HEADER, PayloadLength);
        goto BadHeader;
    }
    
    //
    // First obtain the extension header, then walk the options one by one.
    //
    ExtensionHeader =
        NetioGetDataBuffer(
            NetBuffer,
            sizeof(IPV6_EXTENSION_HEADER),
            &ExtensionHeaderBuffer,
            __builtin_alignof(IPV6_EXTENSION_HEADER),
            0);

    ExtensionHeaderLength =
        IPV6_EXTENSION_HEADER_LENGTH(ExtensionHeader->Length);

    //
    // Ensure that the packet is large enough for the entire extension-header.
    //
    if (NetBuffer->DataLength < ExtensionHeaderLength) {
        DiscardReason = IpDiscardBadLength;
        ErrorOffset = FIELD_OFFSET(IPV6_HEADER, PayloadLength);
        goto BadHeader;
    }    
    
    ASSERT(ExtensionHeaderLength >= sizeof(IPV6_EXTENSION_HEADER));
    AvailableOptionLength =
        ExtensionHeaderLength - sizeof(IPV6_EXTENSION_HEADER);

    NetioAdvanceNetBuffer(NetBuffer, sizeof(IPV6_EXTENSION_HEADER));
    
    ASSERT((ReceiveDatagram->NextHeaderValue == IPPROTO_HOPOPTS) ||
           (ReceiveDatagram->NextHeaderValue == IPPROTO_DSTOPTS));

    //
    // The HopByHop Options header, when present,
    // must immediately follow the IPv6 header.
    //
    ASSERT((ReceiveDatagram->NextHeaderValue != IPPROTO_HOPOPTS) ||
           (ReceiveDatagram->NetworkLayerHeadersSize == sizeof(IPV6_HEADER)));
    
    while (AvailableOptionLength > 0) {
        //
        // First we check the option length and ensure that it fits.
        //
        OptionHeader =
            NetioGetDataBuffer(
                NetBuffer,
                min(sizeof(IPV6_OPTION_HEADER), AvailableOptionLength),
                &OptionHeaderBuffer,
                __builtin_alignof(IPV6_OPTION_HEADER),
                0);
        ASSERT(OptionHeader != NULL);

        ASSERT(RTL_SIZEOF_THROUGH_FIELD(IPV6_OPTION_HEADER, Type) == 1);

        if (OptionHeader->Type == IP6OPT_PAD1) {
            //
            // This is a special pad option which is just a one byte field,
            // i.e. it has no length or data field.
            //
            OptionLength = 1;
        } else {
            //
            // This is a multi-byte option.
            //
            if ((AvailableOptionLength < sizeof(IPV6_OPTION_HEADER)) ||
                (AvailableOptionLength <
                 (sizeof(IPV6_OPTION_HEADER) + OptionHeader->DataLength))) {
                goto BadOptionLength;
            }

            OptionLength =
                sizeof(IPV6_OPTION_HEADER) + OptionHeader->DataLength;
        }
        
        switch(OptionHeader->Type) {
        case IP6OPT_PAD1:
        case IP6OPT_PADN:
            break;

        case IP6OPT_JUMBO:
            if (ReceiveDatagram->NextHeaderValue != IPPROTO_HOPOPTS) {
                goto BadOptionType;
            }

            if (OptionLength != sizeof(IPV6_OPTION_JUMBOGRAM)) {
                goto BadOptionLength;
            }

            if (Control->Jumbogram) {
                //
                // Can only have one Jumbogram option.
                //                
                goto BadOptionType;
            }

            if (((PIPV6_HEADER) Control->IP)->PayloadLength != 0) {
                //
                // Jumbogram option encountered when PayloadLength is not zero.
                //                
                goto BadOptionType;
            }

            Jumbogram =
                NetioGetDataBuffer(
                    NetBuffer,
                    sizeof(IPV6_OPTION_JUMBOGRAM),
                    &JumbogramBuffer,
                    __builtin_alignof(IPV6_OPTION_JUMBOGRAM),
                    0);
            
            JumbogramLength = *((ULONG UNALIGNED *)Jumbogram->JumbogramLength);
            JumbogramLength = RtlUlongByteSwap(JumbogramLength);

            if (JumbogramLength <= MAX_IPV6_PAYLOAD) {
                //
                // Jumbogram length is not jumbo.
                //
                goto BadOptionValue;
            }

            Control->Jumbogram = TRUE;
            
            //
            // Check that the Jumbogram length is big enough to include
            // the extension header length. This must be true because
            // the extension-header length is at most 11 bits,
            // while the Jumbogram length is at least 16 bits.
            //
            ASSERT(JumbogramLength > ExtensionHeaderLength);

            //
            // Check that the amount of payload specified in the jumbogram
            // payload value fits in the buffer handed to us.
            // Note: The Jumbogram length does not include the IPv6
            // header length.  At the same time, we are guaranteed that
            // ReceiveDatagram->NetworkLayerHeadersSize (part of BytesParsed)
            // is equal to sizeof(IPV6_HEADER) (part of JumbogramLength). 
            // So the two cancel each other.
            //
            BytesParsed = ExtensionHeaderLength - AvailableOptionLength;
            if (NetBuffer->DataLength < (JumbogramLength - BytesParsed)) {
                //
                // Silently discard data.
                //
                NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                           "IPNG: Validation of IPv6 packet failed - "
                           "Jumbogram length too big\n");
            
                DiscardReason = IpDiscardBadLength;
                goto BadOptionValue;
            }

            //
            // As in Ipv6pValidateNetBuffer, truncate NetBuffer::DataLength to
            // exactly fit the IPv6 packet (assume excess is media padding).
            //
            NetioTruncateNetBuffer(
                NetBuffer,
                NetBuffer->DataLength - (JumbogramLength - BytesParsed));
            
            break;
            
        case IP6OPT_ROUTER_ALERT:
            if (ReceiveDatagram->NextHeaderValue != IPPROTO_HOPOPTS) {
                goto BadOptionType;
            }
            
            if (OptionLength != sizeof(IPV6_OPTION_ROUTER_ALERT)) {
                goto BadOptionLength;
            }

            if (Control->RouterAlert) {
                //
                // Can only have one router alert option.
                //
                goto BadOptionType;
            }

            Control->RouterAlert = TRUE;
            break;
            
        default:
            //
            // Handle unknown options based on the option type.
            //
            switch (IP6OPT_TYPE(OptionHeader->Type)) {
            case IP6OPT_TYPE_SKIP:
                //
                // Ignore the unrecognized option.
                //
                break;
                
            case IP6OPT_TYPE_DISCARD:
                //
                // Silently discard the packet.
                //
                SendIcmpError = FALSE;                
                IcmpCode = ICMP6_PARAMPROB_OPTION;                
                goto BadOptionType;

            case IP6OPT_TYPE_FORCEICMP:
                //
                // Discard the packet and send an ICMP message.
                //
                MulticastOverride = TRUE;

            case IP6OPT_TYPE_ICMP:
                //
                // Discard the packet and send an ICMP message
                // (if the packet was not destined to a multicast address).
                //
                IcmpCode = ICMP6_PARAMPROB_OPTION;    
                goto BadOptionType;
            }
        }

        NetioAdvanceNetBuffer(NetBuffer, OptionLength);
        AvailableOptionLength -= OptionLength;
    }

    ASSERT(AvailableOptionLength == 0);
    ReceiveDatagram->NetworkLayerHeadersSize += ExtensionHeaderLength;
    ReceiveDatagram->NextHeaderValue  = ExtensionHeader->NextHeader;
    return IpDiscardReceivePathMax;
    
BadOptionValue:
    NetioAdvanceNetBuffer(NetBuffer, sizeof(UINT8));
    AvailableOptionLength -= sizeof(UINT8);
    
BadOptionLength:
    NetioAdvanceNetBuffer(NetBuffer, sizeof(UINT8));
    AvailableOptionLength -= sizeof(UINT8);

BadOptionType:
    BytesParsed = ExtensionHeaderLength - AvailableOptionLength;
    ReceiveDatagram->NetworkLayerHeadersSize += BytesParsed;
    ErrorOffset = ReceiveDatagram->NetworkLayerHeadersSize;
    
BadHeader:
    ReceiveDatagram->NextHeaderValue = IPPROTO_NONE;
    Control->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
               "IPNG: Validation of IPv6 packet failed : "
               "Bad hop-by-hop options\n");

    if ((IppDiscardReceivedPackets(
            &Ipv6Global, 
            DiscardReason,
            Control, 
            NULL,
            NULL) == IpDiscardAllowIcmp) &&
        SendIcmpError) {
        IppSendErrorList(
            TRUE,
            &Ipv6Global,
            Control,
            ICMP6_PARAM_PROB,
            IcmpCode,
            RtlUlongByteSwap(ErrorOffset),
            MulticastOverride);
    }

    return DiscardReason;
}


NTSTATUS
Ipv6pValidateNetBuffer(
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN PNDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo
    )
/*++

Routine Description:

    Validate and process an IPv6 header.
    Retrieve pointers to source and destination addresses and the IPv6 header.

    This is the equivalent of IPv6HeaderReceive() in XP.

Arguments:

    Control - Supplies a packet to validate.
        Returns the source and destination addresses and the IPv6 header.
    
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
    PIPV6_HEADER Header;
    ULONG PacketLength;
    PUCHAR SourceAddress, DestinationAddress;
    IP_DISCARD_REASON DiscardReason;
    UINT32 VersionClassFlow;
    
    UNREFERENCED_PARAMETER(ChecksumInfo);

    //
    // Ensure we have enough bytes for an IPv6 header.
    //
    if (NetBuffer->DataLength < sizeof(IPV6_HEADER)) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv6 packet failed - "
                   "Packet too small (%d bytes) to contain IPv6 header\n",
                   NetBuffer->DataLength);

        (VOID) IppDiscardReceivedPackets(
                   &Ipv6Global, 
                   IpDiscardBadLength,
                   NULL, 
                   Control->SourceSubInterface, 
                   NetBufferList);
        
        return (NetBufferList->Status = STATUS_BUFFER_TOO_SMALL);
    }

    //
    // The FL provider and lower layers guarantee that the IPv6 header is in
    // contiguous memory, so we don't need any local storage space and this
    // call should always succeed.  They also guarantees 2-byte alignment.
    // However, that means that any accesses to the 4-byte VersionClassFlow
    // field must be unaligned.
    //
    Header = NetioGetDataBufferSafe(NetBuffer, sizeof(IPV6_HEADER));
    ASSERT(Header != NULL);

    //
    // Copy out the Version, Class & Flow fields of the header for alignment.
    //
    VersionClassFlow = ((UNALIGNED IPV6_HEADER *) Header)->VersionClassFlow;
    
    // 
    // Check if the IP version is correct.
    // We specifically do NOT check HopLimit.
    // HopLimit is only checked when forwarding.
    //
    if ((VersionClassFlow & IP_VER_MASK) != IPV6_VERSION) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv6 packet failed - "
                   "Bad version (%d)\n",
                   (((UNALIGNED IPV6_HEADER *) Header)->VersionClassFlow &
                    IP_VER_MASK));

        (VOID) IppDiscardReceivedPackets(
                   &Ipv6Global,
                   IpDiscardMalformedHeader,
                   NULL,             
                   Control->SourceSubInterface, 
                   NetBufferList);        
        
        return (NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED);
    }

    //
    // Copy out the ECN Field into the receive datagram for use by TL.
    //
    ((PNETIO_NET_BUFFER_CONTEXT) 
        NET_BUFFER_PROTOCOL_RESERVED(NetBuffer))->EcnField = 
        ((VersionClassFlow & IPV6_ECN_MASK) >> IPV6_ECN_SHIFT);
    
    //
    // We use a separate pointer to refer to the source and destination
    // addresses so that later options can change them.
    //
    Control->IP = (PUCHAR) Header;

    Control->CurrentDestinationAddress = DestinationAddress = 
        (PUCHAR) &Header->DestinationAddress;
    Control->CurrentDestinationType =
        Ipv6AddressType(DestinationAddress);

    Control->SourceAddress.Address = SourceAddress = 
        (PUCHAR) &Header->SourceAddress;

    //
    // Protect against attacks that use bogus source addresses.
    //
    if (IppIsInvalidSourceAddress(&Ipv6Global, SourceAddress) ||
        IN6_IS_ADDR_LOOPBACK((PIN6_ADDR) SourceAddress)) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv6 packet failed - "
                   "Bad source address\n");
        DiscardReason = IpDiscardBadSourceAddress;
        NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Discard;
    }

    //
    // Disallow interface local scope addresses. 
    // Note that only multicast addresses can be interface local scoped.
    //
    if ((Control->CurrentDestinationType == NlatMulticast) &&
        IN6_MULTICAST_SCOPE(DestinationAddress) < ScopeLevelLink) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv6 packet failed - "
                   "Bad destination address\n");
        DiscardReason = IpDiscardBeyondScope;
        NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        goto Discard;
    }
    
    //
    // Before processing any headers, including HopByHop,
    // check that the amount of payload the IPv6 header thinks is present
    // can actually fit inside the packet data area that the link handed us.
    // Note that a Payload Length of zero *might* mean a Jumbogram option.
    //
    PacketLength =
        sizeof(IPV6_HEADER) + RtlUshortByteSwap((USHORT)Header->PayloadLength);

    if (NetBuffer->DataLength < PacketLength) {
        //
        // Silently discard the packet.
        //
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Validation of IPv6 packet failed - "
                   "Length in header (%d) greater than actual length (%d)\n",
                   PacketLength, NetBuffer->DataLength);
        DiscardReason = IpDiscardBadLength;
        NetBufferList->Status = STATUS_BUFFER_TOO_SMALL;
        goto Discard;
    } 

    if (Header->NextHeader == IPPROTO_HOPOPTS) {
        ReceiveDatagram->NextHeaderValue = IPPROTO_HOPOPTS;
        
        //
        // If the HopByHop options header has a Jumbogram option,
        // Ipv6pProcessOptions will truncate NetBuffer::DataLength.  Otherwise
        // take care of it now, before processing the HopByHop options header.
        //
        if (PacketLength != sizeof(IPV6_HEADER)) {
            NetioTruncateNetBuffer(
                NetBuffer, NetBuffer->DataLength - PacketLength);
        }
        
        //
        // Parse the HopByHop options header.
        //
        ReceiveDatagram->NetworkLayerHeadersSize += sizeof(IPV6_HEADER);
        NetioAdvanceNetBuffer(
            NetBuffer, ReceiveDatagram->NetworkLayerHeadersSize);

        DiscardReason = Ipv6pProcessOptions(Control);

        NetioRetreatNetBuffer(
            NetBuffer, ReceiveDatagram->NetworkLayerHeadersSize, 0);
        ReceiveDatagram->NetworkLayerHeadersSize -= sizeof(IPV6_HEADER);

        if (DiscardReason != IpDiscardReceivePathMax) {
            //
            // The packet had bad Hop-by-Hop Options.  Drop it.
            // Ipv6pProcessOptions would have called IppDiscardReceivedPackets.
            //
            ASSERT(NetBufferList->Status == STATUS_DATA_NOT_ACCEPTED);
            return STATUS_DATA_NOT_ACCEPTED;
        }

        if ((PacketLength == sizeof(IPV6_HEADER)) && !Control->Jumbogram) {
            //
            // We should have a Jumbogram option,
            // but we didn't find it. Send an ICMP error if allowed.
            //
            if (IppDiscardReceivedPackets(
                   &Ipv6Global, 
                   IpDiscardBadLength,
                   Control, 
                   NULL,
                   NULL) == IpDiscardAllowIcmp) {
                IppSendErrorList(
                    TRUE,
                    &Ipv6Global,
                    Control,
                    ICMP6_PARAM_PROB,
                    ICMP6_PARAMPROB_HEADER,
                    RtlUlongByteSwap(FIELD_OFFSET(IPV6_HEADER, PayloadLength)),
                    FALSE);
            }                
            NetBufferList->Status = STATUS_BUFFER_TOO_SMALL;
            return STATUS_BUFFER_TOO_SMALL;
        }        
    } else {
        //
        // Truncate NetBuffer::DataLength.
        //
        NetioTruncateNetBuffer(
            NetBuffer, NetBuffer->DataLength - PacketLength);
    }

    return STATUS_SUCCESS;

Discard:
    {
        NTSTATUS Status = NetBufferList->Status;        

        //
        // Silently discard the packet.
        //
        (VOID) IppDiscardReceivedPackets(
                   &Ipv6Global, 
                   DiscardReason,
                   Control, 
                   NULL,
                   NULL);
        
        return Status;
    }
}
