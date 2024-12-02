/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    send.c

Abstract:

    This module implements the functions of the IPv4 Fragmenter module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "send.tmh"

NETIO_INLINE
VOID
Ipv4pZeroPacketChecksum(
    IN PNET_BUFFER Packet
)
/*++

Routine Description:

    Zeros the checksum in the IP Header.

Arguments:

    Packet - The net buffer containing the IPV4_HEADER.

Return Value:

    None

--*/
{
    IPV4_HEADER *Header;
   
    Header = NetioGetDataBufferSafe(Packet, sizeof(IPV4_HEADER));
    ASSERT(Header != NULL);
    //
    // zero the checksum field.
    //
    Header->HeaderChecksum = 0;
}

NETIO_INLINE
VOID
Ipv4pFillPacketChecksum(
    IN PNET_BUFFER Packet
    )
/*++

Routine Description:

    Computes the checksum for an IPV4 packet and fills in the header.

Arguments:

    Packet - The net buffer containing the IPV4_HEADER.

Return Value:

    None

--*/
{
    IPV4_HEADER *Header;
    ULONG HeaderBytes;
    ULONG Checksum; 
   
    Header = NetioGetDataBufferSafe(Packet, sizeof(IPV4_HEADER));
    ASSERT(Header != NULL);
    HeaderBytes = Ip4HeaderLengthInBytes(Header);

    if (HeaderBytes > sizeof(IPV4_HEADER)) {
        Header = NetioGetDataBufferSafe(Packet, HeaderBytes);
    }
    
    //
    // Recompute the checksum as appropriate - zero the checksum field first.
    //
    Header->HeaderChecksum = 0;
        
    Checksum = IppChecksum(Header, HeaderBytes);
    Checksum = (Checksum >> 16) + (Checksum & 0xffff);
    Checksum += (Checksum >> 16);
    
    //
    // Take ones-complement and replace 0 with 0xffff.
    //
    if (Checksum != 0xffff) {
        Checksum = (UINT16) ~Checksum;
    }
    
    Header->HeaderChecksum = (UINT16) Checksum;
}

VOID
IppInspectFillIpv4PacketChecksum(
    IN PNET_BUFFER Packet
    )
{
    Ipv4pFillPacketChecksum(Packet);
}

NETIO_INLINE
VOID
Ipv4pChecksumPacket(
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_REQUEST_CONTROL_DATA ControlData
    )
/*++

Routine Description:

    This function will check for checksum offload flag and if checksum can 
    not be offloaded, compute the checksum for the packet list. This routine is
    only called for packets going out on an interface.

Arguments:

    SubInterface - Pointer to sub interface on which we are going to send out 
        the packets.

    ControlData - Pointer to IP_REQUEST_CONTROL_DATA structure.

Return Value:

    None.

Caller IRQLs: <= DISPATCH_LEVEL.    

--*/
{
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo;
    PIPV4_HEADER Header;
    PNET_BUFFER NetBuffer;
    
    if (SubInterface->Interface->TransmitOffload.NlChecksumSupported && 
        !ControlData->Flags.UseIpSec &&
        (ControlData->Path != NULL)) {
        ChecksumInfo.Value = (ULONG)(ULONG_PTR)
            NET_BUFFER_LIST_INFO(
                ControlData->NetBufferList,
                TcpIpChecksumNetBufferListInfo);

        Header = 
            NetioGetDataBufferSafe(
                ControlData->NetBufferList->FirstNetBuffer,
                sizeof(IPV4_HEADER));

        //
        // Checksum can be offloaded only if there are no options in the packet
        // or there are options and the interface supports IP header checksum
        // offload with options.
        //
        if ((Header->VersionAndHeaderLength == IPV4_DEFAULT_VERHLEN) ||
            SubInterface->Interface->TransmitOffload.NlOptionsSupported) {
            
            ChecksumInfo.Transmit.NdisPacketChecksumV4 = TRUE;
            ChecksumInfo.Transmit.NdisPacketIpChecksum = TRUE;

            //
            // Zero the checksum
            //
            for (NetBuffer = ControlData->NetBufferList->FirstNetBuffer;
                NetBuffer != NULL;
                NetBuffer = NetBuffer->Next) {
                Ipv4pZeroPacketChecksum(NetBuffer);
            }
            
            NET_BUFFER_LIST_INFO(
                ControlData->NetBufferList,
                TcpIpChecksumNetBufferListInfo) =
                (PVOID) (ULONG_PTR) ChecksumInfo.Value;
            return;
        }
    }
    
    //
    // Compute the checksum for the packet list.
    //
    for (NetBuffer = ControlData->NetBufferList->FirstNetBuffer;
        NetBuffer != NULL;
        NetBuffer = NetBuffer->Next) {
        Ipv4pFillPacketChecksum(NetBuffer);
    }
}

ULONG
Ipv4pCompactFragmentationHeader(
    IN IPV4_HEADER *IpHeader,
    OUT IPV4_HEADER *FragmentHeader
    )
/*++
  
Routine Description:

    This routine takes an IP header including options and creates an IP header
    where only the options that need to be duplicated on fragmentation are
    duplicated.

Arguments:

    IpHeader - Supplies the original IP header to compact down. If any options
        follow it is expected to be contiguous.

    FragmentHeader - Returns a new IP header where any options have been
        compacted down. Note that the memory pointed to by FragmentHeader must
        be big enough to accomodate the largest v4 header and allocated by the
        caller before calling.

Return Value:

    Returns the number of bytes in the IPV4 header including options.

--*/
{
    PIPV4_OPTION_HEADER OptionHeader;
    ULONG OptionLength;
    ULONG Offset = sizeof(IPV4_HEADER);
    ULONG PaddingLength;
    
    OptionLength = Ip4HeaderLengthInBytes(IpHeader) - sizeof(IPV4_HEADER);
    RtlCopyMemory(FragmentHeader, IpHeader, sizeof(IPV4_HEADER));
    
    if (IpHeader->VersionAndHeaderLength == IPV4_DEFAULT_VERHLEN) {
        return Ip4HeaderLengthInBytes(FragmentHeader);
    }

    //
    // Walk the list of options and check which ones really need to be copied.
    //
    OptionHeader = (PIPV4_OPTION_HEADER) (IpHeader + 1);
    
    while (OptionLength > 0) {
        if (OptionHeader->CopiedFlag == 1) {
            //
            // Option must be copied for all fragment headers.
            //
            RtlCopyMemory(((PUCHAR) FragmentHeader) + Offset,
                          OptionHeader,
                          OptionHeader->OptionLength);
            Offset += OptionHeader->OptionLength;
        }

        if (OptionHeader->OptionType == IP_OPT_EOL) {
            break;
        }
        if (OptionHeader->OptionType == IP_OPT_NOP) {
            OptionLength--;
            OptionHeader = (PIPV4_OPTION_HEADER) (((PUCHAR) OptionHeader) + 1);
            continue;
        }
        
        OptionLength -= OptionHeader->OptionLength;
        OptionHeader = (PIPV4_OPTION_HEADER) 
            (((PUCHAR) OptionHeader) + OptionHeader->OptionLength);
    }

    //
    // Options must be aligned on a 32 bit boundary. Move offset to accomodate
    // the padding.
    //
    PaddingLength = (4 - (Offset & 0x3)) & 0x3;

    if (PaddingLength != 0) {
        RtlZeroMemory(((PUCHAR) FragmentHeader) + Offset, PaddingLength);
        Offset += PaddingLength;
    }
    FragmentHeader->HeaderLength = Offset >> 2;
    
    return Offset;
}


VOID
Ipv4pFragmentPacketHelper(
    IN PIP_REQUEST_CONTROL_DATA Args,
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    Compare IPv6SendFragments in the XP IPv6 stack. This routine is where the
    checksum computation is performed.

Arguments:

    Args - Supplies a list of packets to send.

    SubInterface - Supplies the sub-interface on which the packet is going
        out. 

Return Value:

    Args->NetBufferList can be NULL on return.  If it's not, then the
    status is returned in Args->NetBufferList->Status:

    STATUS_SUCCESS - Caller should continue to send.
    STATUS_DATA_NOT_ACCEPTED,
    STATUS_INVALID_BUFFER_SIZE,
    STATUS_INSUFFICIENT_RESOURCES - Caller should drop.

--*/
{
    IP_FILTER_ACTION Action;
    PNET_BUFFER_LIST BufferList = Args->NetBufferList;
    ULONG Mtu;
    PNET_BUFFER Buffer;
    PIP_INTERFACE Interface;
    PIPV4_HEADER Ip;
        
    Interface = SubInterface->Interface;

    //
    // Check if fragmentation is needed.
    //
    if (!Args->IsOriginLocal) {
        Buffer = BufferList->FirstNetBuffer;
        ASSERT(Buffer->Next == NULL);
        ASSERT(PtrToUlong(NET_BUFFER_LIST_INFO(
                            BufferList, TcpLargeSendPacketInfo)) == 0);

        //
        // Check that the packet is not too big for the outgoing link.
        // Note that NlMtu is volatile, so we capture
        // it in a local variable for consistency.
        //
        Mtu = SubInterface->NlMtu;
        if (Buffer->DataLength <= Mtu) {
            //
            // The hop limit might have been modified.  But the checksum is
            // modified in place.  So, there is no need to re-compute the
            // checksum. 
            //
            goto Done;
        } else if (!((PIPV4_HEADER)Args->IP)->DontFragment) {
            goto Fragment;
        } else {
            BufferList->Status = STATUS_INVALID_BUFFER_SIZE;
            
            Interface->Compartment->Protocol->
                PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                OutDiscards += IppGetPacketCount(BufferList);
            
            //
            // Send ICMP packet too big error.
            //
            // Note that MulticastOverride is FALSE, since IPv4 does not 
            // support Path MTU Discovery for multicast. Also, this does
            // not consume the packet (IP_REQUEST_CONTROL_DATA). It might
            // consume the net buffer list in which case the NetBufferList
            // pointer is set to NULL.  
            //
            IppSendErrorList(
                FALSE,
                &Ipv4Global,
                Args,
                ICMP4_DST_UNREACH,
                ICMP4_UNREACH_FRAG_NEEDED,
                RtlUlongByteSwap(Mtu),
                FALSE);
            return;
        } 
    } else {

        if (Args->Path == NULL) {
            Mtu = SubInterface->NlMtu;
        } else {
            Mtu = Args->Path->PathMtu;
        }

        Action = IppInspectLocalPacketsOut(
            IPPROTO_IP, 
            (PNL_LOCAL_ADDRESS) Args->SourceLocalAddress,
            Args->FinalDestinationAddress.Buffer,
            Args->CurrentDestinationType,
            (PNL_INTERFACE) Interface,
            SubInterface->Index,
            FALSE,
            Args->DestinationProtocol,
            Args->IpHeaderAndExtensionHeadersLength,
            Mtu,
            Args->Flags.DontFragment,
            &Args->TransportData,
            Args->TransportHeaderLength,
            BufferList);
        if (Action >= IpFilterDrop) {       
            if ((Action == IpFilterDrop) || (Action == IpFilterDropAndSendIcmp)) {
                Ipv4Global.
                    PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                    OutFilterDrops += IppGetPacketCount(BufferList);
                
                Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            } else {
                ASSERT(Action == IpFilterAbsorb);
                NetioDereferenceNetBufferList(Args->NetBufferList, FALSE);
                Args->NetBufferList = NULL;
            }
            return;            
        }
        ASSERT(Action == IpFilterAllow);

        if (PtrToUlong(NET_BUFFER_LIST_INFO(
                           BufferList, TcpLargeSendPacketInfo)) != 0) {
            goto Done;
        }

        if (Args->Path == NULL) {
            Mtu = SubInterface->NlMtu;
        } else {
            Mtu = Ipv4pGetMtuFromPath(
                Args->Path, 
                Args->Path->SourceAddress->Interface, 
                SubInterface);
        }
    
        for (Buffer = BufferList->FirstNetBuffer;
             Buffer != NULL;
             Buffer = Buffer->Next) {
            if (Buffer->DataLength > Mtu) {
                if (!Args->Flags.DontFragment) {
                    goto Fragment;
                } else {
                    BufferList->Status = STATUS_INVALID_BUFFER_SIZE;
                    
                    Interface->Compartment->Protocol->PerProcessorStatistics[
                        KeGetCurrentProcessorNumber()].OutDiscards +=
                        IppGetPacketCount(BufferList);
					
                    IpSecCleanupSessionInformation(BufferList);
                    return;
                }                    
            }
        }
        
        goto FillChecksum;
    }

    {
        PNET_BUFFER_LIST NewNbl;
        PNET_BUFFER NewNb;
        UINT16 FragmentOffset;
        UINT16 OriginalFragmentOffset;
        UINT16 FragmentSize;
        ULONG UnfragmentableBytes;
        IPV4_HEADER UNALIGNED *NewIpHeader;
        PUCHAR NewHeader;
        USHORT BytesSent, BytesLeft;
        PIP_SUBINTERFACE_STATISTICS SubInterfaceStats;
        PIP_GLOBAL_STATISTICS GlobalStats;
        ULONG Processor;
        ULONG PacketCount, FragmentHeaderLength;
        UCHAR IpHeader[MAX_IPV4_HLEN];
        //
        // FragmentHeader is defined as a union to force alignment.
        //
        union {
            IPV4_HEADER IpHeader;
            UCHAR Buffer[MAX_IPV4_HLEN];
        } FragmentHeader;

Fragment:
        Processor = KeGetCurrentProcessorNumber();
        SubInterfaceStats = SubInterface->
            PerProcessorStatistics[Processor];
        GlobalStats = &Interface->Compartment->Protocol->
            PerProcessorStatistics[Processor];

        //
        // Determine the 'unfragmentable' portion of this packet.
        // Unfragmentable portion is just the IPv4 header plus options.  We
        // assume that all the net buffers in the net buffer list have the same
        // unfragmentable data.  So, it suffices to look at just the first
        // one. 
        //
        Buffer = BufferList->FirstNetBuffer;
        Ip = NetioGetDataBufferSafe(Buffer, sizeof(IPV4_HEADER));
        UnfragmentableBytes = (ULONG) Ip4HeaderLengthInBytes(Ip);

        //
        // Check that we can actually fragment this packet.
        // If the unfragmentable part is too large, we can't.
        // We need to send at least 8 bytes of fragmentable data
        // in each fragment.
        //
        if ((UnfragmentableBytes + 8) > Mtu) {
            goto FragmentFail;
        }

        //
        // Fragment size must be a multiple of 8.
        //
        FragmentSize = (UINT16)
            ((Mtu - UnfragmentableBytes) & ~7);

        //
        // Create fragments and allocate space.
        //
        NewNbl = NetioAllocateAndReferenceFragmentNetBufferList(
                     BufferList,
                     UnfragmentableBytes,
                     FragmentSize,
                     UnfragmentableBytes,
                     Interface->FlBackfill,
                     FALSE);
           
        if (NewNbl == NULL) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                       "IPNG: Error allocating IPv4 fragment\n");
FragmentFail:
            BufferList->Status = STATUS_INSUFFICIENT_RESOURCES; 
            PacketCount = IppGetPacketCount(BufferList);
            SubInterfaceStats->FragmentFailures += PacketCount;
            GlobalStats->FragmentFailures += PacketCount;
			
            IpSecCleanupSessionInformation(BufferList);
            return;            
        }

        //
        // Undo the retreats since some buffers might not need
        // a Fragment Header.  We want to use the "receive" versions
        // now since we don't want to allocate/deallocate anything.
        //
        NetioAdvanceNetBufferList(NewNbl, (USHORT) UnfragmentableBytes);

        //
        // Now go over each net buffer in the original net buffer list.  For
        // each net buffer in the original list, traverse the net buffers in
        // the fragmented net buffer list until we fill in all the data.  For
        // net buffers that are not fragmented, we end up traversing just one
        // net buffer in the new list. 
        //
        for (NewNb = NewNbl->FirstNetBuffer, 
             Buffer = BufferList->FirstNetBuffer;
             Buffer != NULL; 
             Buffer = Buffer->Next) {
            //
            // Not all options need to be copied on fragmentation.
            // Create a local copy of the IP header with options
            // trimmed for fragmented packets. This only gets created
            // once for each packet that needs fragmentation. Next time
            // we traverse this loop, the fragmentation information
            // will be picked up and used.
            //
            Ip = NetioGetDataBuffer(Buffer,
                                    UnfragmentableBytes,
                    IpHeader,
                    1,
                    0);
            FragmentHeaderLength = Ipv4pCompactFragmentationHeader(
                    Ip,
                    &FragmentHeader.IpHeader);

            //
            // Clear any existing fragment offset which may be set if this is a
            // fragment of a fragment.
            //
            FragmentHeader.IpHeader.FlagsAndOffset &= ~IP4_OFF_MASK;
            
            //
            // FragmentOffset is relative to fragmentable part of original 
            // packet and includes any existing offset in case we are
            // fragmenting a fragment.
            //
            FragmentOffset = OriginalFragmentOffset = Ip4FragmentOffset(Ip);
            BytesLeft = Buffer->DataLength - UnfragmentableBytes;

            for (; BytesLeft > 0; NewNb = NewNb->Next) {
                ASSERT(NewNb != NULL);
                ASSERT(NewNb->DataLength <= MAX_IPV4_PACKET);
                BytesSent = (USHORT)NewNb->DataLength;
                ASSERT(BytesSent <= BytesLeft);
            
                //
                // Copy unfragmentable bytes.  For the first fragment, this is
                // the complete IP header + options.  For subsequent fragments,
                // we use the compact header.  Note that the complete IP header
                // (including options) is guaranteed to be contiguous in the
                // new net buffer list.
                //
                if (FragmentOffset == OriginalFragmentOffset) {
                    NetioRetreatNetBuffer(NewNb, UnfragmentableBytes, 0);
                    NewHeader = 
                        NetioGetDataBufferSafe(NewNb, UnfragmentableBytes);
                    RtlCopyMemory(NewHeader, Ip, UnfragmentableBytes);
                } else {
                    NetioRetreatNetBuffer(NewNb, FragmentHeaderLength, 0);
                    NewHeader = 
                        NetioGetDataBufferSafe(NewNb, FragmentHeaderLength);
                    RtlCopyMemory(
                        NewHeader, FragmentHeader.Buffer, FragmentHeaderLength);
                }
                            
                if (Buffer->DataLength - UnfragmentableBytes > FragmentSize) {
                    //
                    // Correct the TotalLength, fragmentation data in case the
                    // net buffer needs fragmentation.
                    //
                    NewIpHeader = (IPV4_HEADER UNALIGNED *) NewHeader;
                    NewIpHeader->TotalLength = 
                        RtlUshortByteSwap(NewNb->DataLength);
                    NewIpHeader->FlagsAndOffset |= 
                        RtlUshortByteSwap(FragmentOffset >> 3) & IP4_OFF_MASK;

                    //
                    // If the MF bit was set on the original packet all
                    // fragments, including the last fragment, must have it
                    // set. Otherwise set it only if this is not the last
                    // fragment of the packet. This is necessary to enable
                    // proper reassembly of fragments of a fragment.
                    //
                    NewIpHeader->MoreFragments |= (BytesLeft != BytesSent);
                }
                
                FragmentOffset += BytesSent;
                BytesLeft -= BytesSent;
            }
        }
        
        ASSERT(Buffer == NULL);

        //
        // TODO: This is counting the total number of packets in the net buffer
        // list, some of which might not be undergoing fragmentations.  We
        // should just count packes that are fragmented. 
        //
        PacketCount = IppGetPacketCount(BufferList);
        SubInterfaceStats->FragmentOks += PacketCount;
        GlobalStats->FragmentOks += PacketCount;

        //
        // Even though fragments may be absorbed by IPSec and 
        // not sent in plain text, we probably should count them, 
        // because we performed fragmentation.
        //
        PacketCount = IppGetPacketCount(NewNbl);
        SubInterfaceStats->FragmentsCreated += PacketCount;
        GlobalStats->FragmentsCreated += PacketCount;

        Action = IPsecProcessOutboundFragList(IPPROTO_IP, BufferList, NewNbl);
        if (Action >= IpFilterDrop) {       
            ASSERT(Action == IpFilterAbsorb);
            NetioDereferenceNetBufferList(BufferList, FALSE);
            NetioDereferenceNetBufferList(NewNbl, FALSE);			
            Args->NetBufferList = NULL;
            return;            
        }

        ASSERT(Action == IpFilterAllow);

        //
        // We are replacing the net buffer list in the args
        // structure. Dereference the old net buffer list. 
        //
        NetioDereferenceNetBufferList(BufferList, FALSE);
        Args->NetBufferList = NewNbl;
    }

FillChecksum:
    Ipv4pChecksumPacket(SubInterface, Args);

Done:
    Args->NetBufferList->Status = STATUS_SUCCESS;

    IpSecCleanupSessionInformation(Args->NetBufferList);
}
