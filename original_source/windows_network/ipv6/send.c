/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    send.c

Abstract:

    This module implements the functions of the IPv6 Fragmenter module.

Author:

    Dave Thaler (dthaler) 7-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "send.tmh"


__inline
ULONG
Ipv6pGenerateFragmentId(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
    
    Generate a unique fragment identifier for the interface.

Arguments:

    Interface - Supplies the interface.
    
Return Value:

    Returns a fragment identifier in network byte order. The host stack uses 
    only the bottom half of the fragment Id space.

Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ULONG FragmentId;

    FragmentId = InterlockedExchangeAdd(&Interface->FragmentId, 1);
    return RtlUlongByteSwap(0x7FFFFFFF & FragmentId);
}


VOID
Ipv6pFragmentPacketHelper(
    IN PIP_REQUEST_CONTROL_DATA Args,
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    Compare IPv6SendFragments in the XP IPv6 stack.

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
    BOOLEAN ForceFragment = FALSE;
    PIP_INTERFACE Interface;
    PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO NblInfo;

    Interface = SubInterface->Interface;
    
    //
    // Check if fragmentation is needed.
    //
    if (!Args->IsOriginLocal) {
        Buffer = BufferList->FirstNetBuffer;
        ASSERT(Buffer->Next == NULL);
        ASSERT(NET_BUFFER_LIST_INFO(BufferList, TcpLargeSendPacketInfo) == 0);

        //
        // Check that the packet is not too big for the outgoing link.
        // Note that NlMtu is volatile, so we capture
        // it in a local variable for consistency.
        //
        Mtu = SubInterface->NlMtu;
        if (Buffer->DataLength <= Mtu) {
            goto Done;
        } 
        
        //
        // IPv6 doesn't allow fragmentation in the forwarding path.
        //
        BufferList->Status = STATUS_INVALID_BUFFER_SIZE;
        
        Interface->Compartment->Protocol->
            PerProcessorStatistics[KeGetCurrentProcessorNumber()].
            OutDiscards += IppGetPacketCount(BufferList);
        
        //
        // This does not consume the packet (IP_REQUEST_CONTROL_DATA).
        // It might consume the net buffer list in which case the
        // NetBufferList pointer is set to NULL.
        //
        IppSendErrorList(
            FALSE, 
            &Ipv6Global,
            Args,
            ICMP6_PACKET_TOO_BIG,
            0,
            RtlUlongByteSwap(Mtu),
            TRUE);
        return;
    } else {

        if (Args->Path == NULL) {
            Mtu = SubInterface->NlMtu;
        } else {
            Mtu = Args->Path->PathMtu;
        }

        Action = IppInspectLocalPacketsOut(
            IPPROTO_IPV6, 
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
                Ipv6Global.
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
        
        if (Args->Path == NULL) {
            Mtu = SubInterface->NlMtu;
        } else {
            Mtu = Ipv6pGetMtuFromPath(
                Args->Path, 
                Args->Path->SourceAddress->Interface,
                SubInterface);
            
            ForceFragment = Args->Path->Flags.ForceFragment;
        }
        
        if (ForceFragment) {
            goto Fragment;
        } else {
            //
            // For GSO packet, we only need to append fragmentation header iff
            // ForceFragment is set to TRUE.
            //
            if (NET_BUFFER_LIST_INFO(BufferList, TcpLargeSendPacketInfo) != 0) {
                goto Done;
            }
            // 
            // Determine if there is at least one NetBuffer that requires
            // fragmentation, and fragment packets if allowed.
            //
            for (Buffer = BufferList->FirstNetBuffer;
                 Buffer != NULL;
                 Buffer = Buffer->Next) {
                if (Buffer->DataLength > Mtu) {
                    if (!Args->Flags.DontFragment) {
                        goto Fragment;
                    } else {
                        BufferList->Status = STATUS_INVALID_BUFFER_SIZE;
                        
                        Interface->Compartment->Protocol->
                            PerProcessorStatistics[
                            KeGetCurrentProcessorNumber()].OutDiscards +=
                            IppGetPacketCount(BufferList);

                        IpSecCleanupSessionInformation(BufferList);
                        return;
                    }                        
                }
            }
        }
        goto Done;
    }
    
    {
        PNET_BUFFER_LIST NewNbl;
        PNET_BUFFER NewNb;
        ULONG StartOffset;
        PIPV6_FRAGMENT_HEADER FragmentHeader;
        PIPV6_HEADER Ip;
        ULONG FragmentOffset;
        ULONG FragmentSize;
        ULONG DataOffsetDelta;
        USHORT UnfragmentableBytes;
        UINT8 HeaderType;
        ULONG NextHeaderOffset;
        USHORT AdvancedBytes;
        ULONG FragmentPayloadLength;
        PUCHAR Data;
        USHORT BytesSent, BytesLeft;
        SIZE_T BytesCopied;
        PIP_SUBINTERFACE_STATISTICS SubInterfaceStats;
        PIP_GLOBAL_STATISTICS GlobalStats;
        IPV6_HEADER IpStorage;
        ULONG Processor;
        ULONG PacketCount;
        ULONG FragmentId;

Fragment:
        Processor = KeGetCurrentProcessorNumber();
        SubInterfaceStats = SubInterface->
            PerProcessorStatistics[Processor];
        GlobalStats = &Interface->Compartment->Protocol->
            PerProcessorStatistics[Processor];

        PacketCount = IppGetPacketCount(BufferList);

        if (BufferList->FirstNetBuffer->DataLength - sizeof(IPV6_HEADER) >=
            MAX_IPV6_PAYLOAD) {
            BufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            GlobalStats->OutDiscards += PacketCount;

            IpSecCleanupSessionInformation(BufferList);
            return;
        }
        
        FragmentHeader = NULL;

        //
        // Determine the 'unfragmentable' portion of this packet.
        // We do this by scanning through all extension headers,
        // and noting the last occurrence, if any, of
        // a routing or hop-by-hop header.
        // We do not assume the extension headers are in recommended order,
        // but otherwise we assume that the headers are well-formed.
        //
        Buffer = BufferList->FirstNetBuffer;
        Ip = NetioGetDataBuffer(Buffer, 
                                sizeof(IPV6_HEADER), 
                                &IpStorage, 
                                1,
                                0);

        UnfragmentableBytes = sizeof(IPV6_HEADER);
        HeaderType = Ip->NextHeader;
        NextHeaderOffset = FIELD_OFFSET(IPV6_HEADER, NextHeader);

        NetioAdvanceNetBuffer(Buffer, sizeof(IPV6_HEADER));
        AdvancedBytes = sizeof(IPV6_HEADER);

        while ((HeaderType == IPPROTO_HOPOPTS) ||
               (HeaderType == IPPROTO_ROUTING) ||
               (HeaderType == IPPROTO_DSTOPTS)) {
            IPV6_EXTENSION_HEADER EHdrBuffer, *EHdr;
            USHORT Length;

            EHdr = (PIPV6_EXTENSION_HEADER)NetioGetDataBuffer(
                                               Buffer,
                                               sizeof(*EHdr),
                                               &EHdrBuffer,
                                               1,
                                               0);
            
            Length = (EHdr->Length + 1) * 8;
            NetioAdvanceNetBuffer(Buffer, Length);
            AdvancedBytes += Length;

            if (HeaderType != IPPROTO_DSTOPTS) {
                UnfragmentableBytes = AdvancedBytes;
                NextHeaderOffset = AdvancedBytes - Length +
                                   FIELD_OFFSET(IPV6_EXTENSION_HEADER, 
                                                NextHeader);
            }
            HeaderType = EHdr->NextHeader;
        }
        NetioRetreatNetBuffer(Buffer, AdvancedBytes, 0);

        //
        // Check that we can actually fragment this packet.
        // If the unfragmentable part is too large, we can't.
        // We need to send at least 8 bytes of fragmentable data
        // in each fragment.
        //
        DataOffsetDelta = UnfragmentableBytes + sizeof(IPV6_FRAGMENT_HEADER);
        if (DataOffsetDelta + 8 > Mtu) {
            goto FragmentFail;
        }
        StartOffset = UnfragmentableBytes;

        //
        // Fragment size must be a multiple of 8.
        //
        if (NET_BUFFER_LIST_INFO(BufferList, TcpLargeSendPacketInfo) == 0) {
            FragmentSize = (UINT16)((Mtu - StartOffset - 
                                     sizeof(IPV6_FRAGMENT_HEADER)) & ~7);
        } else {
            FragmentSize = Buffer->DataLength;
        }

        //
        // Create fragments and allocate space.
        //
        NewNbl = NetioAllocateAndReferenceFragmentNetBufferList(
                    BufferList,
                    StartOffset, 
                    FragmentSize,
                    DataOffsetDelta,
                    Interface->FlBackfill,
                    FALSE);

        if (NewNbl == NULL) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                       "IPNG: Error allocating IPv6 fragment\n");
        FragmentFail:
            BufferList->Status = STATUS_INSUFFICIENT_RESOURCES; 
            SubInterfaceStats->FragmentFailures += PacketCount;
            GlobalStats->FragmentFailures += PacketCount;

            IpSecCleanupSessionInformation(BufferList);
            return;
        }

        //
        // FragmentOffset is relative to fragmentable part of original 
        // packet.
        //
        FragmentOffset = 0;
        BytesLeft = Buffer->DataLength - UnfragmentableBytes;

        //
        // Undo the retreats since some buffers might not need
        // a Fragment Header.  We want to use the "receive" versions
        // now since we don't want to allocate/deallocate anything.
        //
        NetioAdvanceNetBufferList(NewNbl, (USHORT) DataOffsetDelta);

        FragmentId = Ipv6pGenerateFragmentId(Interface);

        for (NewNb = NewNbl->FirstNetBuffer;
             NewNb != NULL;
             NewNb = NewNb->Next) {

            ASSERT(NewNb->DataLength <= MAX_IPV6_PAYLOAD);
            BytesSent = (USHORT)NewNb->DataLength;
            ASSERT(BytesSent <= BytesLeft);

            if ((Buffer->DataLength - UnfragmentableBytes > FragmentSize) ||
                ForceFragment) {
                //
                // Prepend IPv6 Fragment header.
                //
                NetioRetreatNetBuffer(NewNb, 
                                      sizeof(IPV6_FRAGMENT_HEADER),
                                      0);
                FragmentHeader = NetioGetDataBuffer(
                    NewNb, 
                    sizeof(IPV6_FRAGMENT_HEADER),
                    NULL,
                    1,
                    0);
                FragmentHeader->NextHeader = HeaderType;
                FragmentHeader->Reserved = 0;
                FragmentHeader->OffsetAndFlags = 
                    RtlUshortByteSwap(FragmentOffset);
                FragmentHeader->Id = FragmentId;
            }
        
            //
            // Copy unfragmentable bytes.
            // TODO: This can be changed to RtlCopyMdlToBuffer. 
            //
            NetioRetreatNetBuffer(NewNb, UnfragmentableBytes, 0);
            RtlCopyMdlToMdl(Buffer->MdlChain,
                            Buffer->DataOffset,
                            NewNb->MdlChain,
                            NewNb->DataOffset,
                            UnfragmentableBytes,
                            &BytesCopied);
            
            ASSERT(BytesCopied == UnfragmentableBytes);

            if ((Buffer->DataLength - UnfragmentableBytes > FragmentSize) ||
                ForceFragment) {
                //
                // Correct the PayloadLength and NextHeader fields.
                //
                FragmentPayloadLength = UnfragmentableBytes + 
                                        sizeof(IPV6_FRAGMENT_HEADER) + 
                                        BytesSent - sizeof(IPV6_HEADER);
                ASSERT(FragmentPayloadLength <= MAX_IPV6_PAYLOAD);
                Data = NetioGetDataBuffer(NewNb, 
                                          sizeof(IPV6_HEADER), 
                                          NULL, 
                                          1,
                                          0);
                ((IPV6_HEADER UNALIGNED *)Data)->PayloadLength =
                    RtlUshortByteSwap((USHORT) FragmentPayloadLength);
                ASSERT(Data[NextHeaderOffset] == HeaderType);
                Data[NextHeaderOffset] = IPPROTO_FRAGMENT;
            }

            if (BytesLeft == BytesSent) {
                Buffer = Buffer->Next;
                FragmentOffset = 0;
                BytesLeft = (Buffer != NULL) ? (Buffer->DataLength - 
                                                UnfragmentableBytes) : 0;
            } else {
                FragmentHeader->MoreFragments = TRUE;
                FragmentOffset += BytesSent;
                BytesLeft -= BytesSent;
            }
        }
        ASSERT(Buffer == NULL);

        NblInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)
            &NET_BUFFER_LIST_INFO(NewNbl, TcpLargeSendNetBufferListInfo);
        if (NblInfo->Value != 0) {
            ASSERT(NblInfo->Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE);
            NblInfo->LsoV2Transmit.TcpHeaderOffset += sizeof(IPV6_FRAGMENT_HEADER);
       }
        //
        // TODO: This is counting the total number of packets in the net buffer
        // list, some of which might not be undergoing fragmentations.  We
        // should just count packes that are fragmented. 
        //
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

        Action = IPsecProcessOutboundFragList(IPPROTO_IPV6, BufferList, NewNbl);
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
        // structure. Dereferecnce the old net buffer list. 
        //
        NetioDereferenceNetBufferList(BufferList, FALSE);
        Args->NetBufferList = NewNbl;

    }

Done:
    Args->NetBufferList->Status = STATUS_SUCCESS;

    IpSecCleanupSessionInformation(Args->NetBufferList);
}
