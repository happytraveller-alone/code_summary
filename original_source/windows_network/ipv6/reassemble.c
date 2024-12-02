/*++

Copyright (c) Microsoft Corporation

Module Name:

    reassemble.c

Abstract:

    This module implements the functions of the IPv6 Reassembler module.

Author:

    Dave Thaler (dthaler) 1-July-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "reassemble.tmh"

IP_INTERNAL_RECEIVE_DATAGRAMS Ipv6pReceiveFragmentList;
IP_INTERNAL_AUTHENTICATE_HEADER Ipv6pAuthenticateFragmentHeader;

IP_RECEIVE_DEMUX Ipv6FragmentDemux = {
    Ipv6pReceiveFragmentList, 
    Ipv6pReceiveFragmentControl, 
    Ipv6pAuthenticateFragmentHeader,
    NULL,
    NULL,
    TRUE
};

PREASSEMBLY
Ipv6pFragmentLookup(
    IN PIP_INTERFACE Interface,
    IN ULONG Id,
    IN UNALIGNED IPV6_HEADER *IP,
    IN PKIRQL OldIrql
    )
/*++

Routine Description:

    Look for record of previous fragments from this datagram.

    A datagram on an interface is uniquely identified by its
    {source address, destination address, identification field} triple.
    This function checks our reassembly list for previously
    received fragments of a given datagram.

    If an existing reassembly record is found,
    it is returned locked.

    If there is no existing reassembly record, returns NULL
    and leaves the global reassembly list locked.

Arguments:

    Interface - Supplies the receiving interface.

    Id - Supplies the fragment identification field to match.

    IP - Pointer to IP header to find the reassembly.
    
    OldIrql - Returns the original IRQL. 

Locks:

    None. 
    Returns with the reassembly lock held if a reassembly is found.
    Returns with the global set lock held if no reassembly is found. 

Caller IRQL: <= DISPATCH.

--*/
{
    PREASSEMBLY Reassembly;
    PIP_PROTOCOL Protocol = &Ipv6Global;
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_CONTEXT Context;
    PRTL_HASH_TABLE Table;
    ULONG Key;
    IN6_ADDR *Source;
    IN6_ADDR *Destination;

    Source = AlignAddr(&IP->SourceAddress);
    Destination = AlignAddr(&IP->DestinationAddress);

    Key = IppReassemblyHashKey(Interface->Compartment, Id, (PUCHAR)IP);

    KeAcquireSpinLock(&Protocol->ReassemblySet.Lock, OldIrql);

    Table = &Protocol->ReassemblySet.ReassemblyTable;
    RtlInitHashTableContext(&Context);
    for (Curr = RtlLookupEntryHashTable(Table, Key, &Context);
         Curr != NULL;
         Curr = RtlGetNextEntryHashTable(Table, &Context)) {

        Reassembly = CONTAINING_RECORD(Curr, REASSEMBLY, TLink);

        if ((Reassembly->Interface == Interface) &&
            (Reassembly->Id == Id) &&
            IN6_ADDR_EQUAL(&Reassembly->IpHeader.Ipv6.SourceAddress,
                           Source) &&
            IN6_ADDR_EQUAL(&Reassembly->IpHeader.Ipv6.DestinationAddress,
                           Destination)) {
            //
            // Is this reassembly record being deleted?
            // If so, ignore it.
            //
            KeAcquireSpinLockAtDpcLevel(&Reassembly->Lock);
            ASSERT((Reassembly->State == ReassemblyStateNormal) ||
                   (Reassembly->State == ReassemblyStateDeleting));

            if (Reassembly->State == ReassemblyStateDeleting) {
                KeReleaseSpinLockFromDpcLevel(&Reassembly->Lock);
                continue;
            }

            RtlReleaseHashTableContext(&Context);
            //
            // Return with the reassembly record lock still held.
            //
            KeReleaseSpinLockFromDpcLevel(&Protocol->ReassemblySet.Lock);
            return Reassembly;
        }
    }
    RtlReleaseHashTableContext(&Context);

    //
    // Return with the global reassembly list lock still held.
    //
    return NULL;
}

VOID
Ipv6pReassembleDatagram(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PREASSEMBLY Reassembly, 
    IN KIRQL OldIrql
    )
/*++

Routine Description: 

    Put all the fragments together.
  
    Called when we have all the fragments to complete a datagram.
    Patch them together and pass the packet up.
  
    We allocate a single contiguous buffer and copy the fragments
    into this buffer.
    REVIEW: Instead use ndis buffers to chain the fragments?
  
    Deletes the reassembly record.

Arguments:

    NetBufferList - Supplies the packet being currently received.

    Reassembly - Supplies the reassembly record for the fragmented datagram.

    OldIrql - Supplies the original IRQL.

Locks:

    Called with the reassembly record lock held,
    but not the global reassembly list lock.
    Releases the reassembly record lock. 

Caller IRQL:

    Must be called at DISPATCH level.
  
--*/
{
    NTSTATUS Status;
    ULONG PayloadLength;
    ULONG TotalLength, UnfragmentableLength;
    PIP_FRAGMENT ThisShim;
    PNET_BUFFER_LIST ReassemblyNbl;
    PNET_BUFFER ReassemblyNb;
    PIP_REQUEST_CONTROL_DATA ReassControl;
    PUCHAR ReassemblyBuffer;
    PUCHAR pNextHeader;
    PIP_INTERFACE Interface;
    PIP_INTERFACE_STATISTICS InterfaceStats;
    PIP_GLOBAL_STATISTICS GlobalStats;
    PMDL ThisMdl;
    ULONG Processor;
    PIP_PROTOCOL Protocol;
    NL_ECN_CODEPOINT EcnField;
    
    DISPATCH_CODE();

    PayloadLength = Reassembly->DataLength + Reassembly->UnfragmentableLength;
    ASSERT(PayloadLength <= MAX_IPV6_PAYLOAD);
    TotalLength = sizeof(IPV6_HEADER) + PayloadLength;
    UnfragmentableLength = sizeof(IPV6_HEADER) + 
                           Reassembly->UnfragmentableLength;

    Interface = Control->DestLocalAddress->Interface;
    Protocol = Interface->Compartment->Protocol;

    Processor = KeGetCurrentProcessorNumber();
    InterfaceStats = Interface->PerProcessorStatistics[Processor];
    GlobalStats = &Protocol->PerProcessorStatistics[Processor];

    //
    // Allocate memory for buffer and copy fragment data into it. The
    // completion contest is the reassembly pointer. 
    //
    ReassemblyNbl = NetioAllocateAndReferenceNetBufferAndNetBufferList(
        IppReassemblyNetBufferListsComplete, 
        Reassembly, 
        NULL, 
        0, 
        0, 
        FALSE);
    if (ReassemblyNbl == NULL) {
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly, 
                                   OldIrql);
        goto ExitAllocationFailure;
    }
    
    ReassemblyNb = ReassemblyNbl->FirstNetBuffer;
    Status = NetioRetreatNetBuffer(ReassemblyNb, 
                                   (USHORT)UnfragmentableLength, 
                                   0);
    if (!NT_SUCCESS(Status)) {
        IppRemoveFromReassemblySet(&Protocol->ReassemblySet,
                                   (PREASSEMBLY_ELEMENT)Reassembly,
                                   OldIrql);    
        NetioDereferenceNetBufferList(ReassemblyNbl, FALSE);
        goto ExitAllocationFailure;
    }
    
    ReassemblyBuffer = NetioGetDataBuffer(ReassemblyNb, 
                                          UnfragmentableLength, 
                                          NULL,
                                          1,
                                          0);

    ReassControl = IppCopyPacket(Protocol, Control);
    if (ReassControl == NULL) {
        IppRemoveFromReassemblySet(&Protocol->ReassemblySet,
                                   (PREASSEMBLY_ELEMENT)Reassembly,
                                   OldIrql);    
        NetioDereferenceNetBufferList(ReassemblyNbl, FALSE);
        goto ExitAllocationFailure;
    }

    //
    // We must take a reference on the interface before
    // IppRemoveFromReassemblySet releases the record lock.
    //

    //
    // Generate the original IP hdr and copy it and any unfragmentable
    // data into the new packet.  Note we have to update the next header
    // field in the last unfragmentable header (or the IP hdr, if none).
    //
    Reassembly->IpHeader.Ipv6.PayloadLength = 
        RtlUshortByteSwap((USHORT)PayloadLength);
    RtlCopyMemory(ReassemblyBuffer,
                  &Reassembly->IpHeader,
                  sizeof(IPV6_HEADER));

    RtlCopyMemory(ReassemblyBuffer + sizeof(IPV6_HEADER), 
                  Reassembly->UnfragmentableData,
                  Reassembly->UnfragmentableLength);

    pNextHeader = ReassemblyBuffer + Reassembly->NextHeaderOffset;
    ASSERT(*pNextHeader == IPPROTO_FRAGMENT);
    *pNextHeader = Reassembly->NextHeader;

#ifdef DBG
{
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo;    
    ChecksumInfo.Value = (ULONG) (ULONG_PTR)
        NET_BUFFER_LIST_INFO(ReassemblyNbl,TcpIpChecksumNetBufferListInfo);
    
    //
    // Upper layers must re-calculate the checksum, because offload cards can
    // not handle checksums for reassembled fragments.
    //
    ASSERT(!ChecksumInfo.Receive.NdisPacketUdpChecksumSucceeded);
    ASSERT(!ChecksumInfo.Receive.NdisPacketUdpChecksumFailed);
}
#endif

    //
    // Reassemble the ECN field.
    //
    EcnField = IppReassembleEcnField(Reassembly);
    Reassembly->IpHeader.Ipv6.VersionClassFlow |= (EcnField << IPV6_ECN_SHIFT);
    ((PNETIO_NET_BUFFER_CONTEXT) 
        NET_BUFFER_PROTOCOL_RESERVED(ReassemblyNb))->EcnField = EcnField;
    
    //
    // Set the reassembled flag and the net buffer list.
    //
    ReassControl->Reassembled = TRUE;
    ReassControl->NetBufferList = ReassemblyNbl;

    //
    // Remove the reassembly from the set and drop the reassembly lock.
    //
    IppRemoveFromReassemblySet(&Protocol->ReassemblySet,
                               (PREASSEMBLY_ELEMENT)Reassembly,
                               OldIrql);

    //
    // Run through the contiguous list, copying data over to our new packet.
    //
    for (ThisShim = Reassembly->ContiguousList;
         ThisShim != NULL;
         ThisShim = ThisShim->Next) {
        ThisMdl = &ThisShim->Mdl;
        NetioExpandNetBuffer(ReassemblyNb,
                             ThisMdl, 
                             MmGetMdlByteCount(ThisMdl));
    }
    if (ReassemblyNb->DataLength > TotalLength) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR, 
                   "IPNG: IPv6 reassembly failure: Packets don't add up\n");
        IppCompleteAndFreePacketList(ReassControl, FALSE);
        goto ExitUpdateFailureStatistics;        
    }

    InterfaceStats->ReassemblyOks++;
    GlobalStats->ReassemblyOks++;

    //
    // Restore the IPSec history of the packet.
    //
    IPsecSetSecurityCtxtOnReassembledPkt(&Reassembly->IPSecContext, 
                                         ReassemblyNbl);
    //
    // Receive the reassembled packet.
    // If the current fragment was reassembled,
    // then we should avoid another level of recursion.
    // We must prevent "reassembly recursion".
    // Test both paths in checked builds.
    //
    if ((Control->Reassembled)
#if DBG
        || (RandomNumber(0, 1) == 1)
#endif
        ) {
        PIP_WORK_QUEUE_ITEM rrc;

        rrc = ExAllocatePoolWithTagPriority(NonPagedPool, 
                                            sizeof *rrc,
                                            IpWorkItemPoolTag, 
                                            LowPoolPriority);
        if (rrc == NULL) {
            IppCompleteAndFreePacketList(ReassControl, FALSE);
            goto ExitAllocationFailure;
        }

        rrc->Context = ReassControl;
        rrc->WorkQueueItem = IoAllocateWorkItem(IppDeviceObject);
        if (rrc->WorkQueueItem == NULL) {
            IppCompleteAndFreePacketList(ReassControl, FALSE);
            ExFreePool(rrc);
            goto ExitAllocationFailure;
        }
        IoQueueWorkItem(rrc->WorkQueueItem,
                        IppReassembledReceive,
                        DelayedWorkQueue,
                        rrc);
    } else {
        IppReceiveHeaders(ReassControl->Compartment->Protocol, ReassControl);
    }

ExitAllocationFailure:    
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
               "IPNG: Failure allocating IPv6 reassembly structures.\n");
    
ExitUpdateFailureStatistics:    
    InterfaceStats->ReassemblyFailures++;
    GlobalStats->ReassemblyFailures++;
}

VOID
NTAPI
Ipv6pReceiveFragment(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    Handle a IPv6 datagram fragment.
  
    This is the routine called by IPv6 when it receives a fragment of an
    IPv6 datagram, i.e. a next header value of 44.  Here we attempt to
    reassemble incoming fragments into complete IPv6 datagrams.
  
    If a later fragment provides data that conflicts with an earlier
    fragment, then we use the first-arriving data.
  
    We silently drop the fragment and stop reassembly in several
    cases that are not specified in the spec, to prevent DoS attacks.
    These include partially overlapping fragments and fragments
    that carry no data. Legitimate senders should never generate them.
  
    Compare FragmentReceive in the XP IPv6 stack.
  
Arguments:

    Packet - Supplies IP packet data.
  
--*/
{
    PIP_INTERFACE Interface;
    IPV6_FRAGMENT_HEADER UNALIGNED *Fragment;
    PREASSEMBLY Reassembly;
    UINT16 FragmentOffset;
    PIP_FRAGMENT Shim, ThisShim, *MoveShim;
    USHORT NextHeaderPosition;
    PNET_BUFFER_LIST BufferList = Packet->NetBufferList;
    PNET_BUFFER Buffer = BufferList->FirstNetBuffer;
    PIP_INTERFACE_STATISTICS InterfaceStats;
    PIP_GLOBAL_STATISTICS GlobalStats;
    UNALIGNED IPV6_HEADER *IP;
    SIZE_T BytesCopied, MdlSize, ShimSize;
    ULONG Processor;
    IP_FILTER_ACTION Action;
    PIP_PROTOCOL Protocol;
    KIRQL OldIrql;
    NTSTATUS Status;
    UINT8 EcnField;
    
    ASSERT(Buffer->Next == NULL);
    
    if (Packet->PromiscuousOnlyReceive) {
        //
        // If the packet is not really locally-destined, then just
        // deliver the fragment up to raw.
        //
        Packet->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    Interface = Packet->DestLocalAddress->Interface;
    Protocol = Interface->Compartment->Protocol;

    Processor = KeGetCurrentProcessorNumber();
    InterfaceStats = Interface->PerProcessorStatistics[Processor];
    GlobalStats = &Protocol->PerProcessorStatistics[Processor];

    InterfaceStats->ReassemblyRequireds++;
    GlobalStats->ReassemblyRequireds++;

#ifdef NOT_YET_IMPLEMENTED
    //
    // We can not reassemble fragments that have had IPsec processing.
    // It can't work because the IPsec headers in the unfragmentable part
    // of the offset-zero fragment will authenticate/decrypt that fragment.
    // Then the same headers would be copied to the reassembled packet.
    // They couldn't possibly successfully authenticate/decrypt again.
    // Also see RFC 2401 B.2.
    //
    if (Packet->SAPerformed != NULL) {
        DbgPrint("FragmentReceive: IPsec on fragment\n");
        //
        // The spec does not tell us what ICMP error to generate in this case,
        // but flagging the fragment header seems reasonable.
        //
        goto BadFragment;
    }

    //
    // If a jumbo payload option was seen, send an ICMP error.
    // Set ICMP pointer to the offset of the fragment header.
    //
    if (IP->PayloadLength == 0) {
        DbgPrint("FragmentReceive: jumbo fragment\n");

    BadFragment:
        //
        // The NextHeader value passed to Icmpv6pSendError
        // is IPPROTO_FRAGMENT because we haven't moved
        // past the fragment header yet.
        //
        IppSendError(
            FALSE, 
            &Ipv6Global,
            Packet,
            ICMP6_PARAM_PROB,
            ICMP6_PARAMPROB_HEADER,
            RtlUlongByteSwap(Packet->NetworkLayerHeadersSize),
            FALSE);
        goto Failed; // Drop packet.
    }
#endif

    //
    // Verify that we have enough contiguous data to overlay a FragmentHeader
    // structure on the incoming packet.  Then do so.
    //
    Fragment = (IPV6_FRAGMENT_HEADER UNALIGNED *)
        NetioGetDataBuffer(Buffer, sizeof *Fragment, NULL, 1, 0);
    if (Fragment == NULL) {
        //
        // Pullup failed.
        //
        if (Buffer->DataLength < sizeof *Fragment) {
            IppSendError(
                FALSE, 
                &Ipv6Global,
                Packet,
                ICMP6_PARAM_PROB,
                ICMP6_PARAMPROB_HEADER,
                RtlUlongByteSwap(FIELD_OFFSET(IPV6_HEADER, PayloadLength)),
                FALSE);
        }
        goto Failed; // Drop packet.
    }

    FragmentOffset = Ip6FragmentOffset(Fragment);

    Action =
        IppInspectFragmentIn(
            IPPROTO_IPV6,
            Packet->SourceAddress.Address,
            (PNL_LOCAL_ADDRESS) Packet->DestLocalAddress,
            (PNL_INTERFACE)Packet->SourceSubInterface->Interface,
            Packet->SourceSubInterface->Index,
            Packet->NlcReceiveDatagram.Loopback,
            Packet->NlcReceiveDatagram.NetworkLayerHeadersSize,
            Fragment->Id,
            FragmentOffset,
            Buffer->DataLength - sizeof *Fragment,
            BufferList);
    if (Action >= IpFilterDrop) {
        goto Failed;
    }
    ASSERT(Action == IpFilterAllow);

    //
    // Remember offset to this header's NextHeader field.
    // But don't overwrite offset to previous header's NextHeader just yet.
    //
    NextHeaderPosition =
        Packet->NlcReceiveDatagram.NetworkLayerHeadersSize + 
        FIELD_OFFSET(IPV6_FRAGMENT_HEADER, NextHeader);

    //
    // Skip over fragment header. Also add the size of the fragment header to
    // the NetworkLayerHeadersSize (in IP_REQUEST_CONTROL_DATA) so that the
    // header can be retreated on the completion path.
    //
    NetioAdvanceNetBuffer(Buffer, sizeof *Fragment);
    Packet->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(*Fragment);

    //
    // Lookup this fragment triple (Source Address, Destination
    // Address, and Identification field) per-interface to see if
    // we've already received other fragments of this packet.
    //
    IP = (UNALIGNED IPV6_HEADER *) Packet->IP;
    Reassembly = Ipv6pFragmentLookup(Interface, 
                                     Fragment->Id,
                                     IP,
                                     &OldIrql);
    if (Reassembly == NULL) {
        //
        // We hold the global reassembly list lock.
        //
        // Handle a special case first: if this is the first, last, and only
        // fragment, then we can just continue parsing without reassembly.
        // Test both paths in checked builds.
        //
        if ((FragmentOffset == 0) && !Fragment->MoreFragments
#if DBG
            && (RandomNumber(0, 1) == 0)
#endif
            ) {
            //
            // Return next header value.
            //
            KeReleaseSpinLockFromDpcLevel(&Protocol->ReassemblySet.Lock);
            Packet->NextHeaderPosition = NextHeaderPosition;
            InterfaceStats->ReassemblyOks++;
            GlobalStats->ReassemblyOks++;
            Packet->NlcReceiveDatagram.NextHeaderValue = Fragment->NextHeader;
            return;
        }

        //
        // This is the first fragment of this datagram we've received.
        // Allocate a reassembly structure to keep track of the pieces
        // and add it to the front of the ReassemblySet.
        // Also acquires the reassembly record lock and
        // releases the global reassembly list lock.
        //
        Reassembly =
            IppCreateInReassemblySet(
                &Protocol->ReassemblySet,
                Packet->IP,
                Interface,
                Fragment->Id, 
                OldIrql);
        if (Reassembly == NULL) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                       "IPNG: Failure allocating IPv6 reassembly structure\n");
            goto Failed;
        }
    } else {
        //
        // Unlike for IPv4 we do not sanity check that the protocols of the
        // incoming packet and previous packets are the same.  RFC 2460
        // requires us NOT to perform the check.
        //
        //
        // We have found and locked an existing reassembly structure.
        // Because we remove the reassembly structure in every
        // error situation below, an existing reassembly structure
        // must have a shim that has been successfully added to it.
        //
        ASSERT((Reassembly->ContiguousList != NULL) || 
               (Reassembly->GapList != NULL));
    }

    //
    // At this point, we have a locked reassembly record.
    // We do not hold the global reassembly list lock
    // while we perform the relatively expensive work
    // of copying the fragment.
    //
    ASSERT(Reassembly->State == ReassemblyStateNormal);

    //
    // Update the saved packet flags from this fragment packet.
    // We are really only interested in NBL_LINK_LAYER_NOT_UNICAST.
    //
    Reassembly->Flags |= (BufferList->Flags & NBL_FLAGS_PROTOCOL_RESERVED);

    //
    // Update ECN state based on the IP Header. This will be processed later
    // during reassembly.
    //
    EcnField = (IP->VersionClassFlow & IPV6_ECN_MASK) >> IPV6_ECN_SHIFT;
    Reassembly->Flags |= (1 << EcnField);
    
    //
    // Send ICMP error if this fragment causes the total packet length
    // to exceed the maximum IPv6 payload size.  Set ICMP pointer equal to the
    // offset to the Fragment Offset field.
    //
    if (FragmentOffset + Buffer->DataLength > MAX_IPV6_PAYLOAD) {
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly, 
                                   OldIrql);
        IppSendError(
            FALSE, 
            &Ipv6Global,
            Packet,
            ICMP6_PARAM_PROB,
            ICMP6_PARAMPROB_HEADER,
            RtlUlongByteSwap(
                (Packet->NlcReceiveDatagram.NetworkLayerHeadersSize - 
                 sizeof(IPV6_FRAGMENT_HEADER) +
                 (UINT) FIELD_OFFSET(IPV6_FRAGMENT_HEADER, OffsetAndFlags))),
            FALSE);    
        goto Failed;
    }

    //
    // Check for IPSec integrity.
    //
    Status = IPsecVerifyFragment(&Reassembly->IPSecContext, 
                                 BufferList,
                                 Protocol->Level,
                                 (UCHAR *)AlignAddr(&IP->SourceAddress),
                                 (UCHAR *)AlignAddr(&IP->DestinationAddress));
                                                
    if (!NT_SUCCESS(Status)) {
        //
        // IPSec-status of this fragment is different from the
        // IPSec-status of the fragment we received first.
        // We don't allow mixed reassemblies.
        //
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Received mixed IPSec and non-IPSec IPv6 fragments\n");
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly, 
                                   OldIrql);
        goto DropFragment;
    }


    if ((Buffer->DataLength == 0) && 
        ((FragmentOffset != 0) || Fragment->MoreFragments)) {
        //
        // We allow a moot fragment header because some test programs 
        // might generate them.
        // (The first/last/only check above catches this in free builds.)
        // But otherwise, we disallow fragments that do not actually
        // carry any data for DoS protection.
        //
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Received zero length IPv6 fragment\n");
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly, 
                                   OldIrql);
        goto DropFragment;
    }

    //
    // If this is the last fragment (more fragments bit not set), then
    // remember the total data length, else, check that the length
    // is a multiple of 8 bytes.
    //
    if (!Fragment->MoreFragments) {
        if (Reassembly->DataLength != (UINT)-1) {
            //
            // We already received a last fragment.
            // This can happen if a packet is duplicated.
            //
            if (FragmentOffset + Buffer->DataLength != Reassembly->DataLength) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Received duplicate last IPv6 fragment "
                           "with conflicting length (%d) expected %d\n", 
                           Buffer->DataLength, 
                           Reassembly->DataLength - FragmentOffset);
                IppDeleteFromReassemblySet(&Protocol->ReassemblySet,
                                           (PREASSEMBLY_ELEMENT)Reassembly, 
                                           OldIrql);
                goto DropFragment;
            }
        } else {
            //
            // Set expected data length from this fragment.
            //
            Reassembly->DataLength = FragmentOffset + Buffer->DataLength;

            //
            // Do we have any fragments beyond this length?
            //
            if ((Reassembly->Marker > Reassembly->DataLength) ||
                (Reassembly->MaxGap > Reassembly->DataLength)) {
                goto BadFragmentBeyondData;
            }
        }
    } else {
        if ((Buffer->DataLength % 8) != 0) {
            //
            // Length is not multiple of 8, send ICMP error with a pointer
            // value equal to offset of payload length field in IP header.
            //
            IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                       (PREASSEMBLY_ELEMENT)Reassembly, 
                                       OldIrql);
            IppSendError(
                FALSE, 
                &Ipv6Global,
                Packet,
                ICMP6_PARAM_PROB,
                ICMP6_PARAMPROB_HEADER,
                RtlUlongByteSwap(FIELD_OFFSET(IPV6_HEADER, PayloadLength)),
                FALSE);
            goto Failed; // Drop packet.
        }

        if ((Reassembly->DataLength != (UINT)-1) &&
            (FragmentOffset + Buffer->DataLength > Reassembly->DataLength)) {
            //
            // This fragment falls beyond the data length.
            // As part of our DoS prevention, drop the reassembly.
            //
        BadFragmentBeyondData:
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Received IPv6 fragment beyond data length\n");
            IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                       (PREASSEMBLY_ELEMENT)Reassembly, 
                                       OldIrql);
            goto DropFragment;
        }
    }

    //
    // Allocate and initialize a shim structure to hold the fragment data.
    //
    Shim = NULL;    
    MdlSize = ALIGN_UP(MmSizeOfMdl(DUMMY_VA, Buffer->DataLength), PVOID);

    Status = RtlSIZETAdd(FIELD_OFFSET(IP_FRAGMENT, Mdl), MdlSize, &ShimSize);
    if (NT_SUCCESS(Status)) {
        Status = RtlSIZETAdd(ShimSize, Buffer->DataLength, &ShimSize);
    }        

    if (NT_SUCCESS(Status)) {        
        Shim = ExAllocatePoolWithTagPriority(NonPagedPool, 
                                             ShimSize,
                                             IpReassemblyPoolTag, 
                                             LowPoolPriority);
    }

    if (Shim == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Failure allocating shim for IPv6 reassembly\n");
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly, 
                                   OldIrql);
        goto Failed;
    }
    MmInitializeMdl(&Shim->Mdl, 
                    (PVOID)(((PUCHAR)&Shim->Mdl) + MdlSize), 
                    Buffer->DataLength);
    MmBuildMdlForNonPagedPool(&Shim->Mdl);

    IppIncreaseReassemblySize(&Protocol->ReassemblySet,
                              (PREASSEMBLY_ELEMENT)Reassembly, 
                              REASSEMBLY_SIZE_FRAG + Buffer->DataLength,
                              Buffer->DataLength);
    Shim->Length = (USHORT)Buffer->DataLength;
    Shim->Offset = FragmentOffset;
    Shim->Next = NULL;

    //
    // Determine where this fragment fits among the previous ones.
    //
    // There is no good reason for senders to ever generate overlapping
    // fragments. However, packets may sometimes be duplicated in the network.
    // If we receive a fragment that duplicates previously received fragments,
    // then we just discard it. If we receive a fragment that only partially
    // overlaps previously received fragments, then we assume a malicious
    // sender and just drop the reassembly. This gives us better behavior
    // under some kinds of DoS attacks, although the upper bound on reassembly
    // buffers (see IppCheckReassemblyQuota) is the ultimate protection.
    //
    if (FragmentOffset == Reassembly->Marker) {
        //
        // This fragment extends the contiguous list.
        //

        if (Reassembly->ContiguousList == NULL) {
            //
            // We're first on the list.
            // We use info from the (first) offset zero fragment to recreate
            // the original datagram. Info in a second offset zero fragment
            // is ignored.
            //
            ASSERT(FragmentOffset == 0);
            ASSERT(Reassembly->UnfragmentableData == NULL);
            Reassembly->ContiguousList = Shim;

            // Save the next header value.
            Reassembly->NextHeader = Fragment->NextHeader;

            //
            // Grab the unfragmentable data, i.e. the extension headers that
            // preceded the fragment header.
            //
            Reassembly->UnfragmentableLength = (USHORT)
                (Packet->NlcReceiveDatagram.NetworkLayerHeadersSize - 
                 sizeof(IPV6_FRAGMENT_HEADER) -
                 sizeof(IPV6_HEADER));

            if (Reassembly->UnfragmentableLength != 0) {
                Reassembly->UnfragmentableData = ExAllocatePoolWithTagPriority(
                                        NonPagedPool, 
                                        Reassembly->UnfragmentableLength,
                                        IpReassemblyPoolTag, 
                                        LowPoolPriority);
                if (Reassembly->UnfragmentableData == NULL) {
                    //
                    // Out of memory!?!  Clean up and drop packet.
                    //
                    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                               "IPNG: Failure allocating space for IPv6 "
                               "reassembly unfragmentable data\n");
                    
                    //
                    // Will also free Shim because of 
                    // Reassembly->ContiguousList.
                    //
                    IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                               (PREASSEMBLY_ELEMENT)Reassembly,
                                               OldIrql);
                    goto Failed;
                }
                IppIncreaseReassemblySize(&Protocol->ReassemblySet,
                                          (PREASSEMBLY_ELEMENT)Reassembly, 
                                          Reassembly->UnfragmentableLength,
                                          Reassembly->UnfragmentableLength);

                //
                // Copy data into flat buffer.
                //
                RtlCopyMdlToBuffer(
                    Buffer->MdlChain,
                    Buffer->DataOffset - 
                    Packet->NlcReceiveDatagram.NetworkLayerHeadersSize +
                    sizeof(IPV6_HEADER),              // Offset.
                    Reassembly->UnfragmentableData,   // Flat buffer.
                    Reassembly->UnfragmentableLength, // Length.
                    &BytesCopied);
                ASSERT(BytesCopied == Reassembly->UnfragmentableLength);

                Reassembly->NextHeaderOffset = Packet->NextHeaderPosition;
            } else {
                Reassembly->NextHeaderOffset = FIELD_OFFSET(IPV6_HEADER, 
                                                            NextHeader);
            }

            //
            // We need to have the IP header of the offset-zero fragment.
            // (Every fragment normally will have the same IP header,
            // except for PayloadLength, and unfragmentable headers,
            // but they might not.) Ipv6pReassembleDatagram and
            // CreateFragmentPacket both need it.
            //
            // Of the 40 bytes in the header, the 32 bytes in the source
            // and destination addresses are already correct.
            // So we just copy the other 8 bytes now.
            //
            RtlCopyMemory(&Reassembly->IpHeader, Packet->IP, 8);

        } else {
            //
            // Add us to the end of the list.
            //
            Reassembly->ContiguousEnd->Next = Shim;
        }
        Reassembly->ContiguousEnd = Shim;

        //
        // Increment our contiguous extent marker.
        //
        Reassembly->Marker += (USHORT)Buffer->DataLength;

        //
        // Now peruse the non-contiguous list here to see if we already
        // have the next fragment to extend the contiguous list, and if so,
        // move it on over.  Repeat until we can't.
        //
        MoveShim = &Reassembly->GapList;
        while ((ThisShim = *MoveShim) != NULL) {
            if (ThisShim->Offset == Reassembly->Marker) {
                //
                // This fragment now extends the contiguous list.
                // Add it to the end of the list.
                //
                Reassembly->ContiguousEnd->Next = ThisShim;
                Reassembly->ContiguousEnd = ThisShim;
                Reassembly->Marker += ThisShim->Length;

                //
                // Remove it from non-contiguous list.
                //
                *MoveShim = ThisShim->Next;
                ThisShim->Next = NULL;
            } else if (ThisShim->Offset > Reassembly->Marker) {
                //
                // This fragment lies beyond the contiguous list.
                // Because the gap list is sorted, we can stop now.
                //
                break;
            } else {
                //
                // This fragment overlaps the contiguous list.
                // For DoS prevention, drop the reassembly.
                //
            BadFragmentOverlap:
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Received overlapping IPv6 fragment\n");
                IppDeleteFromReassemblySet(&Protocol->ReassemblySet,
                                           (PREASSEMBLY_ELEMENT)Reassembly, 
                                           OldIrql);
                goto DropFragment;
            }
        }
    } else {
        //
        // Check whether the fragment duplicates data already in
        // the contiguous list.
        //
        if (Shim->Offset <= Reassembly->Marker) {
            if (Shim->Offset + Shim->Length > Reassembly->Marker) {
                //
                // We have a partial overlap.
                //
                ExFreePool(Shim);
                goto BadFragmentOverlap;
            }

            //
            // We already have all the data.  Don't bother distinguishing
            // between an exact duplicate and a partial overlap, just
            // ignore the new fragment.
            //
            goto Duplicate;
        }

        //
        // Exile this fragment to the non-contiguous (gap) list.
        // The gap list is sorted by Offset.
        //
        MoveShim = &Reassembly->GapList;
        for (;;) {
            ThisShim = *MoveShim;
            if (ThisShim == NULL) {
                //
                // Insert Shim at the end of the gap list.
                //
                Reassembly->MaxGap = Shim->Offset + Shim->Length;
                break;
            }

            if (Shim->Offset < ThisShim->Offset) {
                //
                // Check for partial overlap.
                //
                if (Shim->Offset + Shim->Length > ThisShim->Offset) {
                    ExFreePool(Shim);
                    goto BadFragmentOverlap;
                }

                //
                // OK, insert Shim before ThisShim.
                //
                break;
            } else if (ThisShim->Offset < Shim->Offset) {
                //
                // Check for partial overlap.
                //
                if (ThisShim->Offset + ThisShim->Length > Shim->Offset) {
                    ExFreePool(Shim);
                    goto BadFragmentOverlap;
                }

                //
                // OK, insert Shim somewhere after ThisShim.
                // Keep looking for the right spot.
                //
                MoveShim = &ThisShim->Next;
            } else {
                //
                // If the new fragment duplicates the old,
                // then just ignore the new fragment.
                //
                if (Shim->Length == ThisShim->Length) {
                Duplicate:
                    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                               "IPNG: Received duplicate IPv6 fragment\n");
                    ExFreePool(Shim);
                    KeReleaseSpinLockFromDpcLevel(&Reassembly->Lock);
                    goto DropFragment;
                } else {
                    ExFreePool(Shim);
                    goto BadFragmentOverlap;
                }
            }
        }

        Shim->Next = *MoveShim;
        *MoveShim = Shim;
    }

    //
    // Now that we have added the shim to the reassembly record
    // and passed various checks (particularly DoS checks),
    // copy the actual fragment data to the shim.
    //
    RtlCopyMdlToBuffer(Buffer->MdlChain,    // SourceMdlChain.
                       Buffer->DataOffset,  // SourceOffset.
                       (PVOID)(((PUCHAR)&Shim->Mdl) + MdlSize), // Buffer.
                       Buffer->DataLength,  // BytesToCopy.
                       &BytesCopied);       // BytesCopied.
    ASSERT(BytesCopied == Buffer->DataLength);

    if (Reassembly->Marker == Reassembly->DataLength) {
        //
        // We have received all the fragments.
        // Because of the overlapping/data-length/zero-size sanity checks
        // above, when this happens there should be no fragments
        // left on the gap list. However, Ipv6pReassembleDatagram does not
        // rely on having an empty gap list.
        //
        ASSERT(Reassembly->GapList == NULL);
        Ipv6pReassembleDatagram(Packet, Reassembly, OldIrql);
    } else {
        //
        // Finally, check if we're too close to our limit for
        // reassembly buffers.  If so, drop this packet.  Otherwise,
        // wait for more fragments to arrive.
        //
        IppCheckReassemblyQuota(&Protocol->ReassemblySet, 
                                (PREASSEMBLY_ELEMENT)Reassembly, 
                                OldIrql);
    }

    //
    // We're now done with the fragment.  Any data we need has been copied
    // out of it.
    //
    Packet->NetBufferList->Status = STATUS_REQUEST_ABORTED;
    Packet->NlcReceiveDatagram.NextHeaderValue = IPPROTO_NONE;

    IpSecDropInboundPacket(Packet->NetBufferList);
    return;

Failed:
    InterfaceStats->ReassemblyFailures++;
    GlobalStats->ReassemblyFailures++;
DropFragment:
    if (Packet->NetBufferList != NULL) {
        Packet->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        IpSecDropInboundPacket(Packet->NetBufferList);
    }
    Packet->NlcReceiveDatagram.NextHeaderValue = IPPROTO_NONE;
}

VOID
NTAPI
Ipv6pReceiveFragmentList(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    PIP_REQUEST_CONTROL_DATA Curr;

    for (Curr = Args; Curr != NULL; Curr = Curr->Next) {
        if ((Curr->NetBufferList == NULL) ||
            (!NT_SUCCESS(Curr->NetBufferList->Status)) ||
            (!Ipv6Global.ReceiveDemux[Curr->NlcReceiveDatagram.NextHeaderValue].
            IsExtensionHeader)) {
            //
            // Skip datagrams with errors or upper layer extension headers. 
            //
            continue;
        }
        
        if (Curr->NlcReceiveDatagram.NextHeaderValue != IPPROTO_FRAGMENT) {
            break;
        }
        
        Ipv6pReceiveFragment(Curr);
    }
}

VOID
Ipv6pReceiveFragmentControl(
    IN PIP_REQUEST_CONTROL_DATA ControlMessage
    )
/*++

Routine Description:

    Handle an ICMP error message in response to a fragment we sent.

    Compare the IP_PROTOCOL_FRAGMENT case of ExtHdrControlReceive()
    in the XP IPv6 stack.

Arguments:

    ControlMessage - Supplies information about the message received.

Return Value:

    STATUS_SUCCESS to drop the message.
    STATUS_MORE_ENTRIES if the caller should continue parsing past the
        fragment header.

--*/
{
    IPV6_FRAGMENT_HEADER FragmentBuffer;
    IPV6_FRAGMENT_HEADER UNALIGNED *Fragment;
    PNET_BUFFER_LIST NetBufferList;
    PNET_BUFFER NetBuffer;

    NetBufferList = ControlMessage->NetBufferList;
    NetBuffer = NetBufferList->FirstNetBuffer;

    if (NetBuffer->DataLength < sizeof *Fragment) {
        //
        // Packet too small.  Drop it, but make it available to RAW sockets.
        //
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    Fragment = (IPV6_FRAGMENT_HEADER UNALIGNED *) 
                   NetioGetDataBuffer(NetBuffer, 
                                      sizeof *Fragment, 
                                      &FragmentBuffer,
                                      1,
                                      0);

    if (Ip6FragmentOffset(Fragment) != 0) {
        //
        // We can only continue parsing if this fragment has offset zero.
        // Make the packet available to RAW sockets.
        //
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    NetioAdvanceNetBuffer(NetBuffer, sizeof *Fragment);
    ControlMessage->NlcControlMessage.NetworkLayerHeadersSize += 
        sizeof(*Fragment);

    ControlMessage->NlcControlMessage.NextHeaderValue = Fragment->NextHeader;
    NetBufferList->Status = STATUS_MORE_ENTRIES;
}

VOID
Ipv6pAuthenticateFragmentHeader(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PNET_BUFFER Buffer,
    IN OUT PUINT8 NextHeaderPointer,
    IN OUT PUINT8 DeferredHeaderPointer,
    IN OUT PUCHAR *DeferredDataPointer,
    IN OUT BOOLEAN *FreeData
    )
/*++

Routine Description:

    Do AH processing over a correctly-formed fragment header.

    We normally won't encounter a fragment header here,
    since reassembly will occur before authentication.
    However, our implementation optimizes the reassembly of
    single-fragment packets by leaving the fragment header in
    place.  When performing the authentication calculation,
    we treat such fragment headers as if they didn't exist.
    
--*/
{
    IPV6_FRAGMENT_HEADER FragmentBuffer;
    IPV6_FRAGMENT_HEADER UNALIGNED *Fragment;
    
    UNREFERENCED_PARAMETER(Packet);
    UNREFERENCED_PARAMETER(DeferredHeaderPointer);
    UNREFERENCED_PARAMETER(DeferredDataPointer);
    UNREFERENCED_PARAMETER(FreeData);

    Fragment = (IPV6_FRAGMENT_HEADER UNALIGNED *) 
        NetioGetDataBuffer(Buffer, sizeof(*Fragment), &FragmentBuffer, 1, 0);

    *NextHeaderPointer = Fragment->NextHeader;

    NetioAdvanceNetBuffer(Buffer, sizeof(*Fragment));
}


BOOLEAN
Ipv6pIsFragment(
    IN PNET_BUFFER_LIST NetBufferList,
    IN PVOID HeaderBuffer,
    OUT PUCHAR* SourceAddress,
    OUT PUCHAR* CurrentDestinationAddress,
    OUT PULONG Identification,
    OUT PULONG FragmentOffset,
    OUT PULONG FragmentLength,
    OUT PULONG PayloadLength
    )
/*++

Routine Description:

    Determines whether the given packet is a fragment and, if so,
    extracts relevant information about the fragment.

Arguments:

    Args - The packet to examine.

    SourceAddress - Receives the source address of the fragment.

    CurrentDestinationAddress - Receives the current destination address
        of the fragment.

    Identification - Receives the unique fragment identifier.

    FragmentOffset - Receives the offset of this fragment.

    FragmentLength - Receives the length of the payload in this fragment.

    PayloadLength - If this is the last fragment, receives the computed
        total payload length for the fragment's original datagram.

Return Value:

    TRUE if the packet is a fragment and fields were extracted,
    FALSE otherwise.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ULONG AdvancedBytes;
    ULONG HeaderLength;
    IPV6_HEADER UNALIGNED *Ipv6Header;
    PNET_BUFFER NetBuffer;
    UINT8 NextHeader;

    NetBuffer = NetBufferList->FirstNetBuffer;
    Ipv6Header = (IPV6_HEADER UNALIGNED *)HeaderBuffer;
    HeaderLength = sizeof(*Ipv6Header);

    NextHeader = Ipv6Header->NextHeader;
    NetioAdvanceNetBuffer(NetBuffer, HeaderLength);
    AdvancedBytes = HeaderLength;

    while ((NextHeader == IPPROTO_HOPOPTS) ||
           (NextHeader == IPPROTO_ROUTING) ||
           (NextHeader == IPPROTO_DSTOPTS) ||
           (NextHeader == IPPROTO_AH)) {

        IPV6_EXTENSION_HEADER UNALIGNED *ExtensionHeader, ExtensionHeaderBuffer;

        HeaderLength = sizeof(ExtensionHeaderBuffer);
        if (NetBuffer->DataLength < HeaderLength) {
            goto RetreatAndReturn;
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

        if (NetBuffer->DataLength < HeaderLength) {
            goto RetreatAndReturn;
        }
        NetioAdvanceNetBuffer(NetBuffer, HeaderLength);
        AdvancedBytes += HeaderLength;
    }

    if (NextHeader == IPPROTO_FRAGMENT) {

        IPV6_FRAGMENT_HEADER UNALIGNED *FragmentHeader, FragmentHeaderBuffer;

        HeaderLength = sizeof(FragmentHeaderBuffer);
        if (NetBuffer->DataLength < HeaderLength) {
            NextHeader = IPPROTO_NONE;
            goto RetreatAndReturn;
        }

        FragmentHeader =
            NetioGetDataBuffer(
                NetBuffer,
                HeaderLength,
                &FragmentHeaderBuffer,
                1,
                0);

        *SourceAddress = (PUCHAR)&Ipv6Header->SourceAddress;
        *CurrentDestinationAddress = (PUCHAR)&Ipv6Header->DestinationAddress;
        *Identification = FragmentHeader->Id;
        *FragmentOffset = Ip6FragmentOffset(FragmentHeader);
        *FragmentLength = NetBuffer->DataLength - sizeof(*FragmentHeader);
        if (FragmentHeader->MoreFragments) {
            *PayloadLength = (ULONG)-1;
        } else {
            *PayloadLength = *FragmentOffset + *FragmentLength;
        }
    }

RetreatAndReturn:
    NetioRetreatNetBuffer(NetBuffer, AdvancedBytes, 0);

    return (NextHeader == IPPROTO_FRAGMENT);
}


VOID
Ipv6pReassemblyTimeout(
    IN PREASSEMBLY_ELEMENT Element
    )
/*++

Routine Description:
    
    Recreates the first fragment packet and notifies the source of a
    'fragment reassembly time exceeded' error.
    
Arguments:

    Element - Supplies the reassembly element for the fragmented datagram.

Return Value:

    None.
    
Caller IRQL:

    Must be called at DISPATCH level.

--*/
{
    NTSTATUS Status;
    PREASSEMBLY Reassembly;
    PIPV6_HEADER Ipv6;
    PUCHAR LocalAddress;
    PUCHAR RemoteAddress;
    PIP_INTERFACE Interface;
    PIP_COMPARTMENT Compartment;
    PIP_FRAGMENT FirstFragment;
    USHORT PayloadLength;
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    PIPV6_FRAGMENT_HEADER FragmentHeader;
    PIP_LOCAL_ADDRESS Address;
    NL_REQUEST_GENERATE_CONTROL_MESSAGE SendArgs;
    
    DISPATCH_CODE();

    ASSERT(Element->Type == ReassemblyTypeRecord);

    Reassembly = (PREASSEMBLY)Element;
    Ipv6 = &Reassembly->IpHeader.Ipv6;
    LocalAddress = (PUCHAR) &Ipv6->DestinationAddress;
    RemoteAddress = (PUCHAR) &Ipv6->SourceAddress;
    Interface = Reassembly->Interface;
    Compartment = Interface->Compartment;

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_ERROR,
               "IPNG: ReassemblyTimeout Src %!IPV6!, Dst %!IPV6!, Id %x\n",
               RemoteAddress, LocalAddress, Reassembly->Id);

    //
    // Send ICMP error IFF we have received the first (offset-zero) fragment.
    // NB: Checking Marker != 0 is wrong, because we might have
    // received a zero-length first fragment.
    //
    FirstFragment = Reassembly->ContiguousList;
    if (FirstFragment == NULL) {
        return;
    }
    ASSERT(FirstFragment->Offset == 0);

    //
    // We must not send an ICMP error message as a result
    // of receiving any kind of multicast or broadcast.
    //
    if ((Reassembly->Flags & NBL_LINK_LAYER_NOT_UNICAST) != 0) {
        return;
    }

    Address = IppFindAddressOnInterface(Interface, LocalAddress);
    if (Address == NULL) {
        return;
    }
    
    if (NL_ADDRESS_TYPE(Address) == NlatMulticast) {
        goto Done;
    }
    
    //
    // Determine the payload length required for creating the first fragment,
    // i.e. the first buffer in our contiguous list.
    //
    PayloadLength = (Reassembly->UnfragmentableLength +
                     sizeof(IPV6_FRAGMENT_HEADER) +
                     FirstFragment->Length);
    
    Status =
        IppNetAllocate(
            &NetBufferList, 
            &Buffer, 
            0, 
            sizeof(IPV6_HEADER) + PayloadLength);
    if (!NT_SUCCESS(Status)) {
        goto Done;
    }
        
    //
    // Copy the original IPv6 header into the packet.
    // Note that FragmentReceive ensures that
    // Reassembly->IpHeader, Reassembly->UnfragmentableData, and FirstFragment
    // are all consistent.
    //
    RtlCopyMemory(Buffer, Ipv6, sizeof(IPV6_HEADER));
    ASSERT(Ipv6->PayloadLength == RtlUshortByteSwap(PayloadLength));
    Buffer += sizeof(IPV6_HEADER);

    //
    // Copy the unfragmentable data into the packet.
    //
    RtlCopyMemory(Buffer,
                  Reassembly->UnfragmentableData,
                  Reassembly->UnfragmentableLength);
    Buffer += Reassembly->UnfragmentableLength;

    //
    // Create a fragment header in the packet.
    // Note that if the original offset-zero fragment had
    // a non-zero value in the Reserved field, then we will
    // not recreate it properly.  It shouldn't do that.
    //
    FragmentHeader = (PIPV6_FRAGMENT_HEADER) Buffer;
    FragmentHeader->NextHeader = Reassembly->NextHeader;
    FragmentHeader->Reserved = 0;
    FragmentHeader->OffsetAndFlags = 0;
    FragmentHeader->MoreFragments = TRUE;
    FragmentHeader->Id = Reassembly->Id;
    Buffer += sizeof(IPV6_FRAGMENT_HEADER);

    //
    // Copy the original fragment data into the packet.
    //
    RtlCopyMemory(Buffer,
                  MmGetMdlVirtualAddress(&FirstFragment->Mdl),
                  FirstFragment->Length);

    //
    // Truncate the final packet so that it doesn't exceed ICMP error
    // payload size requirements.  We can do pre-calculations to
    // avoid allocating memory, copying and then truncating, but this makes
    // the code simpler given that this is an uncommon case.
    //
    if (NetBufferList->FirstNetBuffer->DataLength >
        Ipv6Global.MaximumIcmpErrorPayloadLength) {
        NetioTruncateNetBuffer(
            NetBufferList->FirstNetBuffer,
            (NetBufferList->FirstNetBuffer->DataLength
             - Ipv6Global.MaximumIcmpErrorPayloadLength));
    }             
    //
    // Send a 'fragment reassembly time exceeded' error.
    // We already hold a reference on the interface,
    // and hence also an implicit reference on the compartment.
    //
    RtlZeroMemory(&SendArgs, sizeof(SendArgs));
    SendArgs.NetBufferList = NetBufferList;
    SendArgs.NlInterface.Interface = (PNL_INTERFACE) Interface;
    SendArgs.NlLocalAddress.LocalAddress = (PNL_LOCAL_ADDRESS) Address;
    SendArgs.RemoteScopeId = scopeid_unspecified;
    SendArgs.RemoteAddress = RemoteAddress;
    SendArgs.NlCompartment.Compartment = (PNL_COMPARTMENT) Compartment;
    SendArgs.Type = ICMP6_TIME_EXCEEDED;
    SendArgs.Code = ICMP6_TIME_EXCEED_REASSEMBLY;
    
    IppSendControl(TRUE, &Ipv6Global, &SendArgs);

Done:
    IppDereferenceLocalAddress(Address);
}
