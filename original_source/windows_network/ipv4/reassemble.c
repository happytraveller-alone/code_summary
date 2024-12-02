/*++

Copyright (c) Microsoft Corporation

Module Name:

    reassemble.c

Abstract:

    This module implements the functions of the IPv4 Reassembler module.

Author:

    Dave Thaler (dthaler) 1-July-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "reassemble.tmh"

IP_INTERNAL_RECEIVE_DATAGRAMS Ipv4pReceiveFragmentList;

IP_RECEIVE_DEMUX Ipv4FragmentDemux = {
    Ipv4pReceiveFragmentList, 
    NULL,
    NULL,
    NULL,
    NULL,
    TRUE
};

PREASSEMBLY
Ipv4pFragmentLookup(
    IN PIP_INTERFACE Interface,
    IN ULONG Id,
    IN UNALIGNED IPV4_HEADER *IP,
    OUT PKIRQL OldIrql
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
    IN_ADDR S, D;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_CONTEXT Context;
    PRTL_HASH_TABLE Table;
    ULONG Key;
    UNALIGNED IN_ADDR *Source;
    UNALIGNED IN_ADDR *Destination;

    Source = &IP->SourceAddress;
    Destination = &IP->DestinationAddress;

    Key = IppReassemblyHashKey(Interface->Compartment, Id, (PUCHAR)IP);

    KeAcquireSpinLock(&Protocol->ReassemblySet.Lock, OldIrql);

    DISPATCH_CODE();

    Table = &Protocol->ReassemblySet.ReassemblyTable;
    RtlInitHashTableContext(&Context);
    for (Curr = RtlLookupEntryHashTable(Table, Key, &Context);
         Curr != NULL;
         Curr = RtlGetNextEntryHashTable(Table, &Context)) {

        Reassembly = CONTAINING_RECORD(Curr, REASSEMBLY, TLink);

        if ((Reassembly->Interface != Interface) ||
            (Reassembly->Id != Id)) {
            continue;
        } 

        S = *Source;
        D = *Destination;

        if (IN4_ADDR_EQUAL(&Reassembly->IpHeader.Ipv4.SourceAddress,
                           &S) &&
            IN4_ADDR_EQUAL(&Reassembly->IpHeader.Ipv4.DestinationAddress,
                           &D)) {
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
Ipv4pReassembleDatagram(
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
    PIP_INTERFACE Interface;
    PIP_INTERFACE_STATISTICS InterfaceStats;
    PIP_GLOBAL_STATISTICS GlobalStats;
    PMDL ThisMdl;
    ULONG Processor;
    PIP_PROTOCOL Protocol;
    NL_ECN_CODEPOINT EcnField;
    
    DISPATCH_CODE();

    PayloadLength = sizeof(IPV4_HEADER) + Reassembly->DataLength + 
        Reassembly->UnfragmentableLength;
    ASSERT(PayloadLength <= MAX_IPV4_PACKET);
    TotalLength = PayloadLength;
    UnfragmentableLength = sizeof(IPV4_HEADER) + 
        Reassembly->UnfragmentableLength;

    Interface = Control->DestLocalAddress->Interface;
    Protocol = Interface->Compartment->Protocol;

    Processor = KeGetCurrentProcessorNumber();
    InterfaceStats = Interface->PerProcessorStatistics[Processor];
    GlobalStats = &Protocol->PerProcessorStatistics[Processor];

    //
    // Allocate memory for buffer and copy fragment data into it. The
    // completion context is the reassembly pointer.
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
    // data into the new packet.
    //
    Reassembly->IpHeader.Ipv4.TotalLength =
        RtlUshortByteSwap((USHORT)PayloadLength);
    Reassembly->IpHeader.Ipv4.FlagsAndOffset = 0;

    RtlCopyMemory(ReassemblyBuffer, 
                  &Reassembly->IpHeader, 
                  sizeof(IPV4_HEADER));

    RtlCopyMemory(ReassemblyBuffer + sizeof(IPV4_HEADER), 
                  Reassembly->UnfragmentableData,
                  Reassembly->UnfragmentableLength);

    //
    // Fix up the IP header checksum.
    //
    Ipv4pFillPacketChecksum(ReassemblyNb);

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
                   "IPNG: IPv4 reassembly failure: Packets don't add up\n");
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
            ASSERT(ReassControl->Next == NULL);
            IppCompleteAndFreePacketList(ReassControl, FALSE);
            goto ExitAllocationFailure;
        }

        rrc->Context = ReassControl;
        rrc->WorkQueueItem = IoAllocateWorkItem(IppDeviceObject);
        if (rrc->WorkQueueItem == NULL) {
            ASSERT(ReassControl->Next == NULL);
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
               "IPNG: Failure allocating IPv4 reassembly structures.\n");
    
ExitUpdateFailureStatistics:    
    InterfaceStats->ReassemblyFailures++;
    GlobalStats->ReassemblyFailures++;
}


VOID
NTAPI
Ipv4pReceiveFragment(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    Handle a IPv4 datagram fragment.
  
    This is the routine called by IPv4 when it receives a fragment of an
    IPv4 datagram, i.e. a next header value of 44.  Here we attempt to
    reassemble incoming fragments into complete IPv4 datagrams.
  
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
    PREASSEMBLY Reassembly;
    UINT16 FragmentOffset;
    UINT16 PayloadLength;
    PIP_FRAGMENT Shim, ThisShim, *MoveShim;
    PNET_BUFFER_LIST BufferList = Packet->NetBufferList;
    PNET_BUFFER Buffer = BufferList->FirstNetBuffer;
    PIP_INTERFACE_STATISTICS InterfaceStats;
    PIP_GLOBAL_STATISTICS GlobalStats;
    UNALIGNED IPV4_HEADER *IP;
    SIZE_T BytesCopied, MdlSize, ShimSize;
    ULONG Processor;
    IP_FILTER_ACTION Action;
    PIP_PROTOCOL Protocol;
    KIRQL OldIrql;
    NTSTATUS Status;

    ASSERT(Buffer->Next == NULL);

    if (Packet->PromiscuousOnlyReceive) {
        //
        // If the packet is not really locally-destined, then just
        // deliver the fragment up to raw.
        //
        Packet->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        return;
    }

    IP = (UNALIGNED IPV4_HEADER *) Packet->IP;    

    if ((IP->Protocol == IPPROTO_FRAGMENT) ||
        (Packet->NlcReceiveDatagram.NetworkLayerHeadersSize != 
         Ip4HeaderLengthInBytes(IP))) {
        //
        // This handler must not handle wire packets with a protocol of
        // IPPROTO_FRAGMENT.  It only handles IPv4 packets that have the MF
        // the MF bit or a non-zero fragment offset.
        // The header length check covers the case when
        // IPPROTO_FRAGMENT was used as a next header value
        // in one of the encapsulation headers. This condition
        // is also valid in case both fragmentation and routing
        // header are present.
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

    FragmentOffset = Ip4FragmentOffset(IP);

    Action =
        IppInspectFragmentIn(
            IPPROTO_IP,
            Packet->SourceAddress.Address,
            (PNL_LOCAL_ADDRESS) Packet->DestLocalAddress,
            (PNL_INTERFACE)Packet->SourceSubInterface->Interface,
            Packet->SourceSubInterface->Index,
            Packet->NlcReceiveDatagram.Loopback,
            Packet->NlcReceiveDatagram.NetworkLayerHeadersSize,
            IP->Identification,
            FragmentOffset,
            Buffer->DataLength,
            BufferList);
    if (Action >= IpFilterDrop) {
        goto Failed;
    }
    ASSERT(Action == IpFilterAllow);

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
    if (Packet->Flags & PACKET_JUMBO_OPTION) {
        DbgPrint("FragmentReceive: jumbo fragment\n");

    BadFragment:
        //
        // The NextHeader value passed to Icmpv4pSendError
        // is IPPROTO_FRAGMENT because we haven't moved
        // past the fragment header yet.
        //
        Icmpv4pSendError(
            Packet,
            ICMP4_PARAM_PROB,
            ICMP4_PARAMPROB_HEADER,
            Packet->NetworkLayerHeadersSize,
            IPPROTO_FRAGMENT, 
            FALSE);
        Packet->NetBufferList = NULL;
        goto Failed; // Drop packet.
    }
#endif

    //
    // Lookup this fragment triple (Source Address, Destination
    // Address, and Identification field) per-interface to see if
    // we've already received other fragments of this packet.
    //
    Reassembly = Ipv4pFragmentLookup(Interface, 
                                     IP->Identification,
                                     IP,
                                     &OldIrql);

    if (Reassembly == NULL) {
        //
        // This is the first fragment of this datagram we've received.
        // Allocate a reassembly structure to keep track of the pieces
        // and add it to the front of the ReassemblySet.
        // Also acquires the reassembly record lock and
        // releases the global reassembly list lock (which we hold).
        //
        Reassembly =
            IppCreateInReassemblySet(
                &Protocol->ReassemblySet,
                Packet->IP,
                Interface,
                IP->Identification, 
                OldIrql);
        if (Reassembly == NULL) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                       "IPNG: Failure allocating IPv6 reassembly structure\n");
            goto Failed;
        }
    } else {
        //
        // Sanity check that the protocols of the incoming packet and
        // previous packets are the same.
        //
        if (Reassembly->IpHeader.Ipv4.Protocol != IP->Protocol) {
            IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                       (PREASSEMBLY_ELEMENT)Reassembly, 
                                       OldIrql);
            IppSendError(
                FALSE,
                &Ipv4Global,
                Packet,
                ICMP4_PARAM_PROB,
                0,
                RtlUlongByteSwap(
                    (Packet->NlcReceiveDatagram.NetworkLayerHeadersSize +
                     (UINT) FIELD_OFFSET(IPV4_HEADER, Protocol))),
                FALSE);
            goto Failed;
        }
            
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
    Reassembly->Flags |= (1 << IP->EcnField);
    
    //
    // Calculate the payload size this fragment is transporting.  If this
    // is the first and non-duplicate fragment of the datagram then include
    // the size of the options in the calculation; otherwise we ignore the
    // options since they will not become part of the reassembled IP packet.
    //
    if ((FragmentOffset == 0) && (Reassembly->Marker == 0)) {
        ASSERT(Reassembly->ContiguousList == NULL);
        PayloadLength = MAX_IPV4_PACKET - Ip4HeaderLengthInBytes(IP);
    }
    else {
        PayloadLength = MAX_IPV4_PAYLOAD;
    }
    
    //
    // Send ICMP error if this fragment causes the total packet length
    // to exceed the maximum IPv4 payload size.  Set ICMP pointer equal to the
    // offset to the Fragment Offset field.
    //
    if ((FragmentOffset + Buffer->DataLength) > PayloadLength) {
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly, 
                                   OldIrql);
        IppSendError(
            FALSE,
            &Ipv4Global,
            Packet,
            ICMP4_PARAM_PROB,
            0,
            RtlUlongByteSwap(
                (Packet->NlcReceiveDatagram.NetworkLayerHeadersSize +
                 (UINT) FIELD_OFFSET(IPV4_HEADER, FlagsAndOffset))),
            FALSE);
        goto Failed;
    }

    //
    // Check for IPSec integrity. 
    //
    Status = IPsecVerifyFragment(&Reassembly->IPSecContext, 
                                 BufferList,
                                 Protocol->Level,
                                 (UCHAR *)&IP->SourceAddress,
                                 (UCHAR *)&IP->DestinationAddress);
                                                
    if (!NT_SUCCESS(Status)) {
        //
        // IPSec-status of this fragment is different from the
        // IPSec-status of the fragment we received first.
        // We don't allow mixed reassemblies.
        //
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Received mixed IPSec and non-IPSec IPv4 fragments\n");
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly, 
                                   OldIrql);
        goto DropFragment;
    }

    if (Buffer->DataLength == 0) {
        //
        // We disallow fragments that do not actually
        // carry any data for DoS protection.
        //
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Received zero length IPv4 fragment\n");
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
    if (!IP->MoreFragments) {
        if (Reassembly->DataLength != (UINT)-1) {
            //
            // We already received a last fragment.
            // This can happen if a packet is duplicated.
            //
            if (FragmentOffset + Buffer->DataLength != Reassembly->DataLength) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Received duplicate last IPv4 fragment "
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
                &Ipv4Global,
                Packet,
                ICMP4_PARAM_PROB,
                0,
                RtlUlongByteSwap(FIELD_OFFSET(IPV4_HEADER, TotalLength)),
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
                       "IPNG: Received IPv4 fragment beyond data length\n");
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
                   "IPNG: Failure allocating shim for IPv4 reassembly\n");
        IppDeleteFromReassemblySet(&Protocol->ReassemblySet, 
                                   (PREASSEMBLY_ELEMENT)Reassembly,
                                   OldIrql);
        goto Failed;
    }
    MmInitializeMdl(&Shim->Mdl, 
                    (PVOID)(((PUCHAR)&Shim->Mdl) + MdlSize), 
                    Buffer->DataLength);
    MmBuildMdlForNonPagedPool(&Shim->Mdl);

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
            Reassembly->NextHeader = IP->Protocol;

            //
            // Grab the unfragmentable data.
            // Unfragmentable portion is just the length of IP options.
            //
            Reassembly->UnfragmentableLength = 
                (USHORT)Ip4HeaderLengthInBytes(IP) -
                sizeof(IPV4_HEADER);

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
                               "IPNG: Failure allocating space for IPv4 "
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
                    (Buffer->DataOffset - 
                     Packet->NlcReceiveDatagram.NetworkLayerHeadersSize) +
                    sizeof(IPV4_HEADER),          // Offset.
                    Reassembly->UnfragmentableData,   // Flat buffer.
                    Reassembly->UnfragmentableLength, // Length.
                    &BytesCopied);
                ASSERT(BytesCopied == Reassembly->UnfragmentableLength);
            }            

            //
            // We need to have the IP header of the offset-zero fragment.
            // (Every fragment normally will have the same IP header,
            // except for length and options,
            // but they might not.) Ipv4pReassembleDatagram and
            // CreateFragmentPacket both need it.
            //
            // Of the 20 bytes in the header, the 8 bytes in the source
            // and destination addresses are already correct.
            // So we just copy the other 12 bytes now.
            //
            RtlCopyMemory(&Reassembly->IpHeader, Packet->IP, 12);

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
                           "IPNG: Received overlapping IPv4 fragment\n");
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
                               "IPNG: Received duplicate IPv4 fragment\n");
                    ExFreePool(Shim);
                    KeReleaseSpinLock(&Reassembly->Lock, OldIrql);
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


    IppIncreaseReassemblySize(
        &Protocol->ReassemblySet,
        (PREASSEMBLY_ELEMENT)Reassembly, 
        REASSEMBLY_SIZE_FRAG + Buffer->DataLength,
        Buffer->DataLength);

    if (Reassembly->Marker == Reassembly->DataLength) {
        //
        // We have received all the fragments.
        // Because of the overlapping/data-length/zero-size sanity checks
        // above, when this happens there should be no fragments
        // left on the gap list. However, Ipv4pReassembleDatagram does not
        // rely on having an empty gap list.
        //
        ASSERT(Reassembly->GapList == NULL);
        Ipv4pReassembleDatagram(Packet, Reassembly, OldIrql);
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
Ipv4pReceiveFragmentList(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
{
    PIP_REQUEST_CONTROL_DATA Curr;

    for (Curr = Args; Curr != NULL; Curr = Curr->Next) {
        if ((Curr->NetBufferList == NULL) ||
            (!NT_SUCCESS(Curr->NetBufferList->Status)) ||
            (!Ipv4Global.ReceiveDemux[Curr->NlcReceiveDatagram.NextHeaderValue].
            IsExtensionHeader)) {
            //
            // Skip datagrams with errors or upper layer extension headers. 
            //
            continue;
        }
        
        if (Curr->NlcReceiveDatagram.NextHeaderValue != IPPROTO_FRAGMENT) {
            break;
        }

        Ipv4pReceiveFragment(Curr);
    }
}


BOOLEAN
Ipv4pIsFragment(
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
    IPV4_HEADER UNALIGNED *Ipv4Header = (IPV4_HEADER UNALIGNED *)HeaderBuffer;

    if (!IPV4_IS_FRAGMENT(Ipv4Header)) {
        return FALSE;
    }

    *SourceAddress = (PUCHAR)&Ipv4Header->SourceAddress;
    *CurrentDestinationAddress = (PUCHAR)&Ipv4Header->DestinationAddress;
    *Identification = Ipv4Header->Identification;
    *FragmentOffset = Ip4FragmentOffset(Ipv4Header);
    *FragmentLength =
        NetBufferList->FirstNetBuffer->DataLength -
        Ip4HeaderLengthInBytes(Ipv4Header);
    if (Ipv4Header->MoreFragments) {
        *PayloadLength = (ULONG)-1;
    } else {
        *PayloadLength = *FragmentOffset + *FragmentLength;
    }

    return TRUE;
}


VOID
Ipv4pReassemblyTimeout(
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
    PIPV4_HEADER Ipv4;
    PUCHAR LocalAddress;
    PUCHAR RemoteAddress;
    PIP_INTERFACE Interface;
    PIP_COMPARTMENT Compartment;
    PIP_FRAGMENT FirstFragment;
    USHORT TotalLength;
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    PIP_LOCAL_ADDRESS Address;
    NL_REQUEST_GENERATE_CONTROL_MESSAGE SendArgs;
    NL_ADDRESS_TYPE AddressType;

    DISPATCH_CODE();

    ASSERT(Element->Type == ReassemblyTypeRecord);

    Reassembly = (PREASSEMBLY)Element;
    Ipv4 = &Reassembly->IpHeader.Ipv4;
    LocalAddress = (PUCHAR) &Ipv4->DestinationAddress;
    RemoteAddress = (PUCHAR) &Ipv4->SourceAddress;
    Interface = Reassembly->Interface;
    Compartment = Interface->Compartment;

    NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_ERROR,
               "IPNG: ReassemblyTimeout Src %!IPV4!, Dst %!IPV4!, Id %x\n",
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
    
    AddressType = NL_ADDRESS_TYPE(Address);
    if ((AddressType == NlatMulticast) || (AddressType == NlatBroadcast)) {
        goto Done;
    }
    
    //
    // Determine the payload length required for creating the first fragment,
    // i.e. the first buffer in our contiguous list.
    //
    TotalLength = (sizeof(IPV4_HEADER) +
                   Reassembly->UnfragmentableLength +
                   FirstFragment->Length);
    
    Status = IppNetAllocate(&NetBufferList, &Buffer, 0, TotalLength);
    if (!NT_SUCCESS(Status)) {
        goto Done;
    }
        
    //
    // Copy the original Ipv4 header into the packet.
    // Note that FragmentReceive ensures that
    // Reassembly->IpHeader, Reassembly->UnfragmentableData, and FirstFragment
    // are all consistent.
    //
    RtlCopyMemory(Buffer, Ipv4, sizeof(IPV4_HEADER));
    ASSERT(Ipv4->TotalLength == RtlUshortByteSwap(TotalLength));
    Buffer += sizeof(IPV4_HEADER);

    //
    // Copy the unfragmentable data into the packet.
    //
    RtlCopyMemory(Buffer,
                  Reassembly->UnfragmentableData,
                  Reassembly->UnfragmentableLength);
    Buffer += Reassembly->UnfragmentableLength;

    //
    // Verify the fragmentation information in the packet.
    //
    ASSERT(Ipv4->MoreFragments);
    ASSERT(Ipv4->Protocol == Reassembly->NextHeader);
    ASSERT(Ipv4->Identification == Reassembly->Id);

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
        Ipv4Global.MaximumIcmpErrorPayloadLength) {
        NetioTruncateNetBuffer(
            NetBufferList->FirstNetBuffer,
            (NetBufferList->FirstNetBuffer->DataLength
             - Ipv4Global.MaximumIcmpErrorPayloadLength));
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
    SendArgs.Type = ICMP4_TIME_EXCEEDED;
    SendArgs.Code = ICMP4_TIME_EXCEED_REASSEMBLY;
    
    IppSendControl(TRUE, &Ipv4Global, &SendArgs);

Done:    
    IppDereferenceLocalAddress(Address);
}
