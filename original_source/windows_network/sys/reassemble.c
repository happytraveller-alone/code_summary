/*++

Copyright (c) Microsoft Corporation

Module Name:

    reassemble.c

Abstract:

    This module implements protocol-independent functions of the 
    Reassembler module.

Author:

    Dave Thaler (dthaler) 10-July-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "reassemble.tmh"
#include "subr.h"

NETIO_NET_BUFFER_LIST_COMPLETION_ROUTINE IppFragmentGroupNetBufferListsComplete;

#define CurrentSystemTimeToMs(Time) ((Time).QuadPart / 100000)

//
// Threshold for minimum incoming rate of useful data, bytes per ms.
//
#define REASSEMBLY_MIN_RATE 50

//
// Threshold for minimum ratio of useful data to overheads.
//
#define REASSEMBLY_DATA_RATIO_MIN 6 

ULONG 
IppReassemblyHashKey(
    IN PIP_COMPARTMENT Compartment, 
    IN ULONG Id, 
    IN PUCHAR IP
    )
/*++

Routine Description:
    
    Computes the hash key for reassembly/fragment group entry,
    given the hash key context, entry ID and source and destination 
    addresses.
    
Arguments:

    Compartment - Required to get the IP protocol version/addresses lengths.

    Id - Identification field from the fragmentation headers.

    IP - Pointer to the IP header, to get the source and destination addresses
    from.
    
Return Value:

    The hash key value.
    
--*/
{
    PUCHAR Src, Dst;
    ULONG Size, Key; 

    if(IS_IPV4_PROTOCOL(Compartment->Protocol)) {
        Src = (PUCHAR)&((UNALIGNED IPV4_HEADER *)IP)->SourceAddress;
        Dst = (PUCHAR)&((UNALIGNED IPV4_HEADER *)IP)->DestinationAddress;

    } else {
        ASSERT(IS_IPV6_PROTOCOL(Compartment->Protocol));
        Src = (PUCHAR)&((UNALIGNED IPV6_HEADER *)IP)->SourceAddress;
        Dst = (PUCHAR)&((UNALIGNED IPV6_HEADER *)IP)->DestinationAddress;
    }

    Size = Compartment->Protocol->Characteristics->AddressBytes;

    Key = RtlCompute37Hash(g_37HashSeed, Src, Size);

    Key = RtlCompute37Hash(Key, Dst, Size);

    Key = RtlCompute37Hash(Key, (UCHAR *)&Id, sizeof(Id));

    Key |= 0x80000000;

    return Key;
}

NTSTATUS
IppInitializeReassembler(
    OUT PREASSEMBLY_SET Set
    )
/*++

Routine Description:
    
    Initialize data structures required for reassembly.
    
Arguments:

    Set - Returns an initialized reassembly set.
    
Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    BOOLEAN Success;
    PRTL_HASH_TABLE HashTablePointer;

    HashTablePointer = &Set->ReassemblyTable;

    Success = RtlCreateHashTable(&HashTablePointer, 0, 0);
    if (!Success) {

        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                   "IPNG: Error initializing reassembler. Failed to create reassembly hash table.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    HashTablePointer = &Set->FragmentGroupTable;

    Success = RtlCreateHashTable(&HashTablePointer, 0, 0);
    if (!Success) {
        RtlDeleteHashTable(&Set->ReassemblyTable);
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                   "IPNG: Error initializing reassembler. Failed to create fragment group hash table.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Set->TimerTable = TtCreateTable(DEFAULT_REASSEMBLY_TIMEOUT, FALSE);
    if (Set->TimerTable == NULL) {
        RtlDeleteHashTable(&Set->ReassemblyTable);
        RtlDeleteHashTable(&Set->FragmentGroupTable);
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                   "IPNG: Error initializing reassembler. Failed to create timer table.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }    

    KeInitializeSpinLock(&Set->Lock);
    KeInitializeSpinLock(&Set->LockSize);
    Set->Limit = IppDefaultMemoryLimitOfBuffers;

    return STATUS_SUCCESS;
}


VOID
IppUninitializeReassembler(
    IN PREASSEMBLY_SET Set
    )
/*++

Routine Description:
    
    Cleanup the reassembly data structures and prepare for unload.
  
Arguments:

    Set - Supplies the reassembly set to cleanup.
    
Return Value:

    None.

--*/ 
{
    ASSERT(Set->Size == 0);
    TtDestroyTable(Set->TimerTable);
    KeUninitializeSpinLock(&Set->Lock);
    KeUninitializeSpinLock(&Set->LockSize);

    ASSERT(RtlActiveEnumeratorsHashTable(&Set->ReassemblyTable) == 0);
    ASSERT(RtlActiveEnumeratorsHashTable(&Set->FragmentGroupTable) == 0);

    RtlDeleteHashTable(&Set->ReassemblyTable);
    RtlDeleteHashTable(&Set->FragmentGroupTable);
}


VOID
IppInsertReassembly(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element
    )
/*++

Routine Description:
    
    Insert the element in the reassembly set.
    
Arguments:

    Set - Supplies the reassembly set to insert the record in.

    Element - Supplies the element to insert.
    
Return Value:

    None.
    
Caller Lock:

    Called with the global reassembly list lock held.
    The element lock may be held.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.
  
--*/
{
    ASSERT_SPIN_LOCK_HELD(&Set->Lock);
    
    if (Element->Type == ReassemblyTypeRecord) {
        RtlInsertEntryHashTable(
            &Set->ReassemblyTable,
            &Element->TLink,
            HASH_ENTRY_KEY(&Element->TLink),
            NULL);
    } else {
        ASSERT(Element->Type == ReassemblyTypeGroup);
        RtlInsertEntryHashTable(
            &Set->FragmentGroupTable,
            &Element->TLink,
            HASH_ENTRY_KEY(&Element->TLink),
            NULL);
    }

    TtStartTimer(
        Set->TimerTable,
        &Element->Timer,
        DEFAULT_REASSEMBLY_TIMEOUT);

    KeAcquireSpinLockAtDpcLevel(&Set->LockSize);
    Set->Size += Element->Size;
    KeReleaseSpinLockFromDpcLevel(&Set->LockSize);
}


VOID
IppRemoveReassembly(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element
    )
/*++

Routine Description:
    
    Remove the element from the reassembly set.
    
Arguments:

    Set - Supplies the reassembly set to remove the record from.

    Element - Supplies the element to remove.
    
Return Value:

    None.
    
Caller Lock:

    Called with the global reassembly list lock held.
    The element lock may be held.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.
  
--*/
{
    ASSERT_SPIN_LOCK_HELD(&Set->Lock);
    
    if (Element->Type == ReassemblyTypeRecord) {
        RtlRemoveEntryHashTable(
            &Set->ReassemblyTable,
            &Element->TLink,
            NULL);
    } else {
        ASSERT(Element->Type == ReassemblyTypeGroup);
        RtlRemoveEntryHashTable(
            &Set->FragmentGroupTable,
            &Element->TLink,
            NULL);
    }

    if (TtIsTimerActive(&Element->Timer)) {
        TtStopTimer(Set->TimerTable, &Element->Timer);
    }

    KeAcquireSpinLockAtDpcLevel(&Set->LockSize);
    Set->Size -= Element->Size;
    KeReleaseSpinLockFromDpcLevel(&Set->LockSize);
}

NETIO_INLINE
VOID
IppTimeStampReassemblyElement(
    IN PREASSEMBLY_ELEMENT Element
    )
{
    LARGE_INTEGER CurrentTime;
    ULONG Time;

    KeQuerySystemTime(&CurrentTime);
    Time = (ULONG) CurrentSystemTimeToMs(CurrentTime);

    Element->StartTime = Time;
}

PREASSEMBLY
IppCreateReassembly(
    IN PUCHAR IpHeader,
    IN PIP_INTERFACE Interface,
    IN ULONG Id
    )
/*++

Routine Description:

    Create a reassembly record.

Arguments:

    IpHeader - Supplies the IP Header for the IP packet.

    Interface - Supplies the interface over which the packet arrived.

    Id - Supplies the identifier for the IP packet.
    
Return Value:

    Reassembly record, or NULL.

--*/ 
{
    PREASSEMBLY Reassembly;
    ULONG Key;
    
    Reassembly = ExAllocatePoolWithTagPriority(NonPagedPool, 
                                               sizeof(REASSEMBLY),
                                               IpReassemblyPoolTag, 
                                               LowPoolPriority);
    if (Reassembly != NULL) {
        KeInitializeSpinLock(&Reassembly->Lock);
        Reassembly->Type = ReassemblyTypeRecord;
        Reassembly->State = ReassemblyStateNormal;
        Reassembly->DataReceived = 0;
    
        RtlCopyMemory(&Reassembly->IpHeader,
                      IpHeader,
                      Interface->Compartment->Protocol->HeaderSize);
        Reassembly->Interface = Interface;
        Reassembly->Id = Id;
        Reassembly->ContiguousList = NULL;
#if DBG
        Reassembly->ContiguousEnd = NULL;
#endif
        Reassembly->GapList = NULL;
        Reassembly->Marker = 0;
        Reassembly->MaxGap = 0;
        //
        // We must initialize DataLength to an invalid value.
        // Initializing to zero doesn't work.
        //
        Reassembly->DataLength = (UINT)-1;
        Reassembly->UnfragmentableLength = 0;
        Reassembly->UnfragmentableData = NULL;
        Reassembly->Flags = 0;
        Reassembly->Size = REASSEMBLY_SIZE_PACKET;
        IppTimeStampReassemblyElement((PREASSEMBLY_ELEMENT) Reassembly);

        Key = IppReassemblyHashKey(
                  Interface->Compartment,
                  Id, 
                  (PUCHAR)&Reassembly->IpHeader);

        HASH_ENTRY_KEY(&Reassembly->TLink) =  Key;
        IPsecCreateReassemblyContext(&Reassembly->IPSecContext);
    }

    return Reassembly;
}


VOID
IppDeleteReassembly(
    IN PREASSEMBLY Reassembly
    )
/*++

Routine Description:

    Delete a reassembly record.

Arguments:

    Reassembly - Supplies the reassembly to delete.
    
Return Value:

    None.
    
--*/ 
{
    PIP_FRAGMENT ThisShim, PrevShim;

    ASSERT(!TtIsTimerActive(&Reassembly->Timer));
    
    //
    // Call IPSec to free resources if it used any.
    //
    IPsecDestroyReassemblyContext(&Reassembly->IPSecContext);

    //
    // Free ContiguousList if populated.
    //
    PrevShim = ThisShim = Reassembly->ContiguousList;
    while (ThisShim != NULL) {
        PrevShim = ThisShim;
        ThisShim = ThisShim->Next;
        ExFreePool(PrevShim);
    }

    //
    // Free GapList if populated.
    //
    PrevShim = ThisShim = Reassembly->GapList;
    while (ThisShim != NULL) {
        PrevShim = ThisShim;
        ThisShim = ThisShim->Next;
        ExFreePool(PrevShim);
    }

    //
    // Free unfragmentable data.
    //
    if (Reassembly->UnfragmentableData != NULL) {
        ExFreePool(Reassembly->UnfragmentableData);
    }

    KeUninitializeSpinLock(&Reassembly->Lock);
    ExFreePool(Reassembly);
}


VOID
IppDeleteFragmentGroup(
    IN PFRAGMENT_GROUP Group
    )
/*++

Routine Description:

    Delete a fragment group.

Arguments:

    Group - Supplies the fragment group to delete.
    
Return Value:

    None.
    
--*/ 
{
    ASSERT(!TtIsTimerActive(&Group->Timer));

    while (Group->ArrivalList != NULL) {
        PIP_FRAGMENT Next = Group->ArrivalList;
        Group->ArrivalList = Next->Next;
        ExFreePool(Next);
    }
    
    KeUninitializeSpinLock(&Group->Lock);
    ExFreePool(Group);
}


PREASSEMBLY
IppCreateInReassemblySet(
    IN PREASSEMBLY_SET Set,
    IN PUCHAR IpHeader,
    IN PIP_INTERFACE Interface,
    IN ULONG Id,
    IN KIRQL OldIrql
    )
/*++

Routine Description:

    Create a reassembly record and insert it in the reassembly set.
    It must NOT already be in the set.

Arguments:

    Set - Supplies the reassembly set to insert the record in.
    
    IpHeader - Supplies the IP Header for the IP packet.

    Interface - Supplies the interface over which the packet arrived.

    Id - Supplies the identifier for the IP packet.

    OldIrql - Supplies the original IRQL.  This is used if all the locks are
        getting released. 

Return Value:

    Reassembly record, or NULL.

Caller Lock:

    Called with the global reassembly list lock held.
    Returns with the reassembly record lock held on success.
    Releases the global reassembly list lock.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.
  
--*/
{
    PREASSEMBLY Reassembly;

    ASSERT_SPIN_LOCK_HELD(&Set->Lock);
    
    //
    // Create the reassembly record.
    //
    Reassembly = IppCreateReassembly(IpHeader, Interface, Id);
    if (Reassembly != NULL) {
        IppInsertReassembly(Set, (PREASSEMBLY_ELEMENT)Reassembly);

        //
        // We must acquire the reassembly record lock
        // *before* releasing the global reassembly list lock,
        // to prevent the reassembly from diappearing underneath us.
        //
        KeAcquireSpinLockAtDpcLevel(&Reassembly->Lock);
        KeReleaseSpinLockFromDpcLevel(&Set->Lock);
    } else {
        KeReleaseSpinLock(&Set->Lock, OldIrql);        
    }
    
    return Reassembly;
}


VOID
IppRemoveFromReassemblySet(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element, 
    IN KIRQL OldIrql
    )
/*++

Routine Description:

    Remove the element from the reassembly set.
    The element MUST be in the reassembly set.

Arguments:

    Set - Supplies the reassembly set to remove the record from.

    Element - Supplies the element to remove.

    OldIrql - Supplies the original IRQL.

Return Value:

    None.
    
Caller Lock:

    Called with the element lock held,
    but not the global reassembly list lock. 
    Returns with no lock held. 

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/ 
{
    ASSERT_SPIN_LOCK_HELD(&Element->Lock);
    
    //
    // Mark the element as being deleted.
    // This will prevent someone else from freeing it.
    //
    ASSERT(Element->State == ReassemblyStateNormal);
    Element->State = ReassemblyStateDeleting;
    KeReleaseSpinLock(&Element->Lock, OldIrql);

    KeAcquireSpinLock(&Set->Lock, &OldIrql);
    KeAcquireSpinLockAtDpcLevel(&Element->Lock);
    ASSERT((Element->State == ReassemblyStateDeleting) ||
           (Element->State == ReassemblyStateRemoved));

    //
    // Remove the element from the list,
    // if someone else hasn't already removed it.
    //
    if (Element->State != ReassemblyStateRemoved) {
        IppRemoveReassembly(Set, Element);
        Element->InterfaceOrCompartment = NULL;
    }

    KeReleaseSpinLockFromDpcLevel(&Element->Lock);
    KeReleaseSpinLock(&Set->Lock, OldIrql);
}


VOID
IppDeleteFromReassemblySet(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element, 
    IN KIRQL OldIrql
    )
/*++

Routine Description:

    Remove and delete the element.
    The element MUST be in the reassembly set.

Arguments:

    Set - Supplies the reassembly set to delete the record from.

    Element - Supplies the element to delete.

    OldIrql - Supplies the original IRQL.

Return Value:

    None.
    
Caller Lock:

    Called with the element lock held,
    but not the global reassembly list lock. 
    Returns with no lock held. 

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/ 
{
    ASSERT_SPIN_LOCK_HELD(&Element->Lock);

    //
    // Remove the element.
    //
    IppRemoveFromReassemblySet(Set, Element, OldIrql);    

    //
    // Delete the element.
    //
    if (Element->Type == ReassemblyTypeRecord) {
        IppDeleteReassembly((PREASSEMBLY)Element);
    } else {
        ASSERT(Element->Type == ReassemblyTypeGroup);
        IppDeleteFragmentGroup((PFRAGMENT_GROUP)Element);
    }
}


PREASSEMBLY_ELEMENT
IppFindBestDropCandidateInSet(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element,
    IN KIRQL OldIrql
    )
/*++

Routine Description:
    
    Finds the best candidate to be dropped. Like in W2K3,
    we are considering a single hash table cell.

Arguments:

    Set - Supplies the set.

    Element - Supplies the element that caused the quota check.

    OldIrql - Irql to return to if all locks are released.

Return Value:

    The best found candidate. NULL if there is no candidate over the
    thresholds.
    
Caller Lock:

    Called with the Element lock held,
    but not the global reassembly list lock. 
    Releases Element lock.
    Returns with Candidate locks held, or w/o lock
    if no Candidate found.
  
Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    ULONG_PTR  Key;
    PREASSEMBLY_ELEMENT CurrElement, Candidate ;
    PREASSEMBLY_ELEMENT RatioDropCandidate = NULL, RateDropCandidate = NULL;
    PRTL_HASH_TABLE_ENTRY Curr ;
    RTL_HASH_TABLE_CONTEXT Context;
    PRTL_HASH_TABLE Table;
    LARGE_INTEGER CurrentTime;
    ULONG Time;
    ULONG Rate, DropCandidateRate = 0;
    ULONG DataRatio, DropCandidateRatio = 0;


    KeQuerySystemTime(&CurrentTime);
    Time = (ULONG) CurrentSystemTimeToMs(CurrentTime);

    Key = HASH_ENTRY_KEY(&Element->TLink);
    KeReleaseSpinLock(&Element->Lock, OldIrql);

    KeAcquireSpinLock(&Set->Lock, &OldIrql);
    Table = &Set->ReassemblyTable;
    RtlInitHashTableContext(&Context);

    for (Curr = RtlLookupEntryHashTable(Table, Key, &Context);
         Curr != NULL;
         Curr = RtlGetNextEntryHashTable(Table, &Context)) {

        CurrElement = CONTAINING_RECORD(Curr, REASSEMBLY_ELEMENT, TLink);
        Candidate = CurrElement;

        if(Candidate->State != ReassemblyStateNormal) {
            continue;
        }

        if(Time == CurrElement->StartTime) {
            Rate = CurrElement->DataReceived;
        } else {
            Rate = 
                CurrElement->DataReceived / 
                ((ULONG)(Time - CurrElement->StartTime));
        }

        DataRatio = 
            CurrElement->DataReceived / 
            (CurrElement->Size - CurrElement->DataReceived);

        //
        // We only consider the element as a candidate if
        // it falls under at least one of the limits.
        //
        if ((Rate < REASSEMBLY_MIN_RATE) &&
            ((RateDropCandidate == NULL) || (DropCandidateRate > Rate))) {
            RateDropCandidate = CurrElement;
            DropCandidateRate = Rate;
        }

        if ((DataRatio <  REASSEMBLY_DATA_RATIO_MIN) &&
            ((RatioDropCandidate == NULL) || (DataRatio < DropCandidateRatio))) {
            RatioDropCandidate = CurrElement;
            DropCandidateRatio = DataRatio;
        }
    }
    RtlReleaseHashTableContext(&Context);

    if (RateDropCandidate != NULL) {
        Candidate = RateDropCandidate;
    } else {
        Candidate = RatioDropCandidate;
    }

    if (Candidate != NULL) {
        KeAcquireSpinLockAtDpcLevel(&Candidate->Lock);
        if (Candidate->State != ReassemblyStateNormal)  {
            KeReleaseSpinLockFromDpcLevel(&Candidate->Lock);
            Candidate = NULL;
        }
    }

    if (Candidate != NULL) {
        KeReleaseSpinLockFromDpcLevel(&Set->Lock);
    } else {
        KeReleaseSpinLock(&Set->Lock, OldIrql);
    }

    return Candidate;
}

VOID
IppCheckReassemblyQuota(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element, 
    IN KIRQL OldIrql
    )
/*++

Routine Description:
    
    Delete a element if necessary,
    to keep the reassembly buffering under quota.

Arguments:

    Set - Supplies the set.

    Element - Supplies the element to possibly delete.
    
    OldIrql - Supplies the original IRQL.

Return Value:

    None.
    
Caller Lock:

    Called with the element lock held,
    but not the global reassembly list lock. 
    Returns with no lock held.
  
Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PREASSEMBLY_ELEMENT DropCandidate; 
    BOOLEAN Prune = FALSE;
    ULONG Threshold = Set->Limit / 2;

    ASSERT_SPIN_LOCK_HELD(&Element->Lock);    
    
    //
    // Decide whether to drop the element based on a RED-like
    // algorithm.  If the total size is less than 50% of the max, never
    // drop.  If the total size is over the max, always drop.  If between
    // 50% and 100% full, drop based on a probability proportional to the
    // amount over 50%.  This is an O(1) algorithm which is proportionally
    // biased against large packets, and against sources which send more
    // packets.  This should provide a decent level of protection against
    // DoS attacks.
    //
    KeAcquireSpinLockAtDpcLevel(&Set->LockSize);
    if ((Set->Size > Threshold) &&
        (RandomNumber(0, Threshold) < Set->Size - Threshold)) {
        Prune = TRUE;
    }
    KeReleaseSpinLockFromDpcLevel(&Set->LockSize);

    if (Prune) {
        //
        // IppFindBestDropCandidateInSet consumes lock on the 
        // current element, possibly drops IRQL to the old value,
        // but it elevates it back if returns a non-NULL locked element.
        // If there is no element found matching criteria, we won't 
        // delete the current element, as opposed to Vista RTM, 
        // but it's ok.
        //
        DropCandidate = IppFindBestDropCandidateInSet(Set, Element, OldIrql);
        if (DropCandidate != NULL) {
            //
            // Delete this element.
            // We do not send ICMP errors in this situation.
            // The reassembly timer has not expired.
            // This is more analogous to a router dropping packets
            // when a queue gets full, and no ICMP error is sent
            // in that situation.
            //
            IppDeleteFromReassemblySet(Set, DropCandidate, OldIrql);
        }
    } else {
        KeReleaseSpinLock(&Element->Lock, OldIrql);
    }
}


VOID
IppIncreaseReassemblySize(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element, 
    IN ULONG Size,
    IN ULONG NetSize
    )
/*++

Routine Description:
    
    Increase the size of the reassembly set element.
    
Arguments:

    Set - Supplies the set to which the reassembly belongs.

    Element - Supplies the set element to increase the size of.

    Size - Supplies the amount to increase the size by, including overheads.

    NetSize - Supplies the amount of actual payload handled, 
        not including overheads.
    
Return Value:

    None.
    
Caller Lock:

    Called with the element lock held.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    ASSERT_SPIN_LOCK_HELD(&Element->Lock);    
    
    Element->Size += Size;
    Element->DataReceived += NetSize;
    KeAcquireSpinLockAtDpcLevel(&Set->LockSize);
    Set->Size += Size;
    KeReleaseSpinLockFromDpcLevel(&Set->LockSize);
}


BOOLEAN
IppGroupFragments(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN OUT PIP_REQUEST_CONTROL_DATA* List
    )
/*++

Routine Description:

    Determine whether the given packet is a fragment and, if so,
    attempt to group it with others from its original datagram
    for collective forwarding.

Arguments:

    Protocol - Supplies the protocol for which the packet was received.

    Packet - The packet to be examined and grouped.

    List - On input, contains a group of packets currently being processed.
        On successful grouping, additional fragments to be processed may be
        prepended here.

Return Value:

    TRUE if the packet is a fragment and has been absorbed for grouping,
    FALSE otherwise.

Caller Lock:

    Caller should hold no locks.

Caller IRQL:

    Callable at PASSIVE through DISPATCH level.

--*/
{
    SIZE_T BytesCopied;
    PIP_FRAGMENT* Fragment;
    LONG EffectiveFragmentLength;
    ULONG FragmentOffset, FragmentLength, PayloadLength;
    SIZE_T MdlSize, MemorySize;
    PFRAGMENT_GROUP Group;
    ULONG Identification;
    PNET_BUFFER NetBuffer;
    KIRQL OldIrql;
    PUCHAR SourceAddress, CurrentDestinationAddress;
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_CONTEXT Context;
    PRTL_HASH_TABLE Table;
    ULONG Key;

    ASSERT(Packet->Next == NULL);

    //
    // We'll begin by deciding whether this packet is a fragment.
    // In the process, we'll pick up fields that we need later on.
    //
    if (!Protocol->IsFragment(
            Packet->NetBufferList,
            Packet->IP,
            &SourceAddress,
            &CurrentDestinationAddress,
            &Identification,
            &FragmentOffset,
            &FragmentLength,
            &PayloadLength)) {
        return FALSE;
    }

    //
    // The packet appears to be a fragment, so let's try to group it
    // with the others from its original datagram.
    // We'll first look for an existing group.
    //
    KeAcquireSpinLock(&Protocol->ReassemblySet.Lock, &OldIrql);

    Key = IppReassemblyHashKey(
              Packet->Compartment, 
              Identification, 
              Packet->IP);

    Group = NULL;
    Table = &Protocol->ReassemblySet.FragmentGroupTable;
    RtlInitHashTableContext(&Context);
    for (Curr = RtlLookupEntryHashTable(Table, Key, &Context);
         Curr != NULL;
         Curr = RtlGetNextEntryHashTable(Table, &Context)) {

        Group = CONTAINING_RECORD(Curr, FRAGMENT_GROUP, TLink);

        if (Group->Compartment == Packet->Compartment &&
            Group->Id == Identification &&
            INET_UNALIGNED_ADDR_EQUAL(
                Protocol->Family,
                &Group->SourceAddress,
                SourceAddress) &&
            INET_UNALIGNED_ADDR_EQUAL(
                Protocol->Family,
                &Group->DestinationAddress,
                CurrentDestinationAddress)) {

            KeAcquireSpinLockAtDpcLevel(&Group->Lock);

            ASSERT((Group->State == ReassemblyStateNormal) ||
                   (Group->State == ReassemblyStateDeleting));

            if (Group->State != ReassemblyStateDeleting) {
                //
                // This is the group we want. We'll unlock the reassembly set
                // and continue with the group still locked.
                //
                KeReleaseSpinLockFromDpcLevel(&Protocol->ReassemblySet.Lock);
                break;
            }

            KeReleaseSpinLockFromDpcLevel(&Group->Lock);
        }

        Group = NULL;
    }
    RtlReleaseHashTableContext(&Context);
    //
    // If we didn't find a group, we'll create one now.
    // The loop above would have ended with the set still locked.
    // If we succeed, we'll proceed with just the group locked.
    //
    // $REVIEW: When we're unable to create a group, we're currently dropping
    // the fragment rather than allowing it to proceed. Should we send an ICMP
    // error as well?
    //
    if (Group == NULL) {
        Group =
            ExAllocatePoolWithTagPriority(
                NonPagedPool,
                sizeof(*Group),
                IpFragmentGroupPoolTag,
                LowPoolPriority);
        if (Group == NULL) {
            KeReleaseSpinLock(&Protocol->ReassemblySet.Lock, OldIrql);
            Packet->NetBufferList->Status = STATUS_INSUFFICIENT_RESOURCES;
            IppCompleteAndFreePacketList(Packet, OldIrql == DISPATCH_LEVEL);
            return TRUE;
        }

        RtlZeroMemory(Group, sizeof(*Group));

        KeInitializeSpinLock(&Group->Lock);
        Group->Type = ReassemblyTypeGroup;
        Group->State = ReassemblyStateNormal;
        Group->DataReceived = 0;
        Group->Size = REASSEMBLY_SIZE_PACKET;
        Group->Compartment = Packet->Compartment;
        Group->Id = Identification;
        Group->PayloadLength = (ULONG)-1;

        IppTimeStampReassemblyElement((PREASSEMBLY_ELEMENT) Group);

        RtlCopyMemory(
            &Group->SourceAddress,
            SourceAddress,
            Protocol->Characteristics->AddressBytes);
        RtlCopyMemory(
            &Group->DestinationAddress,
            CurrentDestinationAddress,
            Protocol->Characteristics->AddressBytes);

        HASH_ENTRY_KEY(&Group->TLink) = Key;

        IppInsertReassembly(
            &Protocol->ReassemblySet,
            (PREASSEMBLY_ELEMENT)Group);

        KeAcquireSpinLockAtDpcLevel(&Group->Lock);
        KeReleaseSpinLockFromDpcLevel(&Protocol->ReassemblySet.Lock);
    }

    //
    // Now that we have a group, we'll see how this packet fits into it.
    // We'll first check against the fragment group structure itself.
    //
    if (PayloadLength == (ULONG)-1) {
        //
        // This isn't the last fragment. If we know where the datagram ends,
        // make sure this doesn't go beyond that point.
        //
        if (Group->PayloadLength != (ULONG)-1 &&
            Group->PayloadLength < FragmentOffset + FragmentLength) {
            KeReleaseSpinLock(&Group->Lock, OldIrql);
            Packet->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            IppCompleteAndFreePacketList(Packet, OldIrql == DISPATCH_LEVEL);
            return TRUE;
        }
    } else {
        //
        // This is the last fragment. Make sure we haven't already seen
        // a last fragment for the datagram, and that the data we've got
        // isn't already beyond the end of this last fragment.
        //
        if (Group->PayloadLength != (ULONG)-1 ||
            Group->PayloadAvailable >= PayloadLength) {
            KeReleaseSpinLock(&Group->Lock, OldIrql);
            Packet->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            IppCompleteAndFreePacketList(Packet, OldIrql == DISPATCH_LEVEL);
            return TRUE;
        }
    }

    //
    // The next step is to compare the packet against the existing fragments.
    // As we look at the existing fragments, we'll figure out which bytes
    // appear only in the incoming packet. Those bytes are its effective
    // fragment length.
    //
    // $REVIEW: The logic below allows the effective length to drop
    // below zero in the case of multiple overlaps. When that happens,
    // it means the fragment contributes nothing but overlapping bytes
    // to the group. For now we'll drop such fragments.
    //
    EffectiveFragmentLength = FragmentLength;
    for (Fragment = &Group->ArrivalList;
         *Fragment != NULL;
         Fragment = &(*Fragment)->Next) {

        ULONG Head, Tail;

        //
        // Does the packet overlap with this fragment?
        //
        if (FragmentOffset + FragmentLength <= (*Fragment)->Offset ||
            (ULONG)(*Fragment)->Offset + (*Fragment)->Length
                <= FragmentOffset) {
            //
            // No overlap.
            //
            continue;
        }

        //
        // Some overlap exists. We'll need to adjust the overlap out of the
        // effective length of this fragment.
        //
        // E.g. given the following packet and fragment
        //
        //              [------Packet-----]
        //      [-----Fragment------]
        //      ^       {--Overlap--}     ^
        //      |                         |
        //     Head                      Tail
        //
        // The overlapping bytes can be computed as the sum of the lengths
        // minus the distance from head to tail.
        //
        Head = min(FragmentOffset, (*Fragment)->Offset);
        Tail =
            max(
                FragmentOffset + FragmentLength,
                (ULONG)(*Fragment)->Offset + (*Fragment)->Length);
        EffectiveFragmentLength -=
            ((*Fragment)->Length + FragmentLength) - (Tail - Head);
    }

    //
    // We've now accounted for all the existing fragments.
    // If this fragment has no contribution to make, we'll discard it.
    //
    // $REVIEW: Should we send an ICMP error for these?
    //
    if (EffectiveFragmentLength <= 0) {
        KeReleaseSpinLock(&Group->Lock, OldIrql);
        Packet->NetBufferList->Status = STATUS_REQUEST_ABORTED;
        IppCompleteAndFreePacketList(Packet, OldIrql == DISPATCH_LEVEL);
        return TRUE;
    }

    //
    // The packet has something to contribute, so we'll allow it to join
    // the group. This involves allocating a new fragment, chaining it
    // to the list, and updating tracking state.
    //
    // As an optimization, we'll note that we can reuse the packet which
    // completes our group, rather than allocating a fragment for it.
    // We'll therefore check now to see if this packet completes the group.
    //
    // N.B. Reusing the final packet in this way also allows us to obtain
    // the next hop without an additional route lookup.
    //
    if ((Group->PayloadLength != (ULONG)-1 &&
         Group->PayloadLength ==
         Group->PayloadAvailable + EffectiveFragmentLength)
            ||
        (PayloadLength != (ULONG)-1 &&
         PayloadLength == Group->PayloadAvailable + EffectiveFragmentLength)) {

        PIP_REQUEST_CONTROL_DATA Head = NULL, *Tail;

        //
        // This fragment was the missing piece.
        //
        // We'll now chain all the fragments in the group onto this one,
        // and then chain the resulting list to the caller's input list.
        //
        Tail = &Head;
        while (Group->ArrivalList != NULL) {

            //
            // Allocate a new packet for this fragment, using the incoming one
            // as a template, and marking it to indicate no grouping is needed.
            //
            *Tail = IppCopyPacket(Protocol, Packet);
            if (*Tail == NULL) {
                break;
            }

            (*Tail)->NoFragmentGrouping = TRUE;

            //
            // Allocate a NetBufferList to describe the fragment's memory.
            //
            (*Tail)->NetBufferList =
                NetioAllocateAndReferenceNetBufferAndNetBufferList(
                    IppFragmentGroupNetBufferListsComplete,
                    Group->ArrivalList,
                    &Group->ArrivalList->Mdl,
                    0,
                    MmGetMdlByteCount(&Group->ArrivalList->Mdl),
                    TRUE);
            if ((*Tail)->NetBufferList == NULL) {
                break;
            }

            //
            // Update fields in the packet to point into the NetBufferList.
            //
            // N.B.!!! Fields like CurrentDestinationType should already be
            // correct.
            //
            IppParseHeaderIntoPacket(Protocol, *Tail);

            //
            // Move on to the next fragment.
            // Memory for the last one will be freed by the NetBufferList
            // completion routine.
            //
            Group->ArrivalList = Group->ArrivalList->Next;
            Tail = &(*Tail)->Next;
        }

        //
        // If we succeeded in making packets for all the fragments,
        // we'll now chain the packets to the caller's input list.
        // Otherwise, we may have made some packets before failing,
        // and those will get cleaned up below.
        //
        // Before combining the local and input lists, though,
        // we'll ask the inspection point whether to permit these fragments.
        //
        if (Group->ArrivalList == NULL) {

            IP_FILTER_ACTION Action;
            PIP_INTERFACE SourceInterface, DestinationInterface;
            PIP_SUBINTERFACE SourceSubInterface, DestinationSubInterface;
            PNET_BUFFER_LIST NetBufferListHead = NULL, *NetBufferListTail;
            NTSTATUS Status;

            //
            // Append the incoming packet to the fragment group.
            //
            Packet->NoFragmentGrouping = TRUE;
            *Tail = Packet;
            Tail = &(*Tail)->Next;

            //
            // Extract noteworthy fields from the packet.
            //
            SourceSubInterface = Packet->SourceSubInterface;
            SourceInterface = Packet->SourceSubInterface->Interface;

            ASSERT(IppIsNextHopNeighbor(Packet->NextHop));
            DestinationSubInterface = Packet->NextHopNeighbor->SubInterface;
            DestinationInterface = DestinationSubInterface->Interface;

            //
            // Chain together all the NetBufferLists of the fragment group
            // so we can pass the chain to the inspection callout.
            //
            NetBufferListTail = &NetBufferListHead;
            Packet = Head;
            do {
                *NetBufferListTail = Packet->NetBufferList;
                NetBufferListTail = &(*NetBufferListTail)->Next;
                Packet = Packet->Next;
            } while (Packet != NULL);

            //
            // Invoke the callout.
            //
            Action =
                IppInspectForwardedFragmentGroup(
                    Protocol->Level,
                    (CONST NL_INTERFACE*)SourceInterface,
                    SourceSubInterface->Index,
                    (CONST NL_INTERFACE*)DestinationInterface,
                    DestinationSubInterface->Index,
                    Head->SourceAddress.Address,
                    Head->CurrentDestinationAddress,
                    Head->CurrentDestinationType,
                    NetBufferListHead);

            Packet = Head;

            if (Action  != IpFilterAbsorb) {
                //
                // The callout owns the status for absorb.
                //
                if ((Action == IpFilterDrop) || (Action == IpFilterDropAndSendIcmp)) {
                    Status = STATUS_DATA_NOT_ACCEPTED;
                } else {
                    ASSERT(Action == IpFilterAllow);
                    Status = STATUS_SUCCESS;
                }
            
                //
                // The callout breaks the chain. Now set the status.
                //
                do {
                    PNET_BUFFER_LIST NetBufferList = Packet->NetBufferList;
                    NetBufferList->Status = Status;
                    ASSERT(NetBufferList->Next == NULL);
                    Packet = Packet->Next;
                } while (Packet != NULL);
                 
                //
                // Obey the callout's command.
                //
                if (!NT_SUCCESS(Status)) {
     
                    //
                    // Drop everything by letting the code below free the group.
                    //
                    Packet = Head;
                } else {
     
                    //
                    // Append the input list to the fragment group,
                    // set the caller's pointer to the head of the combined list,
                    // and remember not to free the fragment group.
                    //
                    *Tail = *List;
                    *List = Head;
                    ASSERT(Packet == NULL);
                }
            }
        }

        //
        // We're now done with the fragment group.
        //
        IppDeleteFromReassemblySet(
            &Protocol->ReassemblySet,
            (PREASSEMBLY_ELEMENT)Group,
            OldIrql);

        //
        // If we failed above, we might have some packets to clean up.
        //
        if (Packet != NULL) {
            IppCompleteAndFreePacketList(Packet, OldIrql == DISPATCH_LEVEL);
        }

        return TRUE;
    }

    //
    // The fragment group is incomplete even with this contribution.
    //
    // Allocate a new fragment for the packet, and chain it to the list.
    //
    *Fragment = NULL;
    NetBuffer = Packet->NetBufferList->FirstNetBuffer;
    MdlSize = ALIGN_UP(MmSizeOfMdl(DUMMY_VA, NetBuffer->DataLength), PVOID);
    MemorySize = FIELD_OFFSET(IP_FRAGMENT, Mdl) + MdlSize;
   
    if (NT_SUCCESS(
            RtlSIZETAdd(MemorySize, NetBuffer->DataLength, &MemorySize))) {
        *Fragment =
            ExAllocatePoolWithTagPriority(
                NonPagedPool,
                MemorySize,
                IpReassemblyPoolTag,
                LowPoolPriority);
    }        
    if (*Fragment == NULL) {
        KeReleaseSpinLock(&Group->Lock, OldIrql);
        Packet->NetBufferList->Status = STATUS_INSUFFICIENT_RESOURCES;
        IppCompleteAndFreePacketList(Packet, OldIrql == DISPATCH_LEVEL);
        return TRUE;
    }

    (*Fragment)->Next = NULL;
    (*Fragment)->Offset = (USHORT)FragmentOffset;
    (*Fragment)->Length = (USHORT)FragmentLength;
    MmInitializeMdl(
        &(*Fragment)->Mdl,
        (PUCHAR)&(*Fragment)->Mdl + MdlSize,
        NetBuffer->DataLength);
    MmBuildMdlForNonPagedPool(&(*Fragment)->Mdl);

    //
    // $REVIEW: Other reassembly copying logic starts from MdlChain. Why?
    //
    RtlCopyMdlToBuffer(
        NetBuffer->CurrentMdl,
        NetBuffer->CurrentMdlOffset,
        (PVOID)((PUCHAR)&(*Fragment)->Mdl + MdlSize),
        NetBuffer->DataLength,
        &BytesCopied);
    ASSERT(BytesCopied == NetBuffer->DataLength);

    //
    // Account for the size of the data we've just added,
    // in the process unlocking the fragment group.
    //
    Group->PayloadAvailable += EffectiveFragmentLength;
    if (PayloadLength != (ULONG)-1) {
        Group->PayloadLength = PayloadLength;
    }
    ASSERT(Group->PayloadAvailable < Group->PayloadLength);

    IppIncreaseReassemblySize(
        &Protocol->ReassemblySet,
        (PREASSEMBLY_ELEMENT)Group,
        REASSEMBLY_SIZE_FRAG + NetBuffer->DataLength,
        NetBuffer->DataLength);
    IppCheckReassemblyQuota(
        &Protocol->ReassemblySet,
        (PREASSEMBLY_ELEMENT)Group,
        OldIrql);

    //
    // Almost done.
    //
    // A side-effect of grouping is that all fragments for this datagram
    // will be sent at once, rather than being sent as they arrive.
    // If the neighbor happens to be incomplete when the last fragment arrives,
    // all fragments in the group but one will be dropped, due to the fact that
    // each neighbor queues only one packet.
    //
    // To minimize the chances of this happening, we'll attempt to refresh
    // the neighbor each time we absorb a packet into a group.
    //
    if (IppIsNextHopNeighbor(Packet->NextHop)) {
        IppResolveNeighbor(Packet->NextHopNeighbor, NULL);
    }

    //
    // All done.
    //
    Packet->NetBufferList->Status = STATUS_SUCCESS;
    IppCompleteAndFreePacketList(Packet, OldIrql == DISPATCH_LEVEL);    
    return TRUE;
}


VOID
IppReassemblyInterfaceCleanup(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
    
    Cleanup the reassembly data structures when an interface becomes invalid.

Arguments:

    Interface - Supplies the interface to delete reassemblies for.
    
Return Value:

    None.
    
--*/    
{
    KIRQL OldIrql;
    PREASSEMBLY Reassembly;
    PREASSEMBLY_SET Set = &Interface->Compartment->Protocol->ReassemblySet;
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PRTL_HASH_TABLE Table;
    
    KeAcquireSpinLock(&Set->Lock, &OldIrql);

    Table = &Set->ReassemblyTable;
    RtlInitEnumerationHashTable(Table, &Enumerator);
    for (Curr = RtlEnumerateEntryHashTable(Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(Table, &Enumerator)) {

        Reassembly = CONTAINING_RECORD(Curr, REASSEMBLY, TLink);

        if (Reassembly->Interface == Interface) {
            //
            // Remove this reassembly since its interface is no longer valid.
            // If it is not already being deleted, put it on our delete list.
            //
            IppRemoveReassembly(Set, (PREASSEMBLY_ELEMENT)Reassembly);

            KeAcquireSpinLockAtDpcLevel(&Reassembly->Lock);
            if (Reassembly->State == ReassemblyStateDeleting) {
                //
                // Note that it has been removed from the list.
                //
                Reassembly->State = ReassemblyStateRemoved;
                Reassembly->Interface = NULL;
                KeReleaseSpinLockFromDpcLevel(&Reassembly->Lock);
            } else {
                ASSERT(Reassembly->State == ReassemblyStateNormal);
                KeReleaseSpinLockFromDpcLevel(&Reassembly->Lock);
                IppDeleteReassembly(Reassembly);
            }
        }
    }
    RtlEndEnumerationHashTable(Table, &Enumerator);

    KeReleaseSpinLock(&Set->Lock, OldIrql);
}


VOID
IppFragmentGroupCompartmentCleanup(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:
    
    Cleanup the fragment group structures when a compartment becomes invalid.

Arguments:

    Compartment - Supplies the compartment to delete fragment groups for.
    
Return Value:

    None.
    
--*/    
{
    PFRAGMENT_GROUP Group;
    KIRQL OldIrql;
    PREASSEMBLY_SET Set = &Compartment->Protocol->ReassemblySet;
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PRTL_HASH_TABLE Table;   

    KeAcquireSpinLock(&Set->Lock, &OldIrql);
    Table = &Set->FragmentGroupTable;
    RtlInitEnumerationHashTable(Table, &Enumerator);
    for (Curr = RtlEnumerateEntryHashTable(Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(Table, &Enumerator)) {

        Group = CONTAINING_RECORD(Curr, FRAGMENT_GROUP, TLink);

        if (Group->Compartment == Compartment) {
            //
            // Remove this entry since its compartment is no longer valid.
            // If it is not already being deleted, put it on our delete list.
            //
            IppRemoveReassembly(Set, (PREASSEMBLY_ELEMENT)Group);

            KeAcquireSpinLockAtDpcLevel(&Group->Lock);
            if (Group->State == ReassemblyStateDeleting) {
                //
                // Note that it has been removed from the list.
                //
                Group->State = ReassemblyStateRemoved;
                Group->Compartment = NULL;
                KeReleaseSpinLockFromDpcLevel(&Group->Lock);
            } else {
                ASSERT(Group->State == ReassemblyStateNormal);
                KeReleaseSpinLockFromDpcLevel(&Group->Lock);
                IppDeleteFragmentGroup(Group);
            }
        }
    }
    RtlEndEnumerationHashTable(Table, &Enumerator);

    KeReleaseSpinLock(&Set->Lock, OldIrql);
}


VOID
IppReassemblyTimeout(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Process a reassembly timeout event.    
    Called periodically by IppTimeout to check for timed out reassemblies.

Arguments:

    Protocol - Supplies the protocol whose reassembly set timer fired.
    
Return Value:

    None.
    
Caller IRQL:

    DISPATCH_LEVEL.

--*/    
{
    PREASSEMBLY_SET Set = &Protocol->ReassemblySet;
    PREASSEMBLY_ELEMENT Element;
    PLIST_ENTRY Next;
    LIST_ENTRY FiredList, DeleteList;
   
    DISPATCH_CODE();

    InitializeListHead(&DeleteList);
    
    KeAcquireSpinLockAtDpcLevel(&Set->Lock);

    //
    // Determine which timers fired.
    //
    (VOID) TtFireTimer(Set->TimerTable, &FiredList);

    Next = FiredList.Flink;
    while (Next != &FiredList) {
        Element = CONTAINING_RECORD(Next, REASSEMBLY_ELEMENT, Timer.Link);
        Next = Next->Flink;

        TtInitializeTimer(&Element->Timer);

        //
        // Remove this element since its timer is no longer running.
        // If it is not already being deleted, we also delete it.
        //
        IppRemoveReassembly(Set, Element);

        KeAcquireSpinLockAtDpcLevel(&Element->Lock);
        if (Element->State == ReassemblyStateDeleting) {
            //
            // Note that it has been removed from the list.
            //
            Element->State = ReassemblyStateRemoved;
            Element->InterfaceOrCompartment = NULL;
        } else {
            ASSERT(Element->State == ReassemblyStateNormal);
            InsertTailList(&DeleteList, &Element->Link);
            if (Element->Type == ReassemblyTypeRecord) {
                //
                // The element lock protects the interface.
                // Hence, we must take a reference on the interface
                // before releasing the element lock.
                //
                IppReferenceInterface(Element->Interface);
            } else {
                ASSERT(Element->Type == ReassemblyTypeGroup);
            }
        }
        KeReleaseSpinLockFromDpcLevel(&Element->Lock);
    }

    KeReleaseSpinLockFromDpcLevel(&Set->Lock);

    //
    // Now that we no longer need the reassembly list lock,
    // we can send ICMP errors at our leisure.
    //
    while (!IsListEmpty(&DeleteList)) {
        Next = RemoveHeadList(&DeleteList);
        Element = CONTAINING_RECORD(Next, REASSEMBLY_ELEMENT, Link);

        if (Element->Type == ReassemblyTypeRecord) {
            //
            // Recreate the first fragment and send an ICMP error.
            //
            Protocol->ReassemblyTimeout(Element);

            //
            // Delete the reassembly record.
            //
            IppDereferenceInterface(Element->Interface);
            IppDeleteReassembly((PREASSEMBLY)Element);
        } else {
            ASSERT(Element->Type == ReassemblyTypeGroup);
            IppDeleteFragmentGroup((PFRAGMENT_GROUP)Element);
        }
    }
}


VOID
IppReassemblyNetBufferListsComplete(
    IN PNET_BUFFER_LIST NetBufferListChain,
    IN ULONG Count, 
    IN BOOLEAN DispatchLevel
    )
{
    PREASSEMBLY Reassembly;
    PNET_BUFFER_LIST NetBufferList;
    
    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(DispatchLevel);
    
    for (NetBufferList = NetBufferListChain;
         NetBufferList != NULL; 
         NetBufferList = NetBufferListChain) {
        NetBufferListChain = NetBufferList->Next;

        Reassembly = NetioQueryNetBufferListCompletionContext(NetBufferList);
        ASSERT(Reassembly != NULL);

        //
        // The first MDL in the MDL chain was allocated for the unfragmentable
        // length.  It is freed by restore.  All the other MDLs are part of the
        // reassembly and are freed when we delete the reassembly below.  So,
        // first restore the net buffer list which deletes the first MDL, free
        // the reassembly and finally free the net buffer and net buffer list.
        //

        //
        // This restores the net buffer and frees first MDL.
        //
        NetioRestoreNetBufferList(NetBufferList);
        
        //
        // The only MDLs are the ones that we allocated.
        //
        ASSERT(NetBufferList->FirstNetBuffer->MdlChain == 
               &Reassembly->ContiguousList->Mdl);

        //
        // Now free up the reassembly structure and all the shim data (and
        // MDLs).
        //
        IppDeleteReassembly(Reassembly);
        
        //
        // Free the net buffer and the net buffer list. 
        //
        NetioFreeNetBufferAndNetBufferList(NetBufferList, FALSE);
    }
}


VOID
IppFragmentGroupNetBufferListsComplete(
    IN PNET_BUFFER_LIST NetBufferListChain,
    IN ULONG Count,
    IN BOOLEAN DispatchLevel
    )
{
    UNREFERENCED_PARAMETER(Count);
    
    while (NetBufferListChain != NULL) {

        PIP_FRAGMENT Fragment;
        PNET_BUFFER_LIST NetBufferList;

        NetBufferList = NetBufferListChain;
        NetBufferListChain = NetBufferList->Next;

        NetioRestoreNetBufferList(NetBufferList);

        Fragment = NetioQueryNetBufferListCompletionContext(NetBufferList);
        ASSERT(Fragment != NULL);
        ASSERT(NetBufferList->FirstNetBuffer->MdlChain == &Fragment->Mdl);
        ExFreePool(Fragment);

        NetioFreeNetBufferAndNetBufferList(NetBufferList, DispatchLevel);
    }
}


VOID
IppReassembledReceive(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    Receive a reassembled packet.
    This function is called from a kernel worker thread context.
    It prevents "reassembly recursion".

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
    System worker threads typically run at PASSIVE.

--*/
{
    PIP_WORK_QUEUE_ITEM rrc = (PIP_WORK_QUEUE_ITEM)Context;
    KIRQL Irql;

    ASSERT(DeviceObject == IppDeviceObject);
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // All receive processing normally happens at DPC level,
    // so we must pretend to be a DPC, so we raise IRQL.
    // (System worker threads typically run at PASSIVE_LEVEL).
    //
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    IppReceiveHeaders(
        ((PIP_REQUEST_CONTROL_DATA) rrc->Context)->Compartment->Protocol, 
        (PIP_REQUEST_CONTROL_DATA) rrc->Context);
    KeLowerIrql(Irql);

    IoFreeWorkItem(rrc->WorkQueueItem);
    ExFreePool(rrc);
}


NL_ECN_CODEPOINT
IppReassembleEcnField(
    IN PREASSEMBLY Reassembly
    )
/*++

Routine Description:

    This routine reassembles the ECN Field based on the reassembly set
    specified. Any invalid codepoints parsed in the reassembly will result
    in the NotEct codepoint being set.
    
Arguments:

    Reassembly - Supplies the reassembly set.

Returns:

    One of the NL_ECN_CODEPOINT values.
    
--*/
{
    NL_ECN_CODEPOINT EcnField;

    if (Reassembly->EcnCePresent) {        
        //
        // A CE is valid in reassembly only in the following cases:
        //    o All fragments contain only CE or
        //    o All fragments contain CE in conjunction with one of 
        //      ECT(0) or ECT(1) but not both.
        // If an invalid sequence is observed, we generate a warning
        // and ignore the EcnField.
        //        
        if (!Reassembly->EcnNotEctPresent && 
            !(Reassembly->EcnEct1Present && Reassembly->EcnEct0Present)) {
            EcnField = NlEcnCodepointCe;
        } else {        
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                       "IPNG: Invalid ECN codepoints in reassembly, "
                       "Ce = %#x Ect0 = %#x Ect1 = %#x NotEct = %#x.\n",
                       Reassembly->EcnCePresent,
                       Reassembly->EcnEct0Present,
                       Reassembly->EcnEct1Present,
                       Reassembly->EcnNotEctPresent);
            EcnField = NlEcnCodepointNotEct;
        }
    } else {
        //
        // A non CE reassembly is valid only in the following cases:
        //    o All fragments contain NotECT or
        //    o All fragments contain Ect(1) or ECT(0) but not both.
        // If an invalid sequence is observed, we generate a warning
        // and ignore the EcnField.
        //
        if (!(Reassembly->EcnEct1Present && Reassembly->EcnEct0Present) &&
            !((Reassembly->EcnEct1Present || Reassembly->EcnEct0Present) &&
              Reassembly->EcnNotEctPresent)) {
            EcnField = Reassembly->Flags & ~NBL_FLAGS_PROTOCOL_RESERVED;
        } else {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                       "IPNG: Invalid ECN codepoints in reassembly, "
                       "Ce = %#x Ect0 = %#x Ect1 = %#x NotEct = %#x.\n",
                       Reassembly->EcnCePresent,
                       Reassembly->EcnEct0Present,
                       Reassembly->EcnEct1Present,
                       Reassembly->EcnNotEctPresent);
            EcnField = NlEcnCodepointNotEct;
        }
    }
    
    return EcnField;
}

BOOLEAN
IpIsPacketFragmentGrouped(
    IN IPPROTO IpProtocol,
    IN PNET_BUFFER_LIST NetBufferList
    )
   /*++
   
   Routine Description:
   
       Determine whether the given packet is going to be indicated
       as a fragment group
   
   Arguments:
   
       Protocol - Supplies if the packet is IPv4 or IPv6.
   
       Packet - The packet to be examined.
      
   Return Value:
   
       TRUE if fragment grouping is enabled and the packet is a fragment,
       FALSE otherwise.
   
   Caller Lock:
   
       Caller should hold no locks.
   
   Caller IRQL:
   
       Callable at PASSIVE through DISPATCH level.
   
   --*/

{
    PIP_PROTOCOL Protocol;
    PNET_BUFFER NetBuffer;
    ULONG HeaderLength;
    PVOID Header;
    ULONG Identification;
    ULONG FragmentOffset, FragmentLength, PayloadLength;
    PUCHAR SourceAddress, CurrentDestinationAddress;
    CHAR HeaderBuffer[40];
    
    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;
    if (!Protocol->GroupForwardedFragments) {
        return FALSE;
    }

    NetBuffer = NetBufferList->FirstNetBuffer;
    HeaderLength = Protocol->HeaderSize ;
    Header = 
            NetioGetDataBuffer(
                NetBuffer,
                HeaderLength,
                HeaderBuffer,
                1,
                0);
    return Protocol->IsFragment(
                     NetBufferList,
                     Header,
                     &SourceAddress,
                     &CurrentDestinationAddress,
                     &Identification,
                     &FragmentOffset,
                     &FragmentLength,
                     &PayloadLength);
}
