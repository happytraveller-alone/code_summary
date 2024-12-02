/*++

Copyright (c) 2002-2005  Microsoft Corporation

Module Name:

    multicastfwd.c

Abstract:

    This module contains the protocol independent part of the multicast
    forwarding module.
    
Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "multicastfwd.tmh"

#if MFE_REFHIST
PREFERENCE_HISTORY IppMfeReferenceHistory;
#endif
   
__inline
VOID
IppMulticastForwardingTrace(
    IN ULONG Level, 
    IN PIP_PROTOCOL Protocol,
    IN ULONG Index,
    IN CONST UCHAR* MulticastAddress,
    IN CONST UCHAR* SourceAddress, 
    IN CONST UCHAR *Message 
    )
{
    if (IS_IPV4_PROTOCOL(Protocol)) {
        NetioTrace(
            NETIO_TRACE_NETWORK, 
            Level, 
            "IPNG: [%u] MFE (%!IPV4!, %!IPV4!) %s\n", 
            Index,
            MulticastAddress,
            SourceAddress,
            Message);
    } else {
        NetioTrace(
            NETIO_TRACE_NETWORK, 
            Level, 
            "IPNG: [%u] MFE (%!IPV6!, %!IPV6!) %s\n", 
            Index,
            MulticastAddress,
            SourceAddress,
            Message);
    }
}

NTSTATUS
IppInitializeMfeSet(
    OUT PIP_MFE_LOCKED_SET *Set
    ) 
/*++

Routine Description:

    Allocate and initialize Mfe set for a compartment.
    
Arguments:

    Set - Returns the initialized Mfe set.
    
Return Value:

    STATUS_SUCCESS or failure code.
    
--*/
{
    PIP_MFE_LOCKED_SET MfeSet = NULL;
    NTSTATUS Status;
    
    *Set = NULL;
    MfeSet = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            sizeof(IP_MFE_LOCKED_SET), 
            IpMfePoolTag);
    if (MfeSet == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(MfeSet, sizeof(*MfeSet));
    
    MfeSet->TimerTable = TtCreateTable(IP_MFE_TIMER_TABLE_SLOTS, FALSE);
    if (MfeSet->TimerTable == NULL) {
        ExFreePoolWithTag(MfeSet, IpMfePoolTag);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Status = IppInitializeLockedHashTable((PLOCKED_HASH_TABLE) MfeSet);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(MfeSet, IpMfePoolTag);
        return Status;
    }

    MfeSet->TotalSizeOfQueuedPackets = 0;
    MfeSet->TotalLimitOfQueuedPackets = IppDefaultMemoryLimitOfBuffers;
    
    *Set = MfeSet;
    return STATUS_SUCCESS;
}

VOID
IppUninitializeMfeSet(
    IN PIP_MFE_LOCKED_SET Set
    ) 
/*++

Routine Description:

    Free Mfe set of a compartment.
    
Arguments:

    Set - Supplies an Mfe set.
    
Return Value:

    None.
    
--*/
{    
    IppUninitializeLockedHashTable((PLOCKED_HASH_TABLE) Set);
    TtDestroyTable(Set->TimerTable);
    Set->TimerTable = NULL;
    ExFreePoolWithTag(Set, IpMfePoolTag);
}

__inline
ULONG
IppFindMfeBucket(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourceAddress
    )
/*++

Routine Description:

    Find the Mfe bucket for the given group and source. Essentially a hashing 
    function.
    
Arguments:

    Compartment - Supplies the compartment.

    Group - Supplies the multicast group address.

    Source - Supplies the source address
    
Return Value:

    Index of bucket in hash table.
    
Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.
    
--*/
{
    ULONG BucketIndex;

    UNREFERENCED_PARAMETER(SourceAddress);
    
    //
    // FUTURE-2005/08/02-sgarg -- Use a better hashing function.
    //
    BucketIndex = 
        IppChecksum(
            Group, 
            Compartment->Protocol->Characteristics->AddressBytes);
    
    return (BucketIndex & (Compartment->MfeSet->HashTable.NumBuckets - 1));
}

VOID 
IppCleanupMfe(
    IN PIP_MFE Mfe
    )
/*++

Routine Description:

    Free all resources in use by the Mfe: free next hops, drop any queued 
    packets. It should already have been removed from Mfe set and timer table.

Arguments:

    Mfe - Supplies the Mfe to be destroyed.
    
Return Value:

    None.
    
Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.
    
--*/
{
    PIP_COMPARTMENT Compartment = Mfe->Compartment;
    PIP_MFE_NEXT_HOP NextHopEntry = NULL;
    PLIST_ENTRY ListHead;
    
    ASSERT(Mfe->ReferenceCount == 0);    

    ASSERT(IsListEmpty(&Mfe->NextHopList) || Mfe->NumberOfNextHops > 0);

    //
    // The Mfe is not in the set.
    //
    ASSERT(!IsListEntry(&Mfe->HashLink));
    ASSERT(!TtIsTimerActive(&Mfe->TimerEntry));

    //
    // Clean entries in list of Next Hops.
    //
    while (!IsListEmpty(&Mfe->NextHopList)) {
        ListHead = RemoveHeadList(&Mfe->NextHopList);
        NextHopEntry = 
            (PIP_MFE_NEXT_HOP) 
            CONTAINING_RECORD(ListHead, IP_MFE_NEXT_HOP, Link);
        
        if (NextHopEntry->CurrentNextHop != NULL) {
            IppDereferenceNeighbor(NextHopEntry->CurrentNextHop);
            NextHopEntry->CurrentNextHop = NULL;
        }
        ExFreePoolWithTag((PUCHAR) NextHopEntry, IpMfePoolTag);
    }

    //
    // Drop queued packets.
    //
    if (Mfe->NumberOfPendingPackets > 0) {
        IppCompleteAndFreePacketList(Mfe->PendingPackets.Head, FALSE);
        Mfe->SizeOfPendingPackets = 0;
    }
    
    ExFreePoolWithTag((PUCHAR) Mfe, IpMfePoolTag);

    //
    // Release the Mfe's reference on its compartment.
    // This might cause the compartment to be destroyed, hence we do it last.
    //
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);
    }
}

VOID
IppRestartMfeTimer(
    IN PIP_MFE Mfe
    )
/*++

Routine Description:

    Restarts the activity timer of an Mfe if no timeout was specified.
    
Arguments:

    Mfe - Supplies the Mfe that saw some activity.

Return Value:

    None.

Caller Lock: 

    Exclusive lock on Mfe set.

Caller IRQL: 

    DISPATCH_LEVEL.

--*/
{
    PIP_MFE_LOCKED_SET MfeSet = Mfe->Compartment->MfeSet;

    ASSERT_WRITE_LOCK_HELD(&MfeSet->Lock);

    if (Mfe->TimeOut > 0) {
        
        //
        // Do not restart the timer.
        //
        return;
    }

    //
    // Timer should be active.
    //
    TtStopTimer(MfeSet->TimerTable, &Mfe->TimerEntry);
    TtStartTimer(
        MfeSet->TimerTable, 
        &Mfe->TimerEntry, 
        IppMillisecondsToTicks(DEFAULT_LIFETIME));
}

VOID
IppStartMfeTimer(
    IN PIP_MFE Mfe
    )
/*++

Routine Description:

    Starts the expiration timer of an Mfe. If the timer was already started, it 
    forces a restart.
    
Arguments:

    Mfe - Supplies the Mfe.

Return Value:

    None.

Caller Lock: 

    Exclusive lock on Mfe set.
    
Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_MFE_LOCKED_SET MfeSet = Mfe->Compartment->MfeSet;
    ULONG ExpirationTicks = 0;

    ASSERT_WRITE_LOCK_HELD(&MfeSet->Lock);
    
    if (Mfe->TimeOut > 0) {
        ExpirationTicks = Mfe->TimeOut;
    } else {
        ExpirationTicks = IppMillisecondsToTicks(DEFAULT_LIFETIME);
    }
    if (TtIsTimerActive(&Mfe->TimerEntry)) {
        TtStopTimer(MfeSet->TimerTable, &Mfe->TimerEntry);
    }
    TtStartTimer(
        MfeSet->TimerTable, 
        &Mfe->TimerEntry,  
        ExpirationTicks);
}

__inline
VOID
IppInsertMfeUnderLock(
    IN PIP_MFE Mfe
    )
/*++

Routine Description:

    Insert Mfe in Mfe set. The caller should verify that no duplicate Mfe 
    already exists.
    
Arguments:

    Mfe - Supplies the Mfe to be inserted.

Return Value:

    None.

Caller Lock: 

    Exclusive lock on compartment Mfe set.

Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    ULONG BucketIndex = 0;
    PIP_COMPARTMENT Compartment = Mfe->Compartment;
    PIP_MFE_LOCKED_SET MfeSet = Compartment->MfeSet;
    PIP_MFE_HASH_BUCKET Bucket = NULL;
        
    ASSERT_WRITE_LOCK_HELD(&MfeSet->Lock);

    BucketIndex = 
        IppFindMfeBucket(Compartment, Mfe->GroupAddress, Mfe->SourceAddress);

    Bucket = &MfeSet->HashTable.Bucket[BucketIndex];

    //
    // New Mfe is likely to be referenced in near future, so add it at head.
    //
    InsertHeadList(Bucket, &Mfe->HashLink);
    InterlockedIncrement(&MfeSet->HashTable.NumEntries);

    //
    // Start the timer.
    //
    IppStartMfeTimer(Mfe);

    //
    // Initialize reference count to 1 for being in the table.
    //
    Mfe->ReferenceCount = 1;
}

__inline
VOID
IppRemoveMfeUnderLock(
    IN PIP_MFE Mfe
    )
/*++

Routine Description:

    Remove Mfe from Mfe set and timer table. Note that the Mfe may be in use.
    
Arguments:

    Mfe - Supplies the Mfe to be removed.

Return Value:

    None.

Caller LOCK: 

    Exclusive lock on Mfe set.
    
Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_MFE_LOCKED_SET MfeSet = Mfe->Compartment->MfeSet;
        
    ASSERT_WRITE_LOCK_HELD(&MfeSet->Lock);

    //
    // Update the total number of pending (queued) packets.
    //
    ASSERT(MfeSet->TotalSizeOfQueuedPackets >= Mfe->SizeOfPendingPackets);    
    MfeSet->TotalSizeOfQueuedPackets -= Mfe->SizeOfPendingPackets;   

    if (IsListEntry(&Mfe->HashLink)) {
        RemoveEntryList(&Mfe->HashLink);
        InitializeListEntry(&Mfe->HashLink);
        InterlockedDecrement(&MfeSet->HashTable.NumEntries);

        //
        // Mfe may already have been removed from timer table because of 
        // expiration.
        //
        if (TtIsTimerActive(&Mfe->TimerEntry)) {
            TtStopTimer(MfeSet->TimerTable, &Mfe->TimerEntry);
        }
        //
        //  Dereference after removing Mfe from all lists.
        //
        IppDereferenceMfe(Mfe);
    }
}

VOID 
IppDeleteMfeSetUnderLock(
    IN PIP_COMPARTMENT Compartment
    ) 
/*++

Routine Description:

    Deletes all MFEs from Mfe set of the given compartment.

Arguments:

    Compartment - Supplies the compartment whose Mfe set is to be destroyed.
    
Return Value:

    None.

Caller LOCK: 

    Exclusive lock on Mfe set.
    
Caller IRQL:  

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_MFE_LOCKED_SET MfeSet = Compartment->MfeSet;
    ULONG BucketIndex = 0;
    PIP_MFE_HASH_BUCKET Bucket;
    PLIST_ENTRY MfeList;
    PIP_MFE Mfe;
    
    ASSERT_WRITE_LOCK_HELD(&MfeSet->Lock);

    for (BucketIndex = 0; BucketIndex < MfeSet->HashTable.NumBuckets; 
        BucketIndex++) {
        Bucket = &MfeSet->HashTable.Bucket[BucketIndex];

        MfeList = (PLIST_ENTRY) Bucket;
        while (!IsListEmpty(MfeList)) {
            Mfe = 
                (PIP_MFE) CONTAINING_RECORD(MfeList->Flink, IP_MFE, HashLink);
            IppRemoveMfeUnderLock(Mfe);
        }
    }
}  

__inline
BOOLEAN 
IppIsMfeDependent(
    IN PIP_MFE Mfe,
    IN PIP_INTERFACE Interface OPTIONAL, 
    IN PIP_SUBINTERFACE SubInterface OPTIONAL
    )
/*++

Routine Description:

    Indicates if the Mfe is dependent on the supplied interface or 
    subinterface. Either interface or subinterface should be supplied.

Arguments:

    Compartment - Supplies the compartment whose Mfe set is to be updated.

    Interface - Supplies the interface for which to clean up Mfes.

    SubInterface - Supplies the subinterface for which to clean up Mfes.
    
Return Value:

    TRUE if dependent, FALSE otherwise.

Caller LOCK: 

    None.

Caller IRQL:  

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PLIST_ENTRY Link;
    PIP_MFE_NEXT_HOP NextHopEntry;
    
    if ((Interface != NULL)  && 
        (Mfe->IncomingInterfaceIndex == Interface->Index)) {
        return TRUE;
    }
    
    for (Link = Mfe->NextHopList.Flink; Link != &Mfe->NextHopList; 
         Link = Link->Flink) {
        NextHopEntry = 
            (PIP_MFE_NEXT_HOP) 
            CONTAINING_RECORD(Link, IP_MFE_NEXT_HOP, Link);

        ASSERT(NextHopEntry->CurrentNextHop != NULL);

        if ((NextHopEntry->CurrentNextHop->Interface == Interface) ||
            (NextHopEntry->CurrentNextHop->SubInterface == SubInterface)) {
            return TRUE;
        }
    }

    //
    // For an Mfe in MF_QUEUE mode, look at queued packets source interface.
    //
    if (Mfe->State == MF_QUEUE) {
        PIP_REQUEST_CONTROL_DATA Control;
        for (Control = Mfe->PendingPackets.Head; Control != NULL; 
             Control = Control->Next) {
            //
            // Drop the entire Mfe if any of the packets were from the 
            // interface/subinterface in question.
            //
            if (!Control->IsOriginLocal && 
                ((Control->SourceSubInterface->Interface == Interface) ||
                 (Control->SourceSubInterface == SubInterface))) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

VOID 
IppDeleteMfes(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_INTERFACE Interface OPTIONAL,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL
    ) 
/*++

Routine Description:

    Deletes Mfes referencing an interface or a subinterface.
    Either interface or subinterface should be supplied.

Arguments:

    Compartment - Supplies the compartment whose Mfe set is to be updated.

    Interface - Supplies the interface for which to clean up Mfes.

    SubInterface - Supplies the subinterface for which to clean up Mfes.
    
Return Value:

    None.

Caller LOCK: 

    None.

Caller IRQL:  

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_MFE_LOCKED_SET MfeSet = Compartment->MfeSet;
    ULONG BucketIndex = 0;
    PIP_MFE_HASH_BUCKET Bucket;
    PLIST_ENTRY Link;
    PIP_MFE Mfe;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    RtlAcquireWriteLock(&MfeSet->Lock, &LockHandle);

    for (BucketIndex = 0; BucketIndex < MfeSet->HashTable.NumBuckets; 
          BucketIndex++) {
        Bucket = &MfeSet->HashTable.Bucket[BucketIndex];

        for (Link = Bucket->Flink; Link != Bucket;) {
            Mfe = (PIP_MFE) CONTAINING_RECORD(Link, IP_MFE, HashLink);
            Link = Link->Flink;
            
            if (IppIsMfeDependent(Mfe, Interface, SubInterface)) {
                IppRemoveMfeUnderLock(Mfe);
            }
        }
    }
    RtlReleaseWriteLock(&MfeSet->Lock, &LockHandle);
        
}  

PIP_MFE
IppCreateMfe(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourceAddress
    )
/*++

Routine Description:

    Create an Mfe given mulitcast group and source address. The Mfe will take a 
    reference to the compartment. Hence the caller must guarantee that the 
    compartment will not disappear during the call.
    
Arguments:

    Compartment - Supplies the compartment.

    Group - Supplies the multicast group address.

    SourceAddress - Supplies the source address.

Return Value:

    Referenced Mfe if success, NULL otherwise.

Caller LOCK: 

    None.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_MFE Mfe = NULL;
    ULONG AddressBytes = Compartment->Protocol->Characteristics->AddressBytes;
    ULONG Size;

    // 
    // Account for the address storage.
    //
    Size = sizeof(IP_MFE)+2*AddressBytes;

    Mfe = 
        ExAllocatePoolWithTag(NonPagedPool, Size, IpMfePoolTag);
    if (Mfe == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
            "IPNG: Failure allocating Mfe\n");
        return NULL;
    }
    
    RtlZeroMemory(Mfe, sizeof(*Mfe));

    Mfe->GroupAddress = (PUCHAR)Mfe+sizeof(IP_MFE);
    Mfe->SourceAddress = (PUCHAR)Mfe->GroupAddress + AddressBytes;

    RtlCopyMemory((PUCHAR)Mfe->GroupAddress, Group, AddressBytes);
    RtlCopyMemory((PUCHAR)Mfe->SourceAddress, SourceAddress, AddressBytes);
    
    IppReferenceCompartment(Compartment);
    Mfe->Compartment = Compartment;
    Mfe->NumberOfNextHops = 0;
    Mfe->State = MF_FORWARD;
    Mfe->NumberOfPendingPackets = 0;
    Mfe->SizeOfPendingPackets = 0;
    Mfe->Scope = scopeid_unspecified;
    
    InitializeListEntry(&Mfe->HashLink);
    InitializeListHead(&Mfe->NextHopList);
    IppInitializeGenericList(&Mfe->PendingPackets);
    TtInitializeTimer(&Mfe->TimerEntry);
    return Mfe;    
}

__inline
PIP_MFE
IppCreateAndInsertMfeUnderLock(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourceAddress
    )
/*++

Routine Description:

    Creates an Mfe and adds it to the compartment Mfe set.
    
Arguments:

    Compartment - Supplies the compartment.

    Group - Supplies the multicast group address.

    SourceAddress - Supplies the source address.

Return Value:

    Pointer to referenced Mfe. NULL if failure.

Caller LOCK: 

    Compartment Mfe set lock (Exclusive).

Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_MFE Mfe = NULL;
    
    ASSERT_WRITE_LOCK_HELD(&Compartment->MfeSet->Lock);
    
    Mfe = IppCreateMfe(Compartment, Group, SourceAddress);
    if (Mfe != NULL) {
        IppInsertMfeUnderLock(Mfe);
        IppReferenceMfe(Mfe);
    }
    return Mfe;
}


PIP_MFE
IppFindMfeUnderLock(
   IN PIP_COMPARTMENT Compartment,
   IN CONST UCHAR *Group,
   IN CONST UCHAR *SourceAddress
    ) 
/*++ 

Routine Description:

    Check for an existing Mfe and return it referenced.

Arguments:

    Compartment - Supplies the compartment.

    Group - Supplies the multicast address.

    SoureAddress - Supplies the source address.

Return Value:

    Pointer to referenced Mfe, NULL if not found.
    
Caller LOCK: 

    Caller holds any Mfe set Lock.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).
    
--*/
{
    PIP_MFE_LOCKED_SET MfeSet = Compartment->MfeSet;
    PIP_MFE_HASH_BUCKET Bucket = NULL;
    PLIST_ENTRY Curr = NULL;
    ULONG AddressBytes = Compartment->Protocol->Characteristics->AddressBytes;
    ULONG BucketIndex;
    PIP_MFE Mfe = NULL;

    ASSERT_ANY_LOCK_HELD(&MfeSet->Lock);

    BucketIndex = 
        IppFindMfeBucket(Compartment, Group, SourceAddress);
    Bucket = &MfeSet->HashTable.Bucket[BucketIndex];

    //
    // Walk the list to find a match.
    //
    for (Curr = Bucket->Flink; Curr != Bucket; Curr = Curr->Flink) {
        ASSERT(Curr != NULL);
        Mfe = (PIP_MFE)CONTAINING_RECORD(Curr, IP_MFE, HashLink);
        //
        // Find the perfect match to (S, G).
        //
        if (RtlEqualMemory(Mfe->GroupAddress, Group, AddressBytes) &&
            RtlEqualMemory(Mfe->SourceAddress, SourceAddress, AddressBytes)) {
            IppReferenceMfe(Mfe);
            return Mfe;
        }
    }    
    return NULL;
}

__inline
PIP_MFE
IppFindMfe(
   IN PIP_COMPARTMENT Compartment,
   IN CONST UCHAR *Group,
   IN CONST UCHAR *SourceAddress
   )
{
    PIP_MFE Mfe = NULL;
    KIRQL OldIrql;
    
    RtlAcquireReadLock(&Compartment->MfeSet->Lock, &OldIrql);
    Mfe = IppFindMfeUnderLock(Compartment, Group, SourceAddress);
    RtlReleaseReadLock(&Compartment->MfeSet->Lock, OldIrql);
    return Mfe;
}

__inline
PIP_REQUEST_CONTROL_DATA
IppCreateClonePacketForForwarding(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Create clone of a packet and initialize its next hop.

Arguments:
    
    Control - Supplies the packet to forward.

    Pointer - A pointer to the protocol.

Return Value:

    Returns the cloned packet. NULL on failure.

--*/
{
    PIP_REQUEST_CONTROL_DATA Clone;
    
    Clone = IppCreateStrongClonePacket(Control, Protocol);
    if (Clone == NULL) {
        NetioTrace(
            NETIO_TRACE_NETWORK, 
            TRACE_LEVEL_WARNING, 
            "IPNG: Failure cloning control for forwarding.\n");
        return NULL;
    }
    //
    // Update the IP header pointers.
    //
    IppParseHeaderIntoPacket(Protocol, Clone);

    if (Clone->IsNextHopReferenced) {
        IppDereferenceNextHop(Clone->NextHop);
    }
    Clone->NextHop = NULL;
    Clone->IsNextHopReferenced = FALSE;
    
    return Clone;
}

__inline
NTSTATUS
IppEnqueuePacketToMfeUnderLock(
    IN PIP_MFE Mfe,
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Enqueue a packet to Mfe. The packet should have been cloned by the caller.

Arguments:
    
    Mfe - Supplies the Mfe the packet is to be queued at.

    Control - Supplies the packet for queueing. The caller is not responsible
        for completing the queued packet.

Return Value:

    STATUS_SUCCESS or failure code.

Caller Lock: 

    Exclusive lock on Mfe set.

Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    ASSERT_WRITE_LOCK_HELD(&Mfe->Compartment->MfeSet->Lock);
    
    if (IsListEntry(&Mfe->HashLink)) {
        IppAppendToGenericList(&Mfe->PendingPackets, Control);
        Mfe->NumberOfPendingPackets++;
        Mfe->SizeOfPendingPackets +=
            Control->NetBufferList->FirstNetBuffer->DataLength;
        //
        // Update the total number of pending (queued) packets.
        //
        Mfe->Compartment->MfeSet->TotalSizeOfQueuedPackets += 
            Control->NetBufferList->FirstNetBuffer->DataLength;   
        return STATUS_SUCCESS;
    }
    //
    // Mfe is no longer in the set. No need to enqueue.
    //
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
IppCreateMfeForPacket(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourceAddress, 
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Creates a new Mfe in response to a received packet. Adds a packet clone to
    the PendingPackets list for the Mfe.

Arguments:

    Compartment - Supplies the compartment.

    Group - Supplies the multicast address.

    SoureAddress - Supplies the source address.

    Control - Supplies the received packet.
    
Return Value:

    STATUS_SUCCESS or failure code.
    
Caller LOCK: 

    Exclusive lock on Mfe set.
    
Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).
    
--*/
{
    PIP_MFE Mfe = NULL;
    PIP_REQUEST_CONTROL_DATA Clone = NULL;
    
    ASSERT(Compartment != NULL);
    ASSERT(Compartment->MfeSet != NULL);

    ASSERT_WRITE_LOCK_HELD(&Compartment->MfeSet->Lock);
    
    Mfe = IppCreateAndInsertMfeUnderLock(Compartment, Group, SourceAddress);
    if (Mfe == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    Mfe->State = MF_QUEUE;
    
    //
    // Enqueue the packet.
    //
    Clone = IppCreateClonePacketForForwarding(Control, Compartment->Protocol);
    if (Clone == NULL) {   
        IppDereferenceMfe(Mfe);
        return STATUS_UNSUCCESSFUL;
    }
    
    IppEnqueuePacketToMfeUnderLock(Mfe, Clone);

    IppDereferenceMfe(Mfe);
    return STATUS_SUCCESS;
}

VOID
IppDispatchMfeQueuedPackets(
    IN PIP_MFE Mfe OPTIONAL,
    IN PIP_REQUEST_CONTROL_DATA OldClones OPTIONAL
    )
/*++

Routine Description:

    Forward queued packets (actually clones) according to a given Mfe. This 
    function takes ownership of the packets and completes them. If no Mfe is 
    specified, packets simply get discarded.

Arguments:

    Mfe - Supplies the Mfe to be used for forwarding.

    OldClones - Supplies the list of queued packets to be forwarded.
    
Return Value:

    None.
    
Caller LOCK: 

    Caller should not hold any lock, as a call outside the module is made.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_INTERFACE IncomingInterface;
    
    if (OldClones == NULL) {
        return;
    }

    if (Mfe != NULL && Mfe->State != MF_DROP) {
        PIP_COMPARTMENT Compartment = Mfe->Compartment;

        //
        // Use the Mfe's incoming interface as the arrival interface. 
        // This may cause duplicates. But in absence of actual arrival
        // interfaces, this is the best that can be done.
        // With no lock, make sure incoming interface still exists.
        // The forwarding function will create another set of clones
        // for forwarding, so complete the existing clones.
        //
        IncomingInterface = 
            IppFindInterfaceByIndex(
                Compartment, 
                Mfe->IncomingInterfaceIndex);
        if (IncomingInterface != NULL) {
            IP_GENERIC_LIST RemoteArgs;
            KIRQL OldIrql;
            PIP_REQUEST_CONTROL_DATA Control, Next;

            IppInitializeGenericList(&RemoteArgs);
            //
            // Raising to dispatch irql for the forwarding function.
            //
            OldIrql = KeRaiseIrqlToDpcLevel();
            for (Control = OldClones; Control != NULL; Control = Next) {
                Next = Control->Next;
                Control->Next = NULL;
                //
                // FUTURE-2005/08/02-sgarg -- The routine should reuse the 
                // queued clones.
                //
                IppForwardMulticastPackets(
                    IncomingInterface, 
                    Control, 
                    &RemoteArgs);
            }
            KeLowerIrql(OldIrql);
            IppFragmentPackets(Compartment->Protocol, RemoteArgs.Head);
        }
    }
    //
    // Complete all queued packets.
    //
    IppCompleteAndFreePacketList(OldClones, FALSE);
}

BOOLEAN
IppForwardMulticastPackets(
    IN PIP_INTERFACE ArrivalInterface, 
    IN PIP_REQUEST_CONTROL_DATA Control,
    OUT PIP_GENERIC_LIST RemoteArgs
    ) 
/*++

Routine Description:

    Lookup Mfe corresponding to the packet.

    If no entry if found, notify RRAS of the packet and queue this and any 
    subsequent packets with the same (S, G).

    If entry is found, validate the packet for the incoming interface. For 
    each next hop, for which multicast forwarding is enabled and packet 
    hoplimit exceeds the minimum specified multicastforwardinghoplimit, clone
    the packet and forward the clone.
    
Arguments:
    
    ArrivalInterface - Supplies the interface over which the packet arrived.

    Control - Supplies the packet to forward.

    RemoteArgs - Returns an updated list of packets to be forwarded remotely.

Return Value:

    TRUE if forwarded, FALSE otherwise.

Caller IRQL: 

    DISPATCH_LEVEL.

--*/
{
    CONST UCHAR *SourceAddress, *Group;
    ULONG SourcePrefixLength;
    PIP_MFE Mfe = NULL;
    PIP_COMPARTMENT Compartment = ArrivalInterface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_REQUEST_CONTROL_DATA Clone = NULL;
    PIP_HEADER_STORAGE IpHeader;
    UINT8 HopLimit;
    PIP_INTERFACE OutgoingInterface;
    PIP_MFE_NEXT_HOP MfeNextHop;
    PLIST_ENTRY Link;
    IP_DISCARD_REASON DiscardReason;
    BOOLEAN Forwarded = FALSE;
    
    ASSERT(Control->Next == NULL);

    DISPATCH_CODE();
    
    Group = Control->CurrentDestinationAddress;
    SourceAddress = Control->SourceAddress.Address;
    SourcePrefixLength = Protocol->Characteristics->AddressBytes;

    //
    // On the receive path, IP is correctly set. 
    //
    IpHeader = (PIP_HEADER_STORAGE)Control->IP;
    HopLimit =
        (IS_IPV4_PROTOCOL(Protocol))
        ? IpHeader->Ipv4.TimeToLive
        : IpHeader->Ipv6.HopLimit;
 
    if (HopLimit <= 1) {
        //
        // It will not get forwarded.
        //
        return FALSE;
    }
    //
    // Check if the group can be forwarded.
    //
    if (Protocol->AddressScope(Group) < ScopeLevelSubnet) {
        return FALSE;
    }
    
    RtlAcquireReadLockAtDpcLevel(&Compartment->MfeSet->Lock);
    Mfe = 
        IppFindMfeUnderLock(
            ArrivalInterface->Compartment, 
            Group, 
            SourceAddress);

    //
    // Do not update activity timer if packet will be queued. This puts a bound
    // on how long it remains queued.
    //
    if (Mfe != NULL && Mfe->State == MF_FORWARD) {
        IppRestartMfeTimer(Mfe);
    }
    RtlReleaseReadLockFromDpcLevel(&Compartment->MfeSet->Lock);

    if (Mfe == NULL) {
        RtlAcquireWriteLockAtDpcLevel(&Compartment->MfeSet->Lock, &LockHandle);
        //
        // Verify again that the Mfe is still not in the set. It is ok as 
        // this case will not occur often.
        //
        Mfe = IppFindMfeUnderLock(Compartment, Group, SourceAddress);
        if (Mfe == NULL &&
            !IppIsMfeSetMemoryQuotaExceeded(Compartment->MfeSet)) {
            //
            // If packet is dropped, no need to go and create a MFE entry. 
            // This will further prevent against DoS attacks of creating several
            // MFE entries and queueing lots of packets in those entries.
            //
            IppCreateMfeForPacket(Compartment, Group, SourceAddress, Control);

            //
            // Note that currently is Mfe creation fails, notification is still 
            // sent. This may or may not be desirable.
            //
            IppNotifyMfeChange(
                Compartment->Protocol, 
                MF_RECEIVE_PACKET, 
                Control, 
                ArrivalInterface, 
                NULL, 
                0, 
                NULL);
            
            RtlReleaseWriteLockFromDpcLevel(
                &Compartment->MfeSet->Lock, 
                &LockHandle);        
            return FALSE;
        }
        RtlReleaseWriteLockFromDpcLevel(
            &Compartment->MfeSet->Lock, 
            &LockHandle);
    }

    ASSERT(Mfe != NULL);
    switch (Mfe->State) {
        case MF_QUEUE:
            RtlAcquireWriteLockAtDpcLevel(
                &Compartment->MfeSet->Lock, 
                &LockHandle);
            //
            // Make sure Mfe is still in set. Otherwise, drop.
            //
            if (IsListEntry(&Mfe->HashLink)) {
                //
                // To avoid a large number of queued packets, each Mfe has
                // atmost MAX_MFE_QUEUED_PACKETS number of packets.
                // The statistics will be updated when queued packets get sent 
                // out.
                //
                if (Mfe->NumberOfPendingPackets < MAX_MFE_QUEUED_PACKETS &&
                    !IppIsMfeSetMemoryQuotaExceeded(Compartment->MfeSet)) {
                    Clone = 
                        IppCreateClonePacketForForwarding(
                            Control, 
                            Compartment->Protocol);
                    //
                    // If cloning fails, simply ignore.
                    //
                    if (Clone != NULL) {              
                        IppEnqueuePacketToMfeUnderLock(Mfe, Clone);
                    }
                }
            }
            RtlReleaseWriteLockFromDpcLevel(
                &Compartment->MfeSet->Lock, 
                &LockHandle);
            IppDereferenceMfe(Mfe);
            return FALSE;
            
        case MF_DROP:
            //
            // Drop, essentially no-op.
            //
            Mfe->InPackets++;
            Mfe->InOctets += 
                Control->NetBufferList->FirstNetBuffer->DataLength;
            IppDereferenceMfe(Mfe);
            return FALSE;
        case MF_FORWARD:
            break;
        default: 
            ASSERT(FALSE);
    }

    Mfe->InPackets++;

    //
    // Given Mfe, validate the incoming packet.
    //
    if (ArrivalInterface->Index != Mfe->IncomingInterfaceIndex) {
        Mfe->DifferentInInterfacePackets++;
   
        IppNotifyMfeChange(
            Compartment->Protocol, 
            MF_INCOMING_WRONG_IF, 
            Control, 
            ArrivalInterface, 
            NULL, 
            0, 
            NULL);
        IppDereferenceMfe(Mfe);
        return FALSE;
    }

    //
    // Update statistics.
    //
    Mfe->InOctets += Control->NetBufferList->FirstNetBuffer->DataLength;

    for (Link = Mfe->NextHopList.Flink; Link != &Mfe->NextHopList; 
        Link = Link->Flink) {
        MfeNextHop = CONTAINING_RECORD(Link, IP_MFE_NEXT_HOP, Link);
        OutgoingInterface = MfeNextHop->CurrentNextHop->Interface;
        
        if (HopLimit <= OutgoingInterface->MulticastForwardingHopLimit) {
            //
            // Do not forward on this hop due to low hop limit.            
            //
            IppMulticastForwardingTrace(
                TRACE_LEVEL_WARNING, 
                Protocol, 
                ArrivalInterface->Index, 
                Group, 
                SourceAddress, 
                "Packet hoplimit is low. Dropping");
            continue;
        }
        Clone = IppCreateClonePacketForForwarding(Control, Protocol);
        if (Clone == NULL) {            
            continue;
        }
        IppReferenceNeighbor(MfeNextHop->CurrentNextHop);
        Clone->NextHop = (PIP_NEXT_HOP) MfeNextHop->CurrentNextHop;
        Clone->IsNextHopReferenced = TRUE;

        //
        // Determine if forwarding is allowed and decrement the hop limit.
        //
        if (!IppForwardPackets(
                Protocol,
                ArrivalInterface,
                Clone->NextHop->Interface,
                Clone,
                Clone->NextHop,
                FALSE,
                FALSE,
                &DiscardReason)) {
            //
            // No need to invoke discard inspection point for clones.
            //
            ASSERT(Clone->Next == NULL);
            IppCompleteAndFreePacketList(Clone, FALSE);
            continue;
        }
        //
        // The clone is ready for forwarding.
        //
        Forwarded = TRUE;
        MfeNextHop->OutPackets++;
        IppAppendToGenericList(RemoteArgs, Clone);
    }
    IppDereferenceMfe(Mfe);
    return Forwarded;
}

VOID
IppMfeSetTimeOut(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    Advance the Mfe timer anothet tick and check if any Mfes expired. If some 
    Mfes expired, they are removed from Mfe set and Nsi notification is made.
    
Arguments:

    Compartment - Supplies the compartment.

Return Value:

    None.
    
Caller LOCK: 

    None.
    
Caller IRQL: 

    DISPATCH_LEVEL.

--*/
{
    PIP_MFE_LOCKED_SET MfeSet = Compartment->MfeSet;
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_MFE ExpiredMfe = NULL;
    ULONG NumExpiredMfes = 0, i;
    PIP_MFE ExpiredMfes[MAX_MFE_COUNT];
    LIST_ENTRY FiredList;
    
    //
    // We must be at dispatch irql.
    //
    DISPATCH_CODE();

    RtlAcquireWriteLockAtDpcLevel(&MfeSet->Lock, &LockHandle);

    //
    // Determine which timers fired.
    //
    TtFireTimer(MfeSet->TimerTable, &FiredList);

    // 
    // If more than MAX_MFE_COUNT fired, some may not get reported.
    //
    while (!IsListEmpty(&FiredList)) {
        ExpiredMfe = 
            (PIP_MFE) CONTAINING_RECORD(
                RemoveHeadList(&FiredList), 
                IP_MFE, 
                TimerEntry.Link);
            
        if (NumExpiredMfes < MAX_MFE_COUNT) {
            //
            // With the write lock on Mfe set, this Mfe cannot disappear.
            //
            IppReferenceMfe(ExpiredMfe);
            ExpiredMfes[NumExpiredMfes++] = ExpiredMfe;
        } else {
            //
            // Review comment: Assert will help detect if the limit is too low.
            //
            ASSERT(FALSE);
        }
        
        //
        // Remove Mfe from Mfe set. It has already been removed from timer 
        // table.
        //
        TtInitializeTimer(&ExpiredMfe->TimerEntry);
        IppRemoveMfeUnderLock(ExpiredMfe);
    }
    
    RtlReleaseWriteLockFromDpcLevel(&MfeSet->Lock, &LockHandle);

    if (NumExpiredMfes > 0) {
        IppNotifyMfeChange(
            Compartment->Protocol, 
            MF_DELETE_MFE, 
            NULL, 
            NULL, 
            NULL, 
            NumExpiredMfes, 
            ExpiredMfes);
        for (i = 0; i < NumExpiredMfes; i++) {
            IppDereferenceMfe(ExpiredMfes[i]);
        }
    }
}

__inline
ULONG
IppCopyMfeKey(
    IN PIP_MFE Mfe,
    OUT PUCHAR Buffer
    ) 
/*++

Routine Description:

    Copy Mfe key for the given Mfe to the buffer for notification.
    
Arguments:

    Mfe - Supplies the Mfe whose key is to be written to buffer.

    Buffer - Returns the buffer with the Mfe key.

Return Value:

    Number of bytes written.

Caller LOCK: 

    None.
    
Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PROTOCOL Protocol = Mfe->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    ULONG BytesWritten = 0;
    
    if (IS_IPV4_PROTOCOL(Protocol)) {
        PIPV4_MFE_KEY Key = (PIPV4_MFE_KEY) Buffer;

        RtlCopyMemory(&Key->CompartmentId, &Mfe->Compartment->CompartmentId, 
            sizeof(COMPARTMENT_ID));
        RtlCopyMemory(&Key->Group, Mfe->GroupAddress, AddressBytes);
        RtlCopyMemory(&Key->SourcePrefix, Mfe->SourceAddress, AddressBytes);
        Key->SourcePrefixLength = AddressBytes * 8;

        BytesWritten = sizeof (*Key);
    } else {
        PIPV6_MFE_KEY Key = (PIPV6_MFE_KEY) Buffer;

        RtlCopyMemory(&Key->CompartmentId, &Mfe->Compartment->CompartmentId, 
            sizeof(COMPARTMENT_ID));
        RtlCopyMemory(&Key->Group, Mfe->GroupAddress, AddressBytes);
        RtlCopyMemory(&Key->SourcePrefix, Mfe->SourceAddress, AddressBytes);
        Key->SourcePrefixLength = AddressBytes * 8;
        BytesWritten = sizeof (*Key);
    }
    return BytesWritten;
}

VOID
IppNotifyMfeChangeWorker(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    This worker routine is called to post a notification to RRAS.
    The context is parsed to obtain the rod and Nsi is called for notification.
    
Arguments:

    DeviceObject - Supplies the device object on which the work item was
        created.

    Context - Supplies the context created when the work item was queued.

Return Value:

    None

Caller LOCK:

    None. 

Caller IRQL:

    PASSIVE level.

--*/
{
    NM_INDICATE_PARAMETER_CHANGE NsiArgs = {0};
    PIP_WORK_QUEUE_ITEM IpWorkItem = Context;
    PIP_PROTOCOL Protocol = (PIP_PROTOCOL) IpWorkItem->Context;
    PNMP_CLIENT_CONTEXT ClientContext = Protocol->NmClientContext;
    PNMP_NOTIFICATION_CONTEXT NotificationContext = 
        &ClientContext->MulticastForwardingNotificationContext;

    PASSIVE_CODE();
    
    UNREFERENCED_PARAMETER(DeviceObject);

    IoFreeWorkItem(IpWorkItem->WorkQueueItem);

    //
    // Create the Nsi notification structure. The full ROD
    // structure is passed back up to the client for inspection. This prevents
    // the client from having to call back down at all.
    //
    NsiArgs.ProviderHandle = ClientContext->Npi.ProviderHandle;
    NsiArgs.ObjectIndex = NlMfeNotifyObject;
    
    NsiArgs.KeyStructDesc.KeyStructLength = 0;
    NsiArgs.ParamDesc.StructType = NsiStructRoDynamic;
    if (IS_IPV4_PROTOCOL(Protocol)) {
        NsiArgs.ParamDesc.ParameterLength = sizeof(IPV4_MFE_NOTIFICATION_ROD);
    } else {
        NsiArgs.ParamDesc.ParameterLength = sizeof(IPV6_MFE_NOTIFICATION_ROD);
    }
    NsiArgs.ParamDesc.ParameterOffset = 0;
    NsiArgs.ParamDesc.Parameter = (PUCHAR) (IpWorkItem + 1);

    ClientContext->Npi.Dispatch->ParameterChange(&NsiArgs);
    
    if (RoDereference(&NotificationContext->ReferenceObject)) {
        KeSetEvent(&NotificationContext->DeregisterCompleteEvent, 0, FALSE);
    }
    IppDereferenceNsiClientContext(Protocol);
    ExFreePool(IpWorkItem);
}

NTSTATUS
IppNotifyMfeChange(
    IN PIP_PROTOCOL Protocol,
    IN NL_MFE_NOTIFICATION_TYPE NotificationType,
    IN PIP_REQUEST_CONTROL_DATA Control OPTIONAL,
    IN PIP_INTERFACE ArrivalInterface OPTIONAL,
    IN PIP_SUBINTERFACE ArrivalSubInterface OPTIONAL,
    IN ULONG NumExpiredMfes OPTIONAL,
    IN PIP_MFE *ExpiredMfes OPTIONAL
    )
/*++

Routine Description:

    This routine is called to notify clients of
    - A received packet with no corresponding Mfe, or
    - A packet coming in from wrong interface, or
    - Expiration of Mfes.
    This function saves the rod structure needed then postpones the
    actual work to a workitem.
    
Arguments:

    Protocol - Supplies the protocol on which the request was created.

    NotificationType - Supplies the type of notification to be made.

    Control - Supplies the packet causing the notification. Specified either 
        when no Mfe is found or when packet came in from wrong interface.

    ArrivalInterface - Supplies the arrival interface for the packet.

    ArrivalSubInterface - Supplies the subinterface on which the packet 
        arrived.

    NumExpiredMfes - Supplies the number of Mfes expired. Specified when 
        notification is being caused by expiration of Mfe activity timer.

    ExpiredMfes - Supplies list of expired Mfes.

Return Value:

    Status of change request.

Caller LOCK: 

    None.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNMP_NOTIFICATION_CONTEXT NotificationContext;
    PIP_WORK_QUEUE_ITEM Context;
    PIO_WORKITEM WorkItem;
    PNL_MFE_NOTIFICATION_ROD Rod;
    ULONG RodSize = sizeof(IPV4_MFE_NOTIFICATION_ROD);
    ULONG MfeListOffset = FIELD_OFFSET(IPV4_MFE_NOTIFICATION_ROD,Mfe.Mfe);
    ULONG i = 0, Bytes;
    PUCHAR Buffer;
    
    if (Protocol->Level != IPPROTO_IP) {
        RodSize = sizeof(IPV6_MFE_NOTIFICATION_ROD);
    }
    
    //
    // Take a reference on the attachment.  If this succeeds,
    // then we can safely access the NmClientContext.
    //
    if (!RoReference(&Protocol->NmClientReferenceObject)) {
        return STATUS_UNSUCCESSFUL;
    }

    NotificationContext = 
        &Protocol->NmClientContext->MulticastForwardingNotificationContext;

    //
    // Take a reference on the notification registration.
    // This prevents deregistration from completing until we're done.
    //
    if (!RoReference(&NotificationContext->ReferenceObject)) {
        //
        // There's no one to notify.
        //
        IppDereferenceNsiClientContext(Protocol);
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Queue a workitem.
    //
    Context = 
        ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(IP_WORK_QUEUE_ITEM) + RodSize,
            IpGenericPoolTag);
    if (Context == NULL) {
        RoDereference(&NotificationContext->ReferenceObject);
        IppDereferenceNsiClientContext(Protocol);
        return STATUS_UNSUCCESSFUL;
    }
    
    WorkItem = IoAllocateWorkItem(IppDeviceObject);

    if (WorkItem == NULL) {
        ExFreePool(Context);
        RoDereference(&NotificationContext->ReferenceObject);
        IppDereferenceNsiClientContext(Protocol);
        return STATUS_UNSUCCESSFUL;
    }

    Context->WorkQueueItem = WorkItem;
    Context->Context = Protocol;
    Rod = (PNL_MFE_NOTIFICATION_ROD) (Context + 1);

    //
    // Fill in the rod structure.
    //
    Rod->NotificationType = NotificationType;
    switch (NotificationType) {
        case MF_RECEIVE_PACKET:
        case MF_INCOMING_WRONG_IF:
            {
                Rod->Packet.IncomingInterfaceIndex = ArrivalInterface->Index;
                if (ArrivalSubInterface != NULL) {
                    Rod->Packet.IncomingSubInterfaceIndex = 
                        ArrivalSubInterface->Index;
                }

                //
                // Fill in initial portion of the packet.
                //
                Bytes = 
                    NetioGetContiguousDataBufferSize(
                        Control->NetBufferList->FirstNetBuffer);
                Bytes = min(Bytes, MF_PACKET_BUFFER_SIZE);
                Buffer = 
                    NetioGetDataBufferSafe(
                        Control->NetBufferList->FirstNetBuffer, 
                        Bytes);
                Rod->Packet.DataLength = Bytes;
                RtlCopyMemory((PUCHAR)Rod->Packet.Data, Buffer, Bytes);
            }
            break;
        case MF_DELETE_MFE:

            Rod->NumberOfMfes = NumExpiredMfes;
            Buffer = ((PUCHAR) Rod) + MfeListOffset;
            for (i = 0; i < NumExpiredMfes; i++) {
                Bytes = IppCopyMfeKey(ExpiredMfes[i], Buffer);
                Buffer = (PUCHAR) Buffer + Bytes;
            }            
            break;
    }
        
    IoQueueWorkItem(
        WorkItem,
        IppNotifyMfeChangeWorker,
        DelayedWorkQueue,
        Context);
    
    return STATUS_SUCCESS;
}

BOOLEAN 
IppValidateMfeKey(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourcePrefix,
    IN ULONG SourcePrefixLength
    )
{
    PIP_COMPARTMENT Compartment;
    ULONG AddressBits = Protocol->Characteristics->AddressBytes * 8;

    //
    // Only support full source addresses.
    //
    if (SourcePrefixLength != AddressBits) {
        return FALSE;
    }

    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        return FALSE;
    }
    IppDereferenceCompartment(Compartment);

    if (Protocol->AddressType(Group) != NlatMulticast) {
        return FALSE;
    }

    if (IppIsInvalidSourceAddressStrict(Protocol, SourcePrefix)) {
        return FALSE;
    }
    
    return TRUE;
}

NTSTATUS
NTAPI
IppValidateSetAllMfeParameters(
    IN NSI_SET_ACTION Action,
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourcePrefix,
    IN ULONG SourcePrefixLength,
    IN PNL_MFE_RW MfeRw,
    OUT PVOID *ProviderTransactionContext
    )
/*++

Routine Description:

    This function is used to validate Mfe settings. 

Arguments:

    Action - Supplies the action to be performed for the Mfe.

    Protocol -Supplies the protocol.

    CompartmentId - Supplies the compartment.

    Group - Supplies the multicast group address.

    SourcePrefix - Supplies the source prefix.

    SourcePrefixLength - Supplies the length of source prefix.

    MfeRw - Supplies the read-write Mfe information.
    
    ProviderTransactionContext - Returns the transaction context

Return Value:

    Status of the operation.

--*/
{
    PIP_COMPARTMENT Compartment = NULL;
    PIP_INTERFACE IncomingInterface = NULL;
    IF_INDEX IfIndex;
    ULONG i=0, j=0;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Group); 
    UNREFERENCED_PARAMETER(SourcePrefix); 
    UNREFERENCED_PARAMETER(SourcePrefixLength);
    UNREFERENCED_PARAMETER(ProviderTransactionContext);
    
    switch (Action) {
        case NsiSetCreateOrSet:
            break;
        case NsiSetDelete:
            return STATUS_SUCCESS;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Consider acquiring readlock and validating interface indices.
    //    
    if (MfeRw->NumberOfOutgoingInterfaces != (ULONG) -1) {
        if (MfeRw->NumberOfOutgoingInterfaces > MAX_MFE_INTERFACES) {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        //
        // If no outgoing interfaces are specified, Mfe will drop all packets.
        // No need to validate the incoming interface.
        //
        if (MfeRw->NumberOfOutgoingInterfaces > 0) {
            
            //
            // Incoming interface must be specified.
            //
            IncomingInterface = 
                IppFindInterfaceByIndex(
                    Compartment,
                    MfeRw->IncomingInterfaceIndex);
            if ((IncomingInterface == NULL) ||
                (IS_LOOPBACK_INTERFACE(IncomingInterface))) {
                Status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }
            
            for (i = 0; i < MfeRw->NumberOfOutgoingInterfaces; i++) {
                IfIndex = MfeRw->OutgoingInterfaces[i].OutgoingInterfaceIndex;

                //
                // Do only minimal validation.
                //
                if ((IfIndex == (IF_INDEX) -1) || 
                    (IfIndex == MfeRw->IncomingInterfaceIndex)) {
                    Status = STATUS_INVALID_PARAMETER;
                    goto Exit;
                }
                //
                // Check for duplicates.
                //
                for (j = i + 1; j < MfeRw->NumberOfOutgoingInterfaces; j++) {
                    if (IfIndex == 
                        MfeRw->OutgoingInterfaces[j].OutgoingInterfaceIndex) {
                        Status = STATUS_INVALID_PARAMETER;
                        goto Exit;
                    }
                }
            }
        }
    }

Exit:
    if (IncomingInterface != NULL) {
        IppDereferenceInterface(IncomingInterface);
    }
    IppDereferenceCompartment(Compartment);
    return Status;
}

NTSTATUS
NTAPI
IppCommitSetAllMfeParameters(
    IN NSI_SET_ACTION Action,
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourcePrefix,
    IN ULONG SourcePrefixLength,
    IN PNL_MFE_RW MfeRw,
    OUT PVOID *ProviderTransactionContext
    )
/*++

Routine Description:

    This function is used to set/create an Mfe. Commit may fail as validation 
    was not stringent enough.

Arguments:

    Action - Supplies the action to be performed for the Mfe.

    Protocol - Supplies the protocol.

    CompartmentId - Supplies the compartment.

    Group - Supplies the multicast group address.

    SourcePrefix - Supplies the source prefix.

    SourcePrefixLength - Supplies the length of source prefix.

    MfeRw - Supplies the read-write Mfe information.
    
    ProviderTransactionContext - Returns the transaction context

Return Value:

    Status of the operation.

--*/
{
    PIP_COMPARTMENT Compartment = NULL;
    PIP_INTERFACE IncomingInterface = NULL, OutgoingInterface = NULL;
    PIP_SUBINTERFACE OutgoingSubInterface = NULL;
    PIP_NEIGHBOR Neighbor = NULL;
    PIP_MFE_NEXT_HOP MfeNextHop = NULL;
    ULONG i=0;
    PIP_MFE Mfe = NULL, OldMfe = NULL, GoodMfe = NULL;
    PIP_REQUEST_CONTROL_DATA OldClones = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE LockHandle;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(SourcePrefixLength);
    UNREFERENCED_PARAMETER(ProviderTransactionContext);
        
    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        return STATUS_INVALID_PARAMETER;
    }    
    
    switch (Action) {
        case NsiSetCreateOrSet:

            RtlAcquireReadLock(&Compartment->InterfaceSet.Lock, &OldIrql);

            RtlAcquireWriteLock(&Compartment->MfeSet->Lock, &LockHandle);

            OldMfe = IppFindMfeUnderLock(Compartment, Group, SourcePrefix);
            if (OldMfe != NULL) {

                //
                // Cache pending packets from the old entry before it is 
                // deleted. 
                //
                OldClones = 
                    (PIP_REQUEST_CONTROL_DATA) OldMfe->PendingPackets.Head;

                IppInitializeGenericList(&OldMfe->PendingPackets);
                IppRemoveMfeUnderLock(OldMfe);
            }
            
            Mfe = 
                IppCreateAndInsertMfeUnderLock(
                    Compartment, 
                    Group, 
                    SourcePrefix);

            //
            // Mfe (if created) has a reference to the compartment.
            //
            IppDereferenceCompartment(Compartment);            
            if (Mfe == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto ErrorInitializingMfe;
            }
            
            if (MfeRw->TimeOut != (ULONG) -1) {
                Mfe->TimeOut = MfeRw->TimeOut;

                //
                // Start the timer with specified timeout.
                //
                IppStartMfeTimer(Mfe);
            }
            
            if (MfeRw->NumberOfOutgoingInterfaces > 0) {             
                IncomingInterface = 
                    IppFindInterfaceByIndexUnderLock(
                        Compartment, 
                        MfeRw->IncomingInterfaceIndex);
                if (IncomingInterface == NULL) {
                    Status = STATUS_INVALID_PARAMETER;
                    goto ErrorInitializingMfe;
                }
                Mfe->IncomingInterfaceIndex = IncomingInterface->Index;
                Mfe->Scope = IppGetScopeId(IncomingInterface, Group);
                IppDereferenceInterface(IncomingInterface);

                //
                // This can potentially take some time.
                //
                for (i = 0; i < MfeRw->NumberOfOutgoingInterfaces; i++) {
                    OutgoingSubInterface = 
                        IppFindSubInterfaceByIndexUnderLock(
                            Compartment, 
                            MfeRw->OutgoingInterfaces[i].
                            OutgoingInterfaceIndex,
                            MfeRw->OutgoingInterfaces[i].
                            OutgoingSubInterfaceIndex);

                    if (OutgoingSubInterface == NULL) {
                        Status = STATUS_INVALID_PARAMETER;
                        goto ErrorInitializingMfe;
                    }

                    //
                    // Verify that the outgoing interface matches the scope.
                    // Scope Id must have been specified.
                    //
                    OutgoingInterface = OutgoingSubInterface->Interface;
                    
                    if (Mfe->Scope.Zone !=
                        IppGetInterfaceScopeZone(
                            OutgoingInterface, 
                            Mfe->Scope.Level)) {
                        Status = STATUS_INVALID_PARAMETER;
                        IppDereferenceSubInterface(OutgoingSubInterface);
                        goto ErrorInitializingMfe;
                    }
                                   
                    Neighbor = 
                        IppFindOrCreateNeighbor(
                            OutgoingSubInterface->Interface, 
                            OutgoingSubInterface, 
                            Group, 
                            NlatMulticast);
                    
                    //
                    // Neighbor holds a reference to SubInterface.
                    //
                    IppDereferenceSubInterface(OutgoingSubInterface);
                    
                    if (Neighbor == NULL) {
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        goto ErrorInitializingMfe;
                    }
                    
                    MfeNextHop = 
                        ExAllocatePoolWithTag(
                            NonPagedPool, 
                            sizeof(IP_MFE_NEXT_HOP), 
                            IpMfePoolTag);
                    if (MfeNextHop == NULL) {
                        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                            "IPNG: Failure allocating Mfe Next Hop\n");
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        IppDereferenceNeighbor(Neighbor);
                        goto ErrorInitializingMfe;
                    }
                    RtlZeroMemory(MfeNextHop, sizeof(*MfeNextHop));

                    //
                    // Neighbor already comes referenced.
                    //
                    MfeNextHop->CurrentNextHop = Neighbor;
                    MfeNextHop->OutPackets = 0;
                    InsertTailList(&Mfe->NextHopList, &MfeNextHop->Link);
                    Mfe->NumberOfNextHops++;
                }
            } else {
                Mfe->State = MF_DROP;
                Mfe->NumberOfNextHops = 0;
                InitializeListHead(&Mfe->NextHopList);
            }

            GoodMfe = Mfe;
            goto Exit;
            
ErrorInitializingMfe:
            if (Mfe != NULL) {
                IppRemoveMfeUnderLock(Mfe);
            }

Exit:
            RtlReleaseWriteLock(&Compartment->MfeSet->Lock, &LockHandle);
            RtlReleaseReadLock(&Compartment->InterfaceSet.Lock, OldIrql);
            //
            // Now handle the queued packets.
            //
            IppDispatchMfeQueuedPackets(GoodMfe, OldClones);
            //
            // Dereference may result in cleanup, hence do it after 
            // releasing locks.
            //
            if (Mfe != NULL) {
                IppDereferenceMfe(Mfe);
            }
            if (OldMfe != NULL) {
                IppDereferenceMfe(OldMfe);
            }
            break;
        case NsiSetDelete:
            //
            // The Mfe is likely to be found in the set, hence take the write
            // lock to begin with.
            //
            RtlAcquireWriteLock(&Compartment->MfeSet->Lock, &LockHandle);
            Mfe = IppFindMfeUnderLock(Compartment, Group, SourcePrefix);
            if (Mfe != NULL) {
                IppRemoveMfeUnderLock(Mfe);
            } else {
                Status = STATUS_NOT_FOUND;
            }
            RtlReleaseWriteLock(&Compartment->MfeSet->Lock, &LockHandle);
            if (Mfe != NULL) {
                IppDereferenceMfe(Mfe);
            }
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }
    return Status;    
}

NTSTATUS
NTAPI
IppSetAllMulticastForwardingParameters(
    IN NSI_SET_ACTION Action,
    IN NSI_TRANSACTION Transaction,
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourcePrefix,
    IN ULONG SourcePrefixLength,
    IN PNL_MFE_RW Rw,
    OUT PVOID *ProviderTransactionContext
    )
/*++

Routine Description:

    This function is used to set/create an Mfe. 

Arguments:

    Action - Supplies the action to be performed for the Mfe.

    Transaction - Supplies the transaction state.

    Protocol -Supplies the protocol.

    CompartmentId - Supplies the compartment.

    Group - Supplies the multicast group address.

    SourcePrefix - Supplies the source prefix.

    SourcePrefixLength - Supplies the length of source prefix.

    Rw - Supplies the read-write Mfe information.
    
    ProviderTransactionContext - Returns the transaction context

Return Value:

    STATUS_SUCCESS, or failure code.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    
    if ((Transaction == NsiTransactionNone) ||
        (Transaction == NsiTransactionValidate)) {
        if (!IppValidateMfeKey(
                 Protocol, 
                 CompartmentId, 
                 Group, 
                 SourcePrefix, 
                 SourcePrefixLength)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (Action == NsiSetReset) {
        return STATUS_NOT_IMPLEMENTED;
    }

    //
    // FUTURE-2005/08/02-sgarg -- Handle other transaction cases.
    //
    switch (Transaction) {
        case NsiTransactionNone:
            Status = 
                IppValidateSetAllMfeParameters(
                    Action,
                    Protocol,
                    CompartmentId,
                    Group, 
                    SourcePrefix, 
                    SourcePrefixLength, 
                    Rw, 
                    ProviderTransactionContext);
            if (NT_SUCCESS(Status)) {
                Status = 
                    IppCommitSetAllMfeParameters(
                        Action, 
                        Protocol,
                        CompartmentId, 
                        Group, 
                        SourcePrefix, 
                        SourcePrefixLength, 
                        Rw,
                        ProviderTransactionContext);
            }
            break;
        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
    }
    
    return Status;
}

NTSTATUS
NTAPI
IppGetAllMulticastForwardingParameters(
    IN PIP_PROTOCOL Protocol,
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function is used to get an Mfe and/or statistics. 

Arguments:

    Protocol -Supplies the protocol.

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    STATUS_SUCCESS, or failure code.

--*/
{
    PIP_COMPARTMENT Compartment;
    COMPARTMENT_ID CompartmentId;
    UCHAR *Group = NULL;
    UCHAR *SourceAddress = NULL;
    PIP_MFE Mfe = NULL;
    PNL_MFE_ROD MfeRod = NULL;
    PNL_MFE_RW MfeRw = NULL;
    PIP_MFE_NEXT_HOP MfeNextHop = NULL;
    PLIST_ENTRY Link;
    ULONG i = 0;

    if (IS_IPV4_PROTOCOL(Protocol)) {
        PIPV4_MFE_KEY Key = (PIPV4_MFE_KEY) Args->KeyStructDesc.KeyStruct;
        CompartmentId = Key->CompartmentId;
        Group = (UCHAR *)&Key->Group;
        SourceAddress = (UCHAR *)&Key->SourcePrefix;
    } else {
        PIPV6_MFE_KEY Key = (PIPV6_MFE_KEY) Args->KeyStructDesc.KeyStruct;
        CompartmentId = Key->CompartmentId;
        Group = (UCHAR *)&Key->Group;
        SourceAddress = (UCHAR *)&Key->SourcePrefix;
    }

    switch (Args->Action) {
    case NsiGetExact:
        Compartment = IppFindCompartmentById(Protocol, CompartmentId);
        if (Compartment == NULL) {
            return STATUS_NOT_FOUND;
        }
        
        Mfe = IppFindMfe(Compartment, Group, SourceAddress);
        IppDereferenceCompartment(Compartment);        
        break;
    case NsiGetFirst:
    case NsiGetNext:
        return STATUS_NOT_IMPLEMENTED;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }
    
    if (Mfe == NULL) {
        return STATUS_NOT_FOUND;
    }
    
    if (Args->StructDesc.RoDynamicParameterStruct != NULL) {
        MfeRod = (PNL_MFE_ROD) Args->StructDesc.RoDynamicParameterStruct;
        MfeRod->IncomingInterfaceIndex = Mfe->IncomingInterfaceIndex;
        MfeRod->InPackets = Mfe->InPackets;
        MfeRod->InOctets = Mfe->InOctets;
        MfeRod->DifferentInterfacePackets = Mfe->DifferentInInterfacePackets;
        MfeRod->NumberOfOutgoingInterfaces = Mfe->NumberOfNextHops;

        i = 0;
        for (Link = Mfe->NextHopList.Flink; Link != &Mfe->NextHopList; 
             Link = Link->Flink) {
            MfeNextHop = CONTAINING_RECORD(Link, IP_MFE_NEXT_HOP, Link);
            MfeRod->OutgoingInterfaces[i].OutPackets = MfeNextHop->OutPackets;
            i++;
        }
    }

    if (Args->StructDesc.RwParameterStruct != NULL) {
        MfeRw = (PNL_MFE_RW) Args->StructDesc.RwParameterStruct;
        MfeRw->IncomingInterfaceIndex = Mfe->IncomingInterfaceIndex;
        MfeRw->TimeOut = Mfe->TimeOut;
        MfeRw->NumberOfOutgoingInterfaces = Mfe->NumberOfNextHops;

        i = 0;
        for (Link = Mfe->NextHopList.Flink; Link != &Mfe->NextHopList; 
             Link = Link->Flink) {
            MfeNextHop = CONTAINING_RECORD(Link, IP_MFE_NEXT_HOP, Link);
            MfeRw->OutgoingInterfaces[i].OutgoingInterfaceIndex = 
                MfeNextHop->CurrentNextHop->Interface->Index;
            MfeRw->OutgoingInterfaces[i].OutgoingSubInterfaceIndex =
                MfeNextHop->CurrentNextHop->SubInterface->Index;
            i++;
        }
    }

    Args->StructDesc.RoStaticParameterStructLength = 0;

    IppDereferenceMfe(Mfe);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IpRegisterMulticastForwardingChangeNotification(
    IN PNM_REQUEST_REGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Enable multicast forwarding notifications via the NSI.

Arguments:

    Request - Supplies a request to enable notifications.

Return Value:

    STATUS_DELETE_PENDING if we're trying to deregister with the NSI.
    STATS_SUCCESS on success.

--*/
{
    PNMP_CLIENT_CONTEXT ClientContext = 
        (PNMP_CLIENT_CONTEXT) Request->ProviderHandle;
    PNMP_NOTIFICATION_CONTEXT NotificationContext =
        &ClientContext->MulticastForwardingNotificationContext;

    //
    // Take a reference on the attachment.
    //
    if (!RoReference(&ClientContext->Protocol->NmClientReferenceObject)) {
        return STATUS_DELETE_PENDING;
    }

    RoInitialize(&NotificationContext->ReferenceObject);
    return STATUS_SUCCESS;
}


VOID
NTAPI
IpDeregisterMulticastForwardingChangeNotification(
    IN PNM_REQUEST_DEREGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Disable multicast forwarding notifications via the NSI.

Arguments:

    Request - Supplies a request to disable notifications.

Caller IRQL:

    Must be called at IRQL <= APC level.

--*/
{
    PNMP_CLIENT_CONTEXT ClientContext = 
        (PNMP_CLIENT_CONTEXT) Request->ProviderHandle;
    PNMP_NOTIFICATION_CONTEXT NotificationContext = 
        &ClientContext->MulticastForwardingNotificationContext;

    PAGED_CODE();

    //
    // Initialize an event we can wait on until deregistering is complete.
    //
    KeInitializeEvent(
        &NotificationContext->DeregisterCompleteEvent, 
        NotificationEvent, 
        FALSE);

    if (!RoUnInitialize(&NotificationContext->ReferenceObject)) {
        //
        // Wait for notifications in progress to complete.
        //
        KeWaitForSingleObject(
            &NotificationContext->DeregisterCompleteEvent, 
            UserRequest, 
            KernelMode, 
            FALSE, 
            NULL);
    }

    KeUninitializeEvent(&NotificationContext->DeregisterCompleteEvent);

    //
    // Release the reference on the attachment.
    //
    IppDereferenceNsiClientContext(ClientContext->Protocol);
}

BOOLEAN
IppIsMfeSetMemoryQuotaExceeded(
    IN PIP_MFE_LOCKED_SET MfeSet
    )
/*++

Routine Description:
    
    Determines if the MfeSet memory quota has been exceeded and if
    any incoming packets should be dropped (and not queued)
    followind the RED-like algorithim and the DefaultQueuedPacketQuota
    which is a fraction of the physical memory. 

Arguments:
    
     MfeSet - Supplies an Mfe set.

Return Value:

    Returns TRUE if any new packets should be dropped else FALSE

Caller LOCK: 

    Exclusive lock on Mfe set.

Caller IRQL: 

    DISPATCH_LEVEL.

--*/
{
    BOOLEAN Prune = FALSE;
    ULONG Threshold = MfeSet->TotalLimitOfQueuedPackets / 2;
    
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
    if ((MfeSet->TotalSizeOfQueuedPackets > Threshold) &&
        (RandomNumber(0, Threshold) <
            MfeSet->TotalSizeOfQueuedPackets - Threshold)) {
        Prune = TRUE;
    }

    return Prune;
}