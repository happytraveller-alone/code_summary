/*++

Copyright (c) 2001-2002  Microsoft Corporation

Module Name:

    neighbor.c

Abstract:

    This module contains generic network layer neighbor management functions.

Author:

    Mohit Talwar (mohitt) Tue Oct 09 08:51:21 2001

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "neighbor.tmh"

#pragma warning(disable:4204)   // non-constant aggregate initializer

#if NEIGHBOR_REFHIST
PREFERENCE_HISTORY IppNeighborReferenceHistory;
#endif

//
// Start off small!  Configure.
//
ULONG IppNeighborCacheLimit = 256;

NL_NEIGHBOR_RW IppNeighborDefaultRwData = {0};

#if NEIGHBOR_REFHIST
VOID
IppDereferenceNeighborWithHistory(
    __in PIP_NEIGHBOR Neighbor,
    __in ULONG Line,
    __in PCHAR File
    )
#else
VOID
IppDereferenceNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
#endif
/*++

Routine Description:

    Dereferences a neighbor via the network layer.

Arguments:

    Neighbor - Supplies a pointer to the neighbor to dereference.

Locks:

    Assumer caller held a reference on the neighbor.

--*/
{
    if ((Neighbor->ReferenceCount == 2) && 
        !Neighbor->IsConfigured &&
        Neighbor->IsInSet) {
        InterlockedIncrement(&Neighbor->Interface->NeighborSet.CacheSize);
    }

#if NEIGHBOR_REFHIST
    _IppDereferenceNeighbor(Neighbor, Line, File);
#else
    IppDereferenceNeighborPrimitive(Neighbor);
#endif
}


__inline
VOID
IppDropWaitQueue(
    IN PIP_INTERFACE Interface,
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:
    
    Drop a packet that had been waiting for address resolution.
    
Arguments:

    Interface - Supplies the interface whose drop queue to add the packet to.

    Control - Supplies the waiting packet to drop.

Return Value:

    None.
    
Locks:

Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;

    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);
    
    Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        OutDiscards += IppGetPacketCount(Control->NetBufferList);
    
    //
    // Note: The queue is at most one packet deep.
    //
    ASSERT(Control->Next == NULL);

    //
    // Drop silently.
    //
    Control->NetBufferList->Status = STATUS_SUCCESS;
    
    Control->Next = Interface->NeighborSet.DropQueue;
    Interface->NeighborSet.DropQueue = Control;

}


__inline
VOID
IppFlushDropQueue(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA ControlChain,
    IN BOOLEAN DispatchLevel
    )
/*++

Routine Description:
    
    Completes a chain of packets dropped because of address resolution failure.
    
Arguments:

    Protocol - Supplies the protocol to consider.

    ControlChain - Supplies the chain of packets to complete.

    DispatchLevel - Supplies TRUE if IRQL is known to be at DISPATCH level.
    
Return Value:

    None.
    
Locks:

    This function should not be called under any lock.

--*/
{
    PIP_REQUEST_CONTROL_DATA Control;

    for (Control = ControlChain; Control != NULL; Control = Control->Next) {
        Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
            OutDiscards += IppGetPacketCount(Control->NetBufferList);
    }        
        
    //
    // IppSendErrorList may consume the NetBufferList but not the Control.
    //
    IppSendErrorListForDiscardReason(
        DispatchLevel,
        Protocol,
        ControlChain,
        IpDiscardAddressUnreachable,
        0);
    IppCompleteAndFreePacketList(ControlChain, DispatchLevel);
}


__inline
VOID
IppFlushWaitQueue(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:
    
    Completes a packet that had been waiting for address resolution, but was
    then preempted by another.  This queue overflow is congestion of a sort,
    so we must not send an ICMP error.
     
Arguments:

    Protocol - Supplies the protocol to consider.
    
    Control - Supplies the packet to complete.

Return Value:

    None.
    
Locks:

    This function should not be called under any lock.

--*/
{
    Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        OutDiscards += IppGetPacketCount(Control->NetBufferList);
    
    //
    // Note: The queue is at most one packet deep.
    //
    ASSERT(Control->Next == NULL);
    //
    // Drop silently. 
    // TODO: This should ideally complete with STATUS_ND_QUEUE_OVERFLOW.
    //
    Control->NetBufferList->Status = STATUS_SUCCESS;

    IppCompleteAndFreePacketList(Control, FALSE);
}


#if DBG
VOID
IppVerifyNeighborsUnderLock(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Validate the neighbor discovery invariants.
    
Arguments:

    Interface - Supplies the interface whose neighbors should be verified.
    
Return Value:

    None.

Caller LOCK: 

    Assumes caller holds at an exclusive on the neighbor set. This is because 
    of limitation of the hashtable. 

Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_NEIGHBOR Neighbor;
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIP_NEIGHBOR_SET NeighborSet;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);
       
    NeighborSet = &Interface->NeighborSet;
    RtlInitEnumerationHashTable(&NeighborSet->Table, &Enumerator);

    for (Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator)) {
        BOOLEAN TimerRunning;

        Neighbor = (PIP_NEIGHBOR) CONTAINING_RECORD(Curr, IP_NEIGHBOR, Link);
        
        TimerRunning = TtIsTimerActive(&Neighbor->EventTimer);

        //
        // If there is a packet waiting, we must be in the INCOMPLETE state.
        //
        ASSERT((Neighbor->WaitQueue == NULL) ||
               (Neighbor->State == NlnsIncomplete));

        //
        // If we are sending solicitations, we must have a timer running.
        //
        ASSERT((Neighbor->EventCount == 0) || TimerRunning);
    
        //
        // If the neighbor is unreachable, the interface must support ND or
        // the neighbor must be in the UNREACHABLE state.
        //
        ASSERT(!Neighbor->IsUnreachable ||
               Interface->FlCharacteristics->DiscoversNeighbors ||
               (Neighbor->State == NlnsUnreachable));

        switch (Neighbor->State) {
        case NlnsIncomplete:
        case NlnsProbe:
            //
            // In the INCOMPLETE and PROBE states,
            // we are actively sending solicitations.
            //
            ASSERT(TimerRunning);
            break;

        case NlnsReachable:
        case NlnsPermanent:
            //
            // In the REACHABLE and PERMANENT states,
            // the neighbor can not be considered unreachable.
            //
            ASSERT(!Neighbor->IsUnreachable);
            //
            // Fall through.
            //

        case NlnsStale:
        case NlnsUnreachable:
            //
            // In the STALE, UNREACHABLE, REACHABLE, and PERMANENT states,
            // we are not sending solicitations.
            //
            ASSERT(!TimerRunning);
            break;

        default:
            ASSERT(FALSE);
        }
    }
    RtlEndEnumerationHashTable(&NeighborSet->Table, &Enumerator);
}
#else  // DBG
#define IppVerifyNeighborsUnderLock(Neighbor)
#endif // DBG


ULONG
IppNeighborReachableTicks(
    IN ULONG BaseReachableTime
    )
/*++

Routine Description:
    
    Calculate a pseudo-random ReachableTicks from BaseReachableTime
    (this prevents synchronization of Neighbor Unreachability Detection
    messages from different hosts), and convert it to units of IP
    timer ticks (cheaper to do once here than at every packet send).
    
Arguments:

    BaseReachableTime - Supplies the value learnt from Router Advertisements
        (in milliseconds).
    
Return Value:

    Reachable time (in timer ticks).

--*/
{
    ULONG Factor;
    ULONG ReachableTime;

    //
    // Calculate a uniformly-distributed random value between
    // MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR of the BaseReachableTime.
    // To keep the arithmetic integer, *_RANDOM_FACTOR (and thus the
    // 'Factor' variable) are defined as percentage values.
    //
    Factor = RandomNumber(MIN_RANDOM_FACTOR, MAX_RANDOM_FACTOR);

    //
    // Now that we have a random value picked out of our percentage spread,
    // take that percentage of the BaseReachableTime.
    //
    // BaseReachableTime has a maximum value of 3,600,000 milliseconds
    // (see RFC 1970, section 6.2.1), so Factor would have to exeed 1100 %
    // in order to overflow a 32-bit unsigned integer.
    //
    ReachableTime = (BaseReachableTime * Factor) / 100;

    //
    // Convert from milliseconds (which is what BaseReachableTime is in) to
    // IP timer ticks (which is what we keep ReachableTicks in).
    //
    return IppMillisecondsToTicks(ReachableTime);
}


NTSTATUS
IppInitializeNeighborSet(
    OUT PIP_NEIGHBOR_SET NeighborSet,
    IN USHORT BucketCount
    )
/*++

Routine Description:

    Initialize a network layer neighbor set.

Arguments:

    NeighborSet - Returns an initialized neighbor set.

    BucketCount - Supplies the number of buckets desired in the event table.
        Typically set to the neighbor solicitation timeout (in ticks) for
        broadcast interfaces and to one for point-to-point interfaces.

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK: None.  Exclusive access as the interface is being created.
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    BOOLEAN Success;
    PRTL_HASH_TABLE HashTablePointer = &NeighborSet->Table;
    ASSERT(BucketCount != 0);
    
    NeighborSet->EventTable = TtCreateTable(BucketCount, FALSE);
    if (NeighborSet->EventTable == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NeighborSet->DropQueue = NULL;
    
    NeighborSet->CacheSize = 0;
    NeighborSet->LastEnumerationTick = IppTickCount;

    Success = RtlCreateHashTable(&HashTablePointer, 0, 0);

    if (!Success) {
        TtDestroyTable(NeighborSet->EventTable);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    return STATUS_SUCCESS;
}


VOID
IppUninitializeNeighborSet(
    IN OUT PIP_NEIGHBOR_SET NeighborSet
    )
/*++

Routine Description:

    Uninitialize a network layer neighbor set.

Arguments:

    NeighborSet - Returns an uninitialized neighbor set.

Return Value:

    None.

Caller LOCK: None.  Exclusive access as the interface is being destroyed.
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ASSERT(NeighborSet->DropQueue == NULL);

    ASSERT(RtlActiveEnumeratorsHashTable(&NeighborSet->Table) == 0);
    
    TtDestroyTable(NeighborSet->EventTable);
    NeighborSet->EventTable = NULL;
    RtlDeleteHashTable(&NeighborSet->Table);
}


VOID
IppDeleteNeighborSet(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Delete a network layer neighbor set.

Arguments:

    Interface - Supplies the interface whose neighbor set is to be deleted.
    
Return Value:

    None.

Caller LOCK: None.

--*/    
{
    PIP_REQUEST_CONTROL_DATA ControlBatch;

    //
    // Since subinterfaces have been deleted, the neighbor set should be empty.
    //
    ASSERT(RtlTotalEntriesHashTable(&Interface->NeighborSet.Table) ==  0);
    
    ControlBatch = Interface->NeighborSet.DropQueue;
    Interface->NeighborSet.DropQueue = NULL;

    if (ControlBatch != NULL) {
        IppFlushDropQueue(
            Interface->Compartment->Protocol,
            ControlBatch,
            FALSE);
    }
}


__inline
BOOLEAN
IppIsDeletedNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Determine if the neighbor has been deleted.

Arguments:

    Neighbor - Supplies the neighbor being inspected.
        
Return Value:

    TRUE if deleted, FALSE otherwise.

Caller LOCK: None.

--*/
{
    //
    // Check if the neighbor has been deleted from the neighbor set.
    //
    return !Neighbor->IsInSet;
}


__inline
BOOLEAN
IppIsCachedNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Determine if the neighbor is kept cached.

    Note: A cached neighbor might have an active EventTimer!
    
Arguments:

    Neighbor - Supplies the neighbor being inspected.
        The neighbor should still be a member of a neighbor set.
        
Return Value:

    TRUE if cached, FALSE otherwise.

Caller LOCK: Interface neighbor set (Shared).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    ASSERT_ANY_LOCK_HELD(&Neighbor->Interface->NeighborSetLock);
    
    return 
        ((Neighbor->ReferenceCount == 1) && 
         !Neighbor->IsConfigured &&
         !IppIsDeletedNeighbor(Neighbor));
}


__inline
PIP_NEIGHBOR
IppLessRecentlyUsedNeighbor(
    IN PIP_NEIGHBOR Current OPTIONAL,
    IN PIP_NEIGHBOR Next
    )
/*++

Routine Description:

    Return the less recently used of two neighbors.

Arguments:

    Current - Supplies the current least recently used neighbor.

    Next - Supplies the next neighbor to consider.

Return Value:

    Returns the entry used less recently.
    
--*/
{
    ASSERT(Next != NULL);
    if (Current == NULL) {
        return Next;
    }

    //
    // The following arithmetic correctly handles wraps of TickCount.
    //
    if ((ULONG) (IppTickCount - Current->LastUsed) <
        (ULONG) (IppTickCount - Next->LastUsed)) {
        return Next;
    }
    
    return Current;
}


PIP_NEIGHBOR
IppCreateNeighbor(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Create a neighbor entry.
    
Arguments:

    Interface - Supplies the interface on which the neighbor exists.
    
Return Value:

    Neighbor or NULL.

Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    PIP_NEIGHBOR Neighbor;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    //
    // Allocate the neighbor structure from the appropriate FSB pool.
    //    
    Neighbor = (PIP_NEIGHBOR)
        FsbAllocateAtDpcLevel(Interface->FlModule->NeighborPool);
    if (Neighbor != NULL) {
        RtlZeroMemory(Neighbor, sizeof(IP_NEIGHBOR));
        
        //
        // Initialize fields that remain unchanged for reused neighbors.
        //
        Neighbor->Signature = IP_NEIGHBOR_SIGNATURE;

        //
        // Note the interface over which the neighbor exists.
        //
        Neighbor->Interface = Interface;
        
        TtInitializeTimer(&Neighbor->EventTimer);
        InitializeSListHead(&Neighbor->OffloadRequestQueue);
        InitializeSListHead(&Neighbor->OffloadedBlocks);
        
        //
        // Mark the neighbor, so we know that it has not been mapped yet.
        //
        Neighbor->State = NlnsMaximum;
    } else {        
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Failure allocating %s neighbor\n", 
                   Interface->Compartment->Protocol->TraceString);
    }

    return Neighbor;
}

NETIO_INLINE
ULONG
IppComputeNeighborSetKey(
    IN PIP_INTERFACE Interface, 
    IN CONST UCHAR *DestinationAddress
    ) 
{
    return 
        IppComputeHashKeyFromAddress(
            Interface->Compartment, 
            DestinationAddress);
}

__inline
VOID
IppInsertNeighbor(
    IN PIP_NEIGHBOR Neighbor,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    Insert a neighbor in the neighbor set.
    
Arguments:

    Neighbor - Supplies the neighbor to insert.

    Address - Supplies the neighbor's network layer address.
    
Return Value:

    None.

Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).
    
--*/    
{
    PIP_INTERFACE Interface = Neighbor->Interface;
    ULONG Key;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    //
    // Initialize with a single reference for being in the neighbor set.
    //
    Neighbor->ReferenceCount = 1;

    Key = 
        IppComputeNeighborSetKey(Interface, Address);

    //
    // Link the neighbor to the neighbor set.
    //
    RtlInsertEntryHashTable(
        &Interface->NeighborSet.Table,
        &Neighbor->Link,
        Key,
        NULL);
    Neighbor->IsInSet = TRUE;
}

__inline
VOID
IppDeleteNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Delete a neighbor entry, leading to its demise.

    The neighbor should have already been uninitialized.
    
Arguments:

    Neighbor - Supplies the neighbor to be deleted.
    
Return Value:

    None.

Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    ASSERT_WRITE_LOCK_HELD(&Neighbor->Interface->NeighborSetLock);
    
    //
    // Unlink the neighbor from the neighbor set...
    //
    RtlRemoveEntryHashTable(
        &Neighbor->Interface->NeighborSet.Table, 
        &Neighbor->Link, 
        NULL);

    Neighbor->IsInSet = FALSE;

    //
    // And release the reference obtained for being in it.
    //
    IppDereferenceNeighbor(Neighbor);
}


VOID
IppCleanupNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Destroys a neighbor entry.
    
Arguments:

    Neighbor - Supplies the neighbor to be destroyed.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_SUBINTERFACE SubInterface = Neighbor->SubInterface;
    
    ASSERT(Neighbor->ReferenceCount == 0);    
    ASSERT(Neighbor->Offload.State == NotOffloaded);

    //
    // There shouldn't be any pending EventTimers or waiting Packets.
    //
    ASSERT(Neighbor->EventCount == 0);
    ASSERT(!TtIsTimerActive(&Neighbor->EventTimer));
    ASSERT(Neighbor->WaitQueue == NULL);

    //
    // Verify that the neighbor has been deleted.
    // This will catch bugs where a dereference happened without a reference.
    //
    ASSERT(IppIsDeletedNeighbor(Neighbor));

#ifdef _IP_OFFLOAD_LOGGING
    if (Neighbor->OffloadLog != NULL) {
        ExFreePoolWithTag(Neighbor->OffloadLog, IpOffloadLogPoolTag);
    }        
#endif // _IP_OFFLOAD_LOGGING
    
    FsbFree((PUCHAR) Neighbor);

    //
    // Release the neighbor's reference on its subinterface.
    // This might cause the subinterface to be destroyed, hence we do it last.
    // Note: The SubInterface may be NULL if the neighbor creation failed.
    //
    if (SubInterface != NULL) {
        IppDereferenceSubInterface(SubInterface);
    }
}


PIP_SUBINTERFACE
IppMapNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Initialize the neighbor's datalink layer mapping.

Arguments:

    Neighbor - Supplies the neighbor to map.
        
Return Value:

    SubInterface suggested by the framing layer provider, if any.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;
    FL_ADDRESS_MAPPING_TYPE Type;
    FL_REQUEST_MAP_ADDRESS Args = {0};
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    if (Neighbor->IsConfigured) {
        //
        // Don't mess with user-configured entries.
        //
        ASSERT(Neighbor->State == NlnsPermanent);
        return NULL;
    }
    
    Args.ProviderInterfaceHandle = Interface->FlContext;
    Args.NlAddress = IP_NEIGHBOR_NL_ADDRESS(Neighbor);
    Args.DlAddress = IP_NEIGHBOR_DL_ADDRESS(Neighbor, AddressLength);
    
    //
    // The framing layer has no knowledge of IPv4 subnet broadcast addresses.
    // However, these map to the same datalink layer address as the limited
    // broadcast address (0xffffffff), which the framing layer does understand.
    //
    if (Neighbor->AddressType == NlatBroadcast) {
        ASSERT(IS_IPV4_PROTOCOL(Protocol));
        Args.NlAddress = (PUCHAR) &in4addr_broadcast;
    } else {
        ASSERT(Protocol->AddressType(Args.NlAddress) == Neighbor->AddressType);
    }

    Type = Interface->FlModule->Npi.Dispatch->MapAddress(&Args);
    if (Type == FlAddressMappingDynamic) {
        //
        // Create the neighbor in the UNREACHABLE state.  If the interface
        // supports ND, we will later transition to the INCOMPLETE state
        // (e.g. when a packet is sent) and start solicitations.
        //
        Neighbor->State = NlnsUnreachable;
        RtlZeroMemory(
            IP_NEIGHBOR_DL_ADDRESS(Neighbor, AddressLength), 
            DL_ADDRESS_LENGTH_MAXIMUM);
    } else {
        ASSERT(Type == FlAddressMappingStatic);
        //
        // We might still use NUD to probe reachability for unicast addresses.
        //        
        if (Interface->UseNeighborUnreachabilityDetection &&
            (Neighbor->AddressType == NlatUnicast)) {
            Neighbor->State = NlnsStale;
        } else {
            Neighbor->State = NlnsPermanent;
        }
    }

    //
    // Initialize these timestamps to a value in the past,
    // so comparisons against them do not cause problems.
    //
    Neighbor->LastUsed = Neighbor->LastReachable =
        IppTickCount - Interface->ReachableTicks;

    //
    // Since we know nothing about the neighbor yet, we assume the following...
    // 1. The neighbor is not a router.
    // 2. The neighbor was reachable.
    // 3. The neighbor is not currently unreachable.
    // This ensures the following behavior...
    // If the neighbor is offline when we begin probing,
    // IsUnreachable will eventually transition to TRUE.
    // However, the first indication that the neighbor has come back online
    // will make IsUnreachable FALSE again,
    // regardless of whether the indication is direct or indirect.
    //
    Neighbor->IsRouter = FALSE;
    Neighbor->WasReachable = TRUE;
    Neighbor->IsUnreachable = FALSE;

    //
    // The framing layer provider may suggest a subinterface for the neighbor.
    // Otherwise, return an arbitrary subinterface.
    // Note: It is up to the caller to reference the returned subinterface.
    //
    return (Args.ClientSubInterfaceHandle != NULL)
        ? (PIP_SUBINTERFACE) Args.ClientSubInterfaceHandle
        : IppGetAnySubInterfaceOnInterfaceUnderLock(Interface);
}


PIP_NEIGHBOR
IppInitializeNeighbor(
    OUT PIP_NEIGHBOR Neighbor,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    Initialize the state of a neighbor upon creation.

    Returns a reference on the neighbor to the caller.
    
Arguments:

    Neighbor - Returns a neighbor with its state initialized.
        
    SubInterface - Optionally supplies the subinterface on which the
        neighbor exists.  If this is NULL, the "best" subinterface is chosen
        
    Address - Supplies the neighbor's network layer address.

    AddressType - Supplies the type of the network layer address.
    
Return Value:

    Neighbor, if successful.  NULL, otherwise.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_SUBINTERFACE SuggestedSubInterface;
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;

    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);
    
    //
    // The neighbor should not have been mapped yet.
    //
    ASSERT(Neighbor->ReferenceCount == 1);
    ASSERT(Neighbor->State == NlnsMaximum);

    //
    // Set the LastConfirmation to a value in the past.
    //
    Neighbor->LastConfirmation = IppTickCount - 1;
    
    //
    // Initialize the neighbor's network layer address.
    //
    Neighbor->AddressType = AddressType;
    RtlCopyMemory(IP_NEIGHBOR_NL_ADDRESS(Neighbor), Address, AddressLength);
    
    //
    // Initialize the datalink layer mapping.
    //
    SuggestedSubInterface = IppMapNeighbor(Neighbor);

    if (SubInterface == NULL) {
        //
        // The caller did not care for any particular subinterface.
        //
        SubInterface = SuggestedSubInterface;
    }

    if ((SubInterface == NULL) || IppIsSubInterfaceDisabled(SubInterface)) {
        //
        // Do not create neighbors on disabled sub-interfaces.
        //
        IppDeleteNeighbor(Neighbor);
        return NULL;
    }
    
    if (Neighbor->SubInterface != SubInterface) {
        if (Neighbor->SubInterface != NULL) {
            //
            // Release the neighbor's reference on its old subinterface.
            // This might cause the subinterface to be destroyed.
            //
            IppDereferenceSubInterface(Neighbor->SubInterface);
        }
        
        //
        // Obtain a reference on its new subinterface.
        //
        Neighbor->SubInterface = SubInterface;
        IppReferenceSubInterface(SubInterface);
    }

    //
    // Clear the link-layer source-route.
    //
    RtlCopyMemory(
        &Neighbor->DlSourceRoute,
        &sourceroute_unspecified,
        sourceroute_unspecified.Length);

    //
    // Add another reference for the pointer returned to the caller.
    // While this need not be interlocked (we are guaranteed exclusive access),
    // IppReferenceNeighbor ensures it is logged in the the reference-history.
    //
#if NEIGHBOR_REFHIST
    IppReferenceNeighbor(Neighbor);
#else
    Neighbor->ReferenceCount++;
#endif
    
    return Neighbor;
}


VOID
IppUninitializeNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Uninitialize a neighbor.

    Caller is required to invalidate the destination cache.
    
Arguments:

    Interface - Returns an uninitialized neighbor.

Return Value:

    None.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_REQUEST_CONTROL_DATA Control;
    PIP_INTERFACE Interface = Neighbor->Interface;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);
    
    //
    // Stop any pending timers.
    //
    if (TtIsTimerActive(&Neighbor->EventTimer)) {
        TtStopTimer(Interface->NeighborSet.EventTable, &Neighbor->EventTimer);
        Neighbor->EventCount = 0;
    }

    //
    // Empty the WaitQueue.
    // (Only relevant if we were in the INCOMPLETE state.)
    //
    if (Neighbor->WaitQueue != NULL) {
        ASSERT(Neighbor->State == NlnsIncomplete);
        
        Control = Neighbor->WaitQueue;
        Neighbor->WaitQueue = NULL;

        IppDropWaitQueue(Interface, Control);
    }
}

PIP_NEIGHBOR
IppCreateAndInitializeNeighbor(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    Create a neighbor entry and (re)initialize its state. 

    NOTE: We may flush the neighbor cache here if too many neighbors are 
    cached. But for now, choose not to.
    
    Returns a reference on the neighbor to the caller.
    
Arguments:

    Interface - Supplies the interface on which the neighbor exists.

    SubInterface - Optionally supplies a subinterface for the neighbor.
        
    Address - Supplies the neighbor's network layer address.

    AddressType - Supplies the address type.
    
Return Value:

    Neighbor entry to use or NULL.

Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_NEIGHBOR Neighbor;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

       
    Neighbor = IppCreateNeighbor(Interface);
    if (Neighbor != NULL) {
        IppInsertNeighbor(Neighbor, Address);

        Neighbor =
            IppInitializeNeighbor(
                Neighbor, SubInterface, Address, AddressType);
    }

    return Neighbor;    
}


PIP_NEIGHBOR
IppFindNeighborUnderLock(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    Find a neighbor entry on the specified subinterface with the given address.
    
    Returns a reference on the neighbor to the caller.
    
Arguments:

    Interface - Supplies the interface on which the neighbor exists.

    SubInterface - Optionally supplies the subinterface on which the
        neighbor exists.  If this is NULL, the "best" neighbor is found.

    Address - Supplies the neighbor's network layer address.
    
Return Value:

    Neighbor entry or NULL.

Caller LOCK: Interface neighbor set (Shared).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{   
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_CONTEXT LookupContext;
    PIP_NEIGHBOR_SET NeighborSet = &Interface->NeighborSet;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;
    PIP_NEIGHBOR Neighbor, BestNeighbor = NULL;
    ULONG Key;
    
    ASSERT_ANY_LOCK_HELD(&Interface->NeighborSetLock);

    Key = IppComputeNeighborSetKey(Interface, Address);
    RtlInitHashTableContext(&LookupContext);
 
    for (Curr = 
            RtlLookupEntryHashTable(&NeighborSet->Table, Key, &LookupContext);
         Curr != NULL;
         Curr = 
            RtlGetNextEntryHashTable(&NeighborSet->Table, &LookupContext)) { 
            
        Neighbor = (PIP_NEIGHBOR) CONTAINING_RECORD(Curr, IP_NEIGHBOR, Link);

        if ((SubInterface != NULL) &&
            (Neighbor->SubInterface != SubInterface)) {
            continue;
        }

        if (!RtlEqualMemory(
                IP_NEIGHBOR_NL_ADDRESS(Neighbor), Address, AddressLength)) {
            continue;
        }

        if ((BestNeighbor == NULL) ||
            (Neighbor->State > BestNeighbor->State)) {
            //
            // REVIEW: Cache the Override flag and take that into account too?
            //
            BestNeighbor = Neighbor;
        }
    }
    RtlReleaseHashTableContext(&LookupContext);
    
    if (BestNeighbor != NULL) {
        //
        // Update the cache size.
        //
        if (IppIsCachedNeighbor(BestNeighbor)) {
            InterlockedDecrement(&NeighborSet->CacheSize);
            if (0 > (LONG)NeighborSet->CacheSize) {
                NeighborSet->CacheSize = 0;
            }
        }
        IppReferenceNeighbor(BestNeighbor);
    }
    return BestNeighbor;
}


__inline
PIP_NEIGHBOR
IppFindNeighbor(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address
    )
{
    KIRQL OldIrql;
    PIP_NEIGHBOR Neighbor;    

    RtlAcquireReadLock(&Interface->NeighborSetLock, &OldIrql);
    Neighbor = IppFindNeighborUnderLock(Interface, SubInterface, Address);
    RtlReleaseReadLock(&Interface->NeighborSetLock, OldIrql);
    return Neighbor;
}


PIP_NEIGHBOR
IppFindOrCreateNeighborUnderLock(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    Find a neighbor entry on the specified interface with the given address.

    Create one if the search is unsuccessful.

    Returns a reference on the found/created neighbor to the caller.

    Compare FindOrCreateNeighbor() in the XP IPv6 stack.
    
Arguments:
    
    Interface - Supplies the interface on which the neighbor exists.

    SubInterface - Optionally supplies the subinterface on which the 
        neighbor exists.

    Address - Supplies the neighbor's network layer address.

    AddressType - Supplies the address type.
    
Return Value:

    Neighbor entry or NULL.

Locks:

    Assumes caller holds a write lock on the interface's neighbor set.

Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_NEIGHBOR Neighbor;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    //
    // Do not distinguish between anycast and unicast neighbors.
    //
    if (AddressType == NlatAnycast) {
        AddressType = NlatUnicast;
    }
    
    Neighbor = IppFindNeighborUnderLock(Interface, SubInterface, Address);
    if (Neighbor == NULL) {
        Neighbor =
            IppCreateAndInitializeNeighbor(
                Interface, SubInterface, Address, AddressType);
    }
    return Neighbor;
}


PIP_NEIGHBOR
IppFindOrCreateNeighborAtDpc(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
{
    PIP_NEIGHBOR Neighbor;    
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    Neighbor =
        IppFindOrCreateNeighborUnderLock(
            Interface, 
            SubInterface, 
            Address, 
            AddressType);

    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);
    return Neighbor;
}


PIP_NEIGHBOR
IppFindOrCreateNeighbor(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
{
    PIP_NEIGHBOR Neighbor;    
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

    Neighbor =
        IppFindOrCreateNeighborUnderLock(
            Interface,
            SubInterface, 
            Address, 
            AddressType);

    RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);
    return Neighbor;
}


PIP_NEIGHBOR
IppFindOrCreateNeighborWithoutTypeAtDpc(
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address
    )
{
    DISPATCH_CODE();

    return
        IppFindOrCreateNeighborAtDpc(
            Interface, 
            SubInterface, 
            Address,
            IppUpdateAddressTypeAtDpc(
                Interface,
                Address,
                Interface->Compartment->Protocol->AddressType(Address)));
}


PIP_NEIGHBOR
IppFindOrCreateNeighborWithoutType(
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN CONST UCHAR *Address
    )
{
    KIRQL OldIrql;
    PIP_NEIGHBOR Neighbor;
    
    OldIrql = KeRaiseIrqlToDpcLevel();
    
    Neighbor =
        IppFindOrCreateNeighborWithoutTypeAtDpc(
            Interface,
            SubInterface,
            Address);

    KeLowerIrql(OldIrql);

    return Neighbor;
}


VOID
IppResetNeighborUnderLock(
    IN PIP_NEIGHBOR Neighbor,
    IN BOOLEAN ResetConfigured
    )
/*++

Routine Description:

    Reset a neighbor.

    Caller is required to invalidate the destination cache.
    
Arguments:

    Neighbor - Supplies the neighbor to uninitialize.

    ResetConfigured - Supplies TRUE to reset user-configured state.
    
Return Value:

    None.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    //
    // Deactivate the neighbor.
    //
    IppUninitializeNeighbor(Neighbor);

    if (ResetConfigured) {
        //
        // The user no longer wishes to have this neighbor configured.
        //
        Neighbor->IsConfigured = FALSE;
    }
    
    //
    // If the neighbor is cached, we simply delete it.  Else we remap it.
    //
    if (IppIsCachedNeighbor(Neighbor)) {
        IppDeleteNeighbor(Neighbor);
    } else {
        (VOID) IppMapNeighbor(Neighbor);
    }
}


VOID
IppResetNeighbor(
    IN PIP_INTERFACE Interface,
    IN PIP_NEIGHBOR Neighbor,
    IN BOOLEAN ResetConfigured
    )
{
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

    IppResetNeighborUnderLock(Neighbor, ResetConfigured);

    RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);
}


VOID
IppResetNeighborsUnderLock(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN BOOLEAN ResetConfigured    
    )
/*++

Routine Description:

    Reset all neighbors on the specified (sub)interface.

Arguments:

    Interface - Supplies the interface whose neighbors to delete.

    SubInterface - Supplies the subinterface to constrain the reset on.
        NULL initiates reset of all neighbors on all its subinterfaces.

    ResetConfigured - Supplies TRUE to reset user-configured state.
        
Return Value:

    None.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIP_NEIGHBOR_SET NeighborSet = &Interface->NeighborSet;
    PIP_NEIGHBOR Neighbor;
    BOOLEAN Reset = FALSE;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);
       
    RtlInitEnumerationHashTable(&NeighborSet->Table, &Enumerator);

    for (Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator)) {

        Neighbor = (PIP_NEIGHBOR) CONTAINING_RECORD(Curr, IP_NEIGHBOR, Link);
        if ((SubInterface == NULL) ||
            (SubInterface == Neighbor->SubInterface)) {
            Reset = TRUE;
            IppResetNeighborUnderLock(Neighbor, ResetConfigured);
        }
    }
    RtlEndEnumerationHashTable(&NeighborSet->Table, &Enumerator);
    
    if (Reset) {
        //
        // To ensure we don't continue to use these neighbors,
        // we invalidate the destination cache.
        //
        IppInvalidateDestinationCache(Interface->Compartment);
    }
}


VOID
IppResetNeighborsAtDpc(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN BOOLEAN ResetConfigured    
    )
{
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    IppResetNeighborsUnderLock(Interface, SubInterface, ResetConfigured);

    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);
}


__inline
VOID
IppResetNeighbors(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL,
    IN BOOLEAN ResetConfigured    
    )
{
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

    IppResetNeighborsUnderLock(Interface, SubInterface, ResetConfigured);

    RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);
}


VOID
IppMorphNeighborAtDpc(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    Morph the specified neighbor.

Arguments:

    Interface - Supplies the interface over which the neighbor may exist.

    Address - Supplies the neighbor's network layer address.

    AddressType - Supplies the neighbor's network layer address type.
        This might be different from the neighbor's current address type.
    
Return Value:

    None.
    
Caller LOCK: None.
Caller IRQL: DISPATCH_LEVEL.

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_NEIGHBOR Neighbor;

    DISPATCH_CODE();

    //
    // Do not distinguish between anycast and unicast neighbors.
    //
    if (AddressType == NlatAnycast) {
        AddressType = NlatUnicast;
    }
    
    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    Neighbor = IppFindNeighborUnderLock(Interface, NULL, Address);
    if ((Neighbor != NULL) && (Neighbor->AddressType != AddressType)) {        
        //
        // The neighbor has morphed to a new type.
        //
        Neighbor->AddressType = AddressType;
        
        //
        // The neighbor set lock guarantees the neighbor's existence,
        // hence release the reference returned by IppFindNeighborUnderLock
        // allowing IppResetNeighbor to delete the neighbor, if possible.
        //
        IppDereferenceNeighbor(Neighbor);
        
        //
        // Reset the neighbor.
        //
        IppResetNeighborUnderLock(Neighbor, FALSE);

        //
        // To ensure we don't continue to use this neighbor,
        // we invalidate the destination cache.
        //
        IppInvalidateDestinationCache(Interface->Compartment);
    }

    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);
}
    

VOID
IppDeleteNeighborsUnderLock(
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface OPTIONAL
    )
/*++

Routine Description:

    Delete all neighbors on the specified (sub)interface.

Arguments:

    Interface - Supplies the interface whose neighbors to delete.

    SubInterface - Supplies the subinterface to constrain the deletion on.
        NULL initiates deletion of all neighbors on all its subinterfaces.

Return Value:

    None.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIP_NEIGHBOR_SET NeighborSet = &Interface->NeighborSet;
    PIP_NEIGHBOR Neighbor;
    BOOLEAN Deleted = FALSE;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);
       
    RtlInitEnumerationHashTable(&NeighborSet->Table, &Enumerator);

    for (Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator)) {
        Neighbor = (PIP_NEIGHBOR) CONTAINING_RECORD(Curr, IP_NEIGHBOR, Link);
        if ((SubInterface == NULL) ||
            (SubInterface == Neighbor->SubInterface)) {
        
            Deleted = TRUE;
            
            IppUninitializeNeighbor(Neighbor);

            IppDeleteNeighbor(Neighbor);
        }
    }
    RtlEndEnumerationHashTable(&NeighborSet->Table, &Enumerator);
    
    if (Deleted) {
        //
        // To ensure we don't continue to use these neighbors,
        // we invalidate the destination cache.
        //
        IppInvalidateDestinationCache(Interface->Compartment);
    }
}


PIP_NEIGHBOR
IppGetNextNeighborOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST IF_LUID *SubInterfaceLuid OPTIONAL,
    IN CONST UCHAR *Address OPTIONAL
    )
/*++

Routine Description:

    Find the next neighbor entry on the specified interface.
    
    Returns a reference on the neighbor to the caller.
    
Arguments:

    Interface - Supplies the interface on which the neighbor exists.

    SubInterfaceLuid - Supplies the previous neighbor's subinterface LUID,
        or NULL for the first subinterface.

    Address - Supplies the previous neighbor's network layer address.
        A NULL argument would return the first neighbor entry.
    
Return Value:

    Neighbor entry or NULL.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIP_NEIGHBOR_SET NeighborSet = &Interface->NeighborSet;
    KLOCK_QUEUE_HANDLE Lock;
    USHORT AddressLength =
        Interface->Compartment->Protocol->Characteristics->AddressBytes;
    PIP_NEIGHBOR Neighbor, Found = NULL;
    PIP_SUBINTERFACE SubInterface;
    UCHAR *NeighborAddress;
    CONST IF_LUID *NeighborSubInterfaceLuid, *FoundSubInterfaceLuid = NULL;
    LONG Comparison;

    //
    // Either SubInterfaceLuid and Address should both be specified or
    // both left unspecified.
    //
    ASSERT((SubInterfaceLuid == NULL) == (Address == NULL));
    
    RtlAcquireWriteLock(&Interface->NeighborSetLock, &Lock);
       
    RtlInitEnumerationHashTable(&NeighborSet->Table, &Enumerator);
    for (Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator)) {    
        Neighbor = (PIP_NEIGHBOR) CONTAINING_RECORD(Curr, IP_NEIGHBOR, Link);
        SubInterface = Neighbor->SubInterface;
        NeighborSubInterfaceLuid = &SubInterface->Luid;
        NeighborAddress = IP_NEIGHBOR_NL_ADDRESS(Neighbor);

        if (Address != NULL) {
            Comparison = memcmp(NeighborSubInterfaceLuid, 
                                SubInterfaceLuid, 
                                sizeof(*SubInterfaceLuid));
            
            if ((Comparison < 0) ||
                ((Comparison == 0) &&
                 (memcmp(NeighborAddress, Address, AddressLength) <= 0))) {
                continue;
            }
        }

        if (Found != NULL) {
            Comparison = memcmp(NeighborSubInterfaceLuid, 
                                FoundSubInterfaceLuid, 
                                sizeof(*FoundSubInterfaceLuid));
            if ((Comparison > 0) ||
                ((Comparison == 0) &&
                 (memcmp(NeighborAddress,
                         IP_NEIGHBOR_NL_ADDRESS(Found),
                         AddressLength)
                  >= 0))) {
                continue;
            }
        }

        //
        // We have a (more) appropriate match.
        //
        Found = Neighbor;
        FoundSubInterfaceLuid = NeighborSubInterfaceLuid;
    }
    RtlEndEnumerationHashTable(&NeighborSet->Table, &Enumerator);


    if (Found != NULL) {
        IppReferenceNeighbor(Found);
    }
    
    RtlReleaseWriteLock(&Interface->NeighborSetLock, &Lock);
    
    return Found;
}


PIP_NEIGHBOR
IppGetFirstNeighbor(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Find the first neighbor entry for the specified protocol.
    
    Returns a reference on the neighbor to the caller.
    
Arguments:

    Protocol - Supplies the protocol to consider.
    
Return Value:

    Neighbor entry or NULL.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface;
    PIP_NEIGHBOR Neighbor = NULL;
    IF_LUID Luid;
    
    Interface = IppGetFirstInterface(Protocol);
    while (Interface != NULL) {
        Luid = Interface->Luid;
        Neighbor = IppGetNextNeighborOnInterface(Interface, 0, NULL);
        IppDereferenceInterface(Interface);
        if (Neighbor != NULL) {
            break;
        }
        Interface = IppGetNextInterface(Protocol, &Luid);
    }
    
    return Neighbor;
}


PIP_NEIGHBOR
IppGetNextNeighbor(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *InterfaceLuid,
    IN CONST IF_LUID *SubInterfaceLuid,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    Find the next neighbor entry for the specified protocol.
    
    Returns a reference on the neighbor to the caller.
    
Arguments:

    Protocol - Supplies the protocol to consider.
    
    InterfaceLuid - Supplies the previous neighbor's interface LUID.

    SubInterfaceLuid - Supplies the previous neighbor's subinterface LUID.

    Address - Supplies the previous neighbor's network layer address.
        
Return Value:

    Neighbor entry or NULL.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = NULL;
    PIP_NEIGHBOR Neighbor = NULL;
    IF_LUID Luid = *InterfaceLuid;

    //
    // Find the next neighbor on the specified interface...
    //
    Interface = IppFindInterfaceByLuid(Protocol, &Luid);
    if (Interface != NULL) {
        Neighbor =
            IppGetNextNeighborOnInterface(
                Interface,
                SubInterfaceLuid,
                Address);
        IppDereferenceInterface(Interface);
        if (Neighbor != NULL) {
            return Neighbor;
        }
    }

    //
    // Failing which, find the first neighbor on the next interface.
    //
    Interface = IppGetNextInterface(Protocol, &Luid);
    while (Interface != NULL) {
        Luid = Interface->Luid;
        Neighbor = IppGetNextNeighborOnInterface(Interface, NULL, NULL);
        IppDereferenceInterface(Interface);
        if (Neighbor != NULL) {
            break;
        }
        Interface = IppGetNextInterface(Protocol, &Luid);
    }
    
    return Neighbor;
}


VOID
IppFillNeighborParameters(
    IN PIP_NEIGHBOR Neighbor,
    OUT NL_NEIGHBOR_RW UNALIGNED *Rw,
    OUT NL_NEIGHBOR_ROD UNALIGNED *Rod,
    OUT NL_NEIGHBOR_ROS UNALIGNED *Ros
    )
{
    KIRQL OldIrql;
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;
    
    RtlAcquireReadLock(&Interface->NeighborSetLock, &OldIrql);
    
    if (Rod != NULL) {
        Rod->State = Neighbor->State;

        Rod->LastReachable = IppTickCount - Neighbor->LastReachable;

        //
        // Update state based on when the neighbor was last reachable.
        //
        if ((Rod->State == NlnsReachable) &&
            (Rod->LastReachable > Interface->ReachableTicks)) {
            Rod->State = NlnsStale;
        }

        //
        // Report the LastReachable value in milliseconds.
        //
        Rod->LastReachable = IppTicksToMilliseconds(Rod->LastReachable);
        
        Rod->IsRouter = Neighbor->IsRouter;
        Rod->IsUnreachable = Neighbor->IsUnreachable;

        Rod->DlAddressLength = Interface->FlCharacteristics->DlAddressLength;

        Rod->CompartmentId = Interface->Compartment->CompartmentId;
    }

    if (Rw != NULL) {
        RtlCopyMemory(Rw->DlAddress,
                      IP_NEIGHBOR_DL_ADDRESS(Neighbor, AddressLength),
                      Interface->FlCharacteristics->DlAddressLength);
    }

    if (Ros != NULL) {
        Ros->InterfaceIndex = Interface->Index;
    }

    RtlReleaseReadLock(&Interface->NeighborSetLock, OldIrql);
}


NTSTATUS
NTAPI
IpGetAllNeighborParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:
    
    Retreive all public parameters of a neighbor entry.
    
Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PNL_NEIGHBOR_KEY Key = (PNL_NEIGHBOR_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;
    PIP_NEIGHBOR Neighbor = NULL;
    PIP_SUBINTERFACE SubInterface = NULL;
    PIP_INTERFACE Interface;

    IppCast(Client, NMP_CLIENT_CONTEXT);

    switch (Args->Action) {
    case NsiGetExact:
        SubInterface =
            IppFindSubInterfaceByLuid(
                Protocol, 
                &Key->InterfaceLuid,
                &Key->SubInterfaceLuid);
        if (SubInterface != NULL) {
            Neighbor =
                IppFindNeighbor(
                    SubInterface->Interface,
                    SubInterface,
                    Key->Address);
            IppDereferenceSubInterface(SubInterface);
        }
        break;

    case NsiGetFirst:
        Neighbor = IppGetFirstNeighbor(Protocol);
        break;

    case NsiGetNext:
        Neighbor =
            IppGetNextNeighbor(
                Protocol,
                &Key->InterfaceLuid,
                &Key->SubInterfaceLuid,
                Key->Address);
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    if (Neighbor == NULL) {
        return (Args->Action == NsiGetExact)
            ? STATUS_NOT_FOUND
            : STATUS_NO_MORE_ENTRIES;
    }

    SubInterface = Neighbor->SubInterface;
    Interface = SubInterface->Interface;
    
    if (Args->Action != NsiGetExact) {
        Key->InterfaceLuid = Interface->Luid;
        Key->SubInterfaceLuid = SubInterface->Luid;
        RtlCopyMemory(Key->Address,
                      IP_NEIGHBOR_NL_ADDRESS(Neighbor),
                      AddressLength);
    }

    IppFillNeighborParameters(
        Neighbor,
        (PNL_NEIGHBOR_RW) Args->StructDesc.RwParameterStruct,
        (PNL_NEIGHBOR_ROD) Args->StructDesc.RoDynamicParameterStruct,
        (PNL_NEIGHBOR_ROS) Args->StructDesc.RoStaticParameterStruct);

    IppDereferenceNeighbor(Neighbor);

    return STATUS_SUCCESS;
}


NTSTATUS
IppSetAllNeighborParametersHelper(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *Address,
    IN PNL_NEIGHBOR_RW Data,
    IN NSI_SET_ACTION Action
    )
/*++

Routine Description:
    
    Add, delete, or update a neighbor entry.
    
Arguments:

    SubInterface - Supplies the subinterface to which the neighbor belongs.

    Address - Supplies the neighbor's network layer address.

    Data - Supplies the neighbor's configuration data.

    Action - Supplies the action to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    NL_ADDRESS_TYPE AddressType = Protocol->AddressType(Address);
    KIRQL OldIrql;
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_NEIGHBOR Neighbor = NULL;
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    NTSTATUS Status;

    if ((AddressType != NlatUnicast) &&
        (AddressType != NlatAnycast) &&
        (AddressType != NlatMulticast) &&
        (AddressType != NlatBroadcast)) {   
        return STATUS_INVALID_PARAMETER;
    }

    if (INET_IS_ADDR_LOOPBACK(Protocol->Family, Address)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlAcquireReadLock(&Interface->Lock, &OldIrql);
    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    switch (Action) {
    case NsiSetCreateOnly:
        //
        // Ensure that the neighbor isn't already configured.
        //
        Neighbor = IppFindNeighborUnderLock(Interface, SubInterface, Address);
        if (Neighbor != NULL) {
            if (Neighbor->IsConfigured) {
                Status = STATUS_DUPLICATE_OBJECTID;
                break;
            }
            goto Update;
        }

        //
        // Fall through.
        //
        
    case NsiSetCreateOrSet:
        AddressType =
            IppUpdateAddressTypeUnderLock(Interface, Address, AddressType);

        //
        // For unicast addresses and interfaces with multiple
        // subinterfaces we should have only one entry per
        // interface for the given NL address.
        //
        if (AddressType == NlatUnicast) {
            Neighbor = 
                IppFindNeighborUnderLock(
                    Interface, 
                    NULL, 
                    Address);
        }

        if (Neighbor != NULL) {
            if (Neighbor->SubInterface != SubInterface) {
                IppDereferenceSubInterface(Neighbor->SubInterface);
                Neighbor->SubInterface = SubInterface;
                IppReferenceSubInterface(SubInterface);
            }
        } else {
            Neighbor =
                IppFindOrCreateNeighborUnderLock(
                    Interface, 
                    SubInterface, 
                    Address,
                    AddressType);
            if (Neighbor == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
        }        
        goto Update;

    case NsiSetDefault:
        Neighbor = IppFindNeighborUnderLock(Interface, SubInterface, Address);
        if ((Neighbor == NULL) || !Neighbor->IsConfigured) {
            Status = STATUS_NOT_FOUND;
            break;
        }

Update:        
        if (Neighbor->IsConfigured) {
            ASSERT(Neighbor->State == NlnsPermanent);

            //
            // Update the neighbor's datalink layer address.
            //
            IppUpdateNeighborAddress(
                Neighbor,
                Data->DlAddress,
                &sourceroute_unspecified,
                Protocol->Characteristics->AddressBytes,
                Interface->FlCharacteristics->DlAddressLength);
        } else {
            //
            // Update the neighbor's state and datalink layer address.
            // Change its state to PERMANENT.
            //
            Control =
                IppUpdateNeighbor(
                    Neighbor,
                    Data->DlAddress,
                    &sourceroute_unspecified,
                    TRUE,
                    TRUE,
                    FALSE);
            ASSERT((Neighbor->State == NlnsReachable) ||
                   (Neighbor->State == NlnsPermanent));
            Neighbor->State = NlnsPermanent;
            Neighbor->IsConfigured = TRUE;
        }
        Status = STATUS_SUCCESS;
        break;

    case NsiSetDelete:
        Neighbor = IppFindNeighborUnderLock(Interface, SubInterface, Address);
        if (Neighbor == NULL) {
            Status = STATUS_NOT_FOUND;
            break;
        }

        //
        // The neighbor set lock guarantees the neighbor's existence,
        // hence release the reference returned by IppFindNeighborUnderLock
        // allowing IppResetNeighbor to delete the neighbor, if possible.
        //
        IppDereferenceNeighbor(Neighbor);
        
        IppResetNeighborUnderLock(Neighbor, TRUE);
        
        //
        // To ensure we don't continue to use this neighbor,
        // we invalidate the destination cache.
        //
        IppInvalidateDestinationCache(Interface->Compartment);
        
        Neighbor = NULL;
        
        Status = STATUS_SUCCESS;
        break;

    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);
    RtlReleaseReadLock(&Interface->Lock, OldIrql);
    
    if (Neighbor != NULL) {        
        IppDereferenceNeighbor(Neighbor);
        if (Control != NULL) {
            IppFragmentPackets(Interface->Compartment->Protocol, Control);
        }
    }

    return Status;
}


NTSTATUS
NTAPI
IpSetAllNeighborParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:
    
    Updates public parameters of a neighbor entry.
    
Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or a failure code.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_SUBINTERFACE SubInterface;
    NTSTATUS Status = STATUS_SUCCESS;
    NSI_SET_ACTION Action = Args->Action;
    PIP_PROTOCOL Protocol;
    
    PNL_NEIGHBOR_KEY Key =
        (PNL_NEIGHBOR_KEY) Args->KeyStructDesc.KeyStruct;
    PNL_NEIGHBOR_RW Data =
        (PNL_NEIGHBOR_RW) Args->RwStructDesc.RwParameterStruct;

    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;

    if (Args->Transaction != NsiTransactionNone) {
        return STATUS_NOT_IMPLEMENTED;
    }

    if (Action == NsiSetReset) {
        ULONG Length = Args->KeyStructDesc.KeyStructLength;
        PIP_INTERFACE Interface;

        if (Length ==
            (sizeof(NL_NEIGHBOR_KEY) +
             Protocol->Characteristics->AddressBytes)) {
            //
            // Delete single neighbor.
            //
            Action = NsiSetDelete;

        } else if (Length == FIELD_OFFSET(NL_NEIGHBOR_KEY, Address)) {
            //
            // Delete all neighbors on a given subinterface.
            //
            SubInterface =
                IppFindSubInterfaceByLuid(
                    Protocol,
                    &Key->InterfaceLuid,
                    &Key->SubInterfaceLuid);
            if (SubInterface == NULL) {
                return STATUS_NOT_FOUND;
            }
        
            Interface = SubInterface->Interface;

            IppResetNeighbors(Interface, SubInterface, TRUE);

            IppDereferenceSubInterface(SubInterface);

            return STATUS_SUCCESS;
        } else if (Length == FIELD_OFFSET(NL_NEIGHBOR_KEY, SubInterfaceLuid)) {
            //
            // Delete all neighbors on a given interface.
            //
            Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
            if (Interface == NULL) {
                return STATUS_NOT_FOUND;
            }

            IppResetNeighbors(Interface, NULL, TRUE);

            IppDereferenceInterface(Interface);

            return STATUS_SUCCESS;
        } else if (Length == 0) {
            IF_LUID Luid;

            //
            // Delete all neighbors.
            //
            Interface = IppGetFirstInterface(Protocol);
            while (Interface != NULL) {
                Luid = Interface->Luid;

                IppResetNeighbors(Interface, NULL, TRUE);

                IppDereferenceInterface(Interface);

                Interface = IppGetNextInterface(Protocol, &Luid);
            }

            return STATUS_SUCCESS;
        } else {
            //
            // Invalid length specified.
            //
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (Args->RwStructDesc.RwParameterStructLength == 0) {
        //
        // Use default parameters.
        //
        Data = &IppNeighborDefaultRwData;
    }

    //
    // All operations require a valid subinterface.
    //
    SubInterface =
        IppFindSubInterfaceByLuid(
            Protocol,
            &Key->InterfaceLuid,
            &Key->SubInterfaceLuid);
    if (SubInterface == NULL) {
        return STATUS_NOT_FOUND;
    }

    Status =
        IppSetAllNeighborParametersHelper(
            SubInterface,
            Key->Address,
            Data,
            Action);

    IppDereferenceSubInterface(SubInterface);

    return Status;
}


#define MAX_RESOLVE_NEIGHBOR_COUNT 6

NTSTATUS
NTAPI
IpGetAllResolveNeighborParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:
    
    Retreive all public parameters of a neighbor entry.

    TODO: Resolve the neighbor once NSI supports asynchronous Gets/Sets.
    
Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= PASSIVE LEVEL.

--*/ 
{
    NTSTATUS Status;
    PNL_NEIGHBOR_KEY Key = (PNL_NEIGHBOR_KEY) Args->KeyStructDesc.KeyStruct;
    PNL_NEIGHBOR_RW UNALIGNED Rw = (PNL_NEIGHBOR_RW) 
        Args->StructDesc.RwParameterStruct;
    PNL_NEIGHBOR_ROD UNALIGNED Rod = (PNL_NEIGHBOR_ROD) 
        Args->StructDesc.RoDynamicParameterStruct;
    PNL_NEIGHBOR_ROS UNALIGNED Ros = (PNL_NEIGHBOR_ROS) 
        Args->StructDesc.RoStaticParameterStruct;
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    NL_ADDRESS_TYPE AddressType = Protocol->AddressType(Key->Address);
    PIP_INTERFACE Interface;
    PIP_NEIGHBOR Neighbor;
    PIP_LOCAL_ADDRESS LocalAddress;
    KIRQL OldIrql;
    CONST LONG WaitTime[MAX_RESOLVE_NEIGHBOR_COUNT] =
        {1, 10, 100, 1000, 1000, 1000}; 

    IppCast(Client, NMP_CLIENT_CONTEXT);

    if (Args->Action != NsiGetExact) {
        return STATUS_NOT_SUPPORTED;
    }

    if ((AddressType != NlatUnicast) &&
        (AddressType != NlatAnycast) &&
        (AddressType != NlatMulticast) &&
        (AddressType != NlatBroadcast)) {   
        return STATUS_INVALID_PARAMETER;
    }
    
    Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    Status = STATUS_NOT_FOUND;
    
    RtlAcquireReadLock(&Interface->Lock, &OldIrql);

    LocalAddress = IppFindAddressOnInterfaceUnderLock(Interface, Key->Address);
    if (LocalAddress != NULL) {
        if (Rod != NULL) {
            Rod->State = NlnsPermanent;
            Rod->LastReachable = 0;
            Rod->IsRouter = (BOOLEAN) Interface->Advertise;
            Rod->IsUnreachable = FALSE;
            Rod->DlAddressLength =
                Interface->FlCharacteristics->DlAddressLength;
        }
    
        if (Rw != NULL) {
            RtlCopyMemory(
                Rw->DlAddress,
                Interface->FlCharacteristics->DlAddress,
                Interface->FlCharacteristics->DlAddressLength);
        }

        if (Ros != NULL) {
            Ros->InterfaceIndex = Interface->Index;
        }

        RtlReleaseReadLock(&Interface->Lock, OldIrql);
        IppDereferenceLocalAddress(LocalAddress);
        Status = STATUS_SUCCESS;
        goto Done;
    } 

    //
    // The interface lock protects the address sets and hence
    // a subnet broadcast address could not have been created.
    // We can safely use AddressType below.
    //
    Neighbor =
        IppFindOrCreateNeighborAtDpc(
            Interface, NULL, Key->Address, AddressType);

    RtlReleaseReadLock(&Interface->Lock, OldIrql);
    
    if (Neighbor != NULL) {
        LARGE_INTEGER Time;
        ULONG i;

        //
        // Clear any existing mappings so the neighbor will be probed.
        //
        IppResetNeighbor(Interface, Neighbor, FALSE);       
        
        for (i = 0; ; i++) { 
            if (i >= MAX_RESOLVE_NEIGHBOR_COUNT) {
                //
                // Give up after six tries (~ 3 seconds).
                //
                break;
            }
            
            IppResolveNeighbor(Neighbor, NULL);
        
            //
            // If the mapping has been updated, or if it was unsuccessful,
            // we are done.
            //
            if ((Neighbor->State >= NlnsReachable) ||
                (Neighbor->State == NlnsUnreachable)) {
                break;
            }

            //
            // ASSERT so we catch callers attempting this at elevated IRQLs.
            //
            PASSIVE_CODE();
            if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
                IppDereferenceNeighbor(Neighbor);
                Status = STATUS_INVALID_LEVEL;
                goto Done;                
            }
            
            //
            // Wait for the solicitation to be processed.
            //
            Time.QuadPart = -(WaitTime[i] * 10000);
            KeDelayExecutionThread(KernelMode, FALSE, &Time);        
        }

        IppFillNeighborParameters(Neighbor, Rw, Rod, Ros);
        IppDereferenceNeighbor(Neighbor);
        Status = STATUS_SUCCESS;
    } else {       
        Status = STATUS_UNSUCCESSFUL;
    }
    
Done:
    IppDereferenceInterface(Interface);
    return Status;
}


VOID
IppSuspectNeighborReachability(
    IN PIP_NEIGHBOR Neighbor
    ) 
/*++

Routine Description:

    Updates the neighbor entry in response to an indication from an
    upper-layer protocol that the neighbor may not be reachable.    
    (For example, a reply to a request was not received.)

Argument:

    Neighbor - Supplies the neighbor to consider.

Return Value:

    None.
  
Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_INTERFACE Interface = Neighbor->Interface;

    RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

    //
    // By setting LastConfirmation to something earlier than the
    // current tick, potential callers of IpNlpConfirmForwardReachability
    // will notice that the state is stale, and this will force a 
    // call into this function.
    //

    Neighbor->LastConfirmation = IppTickCount - 1;

    if (Neighbor->State == NlnsReachable) {
        Neighbor->State = NlnsStale;
    }

    RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);
}


ULONG
IppConfirmNeighborReachability(
    IN PIP_NEIGHBOR Neighbor,
    IN ULONG ElapsedTicks
    ) 
/*++

Routine Description:

    Updates the neighbor entry in response to an indication of forward
    reachability from an upper-layer protocol.
    (For example, receipt of a reply to a request).

Argument:

    Neighbor - Supplies the neighbor to consider.

    ElapsedTicks - Supplies the ticks since reachability was confirmed.
    
Return Value:

    Returns the ticks since the neighbor was last known to be reachable.
    
Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    ULONG CurrentTickCount, TicksSinceReachable;

    RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

    CurrentTickCount = IppTickCount;
    
    if ((ElapsedTicks > Interface->ReachableTicks) ||
        (ElapsedTicks > (CurrentTickCount - Neighbor->LastReachability))) {
        //
        // This confirmation is too late to be useful.
        //
        goto Bail;
    }
    
    switch (Neighbor->State) {
    case NlnsUnreachable:
    case NlnsIncomplete:
        //
        // This is strange.  Perhaps the reachability confirmation is
        // arriving very late and ND has already decided the neighbor
        // is unreachable?  Or perhaps the upper-layer protocol is just
        // mistaken?  In any case ignore the confirmation.
        //
        break;
        
    case NlnsProbe:
        //
        // Stop sending solicitations.
        //
        ASSERT(TtIsTimerActive(&Neighbor->EventTimer));        
        TtStopTimer(Interface->NeighborSet.EventTable, &Neighbor->EventTimer);
        Neighbor->EventCount = 0;
        //
        // Fall through.
        //
        
    case NlnsStale:
        //
        // We have forward reachability.
        //
        Neighbor->State = NlnsReachable;

        Neighbor->WasReachable = TRUE;

        if (Neighbor->IsUnreachable) {
            //
            // We can get here if a neighbor is reachable but goes INCOMPLETE.
            // Then we later receive passive information and the state
            // changes to STALE.  Then we receive upper-layer confirmation
            // that the neighbor is reachable again.
            //
            // We had previously concluded this neighbor to be unreachable.
            // Now we know otherwise.
            //
            Neighbor->IsUnreachable = FALSE;
            IppInvalidateDestinationCache(Compartment);
        }
        //
        // Fall through.
        //
        
    case NlnsReachable:
        //
        // Timestamp this reachability confirmation.
        //
        Neighbor->LastConfirmation = 
            Neighbor->LastReachable = CurrentTickCount - ElapsedTicks;
        //
        // Fall through.
        //

    case NlnsPermanent:
        //
        // Ignore the confirmation.
        //
        ASSERT(!Neighbor->IsUnreachable);
        break;

    default:
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR, 
                   "IPNG: Bad neighbor state %d\n", Neighbor->State);
        ASSERT(FALSE);
        break;
    }

Bail:
    //
    // Return the ticks since the neighbor was last known to be reachable.
    // If the neighbor is not known to be reachable, return ReachableTicks.
    //
    switch (Neighbor->State) {
    case NlnsPermanent:
        TicksSinceReachable = 0;
        break;
        
    case NlnsReachable:
        TicksSinceReachable = min((CurrentTickCount - Neighbor->LastReachable),
                                  Interface->ReachableTicks);
        break;
        
    default:
        TicksSinceReachable = Interface->ReachableTicks;
        break;
    }
    
    RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);

    return TicksSinceReachable;
}


VOID
IppProbeNeighborReachability(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Initiates an active probe of an unreachable neighbor,
    to determine if the neighbor is still unreachable.

    To prevent ourselves from probing too frequently,
    the first probe is scheduled after waiting at least
    UNREACH_SOLICIT_INTERVAL from when we last determined
    this neighbor to be unreachable. If called again in this
    interval, we do nothing.

Argument:

    Neighbor - Supplies the neighbor to consider.

Return Value:

    None.

Caller IRQL:

    DISPATCH_LEVEL.

--*/
{
    PIP_SUBINTERFACE SubInterface = Neighbor->SubInterface;
    PIP_INTERFACE Interface = SubInterface->Interface;
    PTIMER_TABLE EventTable = Interface->NeighborSet.EventTable;
    ULONG Elapsed;
    USHORT Delay;
    KLOCK_QUEUE_HANDLE LockHandle;

    DISPATCH_CODE();
    
    if (!Interface->FlCharacteristics->DiscoversNeighbors) {
        //
        // We cannot probe on interfaces that do not support ND.
        //
        return;
    }

    if (SubInterface->OperationalStatus != IfOperStatusUp) {
        //
        // We cannot probe on an unoperational interface.
        //
        return;
    }
    
    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    if (!Neighbor->IsUnreachable || IppIsDeletedNeighbor(Neighbor)) {
        goto Done;
    }
    
    //
    // Calculate the appropriate delay until we can probe unreachability.
    // We do not want to determine unreachability more frequently than
    // UNREACH_SOLICIT_INTERVAL.
    //
    Elapsed = IppTickCount - Neighbor->LastUnreachable;
    if (Elapsed < UNREACH_SOLICIT_INTERVAL) {
        Delay = (USHORT) (UNREACH_SOLICIT_INTERVAL - Elapsed);
    } else {
        Delay = 1;
    }

    //
    // Start soliciting the neighbor to check if it's still unreachable.
    // 
    switch (Neighbor->State) {
    case NlnsIncomplete:
    case NlnsProbe:
        //
        // The neighbor is being actively solicited, 
        // Ensure that at least MAX_UNREACH_SOLICIT solicitations are sent.
        //
        ASSERT(TtIsTimerActive(&Neighbor->EventTimer));
        if (Neighbor->EventCount < MAX_UNREACH_SOLICIT) {
            Neighbor->EventCount = MAX_UNREACH_SOLICIT;
        }
        goto Done;
        
    case NlnsStale:
        Neighbor->State = NlnsProbe;
        break;

    case NlnsUnreachable:
        Neighbor->State = NlnsIncomplete;
        break;

    case NlnsReachable:
    case NlnsPermanent:
        //
        // Because the Neighbor IsUnreachable, we can not be in these states.
        //
        ASSERT(FALSE);
        goto Done;        
    }

    ASSERT(!TtIsTimerActive(&Neighbor->EventTimer));
    Neighbor->EventCount = MAX_UNREACH_SOLICIT;
    TtStartTimer(EventTable, &Neighbor->EventTimer, Delay);
    
Done:
    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);
}


IP_NEIGHBOR_REACHABILITY
IppGetNeighborReachability(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Returns reachability information for a neighbor.

    Because FindNextHop uses GetReachability, any state change
    that changes GetReachability's return value
    must invalidate the route cache.

Argument:

    Neighbor - Supplies the neighbor to consider.

Return Value:

    IP_NEIGHBOR_REACHABILITY code.
    
Caller IRQL:

    DISPATCH_LEVEL.

--*/
{
    PIP_SUBINTERFACE SubInterface = Neighbor->SubInterface;
    PIP_INTERFACE Interface = SubInterface->Interface;
    IP_NEIGHBOR_REACHABILITY Reachable;

    DISPATCH_CODE();
    
    RtlAcquireReadLockAtDpcLevel(&Interface->NeighborSetLock);
    if (SubInterface->OperationalStatus != IfOperStatusUp) {
        Reachable = NeighborInterfaceDisconnected;
    } else if (Neighbor->IsUnreachable) {
        Reachable = NeighborUnreachable;
    } else {
        Reachable = NeighborMayBeReachable;
    }
    RtlReleaseReadLockFromDpcLevel(&Interface->NeighborSetLock);

    return Reachable;
}


//
// Generic neighbor discovery functions.
//

VOID
IppUpdateNeighborAddress(
    IN OUT PIP_NEIGHBOR Neighbor,
    IN CONST UCHAR *DlAddress,    
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN USHORT NlAddressLength,
    IN USHORT DlAddressLength
    )
/*++

Routine Description:
    
    Updates a neighbor's datalink layer address.
    
Arguments:

    Neighbor - Supplies the neighbor under consideration.  On return,
        the neighbor is updated with the supplied information.

    DlAddress - Supplies the neighbor's datalink layer address.

    DlSourceRoute - Supplies the neighbor's link-layer source-route.
    
    NlAddressLength - Supplies the network layer address length.
    
    DlAddressLength - Supplies the datalink layer address length.
    
Return Value:

    None.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{       
    ASSERT_WRITE_LOCK_HELD(&Neighbor->Interface->NeighborSetLock);

    if (!RtlEqualMemory(
            IP_NEIGHBOR_DL_ADDRESS(Neighbor, NlAddressLength), 
            DlAddress, 
            DlAddressLength)) {

        RtlCopyMemory(
            IP_NEIGHBOR_DL_ADDRESS(Neighbor, NlAddressLength), 
            DlAddress, 
            DlAddressLength);

        RtlCopyMemory(
            &Neighbor->DlSourceRoute,
            DlSourceRoute,
            DlSourceRoute->Length);
            
        IppDeferUpdateNeighborOffloadState((PIP_NEIGHBOR) Neighbor);
    }
}

PIP_REQUEST_CONTROL_DATA
IppUpdateNeighbor(
    IN OUT PIP_NEIGHBOR Neighbor,
    IN CONST UCHAR *DlAddress OPTIONAL,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute OPTIONAL,
    IN BOOLEAN Solicited,
    IN BOOLEAN Override,
    IN BOOLEAN IsDAD
    )
/*++

Routine Description:

    Updates a neighbor's state and datalink layer address.

    Called when we receive possibly new information about one of our neighbors.
    1. Source of a Neighbor Solicitation.
    2. Target of a Neighbor Advertisement.
    3. Source of a Router Advertisement, or Router Solicitation.
    4. Target of a Redirect.

Arguments:

    Neighbor - Supplies the neighbor under consideration.  On return,
        the neighbor is updated with the supplied information.

    DlAddress - Optionally supplies the neighbor's datalink layer address.

    DlSourceRoute - Optionally supplies the neighbor's link-layer source-route.
    
    Override - Supplies TRUE if DlAddress may override any cached address.

    Router - Supplies TRUE if the neighbor is known to be a router.

    IsDAD - Supplies TRUE if DAD solicitation received for neighbor IP address.
    
Return Value:

    Any packets queued waiting for neighbor discovery to complete.

Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT NlAddressLength = Protocol->Characteristics->AddressBytes;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    if (Neighbor->State == NlnsPermanent) {
        return NULL;
    }

    if (IsDAD) {
        // 
        // This is a DAD solicitation, for reachable entries
        // we should confirm the address later through
        // unicast probing.
        //
        if (Neighbor->State == NlnsReachable) {
            Neighbor->State = NlnsStale;
        }
        return NULL;
    }

    if (!Protocol->EnableNonUnicastDatalinkAddresses &&
        (DlAddress != NULL) &&
        (IppDatalinkAddressType(DlAddress, Interface) != DlUnicast)) {
        //
        // Disallow neighbors from advertising a non-unicast MAC address.
        //
        DlAddress = NULL;
    }    
    
    //
    // Check to see if the datalink layer address has changed.
    //
    if ((DlAddress != NULL) &&
        ((Neighbor->State == NlnsIncomplete) ||
         (Neighbor->State == NlnsUnreachable) ||
         (!RtlEqualMemory(
             IP_NEIGHBOR_DL_ADDRESS(Neighbor, NlAddressLength),
             DlAddress,
             DlAddressLength) &&
          Override))) {

        //
        // Neighbor's datalink layer address changed!  Update neighbor entry
        // with the new one and change state to STALE as we haven't verified
        // forward reachability with the new address yet.
        //

        //
        // Empty the WaitQueue.
        // (Only relevant if we were in the INCOMPLETE state.)
        //
        if (Neighbor->WaitQueue != NULL) {
            ASSERT(Neighbor->State == NlnsIncomplete);

            Control = Neighbor->WaitQueue;
            Neighbor->WaitQueue = NULL;
            
            //
            // Note: The queue is at most one packet deep.
            //        
            ASSERT(Control->Next == NULL);        
        }

        //
        // If the neighbor is being probed, transition to the probe state.
        // This ensures that we continue trying to determine the neighbor's
        // reachability since it might impact our routing decisions.
        //
        if (TtIsTimerActive(&Neighbor->EventTimer)) {
            //
            // Stop the pending timer.
            //
            TtStopTimer(
                Interface->NeighborSet.EventTable,
                &Neighbor->EventTimer);

            //
            // Transition to the PROBE state and start the probe timer.
            //
            Neighbor->State = NlnsProbe;
            ASSERT(!TtIsTimerActive(&Neighbor->EventTimer));
            Neighbor->EventCount = MAX_UNICAST_SOLICIT;
            TtStartTimer(
                Interface->NeighborSet.EventTable,
                &Neighbor->EventTimer,
                DELAY_FIRST_PROBE_TIME);
        } else {
            Neighbor->State = NlnsStale;
            Neighbor->LastReachable = IppTickCount;
        }
        
        if (Neighbor->WasReachable && Neighbor->IsUnreachable) {
            //
            // The neighbor was online in the past, but then went offline.
            // We now have an indication that the neighbor is back online.
            // To ensure that the neighbor is probed on the next packet,
            // we clear the IsUnreachable flag and invalidate the path cache.
            // We also clear the WasReachable flag so the neighbor only makes
            // this transition on the first implicit indication of the
            // neighbor's presence on the link.  Subsequent implicit
            // indications will be ignored unless an explicit indication has
            // made WasReachable TRUE again.  This ensures that we correctly
            // detect when our connectivity to a neighbor transitions from
            // bidirectional to unidirectional.
            //
            Neighbor->WasReachable = Neighbor->IsUnreachable = FALSE;
            IppInvalidateDestinationCache(Interface->Compartment);
        }            

        //
        // Update the neighbor entry with the new datalink layer address.
        //
        IppUpdateNeighborAddress(
            Neighbor,
            DlAddress,
            DlSourceRoute,
            NlAddressLength,
            DlAddressLength);
    }

    if ((Neighbor->State == NlnsIncomplete) ||
        (Neighbor->State == NlnsUnreachable)) {
        ASSERT(Control == NULL);
        return Control;
    }
    
    if ((DlAddress == NULL) ||
        (RtlEqualMemory(
            IP_NEIGHBOR_DL_ADDRESS(Neighbor, NlAddressLength),
            DlAddress,
            DlAddressLength))) {

        //
        // If this is a solicited advertisement for our updated or cached
        // datalink layer address, then we have confirmed reachability.
        //
        if (Solicited) {
            //
            // Stop any pending timers.
            //
            if (TtIsTimerActive(&Neighbor->EventTimer)) {
                TtStopTimer(
                    Interface->NeighborSet.EventTable,
                    &Neighbor->EventTimer);
                Neighbor->EventCount = 0;
            }

            Neighbor->State = NlnsReachable;

            Neighbor->WasReachable = TRUE;
            
            if (Neighbor->IsUnreachable) {
                //
                // We had previously concluded this neighbor to be unreachable.
                // Now we know otherwise.
                //
                Neighbor->IsUnreachable = FALSE;
                IppInvalidateDestinationCache(Interface->Compartment);
            }            

            //
            // Timestamp it!
            //
            Neighbor->LastReachable = IppTickCount;
        } 
    } else {
        //
        // This is not an advertisement for our cached link-layer address.
        // If the advertisement was unsolicited, give NUD a little nudge.
        // If the Solicited flag is set, it could be a second NA for a
        // anycast address, but it is still ok, since we only do
        // unicast probing, and not actually change the MAC address
        // (per RFC 2461, 7.2.5.)
        //
        if (Neighbor->State == NlnsReachable) {
            Neighbor->State = NlnsStale;
            Neighbor->LastReachable = IppTickCount;
        }
    }
    
    return Control;
}


PIP_LOCAL_UNICAST_ADDRESS
IppGetNeighborSolicitationSource(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Determines the source address to use for sending neighbor solicitations.
    
Arguments:

    Neighbor - Supplies the neighbor to be solicited.

Return Value:

    Source address to use.
    
Caller LOCK: 

    Assumes caller holds at least a read lock on the interface.
    Assumes caller holds a write lock on the neighbor set.

Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_REQUEST_CONTROL_DATA Control = Neighbor->WaitQueue;    
    PIP_LOCAL_UNICAST_ADDRESS Source;
    
    ASSERT_ANY_LOCK_HELD(&Interface->Lock);
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    if (Control != NULL) {
        //
        // If we have a packet waiting for address resolution to complete,
        // then take the solicitation source address from the waiting packet.
        // But make sure that the address is on the outgoing interface.
        //
        ASSERT(Neighbor->State == NlnsIncomplete);

        if (Control->Path != NULL) {
            Source = Control->Path->SourceAddress;
            ASSERT(NL_ADDRESS_TYPE(Source) == NlatUnicast);
            if (IsLocalUnicastAddressValid(Source) && 
                Interface == Source->Interface) {
                //
                // Use the packet's source address.
                //
                IppReferenceLocalUnicastAddress(Source);
                return Source;
            }
        }
    }

    //
    // Else, select the best source address for the neighbor's address.
    //
    return
        IppFindBestSourceAddressOnInterfaceUnderLock(
            Interface,
            IP_NEIGHBOR_NL_ADDRESS(Neighbor),
            NULL);
}


PIP_LOCAL_UNICAST_ADDRESS
IppNeighborTimeout(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Process a timeout event for a neighbor.

    We can not call IppSendNeighborSolicitation or IpvxpAbortSend directly,
    because we hold the neighbor set lock; so we leave that to our caller.

    We do not want to punt IppSendNeighborSolicitation to a worker thread,
    because DPC activity preempts worker threads.  Prolonged activity at DPC
    level (for example a DoS attack) would prevent solicits from being sent,
    and more importantly, would prevent neighbors from being recycled because
    the work items would hold neighbor references.
    
Arguments:

    Neighbor - Supplies the neighbor whose timer has expired.

Return Value:

    Returns the source address to use for the neighbor solicitation,
    if one should be sent.  Otherwise returns NULL.        

Caller LOCK: 

    Assumes caller holds at least a read lock on the interface.
    Assumes caller holds a write lock on the neighbor set.

Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    
    ASSERT_ANY_LOCK_HELD(&Interface->Lock);
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    //
    // Neighbor Discovery has timeouts in the INCOMPLETE and PROBE states.
    // These share the same EventTimer.
    //
    ASSERT((Neighbor->State == NlnsIncomplete) ||
           (Neighbor->State == NlnsProbe));
    
    if (Neighbor->EventCount == 0) {
        //
        // We are done probing. Give up and declare the neighbor unreachable.
        //
        TtInitializeTimer(&Neighbor->EventTimer);

        //
        // Empty the WaitQueue because address resolution failed.
        // (Only relevant if we were in the INCOMPLETE state.)
        //
        if (Neighbor->WaitQueue != NULL) {
            ASSERT(Neighbor->State == NlnsIncomplete);

            Control = Neighbor->WaitQueue;
            Neighbor->WaitQueue = NULL;

            IppDropWaitQueue(Interface, Control);
        }

        //
        // This neighbor is not reachable.
        // IsUnreachable may already be TRUE.
        // We need to give FindRoute an opportunity to round-robin.
        // If we are just done with the unicast probing,
        // don't mark as "IsUnreachable", to allow broadcast
        // query when the next packet is sent.
        //
        if (Neighbor->State != NlnsProbe) {
           Neighbor->IsUnreachable = TRUE;
           Neighbor->LastUnreachable = IppTickCount;
           IppInvalidateDestinationCache(Interface->Compartment);
        }

        Neighbor->State = NlnsUnreachable;

        return NULL;
    }

    //
    // Restart the timer for the next solicitation and
    // transmit another neighbor solicitation.
    //
    Neighbor->EventCount--;
    TtStartTimer(
        Interface->NeighborSet.EventTable,
        &Neighbor->EventTimer,
        Interface->RetransmitTicks);
    
    return IppGetNeighborSolicitationSource(Neighbor);
}

VOID
IppFlushNeighborSet(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Flush the neighbor set and reorder the hash table if required.

    Flush neighbor set if:
    (1) Atleast IPP_NEIGHBORSET_ENUM_DELAY time has passed since last flush.
    (2) Number of cached neighbors exceed the cache limit.

    Flush old cached entries each time unless the cache has grown too large.
    
Arguments:

    Interface - Supplies the interface whose neighbor set needs inspection.
        
Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    PRTL_HASH_TABLE_ENTRY Curr;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIP_NEIGHBOR_SET NeighborSet = &Interface->NeighborSet;
    PIP_NEIGHBOR Neighbor;
    ULONG CacheSize = 0, OriginalCacheSize = NeighborSet->CacheSize;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    ASSERT(RtlActiveEnumeratorsHashTable(&NeighborSet->Table) == 0);

    if (OriginalCacheSize > RtlTotalEntriesHashTable(&NeighborSet->Table)) {
        //
        // The estimate has gone way off.
        //
        OriginalCacheSize = RtlTotalEntriesHashTable(&NeighborSet->Table);
    }
    
    if ((IppTickCount - NeighborSet->LastEnumerationTick < 
            IPP_NEIGHBORSET_ENUM_DELAY) && 
        (OriginalCacheSize < IppNeighborCacheLimit)) {
        return;
    }

    IppRestructureHashTableUnderLock(&NeighborSet->Table);
    
    RtlInitEnumerationHashTable(&NeighborSet->Table, &Enumerator);

    for (Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator);
         Curr != NULL;
         Curr = RtlEnumerateEntryHashTable(&NeighborSet->Table, &Enumerator)) {

        Neighbor = (PIP_NEIGHBOR) CONTAINING_RECORD(Curr, IP_NEIGHBOR, Link);

        //
        // Pick neighbors to flush.  
        //
        if (IppIsCachedNeighbor(Neighbor)) {
            if (!TtIsTimerActive(&Neighbor->EventTimer) && 
                ((OriginalCacheSize > IppNeighborCacheLimit) ||
                 ((Neighbor->State == NlnsUnreachable) && 
                  (IppTickCount - Neighbor->LastUsed > 
                       IPP_NEIGHBORSET_ENUM_DELAY)))) {
                IppDeleteNeighbor(Neighbor);
            } else {
                CacheSize++;
            }
        }
    }
    RtlEndEnumerationHashTable(&NeighborSet->Table, &Enumerator);    

    //
    // Update the cache size and the enumeration tick.
    //
    Interface->NeighborSet.LastEnumerationTick = IppTickCount;
    InterlockedExchange(&Interface->NeighborSet.CacheSize, CacheSize);
}

VOID
IppNeighborSetTimeout(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN RecalculateReachableTime
    )
/*++

Routine Description:

    Process timeouts in an interface's neighbor set.
    Called once every timer tick from IpvxpInterfaceSetTimeout.

Arguments:

    Interface - Supplies the interface whose neighbor set needs inspection.

    RecalculateReachableTime - Supplies TRUE to indicate that the interface's
        ReachableTime should be recalculated.
        
Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
#define DEFAULT_COUNT 10

    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG i, FiredCount, SolicitCount = 0;
    LIST_ENTRY FiredList;
    PTIMER_ENTRY Timer;
    PIP_NEIGHBOR DefaultNeighbor[DEFAULT_COUNT],
        *Neighbor = DefaultNeighbor;
    PIP_LOCAL_UNICAST_ADDRESS DefaultSource[DEFAULT_COUNT],
        *Source = DefaultSource;
    PIP_REQUEST_CONTROL_DATA ControlBatch;
    KLOCK_QUEUE_HANDLE LockHandle;

    DISPATCH_CODE();

    RtlAcquireReadLockAtDpcLevel(&Interface->Lock);
    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    //
    // Verify the neighbor discovery invariants.
    //
    IppVerifyNeighborsUnderLock(Interface);
    
    //
    // Recalculate the reachable time.
    //
    if (RecalculateReachableTime) {
        Interface->ReachableTicks =
            IppNeighborReachableTicks(Interface->BaseReachableTime);
    }    
    
    //
    // Determine which timers fired.
    //
    FiredCount = 
        TtFireTimer(
            Interface->NeighborSet.EventTable, 
            &FiredList);
    if (FiredCount > DEFAULT_COUNT) {
        //
        // We are forced to allocate due to a large number of timeouts.
        //
        Neighbor =
            ExAllocatePoolWithTagPriority(
                NonPagedPool,
                FiredCount *
                (sizeof(PIP_NEIGHBOR) + sizeof(PIP_LOCAL_UNICAST_ADDRESS)),
                IpGenericPoolTag,
                LowPoolPriority);
        if (Neighbor == NULL) {
            //
            // Allocation failed!  Restart timers so we'll try again later.
            //
            while (!IsListEmpty(&FiredList)) {
                Timer = (PTIMER_ENTRY)
                    CONTAINING_RECORD(
                        RemoveHeadList(&FiredList),
                        TIMER_ENTRY,
                        Link);
                TtStartTimer(
                    Interface->NeighborSet.EventTable,
                    Timer,
                    Interface->RetransmitTicks);
            }

            Neighbor = DefaultNeighbor;
            goto FlushDropQueue;
        }

        Source = (PIP_LOCAL_UNICAST_ADDRESS *) (Neighbor + FiredCount);
    }

    while (!IsListEmpty(&FiredList)) {
        //
        // Educate prefast about the FiredCount and FiredList relationship.
        //        
        ASSERT(SolicitCount < FiredCount);
        __analysis_assume(SolicitCount < FiredCount);

        Neighbor[SolicitCount] =
            CONTAINING_RECORD(
                RemoveHeadList(&FiredList),
                IP_NEIGHBOR,
                EventTimer.Link);

        Source[SolicitCount] = IppNeighborTimeout(Neighbor[SolicitCount]);
        if (Source[SolicitCount] != NULL) {
            //
            // Send another solicitation to this neighbor.
            //
            IppReferenceNeighbor(Neighbor[SolicitCount]);
            SolicitCount++;
        }
    }

FlushDropQueue:
    //
    // Flush the DropQueue.
    //
    ControlBatch = Interface->NeighborSet.DropQueue;
    Interface->NeighborSet.DropQueue = NULL;

    IppFlushNeighborSet(Interface);

    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);
    RtlReleaseReadLockFromDpcLevel(&Interface->Lock);

    for (i = 0; i < SolicitCount; i++) {
        IppSendNeighborSolicitation(TRUE, Neighbor[i], Source[i]);
        IppDereferenceNeighbor(Neighbor[i]);
        IppDereferenceLocalUnicastAddress(Source[i]);
    }

    if (Neighbor != DefaultNeighbor) {
        ExFreePool(Neighbor);
    }

    if (ControlBatch != NULL) {
        IppFlushDropQueue(Protocol, ControlBatch, TRUE);
    }

}


BOOLEAN
IppResolveNeighbor(
    IN PIP_NEIGHBOR Neighbor,
    IN PIP_REQUEST_CONTROL_DATA Control OPTIONAL
    )
/*++

Routine Description:
    
    IP primitive for sending via Neighbor Discovery.

    We already know the next-hop neighbor and have a completed packet ready
    to send.  All we really do here is check & update the neighbor's state
    and, if required, queue the packet pending neighbor resolution.

Arguments:

    Neighbor - Supplies the neighbor to resolve.
    
    Control - Optionally supplies the packets to send.

Return Value:

    TRUE, if the packet can be sent.
    FALSE, otherwise.  The packet would have been completed.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIP_LOCAL_UNICAST_ADDRESS Source = NULL;
    PIP_REQUEST_CONTROL_DATA ControlBatch, QueuedControl = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG TicksLastReachable;

    //
    // Common, lock-free path.
    // Since these checks are made without holding the interface lock, there is
    // a small possibility that the neighbor's state or datalink layer address
    // might change from underneath us.  The worst that can happen is that
    // we'll send a packet somewhere strange.
    //
    if (!IppDoesNeighborNeedResolution(Neighbor, Interface)) {
        return TRUE;
    }

    RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

    //
    // Caveat: The neighbor might have been deleted!!!
    // If so, do not restart timers or queue any packets.
    //
    if (IppIsDeletedNeighbor(Neighbor)) {
        if (Neighbor->State > NlnsIncomplete) {
            goto ResolveSuccess;
        } else {
            goto ResolveFailure;
        }        
    }

    //
    // The following arithmetic correctly handles wraps of TickCount.
    //
    TicksLastReachable = (ULONG) (IppTickCount - Neighbor->LastReachable);

    //
    // Check the Neighbor Discovery Protocol state of our Neighbor to ensure
    // that we have current information to work with.  We don't have a timer
    // going off to drive this in the common case, but instead check the
    // reachability timestamp directly here.
    //
    switch (Neighbor->State) {
    case NlnsPermanent:
        //
        // This neighbor is always valid.
        //
        break;

    case NlnsReachable:
        //
        // Common case.  We've verified neighbor reachability within the last
        // 'ReachableTicks' ticks of the system interval timer.  If the time
        // limit hasn't expired, we're free to go.
        //
        if (TicksLastReachable <= Interface->ReachableTicks) {
            //
            // Got here within the time limit.  Just send it.
            //
            break;
        }

        //
        // TODO: For an offloaded neighbor, we can potentially avoid probing by
        // quering the NIC to determine if it has recently confirmed forward
        // reachability.  For now, we just move to STALE since that's simpler.
        //

        //
        // Too long since last send.  Entry went stale.  Conceptually, we've
        // been in the STALE state since the above quantity went positive.  So
        // just drop on into it now...
        // 

    case NlnsStale:
        //
        // We have a stale entry in our neighbor cache. If significant time has 
        // elapsed, then to speed up failover in case of changing MAC address 
        // of the neighbor, declare the neighbor unreachable. This is not 
        // required for an interface like p2p that does not discover neighbors.
        // Otherwise, go into PROBE state, start the probe timer, and send the 
        // packet anyway.
        //
        if ((Interface->FlCharacteristics->DiscoversNeighbors) &&
            (TicksLastReachable > (Interface->ReachableTicks + 
                                   DELAY_FIRST_PROBE_TIME + 
                                   MAX_UNICAST_SOLICIT * 
                                   Interface->RetransmitTicks)) &&
            (TicksLastReachable > UNICAST_PROBING_TIME)) {
            //
            // It has been too long since the last resolution.
            // Declare unreachable and proceed with broadcast.  
            //
            goto Unreachable;
        }

        Neighbor->State = NlnsProbe;
        ASSERT(!TtIsTimerActive(&Neighbor->EventTimer));
        Neighbor->EventCount = MAX_UNICAST_SOLICIT;
        TtStartTimer(
            Interface->NeighborSet.EventTable,
            &Neighbor->EventTimer,
            DELAY_FIRST_PROBE_TIME);
        break;
        
    case NlnsProbe:
        //
        // While in the PROBE state, we continue to send to our cached address
        // and hope for the best.
        //
        break;

Unreachable:
    case NlnsUnreachable:
        //
        // We have an unreachable neighbor in our neighbor cache.
        // There's not much we can do unless the interface supports ND.
        //
        if (!Interface->FlCharacteristics->DiscoversNeighbors) {
            //
            // Mark the neighbor unreachable and invalidate the route cache.
            // This gives FindNextHop an opportunity to round-robin.
            //
            Neighbor->IsUnreachable = TRUE;
            Neighbor->LastUnreachable = IppTickCount;

            IppInvalidateDestinationCache(Interface->Compartment);

            goto ResolveFailure;
        }
        
        Neighbor->State = NlnsIncomplete;
        ASSERT(!TtIsTimerActive(&Neighbor->EventTimer));            
        Neighbor->EventCount = MAX_MULTICAST_SOLICIT;
        TtStartTimer(
            Interface->NeighborSet.EventTable,
            &Neighbor->EventTimer,
            Interface->RetransmitTicks);
            
        //
        // Fall through into the INCOMPLETE state and queue the packet.
        //
        
    case NlnsIncomplete:

        ASSERT(TtIsTimerActive(&Neighbor->EventTimer));
        //
        // If we were trying to probe (by IppProbeNeighborReachability) this 
        // neighbor, but got a packet destined for this neighbor, then simply 
        // fall back to normal resolution mechanism.
        //
        if (TtQueryTimer(
                Interface->NeighborSet.EventTable, 
                &Neighbor->EventTimer) > 
                Interface->RetransmitTicks) {
            //
            // Restart the pending timer.
            //
            TtStopTimer(
                Interface->NeighborSet.EventTable, 
                &Neighbor->EventTimer);
            Neighbor->EventCount = MAX_MULTICAST_SOLICIT;
            TtStartTimer(
                Interface->NeighborSet.EventTable,
                &Neighbor->EventTimer,
                Interface->RetransmitTicks);
        }

        //
        // We do not have a valid link-layer address for the neighbor.
        // We must queue the packet, if any, pending neighbor discovery.
        //      
        if (Control != NULL) {
            QueuedControl = Neighbor->WaitQueue;
            Neighbor->WaitQueue = IppPendPacket(Control);
            if (Neighbor->WaitQueue == NULL) {
                IppCompleteAndFreePacketList(Control, FALSE);                                
            }
            Control = NULL;
        }
        
        //
        // If we have not started neighbor discovery yet,
        // do so now by sending the first solicitation (below).
        // It would be simpler to let IppNeighborTimeout send the
        // first solicitation but that would introduce latency.
        //
        if (Neighbor->EventCount == MAX_MULTICAST_SOLICIT) {
            Source = IppGetNeighborSolicitationSource(Neighbor);
            if (Source != NULL) {
                Neighbor->EventCount--;
            }
        }
        
ResolveFailure:
        if (Control != NULL) {
            IppDropWaitQueue(Interface, Control);
        }
        
        //
        // If there are any packets waiting to be completed, take this
        // opportunity.  With an active DoS attack, we want to do this
        // more frequently than IppNeighborSetTimeout will.
        //
        ControlBatch = Interface->NeighborSet.DropQueue;
        Interface->NeighborSet.DropQueue = NULL;

        RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);

        if (Source != NULL) {
            IppSendNeighborSolicitation(FALSE, Neighbor, Source);
            IppDereferenceLocalUnicastAddress(Source);
        }

        if (QueuedControl != NULL) {
            IppFlushWaitQueue(Protocol, QueuedControl);
        }        

        if (ControlBatch != NULL) {
            IppFlushDropQueue(Protocol, ControlBatch, FALSE);
        }
        
        return FALSE;

    default:
        //
        // Should never happen.
        //
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR, 
                   "IPNG: Bad neighbor state %u\n", Neighbor->State);
        ASSERT(FALSE);
    }

ResolveSuccess:    
    //
    // Unlock before transmitting the packet.  This means that there is a very
    // small chance that Neighbor->DlAddress could change out from underneath
    // us. (For example, if we process an advertisement changing the link-layer
    // address.)  In practice this won't happen, and if it does the worst that
    // will happen is that we'll send a packet somewhere strange.  The best
    // alternative is copying the LinkAddress.
    //
    RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);

    //
    // Timestamp the neighbor so it is preferred by our LRU replacement policy.
    //
    IppRefreshNeighbor(Neighbor);

    return TRUE;
}

VOID 
IppSendNeighborProbe(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Send a neighbor solicitation message. This is simply a wrapper around 
    IppSendNeighborSolicitation.
    
Arguments:

    Neighbor - Supplies the neighbor to be solicited.

Return Value:

    None.

Lock: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_LOCAL_UNICAST_ADDRESS Source;
    KIRQL OldIrql;
    
    RtlAcquireReadLock(&Neighbor->Interface->NeighborSetLock, &OldIrql);
    if (IppIsDeletedNeighbor(Neighbor)) {
        RtlReleaseReadLock(&Neighbor->Interface->NeighborSetLock, OldIrql);
        return;
    }
    RtlReleaseReadLock(&Neighbor->Interface->NeighborSetLock, OldIrql);
        
    Source = 
        IppFindBestSourceAddressOnInterface(
            Neighbor->Interface, 
            IP_NEIGHBOR_NL_ADDRESS(Neighbor),
            NULL);
    if (Source != NULL) {
        IppSendNeighborSolicitation(FALSE, Neighbor, Source);
    }
}

PIP_LOCAL_ADDRESS
IppHandleNeighborSolicitation(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *DlSourceAddress,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN CONST UCHAR *NlSourceAddress,
    IN CONST UCHAR *NlTargetAddress
    )
/*++

Routine Description:

    Perform generic processing of a neighbor solicitation message.

Arguments:

    SubInterface - Supplies the subinterface over which the neighbor
        solicitation was received.

    DlSourceAddress - Supplies the link-layer address of the sender.

    DlSourceRoute - Supplies the link-layer source-route of the sender.
    
    NlSourceAddress - Supplies the network-layer address of the sender.

    NlTargetAddress - Supplies the network-layer address being resolved.

Return Value:

    Returns the local address corresponding to NlTargetAddress.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    NL_ADDRESS_TYPE SourceAddressType, TargetAddressType;
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    PIP_LOCAL_ADDRESS LocalTarget;
    PIP_NEIGHBOR Neighbor;
    KLOCK_QUEUE_HANDLE LockHandle;
    KLOCK_QUEUE_HANDLE NeighborSetLockHandle;

    SourceAddressType = Protocol->AddressType(NlSourceAddress);
    if (((SourceAddressType != NlatUnspecified) &&
         (SourceAddressType != NlatUnicast)) ||
        INET_IS_ADDR_LOOPBACK(Protocol->Family, NlSourceAddress)) {
        //
        // A packet containing an invalid source address is quickly dropped.
        //
        return NULL;
    }

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    
    //
    // See if we're the target of the solicitation.  If the target address is
    // not a unicast or anycast address assigned to receiving interface, then
    // we must silently drop the packet.
    //
    LocalTarget =
        IppFindAddressOnInterfaceExUnderLock(Interface, NlTargetAddress);
    if (LocalTarget == NULL) {
        //
        // See if we have a matching proxy neighbor.
        // If so, obtain the corresponding proxy local address.
        //
        LocalTarget = IppGetProxyLocalAddress(Interface, NlTargetAddress);
        if (LocalTarget == NULL) {
            //
            // It may be a DAD solicitation for some address that
            // is in our cache. Check if we have such a neighbor
            // cached, and if yes, mark it as stale with the current
            // DL address, so it will be verified when used next time.
            //
            if (SourceAddressType == NlatUnspecified) {
                RtlAcquireWriteLockAtDpcLevel(
                   &Interface->NeighborSetLock, 
                   &NeighborSetLockHandle);

                Neighbor =
                   IppFindNeighborUnderLock(
                      Interface,
                      SubInterface,
                      NlTargetAddress);

                if (Neighbor != NULL) {
                    IppUpdateNeighbor(
                       Neighbor,
                       NULL,
                       NULL,
                       FALSE,
                       FALSE,
                       TRUE);
                    IppDereferenceNeighbor(Neighbor);
                }

                RtlReleaseWriteLockFromDpcLevel(
                   &Interface->NeighborSetLock, 
                   &NeighborSetLockHandle);
            }
            RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
            return NULL;
        }        
    }
    
    TargetAddressType = NL_ADDRESS_TYPE(LocalTarget);
    if ((TargetAddressType != NlatUnicast) &&
        (TargetAddressType != NlatAnycast)) {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        IppDereferenceLocalAddress(LocalTarget);
        return NULL;
    }

    //
    // If the source link-layer address belongs to this interface, we must
    // silently drop the packet, like XP does (RFC2461 says the same). 
    // We have seen some wireless APs and routers which echo our 
    // DAD requests back to us, causing DAD to fail.
    //
    if ((DlSourceAddress != NULL) &&
        (RtlEqualMemory(
            DlSourceAddress,
            Interface->FlCharacteristics->DlAddress, 
            Interface->FlCharacteristics->DlAddressLength))) {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        IppDereferenceLocalAddress(LocalTarget);
        return NULL;
    }


    //
    // We've received a valid neighbor solicitation.
    //
    // First, we check our Duplicate Address Detection state [RFC 2462].
    //
    if (TargetAddressType == NlatUnicast) {
        if ((SourceAddressType == NlatUnspecified) &&
             (IsLocalUnicastAddressTentative(
                 (PIP_LOCAL_UNICAST_ADDRESS) LocalTarget) ||
              IsLocalUnicastAddressOptimistic(
                 (PIP_LOCAL_UNICAST_ADDRESS) LocalTarget))) {
            //
            // If the source address of the solicitation is the unspecified
            // address, it came from a node performing DAD on the address.
            // If our local address is tentative, then we make it duplicate. 
            //

            //
            // Link local addresses will likely get auto regenerated, so no 
            // need to generate a notification.
            //
            if (LocalTarget->AddressOrigin != ADDR_CONF_LINK) {
                IppNotifyDad(
                    NlSourceAddress,
                    Protocol->Characteristics->AddressBytes,
                    LocalTarget->Identifier->ScopeId,
                    DlSourceAddress,
                    Interface->FlCharacteristics->DlAddressLength,
                    EVENT_TCPIP_ADDRESS_CONFLICT2);
            }
            IppDadFailed((PIP_LOCAL_UNICAST_ADDRESS) LocalTarget);
        }

        if (!IsLocalUnicastAddressValid(
                (PIP_LOCAL_UNICAST_ADDRESS) LocalTarget)) {
            //
            // Ignore solicitations to invalid addresses.
            // Otherwise defend the address by falling through down below.
            //
                
            RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
            IppDereferenceLocalAddress(LocalTarget);
            return NULL;
        }
    }

    //
    // Create/Update the neighbor entry for the source of this solicitation.
    // In this case, only bother if the SLLA option was present;
    // if it's not, IppUpdateNeighbor won't do anything.
    //
    if ((SourceAddressType != NlatUnspecified) && (DlSourceAddress != NULL)) {

        SourceAddressType =
            IppUpdateAddressTypeUnderLock(
                Interface,
                NlSourceAddress,
                SourceAddressType);
        
        RtlAcquireWriteLockAtDpcLevel(
            &Interface->NeighborSetLock, 
            &NeighborSetLockHandle);

        Neighbor =
            IppFindOrCreateNeighborUnderLock(
                Interface,
                SubInterface,
                NlSourceAddress,
                SourceAddressType);
        if (Neighbor != NULL) {
            Control =
                IppUpdateNeighbor(
                    Neighbor,
                    DlSourceAddress,
                    DlSourceRoute,
                    FALSE,
                    TRUE,
                    FALSE);
            IppDereferenceNeighbor(Neighbor);
        }

        RtlReleaseWriteLockFromDpcLevel(
            &Interface->NeighborSetLock, 
            &NeighborSetLockHandle);
    }
    
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    if (Control != NULL) {
        IppFragmentPackets(Protocol, Control);
    }

    return LocalTarget;
}


VOID
IppHandleNeighborAdvertisement(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *DlSourceAddress,
    IN CONST SOURCEROUTE_HEADER *DlSourceRoute,
    IN CONST UCHAR *NlSourceAddress,
    IN IPV6_NEIGHBOR_ADVERTISEMENT_FLAGS Flags
    )
/*++

Routine Description:

    Perform generic processing of a neighbor advertisement message.

Arguments:

    SubInterface - Supplies the subinterface over which the neighbor
        advertisement was received.

    DlSourceAddress - Supplies the link-layer address of the sender.

    DlSourceRoute - Supplies the link-layer source-route of the sender.
    
    NlSourceAddress - Supplies the network-layer address of the sender.

    Flags - Supplies Solicited, Override, and Router flags.

Return Value:

    Returns the local address corresponding to NlTargetAddress.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT NlAddressLength = Protocol->Characteristics->AddressBytes;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    UCHAR DlAddressBuffer[DL_ADDRESS_LENGTH_MAXIMUM];
    NL_ADDRESS_TYPE AddressType;
    
    BOOLEAN PurgeRouting = FALSE;
    PIP_LOCAL_ADDRESS LocalTarget;
    PIP_NEIGHBOR Neighbor;
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;
    KIRQL OldIrql;

    AddressType = Protocol->AddressType(NlSourceAddress);
    if (((AddressType != NlatUnicast) && (AddressType != NlatAnycast)) ||
        INET_IS_ADDR_LOOPBACK(Protocol->Family, NlSourceAddress)) {
        //
        // A packet containing an invalid target address is quickly dropped.
        //
        return;
    }
    
    RtlAcquireReadLock(&Interface->Lock, &OldIrql);
    
    //
    // We've received a valid neighbor advertisement.
    //
    // First, we check our Duplicate Address Detection state [RFC 2462].
    //
    LocalTarget = (PIP_LOCAL_ADDRESS)
        IppFindAddressOnInterfaceExUnderLock(Interface, NlSourceAddress);
    if (LocalTarget != NULL) {
        if (IppInterfaceDadEnabled(Interface) &&
            (NL_ADDRESS_TYPE(LocalTarget) == NlatUnicast)) {
            PIP_LOCAL_UNICAST_ADDRESS LocalAddress = 
                (PIP_LOCAL_UNICAST_ADDRESS) LocalTarget;
            //
            // Someone out there appears to be using our unicast address;
            // they responded to our DAD solicit. Make sure that the response 
            // is not from our link layer address.
            //
            // RFC 2462 requires us to declare a duplicate only if our address
            // is tentative, whereas we also make our address duplicate
            // if the override bit in the advertisement is set and we are in
            // the optimistic DAD phase. 
            // Reason being, we redo DAD for existing addresses upon reconnect.
            //
            if ((DlSourceAddress == NULL || 
                 !RtlEqualMemory(
                      Interface->FlCharacteristics->DlAddress,
                      DlSourceAddress, 
                      DlAddressLength)) && 
                ((Flags.Override && (LocalAddress->DadCount > 0)) ||
                 IsLocalUnicastAddressTentative(LocalAddress))) {

                //
                // Link local addresses will likely get auto regenerated, so no
                // need to generate a notification.
                //
                if (LocalTarget->AddressOrigin != ADDR_CONF_LINK) {
                    IppNotifyDad(
                        NlSourceAddress,
                        Protocol->Characteristics->AddressBytes,
                        LocalTarget->Identifier->ScopeId,
                        DlSourceAddress,
                        Interface->FlCharacteristics->DlAddressLength,
                        EVENT_TCPIP_ADDRESS_CONFLICT2);
                }
                
                IppDadFailed((PIP_LOCAL_UNICAST_ADDRESS) LocalTarget);

                //
                // We continue with normal processing.
                // For example, we may have an invalid (duplicate) NTE for the
                // address and we are trying to communicate with the address,
                // which is currently assigned to another node.
                //        
            }
        }
        IppDereferenceLocalAddress(LocalTarget);
    }

    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);
    
    //
    // Update the neighbor set in response to the neighbor advertisement.
    // If no matching entry is found, ignore the advertisement.
    //
    Neighbor =
        IppFindNeighborUnderLock(Interface, SubInterface, NlSourceAddress);
    if (Neighbor == NULL) {
        Neighbor = IppFindNeighborUnderLock(Interface, NULL, NlSourceAddress);
        //
        // If the correct subinterface was previously unknown,
        // then save the subinterface on which the advertisement arrived.
        //
        if ((Neighbor != NULL) && (Neighbor->State <= NlnsIncomplete)) {    
            //
            // We don't need the old neighbor.
            // Instead create a new one on the arrival subinterface.
            //
            AddressType = Neighbor->AddressType;
            IppDereferenceNeighbor(Neighbor);
            
            Neighbor =
                IppCreateAndInitializeNeighbor(
                    Interface,
                    SubInterface, 
                    NlSourceAddress, 
                    AddressType);

            IppInvalidateDestinationCache(Interface->Compartment);
        }
    }

    //
    // Ignore NA if Neighbor is not being resolved (Unreachable) or statically 
    // configured.
    //
    if ((Neighbor == NULL) || 
        (Neighbor->State == NlnsPermanent) || 
        (Neighbor->State == NlnsUnreachable)) {
        goto Bail;
    }

    if (!Interface->FlCharacteristics->DiscoversNeighbors ||
        Interface->FlCharacteristics->UseStaticMapping) {
        FL_REQUEST_MAP_ADDRESS MapArgs = {0};
        
        //
        // Interfaces that do not use LLA options should support a static
        // mapping by letting the framing layer specify the DlAddress.
        //
        MapArgs.ProviderInterfaceHandle = Interface->FlContext;
        MapArgs.NlAddress = NlSourceAddress;
        MapArgs.DlAddress = DlAddressBuffer;
        if (Interface->FlModule->Npi.Dispatch->MapAddress(&MapArgs) ==
            FlAddressMappingStatic) {
            DlSourceAddress = DlAddressBuffer;
        }
    }

    Control =
        IppUpdateNeighbor(
            Neighbor,
            DlSourceAddress,
            DlSourceRoute,
            Flags.Solicited,
            Flags.Override,
            FALSE);

    if ((Neighbor->State != NlnsIncomplete) &&
        (Neighbor->State != NlnsUnreachable) &&
        ((DlSourceAddress == NULL) ||
         (RtlEqualMemory(
             IP_NEIGHBOR_DL_ADDRESS(Neighbor, NlAddressLength),
             DlSourceAddress,
             DlAddressLength)))) {
        //
        // If this is an advertisement for our cached link-layer address,
        // Determine if this neighbor used to be a router, but is no longer.
        //
        PurgeRouting = (Neighbor->IsRouter && !Flags.Router);
        Neighbor->IsRouter = Flags.Router;
    }
    
Bail:    
    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);
    RtlReleaseReadLock(&Interface->Lock, OldIrql);

    //
    // If we need to send a packet, do so now.  (Without holding a lock.)
    //
    // It is possible that this neighbor is no longer a router, and the waiting
    // packet wants to use the neighbor as a router.  In this situation the ND
    // spec requires that we still send the waiting packet to the neighbor.
    // Narten/Nordmark confirmed this interpretation in private email [RICH].
    //
    if (Control != NULL) {
        IppFragmentPackets(Protocol, Control);
    }

    //
    // If need be, purge the routing data structures.
    //
    if (PurgeRouting) {
        if (IS_IPV6_PROTOCOL(Protocol)) {
            //
            // Delete the default route with this
            // next hop. 
            // Code Review: Do we need to delete all
            // routes with this neighbor as the next hop?
            //
            IppUpdateAutoConfiguredRoute(
                Interface,
                (CONST UCHAR *) NlSourceAddress,
                Neighbor,
                (CONST UCHAR *) &in6addr_any,
                0,
                0,
                0);
        }
    }
    
    if (Neighbor != NULL) {
        IppDereferenceNeighbor(Neighbor);
    }
}

VOID
IppSendNeighborSolicitation(
    IN BOOLEAN DispatchLevel,
    IN PIP_NEIGHBOR Neighbor,
    IN PIP_LOCAL_UNICAST_ADDRESS Source
    )
/*++

Routine Description:

    Send a neighbor solicitation message.

    Compare NeighborSolicitSend in the XP IPv6 stack.
    
Arguments:

    DispatchLevel - Supplies TRUE if IRQL is known to be at DISPATCH level.

    Neighbor - Supplies the neighbor to be solicited.

    Source - Supplies the source address to use for the neighbor solicitation.

Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    IF_LUID OldLuid = {0};
    PIP_SUBINTERFACE SubInterface = NULL;
    
    ASSERT(Interface->FlCharacteristics->DiscoversNeighbors ||
           Interface->UseNeighborUnreachabilityDetection);

    if (DispatchLevel) {
        DISPATCH_CODE();
    }
    
    //
    // Check neighbor discovery protocol state of our neighbor in order to
    // determine whether we should multicast or unicast our solicitation.
    //
    // Note that we do not take the interface lock to make this check.    
    // The worst that can happen is that we'll think the link-layer address
    // is valid when it's not.  This is rare enough and benign enough to be OK.
    //
    if ((Neighbor->State != NlnsIncomplete) &&
        (Neighbor->State != NlnsUnreachable)) {
        //
        // We have a cached link-layer address that has gone stale.
        // Probe this address via a unicast solicitation.
        //        
        Protocol->SendNeighborSolicitation(
            DispatchLevel,
            Interface,
            Neighbor->SubInterface,
            Neighbor,
            Source,
            IP_NEIGHBOR_NL_ADDRESS(Neighbor),
            IP_NEIGHBOR_NL_ADDRESS(Neighbor));
        return;
    }

    for (;;) {
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 
                                                         &OldLuid, 
                                                         SubInterface);
        if (SubInterface == NULL) {
            break;
        }
        OldLuid = SubInterface->Luid;

        Protocol->SendNeighborSolicitation(
            DispatchLevel,
            Interface,
            SubInterface,
            NULL,
            Source,
            NULL,
            IP_NEIGHBOR_NL_ADDRESS(Neighbor));

    }
}

VOID
IppSendUnsolicitedNeighborAdvertisement(
    IN PIP_LOCAL_UNICAST_ADDRESS Source
    )
/*++

Routine Description:

    Send an unsolicited neighbor advertisement message.
    
Arguments:

    Source - Supplies the source address to be advertised.

Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = Source->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    IF_LUID OldLuid = {0};
    PIP_SUBINTERFACE SubInterface = NULL;
    
    ASSERT(Interface->FlCharacteristics->DiscoversNeighbors ||
           Interface->UseNeighborUnreachabilityDetection);

    DISPATCH_CODE();
    
    for (;;) {
        SubInterface = 
            IppGetNextSubInterfaceOnInterface(Interface, NULL, SubInterface);
        if (SubInterface == NULL) {
            break;
        }
        OldLuid = SubInterface->Luid;

        if (IS_IPV4_PROTOCOL(Protocol)) {
            //
            // Legacy devices relied on gratuitous ARPs to update mappings. 
            //
            Protocol->SendNeighborSolicitation(
                TRUE,
                Interface,
                SubInterface,
                NULL,
                Source,
                NULL,
                NL_ADDRESS(Source));
        } else {
            Protocol->SendNeighborAdvertisement(
                SubInterface,
                NULL,
                NULL,
                (CONST UCHAR *)&in6addr_any, 
                (PIP_LOCAL_ADDRESS) Source);
        }
    }
}

VOID
IppSendDadSolicitation(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
    /*++

Routine Description:
    
    Sends a neighbor solicitation for Duplicate Address Detection (DAD).
    Like IppSendNeighborSolicitation, but specialized for DAD.
    Compare DADSolicitSend in the XP IPv6 stack.
    
Arguments:

    LocalAddress - Supplies a local unicast address to perform DAD for.
        
Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    IF_LUID OldLuid = {0};
    PIP_SUBINTERFACE SubInterface = NULL;

    ASSERT(Interface->FlCharacteristics->DiscoversNeighbors);

    for (;;) {
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 
                                                         &OldLuid, 
                                                         SubInterface);
        if (SubInterface == NULL) {
            break;
        }
        OldLuid = SubInterface->Luid;

        Protocol->SendNeighborSolicitation(
            FALSE,
            Interface, 
            SubInterface,
            NULL,
            NULL,
            NULL,
            NL_ADDRESS(LocalAddress));

    }
}
