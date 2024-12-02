/*++

Copyright (c) 2001-2002  Microsoft Corporation

Module Name:

    timer.h

Abstract:

    This module contains a simple timer table implementation.

Author:

    Mohit Talwar (mohitt) Wed Oct 03 10:54:07 2001

Environment:

    Kernel mode only.

--*/

#ifndef _TIMER_
#define _TIMER_

#pragma once

//
// TIMER_TABLE
//
// Define a simple timer table.
//

typedef struct _TIMER_TABLE {
    ULONG LastFiredTick;
    ULONG TimerCount;
    USHORT BucketCount;
    BOOLEAN FastTimersEnabled;
    LIST_ENTRY Bucket[0];
} TIMER_TABLE, *PTIMER_TABLE;

//
// TIMER_ENTRY
//
// Define the state for each timer entry.
//

typedef struct _TIMER_ENTRY {
    ULONG DueTick;
    LIST_ENTRY Link;
} TIMER_ENTRY, *PTIMER_ENTRY;


__inline
PTIMER_TABLE
TtCreateTable(
    IN USHORT BucketCount,
    IN BOOLEAN FastTimersEnabled
    )
/*++

Routine Description:

    Creates a timer table.

Arguments:

    BucketCount - Supplies the number of buckets required in the timer table.
        This count should ideally be the upper bound of timeout values.

    FastTimersEnabled - Supplies a boolean indicating whether fast timers are
        enabled or not.  Fast timers can be triggered immediately without
        waiting for the next timer tick. 

Return Value:

    The address of the allocated TIMER_TABLE or NULL.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PTIMER_TABLE Table;
    ULONG AllocatedCount;
    ULONG i;

    AllocatedCount = BucketCount + (FastTimersEnabled ? 1 : 0);
    Table = (PTIMER_TABLE) ExAllocatePoolWithTagPriority(
        NonPagedPool,
        sizeof(TIMER_TABLE) + (AllocatedCount * sizeof(LIST_ENTRY)),
        IpTimerTablePoolTag,
        LowPoolPriority);
    if (Table == NULL) {
        return NULL;
    }

    Table->LastFiredTick = 0;
    Table->TimerCount = 0;
    Table->FastTimersEnabled = FastTimersEnabled;
    Table->BucketCount = BucketCount;
    for (i = 0; i < AllocatedCount; i++) {
        InitializeListHead(Table->Bucket + i);
    }
    return Table;
}


__inline
VOID
TtDestroyTable(
    IN PTIMER_TABLE Table
    )
/*++

Routine Description:

    Destroys the timer table.  No timers should be pending at this point.
    
Arguments:

    Table - Supplies the timer table to destroy.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ULONG i;
    ULONG AllocatedCount;
    
    AllocatedCount = Table->BucketCount + (Table->FastTimersEnabled ? 1 : 0);
    for (i = 0; i < AllocatedCount; i++) {
        ASSERT(IsListEmpty(Table->Bucket + i));
    }
    ExFreePool(Table);
}


__inline
BOOLEAN
TtIsTableEmpty(
    IN PTIMER_TABLE Table
    )
/*++

Routine Description:

    Inspect whether the timer table is empty.
   
Arguments:

    Table - Supplies the timer table to inspect.

Return Value:

    TRUE if the table is empty, FALSE otherwise.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    return (Table->TimerCount == 0);
}
    
__inline
VOID
TtInitializeTimer(
    OUT PTIMER_ENTRY Entry
    )
/*++

Routine Description:

    Initializes a timer.
    
Arguments:

    Entry - Supplies the entry whose timer is to be initialized.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.
    
--*/
{
    Entry->DueTick = 0;
    InitializeListHead(&(Entry->Link));
}


__inline
BOOLEAN
TtIsTimerActive(
    IN PTIMER_ENTRY Entry
    )
/*++

Routine Description:

    Inspect whether the timer is active.
   
Arguments:

    Entry - Supplies the entry whose timer is to be inspected.

Return Value:

    TRUE if the timer is active, FALSE otherwise.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    return (!IsListEmpty(&(Entry->Link)));
}

__inline
VOID
TtStartTimerEx(
    IN OUT PTIMER_TABLE Table,
    IN OUT PTIMER_ENTRY Entry,
    IN ULONG CurrentTick,
    IN ULONG Ticks
    )
/*++

Routine Description:

    Starts a timer. The timer should not be active.
    To restart: TtStopTimer(Entry); TtStartTimer(Table, Entry, Ticks);
    
Arguments:

    Table - Supplies the timer table to contain the timer entry.

    Entry - Supplies the entry whose timer is to be started.

    CurrentTick - Supplies the current tick count. The timer expiration is 
    based off of this tick. This is because the timer table itself does not 
    maintain any notion of time.

    Ticks - Supplies the number of ticks after which the timer is fired.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ULONG Index;

    //
    // Offset the DueTick from the current system tick as the 
    // Table->CurrentTick gets updated only so often.
    //
    Entry->DueTick = CurrentTick + Ticks;
    if (Ticks == 0) {
        ASSERT(Table->FastTimersEnabled);
        Index = Table->BucketCount;
    } else {
        Index = Entry->DueTick % Table->BucketCount;
    }
    InsertTailList(Table->Bucket + Index, &(Entry->Link));
    Table->TimerCount++;
    ASSERT(Table->TimerCount > 0);    
}
     
__inline
VOID
TtStopTimer(
    IN OUT PTIMER_TABLE Table,
    IN OUT PTIMER_ENTRY Entry
    )
/*++

Routine Description:

   Stops a timer.  The timer should be active.
   
Arguments:

    Table - Supplies the timer table that contains the timer entry.
    
    Entry - Supplies the entry whose timer is to be stopped.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ASSERT(TtIsTimerActive(Entry));
    ASSERT(Table->TimerCount > 0);
    RemoveEntryList(&(Entry->Link));
    TtInitializeTimer(Entry);
    Table->TimerCount--;
}


__inline
ULONG
TtQueryTimerEx(
    IN PTIMER_TABLE Table,
    IN ULONG CurrentTick,
    IN PTIMER_ENTRY Entry
    )
/*++

Routine Description:

   Query the timer for the remaining number of ticks before it fires.
   
Arguments:

    Table - Supplies the timer table that contains the timer entry.

    CurrentTick - Supplies the current tick count.
    
    Entry - Supplies the entry whose timer is to be queried.

Return Value:

    Returns number of ticks remaining.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ULONG TicksRemaining;

    UNREFERENCED_PARAMETER(Table);

    ASSERT(TtIsTimerActive(Entry));
    ASSERT(Table->TimerCount > 0);

    //
    // The following arithmetic correctly handles wraps of CurrentTick.
    //
    TicksRemaining = ((ULONG) (Entry->DueTick - CurrentTick));
    if (TicksRemaining > (MAXULONG / 2)) {
        TicksRemaining = 0;
    }
    return TicksRemaining;
}

__inline
VOID
MoveList(
    OUT PLIST_ENTRY New,
    IN OUT PLIST_ENTRY Old
    )
{
    if (IsListEmpty(Old)) {
        InitializeListHead(New);
    } else {
        New->Flink = Old->Flink;
        New->Blink = Old->Blink;
        New->Flink->Blink = New;
        New->Blink->Flink = New;
        InitializeListHead(Old);
    }
}

__inline
VOID 
ConcatenateList(
    IN OUT PLIST_ENTRY First,
    IN OUT PLIST_ENTRY Second
    )
{
    if (!IsListEmpty(Second)) {
        First->Blink->Flink = Second->Flink;
        Second->Flink->Blink = First->Blink;
        First->Blink = Second->Blink;
        Second->Blink->Flink = First;
        InitializeListHead(Second);
    }
}


__inline
ULONG
TtFireTimerEx(
    IN OUT PTIMER_TABLE Table,
    IN ULONG CurrentTick,
    OUT PLIST_ENTRY FiredList
    )
/*++

Routine Description:

    This function normally gets called every timer tick, so CurrentTick is 
    LastFiredTick + 1. Unless it is getting invoked after a Sleep/Hibernate, in 
    which case, there may be a big jump.
    
Arguments:

    Table - Supplies a timer table.

    CurrentTick - Supplies the current tick count.
    
    FiredList - Returns a list of entries whose timers have fired.
    
Return Value:

    Number of entries in the FiredList.

Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    ULONG Index, NextIndex, EndIndex, TotalCount = 0, Count;
    PLIST_ENTRY Bucket, This, Next, CurrentList;
    LIST_ENTRY FiredBucket;
    PTIMER_ENTRY Entry;

    InitializeListHead(FiredList);
    
    //
    // Protects against multiple invocations in the same tick.
    //
    if (CurrentTick <= Table->LastFiredTick) {
        return 0;
    }
    
    NextIndex = (Table->LastFiredTick + 1) % Table->BucketCount;
    if ((CurrentTick - Table->LastFiredTick) < Table->BucketCount) {
        EndIndex = CurrentTick % Table->BucketCount;
    } else {
        //
        // Fire all timers.
        //
        EndIndex = Table->LastFiredTick % Table->BucketCount;
    }

    Table->LastFiredTick = CurrentTick;
    CurrentList = &FiredBucket;
    
    do {
        Index = NextIndex;
        NextIndex = (NextIndex + 1) % Table->BucketCount;
        
        //
        // Figure out which bucket we'll be firing from, and copy its list 
        // over. 
        //
        Bucket = Table->Bucket + Index;
        MoveList(CurrentList, Bucket);
        Count = 0;
        //
        // Inspect each entry, and in the rare case that its timer hasn't 
        // fired, put it back in the bucket.
        //
        for (This = CurrentList->Flink; This != CurrentList; This = Next) {
            
            Next = This->Flink;        
            Entry = CONTAINING_RECORD(This, TIMER_ENTRY, Link);

            if (Entry->DueTick > Table->LastFiredTick) {
                //
                // We did hash this entry properly.  Right?
                //
                ASSERT((Entry->DueTick % Table->BucketCount) == Index);
                RemoveEntryList(This);
                InsertTailList(Bucket, This);
            } else {
                Count++;
            }
        }

        ASSERT(Table->TimerCount >= Count);
        Table->TimerCount -= Count;

        ConcatenateList(FiredList, CurrentList);
        TotalCount += Count;        
    } while (Index != EndIndex);
   
    return TotalCount;
} 

//
// TODO: Ip specific routines should be renamed Ipp*
//
#define TtStartTimer(Table, Entry, Ticks) \
    TtStartTimerEx((Table), (Entry), IppTickCount, (Ticks))
    
#define TtQueryTimer(Table, Entry) \
    TtQueryTimerEx((Table), IppTickCount, (Entry))
    
#define TtFireTimer(Table, FiredList) \
    TtFireTimerEx(Table, IppTickCount, FiredList)
    
__inline
ULONG
TtTriggerFastTimers(
    IN OUT PTIMER_TABLE Table,
    OUT PLIST_ENTRY FiredList
    )
/*++

Routine Description:

    This function is called to trigger the fast timers.  Fast timers are ones
    that need to be triggered as soon as possible without waiting for the next
    timer tick (TtFireTimer).  This function can be called any time fast timers 
    are present and does not have to be called periodically.  It does not
    update the timer table's notion of current tick.
    
Arguments:

    Table - Supplies a timer table.
    
    FiredList - Returns a list of entries whose timers have fired.
    
Return Value:

    Number of entries in the FiredList.

Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    ULONG Count = 0;
    PLIST_ENTRY Bucket, This;
    ASSERT(Table->FastTimersEnabled);
    
    //
    // Copy the fast timer bucket over to the output list. 
    //
    Bucket = Table->Bucket + Table->BucketCount;
    MoveList(FiredList, Bucket);

    //
    // Determine the number of timers fired.
    //
    for (This = FiredList->Flink; This != FiredList; This = This->Flink) {
        Count++;
    }

    ASSERT(Table->TimerCount >= Count);
    Table->TimerCount -= Count;
   
    return Count;
}

#endif // _TIMER_
