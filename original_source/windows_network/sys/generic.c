/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    generic.c

Abstract:

    This module contains routines for manipulating generic data structures.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"

#define IP_GENERIC_HANDLE_BITS 32

NTSTATUS
IppInitializeBlockType(
    IN OUT PBLOCK_TYPE Set,
    IN USHORT BlockSize,
    IN POOL_TAG PoolTag
    )
{
    NTSTATUS Status;
    FACTORY_PARAMS Params;

    Params.Length = sizeof(Params);
    Params.HandleBits = IP_GENERIC_HANDLE_BITS;

    Status = HfCreateFactory(&Params, &Set->Factory);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Set->Pool = FsbCreatePool(BlockSize, 0, PoolTag, NULL);
    if (Set->Pool == NULL) {
        HfDestroyFactory(Set->Factory);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

VOID
IppUninitializeBlockType(
    IN OUT PBLOCK_TYPE Set
    )
{
    NTSTATUS Status;

    Status = HfDestroyFactory(&Set->Factory);
    ASSERT(NT_SUCCESS(Status));
    FsbDestroyPool(Set->Pool);
}

NTSTATUS
IppInitializeLockedPrefixTree(
    IN OUT PLOCKED_PREFIX_TREE Set,
    IN ULONG KeySize 
    )
{
    NTSTATUS Status;

    Status = PtCreateTable(KeySize * RTL_BITS_OF(CHAR), &Set->Set);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlInitializeMrswLock(&Set->Lock);

    return STATUS_SUCCESS;
}

VOID
IppUninitializeLockedPrefixTree(
    IN OUT PLOCKED_PREFIX_TREE Set
    )
{
    NTSTATUS Status;

    RtlUninitializeMrswLock(&Set->Lock);
    Status = PtDestroyTable(&Set->Set);
    ASSERT(NT_SUCCESS(Status));
}

RTL_GENERIC_COMPARE_RESULTS
NTAPI
IppCompareRoutineAvl(
    IN PRTL_AVL_TABLE Table,
    CONST VOID *FirstStruct,
    CONST VOID *SecondStruct
    )
{
    LONG KeyOffset = PtrToLong(Table->AllocateRoutine);
    ULONG KeyLength = PtrToUlong(Table->FreeRoutine);

    LONG Compare = memcmp(((PCHAR)FirstStruct) + KeyOffset,
                          ((PCHAR)SecondStruct) + KeyOffset,
                          KeyLength);
    if (Compare < 0) {
        return GenericLessThan;
    } else if (Compare > 0) {
        return GenericGreaterThan;
    } else {
        return GenericEqual;
    }
}

NTSTATUS
IppInitializeAtomicPrefixTree(
    IN PIP_ATOMIC_SET Tree,
    IN ULONG KeySize
    )
/*++

Routine Description:

    Initializes an atomic prefix tree.

Arguments:

    Tree - Supplies the tree to initialize.

    KeySize - Supplies the key size, in bytes, for entries in the tree.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;

    RtlZeroMemory(Tree, sizeof(IP_ATOMIC_SET));

    Status = PtCreateTable(KeySize * RTL_BITS_OF(CHAR), &Tree->Instance[0].Set);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = PtCreateTable(KeySize * RTL_BITS_OF(CHAR), &Tree->Instance[1].Set);
    if (!NT_SUCCESS(Status)) {
        PtDestroyTable(&Tree->Instance[0].Set);
        return Status;
    }

    KeInitializeSpinLock(&Tree->SpinLock);

    return STATUS_SUCCESS;
}

VOID
IppUninitializeAtomicPrefixTree(
    IN PIP_ATOMIC_SET Tree
    )
/*++

Routine Description:

    Cleans up an atomic prefix tree.

Arguments:

    Tree - Supplies the tree to clean up.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;

    Status = PtDestroyTable(&Tree->Instance[0].Set);
    ASSERT(NT_SUCCESS(Status));

    Status = PtDestroyTable(&Tree->Instance[1].Set);
    ASSERT(NT_SUCCESS(Status));

    KeUninitializeSpinLock(&Tree->SpinLock);
}

PIP_INSTANCE_OBJECT
IppLockAtomicSetForUpdate(
    IN PIP_ATOMIC_SET AtomicSet,
    OUT ULONG *ReturnInstanceIndex,
    OUT KIRQL *OldIrql
    )
/*++

Routine Description:

    This function locks the atomic set and prepares it for updates.
    It can be used before beginning a batch of updates.

Arguments:

    AtomicSet - Supplies a pointer to the atomic set.

    ReturnInstanceIndex - Receives the index of the instance to update.

    OldIrql - Receives the previous IRQL.

Return Value:

    Returns a pointer to the instance to update.

Locks:

    Locks the atomic set and returns with the lock still held; caller
    is responsible for calling either IppCommitAtomicSetChanges or
    IppAbortAtomicSetChanges to release the lock.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_INSTANCE_OBJECT NewInstance;
    IP_ATOMIC_COUNTER Counter;

    KeAcquireSpinLock(&AtomicSet->SpinLock, OldIrql);

    Counter.Value = AtomicSet->Counter.Value;
    NewInstance = &AtomicSet->Instance[1 - Counter.Index];

    //
    // See whether all threads have drained from the new instance.
    // This should only happen if we've made two updates during the
    // time another thread has been reading the set.  This is
    // extremely unlikely, so we'll just fail as if we're low on
    // resources.  An alternative would be to require that readers
    // run at dispatch level, and sit and spin here, but we don't
    // currently require that since it would be more expensive in
    // the fast path.  Transaction support will solve this problem 
    // for clients that know they want to make multiple updates.
    //
    if (NewInstance->ExitCount != AtomicSet->FinalEntryCount) {
        KeReleaseSpinLock(&AtomicSet->SpinLock, *OldIrql);
        return NULL;
    }

    *ReturnInstanceIndex = 1 - Counter.Index;
    return NewInstance;
}

VOID
IppCommitAtomicSetChanges(
    IN PIP_ATOMIC_SET AtomicSet,
    IN ULONG NewInstanceIndex,
    IN PIP_INSTANCE_OBJECT NewInstance,
    IN KIRQL *OldIrql OPTIONAL
    )
/*++

Routine Description:

    This function commits a set of updates done in a new instance, and 
    unlocks the atomic set.  It is used to end a batch of updates.

Arguments:

    AtomicSet - Supplies a pointer to the atomic set.

    NewInstanceIndex - Supplies the index of the instance to commit.

    NewInstance - Supplies a pointer to the instance to commit.

    OldIrql - Optionally supplies the original IRQL if the set should
              be unlocked.

Locks:

    Assumes caller holds a lock on the atomic set.
    Unlocks the atomic set of OldIrql is non-null.

Caller IRQL:

    Must be called at DISPATCH level, since a lock is held.

--*/
{
    IP_ATOMIC_COUNTER Counter;

    //
    // Clear the exit-count for the new location,
    // and change the global active counter to start directing
    // new references to the copy that we've just created.
    // In the process, the number of threads processing the old list
    // is captured in a local counter.
    //
    NewInstance->ExitCount = 0;
    Counter.Value = InterlockedExchange(&AtomicSet->Counter.Value,
                                        NewInstanceIndex);

    //
    // Store final entry count of old instance.
    //
    AtomicSet->FinalEntryCount = Counter.EntryCount;

    if (OldIrql != NULL) {
        KeReleaseSpinLock(&AtomicSet->SpinLock, *OldIrql);
    }
}

#define INITIAL_BUCKETS 128

NTSTATUS
IppInitializeHashTable(
    OUT PIP_HT_TABLE Table
    )
/*++

Routine Description:

    Initializes a hash table.

Arguments:

    Set - Supplies the hash table to initialize.

Return Value:

    STATUS_SUCCESS
    STATUS_INSUFFICIENT_RESOURCES

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG BucketIndex;
    
    Table->NumEntries = 0;
    Table->NumBuckets = INITIAL_BUCKETS;
    Table->Bucket = NbAllocMem(INITIAL_BUCKETS * sizeof(*Table->Bucket),
                               IpDestinationCachePoolTag);
    if (Table->Bucket == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Table->Bucket, INITIAL_BUCKETS * sizeof(*Table->Bucket));

    for (BucketIndex = 0; BucketIndex < INITIAL_BUCKETS; BucketIndex++) {
        InitializeListHead(&Table->Bucket[BucketIndex]);
    }

    return STATUS_SUCCESS;
}

VOID
IppUninitializeHashTable(
    IN OUT PIP_HT_TABLE Table
    )
/*++

Routine Description:

    Cleans up a hash table.

Arguments:

    Set - Supplies a pointer to the hash table to clean up.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ASSERT(Table->NumEntries == 0);

    NbFreeMem(Table->Bucket);
}

NTSTATUS
IppInitializeLockedHashTable(
    IN OUT PLOCKED_HASH_TABLE Set
    )
/*++

Routine Description:

    Initializes a locked hash table.  This is a hash table as above,
    with a reader-writer lock.

Arguments:

    Set - Supplies the locked hash table to initialize.

Return Value:

    STATUS_SUCCESS
    STATUS_INSUFFICIENT_RESOURCES

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;

    Status = IppInitializeHashTable(&Set->HashTable);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlInitializeMrswLock(&Set->Lock);

    return STATUS_SUCCESS;
}

VOID
IppUninitializeLockedHashTable(
    IN OUT PLOCKED_HASH_TABLE Set
    )
/*++

Routine Description:

    Cleans up a locked hash table.

Arguments:

    Set - Supplies a pointer to the locked hash table to clean up.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    RtlUninitializeMrswLock(&Set->Lock);
    
    IppUninitializeHashTable(&Set->HashTable);
}

PVOID
IppAllocateTransactionContext(
    IN SIZE_T Size
    )
/*++

Routine Description:

    This function will allocate a transaction context of the requested size.

Arguments:

    Size - Size we need to allocate.

Return Value:

    Pointer to the allocated memory. 
    
--*/
{
    return  
        ExAllocatePoolWithTag(NonPagedPool, Size, IpTransactionContextPoolTag);
}

VOID
IppFreeTransactionContext(
    IN PVOID Context
    )
/*++

Routine Description:

    This function will free the transaction context.

Arguments:

    Context - Pointer to context.

Return Value:

    None.
    
--*/
{
    ExFreePool(Context);
}
