/*++

Copyright (c) 2001-2002  Microsoft Corporation

Module Name:

    generic.h

Abstract:

    This module contains definitions for generic data structures.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#ifndef _GENERIC_
#define _GENERIC_

#ifndef USER_MODE
//
// Include NDIS for access to the fixed-size block allocation API.
//
#include "ndis.h"
#endif

NETIO_INLINE
VOID
UninitializeListHead(
    IN PLIST_ENTRY Head
    )
{
    UNREFERENCED_PARAMETER(Head);
    ASSERT(IsListEmpty(Head));
}

typedef struct _BLOCK_TYPE {
    NDIS_HANDLE Pool;
    FACTORY Factory;
} BLOCK_TYPE, *PBLOCK_TYPE;

NTSTATUS
IppInitializeBlockType(
    IN OUT PBLOCK_TYPE Set,
    IN USHORT BlockSize,
    IN POOL_TAG PoolTag
    );

VOID
IppUninitializeBlockType(
    IN OUT PBLOCK_TYPE Set
    );

typedef struct _LOCKED_LIST {
    RTL_MRSW_LOCK Lock;
    LIST_ENTRY Set;
    ULONG NumEntries;
} LOCKED_LIST, *PLOCKED_LIST;


NETIO_INLINE
VOID
IppInitializeLockedList(
    IN OUT PLOCKED_LIST Set
    )
{
    InitializeListHead(&Set->Set);
    RtlInitializeMrswLock(&Set->Lock);
    Set->NumEntries = 0;
}

NETIO_INLINE
VOID
IppUninitializeLockedList(
    IN OUT PLOCKED_LIST Set
    )
{
    ASSERT(Set->NumEntries == 0);
    RtlUninitializeMrswLock(&Set->Lock);
    UninitializeListHead(&Set->Set);
}

typedef struct _SPIN_LOCKED_LIST {
    KSPIN_LOCK Lock;
    LIST_ENTRY Set;
    ULONG NumEntries;
} SPIN_LOCKED_LIST, *PSPIN_LOCKED_LIST;

NETIO_INLINE
NTSTATUS
IppInitializeSpinLockedSet(
    IN PSPIN_LOCKED_LIST Set
    )
{
    InitializeListHead(&Set->Set);
    KeInitializeSpinLock(&Set->Lock);
    Set->NumEntries = 0;

    return STATUS_SUCCESS;
}

NETIO_INLINE
VOID
IppUninitializeSpinLockedSet(
    IN PSPIN_LOCKED_LIST Set
    )
{
    ASSERT(Set->NumEntries == 0);
    KeUninitializeSpinLock(&Set->Lock);
    UninitializeListHead(&Set->Set);
}

//
// Extra defines for IP's usage of prefix trees.
//

typedef struct _LOCKED_PREFIX_TREE {
    HANDLE Set;
    RTL_MRSW_LOCK Lock;
} LOCKED_PREFIX_TREE, *PLOCKED_PREFIX_TREE;

NTSTATUS
IppInitializeLockedPrefixTree(
    IN OUT PLOCKED_PREFIX_TREE Set,
    IN ULONG KeySize
    );

VOID
IppUninitializeLockedPrefixTree(
    IN OUT PLOCKED_PREFIX_TREE Set
    );

//
// Extra defines for IP's usage of hash tables.
//

typedef LIST_ENTRY IP_HT_ENTRY, *PIP_HT_ENTRY;

typedef union _IP_ATOMIC_COUNTER {
    struct {
        ULONG Index : 1;
        ULONG EntryCount : 31;
    };
    LONG Value;
} IP_ATOMIC_COUNTER, *PIP_ATOMIC_COUNTER;

typedef struct _IP_ATOMIC_INSTANCE {
    union {
        volatile ULONG ExitCount : 31;
        LONG Value;
    };
} IP_ATOMIC_INSTANCE, *PIP_ATOMIC_INSTANCE;

typedef struct _IP_INSTANCE_OBJECT {
    IP_ATOMIC_INSTANCE;
    union {
        IP_HT_ENTRY FirstEntry;
        HANDLE Set;
        PVOID Pointer;
    };
} IP_INSTANCE_OBJECT, *PIP_INSTANCE_OBJECT;

typedef struct _IP_ATOMIC_SET {
    IP_ATOMIC_COUNTER Counter;
    IP_INSTANCE_OBJECT Instance[2];
    KSPIN_LOCK SpinLock;
    ULONG FinalEntryCount;
} IP_ATOMIC_SET, *PIP_ATOMIC_SET;

NETIO_INLINE
PIP_INSTANCE_OBJECT
IppAcquireAtomicReadLock(
    IN PIP_ATOMIC_SET Set,
    OUT ULONG *InstanceIndex
    )
{
    IP_ATOMIC_COUNTER Counter;

    //
    // Grab a reference on the current instance so it can't be freed.
    //
    // Increment the 31-bit entry-count through the 32-bit value that
    // shares its address in the counter structure.
    //
    // N.B. In order to increment EntryCount by 1, we increment Value
    // by 2 since the least-significant bit is occupied by Index,
    // (the current index into Instance) which we don't want to modify.
    //
    Counter.Value = InterlockedExchangeAdd(&Set->Counter.Value, 2);
    *InstanceIndex = Counter.Index;
    return &Set->Instance[Counter.Index];
}

NETIO_INLINE
VOID
IppReleaseAtomicReadLock(
    IN PIP_INSTANCE_OBJECT Instance
    )
{
    //
    // "Free" the reference on the instance now that we're done with it.
    //
    InterlockedIncrement(&Instance->Value);
}

NETIO_INLINE
PIP_INSTANCE_OBJECT
IppLockAtomicSetInstanceForUpdate(
    IN PIP_ATOMIC_SET AtomicSet,
    OUT KIRQL *OldIrql
    ) 
{
    KeAcquireSpinLock(&(AtomicSet->SpinLock), OldIrql);
    return &(AtomicSet->Instance[AtomicSet->Counter.Index]);
}

PIP_INSTANCE_OBJECT
IppLockAtomicSetForUpdate(
    IN PIP_ATOMIC_SET AtomicSet,
    OUT ULONG *ReturnInstanceIndex,
    OUT KIRQL *OldIrql
    );

VOID
IppCommitAtomicSetChanges(
    IN PIP_ATOMIC_SET AtomicSet,
    IN ULONG NewInstanceIndex,
    IN PIP_INSTANCE_OBJECT NewInstance,
    IN KIRQL *OldIrql OPTIONAL
    );

NETIO_INLINE
VOID
IppUnlockAtomicSetForUpdate(
    IN PIP_ATOMIC_SET AtomicSet,
    IN KIRQL OldIrql
    )
{
    KeReleaseSpinLock(&AtomicSet->SpinLock, OldIrql);
}

NTSTATUS
IppInitializeAtomicPrefixTree(
    IN PIP_ATOMIC_SET Tree,
    IN ULONG KeySize
    );

VOID
IppUninitializeAtomicPrefixTree(
    IN PIP_ATOMIC_SET Tree
    );

typedef struct _IP_HT_TABLE {
    LONG NumEntries;
    ULONG NumBuckets;
    PIP_HT_ENTRY Bucket;
} IP_HT_TABLE, *PIP_HT_TABLE;

NTSTATUS
IppInitializeHashTable(
    OUT PIP_HT_TABLE Table
    );

VOID
IppUninitializeHashTable(
    IN OUT PIP_HT_TABLE Table
    );

typedef struct _LOCKED_HASH_TABLE {
    IP_HT_TABLE HashTable;
    RTL_MRSW_LOCK Lock;
} LOCKED_HASH_TABLE, *PLOCKED_HASH_TABLE;

NTSTATUS
IppInitializeLockedHashTable(
    IN OUT PLOCKED_HASH_TABLE Set
    );

VOID
IppUninitializeLockedHashTable(
    IN OUT PLOCKED_HASH_TABLE Set
    );

PVOID
IppAllocateTransactionContext(
    IN SIZE_T Size
    );

VOID
IppFreeTransactionContext(
    IN PVOID Context
    );

//
// Extra defines for IP's usage of lists.
//

typedef struct _IP_GENERIC_LIST {
    PVOID Head;
    PVOID *NextPtr;
} IP_GENERIC_LIST, *PIP_GENERIC_LIST;

NETIO_INLINE
VOID
IppInitializeGenericList(
    OUT PIP_GENERIC_LIST List
    )
{
    List->Head = NULL;
    List->NextPtr = &List->Head;
}

NETIO_INLINE
BOOLEAN
IppIsGenericListEmpty(
    IN CONST IP_GENERIC_LIST *List
    )
{
    if (List->Head == NULL) {
        ASSERT(List->NextPtr == &List->Head);
        return TRUE;
    }
    return FALSE;
}
    
NETIO_INLINE
VOID
IppConcatenateGenericLists(
    IN OUT PIP_GENERIC_LIST First,
    IN CONST IP_GENERIC_LIST *Second
    )
{
    //
    // Concatenate Second list only if it is not empty.
    //
    if (!IppIsGenericListEmpty(Second)) {
        *First->NextPtr = Second->Head;
        First->NextPtr = Second->NextPtr;
    }        
}

#define IppAppendToGenericList(List, Element) \
    *(List)->NextPtr = (Element); \
    (List)->NextPtr = &(Element)->Next

NETIO_INLINE
PVOID
IppPopGenericList(
    IN OUT PIP_GENERIC_LIST List
    )
{
    PSINGLE_LIST_ENTRY Curr = List->Head;

    if (!IppIsGenericListEmpty(List)) {
        List->Head = Curr->Next;
        Curr->Next = NULL;
        if (List->NextPtr == &Curr->Next) {
            List->NextPtr = &List->Head;
        }
    }

    return Curr;
}

//
// Defines for an "Adaptive Table".  For a small number of entries,
// this is simply a doubly-linked list, to minimize memory overhead.
// This allows scalability to a large number of tables with few elements.
// For a large number of entries, this is an AVL tree.
//

typedef union _ADAPTIVE_LINK {
    LIST_ENTRY ListLink;
    RTL_BALANCED_LINKS TreeLink;
} ADAPTIVE_LINK, *PADAPTIVE_LINK;

typedef struct _PADDED_AVL_TABLE {
    PRTL_AVL_TABLE Root;
    
    //
    // This field is always zero, and indicates that the union below
    // uses an AVL table rather than a linked-list.
    //
    PVOID Zero; 
} PADDED_AVL_TABLE, *PPADDED_AVL_TABLE;

typedef union _ADAPTIVE_HEAD {
    LIST_ENTRY List;
    PADDED_AVL_TABLE Tree;
} ADAPTIVE_HEAD, *PADAPTIVE_HEAD;

typedef struct _ADAPTIVE_TABLE {
    ADAPTIVE_HEAD Head;
    ULONG NumEntries;
} ADAPTIVE_TABLE, *PADAPTIVE_TABLE;

NETIO_INLINE
VOID
IppInitializeAdaptiveTable(
    IN PADAPTIVE_TABLE Set
    )
{
    InitializeListHead(&Set->Head.List);
    Set->NumEntries = 0;
}

NETIO_INLINE
VOID
IppUninitializeAdaptiveTable(
    IN PADAPTIVE_TABLE Set
    )
{
    ASSERT(Set->NumEntries == 0);

    if (Set->Head.Tree.Zero == NULL) {
        ASSERT(RtlIsGenericTableEmptyAvl(Set->Head.Tree.Root));
        ExFreePool(Set->Head.Tree.Root);
    } else {
        ASSERT(IsListEmpty(&Set->Head.List));
    }
}

NETIO_INLINE
PVOID
IppFindListEntry(
    IN LIST_ENTRY *Head,
    IN CONST VOID *Key,
    IN LONG KeyOffset,
    IN ULONG KeyLength,
    OUT PVOID *NodeOrParent,
    OUT TABLE_SEARCH_RESULT *SearchResult
    )
{
    PLIST_ENTRY ple;

    for (ple = Head->Flink;
         ple != Head;
         ple = ple->Flink) {

        if (!memcmp(((PCHAR)ple) + KeyOffset, Key, KeyLength)) {
            *NodeOrParent = ple;
            *SearchResult = TableFoundNode;
            return ple;
        }
    }

    //
    // TODO: support ordered lists.
    //
    *NodeOrParent = Head;
    *SearchResult = TableInsertAsLeft;

    return NULL;
}

NETIO_INLINE
PVOID
IppFindAdaptiveTableEntry(
    IN ADAPTIVE_TABLE *Set,
    IN CONST VOID *Key,
    IN LONG KeyOffset,
    IN ULONG KeyLength,
    OUT PVOID *NodeOrParent,
    OUT TABLE_SEARCH_RESULT *SearchResult
    )
{
    if (Set->Head.Tree.Zero == NULL) {
        PUCHAR UserData;
        
        //
        // Find in AVL tree.
        //
        ASSERT((KeyOffset - sizeof(RTL_BALANCED_LINKS))
               == PtrToUlong(Set->Head.Tree.Root->AllocateRoutine));
        ASSERT(KeyLength == PtrToUlong(Set->Head.Tree.Root->FreeRoutine));

        //
        // We subtract the key offset from the key before passing it on to the
        // lookup routine.  The reason is that the comparison routine
        // (IppCompareRoutineAvl) expects the buffer passed to it to be at an
        // (negative) offset from the actual key. 
        //
        UserData = RtlLookupElementGenericTableFullAvl(
            Set->Head.Tree.Root, 
            ((PUCHAR)Key) - KeyOffset + sizeof(RTL_BALANCED_LINKS), 
            NodeOrParent, 
            SearchResult);

        //
        // The lookup routine returns a pointer to the user data (immediately
        // following the RTL_BALANCED_LINKS structure.  So, this needs to be
        // converted to the start of the link (which is what the NL expects).
        //
        return (UserData)? (UserData - sizeof(RTL_BALANCED_LINKS)) : NULL;
    } else {
        //
        // Find in unordered doubly-linked list.
        //
        return IppFindListEntry(&Set->Head.List, Key, KeyOffset, KeyLength,
                                NodeOrParent, SearchResult);
    }
}

NETIO_INLINE
PVOID
IppEnumerateListEntry(
    IN CONST LIST_ENTRY *Head,
    IN OUT PVOID *RestartKey
    )
{
    PLIST_ENTRY Curr;

    Curr = (*RestartKey)? *RestartKey : Head->Flink;

    if (Curr == Head) {
        *RestartKey = NULL;
        return NULL;
    } else {
        *RestartKey = Curr->Flink;
        return Curr;
    }
}

typedef struct _ADAPTIVE_TABLE_ENUMERATION_CONTEXT {
    ULONG DeleteCount;
    PVOID RestartKey;
    CHAR Buffer[0];
} ADAPTIVE_TABLE_ENUMERATION_CONTEXT, *PADAPTIVE_TABLE_ENUMERATION_CONTEXT;

NETIO_INLINE
PVOID 
IppEnumerateAdaptiveTableEntry(
    IN CONST ADAPTIVE_TABLE *Set,
    IN OUT PADAPTIVE_TABLE_ENUMERATION_CONTEXT Context
    )
/*++

Routine Description:

    This routine enumerates all the entries in an adaptive table. It is safe to
    use this routine even when inserting/deleting in between calls to
    enumerate.
    
Arguments:

    Set - Supplies the set to enumerate. 

    Context - Context for enumeration.

Return Value:

    Returns the next entry in the set.

--*/ 
{
    if (Set->Head.Tree.Zero == NULL) {
        PCHAR UserData;
        ULONG KeyOffset, KeyLength;

        KeyOffset = PtrToUlong(Set->Head.Tree.Root->AllocateRoutine);
        KeyLength = PtrToUlong(Set->Head.Tree.Root->FreeRoutine);

        // 
        // Enumerate in AVL tree.
        //
        UserData = RtlEnumerateGenericTableLikeADirectory(
            Set->Head.Tree.Root,
            NULL, 
            NULL, 
            TRUE, 
            &Context->RestartKey, 
            &Context->DeleteCount, 
            ((PUCHAR) &Context->Buffer) - KeyOffset);
        
        //
        // Copy over the key that we have just been returned into the buffer so
        // that on the next enumeration we don't start over even if there are
        // additions or deletions in the table. 
        //
        if (UserData != NULL) {
            RtlCopyMemory(&Context->Buffer, 
                          UserData + KeyOffset, 
                          KeyLength);
            return (UserData - sizeof(RTL_BALANCED_LINKS));
        } else {
            return NULL;
        }
    } else {
        //
        // Enumerate in doubly-linked list.
        //
        return IppEnumerateListEntry(&Set->Head.List, &Context->RestartKey);
    }
}

NETIO_INLINE
BOOLEAN
IppIsAdaptiveTableEmpty(
    IN CONST ADAPTIVE_TABLE *Set
    )
{
    return (Set->NumEntries == 0);
}

NETIO_INLINE
VOID
IppDeleteAdaptiveTableEntry(
    IN PADAPTIVE_TABLE Set,
    IN PADAPTIVE_LINK Link
    )
{
    if (Set->Head.Tree.Zero == NULL) {
        //
        // Delete from AVL tree.
        //

        RtlDeleteElementGenericTableBasicAvl(Set->Head.Tree.Root, 
                                             &Link->TreeLink);
    } else {
        //
        // Delete from unordered doubly-linked list.
        //
        RemoveEntryList(&Link->ListLink);
    }

    Set->NumEntries--;
}

RTL_GENERIC_COMPARE_RESULTS
NTAPI
IppCompareRoutineAvl(
    IN PRTL_AVL_TABLE Table,
    CONST VOID *FirstStruct,
    CONST VOID *SecondStruct
    );

//
// The number is fairly arbitrary.  AVL tables entail an overhead of
// 56 + 16n bytes on an x86 machine, but have O(log n) operations.
// A list has an overhead of 8 + 8n bytes on an x86 machine, but has
// O(n) operations.
//
#define ADAPTIVE_TABLE_THRESHOLD 10

NETIO_INLINE
VOID
IppInsertAdaptiveTableEntry(
    IN PADAPTIVE_TABLE Set,
    IN PADAPTIVE_LINK Link,
    IN LONG KeyOffset,
    IN ULONG KeyLength,
    IN PVOID NodeOrParent,
    IN TABLE_SEARCH_RESULT SearchResult
    )
{
    Set->NumEntries++;

    if (Set->Head.Tree.Zero == NULL) {
        //
        // Insert into AVL tree.
        //
        RtlInsertElementGenericTableBasicAvl(Set->Head.Tree.Root,
                                             &Link->TreeLink,
                                             NodeOrParent,
                                             SearchResult);
    } else {
        //
        // Insert into doubly-linked list.
        //
        InsertTailList(NodeOrParent, &Link->ListLink);

        if (Set->NumEntries >= ADAPTIVE_TABLE_THRESHOLD) {
            PRTL_AVL_TABLE Root;

            Root = ExAllocatePoolWithTagPriority(NonPagedPool, 
                                                 sizeof(RTL_AVL_TABLE), 
                                                 NlAvlPoolTag,
                                                 LowPoolPriority);
            if (Root != NULL) {
                PADAPTIVE_LINK pal;
                PVOID NodeOrParent2;
                TABLE_SEARCH_RESULT SearchResult2;
                PVOID Key;
                
                //
                // Since we do our own memory management, we store the
                // key offset and length, rather than allocate/free routines,
                // so they can be used by a generic compare routine. The key
                // offset is the offset from the end of the link structure and
                // not the beginning. The reason is that the base RTL fuctions
                // pass us a pointer to the "user" data after the link
                // structure. 
                //
                RtlInitializeGenericTableAvl(
                    Root,
                    IppCompareRoutineAvl,
                    LongToPtr(KeyOffset - sizeof(RTL_BALANCED_LINKS)),
                    UlongToPtr(KeyLength),
                    NULL);

                while (!IsListEmpty(&Set->Head.List)) {
                    pal = (PADAPTIVE_LINK)Set->Head.List.Flink;
                    Key = ((PCHAR)pal) + sizeof(RTL_BALANCED_LINKS);

                    RemoveEntryList(&pal->ListLink);
    
                    //
                    // We need to pass the link structure (pal) as the lookup
                    // key because that is what the comparison routine
                    // expects. 
                    //
                    RtlLookupElementGenericTableFullAvl(Root, 
                                                        Key, 
                                                        &NodeOrParent2, 
                                                        &SearchResult2);
                    ASSERT(SearchResult2 != TableFoundNode);
                     
                    RtlInsertElementGenericTableBasicAvl(Root,
                                                         &pal->TreeLink,
                                                         NodeOrParent2,
                                                         SearchResult2);
                }

                Set->Head.Tree.Zero = NULL;
                Set->Head.Tree.Root = Root;
            }
        }
    }
}

#endif // _GENERIC_
