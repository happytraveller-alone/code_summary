/*++

Copyright (c) Microsoft Corporation

Module Name:

    neighbor_offload.c

Abstract:

    This module implements the protocol-independent functions for
    offloading neighbors.

Author:

    Dave Thaler (dthaler) 21-August-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"

//
// NEIGHBOR_OFFLOAD_STATE
//
typedef struct _NEIGHBOR_OFFLOAD_STATE 
{
    NEIGHBOR_OFFLOAD_STATE_CONST ConstState;
    NEIGHBOR_OFFLOAD_STATE_CACHED CachedState;
    NEIGHBOR_OFFLOAD_STATE_DELEGATED DelegatedState;
} NEIGHBOR_OFFLOAD_STATE, *PNEIGHBOR_OFFLOAD_STATE;

#define NEIGHBOR_BLOCK_SIZE (sizeof(NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST) + \
                             sizeof(NEIGHBOR_OFFLOAD_STATE))

VOID
IppInitiatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

VOID
IppTerminatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

VOID
IppUpdatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

VOID
IppInvalidatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

VOID
IppChangePathOffloadMappingComplete(
    IN PIP_PATH Path,
    IN PIP_NEIGHBOR Neighbor, 
    IN NTSTATUS Status
    );

VOID
NTAPI
IpFlcInitiateNeighborOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

VOID
NTAPI
IpFlcTerminateNeighborOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

//
// State:                 Happens when:
//   NotOffloaded       <-  (OffloadCount == 0) && (Handle == NULL)
//   OffloadInProgress  <-  (OffloadCount >  0) && (Handle == NULL)
//   Offloaded          <-  (OffloadCount >  0) && (Handle != NULL)
//   TerminateInProgress<-  (OffloadCount == 0) && (Handle != NULL)
//

__inline
VOID
IppCleanupNeighborOffloadState(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Cleanup offload state.  We delete any offload blocks stored here
    since we know we're done with them.

Arguments:
    
    Neighbor - Supplies a pointer to a neighbor entry to clean up.

--*/
{
    PSLIST_ENTRY Entry;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;

    ASSERT(Neighbor->OffloadHandle.MiniportOffloadContext == NULL);

    for (;;) {
        Entry = InterlockedPopEntrySList(&Neighbor->OffloadedBlocks);
        if (Entry == NULL) {
            return;
        }
    
        Block = CONTAINING_RECORD(Entry,
                                  NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                  NdisReserved[0]);
        ExFreePool(Block);
    }
}

VOID
IppProcessPendingNeighborOffloadRequests(
    IN PIP_NEIGHBOR Neighbor,
    IN NTSTATUS Status
    )
/*++

Routine Description:

    Process the next pended offload request for a given neighbor.
    If it fails, keep trying other ones until they've all failed
    or until one returns pending.
    This is done in the Offloaded and UpdateInProgress states, 
    as well as in the OffloadInProgress state on failure.

    Called when processing the InitiateOffload and InitiateOffloadComplete
    events.

Arguments:

    Neighbor - Supplies the neighbor on which to operate.

    Status - If success, start the next offload.  If failure,
        fail all queued requests.

Locks:

    Assumes the caller holds its own reference on OffloadCount.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList, Block;
    PSLIST_ENTRY Entry;
    PIP_INTERFACE Interface;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;

    for (;;) {
        //
        // Pull off the next pending request, if any.
        //
        Entry = InterlockedPopEntrySList(&Neighbor->OffloadRequestQueue);
        if (Entry == NULL) {
            return;
        }

        ASSERT((Neighbor->Offload.State == Offloaded) ||
               (Neighbor->Offload.State == OffloadInProgress) ||
               (Neighbor->Offload.State == UpdateInProgress));
    
        BlockList = CONTAINING_RECORD(Entry,
                                      NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                      NdisReserved[0]);

        if (NT_SUCCESS(Status)) {
            //
            // Call down to the next lower layer's InitiateOffload routine.
            //
            IP_OFFLOAD_LOG_EVENT(
                IpoeDowncallForPendedRequest, Neighbor, NULL, Neighbor, NULL);
            Interface = Neighbor->Interface;
            Interface->FlModule->Npi.Dispatch->InitiateOffload(
                        Interface->FlContext,
                        BlockList);

            return;
        }

        //
        // Remove our own block from the block list.
        //
        ASSERT(BlockList->Header.Type == NeighborOffloadState);
        Block = BlockList;
        BlockList = Block->DependentBlockList;
        ExFreePool(Block);

        IP_OFFLOAD_LOG_EVENT(
            IpoePendedRequestFailure, Neighbor, NULL, Neighbor, Block);

        //
        // Copy the status to all blocks.
        //
        IppSetDependentBlockStatus(BlockList, Status);

        //
        // Issue an upcall to the next higher layer and then continue 
        // processing pending requests.
        //
        IppInitiatePathOffloadComplete(BlockList);

        //
        // Decrement the OffloadCount.
        // If it hits 0, transition back to the NotOffloaded state.
        //
        do {
            New.Value = Snapshot.Value = Neighbor->Offload.Value;

            New.Value -= IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);

            if (New.Count == 0) {
                ASSERT(Snapshot.State == OffloadInProgress);
                IppCleanupNeighborOffloadState(Neighbor);
                New.State = NotOffloaded;
            }
    
            Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);
    
            //
            // Repeat until the new value is successfully updated.
            //
        } while (Old.Value != Snapshot.Value);
    }
}

BOOLEAN
IppAllocateSpareNeighborBlock(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    We need to ensure that an offload block always exists for our own Update
    and Invalidate calls.  Since those calls must not fail, we need to ensure
    this up front.

Arguments:

    Neighbor - Supplies a pointer to the neighbor to create a spare block for.

Return Value:

    Returns TRUE on success, FALSE on failure.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST SpareBlock;

    SpareBlock = ExAllocatePoolWithTag(NonPagedPool,
                                       NEIGHBOR_BLOCK_SIZE,
                                       IpOffloadPoolTag);
    if (SpareBlock == NULL) {
        return FALSE;
    }
    RtlZeroMemory(SpareBlock, NEIGHBOR_BLOCK_SIZE);
    SpareBlock->Header.Type = NeighborOffloadState;
    SpareBlock->Header.Size = NEIGHBOR_BLOCK_SIZE;

    InterlockedPushEntrySList(&Neighbor->OffloadedBlocks, 
                              (PSLIST_ENTRY) &SpareBlock->NdisReserved[0]);

    return TRUE;
}

VOID
IppInitiateNeighborOffloadHelper(
    IN PIP_NEIGHBOR Neighbor,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlock OPTIONAL,
    IN PVOID Context OPTIONAL,
    IN OUT PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST *CompleteBlockList,
    IN OUT PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST *DowncallBlockList
    )
/*++

Routine Description:

    Called to initiate an offload.  A neighbor block is added to the
    request, which is then passed down to the next layer, or pended
    if needed.

Arguments:

    Neighbor - Supplies a neighbor to be offloaded.

    UpperLayerBlock - Supplies an upper-layer block to offload.

    Context - If UpperLayerBlock is NULL, supplies a Context to pass to
        IppChangePathOffloadMappingComplete on completion.  This
        is used when the path-to-neighbor mapping changes and we
        need to offload a neighbor without offloading the path.

    CompleteBlockList - Supplies a block list to be completed immediately,
        to which we may add entries.

    DowncallBlockList - Supplies a block list to send down to the lower layer,
        to which we may add entries.

Return Value:

    The completion function will be called with the block status values
    set to one of:

    STATUS_NOT_SUPPORTED - Connection is not offloadable.
    STATUS_INSUFFICIENT_RESOURCES - Memory allocation failed.
    STATUS_PENDING - Call will complete asynchronously.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PNEIGHBOR_OFFLOAD_STATE State;
    KIRQL OldIrql;
    PIP_INTERFACE Interface = Neighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressLength = Protocol->Characteristics->AddressBytes;
    BOOLEAN PathAlreadyOffloaded;

    //
    // Allocate a block for the neighbor information.  We allocate one
    // big enough to hold the full state, just in case we need it later.
    // We don't know in general here, since if an offload is in progress,
    // we don't know if it will complete with success or failure.  To
    // avoid failures in the completion routine, we pre-allocate the
    // space here.
    //
    // Also, even if there's a block in the OffloadedBlocks list, we
    // still want to allocate another block, since each upper-layer entry
    // can be uploaded in parallel so we need one for each.
    //
    Block = ExAllocatePoolWithTag(NonPagedPool,
                                  NEIGHBOR_BLOCK_SIZE,
                                  IpOffloadPoolTag);

    if (Block == NULL) {
        if (UpperLayerBlock == NULL) {
            IppChangePathOffloadMappingComplete(
                Context, Neighbor, STATUS_NO_MEMORY);
        } else {
            IppSetDependentBlockStatus(UpperLayerBlock, STATUS_NO_MEMORY);
            UpperLayerBlock->NextBlock = (*CompleteBlockList);
            (*CompleteBlockList) = UpperLayerBlock;
        }

        return;
    }

    RtlZeroMemory(Block, NEIGHBOR_BLOCK_SIZE);    

    if (UpperLayerBlock == NULL) {
        PathAlreadyOffloaded = FALSE;
    } else {
        PathAlreadyOffloaded = 
            (UpperLayerBlock->OffloadHandle == NULL) ||
            (UpperLayerBlock->OffloadHandle->MiniportOffloadContext != NULL);
    }
    
    //
    // Add the neighbor's state to the request's block list.
    //
    Block->DependentBlockList = UpperLayerBlock;
    Block->NextBlock = NULL;
    Block->Header.Type = NeighborOffloadState;
    Block->ProtocolReserved[1] = Context;
    Block->NetBufferListChain = NULL;

    if (PathAlreadyOffloaded) {
        //
        // Path is already offloaded, so we just prepend the neighbor
        // state and do nothing else.  We set the offload handle to NULL
        // so that on completion we know we can free the block.
        //
        Block->Header.Size = sizeof(*Block);
        Block->OffloadHandle = NULL;
        Block->ProtocolReserved[0] = Neighbor;

        Block->NextBlock = (*DowncallBlockList);
        (*DowncallBlockList) = Block;

        IP_OFFLOAD_LOG_EVENT(
            IpoeInsertPlaceHolder, Neighbor, NULL, Neighbor, Block);
        return;
    }

    Block->Header.Size = NEIGHBOR_BLOCK_SIZE;
    State = (PNEIGHBOR_OFFLOAD_STATE)(Block + 1);

    //
    // Account for alignment in the offload call
    //
    State->ConstState.Header.Length =
          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, CachedState) -
          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, ConstState);

    State->CachedState.Header.Length =
          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, DelegatedState) -
          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, CachedState);        
    
    State->DelegatedState.Header.Length = sizeof(State->DelegatedState);    

    //
    // Offload a neighbor only if it's in a reachable or permanent state.
    //
    RtlAcquireReadLock(&(Interface->NeighborSetLock), &OldIrql);
    if ((Neighbor->State == NlnsPermanent) || 
        (Neighbor->State == NlnsReachable)) {
        //
        // Treat a permanent neighbor as currently reachable.  For other 
        // addresses, compute the time since it was last known to be reachable.
        //
        State->CachedState.HostReachabilityDelta = 
            (Neighbor->State == NlnsPermanent) ? 0 :
            IppTicksToMilliseconds(IppTickCount - Neighbor->LastReachable);
        State->DelegatedState.NicReachabilityDelta = 
            State->CachedState.HostReachabilityDelta;

        //
        // Copy DL address.
        //

        RtlCopyMemory(State->CachedState.DlDestinationAddress,
                      IP_NEIGHBOR_DL_ADDRESS(Neighbor, AddressLength),
                      Interface->FlCharacteristics->DlAddressLength);
        RtlCopyMemory(State->ConstState.DlSourceAddress,
                      Interface->FlCharacteristics->DlAddress,
                      Interface->FlCharacteristics->DlAddressLength);
    } else {
        RtlReleaseReadLock(&(Interface->NeighborSetLock), OldIrql);
        
        if (UpperLayerBlock == NULL) {
            IppChangePathOffloadMappingComplete(Context, 
                                                Neighbor,
                                                STATUS_NO_MEMORY);
        } else {
            IppSetDependentBlockStatus(
                UpperLayerBlock, STATUS_HOST_UNREACHABLE);
            UpperLayerBlock->NextBlock = (*CompleteBlockList);
            (*CompleteBlockList) = UpperLayerBlock;
        }

        IP_OFFLOAD_LOG_EVENT(
            IpoeInvalidNeighborState, Neighbor, NULL, Neighbor, Block);

        return;        
    }
    RtlReleaseReadLock(&(Interface->NeighborSetLock), OldIrql);

    Block->OffloadHandle = &Neighbor->OffloadHandle;

    //
    // Atomically do the following:
    //
    // If we're in the NotOffloaded state, 
    //     Transition to the OffloadInProgress state.  
    // Take a reference in either case.
    //
    do {
        New.Value = Snapshot.Value = Neighbor->Offload.Value;

        //
        // If we're offloading a new path, then bump the offload count.
        //
        ASSERT(!PathAlreadyOffloaded);
        New.Value += IP_OFFLOAD_REFERENCE;
        ASSERT(!New.Overflow);

        if (Snapshot.State == NotOffloaded) {
            New.State = OffloadInProgress;
            New.Dirty = FALSE;
        }

        Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                               New.Value,
                                               Snapshot.Value);

        //
        // Repeat until the new value is successfully updated.
        //
    } while (Old.Value != Snapshot.Value);

    //
    // At this point, we know we'll never get to the TerminateInProgress
    // state before this request completes, unless we're in that state
    // already.
    //

    switch (Old.State) {
    case NotOffloaded:
        //
        // When first transitioning out of the NotOffloaded state, we
        // need to ensure that a spare offload block exists for our own
        // Update and Invalidate calls.  Since those calls must not fail,
        // we need to ensure this up front.
        //
        if (QueryDepthSList(&Neighbor->OffloadedBlocks) == 0) {
            if (!IppAllocateSpareNeighborBlock(Neighbor)) {
                IppSetDependentBlockStatus(Block, STATUS_NO_MEMORY);
                IpFlcInitiateNeighborOffloadComplete(Block);
                return;
            }
        }

        //
        // Fall through.
        //

    case Offloaded:
    case UpdateInProgress:
        //
        // Call down to the next lower layer's InitiateOffload routine.
        //
        Block->NextBlock = (*DowncallBlockList);
        (*DowncallBlockList) = Block;

        return;

    default:
        ASSERT((Old.State == OffloadInProgress) ||
               (Old.State == TerminateInProgress));
    }

    //
    // Push the request on the pending list.  This may happen before or 
    // after the transition to the OffloadInProgress state (if in 
    // TerminateInProgress), and before or after the subsequent transition 
    // to the Offloaded state and the emptying of the previous queue.  
    // However, emptying this queue can happen in parallel, since they're 
    // all independent and legal in both the Offloaded and UpdateInProgress 
    // states.
    //

    IP_OFFLOAD_LOG_EVENT(
        IpoePendOffloadRequest, Neighbor, NULL, Neighbor, Block);
    InterlockedPushEntrySList(&Neighbor->OffloadRequestQueue, 
                              (PSLIST_ENTRY)&Block->NdisReserved[0]);

    Snapshot.Value = Neighbor->Offload.Value;
    if ((Snapshot.State == Offloaded) ||
        (Snapshot.State == UpdateInProgress)) {
        //
        // Neighbor has already been offloaded.  Start processing the pending
        // list, since we don't know whether it's been done yet or not.
        //
        IppProcessPendingNeighborOffloadRequests(Neighbor, STATUS_SUCCESS);
    }
}

VOID
IppInitiateEmptyNeighborOffload(
    IN PIP_NEIGHBOR Neighbor,
    IN PVOID Context
    )
/*++

Routine Description:

    Called to initiate an offload.  A neighbor block is added to the
    request, which is then passed down to the next layer, or pended
    if needed.

    This routine is used when the path-to-neighbor mapping changes and we
    need to offload a neighbor without offloading the path.

Arguments:

    Neighbor - Supplies a neighbor to be offloaded.

    Context - Supplies a Context to pass to IppChangePathOffloadMappingComplete
        on completion.  

Return Value:

    The completion function will be called with the block status values
    set to one of:

    STATUS_NOT_SUPPORTED - Connection is not offloadable.
    STATUS_INSUFFICIENT_RESOURCES - Memory allocation failed.
    STATUS_PENDING - Call will complete asynchronously.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_INTERFACE Interface = Neighbor->Interface;

    //
    // Initialize two lists.  The DowncallBlockList will be the list we'll
    // pass down to the next lower layer.  The CompleteBlockList will be
    // the list we'll immediately complete back to the upper layer.
    //
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST DowncallBlockList = NULL;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST CompleteBlockList = NULL;

    IppInitiateNeighborOffloadHelper(Neighbor, 
                                     NULL, 
                                     Context,
                                     &CompleteBlockList,
                                     &DowncallBlockList);

    ASSERT(CompleteBlockList == NULL);

    if (DowncallBlockList != NULL) {
        Interface->FlModule->Npi.Dispatch->InitiateOffload(
            Interface->FlContext,
            DowncallBlockList);
    }
}

PIP_NEIGHBOR
IppGetNeighborFromUpperLayerBlock(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlock
    )
{
    PIP_PATH Path;

    if (UpperLayerBlock->OffloadHandle == NULL) {
        Path = IppCast(UpperLayerBlock->ProtocolReserved[1], IP_PATH);
    } else {
        Path = CONTAINING_RECORD(UpperLayerBlock->OffloadHandle,
                                 IP_PATH,
                                 OffloadHandle);
    }

    return Path->OffloadedNeighbor;
}

VOID
IppInitiateNeighborOffload(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlockList
    )
/*++

Routine Description:

    Called to initiate an offload.  A neighbor block is added to the
    request, which is then passed down to the next layer, or pended
    if needed.

Arguments:

    UpperLayerBlockList - Supplies a list of upper-layer blocks to offload.

Return Value:

    The completion function will be called with the block status values
    set to one of:

    STATUS_NOT_SUPPORTED - Connection is not offloadable.
    STATUS_INSUFFICIENT_RESOURCES - Memory allocation failed.
    STATUS_PENDING - Call will complete asynchronously.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
    
--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlock, Block;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST DowncallBlockList;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST CompleteBlockList;
    PIP_NEIGHBOR Neighbor;
    PIP_INTERFACE Interface = NULL;

    //
    // Initialize two lists.  The DowncallBlockList will be the list we'll
    // pass down to the next lower layer.  The CompleteBlockList will be
    // the list we'll immediately complete back to the upper layer.
    //
    DowncallBlockList = CompleteBlockList = NULL;

    while (UpperLayerBlockList != NULL) {
        //
        // Pop the next upper-layer block off the input list.
        //
        UpperLayerBlock = UpperLayerBlockList;
        UpperLayerBlockList = UpperLayerBlockList->NextBlock;
        UpperLayerBlock->NextBlock = NULL;

        Neighbor = IppGetNeighborFromUpperLayerBlock(UpperLayerBlock);

        if ((Interface != NULL) && (Neighbor->Interface != Interface)) {
            //
            // We're starting a new interface.  Send the old downcall list 
            // and start a new one.
            //
            if (DowncallBlockList != NULL) {
                Interface->FlModule->Npi.Dispatch->InitiateOffload(
                    Interface->FlContext,
                    DowncallBlockList);
            }
            DowncallBlockList = NULL;
        }

        Interface = Neighbor->Interface;

        for (Block = DowncallBlockList;
             Block != NULL;
             Block = Block->NextBlock) {
            if ((Block->OffloadHandle != &Neighbor->OffloadHandle) &&
                ((Block->OffloadHandle != NULL) ||
                 (Block->ProtocolReserved[1] != Neighbor))) {
                continue;
            }

            //
            // We've already processed this state.  Allocate a spare block
            // so we can terminate it, and then make the upper-layer block
            // dependent on the existing path block.
            //
            if (!IppAllocateSpareNeighborBlock(Neighbor)) {
                IppSetDependentBlockStatus(UpperLayerBlock, STATUS_NO_MEMORY);

                //
                // Put the upper-layer block on the immediate completion list.
                //
                UpperLayerBlock->NextBlock = CompleteBlockList;
                CompleteBlockList = UpperLayerBlock;
                continue;
            }

            if ((UpperLayerBlock->OffloadHandle == NULL) ||
                (UpperLayerBlock->OffloadHandle->MiniportOffloadContext ==
                 NULL)) {
                IP_OFFLOAD_OBJECT Old, Snapshot, New;

                do {
                    New.Value = Snapshot.Value = Neighbor->Offload.Value;

                    New.Value += IP_OFFLOAD_REFERENCE;
                    ASSERT(!New.Overflow);

                    Old.Value = InterlockedCompareExchange(
                                    &Neighbor->Offload.Value,
                                    New.Value,
                                    Snapshot.Value);
            
                    //
                    // Repeat until the new value is successfully updated.
                    //
                } while (Old.Value != Snapshot.Value);

                IP_OFFLOAD_LOG_EVENT(
                    IpoeAddInitiateReference, Neighbor, 
                    NULL, Neighbor, UpperLayerBlock);
            }

            UpperLayerBlock->NextBlock = Block->DependentBlockList;
            Block->DependentBlockList = UpperLayerBlock;

            goto NextUpperLayerBlock;
        }

        IppInitiateNeighborOffloadHelper(Neighbor, 
                                         UpperLayerBlock, 
                                         NULL,
                                         &CompleteBlockList,
                                         &DowncallBlockList);

    NextUpperLayerBlock:
        ;
    }

    //
    // Now process the two lists.
    //
    if (CompleteBlockList != NULL) {
        IppInitiatePathOffloadComplete(CompleteBlockList);
    }
    if (DowncallBlockList != NULL) {
        Interface->FlModule->Npi.Dispatch->InitiateOffload(
            Interface->FlContext,
            DowncallBlockList);
    }
}

VOID
IppUpdateNeighborOffloadHelper(
    IN PIP_NEIGHBOR Neighbor,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    )
/*++

Routine Description:

    Call down to the next lower layer to start a state update.
    This must complete asynchronously and succeed.

Arguments:

    Neighbor - Supplies a neighbor to update.

    BlockList - Supplies an offload block list to use for the update.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNEIGHBOR_OFFLOAD_STATE_CACHED State;
    ULONG AddressLength;
    PIP_INTERFACE Interface;
    PFL_PROVIDER_CONTEXT FlProvider;
    KIRQL OldIrql;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PIP_PROTOCOL Protocol;

    Interface = Neighbor->Interface;
    Protocol = Interface->Compartment->Protocol;
    AddressLength = Protocol->Characteristics->AddressBytes;
    FlProvider = Interface->FlModule;

    while (BlockList != NULL) {
        Block = BlockList;
        BlockList = Block->NextBlock;
        Block->NextBlock = NULL;

        Block->Header.Type = NeighborOffloadCachedState;
        Block->Header.Size = sizeof(*Block) + sizeof(*State);
        State = (PNEIGHBOR_OFFLOAD_STATE_CACHED)(Block + 1);
        State->Header.Length = sizeof(*State);

        //
        // Treat a permanent neighbor as currently reachable.  For other
        // addresses, compute the time since it was last known to be reachable.
        //
        State->HostReachabilityDelta =
            (Neighbor->State == NlnsPermanent) ? 0 :
            IppTicksToMilliseconds(IppTickCount - 
                                   Neighbor->LastReachable);

        Block->OffloadHandle = &Neighbor->OffloadHandle;
    
        //
        // Copy DL address under lock.
        //
        RtlAcquireReadLock(&(Interface->NeighborSetLock), &OldIrql);
        RtlCopyMemory(State->DlDestinationAddress,
                      IP_NEIGHBOR_DL_ADDRESS(Neighbor, AddressLength),
                      Interface->FlCharacteristics->DlAddressLength);
        RtlReleaseReadLock(&(Interface->NeighborSetLock), OldIrql);
    
        //
        // Call down to the next lower layer to update the entry.
        // This always completes asynchronously.
        //
        FlProvider->Npi.Dispatch->UpdateOffloadState(Interface->FlContext,
                                                     Block);
    }
}

VOID
IppPrepareDelegatedNeighborStateBlock(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block,
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Initialize a block as a delegated state block for a neighbor.

Arguments:

    Block - Supplies a block to prepare.

    Neighbor - Supplies the neighbor to associate.

--*/
{
    PNEIGHBOR_OFFLOAD_STATE_DELEGATED State;

    Block->Header.Type = NeighborOffloadDelegatedState;
    Block->Header.Size = sizeof(*Block) + sizeof(*State);
    State = (PNEIGHBOR_OFFLOAD_STATE_DELEGATED)(Block + 1);
    State->Header.Length = sizeof(*State);

    Block->OffloadHandle = &Neighbor->OffloadHandle;
}

VOID
NTAPI
IpFlcInitiateNeighborOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This routine is called by the FL when an offload request completes.
    We indicate the completion to the next higher layer, and start 
    processing any pending requests.

Arguments:

    OffloadBlockList - Supplies the list of blocks allocated by
        the protocol layers containing state information that was
        passed in by the client when offload was initiated.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_NEIGHBOR Neighbor;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlockList;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    BOOLEAN NeedUpdate;
    PIP_INTERFACE Interface;
    PFL_PROVIDER_CONTEXT FlProvider;
    ULONG AddressLength;
    NTSTATUS Status;
    PVOID Context;

    while (OffloadBlockList != NULL) {
        Block = OffloadBlockList;
        OffloadBlockList = Block->NextBlock;
        Block->NextBlock = NULL;

        //
        // Remove the block we added in InitiateOffload.
        //
        UpperLayerBlockList = Block->DependentBlockList;
        Block->DependentBlockList = NULL;

        ASSERT(Block->Header.Type == NeighborOffloadState);

        if (Block->OffloadHandle == NULL) {
            ASSERT(Block->Header.Size == sizeof(*Block));
            ExFreePool(Block);    
            IppInitiatePathOffloadComplete(UpperLayerBlockList);
            continue;
        }

        Neighbor = CONTAINING_RECORD(Block->OffloadHandle,
                                     IP_NEIGHBOR, 
                                     OffloadHandle);
        Status = Block->Status;
        Context = Block->ProtocolReserved[1];

        IP_OFFLOAD_LOG_EVENT(
            IpoeOffloadComplete, Neighbor, NULL, Neighbor, Block);

        //
        // Atomically do the following:
        //
        // Snapshot the current state.
        // If we were in the OffloadInProgress state and the request succeeded:
        //     If the state is dirty, 
        //         Transition to UpdateInProgress and mark as clean.
        //     Else transition to the Offloaded state.
        // Take a reference on the Offload.Count ourselves.
        //
        do {
            NeedUpdate = FALSE;
            New.Value = Snapshot.Value = Neighbor->Offload.Value;
    
            ASSERT((Snapshot.State != NotOffloaded) &&
                   (Snapshot.State != TerminateInProgress));
    
            if ((Snapshot.State == OffloadInProgress) && NT_SUCCESS(Status)) {
                ASSERT(Neighbor->OffloadHandle.MiniportOffloadContext != NULL);
    
                if (Snapshot.Dirty) {
                    New.State = UpdateInProgress;
                    NeedUpdate = TRUE;
                    New.Dirty = FALSE;
                } else {
                    New.State = Offloaded;
                }
            }
    
            //
            // Take a reference for ourselves.  This ensures we don't go to the
            // TerminateInProgress state until are done processing this event.
            //
            New.Value += IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);
    
            Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);
    
            //
            // Repeat until the new value is successfully updated.
            //
        } while (Old.Value != Snapshot.Value);
    
        if (!NT_SUCCESS(Status) || 
            (Status == NDIS_STATUS_OFFLOAD_PARTIAL_SUCCESS)) {
            LONG Count = 0;
            PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlock;
            
            //
            // Count number of upper layer blocks that failed completely.
            //
            for (UpperLayerBlock = UpperLayerBlockList;
                 UpperLayerBlock != NULL;
                 UpperLayerBlock = UpperLayerBlock->NextBlock) {
                if (!NT_SUCCESS(UpperLayerBlock->Status)) {
                    Count++;
                }
            }

            IP_OFFLOAD_LOG_EVENT(
                IpoeInitiateOffloadFailure, 
                Neighbor, UlongToPtr(Count), Neighbor, Block);                 

            //
            // Decrement the offload count for the requests (we still have
            // our own reference).
            // We do the decrement by subtracting IP_OFFLOAD_REFERENCE.
            // This can not cause a state change since we hold our own
            // reference.
            //
            InterlockedExchangeAdd(&Neighbor->Offload.Value, 
                                   -(Count * IP_OFFLOAD_REFERENCE));
            ASSERT(!Neighbor->Offload.Overflow);
        }
    
        Interface = Neighbor->Interface;
        FlProvider = Interface->FlModule;
        AddressLength = FlProvider->Protocol->Characteristics->AddressBytes;
    
        if (NeedUpdate) {
            IppUpdateNeighborOffloadHelper(Neighbor, Block);
        }

CompleteOffloadRequests:
        //
        // Start the next pended downcall, if any.
        //
        IppProcessPendingNeighborOffloadRequests(Neighbor, Status);
    
        //
        // At this point either all pended downcalls have failed,
        // or else one is pending.
        //
    
        //
        // Atomically do the following:
        //
        // Release our own reference on the Offload.Count.
        // If the count goes to 0:
        //     If the current state is Offloaded, 
        //         transition to TerminateInProgress.
        //     If the current state is OffloadInProgress,
        //         transition to NotOffloaded.
        //     (Otherwise the state is UpdateInProgress and the transition will
        //     happen when the update completes.)
        //
        do {
            New.Value = Snapshot.Value = Neighbor->Offload.Value;
    
            New.Value -= IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);
    
            if (New.Count == 0) {
                if (Snapshot.State == Offloaded) {
                    New.State = TerminateInProgress;
                } else if (Snapshot.State == OffloadInProgress) {
                    IppCleanupNeighborOffloadState(Neighbor);
                    New.State = NotOffloaded;
                }
            }
    
            Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);
    
            //
            // Repeat until the new value is successfully updated.
            //
        } while (Old.Value != Snapshot.Value);
    
        //
        // If we just transitioned to TerminateInProgress, start it.
        //
        if (New.State == TerminateInProgress) {
            //
            // Call down to the next lower layer, reusing the block we removed
            // at the start.
            //
            IppPrepareDelegatedNeighborStateBlock(Block, Neighbor);

            FlProvider->Npi.Dispatch->TerminateOffload(Interface->FlContext,
                                                       Block);
        } else if (New.State == NotOffloaded) {
            //
            // We already cleaned up all the other blocks besides the one
            // we used, so clean it up now.
            //
            ExFreePool(Block);
        } else if (New.State == OffloadInProgress) {
            //
            // New offload request(s) were queued between the time we 
            // called IppProcessPendingNeighborOffloadRequests and dropped
            // our reference. So let's add another reference and
            // fail those newly queued requests. We can safely add a 
            // reference without checking for state transitions because
            // the state is OffloadInProgress so new requests will only
            // be queued without causing any state transitions.
            //
            InterlockedExchangeAdd(
                &Neighbor->Offload.Value, IP_OFFLOAD_REFERENCE);
            ASSERT(Neighbor->Offload.State == OffloadInProgress);            
            goto CompleteOffloadRequests;
        } else if (NeedUpdate) {
            //
            // Block is already in use.
            //
        } else {
            //
            // Save the block we allocated in InitiateOffload.
            //
            IP_OFFLOAD_LOG_EVENT(
                IpoeSaveInitiateBlock, Neighbor, NULL, Neighbor, Block);
            InterlockedPushEntrySList(&Neighbor->OffloadedBlocks, 
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
        }
    
        //
        // Call up to the next layer's completion routine.
        // If the request completed with success, then at this point the
        // higher layer may call TerminateOffload or UpdateOffload.
        // This must be done after we save the block, so that we'll have one
        // if the higher layer calls back down.
        //
        if (UpperLayerBlockList == NULL) {
            if (Context != NULL) {
                IppChangePathOffloadMappingComplete(Context, Neighbor, Status);
            }
        } else {
            IppInitiatePathOffloadComplete(UpperLayerBlockList);
        }
    }
}

VOID
IppTerminateNeighborOffloadHelper(
    IN PIP_NEIGHBOR Neighbor,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlock OPTIONAL,
    IN OUT PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST *DowncallBlockList
    )
/*++

Routine Description:

    Start uploading state using a given neighbor.

Arguments:

    Neighbor - Supplies a pointer to a neighbor to dereference and
        upload if needed.

    UpperLayerBlockList - Supplies an upper-layer block allocated by
        the protocol layers containing state information that was
        passed in by the client when offload was initiated.

    DowncallBlockList - Supplies a block list to send down to the lower layer,
        to which we may add entries.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PSLIST_ENTRY Entry;

    //
    // Atomically do the following:
    //
    // Snapshot the current state.
    // If the state is Offloaded and the count is 1,
    //     Transition to TerminateInProgress.
    // (Transitioning and uploading the entry when the count is 1 rather 
    // than 0 is an optimization for the common case where an 
    // InitiateOffload will not come in momentarily, so we piggyback our 
    // upload with the last upload of the higher layer state.)
    //
    do {
        New.Value = Snapshot.Value = Neighbor->Offload.Value;

        ASSERT((Snapshot.State == Offloaded) ||
               (Snapshot.State == UpdateInProgress));

        if ((Snapshot.State == Offloaded) && (Snapshot.Count == 1) &&
            ((UpperLayerBlock == NULL) || 
             (UpperLayerBlock->OffloadHandle != NULL))) {
            New.State = TerminateInProgress;
        } else {
            Old.Value = Snapshot.Value;
            break;
        }

        Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                               New.Value,
                                               Snapshot.Value);

        //
        // Repeat until the new value is successfully updated.
        //
    } while (Old.Value != Snapshot.Value);

    //
    // Prepend an entry to the request block list so that on completion
    // we know which entry to dereference.
    //
    Entry = InterlockedPopEntrySList(&Neighbor->OffloadedBlocks);
    ASSERT(Entry != NULL);

    Block = CONTAINING_RECORD(Entry,
                              NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                              NdisReserved[0]);
    ASSERT(Block->DependentBlockList == NULL);

    if (UpperLayerBlock == NULL) {
        //
        // Remember to decrement the offload count and release a reference
        // in the completion routine.  The actual value we fill in here 
        // doesn't matter, as long as it's non-NULL.
        //
        Block->ProtocolReserved[1] = UlongToPtr(TRUE);
    } else {
        Block->ProtocolReserved[1] = NULL;
    }

    Block->DependentBlockList = UpperLayerBlock;

    Block->NextBlock = (*DowncallBlockList);
    (*DowncallBlockList) = Block;

    //
    // If we just transitioned into the TerminateInProgress state,
    //     Fill in the offload handle, so that the NIC will actually 
    //     upload this state.
    //
    if (New.State == TerminateInProgress) {
        IppPrepareDelegatedNeighborStateBlock(Block, Neighbor);
    } else {
        Block->OffloadHandle = NULL;
        Block->ProtocolReserved[0] = Neighbor;

        //
        // This is a "placeholder" block.
        //
        Block->Header.Type = NeighborOffloadState;
        Block->Header.Size = sizeof(*Block);
    }
}

VOID
IppTerminateNeighborOffload(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlockList
    )
/*++

Routine Description:

    Start uploading state using a given neighbor.

Arguments:

    UpperLayerBlockList - Supplies the list of blocks allocated by
        the protocol layers containing state information that was
        passed in by the client when offload was initiated.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlock, DowncallBlockList;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST PlaceHolderBlockList;
    PIP_INTERFACE Interface = NULL;
    PIP_NEIGHBOR Neighbor;

    DowncallBlockList = NULL;
    PlaceHolderBlockList = NULL;

    while (UpperLayerBlockList != NULL) {
        //
        // Pop the next upper-layer block off the input list.
        //
        UpperLayerBlock = UpperLayerBlockList;
        UpperLayerBlockList = UpperLayerBlock->NextBlock;
        UpperLayerBlock->NextBlock = NULL;

        Neighbor = IppGetNeighborFromUpperLayerBlock(UpperLayerBlock);

        if ((Interface != NULL) && (Neighbor->Interface != Interface)) {
            //
            // We're starting a new interface.  Send the old downcall list
            // and start a new one.
            //
            if (DowncallBlockList != NULL) {
                Interface->FlModule->Npi.Dispatch->TerminateOffload(
                    Interface->FlContext,
                    DowncallBlockList);
            }
            DowncallBlockList = NULL;

            if (PlaceHolderBlockList != NULL) {
                Interface->FlModule->Npi.Dispatch->TerminateOffload(
                    Interface->FlContext,
                    PlaceHolderBlockList);
            }
            PlaceHolderBlockList = NULL;
        }

        Interface = Neighbor->Interface;

        //
        // If the upper-layer block is a place-holder, then we do not need to
        // add any neighbor blocks, simply send this down to the next layer's
        // TerminateOffload routine. Note that we queue these seperately in
        // PlaceHolderBlockList because the blocks will be of different type
        // (not a neighbor block).
        //
        if (UpperLayerBlock->OffloadHandle == NULL) {
            //
            // Assert that the place-holder blocks belong to the same
            // layer. Note that the place-holder blocks need not belong to the
            // immediate upper-layer so we cannot hard code the assert type
            // here.
            //
            ASSERT((PlaceHolderBlockList == NULL) || 
                   (UpperLayerBlock->Header.Type ==
                    PlaceHolderBlockList->Header.Type));
            
            UpperLayerBlock->NextBlock = PlaceHolderBlockList;
            PlaceHolderBlockList = UpperLayerBlock;
            continue;
        }

        IppTerminateNeighborOffloadHelper(Neighbor,
                                          UpperLayerBlock,
                                          &DowncallBlockList);
    }

    //
    // Call down to the next layer's TerminateOffload routine.
    //
    if (DowncallBlockList != NULL) {
        Interface->FlModule->Npi.Dispatch->TerminateOffload(
            Interface->FlContext,
            DowncallBlockList);
    }

    //
    // Call down to the next layer's TerminateOffload routine.
    //
    if (PlaceHolderBlockList != NULL) {
        Interface->FlModule->Npi.Dispatch->TerminateOffload(
            Interface->FlContext,
            PlaceHolderBlockList);
    }
    
}

VOID
IppTerminateEmptyNeighborOffload(
    IN PIP_NEIGHBOR Neighbor
    )
{
    PIP_INTERFACE Interface = Neighbor->Interface;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST DowncallBlockList = NULL;

    IppTerminateNeighborOffloadHelper(Neighbor, NULL, &DowncallBlockList);

    if (DowncallBlockList != NULL) {
        Interface->FlModule->Npi.Dispatch->TerminateOffload(
            Interface->FlContext,
            DowncallBlockList);
    }
}

VOID
NTAPI
IpFlcTerminateNeighborOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This routine signals that a request to upload state has completed
    successfully.

Arguments:

    OffloadBlockList - Supplies a list of blocks passed in by the
        framing layer provider containing information on what states
        were uploaded.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlockList;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PIP_NEIGHBOR Neighbor;
    BOOLEAN TerminatedUpper = FALSE, ReleaseReference = FALSE;

    while (OffloadBlockList != NULL) {
        Block = OffloadBlockList;

        //
        // Check if these blocks belong to us or to the upper-layers. If they belong
        // to the upper-layers then we would not have added any of our own blocks
        // in the TerminateOffload call, hence no processing is required here, merely
        // pass the blocks up.
        //
        if ( (Block->Header.Type != NeighborOffloadState) &&
              (Block->Header.Type != NeighborOffloadDelegatedState) ) {
            ASSERT(Block->OffloadHandle == NULL);
            IppTerminatePathOffloadComplete(OffloadBlockList);              
            OffloadBlockList = NULL;
            continue;    
        }

        //
        // Remove the block added by TerminateOffload.
        //
        OffloadBlockList = Block->NextBlock;
        Block->NextBlock = NULL;        
        UpperLayerBlockList = Block->DependentBlockList;
        Block->DependentBlockList = NULL;

        if (Block->OffloadHandle == NULL) {
            //
            // This was a higher-only upload.
            //
            ASSERT(Block->Header.Type == NeighborOffloadState);
            ASSERT(Block->Header.Size == sizeof(*Block));

            Neighbor = IppCast(Block->ProtocolReserved[0], IP_NEIGHBOR);
        } else {
            //
            // This was an upload for this neighbor.
            //
            ASSERT(Block->Header.Type == NeighborOffloadDelegatedState);
    
            Neighbor = CONTAINING_RECORD(Block->OffloadHandle,
                                         IP_NEIGHBOR, 
                                         OffloadHandle);

            Neighbor->OffloadHandle.MiniportOffloadContext = NULL;
        }

        //
        // Take a reference for ourselves.  This ensures that the state doesn't
        // hit NotOffloaded until we're done.  This prevents problems where
        // the upper layer calls back down to offload us and we don't have
        // an unused offload block at that point.
        //
        do {
            New.Value = Snapshot.Value = Neighbor->Offload.Value;
    
            New.Value += IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);
    
            Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);

            //
            // Repeat until the new value is successfully updated.
            //
        } while (Old.Value != Snapshot.Value);

        //
        // Call up to the next layer's completion routine if needed.
        // We want to do this before decrementing the offload count
        // so that the count is safe.
        //
        if (UpperLayerBlockList != NULL) {
            //
            // The terminate routine currently uses a separate neighbor block
            // for each upper layer block.
            //
            ASSERT(UpperLayerBlockList->NextBlock == NULL);

            TerminatedUpper = (UpperLayerBlockList->OffloadHandle != NULL);

            //
            // Defer the terminate complete upcall until we have pushed the 
            // block on our OffloadedBlocks list. This ensures that the any 
            // future requests always find an available block. We can defer
            // the upcall in this way because it is independent of the 
            // neighbor's offload block.
            //
        } else if (Block->ProtocolReserved[1] != NULL) {
            //
            // The neighbor was terminated as a result of a path-to-neighbor
            // mapping change.  So we'll need to remove an offload reference
            // even though we didn't terminate a path.
            //
            TerminatedUpper = TRUE;
            ReleaseReference = TRUE;
        }

        if (Block->OffloadHandle == NULL) {
            //
            // This was a higher-only upload.
            //
    
            //
            // Atomically do the following:
            //
            do {
                New.Value = Snapshot.Value = Neighbor->Offload.Value;
                ASSERT((Snapshot.State == Offloaded) ||
                       (Snapshot.State == UpdateInProgress));
    
                //
                // If we uploaded a path too, decrement the offload count.
                //
                if (TerminatedUpper) {
                    New.Value -= IP_OFFLOAD_REFERENCE;
                    ASSERT(!New.Overflow);
                }
    
                //
                // Release our own reference too.
                //
                New.Value -= IP_OFFLOAD_REFERENCE;
                ASSERT(!New.Overflow);
    
                //
                // If the state is Offloaded and the OffloadCount hits 0,
                //     Transition into the TerminateInProgress state.
                //
                if ((New.Count == 0) && (Snapshot.State == Offloaded)) {
                    New.State = TerminateInProgress;
                }
    
                Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                                       New.Value,
                                                       Snapshot.Value);
        
                //
                // Repeat until the new value is successfully updated.
                //
            } while (Old.Value != Snapshot.Value);
    
            if (New.State == TerminateInProgress) {
                PIP_INTERFACE Interface = Neighbor->Interface;
    
                //
                // Call down to the next lower layer to terminate the
                // offload for this state.  This must complete asynchronously
                // and succeed.
                //
                IppPrepareDelegatedNeighborStateBlock(Block, Neighbor);

                Interface->FlModule->Npi.Dispatch->TerminateOffload(
                    Interface->FlContext,
                    Block);
            } else if (!TerminatedUpper) {
                //
                // Put the block back on the offloaded list.
                //
                InterlockedPushEntrySList(
                    &Neighbor->OffloadedBlocks, 
                    (PSLIST_ENTRY)&Block->NdisReserved[0]);
            } else {
                //
                // Free the block we allocated in InitiateOffload.
                //
                ExFreePool(Block);
            }

        } else {
            //
            // This was an upload for this neighbor.
            //
            // TODO: use the delegated state we get back from the NIC.
            //
    
            //
            // Atomically do the following:
            //
            // Snapshot the current state.
            // If we uploaded higher-layer state too,
            //     Decrement the offload count.
            // If OffloadCount is 0,
            //     Transition to the NotOffloaded state.
            // Else
            //     Transition to the OffloadInProgress state.
            do {
                New.Value = Snapshot.Value = Neighbor->Offload.Value;
    
                ASSERT(Snapshot.State == TerminateInProgress);
        
                if (TerminatedUpper) {
                    New.Value -= IP_OFFLOAD_REFERENCE;
                    ASSERT(!New.Overflow);
                }
    
                //
                // Release our own reference too.
                //
                New.Value -= IP_OFFLOAD_REFERENCE;
                ASSERT(!New.Overflow);
                
                if (New.Count == 0) {
                    IppCleanupNeighborOffloadState(Neighbor);
                    New.State = NotOffloaded;
                } else {
                    New.State = OffloadInProgress;
                    New.Dirty = FALSE;
                }
        
                Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                                       New.Value,
                                                       Snapshot.Value);
        
                //
                // Repeat until the new value is successfully updated.
                //
            } while (Old.Value != Snapshot.Value);
    
            if (New.State == OffloadInProgress) {
                PIP_INTERFACE Interface = Neighbor->Interface;                
                PNEIGHBOR_OFFLOAD_STATE State;
                PSLIST_ENTRY Entry;
                KIRQL OldIrql;
    
                //
                // If we have a pended upper-layer request, grab it instead.  
                // This happens when we pended an offload request during an 
                // upload.
                //
                Entry = 
                    InterlockedPopEntrySList(&Neighbor->OffloadRequestQueue);
                if (Entry != NULL) {
                    ASSERT(Block->DependentBlockList == NULL);
                    ExFreePool(Block);
    
                    Block = CONTAINING_RECORD(Entry,
                                              NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                              NdisReserved[0]);
    
                    ASSERT(Block->Header.Type == NeighborOffloadState);
                }

                if (Block->Header.Type != NeighborOffloadState) {

                    Block->Header.Type = NeighborOffloadState;                    
                    Block->DependentBlockList = NULL;
                    Block->NextBlock = NULL;
                    Block->ProtocolReserved[1] = NULL;
                    Block->NetBufferListChain = NULL;

                    Block->Header.Size = NEIGHBOR_BLOCK_SIZE;
                    State = (PNEIGHBOR_OFFLOAD_STATE)(Block + 1);

                    //
                    // Account for alignment in the offload call.
                    //
                    State->ConstState.Header.Length =
                          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, CachedState) -
                          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, ConstState);

                    State->CachedState.Header.Length =
                          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, DelegatedState) -
                          FIELD_OFFSET(NEIGHBOR_OFFLOAD_STATE, CachedState);        
                    
                    State->DelegatedState.Header.Length = sizeof(State->DelegatedState);    

                    //
                    // Treat a permanent neighbor as currently reachable.  For other 
                    // addresses, compute the time since it was last known to be reachable.
                    //
                    State->CachedState.HostReachabilityDelta = 
                        (Neighbor->State == NlnsPermanent) ? 0 :
                        IppTicksToMilliseconds(IppTickCount - Neighbor->LastReachable);
                    State->DelegatedState.NicReachabilityDelta = 
                        State->CachedState.HostReachabilityDelta;

                    //
                    // Copy DL address under lock.
                    //
                    RtlAcquireReadLock(&(Interface->NeighborSetLock), &OldIrql);
                    RtlCopyMemory(State->CachedState.DlDestinationAddress,
                                  IP_NEIGHBOR_DL_ADDRESS(Neighbor, 
                                        Interface->FlCharacteristics->DlAddressLength),
                                  Interface->FlCharacteristics->DlAddressLength);
                    RtlCopyMemory(State->ConstState.DlSourceAddress,
                                  Interface->FlCharacteristics->DlAddress,
                                  Interface->FlCharacteristics->DlAddressLength);
                    
                    RtlReleaseReadLock(&(Interface->NeighborSetLock), OldIrql);

                    Block->OffloadHandle = &Neighbor->OffloadHandle;
                }
    
                //
                // Pass a request down to the next layer, reusing the
                // offload block.  This always completes asynchronously,
                // even if it fails immediately.
                //
                Interface = Neighbor->Interface;
                Interface->FlModule->Npi.Dispatch->InitiateOffload(
                    Interface->FlContext,
                    Block);
            } else {
                ASSERT(New.State == NotOffloaded);

                //
                // Free the block we allocated in InitiateOffload.
                //
                ExFreePool(Block);
            }
        }

        if (UpperLayerBlockList != NULL) {
            IppTerminatePathOffloadComplete(UpperLayerBlockList);
        }        
    
        if (ReleaseReference) {
            IppDereferenceNeighbor(Neighbor);
        }
    }
}

VOID
IpFlcQueryNeighborReachability(
    IN PNDIS_OFFLOAD_HANDLE OffloadHandle,
    IN ULONG NicReachabilityDelta,
    OUT PULONG StackReachabilityDelta
    )
/*++

Routine Description:

    This function is used by a NIC when it sends a packet and
    it believes the neighbor stale timeout has passed.  It notifies
    the stack of its own elapsed time, and gets back the stack's
    updated elapsed time.

Arguments:

    NicReachabilityDelta - Supplies the elapsed time (in milliseconds)
        since last forward reachability confirmation inside the NIC.

    StackReachabilityDelta - Receives the elapsed time (in milliseconds)
        since last forward reachability confirmation.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_NEIGHBOR Neighbor =
        CONTAINING_RECORD(OffloadHandle, IP_NEIGHBOR, OffloadHandle);
    
    //
    // Convert milliseconds to ticks.
    //
    NicReachabilityDelta = IppMillisecondsToTicks(NicReachabilityDelta);

    *StackReachabilityDelta =
        IppConfirmNeighborReachability(Neighbor, NicReachabilityDelta);

    //
    // Convert ticks to milliseconds.
    //
    *StackReachabilityDelta = IppTicksToMilliseconds(*StackReachabilityDelta);

    //
    // Start probing the neighbor, if required.
    //
    IppResolveNeighbor(Neighbor, NULL);
}

VOID
NTAPI
IpFlcSuspectNeighborReachability(
    IN PNDIS_OFFLOAD_HANDLE OffloadHandle
    )
{
    PIP_NEIGHBOR Neighbor;

    Neighbor = CONTAINING_RECORD(OffloadHandle, IP_NEIGHBOR, OffloadHandle);

    IppSuspectNeighborReachability(Neighbor);
}

VOID
IppUpdateNeighborOffload(
    IN PIP_NEIGHBOR Neighbor,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    )
/*++

Routine Description:

    Called to update offload state.  A neighbor block is added to the
    request, which is then passed down to the next layer, or pended
    if needed.

Arguments:

    Neighbor - Supplies a neighbor to be offloaded.

    BlockList - Supplies a block list to update.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PSLIST_ENTRY Entry;

    do {
        New.Value = Snapshot.Value = Neighbor->Offload.Value;

        //
        // We don't invalidate neighbors, so the state must be Offloaded.
        // The neighbor may not be dirty if this is a higher-only update.
        //
        if ((New.State != Offloaded) || (!New.Dirty)) {
            return;
        }

        New.State = UpdateInProgress;
        New.Dirty = FALSE;

        Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                               New.Value,
                                               Snapshot.Value);

        //
        // Repeat until the new value is successfully updated.
        //
    } while (Old.Value != Snapshot.Value);

    Entry = InterlockedPopEntrySList(&Neighbor->OffloadedBlocks);
    ASSERT(Entry != NULL);

    Block = CONTAINING_RECORD(Entry,
                              NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                              NdisReserved[0]);
    ASSERT(Block->DependentBlockList == NULL);
    Block->DependentBlockList = BlockList;

    IppUpdateNeighborOffloadHelper(Neighbor, Block);
}

VOID
IppUpdateNeighborOffloadStateWorker(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    This gets called from a work item to update offloaded state if needed.

Arguments:

    DeviceObject - Supplies a pointer to the device object.

    Context - Supplies the context for the work item. This is a
        PIP_WORK_QUEUE_ITEM that contains the neighbor to update.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
    System worker threads typically run at PASSIVE.

--*/
{
    PIP_WORK_QUEUE_ITEM WorkItem = (PIP_WORK_QUEUE_ITEM)Context;
    PIP_NEIGHBOR Neighbor;

    UNREFERENCED_PARAMETER(DeviceObject);
    Neighbor = IppCast(WorkItem->Context, IP_NEIGHBOR);

    IppUpdateNeighborOffload(Neighbor, NULL);

    IppDereferenceNeighbor(Neighbor);
    IoFreeWorkItem(WorkItem->WorkQueueItem);
    ExFreePool(WorkItem);
}

IP_OFFLOAD_OBJECT
IppMarkNeighborDirty(
    IN PIP_NEIGHBOR Neighbor
    )
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;

    do {
        New.Value = Snapshot.Value = Neighbor->Offload.Value;

        if ((New.State == OffloadInProgress) ||
            (New.State == UpdateInProgress) ||
            (New.State == Offloaded)) {
            New.Dirty = TRUE;
        }

        Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                               New.Value,
                                               Snapshot.Value);

        //
        // Repeat until the new value is successfully updated.
        //
    } while (Old.Value != Snapshot.Value);

    return New;
}

VOID
IppDeferUpdateNeighborOffloadState(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    This gets called when some cached state changes, and we hold a lock
    that prevents us from being able to do an update immediately.  
    We schedule an offload update if needed.

Arguments:

    Neighbor - Supplies a neighbor to update.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT New;
    PIP_WORK_QUEUE_ITEM WorkItem;
    
    New = IppMarkNeighborDirty(Neighbor);

    if (New.State != Offloaded) {
        return;
    }

    //
    // We want to call down to update the offloaded state asap, but
    // we can't because we're holding a lock at the moment.  Instead,
    // we'll schedule a work item to do it.
    //
    WorkItem = ExAllocatePoolWithTag(NonPagedPool,
                                     sizeof(IP_WORK_QUEUE_ITEM),
                                     IpWorkItemPoolTag);
    if (WorkItem == NULL) {
        return;
    }

    WorkItem->WorkQueueItem = IoAllocateWorkItem(IppDeviceObject);
    if (WorkItem->WorkQueueItem == NULL) {
        ExFreePool(WorkItem);
        return;
    }

    IppReferenceNeighbor(Neighbor);
    WorkItem->Context = Neighbor;

    IoQueueWorkItem(WorkItem->WorkQueueItem, 
                    IppUpdateNeighborOffloadStateWorker, 
                    DelayedWorkQueue, 
                    WorkItem);
}

VOID
NTAPI
IpFlcUpdateNeighborOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This function is used by a framing layer provider to indicate the
    completion of a previously pended update request from the framing
    layer client.

Arguments:

    OffloadBlockList - Supplies a list of blocks passed in by the
        framing layer client containing information on what states
        to update.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PIP_NEIGHBOR Neighbor;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlockList;
    PIP_INTERFACE Interface;
    PFL_PROVIDER_CONTEXT FlProvider;

    while (OffloadBlockList != NULL) {
        Block = OffloadBlockList;
        OffloadBlockList = Block->NextBlock;
        Block->NextBlock = NULL;

        //
        // If the update was not for a neighbor, pass the completion to the path
        // handler. The path handler is responsible for passing it on to TCB if
        // necessary. 
        //
        if ((Block->Header.Type != NeighborOffloadCachedState) &&
            (Block->Header.Type != NeighborOffloadState)) {
            IppUpdatePathOffloadComplete(Block);
            continue;
        }
    
        //
        // Remove the block added by UpdateOffload.
        // 
        UpperLayerBlockList = Block->DependentBlockList;
        Block->DependentBlockList = NULL;
    
        if (Block->OffloadHandle == NULL) {
            //
            // This was a higher-only update.
            //
            ASSERT(Block->Header.Type == NeighborOffloadState);
            ASSERT(Block->Header.Size == sizeof(*Block));
    
            Neighbor = IppCast(Block->ProtocolReserved[0], IP_NEIGHBOR);
    
            //
            // Save the block again.
            //
            InterlockedPushEntrySList(&Neighbor->OffloadedBlocks,
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
            goto Done;
        } else {
            //
            // This was an update for this neighbor.
            //
            ASSERT(Block->Header.Type == NeighborOffloadCachedState);
    
            Neighbor = CONTAINING_RECORD(Block->OffloadHandle,
                                         IP_NEIGHBOR,
                                         OffloadHandle);
        }
    
        Interface = Neighbor->Interface;
        FlProvider = Interface->FlModule;
    
        //
        // Atomically do the following:
        //
        // If the offload count is 0,
        //     Transition to the TerminateInProgress state.
        // Else if the state is dirty again
        //     Clear the dirty bit.
        // Else
        //     Transition to the Offloaded state.
        do {
            New.Value = Snapshot.Value = Neighbor->Offload.Value;
    
            if (New.Count == 0) {
                New.State = TerminateInProgress;
            } else if (New.Dirty) {
                New.Dirty = FALSE;
            } else {
                New.State = Offloaded;
            }
    
            Old.Value = InterlockedCompareExchange(&Neighbor->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);
    
            //
            // Repeat until the new value is successfully updated.
            //
        } while (Old.Value != Snapshot.Value);
    
        if (New.State == TerminateInProgress) {
            //
            // Call down to the next lower layer, reusing the block we removed
            // at the start.
            //
            IppPrepareDelegatedNeighborStateBlock(Block, Neighbor);

            FlProvider->Npi.Dispatch->TerminateOffload(Interface->FlContext,
                                                       Block);
        } else if (New.State == UpdateInProgress) {
            IppUpdateNeighborOffloadHelper(Neighbor, Block);
        } else {
            //
            // Save the block again.
            //
            InterlockedPushEntrySList(&Neighbor->OffloadedBlocks, 
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
        }
    
    Done:
        //
        // Call up to the next higher layer.
        //
        if (UpperLayerBlockList != NULL) {
            IppUpdatePathOffloadComplete(UpperLayerBlockList);
        }
    }
}

VOID
NTAPI
IpFlcInvalidateNeighborOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This function is used by a framing layer provider to indicate the
    completion of a previously pended invalidate request from the framing
    layer client.

Arguments:

    OffloadBlockList - Supplies a list of blocks passed in by the
        framing layer client containing information on what states
        to invalidate.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    //
    // Currently neighbors are never invalidated and path blocks are passed
    // directly down without neighbor placeholders.  Hence we can just
    // complete the path blocks directly.
    // 
    IppInvalidatePathOffloadComplete(OffloadBlockList);
}


