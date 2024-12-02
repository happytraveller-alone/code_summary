/*++

Copyright (c) Microsoft Corporation

Module Name:

    path_offload.c

Abstract:

    This module implements the protocol-independent functions for 
    offloading paths.

Author:

    Dave Thaler (dthaler) 21-August-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"

//
// PATH_OFFLOAD_STATE
//
// All IP path parameters.
//
typedef struct _PATH_OFFLOAD_STATE {
    PATH_OFFLOAD_STATE_CONST ConstState;
    PATH_OFFLOAD_STATE_CACHED CachedState;
    PATH_OFFLOAD_STATE_DELEGATED DelegatedState;
} PATH_OFFLOAD_STATE, *PPATH_OFFLOAD_STATE;

#define PATH_BLOCK_SIZE (sizeof(NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST) + \
                         sizeof(PATH_OFFLOAD_STATE))

VOID
IppInitiatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

VOID
IppUpdatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

VOID
IppTerminatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    );

NTSTATUS
IppInitiateNeighborOffload(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    );

VOID
IppInitiateEmptyNeighborOffload(
    IN PIP_NEIGHBOR Neighbor,
    IN PVOID Context
    );

VOID
IppTerminateEmptyNeighborOffload(
    IN PIP_NEIGHBOR Neighbor
    );

VOID
IppUpdateNeighborOffload(
    IN PIP_NEIGHBOR Neighbor,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    );

VOID
IppTerminateNeighborOffload(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    );

VOID
IppUpdatePathOffloadHelper(
    IN PIP_PATH Path,
    IN PIP_NEIGHBOR NewNeighbor,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    );

VOID
IppInvalidatePathOffloadHelper(
    IN PIP_PATH Path,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    );

IP_OFFLOAD_OBJECT
IppMarkNeighborDirty(
    IN PIP_NEIGHBOR Neighbor
    );

//
// State:                 Happens when:
//   NotOffloaded       <-  (OffloadCount == 0) && (Handle == NULL)
//   OffloadInProgress  <-  (OffloadCount >  0) && (Handle == NULL)
//   Offloaded          <-  (OffloadCount >  0) && (Handle != NULL)
//   TerminateInProgress<-  (OffloadCount == 0) && (Handle != NULL)
//

__inline
BOOLEAN
IppHasPathMappingChanged(
    IN PIP_PATH Path, 
    IN PIP_NEIGHBOR Neighbor
    )
{
    return (Neighbor != Path->OffloadedNeighbor);
}

__inline
VOID
IppCleanupPathOffloadState(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    Cleanup offload state.  We delete any offload blocks stored here
    since we know we're done with them.

Arguments:
    
    Path - Supplies a pointer to a Path entry to clean up.

--*/
{
    PSLIST_ENTRY Entry;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PIP_CLIENT_CONTEXT NlClient;
    PIP_NEIGHBOR Neighbor;

    ASSERT(Path->OffloadHandle.MiniportOffloadContext == NULL);

    Neighbor = InterlockedExchangePointer(&Path->OffloadedNeighbor, NULL);
    if (Neighbor != NULL) {
        IppDereferenceNeighbor(Neighbor);
    }

    for (;;) {
        Entry = InterlockedPopEntrySList(&Path->OffloadedBlocks);
        if (Entry == NULL) {
            return;
        }
    
        Block = CONTAINING_RECORD(Entry,
                                  NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                  NdisReserved[0]);

        NlClient = IppCast(Block->ProtocolReserved[0], IP_CLIENT_CONTEXT);
        IppDereferenceNlClient(NlClient);

        ExFreePool(Block);
    }
}

VOID
IppProcessPendingPathOffloadRequests(
    IN PIP_PATH Path,
    IN NTSTATUS Status
    )
/*++

Routine Description:

    Process the next pended offload request for a given path.
    If it fails, keep trying other ones until they've all failed
    or until one returns pending.
    This is done in the Offloaded, UpdateBlocked, UpdateInProgress
    states, as well as in the OffloadInProgress state on failure.

    Called when processing the InitiateOffload and InitiateOffloadComplete 
    events.

Arguments:

    Path - Supplies the path on which to operate.

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
    PIP_CLIENT_CONTEXT NlClient;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;

    if (NT_SUCCESS(Status) &&
        ((Path->Offload.State == InvalidateInProgress) ||
         (Path->Offload.State == OffloadInvalid))) {
        Status = STATUS_NOT_SUPPORTED;
    }

    IP_OFFLOAD_LOG_EVENT(IpoeProcessPendingRequests, 
        Path, Path, Path->CurrentNextHop, UlongToPtr(Status));

    for (;;) {
        //
        // Pull off the next pending request, if any.
        //
        Entry = InterlockedPopEntrySList(&Path->OffloadRequestQueue);

        if (Entry == NULL) {
            IP_OFFLOAD_LOG_EVENT(
                IpoeNoPendingRequest, Path, Path, Path->CurrentNextHop, Entry);
            return;
        }

        ASSERT((Path->Offload.State == Offloaded) ||
               (Path->Offload.State == OffloadInProgress) ||
               (Path->Offload.State == UpdateBlocked) ||
               (Path->Offload.State == UpdateInProgress));
    
        BlockList = CONTAINING_RECORD(Entry,
                                      NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                      NdisReserved[0]);

        if (NT_SUCCESS(Status)) {
            ASSERT(Path->OffloadedNeighbor != NULL);

            //
            // Call down to the next lower layer's InitiateOffload routine.
            //
            IP_OFFLOAD_LOG_EVENT(
                IpoeDowncallForPendedRequest, Path, Path, 
                Path->CurrentNextHop, NULL);
            IppInitiateNeighborOffload(BlockList);
            return;
        }

        //
        // Remove our own block from the block list.
        //
        Block = BlockList;
        BlockList = Block->DependentBlockList;
        NlClient = IppCast(Block->ProtocolReserved[0], IP_CLIENT_CONTEXT);
        ASSERT(Block->Header.Type == 
               NlClient->Protocol->PathOffloadFullStateType);
        ExFreePool(Block);

        IP_OFFLOAD_LOG_EVENT(
            IpoePendedRequestFailure, Path, Path, Path->CurrentNextHop, Block);

        //
        // Copy the status to all blocks.
        //
        IppSetDependentBlockStatus(BlockList, Status);

        //
        // Issue an upcall to the next higher layer and then continue
        // processing pending requests.
        //
        NlClient->Npi.Dispatch->InitiateOffloadComplete(BlockList);
        IppDereferenceNlClient(NlClient);

        //
        // Decrement the OffloadCount.
        // If it hits 0, transition back to the NotOffloaded state.
        //
        do {
            New.Value = Snapshot.Value = Path->Offload.Value;

            New.Value -= IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);

            if (New.Count == 0) {
                ASSERT(Snapshot.State == OffloadInProgress);
                IppCleanupPathOffloadState(Path);
                New.State = NotOffloaded;
            }

            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);

            //
            // Repeat until the new value is successfully updated.
            //
        } while (Old.Value != Snapshot.Value);
    }
}

VOID
IppSetDependentBlockStatus(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList,
    IN NTSTATUS Status
    )
/*++

Routine Description:

    Set a status for an entire subtree of dependent blocks.

Arguments:

    BlockList - Supplies the root of a tree of blocks.

    Status - Supplies the status value to set.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;

    BlockList->Status = Status;

    for (Block = BlockList->DependentBlockList; 
         Block != NULL; 
         Block = Block->NextBlock) {
        IppSetDependentBlockStatus(Block, Status);
    }
}

__inline
VOID
IppFillOffloadSessionState(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block
    )
/*++

Routine Description:

    Updates the session state information in a TCP offoad block.

Arguments:

    Block - Supplies the offload block to set the session state in.

--*/
{
    PIP_SESSION_STATE Session;
    PTCP_OFFLOAD_STATE_CACHED TcpCachedState;

    Session = (PIP_SESSION_STATE)(Block->NlioSessionState);
    TcpCachedState = (PTCP_OFFLOAD_STATE_CACHED)(Block->NlioCachedState);

    if (Session == NULL || 
        Session->UnicastHopLimit == IP_UNSPECIFIED_HOP_LIMIT) {
        PIP_PATH Path;
        Path = IppCast(Block->NlioPath, IP_PATH);

        //
        // The Interface for the source address could be different from the
        // Interface pointed to by the neighbor (which is the one offload is
        // occuring on). However, both of them are guaranteed to belong to the
        // same compartment and getting the compartment via SourceAddress is
        // less expensive - and do so.
        //
        TcpCachedState->TtlOrHopLimit = 
            Path->SourceAddress->Interface->Compartment->DefaultHopLimit;
    } else {
        TcpCachedState->TtlOrHopLimit = (UINT8)Session->UnicastHopLimit;
    }

    TcpCachedState->TosOrTrafficClass = 0;
}

BOOLEAN
IppAllocateSparePathBlock(
    IN PIP_PROTOCOL Protocol,
    IN PIP_CLIENT_CONTEXT NlClient,
    IN PIP_PATH Path
    )
/*++

Routine Description:

    We need to ensure that an offload block always exists for our own Update 
    and Invalidate calls.  Since those calls must not fail, we need to ensure
    this up front.

Arguments:

    Protocol - Supplies a pointer to the global protocol state.

    NlClient - Supplies a pointer to the TCP client binding.

    Path - Supplies a pointer to the path to create a spare block for.
    
Return Value:

    Returns TRUE on success, FALSE on failure.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
    
--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST SpareBlock;

    SpareBlock = ExAllocatePoolWithTag(NonPagedPool,
                                       PATH_BLOCK_SIZE,
                                       IpOffloadPoolTag);
    if (SpareBlock == NULL) {
        return FALSE;
    }
    RtlZeroMemory(SpareBlock, PATH_BLOCK_SIZE);
    SpareBlock->Header.Type = Protocol->PathOffloadFullStateType;
    SpareBlock->Header.Size = PATH_BLOCK_SIZE;
    
    //
    // All blocks need an NlClient reference.
    //
    IppReferenceValidNlClient(NlClient);
    SpareBlock->ProtocolReserved[0] = NlClient;
    
    InterlockedPushEntrySList(&Path->OffloadedBlocks, 
                              (PSLIST_ENTRY) &SpareBlock->NdisReserved[0]);
    return TRUE;
}

VOID
NTAPI
IpNlpInitiatePathOffload(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlockList
    )
/*++

Routine Description:

    This gets called when offloading a new TCP connection.
    We want to offload the path and neighbor if not already done.

Arguments:

    UpperLayerBlockList - Supplies a list of upper-layer blocks to offload.

Return Value:

    The completion function will be called with the block status values
    set to one of:

    STATUS_NOT_SUPPORTED - Connection is not offloadable.
    STATUS_NO_MEMORY     - Memory allocation failed.
    STATUS_PENDING       - Call will complete asynchronously.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
    
--*/
{
    PIP_PROTOCOL Protocol;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlock;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST DowncallBlockList;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST CompleteBlockList;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PPATH_OFFLOAD_STATE State;
    PIP_CLIENT_CONTEXT NlClient;
    PIP_RECEIVE_DEMUX Demux;
    PIP_NEIGHBOR Neighbor;
    BOOLEAN UpperLayerAlreadyOffloaded;
    PIP_PATH Path;
    NTSTATUS Status;

    Path = IppCast(UpperLayerBlockList->NlioPath, IP_PATH);
    Protocol = Path->SourceAddress->Interface->Compartment->Protocol;

    //
    // Get the NL client pointer.  The client is responsible for ensuring
    // we cannot detach while this call is in progress, since we have to
    // be able to call the completion function on failure.
    //
    Demux = &Protocol->ReceiveDemux[IPPROTO_TCP];
    NlClient = Demux->NlClient;

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

        IppFillOffloadSessionState(UpperLayerBlock);
        Path = IppCast(UpperLayerBlock->NlioPath, IP_PATH);

        for (Block = DowncallBlockList; 
             Block != NULL; 
             Block = Block->NextBlock) {
            if ((Block->OffloadHandle != &Path->OffloadHandle) &&
                ((Block->OffloadHandle != NULL) ||
                 (Block->ProtocolReserved[1] != Path))) {
                continue;
            }

            //
            // We've already processed this state.  Allocate a spare block
            // so we can terminate it, and then make the upper-layer block
            // dependent on the existing path block.
            //
            if (!IppAllocateSparePathBlock(Protocol, NlClient, Path)) {
                Status = STATUS_NO_MEMORY;
                goto Fail;
            }
            UpperLayerBlock->NextBlock = Block->DependentBlockList;
            Block->DependentBlockList = UpperLayerBlock;

            if (UpperLayerBlock->OffloadHandle->MiniportOffloadContext == 
                NULL) {
                do {
                    New.Value = Snapshot.Value = Path->Offload.Value;
    
                    New.Value += IP_OFFLOAD_REFERENCE;
                    ASSERT(!New.Overflow);
        
                    Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                                           New.Value,
                                                           Snapshot.Value);
    
                    //
                    // Repeat until the new value is successfully updated.
                    //
                } while (Old.Value != Snapshot.Value);
            }

            goto NextUpperLayerBlock;
        }

        //
        // If path is not offloadable, return error.
        //
        Neighbor = IppGetNeighborFromPath(Path);
        if (Neighbor == NULL) {
            Status = STATUS_UNSUCCESSFUL;
            goto Fail;
        }
        
        if ((Neighbor->Interface->Index 
                != PtrToUlong(UpperLayerBlock->NlioDesiredIndex)) ||
            !IppIsPathOffloadable(Path, Neighbor)) {
            Status = STATUS_NOT_SUPPORTED;
            goto DereferenceAndFail;
        }
    
        //
        // Allocate a block for the path information.  We allocate one
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
                                      PATH_BLOCK_SIZE,
                                      IpOffloadPoolTag);
        if (Block == NULL) {
            Status = STATUS_NO_MEMORY;

    DereferenceAndFail:
            IppDereferenceNeighbor(Neighbor);
    Fail:
            IppSetDependentBlockStatus(UpperLayerBlock, Status);

            IP_OFFLOAD_LOG_EVENT(
                IpoeInitiateOffloadResources, Path, Path, 
                Path->CurrentNextHop, Block);
    
            //
            // Put the upper-layer block on the immediate completion list.
            //
            UpperLayerBlock->NextBlock = CompleteBlockList;
            CompleteBlockList = UpperLayerBlock;
            continue;
        }
    
        //
        // Add the path's state to the request's block list.
        //
        Block->DependentBlockList = UpperLayerBlock;
        Block->NextBlock = NULL;
        Block->NetBufferListChain = NULL;
        IppReferenceValidNlClient(NlClient);
        Block->ProtocolReserved[0] = NlClient;

        Block->Header.Type = Protocol->PathOffloadFullStateType;

        UpperLayerAlreadyOffloaded =
            (UpperLayerBlock->OffloadHandle->MiniportOffloadContext != NULL);
    
        if (UpperLayerAlreadyOffloaded) {
            //
            // Currently TCP is the upper-most layer so we should never
            // hit this code path.
            //
            ASSERT(FALSE);
            
            //
            // Upper layer state is already offloaded, so we just prepend the 
            // path state and do nothing else.  This is a place-holder block
            // so we set the offload handle to NULL. Then on completion we 
            // know we can free the block. 
            //
            Block->Header.Size = sizeof(*Block);
            Block->OffloadHandle = NULL;
            Block->ProtocolReserved[1] = Path;

            ASSERT(Path->OffloadedNeighbor != NULL);

        QueueForDowncall:
            //
            // Put the block on the downcall list.
            //
            IP_OFFLOAD_LOG_EVENT(
                IpoeQueueForDowncall, Path, Path, Path->CurrentNextHop, Block);
            Block->NextBlock = DowncallBlockList;
            DowncallBlockList = Block;
            continue;
        }

        Block->Header.Size = PATH_BLOCK_SIZE;
        Block->OffloadHandle = &Path->OffloadHandle;

        State = (PPATH_OFFLOAD_STATE)(Block + 1);

        //
        // Account for alignment in the offload call
        //
        State->ConstState.Header.Length =
              FIELD_OFFSET(PATH_OFFLOAD_STATE, CachedState) -
              FIELD_OFFSET(PATH_OFFLOAD_STATE, ConstState);

        State->CachedState.Header.Length =
              FIELD_OFFSET(PATH_OFFLOAD_STATE, DelegatedState) -
              FIELD_OFFSET(PATH_OFFLOAD_STATE, CachedState);        
        
        State->DelegatedState.Header.Length = sizeof(State->DelegatedState);

        State->ConstState.SourceAddress = NL_ADDRESS(Path->SourceAddress);
        State->ConstState.DestinationAddress = Path->DestinationAddress;
        State->CachedState.PathMtu = Path->PathMtu;
    
        //
        // Atomically do the following:
        //
        // If we're in the NotOffloaded state, 
        //     Transition to the OffloadInProgress state.
        // Take a reference in either case.
        //
       
        do {
            New.Value = Snapshot.Value = Path->Offload.Value;
    
            //
            // If we're offloading a new upper-layer entry, then bump the 
            // offload count.
            //
            ASSERT(!UpperLayerAlreadyOffloaded);
            New.Value += IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);

            if (Snapshot.State == NotOffloaded) {
                New.State = OffloadInProgress;
                New.Dirty = FALSE;
            }
    
            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);

            IP_OFFLOAD_LOG_EVENT(
                IpoeTransitionToInProgress, Path, UlongToPtr(New.Value), 
                UlongToPtr(Old.Value), UlongToPtr(Snapshot.Value));
            
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
            if (QueryDepthSList(&Path->OffloadedBlocks) == 0) {
                if (!IppAllocateSparePathBlock(Protocol, NlClient, Path)) {
                    IppDereferenceNeighbor(Neighbor);
                    IppSetDependentBlockStatus(Block, STATUS_NO_MEMORY);
                
                    //
                    // TODO: make IppInitiatePathOffloadComplete queue to
                    // our completion list instead.
                    //
                    IppInitiatePathOffloadComplete(Block);
                    continue;
                }
            }
    
            //
            // Donate our neighbor reference to the path.
            //
            ASSERT(Path->OffloadedNeighbor == NULL);
            Path->OffloadedNeighbor = Neighbor;

            goto QueueForDowncall;
    
        case Offloaded:
        case UpdateBlocked:
        case UpdateInProgress:
            IppDereferenceNeighbor(Neighbor);

            goto QueueForDowncall;

        case InvalidateInProgress:
        case OffloadInvalid:
            //
            // Fail the request.
            //
            ExFreePool(Block);

            Status = STATUS_UNSUCCESSFUL;
            goto DereferenceAndFail;
    
        default:
            IppDereferenceNeighbor(Neighbor);
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
        InterlockedPushEntrySList(&Path->OffloadRequestQueue,
                                  (PSLIST_ENTRY)&Block->NdisReserved[0]);

        IP_OFFLOAD_LOG_EVENT(
            IpoePendOffloadRequest, Path, Path, Path->CurrentNextHop, Block);
   
        Snapshot.Value = Path->Offload.Value;
        if ((Snapshot.State == Offloaded) ||
            (Snapshot.State == UpdateBlocked) ||
            (Snapshot.State == UpdateInProgress)) {
            //
            // Path has already been offloaded.  Start processing the pending
            // list, since we don't know whether it's been done yet or not.
            //
            IP_OFFLOAD_LOG_EVENT(
                IpoeInitiateProcessPendingList, 
                Path, Path, Path->CurrentNextHop, Block);
            IppProcessPendingPathOffloadRequests(Path, STATUS_SUCCESS);
        }

NextUpperLayerBlock:
        ;
    }

    //
    // Now process the two lists.
    //
    if (CompleteBlockList != NULL) {
        NlClient->Npi.Dispatch->InitiateOffloadComplete(CompleteBlockList);
    }
    if (DowncallBlockList != NULL) {
        IppInitiateNeighborOffload(DowncallBlockList);
    }
}

VOID
IppPrepareDelegatedPathStateBlock(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block,
    IN PIP_PATH Path
    )
/*++

Routine Description:

    Initialize a block as a delegated state block for a path.

Arguments:

    Block - Supplies a block to prepare.

    Path - Supplies the neighbor to associate.

--*/
{
    PPATH_OFFLOAD_STATE_DELEGATED State;
    PIP_INTERFACE Interface = Path->OffloadedNeighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;

    Block->Header.Type = Protocol->PathOffloadDelegatedStateType;
    Block->Header.Size = sizeof(*Block) + sizeof(*State);
    State = (PPATH_OFFLOAD_STATE_DELEGATED)(Block + 1);
    State->Header.Length = sizeof(*State);

    Block->OffloadHandle = &Path->OffloadHandle;
}

VOID
IppChangePathOffloadMappingHelper(
    IN PIP_PATH Path, 
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Call down to the next lower layer to start a neighbor offload.

Arguments:

    Path - Supplies a path to change the mapping for.

    Neighbor - Supplies the new neighbor. 

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IppReferencePath(Path);
    IppInitiateEmptyNeighborOffload(Neighbor, Path);
}

VOID
IppChangePathOffloadMappingComplete(
    IN PIP_PATH Path,
    IN PIP_NEIGHBOR Neighbor,
    IN NTSTATUS Status
    )
/*++

Routine Description:

    Start an update now that the new neighbor is offloaded.

Arguments:

    Path - Supplies a path to change the mapping for.

    Neighbor - Supplies the neigbor to which the mapping is getting changed. 

    Status - Supplies the status from offloading the new neighbor.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PSLIST_ENTRY Entry;

    ASSERT(Status != NDIS_STATUS_OFFLOAD_PARTIAL_SUCCESS);
    
    //
    // Atomically do the following:
    //
    // If the refcount is 0,
    //     Transition to the TerminateInProgress state.
    // Else if the status was success and the state is still offloadable
    //     Transition to the UpdateInProgress state.
    // Else
    //     Transition to the InvalidateInProgress state.
    //
    do {
        New.Value = Snapshot.Value = Path->Offload.Value;

        ASSERT(New.State == UpdateBlocked);
        if (New.Count == 0) {
            New.State = TerminateInProgress;
        } else if (NT_SUCCESS(Status) && IppIsPathOffloadable(Path, Neighbor)) {
            New.State = UpdateInProgress;
        } else {
            New.State = InvalidateInProgress;
        }

        Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                               New.Value,
                                               Snapshot.Value);

        //
        // Repeat until the new value is successfully updated.
        //
    } while (Old.Value != Snapshot.Value);

    Entry = InterlockedPopEntrySList(&Path->OffloadedBlocks);
    ASSERT(Entry != NULL);

    Block = CONTAINING_RECORD(Entry,
                              NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                              NdisReserved[0]);
    ASSERT(Block->DependentBlockList == NULL);

    if (New.State == UpdateInProgress) {
        IppUpdatePathOffloadHelper(Path, Neighbor, Block);
    } else if (New.State == InvalidateInProgress) {
        IppInvalidatePathOffloadHelper(Path, Block);
    } else if (New.State == TerminateInProgress) {
        IppPrepareDelegatedPathStateBlock(Block, Path);
        IppTerminateNeighborOffload(Block);
    }

    IppDereferencePath(Path);
}

VOID
IppInvalidatePathOffloadHelper(
    IN PIP_PATH Path,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block
    )
/*++

Routine Description:

    Call down to the next lower layer to start a state invalidate.
    This must complete asynchronously and succeed.

Arguments:

    Path - Supplies a path to invalidate.

    Block - Supplies an offload block to use for the invalidate.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_INTERFACE Interface = Path->OffloadedNeighbor->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;

    //
    // An invalidate uses the full state type but a 0 payload length.
    //
    Block->Header.Type = Protocol->PathOffloadFullStateType;
    Block->Header.Size = sizeof(*Block);

    //
    // Call down to the next lower layer to update the entry.
    // This always completes asynchronously.
    //
    Block->OffloadHandle = &Path->OffloadHandle;

    //
    // The neighbor layer doesn't need to do anything, so we
    // call directly down to the FL.
    //
    Interface->FlModule->Npi.Dispatch->InvalidateOffloadState(
        Interface->FlContext,
        Block);
}

VOID
IppUpdatePathOffloadHelper(
    IN PIP_PATH Path,
    IN PIP_NEIGHBOR NewNeighbor,
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    )
/*++

Routine Description:

    Call down to the next lower layer to start a state update.
    This must complete asynchronously and succeed.

Arguments:

    Path - Supplies a path to update.

    NewNeighbor - Supplies the new neighbor to use for the path.  This is
        different from the currently offloaded neighbor if this is called after
        the change mapping call succeeds. 

    BlockList - Supplies an offload block list to use for the update.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PPATH_OFFLOAD_STATE_CACHED State;
    PIP_NEIGHBOR OldNeighbor;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PIP_PROTOCOL Protocol;

    Protocol = Path->SourceAddress->Interface->Compartment->Protocol;

    while (BlockList != NULL) {
        Block = BlockList;
        BlockList = Block->NextBlock;
        Block->NextBlock = NULL;

        Block->Header.Type = Protocol->PathOffloadCachedStateType;
        Block->Header.Size = sizeof(*Block) + sizeof(*State);
        State = (PPATH_OFFLOAD_STATE_CACHED)(Block + 1);
        State->Header.Length = sizeof(*State);

        State->PathMtu = Path->PathMtu;
        Block->OffloadHandle = &Path->OffloadHandle;
    
        //
        // Call down to the next lower layer to update the entry.
        // This always completes asynchronously.
        //
        OldNeighbor = Path->OffloadedNeighbor;
        if (NewNeighbor != OldNeighbor) {
            //
            // Save the OldNeighbor so that when the update completes
            // we can terminate it.
            //
            IppReferenceNeighbor(NewNeighbor);
            Block->ProtocolReserved[1] = OldNeighbor;
            Path->OffloadedNeighbor = NewNeighbor;

            //
            // Mark the new neighbor as dirty. This will force a mapping 
            // update. See article titled "Linking Path State Objects to a 
            // New Neighbor State Object" in the NDIS documentation.
            //
            IppMarkNeighborDirty(NewNeighbor);
            IppUpdateNeighborOffload(NewNeighbor, Block);
        } else {
            PIP_INTERFACE Interface = OldNeighbor->Interface;
    
            Block->ProtocolReserved[1] = NULL;
            Interface->FlModule->Npi.Dispatch->UpdateOffloadState(
                Interface->FlContext,
                Block);
        }
    }
}

VOID
IppInitiatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This is called when a path offload completes.  We indicate
    the completion to the next higher layer, and start processing
    any pending requests.

Arguments:

    OffloadBlockList - Supplies the list of blocks allocated by
        the protocol layers containing state information that was
        passed in by the client when offload was initiated.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PATH Path;
    PIP_CLIENT_CONTEXT NlClient;
    PIP_NEIGHBOR Neighbor;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlockList;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    BOOLEAN NeedUpdate, NeedMappingChange, NeedInvalidate;
    NTSTATUS Status;

    while (OffloadBlockList != NULL) {
        Block = OffloadBlockList;
        OffloadBlockList = Block->NextBlock;
        Block->NextBlock = NULL;

        //
        // Remove the block we added in InitiateOffload.
        //
        UpperLayerBlockList = Block->DependentBlockList;
        Block->DependentBlockList = NULL;
        NlClient = IppCast(Block->ProtocolReserved[0], IP_CLIENT_CONTEXT);

        ASSERT(Block->Header.Type == 
               NlClient->Protocol->PathOffloadFullStateType);

        if (Block->OffloadHandle == NULL) {
            ASSERT(Block->Header.Size == sizeof(*Block));

            //
            // Save the block, since all upper-layer state can be terminated
            // in parallel.
            //
            Path = IppCast(Block->ProtocolReserved[1], IP_PATH);
    
            InterlockedPushEntrySList(&Path->OffloadedBlocks, 
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
    
            NlClient->Npi.Dispatch->InitiateOffloadComplete(
                UpperLayerBlockList);
            continue;
        }

        Path = CONTAINING_RECORD(Block->OffloadHandle, 
                                 IP_PATH, 
                                 OffloadHandle);
        Status = Block->Status;

        Neighbor = IppGetNeighborFromPath(Path);

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
            NeedUpdate = NeedInvalidate = NeedMappingChange = FALSE;
            New.Value = Snapshot.Value = Path->Offload.Value;

            ASSERT((Snapshot.State != NotOffloaded) && 
                   (Snapshot.State != TerminateInProgress));
    
            if ((Snapshot.State == OffloadInProgress) && NT_SUCCESS(Status)) {
                ASSERT(Path->OffloadHandle.MiniportOffloadContext != NULL);
                if (Snapshot.Dirty) {
                    if (!IppIsPathOffloadable(Path, Neighbor)) {
                        New.State = InvalidateInProgress;
                        NeedInvalidate = TRUE;
                    } else if (IppHasPathMappingChanged(Path, Neighbor)) {
                        New.State = UpdateBlocked;
                        NeedMappingChange = TRUE;
                    } else {
                        New.State = UpdateInProgress;
                        NeedUpdate = TRUE;
                    }
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
    
            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);

            IP_OFFLOAD_LOG_EVENT(
                IpoeOffloadComplete,
                Path, UlongToPtr(New.Value), 
                UlongToPtr(Old.Value), UlongToPtr(Snapshot.Value));
    
            //
            // Repeat until the new value is successfully updated.
            //
        } while (Old.Value != Snapshot.Value);
  
        if (!NT_SUCCESS(Status) ||
            (Status == NDIS_STATUS_OFFLOAD_PARTIAL_SUCCESS)) {
            LONG Count = 0, TotalCount = 0;
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
                TotalCount++;
            }

            IP_OFFLOAD_LOG_EVENT(
                IpoeInitiateOffloadFailure,
                Path, UlongToPtr(TotalCount), UlongToPtr(Count), 
                UlongToPtr(Status));

            //
            // Decrement the offload count for the requests (we still have
            // our own reference).
            // We do the decrement by subtracting IP_OFFLOAD_REFERENCE.
            // This can not cause a state change since we hold our own
            // reference.
            //
            InterlockedExchangeAdd(&Path->Offload.Value, 
                                   -(Count * IP_OFFLOAD_REFERENCE));
            ASSERT(!Path->Offload.Overflow);
        }

        if (NeedUpdate) {
            IppUpdatePathOffloadHelper(Path, Neighbor, Block);
        } else if (NeedMappingChange) {
            IppChangePathOffloadMappingHelper(Path, Neighbor);
        } else if (NeedInvalidate) {
            IppInvalidatePathOffloadHelper(Path, Block);
        }
    
        if (Neighbor != NULL) {
            IppDereferenceNeighbor(Neighbor);
        }

CompleteOffloadRequests:
        //
        // Start the next pended downcall, if any.
        //
        IP_OFFLOAD_LOG_EVENT(
            IpoeInitiateProcessPendingList, Path, Path, 
            Neighbor, UlongToPtr(Status));
        IppProcessPendingPathOffloadRequests(Path, Status);
    
        //
        // At this point either all pended downcalls have failed,
        // or else one is pending.
        //
    
        //
        // Atomically do the following:
        // 
        // Release our own reference on the Offload.Count.
        // If the count goes to 0:
        //      If the current state is Offloaded, 
        //          transition to TerminateInProgress.
        //      If the current state is OffloadInProgress,
        //          transition to NotOffloaded.
        //      (Otherwise the state is UpdateInProgress and the transition will
        //      happen when the update completes.)
        //
        do {
            New.Value = Snapshot.Value = Path->Offload.Value;
    
            New.Value -= IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);
    
            if (New.Count == 0) {
                if (Snapshot.State == Offloaded) {
                    New.State = TerminateInProgress;
                } else if (Snapshot.State == OffloadInProgress) {
                    IppCleanupPathOffloadState(Path);
                    New.State = NotOffloaded;
                }
            }
    
            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                                   New.Value,
                                                   Snapshot.Value);

            IP_OFFLOAD_LOG_EVENT(
                IpoeTransitionFromInProgress,
                Path, UlongToPtr(New.Value), 
                UlongToPtr(Old.Value), UlongToPtr(Snapshot.Value));
    
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
            IP_OFFLOAD_LOG_EVENT(
                IpoeStartTerminate, Path, Path, Neighbor, Block);
            IppPrepareDelegatedPathStateBlock(Block, Path);
            IppTerminateNeighborOffload(Block);
        } else if (New.State == NotOffloaded) {
            //
            // We already cleaned up all the other blocks besides the one
            // we used, so clean it up now.
            //
            ExFreePool(Block);
        } else if (New.State == OffloadInProgress) {
            //
            // New offload request(s) were queued between the time we 
            // called IppProcessPendingPathOffloadRequests and dropped
            // our reference. So let's add another reference and
            // fail those newly queued requests. We can safely add a 
            // reference without checking for state transitions because
            // the state is OffloadInProgress so new requests will only
            // be queued without causing any state transitions.
            //
            InterlockedExchangeAdd(&Path->Offload.Value, IP_OFFLOAD_REFERENCE);
            ASSERT(Path->Offload.State == OffloadInProgress);            
            goto CompleteOffloadRequests;
        } else if (NeedUpdate || NeedInvalidate) {
            //
            // Block is already in use.
            //
        } else {
            //
            // Save the block we allocated in InitiateOffload.
            //
            IP_OFFLOAD_LOG_EVENT(
                IpoeSaveInitiateBlock, Path, Path, Neighbor, Block);
            InterlockedPushEntrySList(&Path->OffloadedBlocks,
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
        }
    
        //
        // Call up to the next layer's completion routine.
        // If the request completed with success, then at this point the
        // higher layer may call TerminateOffload or UpdateOffload.
        // This must be done after we save the block, so that we'll have one
        // if the higher layer calls back down.
        //
        if (UpperLayerBlockList != NULL) {
            IP_OFFLOAD_LOG_EVENT(
                IpoeInvokeUpperCompletion, Path, Path, Neighbor, 
                UpperLayerBlockList);
            NlClient->Npi.Dispatch->InitiateOffloadComplete(UpperLayerBlockList);
        }
        if (New.State == NotOffloaded) {
            IppDereferenceNlClient(NlClient);
        }
    }
}

VOID
IpNlpTerminatePathOffload(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST UpperLayerBlockList
    )
/*++

Routine Description:

    Start uploading state using a given path.

Arguments:

    UpperLayerBlockList - Supplies the list of blocks allocated by
        the protocol layers containing state information that was
        passed in by the client when offload was initiated.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlock, DowncallBlockList;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST PlaceHolderBlockList;
    PSLIST_ENTRY Entry;
    PIP_PATH Path;
    PIP_PROTOCOL Protocol;

    DowncallBlockList = NULL;
    PlaceHolderBlockList = NULL;

    while (UpperLayerBlockList != NULL) {
        UpperLayerBlock = UpperLayerBlockList;
        UpperLayerBlockList = UpperLayerBlock->NextBlock;
        UpperLayerBlock->NextBlock = NULL;

        //
        // If the upper-layer block is a place-holder, then we do not need to add
        // any path blocks, simply send this down to the next layer's TerminateOffload
        // routine. Note that we queue these seperately in PlaceHolderBlockList
        // because the blocks will be of different type (not a path block). 
        //
        if (UpperLayerBlock->OffloadHandle == NULL) {

            //
            // Assert that the place-holder blocks belong to the same layer. Note that the
            // place-holder blocks need not belong to the immediate upper-layer so we cannot 
            // hard code the assert type here.
            //
            ASSERT((PlaceHolderBlockList == NULL) || 
                         (UpperLayerBlock->Header.Type == PlaceHolderBlockList->Header.Type));

            UpperLayerBlock->NextBlock = PlaceHolderBlockList;
            PlaceHolderBlockList = UpperLayerBlock;
            continue;
        }

        Path = IppCast(UpperLayerBlock->NlioPath, IP_PATH);
    
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
            New.Value = Snapshot.Value = Path->Offload.Value;
    
            ASSERT((Snapshot.State == Offloaded) ||
                   (Snapshot.State == InvalidateInProgress) ||
                   (Snapshot.State == UpdateInProgress) ||
                   (Snapshot.State == UpdateBlocked) ||
                   (Snapshot.State == OffloadInvalid));
    
            if (((Snapshot.State == Offloaded) || 
                 (Snapshot.State == OffloadInvalid)) && 
                (Snapshot.Count == 1) &&
                (UpperLayerBlock->OffloadHandle != NULL)) {
                New.State = TerminateInProgress;
            } else {
                Old.Value = Snapshot.Value;
                break;
            }
    
            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
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
        Entry = InterlockedPopEntrySList(&Path->OffloadedBlocks);
        ASSERT(Entry != NULL);
    
        Block = CONTAINING_RECORD(Entry,
                                  NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                  NdisReserved[0]);
        ASSERT(Block->DependentBlockList == NULL);
    
        Block->DependentBlockList = UpperLayerBlock;

        Block->NextBlock = DowncallBlockList;
        DowncallBlockList = Block;
    
        Block->ProtocolReserved[0] = IppCast(Block->ProtocolReserved[0], 
                                             IP_CLIENT_CONTEXT);
    
        Protocol = Path->SourceAddress->Interface->Compartment->Protocol;

        //
        // If we just transitioned into the TerminateInProgress state,
        //     Fill in the offload handle, so that the NIC will actually 
        //     upload this state.
        //
        if (New.State == TerminateInProgress) {
            IppPrepareDelegatedPathStateBlock(Block, Path); 
        } else {
            Block->OffloadHandle = NULL;
            Block->ProtocolReserved[1] = Path;

            //
            // This is a "placeholder" block.
            //
            Block->Header.Type = Protocol->PathOffloadFullStateType;
            Block->Header.Size = sizeof(*Block);
        }
    }

    //
    // Call down to the next layer's TerminateOffload routine.
    //
    IppTerminateNeighborOffload(DowncallBlockList);

    //
    // Call down to the next layer's TerminateOffload routine.
    //
    IppTerminateNeighborOffload(PlaceHolderBlockList);
    
}

VOID
IppTerminatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This routine signals that a request to upload state has completed
    successfully.

Arguments:

    OffloadBlockList - Supplies a list of blocks passed up by the
        neighbor layer containing information on what states
        were uploaded.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlockList;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PIP_PATH Path;
    BOOLEAN TerminatedUpper = FALSE;
    PIP_CLIENT_CONTEXT NlClient;

    while (OffloadBlockList != NULL) {
        Block = OffloadBlockList;
        NlClient = IppCast(Block->ProtocolReserved[0], IP_CLIENT_CONTEXT);
        
        //
        // Check if these blocks belong to us or to the upper-layers. If they belong
        // to the upper-layers then we would not have added any of our own blocks
        // in the TerminateOffload call, hence no processing is required here, merely
        // pass the blocks up.
        //
        if ((Block->Header.Type != NlClient->Protocol->PathOffloadFullStateType) &&
              (Block->Header.Type != NlClient->Protocol->PathOffloadDelegatedStateType)) {
            ASSERT(Block->OffloadHandle == NULL);
            NlClient->Npi.Dispatch->TerminateOffloadComplete(OffloadBlockList);              
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
            ASSERT(Block->Header.Type == 
                   NlClient->Protocol->PathOffloadFullStateType);
            ASSERT(Block->Header.Size == sizeof(*Block));
    
            Path = IppCast(Block->ProtocolReserved[1], IP_PATH);
        } else {
            //
            // This was an upload for this path.
            //
            ASSERT(Block->Header.Type == 
                   NlClient->Protocol->PathOffloadDelegatedStateType);
    
            Path = CONTAINING_RECORD(Block->OffloadHandle,
                                     IP_PATH, 
                                     OffloadHandle);

            Path->OffloadHandle.MiniportOffloadContext = NULL;
        }
    
        //
        // Take a reference for ourselves.  This ensures that the state doesn't
        // hit NotOffloaded until we're done.  This prevents problems where
        // the upper layer calls back down to offload us and we don't have
        // an unused offload block at that point.
        //

        do {
            New.Value = Snapshot.Value = Path->Offload.Value;
    
            New.Value += IP_OFFLOAD_REFERENCE;
            ASSERT(!New.Overflow);
    
            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
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
            // The terminate routine currently uses a separate path block
            // for each upper layer block.
            //
            ASSERT(UpperLayerBlockList->NextBlock == NULL);

            TerminatedUpper = (UpperLayerBlockList->OffloadHandle != NULL);

            //
            // Because TCP is the upper-most layer.
            //
            ASSERT(TerminatedUpper);
            
            NlClient->Npi.Dispatch->TerminateOffloadComplete(
                UpperLayerBlockList);
        }
    
        if (Block->OffloadHandle == NULL) {
            //
            // This was a higher-only upload.
            //
    
            //
            // Atomically do the following:
            //
            // If we uploaded a TCB too, decrement the offload count.
            // Release our own reference too.
            // If the state is Offloaded and the OffloadCount hits 0,
            //     Transition into the TerminateInProgress state.
            //

            do {
                New.Value = Snapshot.Value = Path->Offload.Value;
                ASSERT((Snapshot.State == Offloaded) ||
                       (Snapshot.State == InvalidateInProgress) ||
                       (Snapshot.State == OffloadInvalid) ||
                       (Snapshot.State == UpdateInProgress) ||
                       (Snapshot.State == UpdateBlocked));
    
                if (TerminatedUpper) {
                    New.Value -= IP_OFFLOAD_REFERENCE;
                    ASSERT(!New.Overflow);
                }
    
                New.Value -= IP_OFFLOAD_REFERENCE;
                ASSERT(!New.Overflow);
    
                if ((New.Count == 0) && ((Snapshot.State == Offloaded) || 
                                         (Snapshot.State == OffloadInvalid))) {
                    New.State = TerminateInProgress;
                }
    
                Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                                       New.Value,
                                                       Snapshot.Value);
        
                //
                // Repeat until the new value is successfully updated.
                //
            } while (Old.Value != Snapshot.Value);

            if (New.State == TerminateInProgress) {
                //
                // Call down to the next lower layer to terminate the
                // offload for this state.  This must complete asynchronously
                // and succeed.
                //
                IppPrepareDelegatedPathStateBlock(Block, Path);
                IppTerminateNeighborOffload(Block);
            } else if (!TerminatedUpper) {
                //
                // Put the block back on the offloaded list.
                //
                ASSERT(FALSE);
                InterlockedPushEntrySList(
                    &Path->OffloadedBlocks, 
                    (PSLIST_ENTRY)&Block->NdisReserved[0]);
            } else {
                //
                // Free the block we allocated in InitiateOffload.
                //
                IppDereferenceNlClient(NlClient);
                ExFreePool(Block);
            }
        } else {
            //
            // This was an upload for this path.
            //
            // Paths currently have no delegated state to handle.
            //
            IppDereferenceNeighbor(Path->OffloadedNeighbor);
            Path->OffloadedNeighbor = NULL;

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
                New.Value = Snapshot.Value = Path->Offload.Value;
    
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
                    IppCleanupPathOffloadState(Path);
                    New.State = NotOffloaded;
                } else {
                    New.State = OffloadInProgress;
                    New.Dirty = FALSE;
                }
        
                Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                                       New.Value,
                                                       Snapshot.Value);        

                //
                // Repeat until the new value is successfully updated.
                //
            } while (Old.Value != Snapshot.Value);

            if (New.State == OffloadInProgress) {
                PPATH_OFFLOAD_STATE State;
                PSLIST_ENTRY Entry;
    
                //
                // If we have a pended upper-layer request, grab it instead.  
                // This happens when we pended an offload request during an 
                // upload.
                //
                Entry = InterlockedPopEntrySList(&Path->OffloadRequestQueue);
                if (Entry != NULL) {
                    ASSERT(Block->DependentBlockList == NULL);
                    IppDereferenceNlClient(NlClient);
                    ExFreePool(Block);
    
                    Block = CONTAINING_RECORD(Entry,
                                              NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                              NdisReserved[0]);
    
                    ASSERT((Block->Header.Type == Ip6OffloadState) ||
                           (Block->Header.Type == Ip4OffloadState));
                }
    
                IppValidatePath(Path);
                Path->OffloadedNeighbor = IppGetNeighborFromPath(Path);
                if (Path->OffloadedNeighbor == NULL) {
                    IppSetDependentBlockStatus(Block, STATUS_UNSUCCESSFUL);
                    IppInitiatePathOffloadComplete(Block);
                    continue;
                }

                if (Block->Header.Type != NlClient->Protocol->PathOffloadFullStateType) {

                    Block->Header.Type = NlClient->Protocol->PathOffloadFullStateType;
                    Block->DependentBlockList = NULL;
                    Block->NextBlock = NULL;
                    Block->Header.Size = PATH_BLOCK_SIZE;                    
                    Block->NetBufferListChain = NULL;
                    Block->ProtocolReserved[1] = NULL;
                    Block->OffloadHandle = &Path->OffloadHandle;

                    State = (PPATH_OFFLOAD_STATE)(Block + 1);

                    //
                    // Account for alignment in the offload call
                    //
                    State->ConstState.Header.Length =
                          FIELD_OFFSET(PATH_OFFLOAD_STATE, CachedState) -
                          FIELD_OFFSET(PATH_OFFLOAD_STATE, ConstState);

                    State->CachedState.Header.Length =
                          FIELD_OFFSET(PATH_OFFLOAD_STATE, DelegatedState) -
                          FIELD_OFFSET(PATH_OFFLOAD_STATE, CachedState);        
                    
                    State->DelegatedState.Header.Length = sizeof(State->DelegatedState);

                    State->ConstState.SourceAddress = NL_ADDRESS(Path->SourceAddress);
                    State->ConstState.DestinationAddress = Path->DestinationAddress;
                    State->CachedState.PathMtu = Path->PathMtu;
                }
                    
                //
                // Pass a request down to the next layer, reusing the
                // offload block.  This always completes asynchronously,
                // even if it fails immediately.
                //
                IppInitiateNeighborOffload(Block);
            } else {
                ASSERT(New.State == NotOffloaded);

                //
                // Free the block we allocated in InitiateOffload.
                //
                IppDereferenceNlClient(NlClient);
                ExFreePool(Block);
            }
        }
    }
}

VOID
IppUpdatePathOffloadState(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    Initiate an offload state update.

Arguments:

    Path - Supplies a pointer to the new path state.

--*/
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PIP_NEIGHBOR Neighbor;
    PSLIST_ENTRY Entry;
    
    Neighbor = IppGetNeighborFromPath(Path);
    
    do {
        New.Value = Snapshot.Value = Path->Offload.Value;

        if ((New.State != Offloaded) || !New.Dirty) {
            goto Done;
        }

        if (!IppIsPathOffloadable(Path, Neighbor)) {
            New.State = InvalidateInProgress;
        } else if (IppHasPathMappingChanged(Path, Neighbor)) {
            New.State = UpdateBlocked;
        } else {
            New.State = UpdateInProgress;
        }
        New.Dirty = FALSE;

        Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                               New.Value,
                                               Snapshot.Value);

        //
        // Repeat until the new value is successfully updated.
        //
    } while (Old.Value != Snapshot.Value);

    if (New.State == UpdateBlocked) {
        IppChangePathOffloadMappingHelper(Path, Neighbor);
    } else {
        Entry = InterlockedPopEntrySList(&Path->OffloadedBlocks);
        ASSERT(Entry != NULL);

        Block = CONTAINING_RECORD(Entry,
                                  NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                                  NdisReserved[0]);
        ASSERT(Block->DependentBlockList == NULL);
    
        if (New.State == UpdateInProgress) {
            IppUpdatePathOffloadHelper(Path, Neighbor, Block);
        } else {
            ASSERT(New.State == InvalidateInProgress);
            IppInvalidatePathOffloadHelper(Path, Block);
        }
    }

Done:
    if (Neighbor != NULL) {
        IppDereferenceNeighbor(Neighbor);
    }
}

VOID
IppUpdatePathOffloadStateWorker(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    This gets called from a work item to update offloaded state if needed.

Arguments:

    DeviceObject - Supplies a pointer to the device object.

    Context - Supplies the context for the work item. This is a
        PIP_WORK_QUEUE_ITEM that contains the path to update.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_WORK_QUEUE_ITEM WorkItem = (PIP_WORK_QUEUE_ITEM)Context;
    PIP_PATH Path;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    Path = IppCast(WorkItem->Context, IP_PATH);

    IppUpdatePathOffloadState(Path);
    IppDereferencePath(Path);
    
    IoFreeWorkItem(WorkItem->WorkQueueItem);
    ExFreePool(WorkItem);
}

IP_OFFLOAD_OBJECT
IppMarkPathDirty(
    IN PIP_PATH Path
    )
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;

    do {
        New.Value = Snapshot.Value = Path->Offload.Value;

        if ((New.State == OffloadInProgress) ||
            (New.State == UpdateInProgress) ||
            (New.State == Offloaded)) {
            New.Dirty = TRUE;
        }

        Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
                                               New.Value,
                                               Snapshot.Value);

        //
        // Repeat until the new value is successfully updated.
        //
    } while (Old.Value != Snapshot.Value);

    return New;
}

VOID
IppDeferUpdatePathOffloadState(
    IN PIP_PATH Path
    )
/*++

Routine Description:

    This gets called when some cached state changes, and we hold a lock
    that prevents us from being able to do an update immediately.
    We schedule an offload update if needed.

Arguments:

    Path - Supplies a path to update.

Caller IRQL:

    Must be called at DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT New;
    PIP_WORK_QUEUE_ITEM WorkItem;

    DISPATCH_CODE();

    New = IppMarkPathDirty(Path);

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

    IppReferencePath(Path);
    WorkItem->Context = Path;

    IoQueueWorkItem(WorkItem->WorkQueueItem,
                    IppUpdatePathOffloadStateWorker,
                    DelayedWorkQueue,
                    WorkItem);
}

VOID
IppUpdatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This function is used to indicate the completion of a previously pended 
    path update request.

Arguments:

    OffloadBlockList - Supplies a list of blocks containing information on 
        what states to update.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PIP_PATH Path;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block, UpperLayerBlockList;
    PIP_CLIENT_CONTEXT NlClient;
    PIP_NEIGHBOR Neighbor;
    NTSTATUS Status;

    while (OffloadBlockList != NULL) {
        Block = OffloadBlockList;
        OffloadBlockList = Block->NextBlock;
        Block->NextBlock = NULL;

        //
        // Remove the block added by UpdateOffload.
        // 
        UpperLayerBlockList = Block->DependentBlockList;
        Block->DependentBlockList = NULL;
        NlClient = IppCast(Block->ProtocolReserved[0], IP_CLIENT_CONTEXT);

        if (Block->OffloadHandle == NULL) {
            //
            // This was a higher-only update.
            //
            ASSERT(Block->Header.Type == 
                   NlClient->Protocol->PathOffloadFullStateType);
            ASSERT(Block->Header.Size == sizeof(*Block));
    
            Path = IppCast(Block->ProtocolReserved[1], IP_PATH);
    
            //
            // Save the block again.
            //
            InterlockedPushEntrySList(&Path->OffloadedBlocks, 
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
            goto Done;
        } else {
            //
            // This was an update for this path.
            //
            ASSERT(Block->Header.Type == 
                   NlClient->Protocol->PathOffloadCachedStateType);
    
            Path = CONTAINING_RECORD(Block->OffloadHandle,
                                     IP_PATH,
                                     OffloadHandle);
            ASSERT(Path->Offload.State == UpdateInProgress);

            //
            // Retrieve the previous neighbor (if any) which needs to be
            // terminated now.
            //
            Neighbor = (PIP_NEIGHBOR)Block->ProtocolReserved[1];
            if (Neighbor != NULL) {
                IppTerminateEmptyNeighborOffload(Neighbor);
            }
        }

        Status = Block->Status;
    
        Neighbor = IppGetNeighborFromPath(Path);
    
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
            New.Value = Snapshot.Value = Path->Offload.Value;
            ASSERT(Snapshot.State == UpdateInProgress);
    
            if (New.Count == 0) {
                New.State = TerminateInProgress;
            } else if (New.Dirty) {
                if (!IppIsPathOffloadable(Path, Neighbor) || 
                    !NT_SUCCESS(Status)) {
                    New.State = InvalidateInProgress;
                } else if (IppHasPathMappingChanged(Path, Neighbor)) {
                    New.State = UpdateBlocked;
                }
                New.Dirty = FALSE;
            } else {
                New.State = Offloaded;
            }
    
            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
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
            IppPrepareDelegatedPathStateBlock(Block, Path);
            IppTerminateNeighborOffload(Block);
        } else if (New.State == UpdateInProgress) {
            IppUpdatePathOffloadHelper(Path, Neighbor, Block);
        } else if (New.State == InvalidateInProgress) {
            IppInvalidatePathOffloadHelper(Path, Block);
        } else {
            //
            // Save the block again.
            //
            InterlockedPushEntrySList(&Path->OffloadedBlocks, 
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
    
            if (New.State == UpdateBlocked) {
                IppChangePathOffloadMappingHelper(Path, Neighbor);
            }
        }

        if (Neighbor != NULL) {
            IppDereferenceNeighbor(Neighbor);
        }
    
    Done:
        //
        // Call up to the next higher layer.
        //
        if (UpperLayerBlockList != NULL) {
            NlClient->Npi.Dispatch->UpdateOffloadComplete(UpperLayerBlockList);
        }
    }
}

VOID
IppInvalidatePathOffloadComplete(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:

    This function is used to indicate the completion of a path invalidate 
    request.

Arguments:

    OffloadBlockList - Supplies a list of blocks containing information on 
        what states to invalidate.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PATH Path;
    IP_OFFLOAD_OBJECT Old, Snapshot, New;
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PIP_CLIENT_CONTEXT NlClient;

    while (OffloadBlockList != NULL) {
        Block = OffloadBlockList;
        OffloadBlockList = Block->NextBlock;
        Block->NextBlock = NULL;

        //
        // Nothing above paths gets invalidated.
        //
        ASSERT(Block->DependentBlockList == NULL);

        //
        // Remove the block added by InvalidateOffload.
        // 
        Block->DependentBlockList = NULL;
        NlClient = IppCast(Block->ProtocolReserved[0], IP_CLIENT_CONTEXT);

        //
        // Make sure this is a "placeholder" block.
        //
        ASSERT(Block->Header.Type == 
               NlClient->Protocol->PathOffloadFullStateType);
        ASSERT(Block->Header.Size == sizeof(*Block));

        if (Block->OffloadHandle == NULL) {
            //
            // This was a higher-only invalidate.
            //
    
            Path = IppCast(Block->ProtocolReserved[1], IP_PATH);
            goto Done;
        } else {
            //
            // This was an invalidate for this path.
            //
    
            Path = CONTAINING_RECORD(Block->OffloadHandle,
                                     IP_PATH,
                                     OffloadHandle);
            ASSERT(Path->Offload.State == InvalidateInProgress);
        }

        //
        // Atomically do the following:
        //
        // If the offload count is 0,
        //     Transition to the TerminateInProgress state.
        // Else
        //     Transition to the OffloadInvalid state.
        do {
            New.Value = Snapshot.Value = Path->Offload.Value;
            ASSERT(Snapshot.State == InvalidateInProgress);
    
            if (New.Count == 0) {
                New.State = TerminateInProgress;
            } else {
                New.State = OffloadInvalid;
            }
    
            Old.Value = InterlockedCompareExchange(&Path->Offload.Value,
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
            IppPrepareDelegatedPathStateBlock(Block, Path);
            IppTerminateNeighborOffload(Block);
        } else {
    Done:
            //
            // Save the block again.
            //
            InterlockedPushEntrySList(&Path->OffloadedBlocks, 
                                      (PSLIST_ENTRY)&Block->NdisReserved[0]);
        }
    }
}

VOID
IpNlpUpdatePathOffload(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList
    )
/*++

Routine Description:

    Handle an upper-layer state offload update.  We don't need to do anything
    except send the list to the right interfaces.

--*/
{
    PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST Block;
    PSLIST_ENTRY Entry;
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    PIP_PATH Path = IppCast(BlockList->NlioPath, IP_PATH);

    Interface = Path->OffloadedNeighbor->Interface;
    Protocol = Interface->Compartment->Protocol;
    IppFillOffloadSessionState(BlockList);

    Entry = InterlockedPopEntrySList(&Path->OffloadedBlocks);
    ASSERT(Entry != NULL);

    //
    // Get a "placeholder" block.
    //
    Block = CONTAINING_RECORD(Entry,
                              NDIS_PROTOCOL_OFFLOAD_BLOCK_LIST,
                              NdisReserved[0]);
    ASSERT(Block->DependentBlockList == NULL);
    Block->Header.Type = Protocol->PathOffloadFullStateType;
    Block->Header.Size = sizeof(*Block);

    Block->DependentBlockList = BlockList;
    BlockList = Block;

    Block->ProtocolReserved[0] = IppCast(Block->ProtocolReserved[0], 
                                         IP_CLIENT_CONTEXT);

    //
    // Don't modify the offload state for this path.
    //
    Block->OffloadHandle = NULL;
    Block->ProtocolReserved[1] = Path;

    //
    // The neighbor layer doesn't need to do anything, so we
    // call directly down to the FL.
    //
    Interface->FlModule->Npi.Dispatch->UpdateOffloadState(
        Interface->FlContext,
        Block);
}
