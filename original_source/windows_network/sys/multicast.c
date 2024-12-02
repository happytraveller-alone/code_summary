/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    multicast.c

Abstract:

    This module contains the protocol independent part of the multicast group
    membership protocol.

Author:

    Amit Aggarwal (amitag) Mon Dec 02 18:21:46 2002.

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "multicast.tmh"

#pragma warning(disable:4204) // non-constant aggregate initializer

__inline
VOID
IppMulticastTrace(
    IN ULONG Level, 
    IN CONST UCHAR *Message, 
    IN PIP_PROTOCOL Protocol,
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastAddress
    )
{
    if (IS_IPV4_PROTOCOL(Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: [%u] %s (%!IPV4!)\n", 
                   MulticastAddress->Interface->Index,
                   Message, 
                   NL_ADDRESS(MulticastAddress));
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: [%u] %s (%!IPV6!)\n", 
                   MulticastAddress->Interface->Index,
                   Message, 
                   NL_ADDRESS(MulticastAddress));
    }
}

__inline
VOID
IppMulticastTraceEx(
    IN ULONG Level, 
    IN CONST UCHAR *Message, 
    IN CONST UCHAR *MessageEx,
    IN PIP_PROTOCOL Protocol,
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastAddress,
    IN ULONG Information
    )
{
    if (IS_IPV4_PROTOCOL(Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: [%u] %s (%!IPV4! %s %x)\n", 
                   MulticastAddress->Interface->Index, 
                   Message, 
                   NL_ADDRESS(MulticastAddress), 
                   MessageEx, 
                   Information);
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: [%u] %s (%!IPV6! %s %x)\n", 
                   MulticastAddress->Interface->Index, 
                   Message, 
                   NL_ADDRESS(MulticastAddress), 
                   MessageEx,
                   Information);
    }
}

//
// Forward declarations.
//
VOID
IppUndoRemoveSourcesFromMulticastSessionState(
    IN PIP_SESSION_MULTICAST_STATE State,
    IN PLIST_ENTRY RemoveHandle
    );

VOID
IppCommitRemoveSourcesFromMulticastSessionState(
    IN PLIST_ENTRY RemoveHandle
    );

NTSTATUS
IppModifyMulticastGroup(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN MULTICAST_MODE_TYPE OldMode,
    IN ULONG DeleteCount,
    IN CONST UCHAR *DeleteList,
    IN MULTICAST_MODE_TYPE NewMode, 
    IN ULONG AddCount,
    IN CONST UCHAR *AddList,
    IN CONST LIST_ENTRY *SessionSources
    );

VOID
IppMulticastWorkerRoutine(
    IN PDEVICE_OBJECT DeviceObject, 
    IN PVOID Context
    );

PIP_LOCAL_MULTICAST_SOURCE
IppFindLocalMulticastSource(
    IN PLIST_ENTRY SourceList,
    IN CONST UCHAR *SourceAddress,
    IN ULONG AddressBytes
    )
/*++

Routine Description:

    This routine finds a multicast source entry with a given address in the
    given source address list (stored in a local multicast address). 

Arguments:

    SourceList - Supplies a pointer to the source address list in which to find
        the source.  

    SourceAddress - Supplies the source address to find. 

    AddressBytes - Supplies the length of the address. 

Return Value:

    Returns a pointer to the multicast source entry in case the entry is
    found. Returns NULL otherwise. 

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization. 

--*/ 
{
    PLIST_ENTRY Current;
    PIP_LOCAL_MULTICAST_SOURCE Source;
    
    for (Current = SourceList->Flink;
         Current != SourceList;
         Current = Current->Flink) {
        Source = (PIP_LOCAL_MULTICAST_SOURCE)CONTAINING_RECORD(
            Current,
            IP_LOCAL_MULTICAST_SOURCE,
            Link);
        if (RtlEqualMemory(IP_LOCAL_MULTICAST_SOURCE_ADDRESS(Source),
                           SourceAddress, 
                           AddressBytes)) {
            return Source;
        }
    }
    
    return NULL;
}

PIP_SESSION_MULTICAST_SOURCE
IppFindSessionMulticastSource(
    IN PLIST_ENTRY SourceList,
    IN CONST UCHAR *SourceAddress,
    IN ULONG AddressBytes
    )
/*++

Routine Description:

    This routine finds a multicast source entry with a given address in the
    given source address list (stored in a session state).

Arguments:

    SourceList - Supplies a pointer to the source address list in which to find
        the source.  

    SourceAddress - Supplies the source address to find. 

    AddressBytes - Supplies the length of the address. 

Return Value:

    Returns a pointer to the multicast source entry in case the entry is
    found. Returns NULL otherwise. 

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization. 

--*/ 
{
    PLIST_ENTRY Current;
    PIP_SESSION_MULTICAST_SOURCE Source;
    
    for (Current = SourceList->Flink;
         Current != SourceList;
         Current = Current->Flink) {
        Source = (PIP_SESSION_MULTICAST_SOURCE)CONTAINING_RECORD(
            Current,
            IP_SESSION_MULTICAST_SOURCE,
            Link);
        if (RtlEqualMemory(IP_SESSION_MULTICAST_SOURCE_ADDRESS(Source),
                           SourceAddress, 
                           AddressBytes)) {
            return Source;
        }
    }
    
    return NULL;
}

#define SOURCE_LIST_ELEMENT(SourceList, Index, AddressBytes) \
    (PUCHAR)((SourceList) + ((Index) * (AddressBytes)))

VOID
IppGetMulticastSessionStateSourceList(
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    OUT PUCHAR List
    )
/*++

Routine Description:

    Copy the list of source adresses from a multicast group session state
    into a caller supplied buffer.
    
Arguments:

    MulticastState - Supplies the multicast group session state.

    List - Returns an array of source addresses into a caller supplied buffer.
        The supplied buffer is guaranteed to be sufficiently big.

Return Value:

     None.

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization.  

--*/ 
{
    PLIST_ENTRY Current;
    PIP_SESSION_MULTICAST_SOURCE Source;
    ULONG Count = 0;
    ULONG AddressBytes = MulticastState->MulticastGroup->Interface->
        Compartment->Protocol->Characteristics->AddressBytes;

    for (Current = MulticastState->SourceList.Flink;
         (Current != &MulticastState->SourceList);
         Current = Current->Flink, Count++) {
        Source = (PIP_SESSION_MULTICAST_SOURCE)CONTAINING_RECORD(
            Current,
            IP_SESSION_MULTICAST_SOURCE,
            Link);
        RtlCopyMemory(SOURCE_LIST_ELEMENT(List, Count, AddressBytes),
                      IP_SESSION_MULTICAST_SOURCE_ADDRESS(Source),
                      AddressBytes);
    }
}

NTSTATUS 
IppRemoveSourcesFromMulticastSessionState(
    IN PIP_SESSION_MULTICAST_STATE MulticastState, 
    IN ULONG SourceCount, 
    IN CONST UCHAR *SourceList,
    IN ULONG AddressBytes,
    IN OUT PLIST_ENTRY RemoveHandle
    )
/*++

Routine Description:

    This routine removes a list of sources from a multicast group session
    state. The multicast group session state can be either in include or
    exclude mode.  The operation can fail if one of the sources in the
    SourceList is not present in the multicast group session state. If the
    remove is performed in a series of operations (that can potentially fail),
    then the remove might have to be undone. The problem is that undoing the
    remove requires an allocation that can fail as well which will leave the
    state inconsistent. The solution is to add the removed sources to a list
    (instead of deleting them) that is returned to the caller through the
    RemoveHandle. The caller is then responsible for calling
    IppUndoRemoveSourcesFromMulticastSessionState or
    IppCommitRemoveSourcesFromMulticastSessionState depending on the outcome of
    the other operations. IppUndoRemoveSourcesFromMulticastSessionState adds
    the source list in RemoveHandle back to the state's source
    list. IppCommitRemoveSourcesFromMulticastSessionState deletes the sources
    in RemoveHandle. 

Arguments:

    MulticastState - Supplies the multicast group session state to modify. 

    SourceCount - Supplies the number of sources to be removed from the 
        include/exclude list.  

    SourceList - Supplies the source list to be removed. 

    AddressBytes - Supplies the protocol address length.
    
    RemoveHandle - Supplies a handle that is used if the caller wants to undo
        the remove at some later point. If the caller does not want to undo the
        remove, then contains NULL. Returns the list of removed sources.

Return Value:

    Returns STATUS_SUCCESS if the multicast state was modified
    successfully. Otherwise, returns STATUS_INVALID_ADDRESS if one of the
    sources in the SourceList is not present in the multicast group session
    state.

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization.  

--*/ 
{
    NTSTATUS Status;
    ULONG Count;
    PUCHAR SourceAddress;
    PIP_SESSION_MULTICAST_SOURCE Source;
    
    ASSERT((SourceCount == 0) || (SourceList != NULL));

    for (Count = 0; Count < SourceCount; Count++) {
        SourceAddress =  SOURCE_LIST_ELEMENT(SourceList, Count, AddressBytes);
        Source =
            IppFindSessionMulticastSource(
                &MulticastState->SourceList,
                SourceAddress,
                AddressBytes);
        if (Source == NULL) {
            Status = STATUS_INVALID_ADDRESS;
            goto Error;
        }

        RemoveEntryList(&Source->Link);
        MulticastState->SourceCount--;

        //
        // Add the removed source to the RemovedList so that the change
        // can be undone later. 
        //
        if (RemoveHandle != NULL) {
            InsertTailList(RemoveHandle, &Source->Link);
        } else {
            NbFreeMem(Source);
        }
    }
    
    return STATUS_SUCCESS;

Error:
    if (RemoveHandle != NULL) {
        IppUndoRemoveSourcesFromMulticastSessionState(
            MulticastState, RemoveHandle);
    } else {
        ASSERT(FALSE);
    }
    
    return Status;
}
    
VOID
IppDestroyMulticastSessionState(
    IN PIP_SESSION_MULTICAST_STATE State
    )
/*++

Routine Description:

    Destroy a session multicast state and its associated source list.
    
Arguments:

    State - Supplies the session multicast state to destroy.
    
Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{ 
    PLIST_ENTRY Head, Next;
    PIP_SESSION_MULTICAST_SOURCE Source;

    Head = &State->SourceList;
    for (Next = Head->Flink; Next != Head; ) {
        Source = CONTAINING_RECORD(Next, IP_SESSION_MULTICAST_SOURCE, Link);
        Next = Next->Flink;
        NbFreeMem(Source);
    }
    FsbFree((PUCHAR)State);
}

VOID
IppUndoRemoveSourcesFromMulticastSessionState(
    IN PIP_SESSION_MULTICAST_STATE State,
    IN PLIST_ENTRY RemoveHandle
    )
{
    PLIST_ENTRY Current;
    
    while (!IsListEmpty(RemoveHandle)) {
        Current = RemoveTailList(RemoveHandle);
        InsertTailList(&State->SourceList, Current);
        State->SourceCount++;
    }
}

VOID
IppCommitRemoveSourcesFromMulticastSessionState(
    IN PLIST_ENTRY RemoveHandle
    )
{
    PIP_SESSION_MULTICAST_SOURCE Current;
    
    while (!IsListEmpty(RemoveHandle)) {
        Current = CONTAINING_RECORD(
            RemoveTailList(RemoveHandle), 
            IP_SESSION_MULTICAST_SOURCE, 
            Link);
        NbFreeMem(Current);
    }
}

NTSTATUS
IppAddSourcesToMulticastSessionState(
    IN PIP_PROTOCOL Protocol,
    IN PIP_SESSION_MULTICAST_STATE State, 
    IN ULONG SourceCount, 
    IN CONST UCHAR *SourceList,
    IN ULONG AddressBytes
    )
/*++

Routine Description:

    This routine adds a list of sources to a multicast group session state. The
    multicast group session state can be either in include or exclude mode.  

Arguments:

    Protocol - Supplies the protocol. 

    State - Supplies a pointer to the multicast group session state to modify. 

    SourceCount - Supplies the number of sources to be added to the
        include/exclude list.  

    SourceList - Supplies the source list to be added. 

    AddressBytes - Supplies the length of the address.
    
Return Value:

    Returns STATUS_SUCCESS if the multicast state was modified
    successfully. Otherwise, returns the following error codes:
    STATUS_INSUFFICIENT_RESOURCES if it cannot allocate space for a new source 
    entry; STATUS_ADDRESS_ALREADY_EXISTS if the source is already present in
    the current list of sources. Therefore, if the caller or app (for instance,
    the network layer client) tries to add a source that is already present,
    the call is going to fail here.

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization.  

--*/ 
{
    NTSTATUS Status, UndoStatus;
    ULONG Count;
    PUCHAR SourceAddress;
    PIP_SESSION_MULTICAST_SOURCE Source;
    
    ASSERT((SourceCount == 0) || (SourceList != NULL));
    
    for (Count = 0; Count < SourceCount; Count++) {
        SourceAddress = SOURCE_LIST_ELEMENT(SourceList, Count, AddressBytes);
        if (IppFindSessionMulticastSource(&State->SourceList,
                                          SourceAddress,
                                          AddressBytes) != NULL) {
            Status = STATUS_ADDRESS_ALREADY_EXISTS;
            goto Error;
        }

        //
        // Maintain the invariant that the number of sources in the multicast
        // group never exceeds MAX_MULTICAST_SOURCE_COUNT.
        //
        if (State->SourceCount >= MAX_MULTICAST_SOURCE_COUNT) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Error;
        }
        
        Source = NbAllocMem(Protocol->SessionMulticastSourceSize,
                            IpSessionStatePoolTag);
        if (Source == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Error;
        }
    
        RtlCopyMemory(IP_SESSION_MULTICAST_SOURCE_ADDRESS(Source),
                      SourceAddress,
                      AddressBytes);
        InsertTailList(&State->SourceList, &Source->Link);
        State->SourceCount++;
    }
    
    return STATUS_SUCCESS;

Error:
    //
    // Undo the work we have done so far. Note that the remove operation can
    // never fail.
    //
    UndoStatus = IppRemoveSourcesFromMulticastSessionState(
        State,
        Count,
        SourceList,
        AddressBytes,
        NULL);
    ASSERT(NT_SUCCESS(UndoStatus));

    return Status;
}

PIP_SESSION_MULTICAST_STATE
IppFindMulticastSessionState(
    IN PIP_SESSION_STATE State,
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *MulticastAddress,
    IN CONST IF_INDEX InterfaceIndex OPTIONAL
    )
/*++

Routine Description:

    This routine finds the multicast group session state corresponding to a
    multicast address and an interface address.

Arguments:

    State - Supplies a pointer to the session state in which to search for the
        multicast group session state. 

    Compartment - Supplies the compartment.

    MulticastAddress - Supplies the multicast address to search for.

    InterfaceIndex - Supplies the interface index to search for.  If the
        interface index is unspecified, the routine returns the first matching 
        multicast address. 

Return Value:

    Returns a pointer to the multicast session state. Returns NULL if no state
    is found. 

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization.  

--*/ 
{
    PLIST_ENTRY Current;
    PIP_SESSION_MULTICAST_STATE MulticastState;
    PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup;
    ULONG AddressBytes = Compartment->Protocol->Characteristics->AddressBytes;
    
    for (Current = State->MulticastState.Flink; 
         Current != &State->MulticastState; 
         Current = Current->Flink) {
        MulticastState = (PIP_SESSION_MULTICAST_STATE)CONTAINING_RECORD(
            Current,
            IP_SESSION_MULTICAST_STATE,
            Link);
        MulticastGroup = MulticastState->MulticastGroup;
        if (((InterfaceIndex == IFI_UNSPECIFIED) ||
             (InterfaceIndex == MulticastGroup->Interface->Index)) &&
            (RtlEqualMemory(
                MulticastAddress, 
                NL_ADDRESS(MulticastGroup), 
                AddressBytes))) {
            return MulticastState;
        }
    }
    
    return NULL;
}

BOOLEAN
IppDoesSessionStateIncludeGroupAndSource(
    IN PIP_SESSION_STATE State,
    IN PIP_LOCAL_MULTICAST_ADDRESS Group,
    IN CONST UCHAR *SourceAddress
    )
/*++

Routine Description:

    Test whether a given session allows a given (group,source) pair 
    on a given interface.

Arguments:

    State - Supplies the state of the session to test.

    Group - Supplies a pointer to local multicast address state.

    SourceAddress - Supplies the source address of a multicast packet.

Locks:

    The NL client is responsible for ensuring that no call to 
    CleanupSessionInformation for the same session is in progress during 
    this call.

    Locks the session state.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PLIST_ENTRY Current;
    PIP_SESSION_MULTICAST_STATE MulticastState;
    PIP_SESSION_MULTICAST_SOURCE Source;
    KIRQL OldIrql;
    BOOLEAN Allow;
    ULONG AddressBytes =
        Group->Interface->Compartment->Protocol->Characteristics->AddressBytes;

    //
    // As an optimization, if we notice that the group list is empty,
    // don't bother taking a lock.
    //
    if (IsListEmpty(&State->MulticastState)) {
        return FALSE;
    }

    KeAcquireSpinLock(&State->SpinLock, &OldIrql);

    for (Current = State->MulticastState.Flink; ; Current = Current->Flink) {
        if (Current == &State->MulticastState) {
            //
            // We reached the end of the list, and the group was not joined.
            //
            Allow = FALSE;
            break;
        }

        MulticastState = (PIP_SESSION_MULTICAST_STATE)
            CONTAINING_RECORD(
                Current,
                IP_SESSION_MULTICAST_STATE,
                Link);

        if (Group != MulticastState->MulticastGroup) {
            continue;
        }

        //
        // We have group state.  Now see if the source is allowed.
        //
        Source =
            IppFindSessionMulticastSource(
                &MulticastState->SourceList,
                SourceAddress,
                AddressBytes);

        //
        // Normally, the packet is allowed if the group is in EXCLUDE mode.
        // If the source is in the exception list, then the result is
        // inverted.
        //
        Allow = ((MulticastState->Mode == MCAST_EXCLUDE) ^ (Source != NULL));
        break;
    }

    KeReleaseSpinLock(&State->SpinLock, OldIrql);

    return Allow;
}

NTSTATUS
IppCreateMulticastSessionStateComplete(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    IN NTSTATUS Status
    )
/*++

Routine Description:

    Invoked upon completion of an attempt to create a multicast session state.
    
Arguments:

    MulticastGroup - Supplies the group for the session multicast state.
         If Status indicates failure, the MulticastGroup could not be created.
         
    MulticastState - Supplies the session multicast state, deleted on failure.

    Status - Supplies the status of the creation.
    
Return Value:

    STATUS_SUCCESS or failure code.

Locks:
   
    Assumes caller holds an exclusive lock on the session state.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/ 
{
    PIP_PROTOCOL Protocol = MulticastGroup->Interface->Compartment->Protocol;
    PIP_SESSION_STATE Session = MulticastState->Session;

    ASSERT_SPIN_LOCK_HELD(&Session->SpinLock);
    
    if (NT_SUCCESS(Status)) {
        //
        // Inform the multicast address entry about a new session source list. 
        //
        IppMulticastTrace(TRACE_LEVEL_INFORMATION, 
                          "Created multicast session state",
                          Protocol, MulticastGroup);
        Status = IppModifyMulticastGroup(
            MulticastGroup,
            MCAST_INCLUDE,
            0, 
            NULL,
            MulticastState->Mode, 
            MulticastState->SourceCount,
            NULL,
            MulticastState->SourceList.Flink);
        if (NT_SUCCESS(Status)) {
            MulticastState->MulticastGroup = MulticastGroup;
            InsertTailList(&Session->MulticastState,
                           &MulticastState->Link);
            return STATUS_SUCCESS;
        }
    } else {
        IppMulticastTraceEx(TRACE_LEVEL_INFORMATION, 
                            "Error creating multicast session state", "Status",
                            Protocol, MulticastGroup, Status);
    }

    //
    // Since IppFindOrCreateLocalMulticastAddress returned pending,
    // we're responsible for releasing the reference.
    //
    IppDereferenceLocalMulticastAddress(MulticastGroup);
    
    IppDestroyMulticastSessionState(MulticastState);
    return Status;
}


NTSTATUS
IppCreateMulticastSessionState(
    IN HANDLE InspectHandle,
    IN PIP_SESSION_STATE State,
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *MulticastAddress,
    IN CONST IF_INDEX InterfaceIndex OPTIONAL,
    IN MULTICAST_MODE_TYPE FilterMode,
    IN ULONG SourceCount,
    IN CONST UCHAR *SourceList,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    This routine creates multicast state corresponding to the given multicast
    address and interface address and adds it to the supplied session state.

Arguments:

    InspectHandle - Supplies a handle which is relevant to ALE.

    State - Supplies a pointer to the IP_SESSION_STATE structure where the
        multicast state needs to be added.

    Compartment - Supplies the compartment.

    MulticastAddress - Supplies the multicast address for which the state needs
        to be created.

    InterfaceIndex - Supplies the interface index for which the state need
        to be created.  If the interface index is unspecified, the routine
        chooses an interface index.

    FilterMode - Supplies the mode for the multicast session state.

    SourceCount - Supplies the number of sources to add.

    SourceList - Supplies the list of souces to add.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_PENDING indicates that completion will be asynchronous.
    STATUS_SUCCESS indicates successful synchronous completion.
    Else a failure code is returned to indicate that the call failed.

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization.

--*/
{
    PIP_SET_SESSION_INFO_CONTEXT RequestContext;
    PIP_SESSION_MULTICAST_STATE MulticastState;
    PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup;
    PIP_INTERFACE Interface;
    NTSTATUS Status;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    
    ASSERT_SPIN_LOCK_HELD(&State->SpinLock);
    
    //
    // Assert that there is not any session state for this multicast address.
    //
    ASSERT(IppFindMulticastSessionState(
               State,
               Compartment,
               MulticastAddress,
               InterfaceIndex) == NULL);

    //
    // Assert that the session state will not be redundant.
    //
    ASSERT((FilterMode != MCAST_INCLUDE) || (SourceCount != 0));
    
    if (InterfaceIndex == IFI_UNSPECIFIED) {
        NL_REQUEST_JOIN_PATH JoinPathArgs = {0};
        
        JoinPathArgs.NlCompartment.Compartment = 
            (NL_COMPARTMENT *) Compartment;
        JoinPathArgs.RemoteAddress = MulticastAddress;
        
        Status = IppJoinPath(Protocol, &JoinPathArgs);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
        Interface = (PIP_INTERFACE)JoinPathArgs.Path->SourceAddress->Interface;
        IppReferenceInterface(Interface);
        IppDereferencePath((PIP_PATH) JoinPathArgs.Path);
    } else {
        //
        // Find the interface with the given interface index. 
        //
        Interface = IppFindInterfaceByIndex(Compartment, InterfaceIndex);

        if (Interface == NULL) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Error creating multicast session state: "
                       "Illegal interface %d\n", InterfaceIndex);
            return STATUS_INVALID_ADDRESS;
        }
    }

    if (InspectHandle != NULL) {
        Status = IppInspectJoin(Protocol->Level,
                                InspectHandle,
                                (PNL_INTERFACE) Interface,
                                MulticastAddress,
                                (FilterMode == MCAST_INCLUDE) ? SourceCount : 0,
                                SourceList,
                                NULL,
                                NULL);
        if (!NT_SUCCESS(Status)) {
            NetioTrace(NETIO_TRACE_NETWORK, 
                       TRACE_LEVEL_INFORMATION, 
                       "IPNG: Access denied creating multicast state\n");
            IppDereferenceInterface(Interface);
            return Status;
        }
    }

    //
    // Allocate a request context since the request may pend.
    //
    // TODO: move this allocation down inside 
    //       IppFindOrCreateLocalMulticastAddressUnderLock.
    //
    RequestContext = ExAllocatePoolWithTagPriority(NonPagedPool,
                                                   sizeof(*RequestContext),
                                                   IpGenericPoolTag,
                                                   LowPoolPriority);
    if (RequestContext == NULL) {
        goto AllocationFailure;
    }
    
    //
    // Create the session multicast state.
    //
    MulticastState = (PIP_SESSION_MULTICAST_STATE) FsbAllocate(
        MulticastSessionStatePool);
    if (MulticastState == NULL) {
        ExFreePool(RequestContext);

    AllocationFailure:
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error creating multicast session state: "
                   "Cannot allocate memory\n");
        IppDereferenceInterface(Interface);    
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize the session multicast state.
    //
    RtlZeroMemory(MulticastState, sizeof(IP_SESSION_MULTICAST_STATE));
    MulticastState->Session = State;
    MulticastState->Mode = FilterMode;
    InitializeListHead(&MulticastState->SourceList);
    // MulticastState->SourceCount = 0;
    // MulticastState->MulticastGroup = NULL;

    //
    // Add the sources to the session multicast state.
    //
    Status = IppAddSourcesToMulticastSessionState(Protocol,
                                                  MulticastState,
                                                  SourceCount,
                                                  SourceList,
                                                  AddressBytes);
    if (!NT_SUCCESS(Status)) {
        ExFreePool(RequestContext);
        IppDestroyMulticastSessionState(MulticastState);
        IppDereferenceInterface(Interface);    
        return Status;
    }

    RequestContext->SessionGroup = MulticastState;
    RequestContext->CompletionContext = CompletionContext;
    RequestContext->CompletionRoutine = CompletionRoutine;

    Status = IppFindOrCreateLocalMulticastAddress(
        MulticastAddress,
        Interface,
        RequestContext,
        &MulticastGroup);
    
    IppDereferenceInterface(Interface);
    
    if (Status != STATUS_PENDING) {
        if (NT_SUCCESS(Status)) {
            Status = IppCreateMulticastSessionStateComplete(MulticastGroup,
                                                            MulticastState,
                                                            Status);
        } else {
            //
            // IppCreateMulticastSessionStateComplete assumes we have a 
            // reference on MulticastGroup, which we don't in this case
            // (it may even be NULL).  So just destroy the multicast state
            // directly.
            //
            IppDestroyMulticastSessionState(MulticastState);
        }
        ExFreePool(RequestContext);
    }

    return Status;
}


NTSTATUS
IppModifyMulticastSessionState(
    IN HANDLE InspectHandle,
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    IN ULONG DeleteCount,
    IN CONST UCHAR *DeleteList,
    IN MULTICAST_MODE_TYPE NewMode, 
    IN ULONG AddCount,
    IN CONST UCHAR *AddList
    )
/*++

Routine Description:

    This routine modifies a given multicast group session state. It performs
    three steps in the modification process: (1) Some sources might be
    deleted from the current source list. (2) The mode might be changed (3) New
    sources might be added in the new mode. Note that some of the above steps
    can be no-ops. For instance, new sources can be added in the current mode
    by setting the DeleteCount to 0 and setting the NewMode to be the same as
    the current mode. On the other hand, if the mode needs to be changed from
    include to exclude, this routine can be called to delete all the existing
    sources, change the mode to exclude and potentially add new sources in
    exclude mode. This routine is called for all multicast state related
    requests from the network layer client.
    
Arguments:

    InspectHandle - Supplies a handle which is relevant to ALE.

    MulticastState - Supplies the multicast group session state to modify.

    DeleteCount - The number of sources to delete in the current mode. 

    DeleteList - The list of sources to delete in the current mode. 

    NewMode - The new mode for the multicast group session state. This can be
        the same as the current mode. 

    AddCount - The number of sources to add in the new mode. 

    AddList - The list of sources to add in the new mode.

Return Value:

    STATUS_SUCCESS on success or relevant error code. The routine undoes
    everything in case there is a failure. 

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization.  

--*/ 
{
    NTSTATUS Status, UndoStatus;
    MULTICAST_MODE_TYPE OldMode;
    LIST_ENTRY RemoveHandle;
    PIP_PROTOCOL Protocol = MulticastState->MulticastGroup->Interface->
        Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    
    ASSERT(((DeleteCount == 0) || (DeleteList != NULL)) &&
           ((AddCount == 0) || (AddList != NULL)));
    ASSERT(AddCount <= MAX_MULTICAST_SOURCE_COUNT);
    ASSERT(DeleteCount <= MAX_MULTICAST_SOURCE_COUNT);
    
    //
    // Call ALE if we're changing to EXCLUDE mode, or if we're
    // adding sources in INCLUDE mode.
    //
    if (((NewMode == MCAST_EXCLUDE) && (MulticastState->Mode != NewMode)) ||
        ((NewMode == MCAST_INCLUDE) && (AddCount > 0))) {
        Status =
            IppInspectJoin(
                Protocol->Level,
                InspectHandle,
                (PNL_INTERFACE) MulticastState->MulticastGroup->Interface,
                NL_ADDRESS(MulticastState->MulticastGroup),
                (NewMode == MCAST_INCLUDE) ? AddCount : 0,
                AddList,
                NULL,
                NULL);

        if (!NT_SUCCESS(Status)) {
            NetioTrace(NETIO_TRACE_NETWORK,
                       TRACE_LEVEL_INFORMATION,
                       "IPNG: Access denied changing multicast state\n");
            return Status;
        }
    }

    InitializeListHead(&RemoveHandle);
    
    //
    // Remove sources in current mode. 
    //
    Status =
        IppRemoveSourcesFromMulticastSessionState(
            MulticastState,
            DeleteCount,
            DeleteList,
            AddressBytes,
            &RemoveHandle);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Change the mode if required. 
    //
    OldMode = MulticastState->Mode;
    if (MulticastState->Mode != NewMode) {
        //
        // Mode is changing. Assert that the number of sources is 0. 
        //
        ASSERT(MulticastState->SourceCount == 0);
        MulticastState->Mode = NewMode;
    }

    //
    // Add sources in the new mode. 
    //
    Status =
        IppAddSourcesToMulticastSessionState(
            Protocol,
            MulticastState,
            AddCount, 
            AddList,
            AddressBytes);
    if (!NT_SUCCESS(Status)) {
        //
        // Undo the state change and the deletion of sources. 
        //
        MulticastState->Mode = OldMode;
        IppUndoRemoveSourcesFromMulticastSessionState(
            MulticastState,
            &RemoveHandle);
        return Status;
    }

    //
    // Tell the multicast address entry about the changes to the source list. 
    //
    Status =
        IppModifyMulticastGroup(
            MulticastState->MulticastGroup,
            OldMode,
            DeleteCount,
            DeleteList,
            NewMode, 
            AddCount,
            AddList,
            NULL);
    if (!NT_SUCCESS(Status)) {
        //
        // Failure; undo the state change, deletion of sources and addition of
        // new sources. 
        //
        MulticastState->Mode = OldMode;
        UndoStatus =
            IppRemoveSourcesFromMulticastSessionState(
                MulticastState, 
                AddCount,
                AddList,
                AddressBytes,
                NULL);
        ASSERT(NT_SUCCESS(UndoStatus));
        IppUndoRemoveSourcesFromMulticastSessionState(
            MulticastState,
            &RemoveHandle);
        return Status;
    }
    
    //
    // The modification was successfully completed. Check if the multicast
    // entry needs to be deleted. 
    //
    if ((MulticastState->Mode == MCAST_INCLUDE) &&
        (MulticastState->SourceCount == 0)) {
        //
        // Remove the reference we hold to the multicast address entry. Note
        // that if the multicast group needs to transmit some multicast
        // discovery reports, it should have added a reference for it. So, the
        // session can go away independent of the multicast discovery
        // protocol. 
        //
        IppDereferenceLocalMulticastAddress(MulticastState->MulticastGroup);
        RemoveEntryList(&MulticastState->Link);
        IppDestroyMulticastSessionState(MulticastState);
    }
    
    IppCommitRemoveSourcesFromMulticastSessionState(&RemoveHandle);
    
    return Status;
}

NTSTATUS
IppSetMulticastSessionState(
    IN HANDLE InspectHandle,
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    IN MULTICAST_MODE_TYPE Mode, 
    IN ULONG SourceCount,
    IN CONST UCHAR *SourceList
    )
/*++

Routine Description:

    This routine sets the multicast session state to a particular mode and
    source list. Note that the input to the routine is the desired state, not
    the difference from the current state. This routine computes the difference
    between the current state and the desired state and calls
    IppModifyMulticastSessionState. 

Arguments:

    InspectHandle - Supplies a handle which is relevant to ALE.

    MulticastState - Supplies a pointer to the multicast state to modify.

    Mode - Supplies the desired mode (MCAST_INCLUDE or MCAST_EXCLUDE).

    SourceCount - Supplies the number of sources in the include/exclude list. 

    SourceList - Supplies the source list. 

Return Value:

    STATUS_SUCCESS if the multicast state was modified successfully. Otherwise,
    returns the right error code. 

Caller IRQL: <= DISPATCH_LEVEL. Since the caller (network layer client) is
    responsible for serialization of calls, this function is normally called
    with a lock held at dispatch level. But there is no assumption about the
    lock being held in the function. The caller can use other mechanisms for
    serialization.  

--*/ 
{
    NTSTATUS Status;
    ULONG AddCount = 0, DeleteCount = 0, Count;
    PUCHAR AddList = NULL, DeleteList = NULL;
    PLIST_ENTRY Current;
    PIP_SESSION_MULTICAST_SOURCE Source;
    PUCHAR SourceAddress = NULL;
    ULONG AddressBytes = MulticastState->MulticastGroup->Interface->
        Compartment->Protocol->Characteristics->AddressBytes;
     
    ASSERT(SourceCount <= MAX_MULTICAST_SOURCE_COUNT);

    //
    // Initialize the delete list. This is the list of sources that need to be
    // deleted from the current source list. This list can be no bigger than
    // the current source list. 
    //
    if (MulticastState->SourceCount > 0) {
        DeleteList = NbAllocMem(AddressBytes * MulticastState->SourceCount, 
                                IpGenericPoolTag);
        if (DeleteList == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Done; 
        }
    }
        
    if (MulticastState->Mode == Mode) {
        //
        // The mode is not changing. New sources might be added to the list and
        // old sources might be deleted. Just compute the list of sources to be
        // added and/or deleted. 
        // 

        //
        // Initialize the add list. By default, it is all the sources in the
        // input. If there are sources that are already present in the current
        // source list, we will delete them from the add list later on. 
        //
        if (SourceCount > 0) {
            //
            // AddressBytes * AddCount does not overflow because SourceCount
            // has already been verified to be less than
            // MAX_MULTICAST_SOURCE_COUNT. 
            // 
            AddCount = SourceCount;
            AddList = NbAllocMem(AddressBytes * AddCount, IpGenericPoolTag);
            if (AddList == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Done;
            }
            RtlCopyMemory(AddList, SourceList, AddressBytes * AddCount);
        }
        
        //
        // Go over each source in the current source list. If the source is in
        // the add list, then remove it from the add list (it doesn't need to
        // be added; it is already in the list). If the source is not in the
        // add list, then add it to the delete list. 
        //
        for (Current = MulticastState->SourceList.Flink;
             Current != &MulticastState->SourceList;
             Current = Current->Flink) {
            Source = (PIP_SESSION_MULTICAST_SOURCE)CONTAINING_RECORD(
                Current,
                IP_SESSION_MULTICAST_SOURCE,
                Link);
            for (Count = 0; Count < AddCount; Count++) {
                SourceAddress = SOURCE_LIST_ELEMENT(AddList, 
                                                    Count, 
                                                    AddressBytes);
                if (RtlEqualMemory(IP_SESSION_MULTICAST_SOURCE_ADDRESS(Source),
                                   SourceAddress,
                                   AddressBytes)) {
                    break;
                }
            }
        
            if (Count < AddCount) {
                //
                // This source in the current source list is also in the add
                // list. There is no need to add this source, so remove it from
                // the add list.
                //
                PUCHAR FromSource = SOURCE_LIST_ELEMENT(AddList, 
                                                        AddCount - 1, 
                                                        AddressBytes);
                RtlCopyMemory(SourceAddress, FromSource, AddressBytes);
                AddCount --;
            } else {
                //
                // This source in the current list is not in the add list. It
                // needs to be deleted from the source list. So add it to the
                // delete list. 
                //
                PUCHAR ToSource = SOURCE_LIST_ELEMENT(DeleteList, 
                                                      DeleteCount,
                                                      AddressBytes);
                RtlCopyMemory(ToSource, 
                              IP_SESSION_MULTICAST_SOURCE_ADDRESS(Source),
                              AddressBytes);
                DeleteCount ++;
            }
        }

        //
        // Just call IppModifyMulticastSessionState with the add list and the
        // delete list. 
        //
        Status = IppModifyMulticastSessionState(InspectHandle,
                                                MulticastState, 
                                                DeleteCount, 
                                                DeleteList,
                                                Mode, 
                                                AddCount, 
                                                AddList);
    } else {
        //
        // The mode is changing.  All the sources in the current source list
        // need to be deleted.  All the sources in the input need to be added.
        // So, the delete list is constructed from the current source list.
        // The add list is simply the input list.  The delete list is
        // constructed by calling the IppGetMulticastSessionStateSourceList
        // function.
        //
        DeleteCount = MulticastState->SourceCount;
        IppGetMulticastSessionStateSourceList(MulticastState, DeleteList);

        //
        // Just call IppModifyMulticastSessionState with the add list (input
        // source list) and the delete list (current source list). 
        //
        Status = IppModifyMulticastSessionState(InspectHandle,
                                                MulticastState, 
                                                DeleteCount, 
                                                DeleteList,
                                                Mode, 
                                                SourceCount, 
                                                SourceList);
    }
    
  Done:
    if (DeleteList != NULL) {
        NbFreeMem(DeleteList);
    }
    if (AddList != NULL) {
        NbFreeMem(AddList);
    }

    return Status;
}

//
// Interface based state management starts here. 
//

//
// A source is allowed if at least one of the sessions includes it OR not all
// of the sessions in exclude mode exclude it. 
//
#define IS_SOURCE_ALLOWED(Source, Group)                \
    (((Source)->IncludeCount > 0) ||                    \
     ((Source)->ExcludeCount != (Group)->ExcludeCount))

#define IS_SOURCE_DELETABLE(Source)                     \
     (((Source)->IncludeCount == 0) &&                  \
      ((Source)->ExcludeCount == 0) &&                  \
      ((Source)->TransmitsLeft == 0) &&                 \
      ((Source)->MarkedForQuery == 0))

#define IS_GROUP_ALLOWED(Group)                         \
     (((Group)->ExcludeCount > 0) ||                    \
      (!IsListEmpty(&((Group)->SourceList))))

#define IS_CHANGE_TO_TYPE(Type)                         \
    (((Type) == CHANGE_TO_INCLUDE_MODE) || ((Type) == CHANGE_TO_EXCLUDE_MODE))

#define IS_ALLOW_OR_BLOCK_TYPE(Type)                       \
    (((Type) == ALLOW_NEW_SOURCES) || ((Type) == BLOCK_OLD_SOURCES))

#define IS_IN_TYPE(Type)                                \
    (((Type) == MODE_IS_INCLUDE) || ((Type) == MODE_IS_EXCLUDE))

#define UNSOLICITED_REPORT_INTERVAL IppMilliseconds(1 * SECONDS)

#define IPP_RESET_MULTICAST_TIMER(_Interface_, _Group_, _TimerType_,         \
                                  _MaxTicks_, _Ticks_, _NeverReset_)         \
    IppResetMulticastTimer((_Interface_)->Multicast##_TimerType_##TimerTable,\
                           &((_Group_)->_TimerType_##Timer),                 \
                           (_Group_),                                        \
                           (_MaxTicks_),                                     \
                           (_Ticks_),                                        \
                           (_NeverReset_))

#define IPP_CANCEL_MULTICAST_TIMER(_Interface_, _Group_, _TimerType_) \
    IppCancelMulticastTimer((_Interface_)->Multicast##_TimerType_##TimerTable,\
                            &((_Group_)->_TimerType_##Timer),                 \
                            (_Group_))

__inline
VOID
IppCancelMulticastTimer(
    IN PTIMER_TABLE TimerTable,
    IN PTIMER_ENTRY TimerEntry,
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup
    )
/*++

Routine Description:

    This routine cancels a multicast timer if it is already set. It also
    removes the reference on the multicast group that was present because of
    the timer. 

Arguments:

    TimerTable - Supplies the timer table. 

    TimerEntry - Supplies the timer entry. 

    MulticastGroup - Supplies a pointer to the multicast address. This is used
        for removing the reference in case the timer was already set.
    
Return Value:

    None.

Caller Lock:

    The interface lock is held by the caller. 

Caller IRQL: == DISPATCH_LEVEL.

--*/ 
{
    ASSERT_WRITE_LOCK_HELD(&MulticastGroup->Interface->Lock);
    
    if (TtIsTimerActive(TimerEntry)) {
        TtStopTimer(TimerTable, TimerEntry);
        IppDereferenceLocalMulticastAddressUnderLock(MulticastGroup);
    }
}
    
__inline
VOID
IppResetMulticastTimer(
    IN PTIMER_TABLE TimerTable,
    IN PTIMER_ENTRY TimerEntry,
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup, 
    IN ULONG MaxTicks,
    IN ULONG Ticks,
    IN BOOLEAN NeverReset
    )
/*++

Routine Description:

    Reset a multicast group timeout to a new value.

    There are three possibilities that are handled:
    1. If no timeout is already schecduled, the timeout is set to Ticks
    and a reference is added to the multicast group.
    2. If a timeout is scheduled for before (or at) MaxTicks, it is left alone.
    3. If a timeout is scheduled for after MaxTicks, it is restarted.

    Note that Ticks ranges between 0 to MaxTicks.

Arguments:

    TimerTable - Supplies the timer table. 

    TimerEntry - Supplies the timer entry. 

    MulticastGroup - Supplies a pointer to the multicast address. This is used
        for adding a reference in case a new timer is started. 
    
    MaxTicks - Supplies the maximum number of ticks for the new timeout. The
        timeout is reset only if the current timeout fires after MaxTicks.

    Ticks - Supplies the number of ticks for the new timeout.

    NeverReset - Supplies a boolean indicating that the timer should not be
        reset if it is already set. If this is TRUE, the value of MaxTicks is
        irrelevant because the existing timer is never going to be changed.

Return Value:

    None.

Caller Lock:

    The interface lock is held by the caller. 

Caller IRQL: == DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = MulticastGroup->Interface;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT((Ticks <= MaxTicks) || (MaxTicks == 0));
     
    if ((TtIsTimerActive(TimerEntry)) &&
        ((TtQueryTimer(TimerTable, TimerEntry) <= MaxTicks) ||
         (NeverReset))) {
        //
        // There is already a timer that fires before the new value.
        // Do nothing.
        //
        return;
    } else if (TtIsTimerActive(TimerEntry)) {
        //
        // Stop the old timer because it fires after the new timeout. 
        //
        TtStopTimer(TimerTable, TimerEntry);
    } else {
        //
        // We are setting a completely new timeout. Add a reference. 
        //
        IppReferenceLocalAddress((PIP_LOCAL_ADDRESS)MulticastGroup);
    }
    
    if ((Ticks == 0) && !Interface->MulticastWorkItemScheduled) {
        //
        // If the number of ticks is 0, we need to schedule a work item.
        // Also, acquire an interface reference to prevent premature cleanup.
        //
        IppReferenceInterface(Interface);
        
        IoQueueWorkItem(
            Interface->MulticastWorkItem, 
            IppMulticastWorkerRoutine,
            DelayedWorkQueue, 
            Interface);

        Interface->MulticastWorkItemScheduled = TRUE;
    }
  
    TtStartTimer(TimerTable, TimerEntry, Ticks);
}

VOID
IppResetAllMulticastGroups(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
    
    This routine resets the state of all multicast groups on an interface,
    stops the timers and removes any references on the multicast groups because
    of the timers. When an interface is getting deleted, the interface is
    removed from the list of interfaces and so the timer never gets processed
    for the interface. So, we need to cancel the timers. Otherwise, we will
    keep waiting for the timeout to get fired and never remove the reference
    from the multicast group. 

Arguments:

    Interface - Supplies the interface on which the multicast addresses need to
        be cleaned.

Return Value:

    None.

Caller LOCK:

    Caller holds the interface lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PVOID Pointer;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PLIST_ENTRY Current, Next;
    PIP_LOCAL_MULTICAST_ADDRESS Group;
    PIP_LOCAL_MULTICAST_SOURCE Source;

    //
    // Disable all the timers etc. Some entries might become deletable as a
    // result. 
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Pointer = IppEnumerateNlaSetEntry(
            &Interface->LocalMulticastAddressSet,
            (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Pointer == NULL) {
            break;
        }
        
        Group = (PIP_LOCAL_MULTICAST_ADDRESS)CONTAINING_RECORD(
            Pointer, IP_LOCAL_MULTICAST_ADDRESS, Link);
            
        for (Current = Group->SourceList.Flink;
             Current != &Group->SourceList;
             Current = Next) {
            Next = Current->Flink;
            Source = (PIP_LOCAL_MULTICAST_SOURCE)CONTAINING_RECORD(
                Current,
                IP_LOCAL_MULTICAST_SOURCE,
                Link);
            //
            // Do not use IppMarkOrUnmarkMulticastSourceForQuery because that
            // makes assumptions about the version of the interface. Instead,
            // just set everything to 0. 
            //
            Source->TransmitsLeft = 0;
            Source->MarkedForQuery = 0;
            if (IS_SOURCE_DELETABLE(Source)) {
                RemoveEntryList(&Source->Link);            
                NbFreeMem(Source);
            }
        }
        
        Group->ModeChangeTransmitsLeft = 0;
        Group->MaximumTransmitsLeft = 0;
        Group->MarkedForQueryCount = 0;

        //
        // Cancel all the timers. Be careful to add a reference before trying
        // to cancel the timers because cancelling timers can otherwise lead to
        // the deletion of the group. 
        //
        IppReferenceLocalAddress((PIP_LOCAL_ADDRESS)Group);
        IPP_CANCEL_MULTICAST_TIMER(Interface, Group, Report);
        IPP_CANCEL_MULTICAST_TIMER(Interface, Group, GeneralQuery);
        IPP_CANCEL_MULTICAST_TIMER(Interface, Group, SpecificQuery);
        IppDereferenceLocalMulticastAddressUnderLock(Group);
    }
}

__inline
VOID
IppMarkMulticastSourceForReport(
    IN PIP_LOCAL_MULTICAST_SOURCE Source,
    IN PIP_LOCAL_MULTICAST_ADDRESS Group
    )
/*++

Routine Description:
    
    This routine marks a source for a unsolicited report (this happens when the
    state of a source changes from allowed to not allowed or vice versa). It
    means that at least robustness variable number of reports are sent
    including this source. 

--*/ 
{
    //
    // We never mark the source if the interface is not in version 3 mode. 
    //
    ASSERT(Group->Interface->MulticastDiscoveryVersion == 
           MULTICAST_DISCOVERY_VERSION3);
    
    Source->TransmitsLeft = Group->Interface->RobustnessVariable;
    Group->MaximumTransmitsLeft = Group->Interface->RobustnessVariable;
}

__inline 
VOID
IppMarkMulticastGroupForReport(
    IN PIP_LOCAL_MULTICAST_ADDRESS Group
    )
/*++

Routine Description:
    
    This routine marks a group for an unsolicited report (this happens when the 
    state of the group changes from include to exclude or vice versa). It means
    that at least robustness variable number of mode change reports
    (CHANGE_TO_EXCLUDE_MODE or CHANGE_TO_INCLUDE_MODE) are sent for this group.

--*/ 
{
    ASSERT(Group->Interface->MulticastDiscoveryVersion == 
           MULTICAST_DISCOVERY_VERSION3);
    
    Group->ModeChangeTransmitsLeft = Group->Interface->RobustnessVariable;
    Group->MaximumTransmitsLeft = Group->Interface->RobustnessVariable;
}

__inline
VOID
IppMarkOrUnmarkMulticastSourceForQuery(
    IN PIP_LOCAL_MULTICAST_SOURCE Source,
    IN PIP_LOCAL_MULTICAST_ADDRESS Group,
    IN BOOLEAN Mark
    )
/*++

Routine Description:
    
    This routine marks (or unmarks) a source for a query response. Marking
    happens when a group-and-source specific query is received for the
    source. It means that the next time a response is sent to a
    group-and-source specific query, this source is going to be included in
    it. Unmarking happens when a source is marked and a group-specific query is
    received. 
    TODO: Split this routine into two separate routines. 

Arguments:

    Source - Supplies the source to be marked (or unmarked).

    Group - Supplies the multicast address that the source is a part of. 

    Mark - Supplies a boolean indicating whether the source is to be marked or
       unmarked. 

Lock: 

    Caller holds the interface write lock. 

--*/ 
{
    //
    // Sources are only marked if the interface is in version 3 mode. 
    //
    ASSERT(Group->Interface->MulticastDiscoveryVersion == 
           MULTICAST_DISCOVERY_VERSION3);
    
    if (Mark) {
        if (Source->MarkedForQuery == FALSE) {
            Source->MarkedForQuery = TRUE;
            Group->MarkedForQueryCount++;
        } else {
            ASSERT(Group->MarkedForQueryCount > 0);
        }
    } else {
        if (Source->MarkedForQuery == TRUE) {
            Source->MarkedForQuery = FALSE;
            ASSERT(Group->MarkedForQueryCount > 0);
            Group->MarkedForQueryCount--;
        }
    }
}

NTSTATUS
IppMarkMulticastSourcesForQuery(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN ULONG SourceCount,
    IN PUCHAR SourceList
    )
/*++

Routine Description:
    
    This routine marks a group a list of sources for a query response. In case
    the source does not already exist, one is created so that it can be
    marked. 

Arguments:

    MulticastGroup - Supplies the multicast group go modify. 

    SourceCount - Supplies the number of sources to be marked.

    SourceList - Supplies the list of sources to be marked.

Return Value:

    Returns STATUS_SUCCESS on success or the appropriate failure code. 

--*/ 
{
    ULONG Count;
    PUCHAR SourceAddress;
    PIP_LOCAL_MULTICAST_SOURCE Source;
    PIP_PROTOCOL Protocol = MulticastGroup->Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    BOOLEAN SourceMarked = FALSE;
    ASSERT(MulticastGroup->Interface->MulticastDiscoveryVersion == 
           MULTICAST_DISCOVERY_VERSION3);

    for (Count = 0; Count < SourceCount; Count++) {
        SourceAddress = SOURCE_LIST_ELEMENT(SourceList,
                                            Count,
                                            AddressBytes);
        Source = IppFindLocalMulticastSource(
            &MulticastGroup->SourceList,
            SourceAddress,
            AddressBytes);
        if (Source == NULL) {
            //
            // Create a source (just for the purpose of marking it!).  A
            // source is created only if the group is in exclude mode.  If it
            // is in include mode, the source is not allowed anyways.  So there
            // is no need to create it because we won't include it in the
            // response. 
            //
            if (MulticastGroup->ExcludeCount == 0) {
                continue;
            }

            //
            // If the Multicast group already has 
            // MAX_MULTICAST_SOURCES_CREATED_FOR_QUERY 
            // number of sources marked to be reported in the 
            // next Report then we return with 
            // STATUS_INSUFFICIENT_RESOURCES. We are using upper limit 
            // at this place as sources can be added 
            // repeatedly by an attacker using Query messages. 
            // RFC 3376 sec 9.1/RFC 3810 sec 10.1.
            //

            if (MulticastGroup->MarkedForQueryCount > 
                MAX_MULTICAST_SOURCES_CREATED_FOR_QUERY){
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            Source = NbAllocMem(Protocol->LocalMulticastSourceSize,
                                IpGenericPoolTag);
            if (Source == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(Source, Protocol->LocalMulticastSourceSize);
            RtlCopyMemory(IP_LOCAL_MULTICAST_SOURCE_ADDRESS(Source),
                          SourceAddress,
                          AddressBytes);
            InsertTailList(&MulticastGroup->SourceList, 
                           &Source->Link);
        }
        SourceMarked = TRUE;
        IppMarkOrUnmarkMulticastSourceForQuery(Source,
                                               MulticastGroup,
                                               TRUE);
    }
    //
    // If the MulticastGroup is in INCLUDE mode and the source is not present 
    // in the SourceList, it will not get Marked. 
    // In this case no timer should be set. So return a failure.
    //
    if (SourceMarked || SourceCount == 0) {
        return STATUS_SUCCESS;
    } else { 
        return STATUS_UNSUCCESSFUL;
    }
}

VOID
IppUnmarkAllMulticastSourcesForQuery(
    IN PIP_LOCAL_MULTICAST_ADDRESS Group
    )
/*++

Routine Description:
    
    This routine unmarks all the sources in a multicast group. This is done
    when a group-specific query follows a group-and-source specific query and a
    single response needs to be sent for them. Since, all sources should be
    included in the response, all the sources are unmarked. 

Arguments:

    MulticastGroup - Supplies the multicast group to modify. 

Return Value:

    None.

--*/ 
{
    PLIST_ENTRY Current, Next;
    PIP_LOCAL_MULTICAST_SOURCE Source;
    
    ASSERT(Group->Interface->MulticastDiscoveryVersion == 
           MULTICAST_DISCOVERY_VERSION3);
    
    for (Current = Group->SourceList.Flink;
         Current != &Group->SourceList;
         Current = Next) {
        Next = Current->Flink;
        Source = (PIP_LOCAL_MULTICAST_SOURCE)CONTAINING_RECORD(
            Current,
            IP_LOCAL_MULTICAST_SOURCE,
            Link);
        IppMarkOrUnmarkMulticastSourceForQuery(Source,
                                               Group,
                                               FALSE);
        if (IS_SOURCE_DELETABLE(Source)) {
            RemoveEntryList(&Source->Link);            
            NbFreeMem(Source);
        }
    }
    
    ASSERT(Group->MarkedForQueryCount == 0);
}


VOID
IppCleanSourceListOfMulticastGroup(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup
    )
/*++

Routine Description:
    
    This routine deletes any "deletable" sources from the multicast
    group state. 

Arguments:

    MulticastGroup - Supplies the (aggregate) multicast group state to be
        modified.

Return Value:

    None.

Caller Lock:

    The caller is required to hold the interface lock. 

Caller IRQL: == DISPATCH_LEVEL.

--*/ 
{
    PLIST_ENTRY Current, Next;
    PIP_LOCAL_MULTICAST_SOURCE Source;	
    //
    // Assert that the interface lock is held.
    //
    ASSERT_WRITE_LOCK_HELD(&MulticastGroup->Interface->Lock);

    //
    // Iterate over all the sources in source list.
    //
    for (Current = MulticastGroup->SourceList.Flink;
         Current != &MulticastGroup->SourceList;
         Current = Next) {
        Next = Current->Flink;   
        Source = 
            (PIP_LOCAL_MULTICAST_SOURCE) CONTAINING_RECORD(
                Current,
                IP_LOCAL_MULTICAST_SOURCE,
                Link);

        if (IS_SOURCE_DELETABLE(Source)) {
            //
            // Delete the source entry. 
            //
            RemoveEntryList(&Source->Link);
            NbFreeMem(Source);
        }
    }
}


VOID
IppRemoveSourcesFromMulticastGroup(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN MULTICAST_MODE_TYPE Mode,
    IN ULONG SourceCount,
    IN CONST UCHAR *SourceList,
    IN CONST LIST_ENTRY *SessionSources,
    IN CONST BOOLEAN DeleteFromList
    )
/*++

Routine Description:
    
    This routine removes sources (in a particular mode) from the multicast
    group state. This is called when a particular multicast group session state
    is modified and the aggregate information stored in the multicast address 
    entry needs to be modified as well. This can never fail because the caller
    makes sure that all the sources in the SourceList are already present in
    the state. 

Arguments:

    MulticastGroup - Supplies the (aggregate) multicast group state to be
        modified.

    Mode - Supplies the mode of the sources that need to be removed. 

    SourceCount - Supplies the number of sources to be deleted. 

    SourceList - Supplies the source addresses to be deleted. 

    SessionSources - Supplies the session sources to be deleted.

    NB: (SourceCount != 0) => (SourceList != NULL) || (SessionSources != NULL)
    
    DeleteFromList - Supplies TRUE, if any deletable sources are to be deleted.

Return Value:

    None.

Caller Lock:

    The caller is required to hold the interface lock. 

Caller IRQL: == DISPATCH_LEVEL.

--*/ 
{
    ULONG Count;
    PIP_LOCAL_MULTICAST_SOURCE Source;
    PUCHAR SourceAddress;
    PIP_PROTOCOL Protocol = MulticastGroup->Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    
    ASSERT((Mode == MCAST_INCLUDE) || (Mode == MCAST_EXCLUDE));
    ASSERT((SourceCount == 0) || (SourceList != NULL) || 
           (SessionSources != NULL));
    ASSERT((SourceList == NULL) || (SessionSources == NULL));
    
    //
    // Assert that the interface lock is held. 
    //
    ASSERT_WRITE_LOCK_HELD(&MulticastGroup->Interface->Lock);

    for (Count = 0; Count < SourceCount; Count++) {
        if (SourceList != NULL) {
            SourceAddress = SOURCE_LIST_ELEMENT(SourceList,
                                                Count,
                                                AddressBytes);
        } else {
            SourceAddress = IP_SESSION_MULTICAST_SOURCE_ADDRESS(
                CONTAINING_RECORD(SessionSources,
                                  IP_SESSION_MULTICAST_SOURCE,
                                  Link));
            SessionSources = SessionSources->Flink;
        }
        Source = IppFindLocalMulticastSource(
            &MulticastGroup->SourceList,
            SourceAddress,
            AddressBytes);
        ASSERT(Source != NULL);

        if (Mode == MCAST_INCLUDE) {
            Source->IncludeCount--;
        } else {
            Source->ExcludeCount--;
        }

        if (DeleteFromList) {
            //
            // The source can become deletable as a result of this change. For
            // instance, if the source was already allowed (because not every
            // socket was blocking it) and another socket unblocks it making the
            // exclude count 0, then the source is now deletable. 
            //
        
            if (IS_SOURCE_DELETABLE(Source)) {
                //
                // Delete the source entry. 
                //
                RemoveEntryList(&Source->Link);
                NbFreeMem(Source);
            }
        }
    }
    if (SourceCount > 0) {
        IppMulticastTraceEx(TRACE_LEVEL_INFORMATION, 
                            "Removed sources from multicast group", "Count", 
                            Protocol, MulticastGroup, SourceCount);
    }

}

NTSTATUS 
IppAddSourcesToMulticastGroup(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN MULTICAST_MODE_TYPE Mode,
    IN ULONG SourceCount,
    IN CONST UCHAR *SourceList,
    IN CONST LIST_ENTRY *SessionSources
    )
/*++

Routine Description:
    
    This routine adds sources (in a particular mode) to the multicast
    group state (for instance, blocking sources for a session in exclude mode
    or adding sources for a session in include mode). This is called when a
    particular multicast group session state is modified and the aggregate
    information stored in the multicast address entry needs to be modified as
    well.

Arguments:

    MulticastGroup - Supplies the (aggregate) multicast group state to be
        modified.

    Mode - Supplies the mode of the sources that need to be removed. 

    SourceCount - Supplies the number of source to be added. 

    SourceList - Supplies the source addresses to be added.

    SessionSources - Supplies the session sources to be added.

    NB: (SourceCount != 0) => (SourceList != NULL) || (SessionSources != NULL)
    
Return Value:

    STATUS_SUCCESS or failure code.

Caller Lock:

    The caller is required to hold the PIP_LOCAL_MULTICAST_ADDRESS lock. 

Caller IRQL: == DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    ULONG Count;
    PIP_LOCAL_MULTICAST_SOURCE Source;
    PUCHAR SourceAddress;
    PIP_PROTOCOL Protocol = MulticastGroup->Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;

    ASSERT((Mode == MCAST_INCLUDE) || (Mode == MCAST_EXCLUDE));
    ASSERT((SourceCount == 0) || (SourceList != NULL) || 
           (SessionSources != NULL));
    ASSERT((SourceList == NULL) || (SessionSources == NULL));
    
    //
    // Assert that the interface lock is held
    //
    ASSERT_WRITE_LOCK_HELD(&MulticastGroup->Interface->Lock);

    for (Count = 0; Count < SourceCount; Count++) {
        if (SourceList != NULL) {
            SourceAddress = SOURCE_LIST_ELEMENT(SourceList,
                                                Count,
                                                AddressBytes);
        } else {
            SourceAddress = IP_SESSION_MULTICAST_SOURCE_ADDRESS(
                CONTAINING_RECORD(SessionSources,
                                  IP_SESSION_MULTICAST_SOURCE,
                                  Link));
            SessionSources = SessionSources->Flink;
        }
        
        Source = IppFindLocalMulticastSource(
            &MulticastGroup->SourceList,
            SourceAddress,
            AddressBytes);
        if (Source == NULL) {
            //
            // Create a source entry.
            //
            Source = NbAllocMem(Protocol->LocalMulticastSourceSize, 
                                IpGenericPoolTag);
            if (Source == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Error;
            }
            RtlZeroMemory(Source, Protocol->LocalMulticastSourceSize);
            RtlCopyMemory(IP_LOCAL_MULTICAST_SOURCE_ADDRESS(Source), 
                          SourceAddress, 
                          AddressBytes);
            InsertTailList(&MulticastGroup->SourceList, 
                           &Source->Link);
        }
        
        if (Mode == MCAST_INCLUDE) {
            Source->IncludeCount++;
        } else {
            Source->ExcludeCount++;
        }

        //
        // The source cannot be deletable because we just incremented one of
        // the counts. 
        //
        ASSERT(!IS_SOURCE_DELETABLE(Source));
    }

    if (SourceCount > 0) {
        IppMulticastTraceEx(TRACE_LEVEL_INFORMATION, 
                            "Added sources to multicast group", "Count", 
                            Protocol, MulticastGroup, SourceCount);
    }
        
    return STATUS_SUCCESS;
    
  Error:
    IppMulticastTrace(TRACE_LEVEL_WARNING, 
                      "Error adding sources to multicast group", 
                      Protocol, MulticastGroup);
    
    //
    // $$REVIEW: Some sources might have been marked in the above process. The
    // marking of sources is not undone. This should be acceptable as it only
    // leads to extra reports but not inconsistent state.
    //
    IppRemoveSourcesFromMulticastGroup(
        MulticastGroup, 
        Mode, 
        Count,
        SourceList,
        SessionSources, 
        TRUE);

    return Status;
}

VOID 
IppModifyStateOfMulticastGroup(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    OUT BOOLEAN *StateChanged
    ) 
/*++

Routine Description:

    Compute new State for a multicast group and mark the 
    sources that need to be included in report for MULTICAST version 3.
    NOTE: "State" is set of all sources that are blocked (if the Group is in 
    EXCLUDE mode) or sources that are allowed (if in INCLUDE mode).
    
Arguments:

    MulticastGroup - Supplies the (aggregate) multicast group state to be
        modified.

    StateChanged - Returns TRUE if any sources are marked.
    
--*/
{
    PLIST_ENTRY Current, Next;
    PIP_LOCAL_MULTICAST_SOURCE Source;
    MULTICAST_MODE_TYPE Mode;
    BOOLEAN IsAllowed = FALSE, MemberOfState = FALSE;

    //
    // Assert that the interface lock is held
    //
    ASSERT_WRITE_LOCK_HELD(&MulticastGroup->Interface->Lock);

    if (MulticastGroup->ExcludeCount>0) { 
        Mode = MCAST_EXCLUDE;
    } else {
        Mode = MCAST_INCLUDE;
    }

    //
    // Iterate over all the sources in source list.
    //
    for (Current = MulticastGroup->SourceList.Flink;
         Current != &MulticastGroup->SourceList;
         Current = Next) {
        Next = Current->Flink;
        Source = (PIP_LOCAL_MULTICAST_SOURCE)
            CONTAINING_RECORD(
                Current,
                IP_LOCAL_MULTICAST_SOURCE,
                Link);

        // 
        // If the mode is MCAST_EXCLUDE, the list contains excluded sources.
        // Otherwise, the list is of sources that are allowed.
        //
        IsAllowed = IS_SOURCE_ALLOWED(Source, MulticastGroup);
        if ((IsAllowed && Mode == MCAST_INCLUDE) || 
            (!IsAllowed && Mode == MCAST_EXCLUDE)) {
            MemberOfState = TRUE;
        } else {
            MemberOfState = FALSE;
        }
              
        if (MemberOfState != Source->MemberOfState) {
            //
            // The source needs to be added or removed from State.
            //
            Source->MemberOfState = MemberOfState;

            //
            // If the number of mode change
            // messages scheduled is not MULTICAST_DISCOVERY_ROBUSTNESS, then 
            // mark the source. The check is just an optimization: if there are
            // MULTICAST_DISCOVERY_ROBUSTNESS messages already scheduled for 
            // the group, this source would be included in them. So, there is
            // no need to mark the source. Also, the marking of sources is
            // done only if the interface is currently in version 3 mode.
            //
            if ((MulticastGroup->Interface->MulticastDiscoveryVersion == 
                 MULTICAST_DISCOVERY_VERSION3) &&
                (MulticastGroup->ModeChangeTransmitsLeft <
                 MulticastGroup->Interface->RobustnessVariable)) {
                IppMarkMulticastSourceForReport(Source, MulticastGroup);
                *StateChanged = TRUE;
            }
        }
    }

}
    
VOID
IppReconnectMulticastAddress(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup
    )
/*++

Routine Description:

    Rejoin this multicast group, if it is reportable.  This is invoked
    when media is reconnected.

--*/
{
    PIP_INTERFACE Interface = MulticastGroup->Interface;
    
    //
    // Check if the group is reportable.
    //
    if ((Interface->Compartment->Protocol->MldLevel != MldLevelAll) ||
        (!IS_GROUP_ALLOWED(MulticastGroup)) ||
        (!Interface->Compartment->Protocol->
             IsMulticastDiscoveryAllowed(NL_ADDRESS(MulticastGroup)))) {
        return;
    }
            
    if (Interface->MulticastDiscoveryVersion == MULTICAST_DISCOVERY_VERSION3) {
        IppMarkMulticastGroupForReport(MulticastGroup);
    } else {
        //
        // Send join messages for multicast discovery version 1 and 2. The
        // number of query responses is (RobustnessVariable - 1) and not
        // RobustnessVariable because one report is sent because of
        // StateChangeReport being TRUE.  The reason for separating these
        // is that the first report is not cancellable.
        //
        MulticastGroup->StateChangeReport = TRUE;
        MulticastGroup->QueryResponses = Interface->RobustnessVariable - 1;
    }

    IPP_RESET_MULTICAST_TIMER(Interface, 
                              MulticastGroup, 
                              Report, 
                              1, 
                              1, 
                              FALSE);
}

NTSTATUS
IppModifyMulticastGroupUnderLock(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN MULTICAST_MODE_TYPE OldMode,
    IN ULONG DeleteCount,
    IN CONST UCHAR *DeleteList,
    IN MULTICAST_MODE_TYPE NewMode, 
    IN ULONG AddCount,
    IN CONST UCHAR *AddList,
    IN CONST LIST_ENTRY *SessionSources
    )
/*++

Routine Description:

    This routine modifies a given multicast group. It performs
    three steps in the modification process: (1) Some sources might be
    deleted from the current source list in the old mode. (2) The mode might be
    changed (3) New sources might be added in the new mode. Note that some of
    the above steps can be no-ops.
    
Arguments:

    MulticastGroup - Supplies the multicast group to modify.

    OldMode - Supplies the old mode for the session. 

    DeleteCount - The number of sources to delete in the old mode. 

    DeleteList - The list of sources to delete in the old mode. 

    NewMode - The new mode for the multicast group session state. This can be
        the same as the old mode. 

    AddCount - The number of sources to add in the new mode. 

    AddList - The list of sources to add in the new mode.

    SessionSources - Supplies the session sources to be added.

    NB: (AddCount != 0) => (AddList != NULL) || (SessionSources != NULL)
    
Return Value:

    STATUS_SUCCESS on success or relevant error code. The routine undoes
    everything in case there is a failure. 

Caller LOCK: 

    Caller holds the interface lock.
    
Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    NTSTATUS Status;
    BOOLEAN StateChanged = FALSE, DeleteSources = FALSE;
    BOOLEAN OldIsGroupAllowed, NewIsGroupAllowed;
    PIP_INTERFACE Interface = MulticastGroup->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    ASSERT(((DeleteCount == 0) || (DeleteList != NULL)) &&
           ((AddCount == 0) || (AddList != NULL) || (SessionSources != NULL)));

    //
    // Don't change the state for all nodes multicast group. 
    //
    if ((Protocol->MldLevel != MldLevelAll) ||
        !Interface->Compartment->Protocol->IsMulticastDiscoveryAllowed(
            NL_ADDRESS(MulticastGroup))) {
        IppMulticastTrace(TRACE_LEVEL_VERBOSE, 
                          "Not modifying group state",
                          Protocol, MulticastGroup);
        return STATUS_SUCCESS;
    }
    
    OldIsGroupAllowed = IS_GROUP_ALLOWED(MulticastGroup);
    
    //
    // Add the new sources (in the new mode). This is done first because it can
    // fail and if it fails, there is nothing to undo.
    //
    Status = IppAddSourcesToMulticastGroup(
        MulticastGroup, 
        NewMode, 
        AddCount,
        AddList,
        SessionSources);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    //
    // Change the mode if required. This is done before the removal of
    // sources because the removal can make the exclude and include count of
    // some sources go to 0. If the mode is changed after the removal, the 
    // deletion of such sources could be blocked pending the transmission of
    // state change reports for the source. If the mode change happens before
    // the removal, the state change of the sources can be taken care of by the
    // mode change report and the source entries do not have to wait for the
    // transmission of the reports. 
    //
    if (OldMode != NewMode) {
        if (OldMode == MCAST_EXCLUDE) {
            //
            // Mode changing from MCAST_EXCLUDE to MCAST_INCLUDE. If the
            // exclude count becomes 0 as a result of this change, the mode
            // needs to be changed to INCLUDE for the whole multicast group.
            //
            MulticastGroup->ExcludeCount--;
            if ((MulticastGroup->ExcludeCount == 0) && 
                (Interface->MulticastDiscoveryVersion == 
                 MULTICAST_DISCOVERY_VERSION3)) {
                IppMarkMulticastGroupForReport(MulticastGroup);
                StateChanged = TRUE;
            }
        } else {
            //
            // Mode changing from MCAST_INCLUDE to MCAST_EXCLUDE. If this is
            // the first session in EXCLUDE mode, then the mode of the
            // group changes to INCLUDE.
            //
            MulticastGroup->ExcludeCount++;
            if ((MulticastGroup->ExcludeCount == 1) &&
                (Interface->MulticastDiscoveryVersion == 
                 MULTICAST_DISCOVERY_VERSION3)) {
                IppMarkMulticastGroupForReport(MulticastGroup);
                StateChanged = TRUE;
            }
        }
    }
    
    //
    // Remove all the sources that need to be removed (in the old mode).  
    // But do not delete them from the SourceList if overall mode remains
    // unchanged as they may get included in a report. 
    // NOTE: if the mode changes, entire source State is sent in the report and
    // not just the changes.
    //
    DeleteSources = StateChanged;
    IppRemoveSourcesFromMulticastGroup(
        MulticastGroup, 
        OldMode, 
        DeleteCount,
        DeleteList,
        NULL,
        DeleteSources);

    // 
    // Update the State. Also, if the Group mode did not change, 
    // find the list of sources to included in report.
    // 
   
    IppModifyStateOfMulticastGroup(MulticastGroup, &StateChanged);

    //
    // If sources were not deleted in IppRemoveSourceFromMulticastGroup,
    // delete them now.
    //
    if (!DeleteSources) {
        IppCleanSourceListOfMulticastGroup(MulticastGroup);
    }
    
    //
    // Determine if the state changed for versions 1 and 2. Unlike version 3,
    // the state changes if the group goes to allowed or blocked state. Version
    // 3 is more fine grained. Moving from include to exclude mode is also a
    // state change. 
    //
    NewIsGroupAllowed = IS_GROUP_ALLOWED(MulticastGroup);
    if ((Interface->MulticastDiscoveryVersion != 
        MULTICAST_DISCOVERY_VERSION3) && 
        (OldIsGroupAllowed != NewIsGroupAllowed)) {
        //
        // Multicast discovery version 1 or 2. And the state of the group has
        // changed.  
        //
        if (NewIsGroupAllowed) {
            //
            // Send join messages for multicast discovery version 1 and 2.  The
            // number of query responses is (RobustnessVariable - 1) and not
            // RobustnessVariable because one report is sent because of
            // StateChangeReport being TRUE.  The reason for separating these
            // is that the first report is not cancellable.
            //
            MulticastGroup->StateChangeReport = TRUE;
            MulticastGroup->QueryResponses = Interface->RobustnessVariable - 1;
            StateChanged = TRUE;
        } else {
            //
            // Send leave messages only for multicast discovery version 2 and
            // only if the last report for the group was sent by us.
            //
            if ((Interface->MulticastDiscoveryVersion == 
                 MULTICAST_DISCOVERY_VERSION2) &&
                (MulticastGroup->MulticastReportFlag)) {
                MulticastGroup->StateChangeReport = TRUE;
                MulticastGroup->QueryResponses = 0;
                StateChanged = TRUE;
            } else {
                //
                // No need to send a leave message.  But cancel any outstanding
                // timers so that we don't send any more reports.
                //
                MulticastGroup->StateChangeReport = FALSE;
                MulticastGroup->QueryResponses = 0;
                IPP_CANCEL_MULTICAST_TIMER(Interface,
                                           MulticastGroup, 
                                           Report);
            }
        }
    }
        
    if (StateChanged == TRUE) {
        IppMulticastTrace(TRACE_LEVEL_INFORMATION, 
                          "State of multicast group changed: "
                          "Scheduling timer to send a report", 
                          Protocol, MulticastGroup);
        
        //
        // We cannot send the report here because the transport layer might be
        // holding a lock and so we cannot call the framing layer to send
        // packets. We try to schedule a work item for sending the
        // report. 
        //
        IPP_RESET_MULTICAST_TIMER(Interface,
                                  MulticastGroup, 
                                  Report,
                                  0,
                                  0, 
                                  FALSE);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
IppModifyMulticastGroup(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN MULTICAST_MODE_TYPE OldMode,
    IN ULONG DeleteCount,
    IN CONST UCHAR *DeleteList,
    IN MULTICAST_MODE_TYPE NewMode, 
    IN ULONG AddCount,
    IN CONST UCHAR *AddList,
    IN CONST LIST_ENTRY *SessionSources
    )
{
    NTSTATUS Status;
    PIP_INTERFACE Interface = MulticastGroup->Interface;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // Acquire the interface lock. 
    //
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);  
    Status = 
        IppModifyMulticastGroupUnderLock(
            MulticastGroup,
            OldMode,
            DeleteCount,
            DeleteList,
            NewMode, 
            AddCount,
            AddList,
            SessionSources
        );
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    return Status;
}

__inline 
BOOLEAN 
IppIsSourceInMulticastDiscoveryReport(
    IN MULTICAST_RECORD_TYPE Type,
    IN BOOLEAN IsGeneral,
    IN PIP_LOCAL_MULTICAST_SOURCE Source,
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup
    )
/*++

Routine Description:
    
    This routine determines if a particular source should be part of a
    multicast discovery report or not. This is based on the type of the
    multicast discovery report. 

Arguments:

    Type - Supplies the type of the multicast discovery report. 

    IsGeneral - If the report is in response to a query, indicates whether the
        query was a general query or a source-specific query. 

    Source - Supplies the source for which membership in the report is to be
        determined. 

    MulticastGroup - Supplies the multicast group that contains the source.  

Return Value:

    Returns TRUE if the source should be in the report; FALSE otherwise.

--*/ 
{
    BOOLEAN SourceAllowed = IS_SOURCE_ALLOWED(Source, MulticastGroup);

    ASSERT(MulticastGroup->Interface->MulticastDiscoveryVersion == 
           MULTICAST_DISCOVERY_VERSION3);
    
    switch (Type) {
    case ALLOW_NEW_SOURCES:
        return ((SourceAllowed) && (Source->TransmitsLeft > 0));
    case BLOCK_OLD_SOURCES:
        return ((!SourceAllowed) && (Source->TransmitsLeft > 0));
    case CHANGE_TO_INCLUDE_MODE:
        return (SourceAllowed);
    case CHANGE_TO_EXCLUDE_MODE:
        return (!SourceAllowed);
    case MODE_IS_INCLUDE:
        return ((SourceAllowed) && 
                (Source->MarkedForQuery || IsGeneral));
    case MODE_IS_EXCLUDE:
        return ((!SourceAllowed) &&
                (Source->MarkedForQuery || IsGeneral));
    default:
        ASSERT(FALSE);
    }
    return FALSE;
}

NTSTATUS
IppQueueMulticastDiscoveryRecord(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN MULTICAST_RECORD_TYPE Type,
    IN BOOLEAN IsGeneral,
    IN OUT PIP_GENERIC_LIST RecordQueue
    )
/*++

Routine Description:
 
    This routine creates a multicast discovery record entry. It looks at the
    current state of the multicast group and the type of the record to be
    created and based on that, creates a record entry (with all the sources,
    multicast address etc. in it) and queues it up.
   
Arguments:

    MulticastGroup - Supplies the multicast group for which the record needs to
        be prepared. 

    Type - Supplies the type of the record. 

    IsGeneral - If the report is being sent in response to a query, tells
        whether the query is general or source-specific. 
 
    RecordQueue - Supplies the current list of records queued. Appends the
        record created to this queue. 

Return Value:

    STATUS_SUCCESS or failure code.

Caller Lock:

    The interface lock should be held by the caller. 

Caller IRQL: 

    Called at DISPATCH_LEVEL.

--*/ 
{
    PLIST_ENTRY Current, Next;
    PIP_LOCAL_MULTICAST_SOURCE Source;
    ULONG SourceCount = 0;
    PUCHAR SourceList;
    PIP_MULTICAST_RECORD_ENTRY RecordEntry;
    MULTICAST_DISCOVERY_VERSION Version;
    PIP_PROTOCOL Protocol = MulticastGroup->Interface->Compartment->
        Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;

    ASSERT_WRITE_LOCK_HELD(&MulticastGroup->Interface->Lock);
    
    Version = MulticastGroup->Interface->MulticastDiscoveryVersion;
    ASSERT(Version == MULTICAST_DISCOVERY_VERSION3);
    
    //
    // Calculate the number of sources that go into the record.
    //
    for (Current = MulticastGroup->SourceList.Flink;
         Current != &MulticastGroup->SourceList;
         Current = Current->Flink) {
        Source = (PIP_LOCAL_MULTICAST_SOURCE)CONTAINING_RECORD(
            Current,
            IP_LOCAL_MULTICAST_SOURCE,
            Link);
        if (IppIsSourceInMulticastDiscoveryReport(
                Type,
                IsGeneral,
                Source,
                MulticastGroup)) {
            SourceCount++;
        }
    }

    //
    // If the number of sources is zero, there is no sense sending an 
    // ALLOW_NEW_SOURCES or BLOCK_OLD_SOURCES because they do not convey
    // any new information. 
    //
    // Also if timeout is due to a source-specific query, do not send if 
    // SourceCount==0 (RFC 3376:5.2) and clean the source lists.
    //
    if (SourceCount == 0) {
        if (IS_ALLOW_OR_BLOCK_TYPE(Type)) {
            return STATUS_DATA_NOT_ACCEPTED;
        }
        if (IS_IN_TYPE(Type) && !IsGeneral) {
            goto Clean;
        }
    }
 
    //
    // Create the record entry and fill in the fields.
    //
    RecordEntry = ExAllocatePoolWithTag(
        NonPagedPool, 
        MULTICAST_RECORD_ENTRY_SIZE(SourceCount, AddressBytes),
        IpGenericPoolTag);
    if (RecordEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(RecordEntry, sizeof(IP_MULTICAST_RECORD_ENTRY));
    RecordEntry->Type = Type;
    RecordEntry->SourceCount = SourceCount;
    RtlCopyMemory(MULTICAST_RECORD_ENTRY_GROUP(RecordEntry),
                  NL_ADDRESS(MulticastGroup),
                  AddressBytes);
    IppAppendToGenericList(RecordQueue, RecordEntry);

    SourceList = MULTICAST_RECORD_ENTRY_SOURCE(RecordEntry, 
                                               0,
                                               AddressBytes);
    //
    // Now go over all the sources and fill in the source addresses. 
    //
    for (Current = MulticastGroup->SourceList.Flink;
         Current != &MulticastGroup->SourceList;
         Current = Next) {
        Next = Current->Flink;
        
        Source = (PIP_LOCAL_MULTICAST_SOURCE)CONTAINING_RECORD(
                                                                            Current,
                                                                            IP_LOCAL_MULTICAST_SOURCE,
                                                                            Link);
        if (IppIsSourceInMulticastDiscoveryReport(
                Type,
                IsGeneral,
                Source,
                MulticastGroup)) {
            RtlCopyMemory(SourceList,
                          IP_LOCAL_MULTICAST_SOURCE_ADDRESS(Source),
                          AddressBytes);
            SourceList += AddressBytes;

            if (IS_ALLOW_OR_BLOCK_TYPE(Type)) {
                //
                // This source went into the allow/block report. It should have
                // been marked for a report. Also, decrement the count of
                // transmissions left. 
                //
                ASSERT(Source->TransmitsLeft > 0);
                Source->TransmitsLeft--;
            } 
        }
        //
        // Irrespective of whether the source went into the report or not,
        // decrement the count of transmissions left if this is a
        // CHANGE_TO_EXCLUDE_MODE or CHANGE_TO_INCLUDE_MODE report. This is
        // because these reports are absolute and even if they do not contain 
        // the specific source, they implicitly convey the state of the
        // source. 
        //
        if (IS_CHANGE_TO_TYPE(Type)) {
            if (Source->TransmitsLeft > 0) {
                Source->TransmitsLeft--;
            }
        }
    }

Clean:
    //
    // Clean out source lists.
    //
    for (Current = MulticastGroup->SourceList.Flink;
         Current != &MulticastGroup->SourceList;
         Current = Next) {
        Next = Current->Flink;
        Source = (PIP_LOCAL_MULTICAST_SOURCE)CONTAINING_RECORD(
            Current,
            IP_LOCAL_MULTICAST_SOURCE,
            Link);
        //
        // If this is a response to a source-specific query, unmark the
        // source. 
        //
        if (IS_IN_TYPE(Type) && !IsGeneral) {
            IppMarkOrUnmarkMulticastSourceForQuery(
                Source, 
                MulticastGroup,
                FALSE);
        }
        //
        // The source can become deletable as a result of the timeout. If the
        // only reason that the source was present was that there was an
        // outstanding report to be sent for the source, then the source can be
        // deleted now. 
        //
        if (IS_SOURCE_DELETABLE(Source)) {
            //
            // Delete the source entry. 
            //
            RemoveEntryList(&Source->Link);
            NbFreeMem(Source);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IppSendMulticastDiscoveryRecords(
    IN PIP_INTERFACE Interface, 
    IN PIP_GENERIC_LIST RecordQueue,
    IN PNL_REQUEST_SEND_DATAGRAMS SendArgs,
    IN OUT PIP_GENERIC_LIST ReportQueue
    )
/*++

Routine Description:
 
    This routine processes a list of version 3 multicast record entries,
    combines multiple records into a single report or splits a record into
    multiple reports (depending on the MTU) and queues up the resulting
    reports. The input to the routine is a list of records that need to be sent
    to the router. The output is a list of net buffer lists containing actual 
    multicast reports to be sent to the router. 
   
Arguments:

    Interface - Supplies the interface on which the reports are sent. 

    RecordQueue - Supplies a list of records to be processed.

    SendArgs - Supplies a IP_REQUEST_SEND_DATAGRAMS to be used for
        creating the reports. 

    ReportQueue - Returns a list of reports to be sent to the router. 

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:

    The interface lock should be held by the caller. 

Caller IRQL: 

    Called at DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    BOOLEAN ReportGenerated = FALSE;
    //
    // CurrentRecord points to the current record that we are
    // processing. ReadyToDeliverRecords is a list of records that can be sent
    // in a single report. In every iteration, if the record can be sent in the
    // current report, we add it to the ReadyToDeliverRecords list. If the
    // record cannot be sent in the current list, we add it back to the records
    // queue. At the end of each iteration, we process the
    // ReadyToDeliverRecords list if needed. Note that after each iteration,
    // the size of the RecordQueue or ReadyToDeliverRecords reduces.
    //
    PIP_MULTICAST_RECORD_ENTRY CurrentRecord, SplitRecord;
    ULONG CurrentSize;
    IP_GENERIC_LIST ReadyToDeliverRecords;
    ULONG ReadyToDeliverSize = 0;
    BOOLEAN SendReadyToDeliver = FALSE;
    ULONG Mtu, AllowedSources, RemainingSources;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT(Interface->MulticastDiscoveryVersion == 
           MULTICAST_DISCOVERY_VERSION3);
    ASSERT(SendArgs != NULL);
    
    RtlZeroMemory(SendArgs, sizeof(PNL_REQUEST_SEND_DATAGRAMS));

    //
    // We add a router alert option, so the size of the IPv4 header is
    // sizeof(IPV4_HEADER) + 4; the size of the IPv6 header is
    // sizeof(IPV6_HEADER) + 8.
    // REVIEW: This is sub-optimal since it uses the minimum MTU for all
    // subinterfaces, but it means that we only need to batch up the
    // records into packets once.
    //
    Mtu = Interface->MinimumNlMtu - 
        (IS_IPV4_PROTOCOL(Protocol)
         ? (sizeof(IPV4_HEADER) + SIZEOF_IP_OPT_ROUTERALERT)
         : (sizeof(IPV6_HEADER) + SIZEOF_IPV6_ROUTERALERT));
    
    IppInitializeGenericList(&ReadyToDeliverRecords);

    while (RecordQueue->Head != NULL) {
        CurrentRecord = (PIP_MULTICAST_RECORD_ENTRY)
            IppPopGenericList(RecordQueue);
        
        if (ReadyToDeliverSize > 0) {
            //
            // We already have some records in the ready to deliver report that
            // is going to be sent. 
            //
            ASSERT(ReadyToDeliverRecords.Head != NULL);
            CurrentSize = MULTICAST_RECORD_SIZE(
                Protocol, 
                CurrentRecord->SourceCount);
            if ((CurrentSize + ReadyToDeliverSize) <= Mtu) {
                //
                // Even after adding the current record to the report, the size
                // is still less than the MTU. So, just add the record to the
                // report list. 
                //
                ReadyToDeliverSize += CurrentSize;
                IppAppendToGenericList(&ReadyToDeliverRecords, CurrentRecord);
                if (RecordQueue->Head == NULL) {
                    SendReadyToDeliver = TRUE;
                }
            } else {
                // 
                // The current record cannot fit into the ready to deliver
                // report. Send the ready to deliver report. Put the current
                // record back into the record queue. This will be processed
                // in the next iteration.
                //
                SendReadyToDeliver = TRUE;
                IppAppendToGenericList(RecordQueue, CurrentRecord);
            }
        } else {
            ASSERT(ReadyToDeliverRecords.Head == NULL);
            CurrentSize = MULTICAST_REPORT_SIZE(
                Protocol, 
                CurrentRecord->SourceCount);
            if (CurrentSize <= Mtu) {
                //
                // The current report size is less than the MTU. Add it to the 
                // ReadyToDeliver list so that it can be sent along with other
                // records. 
                //
                ReadyToDeliverSize += CurrentSize;
                IppAppendToGenericList(&ReadyToDeliverRecords, CurrentRecord);
                if (RecordQueue->Head == NULL) {
                    SendReadyToDeliver = TRUE;
                }
            } else {
                //
                // The current record size is greater than the MTU. We need to
                // truncate/split the record.
                //
                AllowedSources = ((Mtu - Protocol->MulticastReportHeaderSize -
                                   Protocol->MulticastRecordHeaderSize)/
                                  AddressBytes);
                if (AllowedSources == 0) {
                    AllowedSources = 1;
                }
                RemainingSources = CurrentRecord->SourceCount - AllowedSources;

                //
                // Send the truncated record.
                //
                CurrentRecord->SourceCount = AllowedSources;
                ReadyToDeliverSize += MULTICAST_REPORT_SIZE(Protocol, 
                                                            AllowedSources);
                IppAppendToGenericList(&ReadyToDeliverRecords, CurrentRecord);
                SendReadyToDeliver = TRUE;
                
                if ((CurrentRecord->Type != MODE_IS_EXCLUDE) && 
                    (CurrentRecord->Type != CHANGE_TO_EXCLUDE_MODE)) {
                    //
                    // Queue a record for the remaining sources. 
                    //
                    ASSERT(RemainingSources > 0);
                    
                    SplitRecord = ExAllocatePoolWithTag(
                        NonPagedPool, 
                        MULTICAST_RECORD_ENTRY_SIZE(RemainingSources, 
                                                    AddressBytes),
                        IpGenericPoolTag);
                    if (SplitRecord != NULL) {                        
                        RtlZeroMemory(SplitRecord, 
                                      sizeof(IP_MULTICAST_RECORD_ENTRY));
                        SplitRecord->Type = CurrentRecord->Type;
                        SplitRecord->SourceCount = RemainingSources;
                        RtlCopyMemory(
                            MULTICAST_RECORD_ENTRY_GROUP(SplitRecord),
                            MULTICAST_RECORD_ENTRY_GROUP(CurrentRecord),
                            AddressBytes);
                        RtlCopyMemory(
                            MULTICAST_RECORD_ENTRY_SOURCE(SplitRecord,
                                                          0, 
                                                          AddressBytes),
                            MULTICAST_RECORD_ENTRY_SOURCE(CurrentRecord, 
                                                          AllowedSources,
                                                          AddressBytes),
                            AddressBytes * RemainingSources);
                        IppAppendToGenericList(RecordQueue, SplitRecord);
                    }
                }
            }
        }

        if (SendReadyToDeliver) {
            //
            // Send the ready to deliver list. 
            //
            ASSERT(ReadyToDeliverRecords.Head != NULL);
            Status = Protocol->CreateMulticastDiscoveryReport(
                Interface,
                ReadyToDeliverSize,
                ReadyToDeliverRecords.Head,
                SendArgs);
            if (NT_SUCCESS(Status)) {
                ReportGenerated = TRUE;
            }
            //
            // Delete all the records in the ready to deliver list. 
            //
            ReadyToDeliverSize = 0;
            SendReadyToDeliver = FALSE;
            while (ReadyToDeliverRecords.Head != NULL) {
                CurrentRecord = (PIP_MULTICAST_RECORD_ENTRY) 
                    IppPopGenericList(&ReadyToDeliverRecords);
                ExFreePool(CurrentRecord);
            }
        }
    }
    
    if (ReportGenerated) {
        IppAppendToGenericList(ReportQueue, SendArgs);
    }

    ASSERT(ReadyToDeliverRecords.Head == NULL);
    ASSERT(RecordQueue->Head == NULL);
    return STATUS_SUCCESS;
}

VOID
IppProcessMulticastDiscoveryTimeoutEvents(
    IN PIP_INTERFACE Interface,
    IN PTIMER_TABLE TimerTable,
    IN BOOLEAN FastTimers
    )
/*++

Routine Description:

    This routine is called when a timeout fires for one (or more)
    multicast group. The timeouts can be of various types (e.g. an unsolicited
    report timeout, a general query timeout or a specific query timeout). The
    routine decides what type of report to generate for each group, updates
    state (e.g. setting a new timer or clearing the marked flags) and sends the
    multicast discovery reports. The routine can be called as a result of a
    time or a worker thread running.

Arguments:

    Interface - Supplies the interface on which the timer fired. 

    TimerTable - Supplies the timer table for which the timeouts fired. This
        tells the routine the type of the timeout (e.g. unsolicited report
        timeout etc.). 

    FastTimers - Supplies a boolean indicating whether the timers fired as a
        result of a regular timeout or work item getting scheduled. 

Return Value:

    None.

Caller Lock:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
#define DEFAULT_ARGS_COUNT 4
    NTSTATUS Status;
    ULONG ArgsCount, FiredCount;
    LIST_ENTRY FiredList;
    NL_REQUEST_SEND_DATAGRAMS DefaultArgsList[DEFAULT_ARGS_COUNT];
    PNL_REQUEST_SEND_DATAGRAMS ArgsList;
    IP_GENERIC_LIST RecordQueue, ReportQueue;
    MULTICAST_DISCOVERY_VERSION Version;
    ULONG CurrentIndex = 0;
    PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    KLOCK_QUEUE_HANDLE LockHandle;

    IppInitializeGenericList(&RecordQueue);
    IppInitializeGenericList(&ReportQueue);
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    Version = Interface->MulticastDiscoveryVersion;

    if (FastTimers) {
        //
        // This was called as a result of a work item getting scheduled.
        // Trigger the fast timers.  
        //
        FiredCount = TtTriggerFastTimers(TimerTable, &FiredList);
    } else {
        //
        // This was a normal timeout. 
        //
        FiredCount = TtFireTimer(TimerTable, &FiredList);
    }
    
    if (FiredCount == 0) {
Done:
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        return;
    }
    
    //
    // Allocate space for the args. There can be at most one report per timeout
    // for version 1 and version 2. For version 3, since all the packets go to
    // the same destination, just one args structure is sufficient.  So, the
    // maximum number of reports is equal to the number of timers fired for
    // version 1 and version 2 and it is one for version 3. 
    //
    if (Version == MULTICAST_DISCOVERY_VERSION3) {
        ArgsCount = 1;
    } else {
        ArgsCount = FiredCount;
    }

    if (ArgsCount > DEFAULT_ARGS_COUNT) {
        //
        // Allocate space for the args. There can be at most FiredCount * 2 
        // reports (for each multicast group, we might end up sending an
        // ALLOW_NEW_SOURCES and BLOCK_OLD_SOURCES report). Just allocate the 
        // maximum number of args.  In the unlikely scenario that the number of
        // fired timers is so huge that it causes an arithmetic overflow, just
        // return with error. 
        // 
        if (ArgsCount > MAXULONG/sizeof(NL_REQUEST_SEND_DATAGRAMS)) {
            goto Done;
        }
        ArgsList =
            ExAllocatePoolWithTag(
                NonPagedPool, 
                ArgsCount * sizeof(NL_REQUEST_SEND_DATAGRAMS),
                IpGenericPoolTag);
        if (ArgsList == NULL) {
            goto Done;
        }
    } else {
        ArgsList = DefaultArgsList;
    }
    RtlZeroMemory(ArgsList, ArgsCount * sizeof(NL_REQUEST_SEND_DATAGRAMS));
        
    while (!IsListEmpty(&FiredList)) {
        MULTICAST_RECORD_TYPE Type[2];
        BOOLEAN IsGeneral = TRUE;
        ULONG ReportCount = 0, Count;
        BOOLEAN ResetTimer;
         
        if (TimerTable == Interface->MulticastReportTimerTable) {
            //
            // This is an unsolicited report timeout. If the mode change
            // transmits left is greater than zero, then send a
            // CHANGE_TO_INCLUDE_MODE or CHANGE_TO_EXCLUDE_MODE report
            // depending on whether the group is in include or exclude
            // more. Otherwise, send a ALLOW_NEW_SOURCES and BLOCK_OLD_SOURCES
            // report. 
            //
            MulticastGroup = (PIP_LOCAL_MULTICAST_ADDRESS)
                CONTAINING_RECORD(
                    RemoveHeadList(&FiredList), 
                    IP_LOCAL_MULTICAST_ADDRESS, 
                    ReportTimer.Link);
            TtInitializeTimer(&MulticastGroup->ReportTimer);

            if (Protocol->MldLevel != MldLevelAll) {
                goto NextGroup;
            }

            if (Version == MULTICAST_DISCOVERY_VERSION3) {
                //
                // Version 3 report timeout. 
                //
                ASSERT(MulticastGroup->MaximumTransmitsLeft > 0);
                MulticastGroup->MaximumTransmitsLeft--;

                if (MulticastGroup->ModeChangeTransmitsLeft > 0) {
                    if (MulticastGroup->ExcludeCount == 0) {
                        Type[ReportCount++] = CHANGE_TO_INCLUDE_MODE;
                    } else {
                        Type[ReportCount++] = CHANGE_TO_EXCLUDE_MODE;
                    }
                    MulticastGroup->ModeChangeTransmitsLeft--;
                } else {
                    Type[ReportCount++] = ALLOW_NEW_SOURCES;
                    Type[ReportCount++] = BLOCK_OLD_SOURCES;
                }

                ResetTimer = (MulticastGroup->MaximumTransmitsLeft > 0);
            } else {
                //
                // Version 1 and 2 report timeout. 
                //
                if (IS_GROUP_ALLOWED(MulticastGroup)) {
                    Type[ReportCount++] = JOIN_GROUP;
                } else {
                    ASSERT(Version != MULTICAST_DISCOVERY_VERSION1);
                    Type[ReportCount++] = LEAVE_GROUP;
                }
                if (MulticastGroup->StateChangeReport) {
                    MulticastGroup->StateChangeReport = FALSE;
                } else {
                    ASSERT(MulticastGroup->QueryResponses > 0);
                    MulticastGroup->QueryResponses--;
                }
                MulticastGroup->MulticastReportFlag = 1;
                ResetTimer = (MulticastGroup->QueryResponses > 0);
            }

            if (ResetTimer) {
                //
                // Set the next timeout.
                //
                ULONG Timeout = RandomNumber(0, UNSOLICITED_REPORT_INTERVAL);
                ULONG Ticks = IppMillisecondsToTicks(Timeout);
                
                //
                // $$REVIEW: The RFC states that timers should be set at the
                // finest granularity possible. IppMillisecondsToTicks converts
                // timers to 500ms granularity which might be too coarse.  
                //
                IPP_RESET_MULTICAST_TIMER(MulticastGroup->Interface, 
                                          MulticastGroup,
                                          Report,
                                          Ticks,
                                          Ticks,
                                          FALSE);
            }
        } else if (TimerTable == Interface->MulticastGeneralQueryTimerTable) {
            //
            // This is a general query timeout. Send a MODE_IS_EXCLUDE or
            // MODE_IS_INCLUDE report (depending on the ExcludeCount). Also,
            // this is a general query response (so all sources should be
            // included). 
            //
            ASSERT(Version == MULTICAST_DISCOVERY_VERSION3);
            MulticastGroup = (PIP_LOCAL_MULTICAST_ADDRESS) CONTAINING_RECORD(
                RemoveHeadList(&FiredList), 
                IP_LOCAL_MULTICAST_ADDRESS, 
                GeneralQueryTimer.Link);
            TtInitializeTimer(&MulticastGroup->GeneralQueryTimer);

            if (Protocol->MldLevel != MldLevelAll) {
                goto NextGroup;
            }

            IsGeneral = TRUE;
            if (MulticastGroup->ExcludeCount > 0) {
                Type[ReportCount++] = MODE_IS_EXCLUDE;
            } else {
                Type[ReportCount++] = MODE_IS_INCLUDE;
            }
        } else {
            //
            // This is a group-specific or group-and-source-specific query
            // response. Send a MODE_IS_INCLUDE or MODE_IS_EXCLUDE report
            // (depending on ExcludeCount). Also, if the number of marked
            // source is greater than 0, send a general response (all sources
            // are included), otherwise only include sources that are marked. 
            //
            ASSERT(TimerTable == Interface->MulticastSpecificQueryTimerTable);
            ASSERT(Version == MULTICAST_DISCOVERY_VERSION3);
            MulticastGroup = (PIP_LOCAL_MULTICAST_ADDRESS) CONTAINING_RECORD(
                RemoveHeadList(&FiredList), 
                IP_LOCAL_MULTICAST_ADDRESS, 
                SpecificQueryTimer.Link);
            TtInitializeTimer(&MulticastGroup->SpecificQueryTimer);

            if (Protocol->MldLevel != MldLevelAll) {
                goto NextGroup;
            }

            if (MulticastGroup->MarkedForQueryCount == 0) {
                IsGeneral = TRUE;
                if (MulticastGroup->ExcludeCount > 0) {
                    Type[ReportCount++] = MODE_IS_EXCLUDE;
                } else {
                    Type[ReportCount++] = MODE_IS_INCLUDE;
                }
            } else {
                //
                // This is a group-and-source specific query.
                // According to RFC, the mode in report is MODE_IS_INCLUDE.
                //
                IsGeneral = FALSE;
                Type[ReportCount++] = MODE_IS_INCLUDE;
            }
        }

        for (Count = 0; Count < ReportCount; Count++) {
            if (Version == MULTICAST_DISCOVERY_VERSION3) {
                Status =
                    IppQueueMulticastDiscoveryRecord(
                        MulticastGroup, 
                        Type[Count], 
                        IsGeneral,
                        &RecordQueue);
            } else {
                IP_MULTICAST_RECORD_ENTRY RecordEntry;

                RecordEntry.Next = NULL;
                RecordEntry.Type = Type[Count];
                RecordEntry.SourceCount = 0;
                RtlCopyMemory(
                    MULTICAST_RECORD_ENTRY_GROUP(&RecordEntry),
                    NL_ADDRESS(MulticastGroup), 
                    AddressBytes);

                //
                // Tell prefast about the ArgsCount and ArgsList relationship.
                //
                ASSERT(CurrentIndex < ArgsCount);
                __analysis_assume(CurrentIndex < ArgsCount);

                Status = Protocol->
                    CreateMulticastDiscoveryReport(
                        Interface, 
                        Protocol->MulticastHeaderSize, 
                        &RecordEntry,
                        &ArgsList[CurrentIndex]);

                if (NT_SUCCESS(Status)) {
                    IppAppendToGenericList(
                        &ReportQueue, 
                        &ArgsList[CurrentIndex]);
                    CurrentIndex++;
                }
            }
        }
        
NextGroup:
        //
        // Release the reference on the multicast group that we had because a
        // timer was scheduled. Note that this should be done at the end
        // because releasing the reference could delete the multicast group. 
        //
        IppDereferenceLocalMulticastAddressUnderLock(MulticastGroup);
    }
    
    if (Version == MULTICAST_DISCOVERY_VERSION3) {
        ASSERT(ReportQueue.Head == NULL);
        IppSendMulticastDiscoveryRecords(Interface, 
                                         &RecordQueue,
                                         ArgsList,
                                         &ReportQueue);
    }
    ASSERT(RecordQueue.Head == NULL);
        
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    
    //
    // Send the net buffer lists from the report queue.
    //
    while (ReportQueue.Head != NULL) {
        PNL_REQUEST_SEND_DATAGRAMS Current = ReportQueue.Head;

        ReportQueue.Head = Current->Next;
        Current->Next = NULL;
        IppSendDatagrams(Protocol, Current);
    }

    if (ArgsList != DefaultArgsList) {
        ExFreePool(ArgsList);
    }
}

VOID
IppMulticastWorkerRoutine(
    IN PDEVICE_OBJECT DeviceObject, 
    IN PVOID Context
    )
/*++

Routine Description:
     
     This routine is the worker routine that is scheduled when join/leave
     messages need to be sent immediately.

Arguments:

     DeviceObject - Supplies the device object for the driver. 

     Context - Supplies the interface for which the worker routine has been
         scheduled. 

Return Value:

    None.

Caller LOCK:

    None.

Caller IRQL: = PASSIVE_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = (PIP_INTERFACE)Context;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    PASSIVE_CODE();

    //
    // The multicast work item is no longer scheduled.  So clear the flag.
    //
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    Interface->MulticastWorkItemScheduled = FALSE;
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    IppProcessMulticastDiscoveryTimeoutEvents(
        Interface,
        Interface->MulticastReportTimerTable,
        TRUE);
    IppProcessMulticastDiscoveryTimeoutEvents(
        Interface,
        Interface->MulticastGeneralQueryTimerTable,
        TRUE);
    IppProcessMulticastDiscoveryTimeoutEvents(
        Interface,
        Interface->MulticastSpecificQueryTimerTable,
        TRUE);

    //
    // Release the reference acquired for the work-item.
    //
    IppDereferenceInterface(Interface);
}

VOID
IppMulticastDiscoveryTimeout(
    IN PIP_INTERFACE Interface,
    IN PTIMER_TABLE TimerTable
    )
/*++

Routine Description:
     
     This routine is called periodically from IpXInterfaceSetTimeout. It
     queries the timer table to see if any timers have fired and processes the
     fired timers. 

Arguments:

     Interface - Supplies the interface for which the timers have fired.

     TimerTable - Supplies the timer table for which the timers have fired.

Return Value:

    None.

Caller LOCK:

    None.

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    IppProcessMulticastDiscoveryTimeoutEvents(
        Interface,
        TimerTable,
        FALSE);
}

VOID 
IppSetMulticastDiscoveryVersion(
    IN PIP_INTERFACE Interface, 
    IN MULTICAST_DISCOVERY_VERSION Version
    )
/*++

Routine Description:
     
     This routine is called to change the multicast discovery version used by
     the interface. It sets the version and resets any outstanding timers and
     state. 

Arguments:

     Interface - Supplies the interface on which to change the version.

     Version - Supplies the version of the interface.

Return Value:

    None.

Caller Lock:

    Caller should hold the interface lock.

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    ASSERT(Interface->MulticastDiscoveryVersion != Version);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Changing multicast version of interface %u to %u\n", 
               Interface->Index, Version);
    
    Interface->MulticastDiscoveryVersion = Version;

    IppResetAllMulticastGroups(Interface);
}

VOID
IppMulticastDiscoveryVersionTimeout(
    IN PIP_INTERFACE Interface, 
    IN MULTICAST_DISCOVERY_VERSION Version
    ) 
/*++

Routine Description:
     
     This routine is called from IpvXpInterfaceSetTimeout when a particular
     multicast discovery version times out. On receiving a query of a
     particular version, the timer is started. When the timer expires, this
     function is called in order to transition to a higher version. 

Arguments:

     Interface - Supplies the interface on which to change the version.

     Version - Supplies the version of the interface.

Return Value:

    None.

Caller Lock:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    MULTICAST_DISCOVERY_VERSION NewVersion;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG CurrentTicks = IppTickCount;
    
    ASSERT(Version < MULTICAST_DISCOVERY_VERSION3);
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    //
    // Check that the timeout really fired. Between the time that the timeout
    // code read the value of MulticastQuerierPresent and called this function,
    // we could have received a query from the router which reset the
    // MulticastQuerierPresent value. Also, there could have been another
    // timeout function called in the mean time for the same version.
    //
    if ((Interface->MulticastQuerierPresent[Version] != CurrentTicks) ||
        (Interface->MulticastQuerierPresent[Version] == 0)) {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        return;
    }
    
    //
    // Version for which timeout fired cannot be less than the current
    // version. If there was a valid query received from a lower version, our
    // version should have been lower than what we currently have.
    //
    ASSERT(Version >= Interface->MulticastDiscoveryVersion);
    
    Interface->MulticastQuerierPresent[Version] = 0;

    //
    // Increase the version until we find some version for which we have
    // received a query recently.
    //
    for (NewVersion = Interface->MulticastDiscoveryVersion;
         ((NewVersion < MULTICAST_DISCOVERY_VERSION3) && 
          (Interface->MulticastQuerierPresent[NewVersion] == 0));
         NewVersion++);
    
    //
    // Never increase the version beyond the maximum configured version. 
    //
    if (NewVersion > Protocol->MaximumMldVersion) {
        NewVersion = Protocol->MaximumMldVersion;
    }
    
    if (NewVersion > Interface->MulticastDiscoveryVersion) {
        IppSetMulticastDiscoveryVersion(Interface, NewVersion);
    }

    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
}

VOID
IppProcessMulticastDiscoveryQueryForSingleGroup(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup, 
    IN BOOLEAN IsGeneral,
    IN ULONG SourceCount,
    IN PUCHAR SourceList,
    IN ULONG MaxResponseTime
    )
/*++

Routine Description:

    This routine is called from IppProcessMulticastDiscoveryQuery to process a
    query for a single multicast group. This can be called for a group-specific
    queries once. For general queries, it is called once for each group that we
    have state for. The function is responsible for setting all the state (for
    instance, marking sources for group-and-source specific queries) and
    setting the timers appropriately. This is the meat of the query
    processing. IppProcessMulticastDiscoveryQuery just calls this function
    single or multiple times depending on the type of query.

Arguments:

    MulticastGroup - Supplies the multicast group for which to process the
        query. 

    IsGeneral - Supplies a boolean indicating whether the query is a general
        query or not. Relevant only for version 3.

    SourceCount - Supplies the number of sources in the query. This is
        non-zero only for group-and-source-specific queries. 

    SourceList - Supplies the list of sources in the query.
    
    MaxResponseTime - Supplies the maximum time in milliseconds for the
        response to the query. 

Return Value:

    None.

Caller Lock:

    The interface lock is held by the caller. 

Caller IRQL: == DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_INTERFACE Interface = MulticastGroup->Interface;
    ULONG Timeout, Ticks;
    ULONG MaxResponseTicks = IppMillisecondsToTicks(MaxResponseTime);
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // According to the RFC, no responses should be sent for groups
    // that do not have recepetion state or for the all nodes multicast group. 
    //      
    if ((!IS_GROUP_ALLOWED(MulticastGroup)) ||
        (!Interface->Compartment->Protocol->IsMulticastDiscoveryAllowed(
            NL_ADDRESS(MulticastGroup)))) {
        return;
    }
            
    //
    // $$REVIEW: The RFC states that timers should be set at the finest
    // granularity possible. IppMillisecondsToTicks converts timers to 500ms
    // granularity which might be too coarse. 
    //
    Timeout = RandomNumber(0, MaxResponseTime);
    Ticks = IppMillisecondsToTicks(Timeout);
    
    if (Interface->MulticastDiscoveryVersion == MULTICAST_DISCOVERY_VERSION3) {
        if ((TtIsTimerActive(&MulticastGroup->GeneralQueryTimer)) &&
            (TtQueryTimer(
                Interface->MulticastGeneralQueryTimerTable,
                &MulticastGroup->GeneralQueryTimer) < Ticks)) {
            //
            // There is already a general query timer scheduled before the
            // current timeout. No need to do anything else. 
            //
            return;
        }
        if (IsGeneral) {
            IPP_RESET_MULTICAST_TIMER(MulticastGroup->Interface, 
                                      MulticastGroup, 
                                      GeneralQuery, 
                                      Ticks,
                                      Ticks, 
                                      FALSE);
            return;
        }
        
        //
        // Multicast discovery version 3. Group-specific and
        // group-and-source-specific query.
        //
        if (TtIsTimerActive(&MulticastGroup->SpecificQueryTimer)) {
            //
            // The specific query timer is set for the group. There is already
            // a group-specific or group-and-source-specific response scheduled
            // for the group. 
            //
            if ((SourceCount > 0) && 
                (MulticastGroup->MarkedForQueryCount > 0)) {
                //
                // The last query (for which a response is scheduled) as well
                // as the current query are group-and-source specific. Just
                // augment the list of sources that need to be in the
                // response. 
                //
                Status = IppMarkMulticastSourcesForQuery(MulticastGroup, 
                                                         SourceCount, 
                                                         SourceList);
            } else {
                //
                // Either the last query (for which a response is scheduled) 
                // or the current query is a group specific query.
                // Clear all the marked sources.  
                //
                IppUnmarkAllMulticastSourcesForQuery(MulticastGroup);
            }
        } else {
            //
            // There is no response scheduled for this group. For a 
            // group-and-source-specific query, mark all the sources that need
            // to be in the response to the query.
            //
            Status = IppMarkMulticastSourcesForQuery(MulticastGroup, 
                                                     SourceCount, 
                                                     SourceList);
                
        }
        
        if (Status == STATUS_INSUFFICIENT_RESOURCES) {
            //
            // We could not create all the sources.  Just treat this as
            // a group specific query instead of a group and source
            // specific query. 
            //
            IppUnmarkAllMulticastSourcesForQuery(MulticastGroup);
            Status = STATUS_SUCCESS;
        }

        if (NT_SUCCESS(Status)) {
            IPP_RESET_MULTICAST_TIMER(MulticastGroup->Interface, 
                                  MulticastGroup, 
                                  SpecificQuery, 
                                  Ticks,
                                  Ticks,
                                  FALSE);
        }
        return;
    }

    //
    // Multicast discovery version 1 and 2. 
    //
    if (MulticastGroup->QueryResponses == 0) {
        MulticastGroup->QueryResponses = 1;
    }
    
    if (Interface->MulticastDiscoveryVersion == 
        MULTICAST_DISCOVERY_VERSION2) {
        //
        // Multicast discovery version 2. Reset the timer if the current
        // timeout expires after MaxResponseTime.
        //
        IPP_RESET_MULTICAST_TIMER(MulticastGroup->Interface, 
                                  MulticastGroup, 
                                  Report, 
                                  MaxResponseTicks,
                                  Ticks,
                                  FALSE);
    } else {
        //
        // Multicast discovery version 1. Never reset the timer if one is
        // already running.
        //
        IPP_RESET_MULTICAST_TIMER(MulticastGroup->Interface, 
                                  MulticastGroup, 
                                  Report, 
                                  Ticks,
                                  Ticks,
                                  TRUE);
    }
}

NTSTATUS
IppProcessMulticastDiscoveryQuery(
    IN PIP_INTERFACE Interface,
    IN MULTICAST_DISCOVERY_VERSION Version,
    IN PUCHAR MulticastAddress, 
    IN ULONG SourceCount,
    IN PUCHAR SourceList,
    IN ULONG MaxResponseTime
    )
/*++

Routine Description:
     
     This routine is called when a query is received from a router. It does two
     things: (1) for general queries, it resets the multicast discovery version
     of the interface if required (2) it calls
     IppProcessMulticastDiscoveryQueryForSingleGroup once or multiple times
     with the right parameters. The meat of query processing happens there. 

Arguments:

    Interface - Supplies the interface on which the query was received. 

    MulticastAddress - Supplies the multicast address for the query. Set to
        NULL for general queries. 

    SourceCount - Supplies the number of sources in the query. This is
        non-zero only for group-and-source-specific queries. 

    SourceList - Supplies the list of sources in the query.
    
    MaxResponseTime - Supplies the maximum time in milliseconds for the
        response to the query. 

Return Value:

    STATUS_SUCCESS or failure code.

Caller Lock:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup = NULL;
    ULONG Timeout, Ticks, CurrentTicks;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PNLA_LINK Link;
    
    if (Protocol->MldLevel != MldLevelAll) {
        return STATUS_NOT_SUPPORTED;
    }
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    if (MulticastAddress == NULL) {
        //
        // Only general queries are used for determining the current multicast
        // disovery version. Set the MulticastQuerierPresent timer for the
        // version of this query. Also, if we have received a query for a lower
        // version, then reset our version to this lower value.
        //
        CurrentTicks = IppTickCount;
        if (Version <= MULTICAST_DISCOVERY_VERSION2) {
            Timeout = ((Interface->RobustnessVariable * 
                        DEFAULT_MULTICAST_DISCOVERY_QUERY_INTERVAL) +
                       ((MaxResponseTime + 4)/5));
            Ticks = IppMillisecondsToTicks(Timeout);
            Interface->MulticastQuerierPresent[Version] = CurrentTicks + Ticks;
        }
        if (Version < Interface->MulticastDiscoveryVersion) {
            IppSetMulticastDiscoveryVersion(Interface, Version);
        }
    }
    
    if (MulticastAddress == NULL) {
        //
        // This is a general query. Go over all the multicast addresses and
        // process the query for each one of them.
        // 
        ASSERT((SourceCount == 0) && (SourceList == NULL));
        IppInitializeAddressEnumerationContext(&Context);
        do {
            Link = IppEnumerateNlaSetEntry(
                &Interface->LocalMulticastAddressSet, 
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);

            if (Link == NULL) {
                break;
            }

            MulticastGroup = (PIP_LOCAL_MULTICAST_ADDRESS)
                CONTAINING_RECORD(Link, IP_LOCAL_MULTICAST_ADDRESS, Link);
            
            IppProcessMulticastDiscoveryQueryForSingleGroup(
                MulticastGroup, 
                TRUE,
                0, 
                NULL,
                MaxResponseTime);
        } while (Link != NULL);
        
        goto Done;
    }
    
    //
    // This is a group-specific query or a group-and-source-specific
    // query. Find the multicast address entry corresponding to the group. 
    //
    ASSERT(MulticastAddress != NULL);
    MulticastGroup = IppFindMulticastAddressOnInterfaceUnderLock(
        Interface, 
        MulticastAddress);
    if (MulticastGroup == NULL) {
        goto Done;
    }

    //
    // Process the query for this multicast group.
    //
    IppProcessMulticastDiscoveryQueryForSingleGroup(MulticastGroup, 
                                                    FALSE, 
                                                    SourceCount, 
                                                    SourceList, 
                                                    MaxResponseTime);

    IppDereferenceLocalMulticastAddressUnderLock(MulticastGroup);

Done:
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    
    return STATUS_SUCCESS;
}

NTSTATUS
IppProcessMulticastDiscoveryReport(
    IN PIP_INTERFACE Interface, 
    IN MULTICAST_DISCOVERY_VERSION Version,
    IN PUCHAR MulticastAddress
    )
/*++

Routine Description:
     
     This routine is called when a report is received from another host.

Arguments:

     Interface - Supplies the interface on which the report was received. 

     Version - Supplies the version of the report. 

     MulticastAddress - Supplies the multicast address in the report.

Return Value:

    STATUS_SUCCESS or failure code.

Caller Lock:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup = NULL;

    if (Interface->Compartment->Protocol->MldLevel != MldLevelAll) {
        return STATUS_NOT_SUPPORTED;
    }
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    if ((Version > Interface->MulticastDiscoveryVersion) ||
        (Interface->MulticastDiscoveryVersion == 
         MULTICAST_DISCOVERY_VERSION3)) {
        //
        // Reports are not processed if we are in version 3 mode. Further, it
        // doesn't make sense to process a report whose version is more than
        // our current version because the querier won't process it either. 
        // 
        goto Done;
    }
    
    MulticastGroup = IppFindMulticastAddressOnInterfaceUnderLock(
        Interface, 
        MulticastAddress);
    if (MulticastGroup == NULL) {
        goto Done;
    }

    //
    // Clear the flag for version 2. This indicates that we don't have to send
    // a leave report for this group because someone else is joined to the
    // group.  
    //
    if (Interface->MulticastDiscoveryVersion == MULTICAST_DISCOVERY_VERSION2) {
        MulticastGroup->MulticastReportFlag = FALSE;
    }
    
    //
    // Cancel all the responses to queries. If there is no state change report
    // outstanding as well, then cancel the timer. 
    //
    MulticastGroup->QueryResponses = 0;
    if (!MulticastGroup->StateChangeReport) {
        IPP_CANCEL_MULTICAST_TIMER(Interface, MulticastGroup, Report);
    }

    IppDereferenceLocalMulticastAddressUnderLock(MulticastGroup);

  Done:
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    return STATUS_SUCCESS;
}
