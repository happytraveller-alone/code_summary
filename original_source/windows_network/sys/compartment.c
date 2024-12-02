/*++

Copyright (c) Microsoft Corporation

Module Name:

    compartment.c

Abstract:

    This module provides protocol-independent Compartment Manager functions
    for use by the IPv4 and IPv6 modules.

Author:

    Dave Thaler (dthaler) 18-Dec-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "compartment.tmh"

#if COMPARTMENT_REFHIST
PREFERENCE_HISTORY IppCompartmentReferenceHistory;
#endif

NTSTATUS
IppStartCompartmentManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    This function initializes the state used by the Compartment Manager
    module for a given protocol.

Arguments:

    Protocol - Supplies a pointer to the global per-protocol state.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS

--*/
{
    //
    // Initialize compartment set
    //
    IppInitializeLockedList(&Protocol->CompartmentSet);
    IppDefaultStartRoutine(Protocol, IMS_COMPARTMENT_MANAGER);

    return STATUS_SUCCESS;
}

//
// Compartment management routines.
//

PIP_COMPARTMENT
IppGetCompartment(
    IN PIP_PROTOCOL Protocol,
    IN CONST NL_COMPARTMENT_ARG *Args
    )
{
    PIP_COMPARTMENT Compartment = IppCast(Args->Compartment, IP_COMPARTMENT);

    if (Compartment != NULL) {
        IppReferenceCompartment(Compartment);
    } else {
        Compartment = IppFindCompartmentById(Protocol, Args->Id);
    }
    return Compartment;
}


PIP_COMPARTMENT
IppFindCompartmentById(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID Id
    )
/*++

Routine Description:

    This routine searches a protocol's compartment set looking for
    a compartment matching a given id.  If the id is 
    UNSPECIFIED_COMPARTMENT_ID, gets the current compartment
    for the caller.

Arguments:

    Protocol - Supplies a pointer to the protocol global data.

    Id - Supplies the id of the compartment to find.

Return Value:

    Returns the compartment or NULL in case of failure. 

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

Locks:

    Assumes caller does not hold a lock on the compartment set.
    Locks the protocol's compartment set for reading.
    Caller is responsible for dereferencing Compartment on success.

--*/
{
    KIRQL OldIrql;
    PLOCKED_LIST CompartmentSet = &Protocol->CompartmentSet;
    PIP_COMPARTMENT Compartment;
    
    if (Id == UNSPECIFIED_COMPARTMENT_ID) {
        Id = NdisGetCurrentThreadCompartmentId();
    }

    RtlAcquireReadLock(&CompartmentSet->Lock, &OldIrql);
    {
        Compartment = IppFindCompartmentByIdUnderLock(CompartmentSet,
                                                      Id);
    }
    RtlReleaseReadLock(&CompartmentSet->Lock, OldIrql);

    return Compartment;
}

PIP_COMPARTMENT
IppGetNextCompartment(
    IN PIP_PROTOCOL Protocol, 
    IN COMPARTMENT_ID CompartmentId
    )
/*++

Return Value:

    This function returns the next compartment in the global list.

Arguments:

    Protocol - Supplies a pointer to the protocol global data.

    CompartmentId - Supplies the last compartment id. 

Return Value:

    Returns the compartment or NULL in case of failure. 

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

Locks:

    Assumes caller does not hold a lock on the compartment set.
    Locks the protocol's compartment set for reading.
    Caller is responsible for dereferencing the compartment pointer returned on
    success. 

--*/
{
    PLIST_ENTRY ple;
    KIRQL OldIrql;
    PLOCKED_LIST CompartmentSet = &Protocol->CompartmentSet;
    PIP_COMPARTMENT Compartment, Found = NULL;
    
    RtlAcquireReadLock(&CompartmentSet->Lock, &OldIrql);
    {
        for (ple = CompartmentSet->Set.Flink;
             ple != &CompartmentSet->Set; 
             ple = ple->Flink) {
            Compartment = (PIP_COMPARTMENT)CONTAINING_RECORD(ple, 
                                                             IP_COMPARTMENT,
                                                             Link);
            if (Compartment->CompartmentId <= CompartmentId) {
                continue;
            }
            
            if ((Found == NULL) || 
                (Compartment->CompartmentId < Found->CompartmentId)) {
                Found = Compartment;
            }
        }
    }
    if (Found != NULL) {
        IppReferenceCompartment(Found);
    }
    RtlReleaseReadLock(&CompartmentSet->Lock, OldIrql);

    return Found;
}

PIP_COMPARTMENT
IppGetFirstCompartment(
    IN PIP_PROTOCOL Protocol
    )
/*++

Return Value:

    This function returns the first compartment in the global list.

Arguments:

    Protocol - Supplies a pointer to the protocol global data.

Return Value:

    Returns the compartment or NULL in case of failure. 

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

Locks:

    Assumes caller does not hold a lock on the compartment set.
    Locks the protocol's compartment set for reading.
    Caller is responsible for dereferencing Compartment on success.

--*/
{
    return IppGetNextCompartment(Protocol, UNSPECIFIED_COMPARTMENT_ID);
}

VOID
IppFreeCompartment(
    IN PLOCKED_LIST CompartmentSet,
    IN OUT PIP_COMPARTMENT *CompartmentPtr
    )
/*++

Routine Description:

    This function uninitializes and frees a compartment structure.

Arguments:

    CompartmentSet - Supplies a pointer to the compartment set from which
        to free a compartment.

    CompartmentPtr - Supplies a pointer to a variable pointing to the 
        compartment to free, and which is NULL'ed.

Return Value:

    None.

Locks:

    Locks compartment set for writing.

Caller IRQL: 

    May be called at PASSIVE_LEVEL through DISPATCH_LEVEL.

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_COMPARTMENT Compartment;

    Compartment = *CompartmentPtr;
    *CompartmentPtr = NULL;

    ASSERT(Compartment->ReferenceCount == 0);
    IppUninitializeNliLockedSet(&Compartment->InterfaceSet);
    IppUninitializeIprLockedSet(&Compartment->RouteSet);
    IppUninitializeSpinLockedSet(&Compartment->SitePrefixSet);
    IppUninitializePathSet(&Compartment->PathSet);
    IppUninitializeSpinLockedSet(&Compartment->AddressIdentifierSet);
    IppUninitializeMfeSet(Compartment->MfeSet);

    NetioShutdownWorkQueue(&Compartment->WorkQueue);
        
    IppUninitializeEphemeralLoopbackAddressSet(
        &Compartment->EphemeralLoopbackAddressSet); 
    
    RtlAcquireWriteLock(&CompartmentSet->Lock, &LockHandle);
    {
        RemoveEntryList(&Compartment->Link);
        CompartmentSet->NumEntries--;
    }
    RtlReleaseWriteLock(&CompartmentSet->Lock, &LockHandle);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Freed %s compartment %u\n", 
               Compartment->Protocol->TraceString, 
               Compartment->CompartmentId);

    ExFreePool(Compartment);
}

VOID
IppCleanupCompartmentManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Cleanup compartment state by removing all compartments, now that
    all outstanding operations have completed.

Locks:

    When this is called, other threads should have already been stopped,
    so no locks are needed.

--*/
{
    PLOCKED_LIST CompartmentSet = &Protocol->CompartmentSet;
    PLIST_ENTRY ple, Next;
    PIP_COMPARTMENT Compartment;

    for (ple = CompartmentSet->Set.Flink;
         ple != &CompartmentSet->Set;
         ple = Next) {
        Next = ple->Flink;
        Compartment = (PIP_COMPARTMENT)CONTAINING_RECORD(ple,
                                                         IP_COMPARTMENT,
                                                         Link);
        ASSERT(Compartment->ReferenceCount == 1);
        Compartment->ReferenceCount--;
        IppFreeCompartment(CompartmentSet, &Compartment);
    }

    IppUninitializeLockedList(CompartmentSet);
}

__inline
PIP_COMPARTMENT
IppAllocateCompartment(
    IN PLOCKED_LIST CompartmentSet
    )
{
    PIP_COMPARTMENT Compartment;

    UNREFERENCED_PARAMETER(CompartmentSet);

    Compartment = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            sizeof(IP_COMPARTMENT),
            NlCompartmentPoolTag);
            
    return Compartment;
}

NTSTATUS
NTAPI
IpNlpReferenceCompartment(
    IN PNL_REQUEST_COMPARTMENT Args
    )
{
    PIP_COMPARTMENT Compartment;
    PIP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);

    Compartment = IppGetCompartment(Client->Protocol, &Args->NlCompartment);
    if (Compartment == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Reference network layer client. If the network layer client already has
    // a reference to the compartment, then guarantee that the reference
    // succeeds. 
    //
    if (Args->NlCompartment.Compartment != NULL) {
        IppReferenceValidNlClient(Client);
    } else {
        if (!IppReferenceNlClient(Client)) {
            IppDereferenceCompartment(Compartment);    
            return STATUS_NOT_FOUND;
        }
        Args->NlCompartment.Compartment = (PNL_COMPARTMENT) Compartment;
    }

    return STATUS_SUCCESS;
}


VOID
NTAPI
IpNlpDereferenceCompartment(
    IN PNL_REQUEST_COMPARTMENT Args
    )
{
    PIP_CLIENT_CONTEXT Client;    
    PIP_COMPARTMENT Compartment =
        IppCast(Args->NlCompartment.Compartment, IP_COMPARTMENT);

    //
    // Client should supply the object pointer
    // either returned from a previous request (ReferenceObject)
    // or supplied in a previous indication (AddObject).
    //
    ASSERT(Compartment != NULL);    

    //
    // Dereference network layer client.
    //
    Client = IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);
    IppDereferenceNlClient(Client);

    IppDereferenceCompartment(Compartment);    
}

VOID
IppCompartmentNotificationWorker(
    IN PSINGLE_LIST_ENTRY WorkQueueHead
    )
/*++

Routine Description:

    Notify clients of a change in an interface or an address or route.

Arguments:

    WorkQueueHead - Supplies a pointer to a structure that holds context
        information about the notification that we will be making.

Return Value:

    None.

Caller Lock:

    Caller should not hold any lock(s). Caller should hold a reference
    on either the address or the interface, depending on which is valid.

Caller IRQL:

    Must be invoked at PASSIVE level.

--*/
{
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem;

    ASSERT(WorkQueueHead != NULL);

    do {

        WorkItem = 
            CONTAINING_RECORD(
                WorkQueueHead, IP_NOTIFICATION_WORK_QUEUE_ITEM, Link);
        WorkQueueHead = WorkQueueHead->Next;

        //
        // WorkItem will be freed by the WorkerRoutine.
        //
        WorkItem->WorkerRoutine((PVOID) WorkItem);
        
    } while (WorkQueueHead != NULL);
}

VOID
IppUpdateCompartment(
    IN PIP_COMPARTMENT Compartment,
    IN ULONG DefaultHopLimit,
    IN NL_COMPARTMENT_FORWARDING Forwarding,
    IN BOOLEAN UpdateForwardingReferenceCount,
    IN BOOLEAN WeakHostSend,
    IN BOOLEAN WeakHostReceive,
    IN BOOLEAN MulticastForwarding,
    IN BOOLEAN RandomizeIdentifiers
    )
/*++

Routine Description:
    
    Update the forwarding state of the compartment.
    
Arguments:

    Compartment - Supplies the compartment to update properties of.

    DefaultHopLimit - Supplies the default hop limit for the compartment. 

    Forwarding - Supplies the new forwarding state.

    WeakHostSend - Supplies the new weak host send state.

    WeakHostReceive - Supplies the new weak host receive state.

    MulticastForwarding - Supplies the new multicast forwarding state.

    RandomizeIdentifiers - Supplies the new identifier randomization state.
    
Return Value:

    None.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    PLIST_ENTRY Head = &Compartment->InterfaceSet.Set, Next;
    PIP_INTERFACE Interface;
    KLOCK_QUEUE_HANDLE Handle1, Handle2, Handle3;
    BOOLEAN Update = FALSE;
    
    RtlAcquireWriteLock(&Compartment->InterfaceSet.Lock, &Handle1);

    if (DefaultHopLimit != (ULONG) -1) {
        Compartment->DefaultHopLimit = (UINT8) DefaultHopLimit;
    }

    if (UpdateForwardingReferenceCount) {
        if (Forwarding == ForwardingEnabled) {
            Compartment->ForwardingReferenceCount++;
        } else if (Forwarding == ForwardingDisabled) {
            Compartment->ForwardingReferenceCount--;
            if (Compartment->ForwardingReferenceCount <= 0) {
                Compartment->ForwardingReferenceCount = 0;
            } else {
                Forwarding = ForwardingUnchanged;
            }
        }
    }
    
    if (Forwarding != ForwardingUnchanged) {
        if (Compartment->Forwarding != Forwarding) {
            Compartment->Forwarding = Forwarding;
            Update = TRUE;
        }
    }

    if (WeakHostSend != (BOOLEAN) -1) {
        WeakHostSend = !!WeakHostSend;
        if (Compartment->WeakHostSend != WeakHostSend) {
            Compartment->WeakHostSend = WeakHostSend;
            Update = TRUE;
        }
    }

    if (WeakHostReceive != (BOOLEAN) -1) {
        WeakHostReceive = !!WeakHostReceive;
        if (Compartment->WeakHostReceive != WeakHostReceive) {
            Compartment->WeakHostReceive = WeakHostReceive;
            Update = TRUE;
        }
    }

    if (MulticastForwarding != (BOOLEAN) -1) {
        MulticastForwarding = !!MulticastForwarding;
        if (Compartment->MulticastForwarding != MulticastForwarding) {
            Compartment->MulticastForwarding = MulticastForwarding;
            Update = TRUE;
            if (!MulticastForwarding) {               
                //
                // Flush the mfe set.
                //
                RtlAcquireWriteLockAtDpcLevel(
                    &Compartment->MfeSet->Lock, 
                    &Handle3);
                IppDeleteMfeSetUnderLock(Compartment);
                RtlReleaseWriteLockFromDpcLevel(
                    &Compartment->MfeSet->Lock, 
                    &Handle3);
            }
        }
    }

    if (RandomizeIdentifiers != (BOOLEAN) -1) {
        Update = TRUE;
    }

    if (Update) {
        //
        // Enumerate all compartment interfaces, updating each.
        //
        for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
            Interface = (PIP_INTERFACE)
                CONTAINING_RECORD(Next, IP_INTERFACE, CompartmentLink);

            RtlAcquireWriteLockAtDpcLevel(&Interface->Lock, &Handle2);

            IppUpdateInterface(
                Interface,
                (BOOLEAN) -1,   // Advertising.
                (BOOLEAN) -1,   // AdvertiseDefaultRoute.
                (BOOLEAN) -1,   // ManagedAddressConfigurationSupported.
                (BOOLEAN) -1,   // OtherStatefulConfigurationSupported.
                (Forwarding != ForwardingUnchanged)
                ? (Compartment->Forwarding == ForwardingEnabled)
                : (BOOLEAN) -1,
                WeakHostSend,
                WeakHostReceive,
                MulticastForwarding,
                (BOOLEAN) -1,   // UseNud.
                RandomizeIdentifiers);

            RtlReleaseWriteLockFromDpcLevel(&Interface->Lock, &Handle2);
        }
    }

    RtlReleaseWriteLock(&Compartment->InterfaceSet.Lock, &Handle1);
}

VOID
IppUpdateAllProtocolCompartments(
    IN PIP_PROTOCOL Protocol,
    IN ULONG DefaultHopLimit,
    IN NL_COMPARTMENT_FORWARDING Forwarding,
    IN BOOLEAN WeakHostSend,
    IN BOOLEAN WeakHostReceive,
    IN BOOLEAN MulticastForwarding,
    IN BOOLEAN RandomizeIdentifiers
    )
/*++

Routine Description:
    
    Update the state of all the compartments associated with a protocol.
    
Arguments:

    Protocol - Supplies the protocol containing compartments to update
        properties of.

    DefaultHopLimit - Supplies the default hop limit.

    Forwarding - Supplies the new forwarding state.

    WeakHostSend - Supplies the new weak host send state.

    WeakHostReceive - Supplies the new weak host receive state.

    MulticastForwarding - Supplies the new multicast forwarding state.

    RandomizeIdentifiers - Supplies the new identifier randomization state.
    
Return Value:

    None.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PLOCKED_LIST CompartmentSet = &Protocol->CompartmentSet;
    PLIST_ENTRY Link, Head = &CompartmentSet->Set;

    RtlAcquireWriteLock(&CompartmentSet->Lock, &LockHandle);
    
    for (Link = Head->Flink; Link != Head; Link = Link->Flink) {
        IppUpdateCompartment(
            (PIP_COMPARTMENT)
            CONTAINING_RECORD(Link, IP_COMPARTMENT, Link),
            DefaultHopLimit,
            Forwarding,
            FALSE,
            WeakHostSend,
            WeakHostReceive,
            MulticastForwarding,
            RandomizeIdentifiers);
    }
    
    RtlReleaseWriteLock(&CompartmentSet->Lock, &LockHandle);
}


NTSTATUS
IppValidateCompartmentRwParameters(
    IN PNL_COMPARTMENT_RW Data
    )
/*++

Routine Description:

    This routine validates compartment RW data.  This is called while
    validating NSI calls and while intiializing the compartment.    
    
Arguments:

    Data - Supplies the compartment RW data. 

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    if ((Data->DefaultHopLimit != (ULONG) -1) &&
        (Data->DefaultHopLimit > 255)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if ((Data->Forwarding != ForwardingUnchanged) && 
        ((Data->Forwarding < ForwardingEnabled) || 
         (Data->Forwarding > ForwardingPartiallyEnabled))) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}


PIP_COMPARTMENT
IppFindCompartmentByIdUnderLock(
    IN PLOCKED_LIST CompartmentSet,
    IN COMPARTMENT_ID Id
    )
/*++

Routine Description:

    This routine searches a protocol's compartment set looking for
    a compartment matching a given id.

Arguments:

    CompartmentSet - Supplies a pointer to the compartment set to search.

    Id - Supplies the id of the compartment to find.

Return Value:

    Returns the compartment or NULL in case of failure.

Caller IRQL: 

    Must be called at DISPATCH level, since a lock is held.

Caller Lock:

    Assumes caller holds a read or write lock on the compartment set.
    Caller is responsible for dereferencing Compartment on success.

--*/
{
    PIP_COMPARTMENT Curr;
    PLIST_ENTRY ple;
    PIP_COMPARTMENT Compartment = NULL;
    
    ASSERT_ANY_LOCK_HELD(&CompartmentSet->Lock);

    for (ple = CompartmentSet->Set.Flink;
         ple != &CompartmentSet->Set;
         ple = ple->Flink) {

        Curr = (PIP_COMPARTMENT)CONTAINING_RECORD(ple, IP_COMPARTMENT,
                                                  Link);
        if (Curr->CompartmentId == Id) {
            Compartment = Curr;
            IppReferenceCompartment(Compartment);
            break;
        }
    }

    return Compartment;
}

PIP_COMPARTMENT
IppCreateCompartment(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId
    )
/*++

Routine Description:

    Create a new compartment and insert it into the protocol's
    compartment set.

Arguments:

    Protocol - Supplies a pointer to the protocol's global data.

    CompartmentId - Supplies the id of the compartment to create.

Return Value:

    Returns the compartment or NULL on failure. 

Caller Lock:

    Assumes caller holds write lock on compartment list.

Caller IRQL:

    Must be called at DISPATCH_LEVEL, since lock is held.

--*/
{
    PIP_COMPARTMENT Compartment;
    NTSTATUS Status;
    PLOCKED_LIST CompartmentSet = &Protocol->CompartmentSet;

    ASSERT_WRITE_LOCK_HELD(&CompartmentSet->Lock);

    Compartment = IppAllocateCompartment(CompartmentSet);
    if (Compartment == NULL) {
        return NULL;
    }
    RtlZeroMemory(Compartment, sizeof(IP_COMPARTMENT));
    Compartment->Signature = IP_COMPARTMENT_SIGNATURE;

    Status = IppInitializeNliLockedSet(&Compartment->InterfaceSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorInterfaceSet;
    }
    Status =
        IppInitializeIprLockedSet(
            &Compartment->RouteSet, Protocol->RouteKeySize);
    if (!NT_SUCCESS(Status)) {
        goto ErrorRouteSet;
    }
    Status = IppInitializeSpinLockedSet(&Compartment->SitePrefixSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorSitePrefixSet;
    }
    Status = IppInitializePathSet(&Compartment->PathSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorPathSet;
    }

    Status = IppInitializeSpinLockedSet(&Compartment->AddressIdentifierSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorAddressIdentifierSet;
    }

    Status = IppInitializeMfeSet(&Compartment->MfeSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorMfeSet;
    }

    Status = 
        IppInitializeEphemeralLoopbackAddressSet(
            &Compartment->EphemeralLoopbackAddressSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorEphemeralAddressSet;
    }
    
    Status = 
        NetioInitializeWorkQueue(
            &Compartment->WorkQueue, 
            IppCompartmentNotificationWorker, 
            NULL, 
            IppDeviceObject);
    if (!NT_SUCCESS(Status)) {
        goto ErrorWorkQueue;
    }

    Compartment->CompartmentId = CompartmentId;
    Compartment->Forwarding = Protocol->EnableForwarding;
    Compartment->ForwardingReferenceCount = 0;
    
    Compartment->Flags = 0;
    Compartment->MulticastForwarding = Protocol->EnableMulticastForwarding;
    Compartment->DefaultHopLimit = Protocol->DefaultHopLimit;
    Compartment->LoopbackIndex = 0;
    Compartment->Protocol = Protocol;

    Compartment->RecalculationTimer = 0;
    Compartment->ForceRouterAdvertisement = FALSE;
        
    //
    // One reference is held by the cache, one for our caller.
    //
    Compartment->ReferenceCount = 2;

    //
    // Insert compartment at the head of the global list.
    //
    InsertHeadList(&CompartmentSet->Set, &Compartment->Link);
    CompartmentSet->NumEntries++;

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Created %s compartment %u\n", 
               Protocol->TraceString, CompartmentId);
    
    return Compartment;

ErrorWorkQueue:
    IppUninitializeEphemeralLoopbackAddressSet(
        &Compartment->EphemeralLoopbackAddressSet);    
ErrorEphemeralAddressSet:
    IppUninitializeMfeSet(Compartment->MfeSet);
ErrorMfeSet:
    IppUninitializeSpinLockedSet(&Compartment->AddressIdentifierSet);
ErrorAddressIdentifierSet:
    IppUninitializePathSet(&Compartment->PathSet);
ErrorPathSet:
    IppUninitializeSpinLockedSet(&Compartment->SitePrefixSet);
ErrorSitePrefixSet:
    IppUninitializeIprLockedSet(&Compartment->RouteSet);
ErrorRouteSet:
    IppUninitializeNliLockedSet(&Compartment->InterfaceSet);
ErrorInterfaceSet:
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
               "IPNG: Error creating %s compartment %u\n", 
               Protocol->TraceString, CompartmentId);

    ExFreePool(Compartment);
    return NULL;
}

PIP_COMPARTMENT
IppFindOrCreateCompartmentById(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID Id
    )
/*++

Description:

    This routine looks for a compartment with a given id, and if not
    found, creates one.

Arguments:

    Protocol - Supplies a pointer to the global protocol block.

    Id - Supplies the id of the compartment to find or create.
    
Return Value:

    Returns the compartment or NULL in case of failure.

Caller Lock:

    Assumes caller does not hold a lock on the compartment set.
    Caller is responsible for dereferencing Compartment on success.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;
    PLOCKED_LIST CompartmentSet = &Protocol->CompartmentSet;
    PIP_COMPARTMENT Compartment;
    BOOLEAN Created = FALSE;
    
    PASSIVE_CODE();

    RtlAcquireWriteLock(&CompartmentSet->Lock, &LockHandle);
    {
        Compartment = IppFindCompartmentByIdUnderLock(CompartmentSet, Id);
        if (Compartment == NULL) {
            Compartment = IppCreateCompartment(Protocol, Id);
            if (Compartment != NULL) {
                Created = TRUE;
            }
        }
    }
    RtlReleaseWriteLock(&CompartmentSet->Lock, &LockHandle);

    if (Created) {
        NL_COMPARTMENT_KEY Key = {0};
        NL_COMPARTMENT_RW Rw;

        //
        // Read persistent configuration.
        //
        Key.CompartmentId = Id;        
        Status =
            NsiGetAllParameters(
                NsiPersistent,
                Protocol->ModuleId,
                NlCompartmentObject,
                &Key, sizeof(Key),
                &Rw, sizeof(Rw),
                NULL, 0,
                NULL, 0);
        if (!NT_SUCCESS(Status)) {
            goto Done;
        }
        
        Status = IppValidateCompartmentRwParameters(&Rw);
        if (!NT_SUCCESS(Status)) {
            goto Done;
        }

        IppUpdateCompartment(
            Compartment, 
            Rw.DefaultHopLimit, 
            Rw.Forwarding,
            FALSE,
            Rw.WeakHostSend, 
            Rw.WeakHostReceive,
            (BOOLEAN) -1,
            (BOOLEAN) -1);
    }

Done:
    return Compartment;
}

NTSTATUS
IppValidateSetAllCompartmentParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will validate a set all compartment parameters request.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    Status of the validation.
    
--*/
{
    NTSTATUS Status;
    PNL_COMPARTMENT_KEY Key;
    PIP_COMPARTMENT Compartment;
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle,
                                         NMP_CLIENT_CONTEXT);

    if (Args->Action == NsiSetReset) {
        return STATUS_NOT_IMPLEMENTED;
    }

    Protocol = Client->Protocol;

    Key = (PNL_COMPARTMENT_KEY)Args->KeyStructDesc.KeyStruct;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_COMPARTMENT_KEY));
    ASSERT(Key != NULL);
    Args->ProviderTransactionContext = NULL;
    Compartment = IppFindCompartmentById(Protocol, Key->CompartmentId);
    
    switch (Args->Action) {
        case NsiSetCreateOnly:
            if (Compartment == NULL) {
                return STATUS_NOT_IMPLEMENTED;
            }

            IppDereferenceCompartment(Compartment);
            return STATUS_DUPLICATE_OBJECTID;

        case NsiSetCreateOrSet:
            if (Compartment == NULL) {
                return STATUS_NOT_IMPLEMENTED;  
            }
            break;

        case NsiSetDefault:
            if (Compartment == NULL) {
                return STATUS_NOT_FOUND;
            }
            break;

        case NsiSetDelete:
            if (Compartment != NULL) {
                IppDereferenceCompartment(Compartment);
            }
            return STATUS_NOT_IMPLEMENTED;

        default:
            if (Compartment != NULL) {
                IppDereferenceCompartment(Compartment);
            }
            return STATUS_INVALID_PARAMETER;
    }
    ASSERT(Compartment != NULL);
    //
    // Validate parameter structure.
    //
    if (Args->RwStructDesc.RwParameterStruct) {
        PNL_COMPARTMENT_RW Data =
            (PNL_COMPARTMENT_RW)Args->RwStructDesc.RwParameterStruct;

        ASSERT(Args->RwStructDesc.RwParameterStructLength == sizeof(*Data));
        
        Status = IppValidateCompartmentRwParameters(Data);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    Args->ProviderTransactionContext = Compartment;
    return STATUS_SUCCESS;
}

VOID
IppCancelSetAllCompartmentParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will cancel a validated set all parameters request.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    None.
    
--*/
{
    PIP_COMPARTMENT Compartment;

    Compartment = Args->ProviderTransactionContext;
    ASSERT(Compartment != NULL);
    IppDereferenceCompartment(Compartment);  
    Args->ProviderTransactionContext = NULL;
}

VOID
IppCommitSetAllCompartmentParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will commit a set all request validated before.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    None.
    
--*/
{
    PIP_COMPARTMENT Compartment = Args->ProviderTransactionContext;
    PNL_COMPARTMENT_RW Data =
        (PNL_COMPARTMENT_RW)Args->RwStructDesc.RwParameterStruct;

    ASSERT(Compartment != NULL);
    ASSERT(Data != NULL);

    IppUpdateCompartment(
        Compartment,
        Data->DefaultHopLimit,
        Data->Forwarding,
        FALSE,
        Data->WeakHostSend,
        Data->WeakHostReceive,
        (BOOLEAN) -1,
        (BOOLEAN) -1);
    
    IppDereferenceCompartment(Compartment);  
    Args->ProviderTransactionContext = NULL;
}

NTSTATUS
NTAPI
IpGetAllCompartmentParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a compartment.

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

Caller IRQL:

    NSI always calls this at PASSIVE level.

--*/
{
    PNL_COMPARTMENT_KEY Key;
    PIP_COMPARTMENT Compartment;
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle,
                                         NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;

    Key = (PNL_COMPARTMENT_KEY)Args->KeyStructDesc.KeyStruct;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_COMPARTMENT_KEY));
    ASSERT(Key != NULL);

    switch (Args->Action) {
    case NsiGetExact:
        Compartment = IppFindCompartmentById(Protocol, Key->CompartmentId);
        if (Compartment == NULL) {
            return STATUS_NOT_FOUND;
        }
        break;

    case NsiGetFirst:
        Compartment = IppGetFirstCompartment(Protocol);
        if (Compartment == NULL) {
            return STATUS_NO_MORE_ENTRIES;
        }
        break;

    case NsiGetNext:
        Compartment = IppGetNextCompartment(Protocol, Key->CompartmentId);
        if (Compartment == NULL) {
            return STATUS_NO_MORE_ENTRIES;
        }
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    ASSERT(Compartment != NULL);
    if (Args->Action != NsiGetExact) {
        Key->CompartmentId = Compartment->CompartmentId;
    }

    if (Args->StructDesc.RwParameterStruct) {
        NL_COMPARTMENT_RW Data = {0};

        ASSERT(Args->StructDesc.RwParameterStructLength == sizeof(Data));

        Data.Forwarding = Compartment->Forwarding;
        Data.WeakHostSend = Compartment->WeakHostSend;
        Data.WeakHostReceive = Compartment->WeakHostReceive;
        Data.DefaultHopLimit = Compartment->DefaultHopLimit;
        
        RtlCopyMemory(Args->StructDesc.RwParameterStruct,
                      &Data,
                      Args->StructDesc.RwParameterStructLength);
    }

    if (Args->StructDesc.RoDynamicParameterStruct) {
        NL_COMPARTMENT_ROD Data;
        KIRQL OldIrql;
        
        ASSERT(Args->StructDesc.RoDynamicParameterStructLength == 
               sizeof(Data));
        
        Data.InterfaceCount = Compartment->InterfaceSet.NumEntries;

        RtlAcquireScalableReadLock(&Compartment->RouteSet.Lock, &OldIrql);
        Data.RouteCount = PtGetNumNodes(Compartment->RouteSet.Tree);
        RtlReleaseScalableReadLock(&Compartment->RouteSet.Lock, OldIrql);

        Data.DestinationCacheEntryCount = 
            RtlTotalEntriesHashTable(&Compartment->PathSet.Table);
        Data.UnicastAddressCount = Compartment->AddressIdentifierSet.NumEntries;
        
        RtlCopyMemory(Args->StructDesc.RoDynamicParameterStruct,
                      &Data,
                      Args->StructDesc.RoDynamicParameterStructLength);
    }
        
    Args->StructDesc.RoStaticParameterStructLength = 0;

    IppDereferenceCompartment(Compartment);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IpSetAllCompartmentParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function sets all public read-write parameters of a compartment.

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

Caller IRQL:

    NSI always calls this at PASSIVE level.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    switch (Args->Transaction) {
        case NsiTransactionNone:
            Status = IppValidateSetAllCompartmentParameters(Args);
            if (NT_SUCCESS(Status)) {
                IppCommitSetAllCompartmentParameters(Args);
            }
            break;
        case NsiTransactionCancel:
            IppCancelSetAllCompartmentParameters(Args);
            break;
        case NsiTransactionCommit:
            IppCommitSetAllCompartmentParameters(Args);
            break;
        case NsiTransactionValidate:
            Status = IppValidateSetAllCompartmentParameters(Args);
            break;
        default:
            Status = STATUS_INVALID_PARAMETER;
    }
    return Status;
}

NTSTATUS
NTAPI
IpSetAllCompartmentForwardingParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Enable or disable compartment-wide forwarding.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NL_COMPARTMENT_FORWARDING Forwarding;
    PIP_COMPARTMENT Compartment;
    PNL_COMPARTMENT_KEY Key =
        (PNL_COMPARTMENT_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_COMPARTMENT_KEY));

    if (Args->Transaction != NsiTransactionNone) {
        //
        // Transactions are not supported on the CompartmentForwarding object.
        //
        return STATUS_INVALID_PARAMETER;
    }

    switch (Args->Action) {
    case NsiSetCreateOrSetWithReference:
        Forwarding = ForwardingEnabled;
        break;

    case NsiSetDeleteWithReference:
        Forwarding = ForwardingDisabled;
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    //
    // All operations require a valid compartment.
    //
    Compartment = IppFindCompartmentById(Client->Protocol, Key->CompartmentId);
    if (Compartment == NULL) {
        return STATUS_NOT_FOUND;
    }

    IppUpdateCompartment(
        Compartment,
        (ULONG) -1,
        Forwarding,
        TRUE,
        (BOOLEAN) -1,
        (BOOLEAN) -1,
        (BOOLEAN) -1,
        (BOOLEAN) -1);
    
    IppDereferenceCompartment(Compartment);

    return STATUS_SUCCESS;
}        
