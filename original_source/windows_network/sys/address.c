/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    address.c

Abstract:

    This module implements the protocol-independent functions of the 
    Address Manager module.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "address.tmh"

#if ADDRESS_REFHIST
PREFERENCE_HISTORY IppAddressReferenceHistory;
#endif

ULONG LastDadTickTime = 0;

__inline
VOID
IppAddressTrace(
    IN ULONG Level, 
    IN CONST UCHAR *Message, 
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *Address, 
    IN ULONG Index
    )
{
    if (IS_IPV4_PROTOCOL(Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: [%u] %s (%!IPV4!)\n", 
                   Index, 
                   Message, 
                   Address);
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: [%u] %s (%!IPV6!)\n", 
                   Index,
                   Message, 
                   Address);
    }
}

VOID
IppCleanupAddressManager(
    IN PIP_PROTOCOL Protocol
    )
{
    //
    // We can only stop the Address Manager after the FL providers
    // have removed all interfaces.
    //
    ASSERT(Protocol->GlobalInterfaceSet.NumEntries == 0);
    ASSERT(Protocol->ModuleStatus & IMS_ADDRESS_MANAGER);

    IppUninitializeBlockType(&Protocol->LocalUnicastAddressBlockType);
    if (Protocol->LocalAnycastAddressBlockType.Pool != NULL) {
        IppUninitializeBlockType(&Protocol->LocalAnycastAddressBlockType);
    }
    if (Protocol->LocalBroadcastAddressBlockType.Pool != NULL) {
        IppUninitializeBlockType(&Protocol->LocalBroadcastAddressBlockType);
    }
    
    FsbDestroyPool(Protocol->LocalMulticastAddressPool);
}

PIP_ADDRESS_IDENTIFIER 
IppFindOrCreateLocalAddressIdentifier(
    IN PIP_COMPARTMENT Compartment,
    IN CONST CHAR *Address, 
    IN SCOPE_ID ScopeId
    )
/*++

Routine Description:

    This routine returns a local address identifier for the given address and
    scope ID.  It tries to first find the identifier in the per-compartment
    address identifier table.  If found, it returns the identifier with a
    reference.  If no identifier is found, then it creates a new one and adds
    it to the table.  
    
Arguments:

    Compartment - Supplies the compartment in which to find or create the local
        address identifier. 

    Address - Supplies the address. 

    ScopeId - Supplies the scope ID of the address. 

Return Value:

    Returns a pointer to the address identifier.  Returns NULL on failure.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    KIRQL OldIrql;
    PLIST_ENTRY Head, Current;
    PIP_ADDRESS_IDENTIFIER CurrentIdentifier, FoundIdentifier = NULL;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG Size = Protocol->Characteristics->AddressBytes;
    
    KeAcquireSpinLock(&Compartment->AddressIdentifierSet.Lock, &OldIrql);
    
    //
    // First try to find the address identifier in the compartment table. 
    //
    Head = &Compartment->AddressIdentifierSet.Set;
    for (Current = Head->Flink; Current != Head; Current = Current->Flink) {
        CurrentIdentifier = (PIP_ADDRESS_IDENTIFIER) 
            CONTAINING_RECORD(Current, IP_ADDRESS_IDENTIFIER, Link);
        if (RtlEqualMemory(CurrentIdentifier->Address, Address, Size) &&
            (CurrentIdentifier->ScopeId.Value == ScopeId.Value)) {
            FoundIdentifier = CurrentIdentifier;
            InterlockedIncrement(&FoundIdentifier->ReferenceCount);
            goto Done;
        }
    }

    //
    // The identifier was not found in the table.  Create a new one. 
    //
    ASSERT(FoundIdentifier == NULL);
    FoundIdentifier = (PIP_ADDRESS_IDENTIFIER) FsbAllocate(
        Protocol->LocalAddressIdentifierBlockType.Pool);
    if (FoundIdentifier == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "Cannot allocate address identifier\n");
        goto Done;
    }
    RtlZeroMemory(FoundIdentifier, sizeof(*FoundIdentifier));
    FoundIdentifier->Address = 
        ((PUCHAR) FoundIdentifier) + sizeof(IP_ADDRESS_IDENTIFIER);
    FoundIdentifier->ScopeId = ScopeId;
    FoundIdentifier->ReferenceCount = 1;
    RtlCopyMemory((PUCHAR) FoundIdentifier->Address, Address, Size);
    InsertTailList(&Compartment->AddressIdentifierSet.Set,
                   &FoundIdentifier->Link);
    Compartment->AddressIdentifierSet.NumEntries++;

Done:
    KeReleaseSpinLock(&Compartment->AddressIdentifierSet.Lock, OldIrql);
    return FoundIdentifier;
}

VOID
IppDereferenceLocalAddressIdentifier(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_ADDRESS_IDENTIFIER AddressIdentifier
    )
/*++

Routine Description:

    This routine dereferences an address identifier.  If the reference count
    goes to zero, the identifier is removed from the per-compartment address
    identifier set.
    
Arguments:

    Compartment - Supplies the compartment.

    AddressIdentifier - Supplies the address identifier. 

Return Value:

    None.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&Compartment->AddressIdentifierSet.Lock, &OldIrql);
    if (InterlockedDecrement(&AddressIdentifier->ReferenceCount) == 0) {
        RemoveEntryList(&AddressIdentifier->Link);
        Compartment->AddressIdentifierSet.NumEntries--;
        FsbFree((PUCHAR) AddressIdentifier);
    }
    KeReleaseSpinLock(&Compartment->AddressIdentifierSet.Lock, OldIrql);
}

PIP_LOCAL_MULTICAST_ADDRESS
IppAllocateLocalMulticastAddress(
    IN PIP_PROTOCOL Protocol
    )
/*++
Locks: none
--*/
{
    PIP_LOCAL_MULTICAST_ADDRESS Address;

    Address = (PIP_LOCAL_MULTICAST_ADDRESS)
        FsbAllocate(Protocol->LocalMulticastAddressPool);

    return Address;
}

#if ADDRESS_REFHIST
VOID
IppDereferenceLocalAddressWithHistory(
    __in PIP_LOCAL_ADDRESS LocalAddress,
    __in ULONG Line,
    __in PCHAR File
    )
#else
VOID
IppDereferenceLocalAddress(
    IN PIP_LOCAL_ADDRESS LocalAddress
    )
#endif
/*++

Routine Description:

    Dereferences an address added via the network layer.

Arguments:

    LocalAddress - Supplies a pointer to the address to dereference.

Locks:

    Assumer caller held a reference on the address.

--*/
{
    ASSERT(LocalAddress->ReferenceCount > 0);
    ASSERT(LocalAddress->Signature == IP_LOCAL_ADDRESS_SIGNATURE);

    switch (NL_ADDRESS_TYPE(LocalAddress)) {
    case NlatMulticast:
        IppDereferenceLocalMulticastAddress(
            (PIP_LOCAL_MULTICAST_ADDRESS) LocalAddress);
        break;
    default:
#if ADDRESS_REFHIST
        _IppDereferenceLocalAddress(LocalAddress, Line, File);
#else
        IppDereferenceAddressPrimitive(LocalAddress);
#endif
        break;
    }
}

NTSTATUS
NTAPI
IpNlpReferenceLocalAddress(
    IN PNL_REQUEST_LOCAL_ADDRESS Args
    )
{
    PIP_LOCAL_ADDRESS LocalAddress;
    PIP_COMPARTMENT Compartment;
    NL_LOCAL_ADDRESS_ARG LocalAddressArg;
    PIP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);

    LocalAddress =
        IppCast(Args->NlLocalAddress.LocalAddress, IP_LOCAL_ADDRESS);

    if (LocalAddress != NULL) {
        //
        // Fast path for when the caller already has a pointer.
        // In this case there's no need to look at the compartment, etc.
        //
        // BUG 1384550: As a quick fix, this currently allows an invalid 
        // address to continue being referenced.
        //
        IppReferenceLocalAddress(LocalAddress);
        IppReferenceValidNlClient(Client);
        return STATUS_SUCCESS;
    }

    Compartment = IppGetCompartment(Client->Protocol, &Args->NlCompartment);
    if (Compartment == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Make a local copy of the local address args so that we get
    // rid of a level of indirection after this point.
    //
    LocalAddressArg = Args->NlLocalAddress;

    LocalAddress = IppFindLocalAddress(Compartment, &LocalAddressArg);

    if (LocalAddress == NULL && 
        IppIsEphemeralAddressCandidate(
            Compartment->Protocol, 
            LocalAddressArg.Address)) {
        PIP_INTERFACE Interface = 
            IppFindInterfaceByIndex(Compartment, Compartment->LoopbackIndex);

        if (Interface != NULL) {
            IppFindOrCreateLocalEphemeralAddress(
                LocalAddressArg.Address, 
                Interface, 
                (PIP_LOCAL_UNICAST_ADDRESS *) &LocalAddress);
            IppDereferenceInterface(Interface);
        }
    }

    IppDereferenceCompartment(Compartment);

    if (LocalAddress == NULL) {
        return STATUS_NOT_FOUND;
    }
    
    //
    // Reference network layer client.
    //
    if (!IppReferenceNlClient(Client)) {
        IppDereferenceLocalAddress(LocalAddress);
        return STATUS_NOT_FOUND;
    }
    
    Args->NlLocalAddress.LocalAddress = (PNL_LOCAL_ADDRESS) LocalAddress;

    return STATUS_SUCCESS;
}


VOID
NTAPI
IpNlpDereferenceLocalAddress(
    IN PNL_REQUEST_LOCAL_ADDRESS Args
    )
{
    PIP_CLIENT_CONTEXT Client;
    PIP_LOCAL_ADDRESS LocalAddress =
        IppCast(Args->NlLocalAddress.LocalAddress, IP_LOCAL_ADDRESS);

    //
    // Client should supply the object pointer
    // either returned from a previous request (ReferenceObject)
    // or supplied in a previous indication (AddObject).
    //
    ASSERT(LocalAddress != NULL);
    
    //
    // Dereference network layer client.
    //
    Client = IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);
    IppDereferenceNlClient(Client);

    IppDereferenceLocalAddress(LocalAddress);
}


BOOLEAN
NTAPI
IpNlpValidateLocalAddress(
    IN OUT PNL_REQUEST_LOCAL_ADDRESS Args
    )
/*++

Routine Description:

    This routine validates a local address pointer.  If the address hasn't been
    deleted, it acquires another reference to the address. Otherwise, it finds
    the new NL_LOCAL_ADDRESS pointer for the address, adds a reference to the
    new pointer and returns it to the caller. 

Arguments:

    LocalAddress - Supplies the local address to validate.  In case the address
        is not valid, returns the validated address pointer. 

Return Value:

    TRUE if a reference has been taken; FALSE otherwise.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_CLIENT_CONTEXT Client;
    PIP_LOCAL_ADDRESS ValidatedLocalAddress, LocalAddress =
        IppCast(Args->NlLocalAddress.LocalAddress, IP_LOCAL_ADDRESS);

    ASSERT(LocalAddress != NULL);

    //
    // If the given local address is still valid, acquire a reference to it.
    //
    if (LocalAddress->Deleted == FALSE) {
        IppReferenceLocalAddress(LocalAddress);
        Client = IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);
        IppReferenceValidNlClient(Client);
        return TRUE;
    }

    //
    // Look for a valid entry for the local address.
    //
    ValidatedLocalAddress =
        IppFindAddressInScope(
            LocalAddress->Interface->Compartment,
            NL_ADDRESS_SCOPE_ID(LocalAddress), 
            NL_ADDRESS(LocalAddress));

    if ((ValidatedLocalAddress == NULL) &&
        IS_LOOPBACK_INTERFACE(LocalAddress->Interface) &&
        IppIsEphemeralAddressCandidate(
            LocalAddress->Interface->Compartment->Protocol,
            NL_ADDRESS(LocalAddress))) {
        IppFindOrCreateLocalEphemeralAddress(
            NL_ADDRESS(LocalAddress), 
            LocalAddress->Interface, 
            (PIP_LOCAL_UNICAST_ADDRESS *) &ValidatedLocalAddress);
    }

    //
    // If found, return the revalidated local address.
    //
    if (ValidatedLocalAddress != NULL) {
        Args->NlLocalAddress.LocalAddress = 
            (PNL_LOCAL_ADDRESS) ValidatedLocalAddress;
        Client = IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);
        IppReferenceValidNlClient(Client);
        return TRUE;
    }

    return FALSE;
}


VOID
IppCleanupLocalAddress(
    PIP_LOCAL_ADDRESS Address
    )
{
    PIP_INTERFACE Interface = Address->Interface;

    if (Address->AddressOrigin == ADDR_CONF_TEMPORARY) {
        //
        // Remove the reference on the public address. 
        // 
        PIP_LOCAL_TEMPORARY_ADDRESS TemporaryAddress;
        
        TemporaryAddress = (PIP_LOCAL_TEMPORARY_ADDRESS)Address;
        if (TemporaryAddress->PublicAddress != NULL) {
            IppDereferenceLocalUnicastAddress(
                TemporaryAddress->PublicAddress);
        }
    }
        
    IppDereferenceLocalAddressIdentifier(
        Interface->Compartment, Address->Identifier);

    FsbFree((PUCHAR)Address);

    //
    // Release the interface reference.  We do this after freeing the
    // address so that we can clean up the address block pool if this
    // is the last reference on any interface.
    //
    if (Interface != NULL) {
        IppDereferenceInterface(Interface);
    }
}

__inline
PNLA_SET
IppGetAddressSet(
    IN PIP_INTERFACE Interface, 
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    This routine returns the correct address set from the interface depending
    on the type of the address.  
    
Arguments:

    Interface - Supplies the interface.

    AddressType - Supplies the type of the address.

Return Value:

    Returns the address list from the interface.

--*/ 
{
    switch (AddressType) {
    case NlatUnicast:
        return &Interface->LocalUnicastAddressSet;
    case NlatBroadcast:
        return &Interface->LocalBroadcastAddressSet;
    case NlatAnycast:
        return &Interface->LocalAnycastAddressSet;
    default:
        ASSERT(AddressType == NlatMulticast);
        return &Interface->LocalMulticastAddressSet;
    }
}

__inline
static
NL_DAD_STATE
IppGetEffectiveDadState(
    IN PIP_LOCAL_UNICAST_ADDRESS Address
    )
/*++

Routine Description:

    Return the effective DAD state of the address for clients. An address
    may be marked as preferred internally but if the underlying interface
    is disconnected then the address is effectively deprecated for clients.

Arguments:

    Address - Supplies the address whose effective DAD state is to be 
        returned.

Return Value:

    The effective DAD state of the address.
    
--*/    
{

    if (Address->DadState == NldsPreferred) {
        if (Address->Interface->ConnectedSubInterfaces == 0) {
            return NldsDeprecated;
        }          
    }
    
    return Address->DadState;
}

__inline
ULONG
IppGetAddressEntrySize(
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    This routine returns the size of the address entry corresponding to the
    address type. 
    
Arguments:

    AddressType - Supplies the type of the address.

Return Value:

    Returns the size of the address entry for the address type. 

--*/ 
{
    switch (AddressType) {
    case NlatUnicast:
        return (sizeof(IP_LOCAL_UNICAST_ADDRESS));
    case NlatBroadcast:
        return (sizeof(IP_LOCAL_BROADCAST_ADDRESS));
    case NlatAnycast:
        return (sizeof(IP_LOCAL_ANYCAST_ADDRESS));
    case NlatMulticast:
        return (sizeof(IP_LOCAL_MULTICAST_ADDRESS));
    default:
        ASSERT(FALSE);
        return 0;
    }
}

__inline
HANDLE
IppGetAddressAllocationPool(
    IN PIP_PROTOCOL Protocol, 
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    This routine returns the allocation pool to use for the given address
    type. 
    
Arguments:

    Protocol - Supplies the interface.

    AddressType - Supplies the type of the address.

Return Value:

    Returns the allocation pool to use for the address type. 

--*/ 
{
    switch (AddressType) {
    case NlatUnicast:
        return Protocol->LocalUnicastAddressBlockType.Pool;
    case NlatBroadcast:
        return Protocol->LocalBroadcastAddressBlockType.Pool;
    case NlatMulticast:
        return Protocol->LocalMulticastAddressPool;
    default:
        ASSERT(AddressType == NlatAnycast);
        return Protocol->LocalAnycastAddressBlockType.Pool;
    }
}

VOID
IppAddOrDeletePersistentRoutes(
    __in PIP_PROTOCOL Protocol,
    IP_ADDRESS_STORAGE *UnicastAddress,
    __in ULONG PrefixLength,
    __in COMPARTMENT_ID CompartmentId,
    __in NET_IFINDEX InterfaceIndex,
    __in NSI_SET_ACTION Action
    )
/*++

Routine Description:

    Check if persistent routes need to be added when a new unicast IP address 
    is added.

Arguments:

    Family - Supplies the address family of the unicast address.

    UnicastAddress - Supplies the unicast IP address.

    PrefixLength - Supplies Onlink prefix length in bits.

    CompartmentId - Supplies compartment ID.

    InterfaceIndex - Supplies interface index.

    Action - Supplies the action to take, it can be either NsiSetCreateOrSet or
        NsiSetDelete.

CALLER IRQL:

    Must be called at PASSIVE Level.

--*/ 
    
{
    NTSTATUS Status;
    PIPV4_ROUTE_KEY RouteKey = NULL;
    PNL_ROUTE_RW RouteRw = NULL;
    PNPI_MODULEID ModuleId;
    ULONG Count, i;
    PIP_INTERFACE Interface = NULL;    
    PIP_COMPARTMENT Compartment = NULL;
    
    //
    // Currently we only support IPv4.
    //
    if (!IS_IPV4_PROTOCOL(Protocol)) {
        return;
    }
    ModuleId = Protocol->ModuleId;   

    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        goto Bail;
    }
    Interface = 
        IppFindInterfaceByIndex(Compartment, InterfaceIndex);
    if (Interface == NULL) {
        goto Bail;
    }
    
    Status =
        NsiAllocateAndGetTable(
            NsiPersistent,
            ModuleId,
            NlRouteObject,
            &RouteKey, sizeof(*RouteKey),
            &RouteRw, sizeof(*RouteRw),
            NULL, 0,
            NULL, 0,
            &Count,
            FALSE);  
    if (!NT_SUCCESS(Status)) {
        goto Bail;
    }  
        
    for (i = 0; i < Count; i++) {
        if (RouteKey[i].InterfaceLuid.Value != NET_IFLUID_UNSPECIFIED) {
            //
            // Routes with NET_IFLUID_UNSPECIFIED are considered to be 
            // auto-configured routes.
            //
            continue;
        }

        if (RouteKey[i].CompartmentId != UNSPECIFIED_COMPARTMENT_ID &&
            RouteKey[i].CompartmentId != CompartmentId) {
            continue;
        }

        if (!HasPrefix((PUCHAR)UnicastAddress, 
                       (PUCHAR)&RouteKey[i].NextHopAddress,
                       PrefixLength)) {
            continue;
        }
            
        Status =
            IppUpdateUnicastRoute(
                Action,
                Interface,
                NULL,
                (PUCHAR) &RouteKey[i].DestinationPrefix, 
                RouteKey[i].DestinationPrefixLength,
                (PUCHAR) &RouteKey[i].SourcePrefix, 
                RouteKey[i].SourcePrefixLength, 
                NlroManual,
                &RouteRw[i],
                (PUCHAR) &RouteKey[i].NextHopAddress);                
    }
    
Bail:
    NsiFreeTable(RouteKey, RouteRw, NULL, NULL);
    if (Interface != NULL) {
        IppDereferenceInterface(Interface);
    }
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);
    }    
}

VOID
IppPersistentRoutesWorker(
    IN PVOID Context
    )
/*++

Routine Description:

    Worker function for calling IppAddPersistentRoutes.

Arguments:

    Context - Supplies an IP_WORK_QUEUE_ITEM struct.

Caller IRQL:

    Called at PASSIVE level from a work item.

--*/
{
    PIP_DELAYED_WORK_QUEUE_ITEM WorkItem = 
        (PIP_DELAYED_WORK_QUEUE_ITEM) Context;
    PIP_ADD_DELETE_PERSISTENT_ROUTE Object = 
        (PIP_ADD_DELETE_PERSISTENT_ROUTE) WorkItem->Object;
    PIP_LOCAL_ADDRESS LocalAddress = 
        (PIP_LOCAL_ADDRESS) Object->LocalAddress;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    IP_ADDRESS_STORAGE UnicastAddress;

    RtlCopyMemory(&UnicastAddress,
                  NL_ADDRESS(LocalAddress),
                  Protocol->Characteristics->AddressBytes);
    
    IppAddOrDeletePersistentRoutes(
        Protocol,
        &UnicastAddress,
        ((PIP_LOCAL_UNICAST_ADDRESS)LocalAddress)->PrefixLength,
        Interface->Compartment->CompartmentId,
        Interface->Index,
        Object->Action);
    
    IppDereferenceLocalAddress(LocalAddress);
    ExFreePoolWithTag(WorkItem, IpGenericPoolTag);
}

NTSTATUS
IppUpdateOnLinkRouteForAddress(
    IN PIP_PROTOCOL Protocol,
    IN PIP_LOCAL_UNICAST_ADDRESS UnicastAddress, 
    IN NSI_SET_ACTION Action
    )
/*++

Routine Description:

    This route creates or deletes an on-link route for a given address.  In
    case of creation, the route is created with a user reference.  The route is
    deleted only if the address has the OnLinkRouteCreated flag set. 
    
Arguments:

    Protocol - Supplies the protocol.

    UnicastAddress - Supplies the address for which to create the on-link
        route. 

    Action - Supplies the action.  This is either NsiSetDelete or
        NsiSetCreateOrSetWithReference. 

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:
  
    Holds the interface write lock. 
    Holds the route set update lock.

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    IP_ADDRESS_STORAGE Prefix;
    ULONG AddressBits = 8 * Protocol->Characteristics->AddressBytes;
    
    ASSERT((Action == NsiSetCreateOrSetWithReference) ||
           (Action == NsiSetDelete));
    ASSERT_WRITE_LOCK_HELD(&UnicastAddress->Interface->Lock);
    ASSERT_SCALABLE_WRITE_LOCK_HELD(&UnicastAddress->Interface->Compartment->
                                    RouteSet.Lock);
        
    //
    // Don't create the on-link route if the prefix length is the same as the
    // address length. 
    //
    ASSERT(UnicastAddress->PrefixLength <= AddressBits);
    if (UnicastAddress->PrefixLength == AddressBits) {
        return STATUS_SUCCESS;
    }
    
    //
    // Don't delete the route if we did not create it in the first place. 
    //
    if ((Action == NsiSetDelete) && (!UnicastAddress->OnLinkRouteCreated)) {
        return STATUS_SUCCESS;
    }
    
    CopyPrefix(
        (UCHAR *)&Prefix, 
        NL_ADDRESS(UnicastAddress), 
        UnicastAddress->PrefixLength, 
        Protocol->Characteristics->AddressBytes);
    
    Status =
        IppUpdateUnicastRouteUnderLock(
            Action, 
            UnicastAddress->Interface,
            NULL, 
            (CONST UCHAR*)&Prefix, 
            (UINT8) UnicastAddress->PrefixLength,
            NULL, 
            0, 
            NlroManual, 
            NULL,
            NULL,
            NULL);
    if (NT_SUCCESS(Status)) {
        UnicastAddress->OnLinkRouteCreated =
            (Action == NsiSetCreateOrSetWithReference) ? 1 : 0;
    }
    return Status;
}

NTSTATUS
IppAddAutoConfiguredRoutesForAddress(
    IN PIP_LOCAL_ADDRESS LocalAddress, 
    IN BOOLEAN RouteSetLockHeld
    )
/*++

Routine Description:

    This routine creates host route and on-link route entries in the route table
    for a given address. Note that the on-link route is created only for a 
    unicast address.
    
Arguments:

    Address - Supplies the address for which to create the routes. 

    RouteSetLockHeld - Supplies a boolean indicating whether the route set lock
        is already held or not.

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:
  
    Holds the interface write lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    NL_ADDRESS_TYPE AddressType = NL_ADDRESS_TYPE(LocalAddress);
    PIPR_LOCKED_SET RouteSet = &Interface->Compartment->RouteSet;
    KLOCK_QUEUE_HANDLE LockHandle;

    ASSERT_WRITE_LOCK_HELD(&LocalAddress->Interface->Lock);

    //
    // We are now going to add routes (host as well as on-link).  Acquire
    // the route set update lock if we don't already hold it. 
    //
    if (!RouteSetLockHeld) {
        RtlAcquireScalableWriteLockAtDpcLevel(&RouteSet->Lock, &LockHandle);
    } else {
        ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);
    }

    if (AddressType == NlatUnicast && LocalAddress->CreateOnLinkRoute) {
        Status =
            IppUpdateOnLinkRouteForAddress(
                Protocol, 
                (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress, 
                NsiSetCreateOrSetWithReference);
                
        if (!NT_SUCCESS(Status)) {
            goto ReleaseLock;
        }
    }

    //
    // Update the host route corresponding to the local address. 
    //
    Status = 
        IppUpdateUnicastRouteUnderLock(
            NsiSetCreateOrSet, 
            Interface, 
            NULL, 
            NL_ADDRESS(LocalAddress),
            (UINT8) (8 * Protocol->Characteristics->AddressBytes),
            NULL,
            0, 
            NlroManual, 
            NULL,
            NULL,
            (PIP_LOCAL_ADDRESS)LocalAddress);

    //
    // If adding host route fails, undo addition of on-link route.
    //
    if (AddressType == NlatUnicast) {
        if (!NT_SUCCESS(Status)) {
            (VOID) IppUpdateOnLinkRouteForAddress(
                Protocol, 
                (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress, 
                NsiSetDelete);
        } else {
            //
            // To serialize IppPersistentRoutesWorker calls for better
            // efficiency, we always queue a work item even if we're at
            // PASSIVE level.
            //
            PIP_DELAYED_WORK_QUEUE_ITEM WorkItem = NULL;

            //
            // This is the object that contains all the information
            // to add/ delete persistant routes and will be passed along
            // with the work item.
            //
            PIP_ADD_DELETE_PERSISTENT_ROUTE Object = NULL;

            WorkItem = 
                ExAllocatePoolWithTag(
                    NonPagedPool,
                    sizeof(*WorkItem) + sizeof(*Object),
                    IpGenericPoolTag);
            if (WorkItem == NULL) {
                IppAddressTrace(
                    TRACE_LEVEL_WARNING, 
                    "Error allocating workitem for address",
                    Protocol, NL_ADDRESS(LocalAddress), Interface->Index);
                goto ReleaseLock;
            }
            
            WorkItem->WorkerRoutine = IppPersistentRoutesWorker;
            WorkItem->Object = (PVOID)(WorkItem + 1);
            
            Object = (PIP_ADD_DELETE_PERSISTENT_ROUTE) WorkItem->Object;
            Object->Action = NsiSetCreateOrSet;
            IppReferenceLocalAddress(LocalAddress);
            Object->LocalAddress = LocalAddress;

            //
            // Insert this work item in the per interface queue as the 
            // per compartment queue is used for notifications
            // and is already quite populated.
            // 
            NetioInsertWorkQueue(&Interface->WorkQueue, &WorkItem->Link);

            //
            // Now make sure that there are no routes with this address as its 
            // next hop on this interface. 
            //
            IppUpdateRoutesWithLocalAddressAsNextHopUnderLock(
                (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress);            
        }
    }
    
ReleaseLock:
    //
    // We are done adding routes (host as well as on-link).  Release the 
    // route set update lock if we acquired it.
    //
    if (!RouteSetLockHeld) {
        RtlReleaseScalableWriteLockFromDpcLevel(&RouteSet->Lock, &LockHandle);
    } else {
        ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);
    }
    
    return Status;
}

VOID
IppDeleteAutoConfiguredRoutesForAddress(
    IN PIP_LOCAL_ADDRESS LocalAddress, 
    IN BOOLEAN RouteSetLockHeld
    )
/*++

Routine Description:

    This routine deletes the auto configures route table entries for a given 
    address. The auto configured entries include host route and for a unicast 
    address, an on-link route.
    
Arguments:

    Address - Supplies the address for which to delete the route. 

    RouteSetLockHeld - Supplies a boolean indicating whether the route set lock
        is already held or not.

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:
  
    Holds the interface write lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    NL_ADDRESS_TYPE AddressType = NL_ADDRESS_TYPE(LocalAddress);
    PIPR_LOCKED_SET RouteSet = &Interface->Compartment->RouteSet;
    KLOCK_QUEUE_HANDLE LockHandle;

    ASSERT_WRITE_LOCK_HELD(&LocalAddress->Interface->Lock);

    //
    // We are now going to delete routes (host as well as on-link).  Acquire
    // the route set update lock if we don't already hold it. 
    //
    if (!RouteSetLockHeld) {
        RtlAcquireScalableWriteLockAtDpcLevel(&RouteSet->Lock, &LockHandle);
    } else {
        ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);
    }

    //
    // Update the host route corresponding to the local address. 
    //
    (VOID) IppUpdateUnicastRouteUnderLock(
        NsiSetDelete, 
        Interface, 
        NULL, 
        NL_ADDRESS(LocalAddress),
        (UINT8) (8 * Protocol->Characteristics->AddressBytes),
        NULL,
        0, 
        NlroManual, 
        NULL,
        NULL,
        (PIP_LOCAL_ADDRESS)LocalAddress);
    
    if (AddressType == NlatUnicast) {

        //
        // To serialize IppPersistentRoutesWorker calls for better
        // efficiency, we always queue a work item even if we're at
        // PASSIVE level.
        //
        PIP_DELAYED_WORK_QUEUE_ITEM WorkItem = NULL;

        //
        // This is the object that contains all the information
        // to add/ delete persistant routes and will be passed along
        // with the work item.
        //
        PIP_ADD_DELETE_PERSISTENT_ROUTE Object = NULL;

        (VOID) IppUpdateOnLinkRouteForAddress(
            Protocol, 
            (PIP_LOCAL_UNICAST_ADDRESS)LocalAddress, 
            NsiSetDelete);

        WorkItem = 
            ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(*WorkItem) + sizeof(*Object),
                IpGenericPoolTag);
        if (WorkItem == NULL) {
            goto ReleaseLock;
        }
        
        WorkItem->WorkerRoutine = IppPersistentRoutesWorker;
        WorkItem->Object = (PVOID)(WorkItem + 1);
        
        Object = (PIP_ADD_DELETE_PERSISTENT_ROUTE) WorkItem->Object;
        Object->Action = NsiSetDelete;
        IppReferenceLocalAddress(LocalAddress);
        Object->LocalAddress = LocalAddress;

        //
        // Insert this work item in the per interface queue as the 
        // per compartment queue is used for notifications
        // and is already quite populated.
        // 
        NetioInsertWorkQueue(&Interface->WorkQueue, 
                             &WorkItem->Link);
    }
    
ReleaseLock:
    //
    // We are done deleting routes (host as well as on-link).  Release the 
    // route set update lock if we acquired it.
    //
    if (!RouteSetLockHeld) {
        RtlReleaseScalableWriteLockFromDpcLevel(&RouteSet->Lock, &LockHandle);
    } else {
        ASSERT_SCALABLE_WRITE_LOCK_HELD(&RouteSet->Lock);
    }
}

VOID 
IppRemoveLocalAddressUnderLock(
    IN PIP_LOCAL_ADDRESS LocalAddress, 
    IN BOOLEAN RouteSetLockHeld
    )
/*++

Description:

    This routine removes an IP address from an interface.

Arguments:

    LocalAddress - Supplies the address to remove from its interface.

    RouteSetLockHeld - Supplies a boolean indicating whether the route set lock
        is already held or not.

Locks: 

    Assumes caller holds interface lock (exclusive).

Caller IRQL: = DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PNLA_SET AddressSet;
    ULONG AddressEntrySize;
    NL_ADDRESS_TYPE AddressType = NL_ADDRESS_TYPE(LocalAddress);
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT(!LocalAddress->Deleted);
    
    AddressSet = IppGetAddressSet(Interface, AddressType);
    AddressEntrySize = IppGetAddressEntrySize(AddressType);

    IppDeleteNlaSetEntry(AddressSet, &LocalAddress->Link);
    
    LocalAddress->Deleted = 1;
    
    if (AddressType == NlatUnicast) {
        //
        // Stop any pending timers for unicast addresses.
        //
        PIP_LOCAL_UNICAST_ADDRESS UnicastAddress = 
            (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress;

        if (IsLocalUnicastAddressValid(UnicastAddress)) {
            ASSERT(Interface->ValidLocalUnicastAddressCount > 0);
            Interface->ValidLocalUnicastAddressCount--;
            if (Interface->ValidLocalUnicastAddressCount == 0) {
                IppRestartLinkLocalAddressConfiguration(Interface);
            }        
        } else {
            //
            // There is a small window in which the link local address may be 
            // deleted before it has finished DAD. 
            // Though it is ok to not restart if DAD failed.
            //
            if ((UnicastAddress->AddressOrigin == ADDR_CONF_LINK) && 
                (UnicastAddress->DadState == NldsTentative) &&
                (Interface->ValidLocalUnicastAddressCount == 0)) {
                IppRestartLinkLocalAddressConfiguration(Interface);
            }
        }
        
        UnicastAddress->DadState = NldsInvalid;
        if (TtIsTimerActive(&UnicastAddress->Timer)) {
            TtStopTimer(Interface->UnicastAddressEventTable, 
                        &UnicastAddress->Timer);
            UnicastAddress->DadCount = 0;
        }
        //
        // Reset the lifetime. This should prevent Temporary Addresses from 
        // regenerating if the public address is deleted.
        //
        UnicastAddress->PreferredLifetime = UnicastAddress->ValidLifetime = 0;
  
        IppNotifyAddressChange(UnicastAddress, NsiDeleteInstance);
    } 

    //    
    // Call the protocol specific handler for deleting the address.  Do this
    // before dereferencing the address.
    //
    if (Protocol->AddressDeletionHelper != NULL) {
        Protocol->AddressDeletionHelper(
            LocalAddress->Interface, NL_ADDRESS(LocalAddress));
    }

    IppAddressTrace(TRACE_LEVEL_WARNING,
                    "Removed address",
                    Protocol, NL_ADDRESS(LocalAddress), Interface->Index);

    IppDeleteAutoConfiguredRoutesForAddress(LocalAddress, RouteSetLockHeld);

    //
    // Dereference the address. 
    //
    IppDereferenceLocalAddress(LocalAddress);
    
    //
    // This LocalAddress is no longer available as a source address.
    //
    IppInvalidateDestinationCache(Interface->Compartment);
}

VOID
IppRemoveLocalAddress(
    IN PIP_LOCAL_ADDRESS LocalAddress,
    IN BOOLEAN RouteSetLockHeld
    )
/*++

Description:

    This routine removes a static IP address from an interface. This just calls
    IppRemoveLocalAddressUnderLock.

Arguments:

    LocalAddress - Supplies a pointer to the address to remove from its 
        interface.

    RouteSetLockHeld - Supplies a boolean indicating whether the route set lock
        is already held or not.

Locks: 

    None.

Caller IRQL: 

    May be called at PASSIVE through DISPATCH level.

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_INTERFACE Interface = LocalAddress->Interface;

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    IppRemoveLocalAddressUnderLock(LocalAddress, RouteSetLockHeld);
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
}

VOID 
IppRemoveLocalEphemeralAddressUnderLock(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
/*++

Description:

    This routine removes an ephemeral IP address from (loopback) interface.

Arguments:

    LocalAddress - Supplies the address to remove from its interface.

Locks: 

    Assumes caller holds ephemeraladdressset lock (exclusive).

Caller IRQL: = DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIP_LOOPBACK_ADDRESS_LOCKED_SET LoopbackAddressSet = 
        &Interface->Compartment->EphemeralLoopbackAddressSet;
    
    ASSERT(LocalAddress->AddressOrigin == ADDR_CONF_EPHEMERAL);
    ASSERT_WRITE_LOCK_HELD(&LoopbackAddressSet->Lock);
    ASSERT(!LocalAddress->Deleted);
    
    IppDeleteNlaSetEntry(
        &LoopbackAddressSet->AddressSet, 
        &LocalAddress->Link);
    
    LocalAddress->Deleted = 1;
            
    LocalAddress->DadState = NldsInvalid;
    if (TtIsTimerActive(&LocalAddress->Timer)) {
        ASSERT(FALSE);
    }

    IppAddressTrace(TRACE_LEVEL_INFORMATION,
                    "Removed ephemeral address",
                    Protocol, NL_ADDRESS(LocalAddress), Interface->Index);

    //
    // Dereference the address. 
    //
    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS)LocalAddress);
}

VOID
IppUnAddressInterfaceUnderLock(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    This routine removes all the addresses from an interface. 
       
Arguments:

    Interface - Supplies the interface from which to remove the addresses. 

Return Value:

    None.

Caller LOCK: Interface exclusive lock. 

Caller IRQL: = DISPATCH_LEVEL since a lock is held.

--*/ 
{
    PNLA_LINK Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress = NULL;
    PIP_LOCAL_BROADCAST_ADDRESS BroadcastAddress = NULL;
    PIP_LOCAL_ANYCAST_ADDRESS AnycastAddress = NULL;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    //
    // Delete the unspecified address. 
    // 
    if (Interface->UnspecifiedAddress != NULL) {
        IppDereferenceLocalUnicastAddress(Interface->UnspecifiedAddress);
        Interface->UnspecifiedAddress = NULL;
    }
    
    //
    // Delete all addresses from Interface.
    //
    IppInitializeAddressEnumerationContext(&Context);
    while (!IppIsNlaSetEmpty(&Interface->LocalUnicastAddressSet)) {
        Link = IppEnumerateNlaSetEntry(
            &Interface->LocalUnicastAddressSet, 
            (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        
        LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);
        
        IppRemoveLocalAddressUnderLock(
            (PIP_LOCAL_ADDRESS)LocalAddress, FALSE);
    }
    
    //
    // Remove broadcast addresses. 
    //
    IppInitializeAddressEnumerationContext(&Context);
    while (!IppIsNlaSetEmpty(&Interface->LocalBroadcastAddressSet)) {
        Link = IppEnumerateNlaSetEntry(
            &Interface->LocalBroadcastAddressSet, 
            (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        
        BroadcastAddress = (PIP_LOCAL_BROADCAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_BROADCAST_ADDRESS, Link);
        
        IppRemoveLocalAddressUnderLock(
            (PIP_LOCAL_ADDRESS)BroadcastAddress, FALSE);
    }
    
    //
    // Remove anycast addresses. 
    //
    IppInitializeAddressEnumerationContext(&Context);
    while (!IppIsNlaSetEmpty(&Interface->LocalAnycastAddressSet)) {
        Link = IppEnumerateNlaSetEntry(
            &Interface->LocalAnycastAddressSet, 
            (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        
        AnycastAddress = (PIP_LOCAL_ANYCAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_ANYCAST_ADDRESS, Link);
        
        IppRemoveLocalAddressUnderLock(
            (PIP_LOCAL_ADDRESS)AnycastAddress, FALSE);
    }

    //
    // Loopback interface should also remove ephemeral addresses.
    //
    if (IS_IPV4_PROTOCOL(Interface->Compartment->Protocol) &&
        IS_LOOPBACK_INTERFACE(Interface)) {
        IppGarbageCollectLoopbackAddressSet(Interface->Compartment);        
    }
}


VOID
IppNotifyAddressChangeAtPassive(
    IN PVOID Context
    )
/*++

Routine Description:

    Notify clients of a change in the state of a unicast address.

    Compare NotifyAddrChange() in the XP IPv4 stack and
    RegisterNetAddressWorker() in the XP IPv6 stack.

Arguments:
    Relevant fields of Context:

    Object - Supplies an address to notify clients about.

    NotificationType - Supplies the type of notification we will make to NSI.

    ParameterDescription - Supplies the parameter that changed.

Locks:

    Must be called with no locks held.  
    Assumes caller holds a reference on UnicastAddress.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem = 
        (PIP_NOTIFICATION_WORK_QUEUE_ITEM) Context;
    NM_INDICATE_PARAMETER_CHANGE NsiArgs;
    NL_DAD_STATE EffectiveDadState;
    PIP_LOCAL_UNICAST_ADDRESS UnicastAddress = 
        (PIP_LOCAL_UNICAST_ADDRESS) WorkItem->Object;
    BOOLEAN Added = FALSE, Deleted = FALSE;
    union {
        IPV6_LOCAL_ADDRESS_KEY Ipv6;
        IPV4_LOCAL_ADDRESS_KEY Ipv4;
        NL_LOCAL_ADDRESS_KEY Generic;
    } Key = {0};
    PIP_INTERFACE Interface = UnicastAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    PNMP_CLIENT_CONTEXT ClientContext = Protocol->NmClientContext;
    SCOPE_ID ScopeId;

    PASSIVE_CODE();

    //
    // WorkerQueue is serialized so we don't need to get a lock here.
    //

    EffectiveDadState = IppGetEffectiveDadState(UnicastAddress);
    ScopeId = IppGetScopeId(Interface, NL_ADDRESS(UnicastAddress));

    //
    // To call NSI, we have to first reference the NSI attachment to
    // see if the client context is valid.  If it is, we then
    // reference the notification registration.  This prevents
    // deregistration from completing until we're done.
    //
    if (RoReference(&Protocol->NmClientReferenceObject)) {
        PNMP_NOTIFICATION_CONTEXT NotificationContext =
            &ClientContext->AddressNotificationContext;

        if (RoReference(&NotificationContext->ReferenceObject)) {
            RtlZeroMemory(&NsiArgs, sizeof(NsiArgs));
            NsiArgs.ProviderHandle = ClientContext->Npi.ProviderHandle;
            NsiArgs.ObjectIndex = NlLocalUnicastAddressObject;
            NsiArgs.NotificationType = WorkItem->NotificationType;
        
            NsiArgs.KeyStructDesc.KeyStruct = (PUCHAR) &Key.Generic;
            Key.Generic.InterfaceLuid = Interface->Luid;
            
            RtlCopyMemory(Key.Generic.Address, 
                          NL_ADDRESS(UnicastAddress), 
                          AddressBytes);
            NsiArgs.KeyStructDesc.KeyStructLength = 
                SIZEOF_NL_LOCAL_ADDRESS_KEY(
                    Protocol->Characteristics->NetworkProtocolId);
        
            NsiArgs.ParamDesc.StructType = NsiStructRoDynamic;
            NsiArgs.ParamDesc.Parameter = (PUCHAR) &EffectiveDadState;
            NsiArgs.ParamDesc.ParameterLength = sizeof(EffectiveDadState);
            NsiArgs.ParamDesc.ParameterOffset = 
                FIELD_OFFSET(NL_LOCAL_UNICAST_ADDRESS_ROD, DadState);
            ClientContext->Npi.Dispatch->ParameterChange(&NsiArgs);
    
            if (RoDereference(&NotificationContext->ReferenceObject)) {
                KeSetEvent(&NotificationContext->DeregisterCompleteEvent, 
                           0, 
                           FALSE);
            }
        }
        IppDereferenceNsiClientContext(Protocol);
    }

    //
    // Notify NL clients if the address is effectively added or
    // deleted.
    //
    // 1. The corresponding address's DadState changes between valid/invalid
    //    states while its interface's media state is connected.
    // 
    // 2. The corresponding address's interface media state changes between
    //    connected/disconnected while its DadState is NldsPreferred.
    //    For this case, IppDisconnectAddresses queues a worker on the connect
    //    to disconnect transition whereas on the reverse transition the 
    //    worker is queued at the completion the duplicate address detection.
    //
    if ((UnicastAddress->DadState == NldsPreferred) &&
        (Interface->ConnectedSubInterfaces > 0)) {
        Added = (UnicastAddress->Connected == FALSE);
        UnicastAddress->Connected = TRUE;
    } else {
        Deleted = (UnicastAddress->Connected == TRUE);
        UnicastAddress->Connected = FALSE;
    }

    if (ScopeId.Zone != (NL_ADDRESS_SCOPE_ZONE(UnicastAddress))) {
        //
        // The zone id changed, so delete and re-add the address.
        //
        Added = Deleted = TRUE;
        NL_ADDRESS_SCOPE_ZONE(UnicastAddress) = ScopeId.Zone;
    }    

    if (Added || Deleted) {
        PLIST_ENTRY Head, Next;
        KIRQL OldIrql;
        PIP_CLIENT_CONTEXT Client;
        NL_INDICATE_LOCAL_ADDRESS Indicate;

        //
        // When address is finally "done", inform all network layer clients.
        // (New clients should enumerate addresses, we only guarantee
        // indications to those clients already registered at this time).
        //
        Head = &Protocol->NlClientSet.Set;
        RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
        for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
            //
            // The client is left in its set upon deletion and cleaned up with
            // the client set lock held.  Hence we can access Next without a
            // reference.  Also, because new clients are only added at the head
            // of the list, we can unlock the list during our traversal and
            // know that the traversal will terminate properly.
            //
            Client = (PIP_CLIENT_CONTEXT)
                CONTAINING_RECORD(Next, IP_CLIENT_CONTEXT, Link);

            //
            // We must be careful to not reference a deleted client.
            // c.f. IppInterfaceCleanup.
            //
            if (!IppReferenceNlClient(Client)) {
                continue;
            }

            RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);

            //
            // Now that we have released all locks, we provide the indication.
            // It's important to do the delete before the add, for the case
            // where the scope id changed.
            //
            Indicate.ClientHandle = Client->Npi.ProviderHandle;
            Indicate.LocalAddress = (PNL_LOCAL_ADDRESS) UnicastAddress;
            if (Deleted && 
               (Client->Npi.Dispatch->DeleteLocalAddressNotification != NULL)){
                Client->Npi.Dispatch->
                    DeleteLocalAddressNotification(&Indicate);
            }
            if (Added && 
                (Client->Npi.Dispatch->AddLocalAddressNotification != NULL)) {
                Client->Npi.Dispatch->
                    AddLocalAddressNotification(&Indicate);
            } 

            //
            // We dereference the client after acquiring the client set lock.
            // Since we hold a reference on the client, it belongs to its set.
            //
            RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
            IppDereferenceNlClient(Client);
        }
        RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);
    }

    //
    // Notify the framing layer about the address change.
    //
    if (((Added ^ Deleted) == TRUE) &&
        (UnicastAddress->AddressOrigin != ADDR_CONF_TEMPORARY)) {

        FL_REQUEST_SET_INTERFACE Request = {0};
        IP_ADDRESS_STORAGE Address;        

        RtlCopyMemory(&Address, NL_ADDRESS(UnicastAddress), AddressBytes);
        
        Request.ProviderInterfaceHandle = Interface->FlContext;
        Request.RequestCode = Added ? FlicAddAddress : FlicRemoveAddress;
        Request.RequestBuffer = Address.Buffer;
        Request.RequestLength = AddressBytes;
        Request.RequestContext = &Interface->LowPowerMode;
        
        (VOID) Interface->FlModule->Npi.Dispatch->SetInterface(&Request);
    }
    
    IppDereferenceLocalUnicastAddress(UnicastAddress);  
    ExFreePoolWithTag(WorkItem, IpGenericPoolTag);
}

VOID
IppNotifyAddressChange(
    IN PIP_LOCAL_UNICAST_ADDRESS UnicastAddress,
    IN NSI_NOTIFICATION NotificationType
    )
/*++

Routine Description:

    Tell clients about the current status of a unicast address.
    This is a wrapper around IppNotifyAddressChangeAtPassive.  If we're
    not at PASSIVE level, we'll queue a work item to execute it.

Arguments:

    UnicastAddress - Supplies the address to notify clients about.

    NotificationType - Supplies the type of notification we will make to NSI.    

Locks:

    Assumes caller holds a reference on UnicastAddress or it holds the
    interface lock so that the address cannot go away.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_INTERFACE Interface = UnicastAddress->Interface;
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem;

    if (IS_IPV4_PROTOCOL(UnicastAddress->Interface->Compartment->Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: [%u] State of address changed "
                   "(%!IPV4! --> %!ADDRESSSTATE!)\n",
                   Interface->Index,
                   NL_ADDRESS(UnicastAddress), 
                   UnicastAddress->DadState);
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: [%u] State of address changed "
                   "(%!IPV6! --> %!ADDRESSSTATE!)\n",
                   Interface->Index,
                   NL_ADDRESS(UnicastAddress), 
                   UnicastAddress->DadState);
    }

    //
    // To serialize with interface notifications, we always queue a
    // work item even if we're at PASSIVE level.
    //
    WorkItem = 
        ExAllocatePoolWithTag(
            NonPagedPool, sizeof(*WorkItem), IpGenericPoolTag);

    //
    // REVIEW: Should we do anything on failure?  The XP IPv6
    // stack doesn't.  We could make the work item be allocated with 
    // the address, but that would waste some space when not in use.
    //
    if (WorkItem != NULL) {

        WorkItem->WorkerRoutine = IppNotifyAddressChangeAtPassive;
        WorkItem->Object = UnicastAddress;
        WorkItem->NotificationType = NotificationType;
        IppReferenceLocalUnicastAddress(UnicastAddress);    
        NetioInsertWorkQueue(
            &Interface->Compartment->WorkQueue, 
            &WorkItem->Link);
    }
}


VOID
IppHandleAddressLifetimeTimeout(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
/*++

Routine Description:

    This routine handles a timeout related to the lifetime of an address. It
    processes the timeout and takes the necessary action (for instance,
    changing the state of the address to deprecated) and sets the timer for the
    next event (for instance, setting the invalidation timer). This routine
    works by looking at the creation time of the address, the lifetimes and the
    current time. So, it is safe to call the routine even when no event has
    occurred just to update the state and set the timers. For example,
    every time the lifetime changes, this routine should be called.    

Arguments:

    LocalAddress - Supplies the address for which to handle the timeout.

Return Value:

    None.

Caller LOCK:

    Caller holds the interface lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIP_LOCAL_TEMPORARY_ADDRESS TemporaryAddress;
    PIP_LOCAL_UNICAST_ADDRESS PublicAddress;
    ULONG Now = IppTickCount;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT(LocalAddress->DadState != NldsInvalid);

    if (LocalAddress->DadCount > 0) {
        //
        // DAD is running. No need to mess with lifetime timeouts. 
        //
        return;
    }
    
    //
    // Stop the timer if one is already running because we are recomputing the
    // timeouts anyways. 
    //
    if (TtIsTimerActive(&LocalAddress->Timer)) {
        TtStopTimer(Interface->UnicastAddressEventTable, 
                    &LocalAddress->Timer);
    }
    
    //
    // Refresh the lifetimes in the address.  This makes the processing below
    // easier since all the timeouts in the address are w.r.t the current
    // time. 
    //
    IppRefreshAddressLifetimes(Now, LocalAddress);
    
    //
    // For temporary addresses, check if the address needs to be regenerated. 
    //
    if ((LocalAddress->AddressOrigin == ADDR_CONF_TEMPORARY) &&
        (!LocalAddress->TemporaryAddressRegenerated)) {
        TemporaryAddress = (PIP_LOCAL_TEMPORARY_ADDRESS)LocalAddress;

        if (LocalAddress->PreferredLifetime <=
            Protocol->TemporaryRegenerateAdvance) {
            //
            // Need to regenerate a new temporary address as the old one is 
            // getting deprecated soon. Fall through to handle the case in
            // which the address also needs to be deprecated.
            //
            ASSERT(LocalAddress->AddressOrigin == ADDR_CONF_TEMPORARY);
            LocalAddress->TemporaryAddressRegenerated = TRUE;
            PublicAddress = ((PIP_LOCAL_TEMPORARY_ADDRESS)LocalAddress)->
                PublicAddress;
            Status =
                IppCreateLocalTemporaryAddress(
                    NL_ADDRESS(LocalAddress), 
                    Interface, 
                    PublicAddress, 
                    FALSE,
                    &TemporaryAddress);
            if (NT_SUCCESS(Status)) {
                IppDereferenceLocalTemporaryAddress(TemporaryAddress);
            } 
        } else {
            //
            // Not yet time to regenerate the address.
            // Start a timer and we are done. 
            //
            if (LocalAddress->PreferredLifetime != NL_INFINITE_LIFETIME) {
                TtStartTimer(
                    Interface->UnicastAddressEventTable, 
                    &LocalAddress->Timer,
                    LocalAddress->PreferredLifetime - 
                    Protocol->TemporaryRegenerateAdvance);
            }
            return;
        }
    }

    //
    // Check if the address needs to be deprecated. 
    // 
    if (LocalAddress->PreferredLifetime == 0) {
        if (LocalAddress->DadState == NldsPreferred) {
            //
            // Set address to deprecated. Notify clients. Fall through to
            // handle the case where the address also needs to be invalidated. 
            //
            LocalAddress->DadState = NldsDeprecated;
            IppNotifyAddressChange(LocalAddress, NsiParameterNotification);
        }
    } else {
        //
        // Not time to set the address to deprecated state. 
        //
        if (LocalAddress->PreferredLifetime != INFINITE_LIFETIME) {
            TtStartTimer(
                Interface->UnicastAddressEventTable, 
                &LocalAddress->Timer,
                LocalAddress->PreferredLifetime);
        }
        return;
    }
            
    if (LocalAddress->ValidLifetime == 0) {
        //
        // Remove address. This also notifies the clients. 
        //
        IppRemoveLocalAddressUnderLock((PIP_LOCAL_ADDRESS)LocalAddress, FALSE);
    } else if (LocalAddress->ValidLifetime != INFINITE_LIFETIME) {
        TtStartTimer(
            Interface->UnicastAddressEventTable, 
            &LocalAddress->Timer,
            LocalAddress->ValidLifetime);
    }
}

VOID
IppDadComplete(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
/*++

Routine Description:

    This function completes address addition processing, after duplicate
    address detection has completed.  It is responsible for notifying
    external modules of the existence of a new valid address.
        Compare AddrConfNotDuplicate() in the XP IPv6 stack.

Arguments:

    LocalAddress - Supplies a pointer to a local address.

Return Value:

    None.

Caller Locks:

    Assumes caller has a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level, since a lock is held.

--*/
{
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    NTSTATUS Status = STATUS_SUCCESS;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT(!TtIsTimerActive(&LocalAddress->Timer));

    //
    // The address has passed Duplicate Address Detection.
    // Transition to a valid state.
    //
    if (!IsLocalUnicastAddressValid(LocalAddress)) {
        LocalAddress->DadState = NldsPreferred;

        Interface->ValidLocalUnicastAddressCount++;
        //
        // Adding the host and on-link route.
        //
        Status = 
            IppAddAutoConfiguredRoutesForAddress(
                (PIP_LOCAL_ADDRESS) LocalAddress, 
                FALSE);
        if (!NT_SUCCESS(Status)) {
            IppRemoveLocalAddressUnderLock(
                (PIP_LOCAL_ADDRESS) LocalAddress, 
                FALSE);
            return;
        }

        //
        // This LocalAddress is now available as a source address.
        //
        IppInvalidateDestinationCache(Compartment);
    }

    //
    // For backwards compatibility with some layer-3 switches, send unsolicted 
    // neighbor advertisement on DAD completion.
    //
    if (IppInterfaceDadEnabled(Interface) &&
        Interface->SendUnsolicitedNeighborAdvertisementOnDad) {
        IppSendUnsolicitedNeighborAdvertisement(LocalAddress);    
    }

    // 
    // If a non link-local address just became valid and the interface
    // link-local address configuration behavior is LinkLocalDelayed, stop
    // link-local address configuration.  This should stop the timer and remove
    // any link local address already present.
    //
    if ((LocalAddress->AddressOrigin != ADDR_CONF_LINK) &&
        (Interface->LinkLocalAddressBehavior == LinkLocalDelayed)) {
        IppStopLinkLocalAddressConfiguration(Interface);
    }

    //
    // DAD is also triggered through an interface disconnect to connect
    // transition in which case the address is not registered with NL clients
    // even if it is in the preferred state.  Hence we notify them
    // about this address outside the "if (!Is...Valid)" clause.
    //
    IppNotifyAddressChange(LocalAddress, NsiParameterNotification);

    //
    // Set a timeout to regenerate an address, deperecate it or invalidate it
    // depending on the type of the address. 
    //
    IppHandleAddressLifetimeTimeout(LocalAddress);
}

__inline
VOID
IppStartDad(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
/*++

Routine Description:

    Starts duplicate address detection for the address,
    unless DAD is disabled.  Compare AddrConfStartDAD in the
    XP IPv6 stack.

    This routine is invoked when a address is added.

Arguments:

    LocalAddress - Supplies a pointer to the address.

Locks:

    Assumes the caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_INTERFACE Interface = LocalAddress->Interface;
    //
    // Handle optimistic DAD.
    //
    if (IsLocalUnicastAddressValid(LocalAddress)) {
        Interface->ValidLocalUnicastAddressCount++;
    }
    IppRestartDad(LocalAddress);
}

VOID
IppRestartDad(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
/*++

Routine Description:

    Starts duplicate address detection for the address,
    unless DAD is disabled.  Compare AddrConfStartDAD in the
    XP IPv6 stack.

Arguments:

    LocalAddress - Supplies a pointer to the address.

Locks:

    Assumes the caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // The timer can be active if the invalidation timer is set and the
    // interface is disconnected and then reconnected again. 
    //
    if (TtIsTimerActive(&LocalAddress->Timer)) {
        TtStopTimer(Interface->UnicastAddressEventTable,
                    &LocalAddress->Timer);
    }
    
    if (!IppInterfaceDadEnabled(Interface) ||
        ((LocalAddress->AddressOrigin == ADDR_CONF_TEMPORARY) &&
         (Protocol->MaxTemporaryDadAttempts == 0))) {
        //
        // Duplicate Address Detection is disabled,
        // so go straight to a valid state
        // if we aren't already valid.
        //
        IppDadComplete(LocalAddress);
    } else if (Interface->ConnectedSubInterfaces == 0) {
        //
        // The interface is not connected,
        // so we can not perform DAD.
        // When the interface is connected,
        // IppReconnectAddresses will start DAD.
        //
    } else {
        //
        // Initialize for DAD.
        // Send first solicit at next timeout. DadCount contains the number of
        // timeouts required for DAD completion. This is one more than the
        // number of DadTransmits because we have to wait one extra timeout
        // period after the sending the last DAD before making the address
        // preferred. 
        //
        LocalAddress->DadCount = (USHORT)Interface->DadTransmits + 1;
        // 
        // Reset DAD state.
        //
        if (LocalAddress->DadState == NldsDuplicate) {
            LocalAddress->DadState = NldsTentative;
        }

        TtStartTimer(
            Interface->UnicastAddressEventTable,
            &LocalAddress->Timer,
            1);
    }
}

VOID
IppDadLogEvent(
    __in PIP_ADDRESS_STORAGE NlAddress,
    __in ULONG NlAddressLength,
    __in SCOPE_ID ScopeId, 
    __in_bcount(DlAddressLength) CONST UCHAR *DlAddress OPTIONAL,  
    __in_range(0, DL_ADDRESS_LENGTH_MAXIMUM) ULONG DlAddressLength,
    __in ULONG EventCode
    )
/*++

Routine Description:

    Duplicate Address Detection has found that the local address 
    conflicts with some other node.  Notify user by a popup message and
    write the log.

Arguments:

    NlAddress - Supplies the network layer address that cause the problem.

    NlAddressLength - Supplies the IP address length in bytes.

    ScopeId - Supplies ScopeId.

    DlAddress - Supplies the datalink layer address that cause the problem.
        This is optional.

    DlAddressLength - Supplies the datalink layer address length.

    EventCode - Supplies the event code. 

CALLER IRQL:

    Must be called at PASSIVE Level.

--*/ 
{
    WCHAR NlAddressString[INET6_ADDRSTRLEN];
    WCHAR DlAddressString[DL_ADDRESS_LENGTH_MAXIMUM * 3];
    ULONG NlAddressStringLength = RTL_NUMBER_OF(NlAddressString), Status;
    WCHAR HighBits, LowBits;
    ULONG i;
    NTSTATUS ErrorCode;
    PIO_ERROR_LOG_PACKET ErrorLogEntry;
    SIZE_T StringSize = 0;

    ASSERT(NlAddress != NULL);
    ASSERT(NlAddressLength > 0);
    ASSERT(DlAddressLength > 0);
    PASSIVE_CODE();

    //
    // Retrieve IP Address.
    //
    if (NlAddressLength == sizeof(IN_ADDR)) {
        Status =
            RtlIpv4AddressToStringExW(
                (PIN_ADDR) NlAddress,
                0,
                NlAddressString,
                &NlAddressStringLength);
    } else {
        Status =
            RtlIpv6AddressToStringExW(
                (PIN6_ADDR) NlAddress,
                ScopeId.Value,
                0,
                NlAddressString,
                &NlAddressStringLength);
    }
    if  (!NT_SUCCESS(Status)) {
        NlAddressString[0] = L'?';
        NlAddressString[1] = L'?';
        NlAddressString[2] = L'?';
        NlAddressString[3] = L'\0';
        NlAddressStringLength = 4;   
    }
    
    //
    // Retrieve MAC Address.
    //
    if (DlAddressLength > 0) {
        for (i = 0; i < DlAddressLength; i++) {
            HighBits = (DlAddress[i] & 0xf0) >> 4;
            LowBits = DlAddress[i] & 0x0f;

            DlAddressString[i * 3] = (
                 HighBits < 10 
                 ? L'0' + HighBits 
                 : L'A' + HighBits - 10);
            
            DlAddressString[i * 3 + 1] = (
                 LowBits < 10 
                 ? L'0' + LowBits 
                 : L'A' + LowBits - 10);
            
            DlAddressString[i * 3 + 2] = L'-';
        }

        DlAddressString[DlAddressLength * 3 - 1] = L'\0';
    }
    
    //
    // Log the Event. 
    //
    if (EventCode == EVENT_TCPIP_ADDRESS_CONFLICT1) {
        ErrorCode = STATUS_IP_ADDRESS_CONFLICT1;        
    } else {
        ErrorCode = STATUS_IP_ADDRESS_CONFLICT2;
    }

    //
    // Allocate Memory.
    //
    StringSize =  
        (NlAddressStringLength + DlAddressLength * 3) * sizeof(WCHAR);
    ErrorLogEntry = 
        IoAllocateErrorLogEntry(
            IppDeviceObject, 
            (UCHAR)
            (StringSize +
             sizeof(IO_ERROR_LOG_PACKET) - 
             RTL_FIELD_SIZE(IO_ERROR_LOG_PACKET, DumpData)));
    if (ErrorLogEntry == NULL) {
        return;
    }
    
    ErrorLogEntry->UniqueErrorValue = 2;
    ErrorLogEntry->ErrorCode = EventCode;
    ErrorLogEntry->NumberOfStrings = 2;
    ErrorLogEntry->StringOffset =
        sizeof(IO_ERROR_LOG_PACKET) -
        RTL_FIELD_SIZE(IO_ERROR_LOG_PACKET, DumpData);
    ErrorLogEntry->DumpDataSize = 0;

    RtlCopyMemory(
        (PUCHAR) ErrorLogEntry + ErrorLogEntry->StringOffset, 
        NlAddressString,
        NlAddressStringLength * sizeof(WCHAR));
    
    RtlCopyMemory(
        (PUCHAR) ErrorLogEntry 
        + ErrorLogEntry->StringOffset
        + NlAddressStringLength * sizeof(WCHAR), 
        DlAddressString,
        DlAddressLength * 3 * sizeof(WCHAR));
    
    IoWriteErrorLogEntry(ErrorLogEntry);
}    

VOID
IppNotifyDadWorker(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    Worker function for calling IppDadEvent.

Arguments:

    DeviceObject - Unused.  Wish they passed the WorkItem instead.

    Context - Supplies an IP_WORK_QUEUE_ITEM struct.

Caller IRQL:

    Called at PASSIVE level from a work item.

--*/
{
    PIP_DAD_WORK_QUEUE_ITEM MyContext = Context;
    UNREFERENCED_PARAMETER(DeviceObject);

    IoFreeWorkItem(MyContext->WorkQueueItem);
    IppDadLogEvent(
        &MyContext->NlAddress,
        MyContext->NlAddressLength,
        MyContext->ScopeId,
        MyContext->DlAddress,
        MyContext->DlAddressLength,
        MyContext->EventCode);
    ExFreePool(MyContext);
}

VOID
IppNotifyDad(
    __in_bcount(NlAddressLength) CONST UCHAR *NlAddress,
    IN ULONG NlAddressLength,
    IN SCOPE_ID ScopeId, 
    __in_bcount(DlAddressLength) CONST UCHAR *DlAddress,  
    IN ULONG DlAddressLength,
    IN ULONG EventCode
    )
/*++

Routine Description:

    Tell clients about the DAD status of an IP address.
    We queue up a work item which calls IppDadLogEvent.

Arguments:

    NlAddress - Supplies the network layer address that cause the problem.

    NlAddressLength - Supplies the IP address length in bytes.

    ScopeId - Supplies ScopeId.

    DlAddress - Supplies the datalink layer address that cause the problem.
        This is optional.

    DlAddressLength - Supplies the datalink layer address length.

    EventCode - Supplies the event code. 
    
Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIO_WORKITEM WorkItem;
    PIP_DAD_WORK_QUEUE_ITEM Context;

    ULONG i;
    
    ASSERT(NlAddress != NULL);
    ASSERT(NlAddressLength > 0);
    ASSERT(DlAddressLength > 0);
    ASSERT(NlAddressLength <= 16);
    ASSERT(DlAddressLength <= DL_ADDRESS_LENGTH_MAXIMUM);
    //
    // Even if we're at passive, queue a work item.  This is because
    // the notification may take a long period of time, and we don't
    // want to hold up interface addition.
    //
    if ((IppTickCount - LastDadTickTime) < IppTimerTicks(5 * MINUTES)) {
        //
        // Rate Control: 5 mins per event.
        //
        return;
    } else {
        LastDadTickTime = IppTickCount;
    }
    
    Context = 
        ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(*Context),
            IpGenericPoolTag);
    if (Context == NULL) {
        return;
    }

    WorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (WorkItem == NULL) {
        ExFreePool(Context);
        return;
    }

    for (i = 0; i < NlAddressLength;  i++) {
        Context->NlAddress.Buffer[i] = NlAddress[i];
    }

    if (DlAddress == NULL ) {
        for (i = 0; i < DlAddressLength; i++) {
            Context->DlAddress[i] = 0;
        }
    } else {
        for (i = 0; i < DlAddressLength; i++) {
            Context->DlAddress[i] = DlAddress[i];
        }
    }
    
    Context->WorkQueueItem = WorkItem;
    Context->NlAddressLength = NlAddressLength;
    Context->DlAddressLength = DlAddressLength;
    Context->EventCode = EventCode;
    Context->ScopeId = ScopeId;

    IoQueueWorkItem(
        WorkItem,
        IppNotifyDadWorker,
        DelayedWorkQueue,
        Context);
}

VOID
IppDadFailed(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    )
/*++

Routine Description:

    Duplicate Address Detection has found that the local address 
    conflicts with some other node.  Compare AddrConfDuplicate in the
    XP IPv6 stack.

    TODO: We should also log an event like NotifyConflictProc does
    in the XP IPv4 stack.

Arguments:

    LocalAddress - Supplies a pointer to the address.

Locks:

    Assumes the caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    NTSTATUS Status;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIP_LOCAL_UNICAST_ADDRESS PublicAddress;
    PIP_LOCAL_TEMPORARY_ADDRESS TemporaryAddress;
     
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    if ((LocalAddress->DadState == NldsInvalid) ||
        (LocalAddress->DadState == NldsDuplicate)) {
        return;
    }

    IppAddressTrace(TRACE_LEVEL_WARNING, 
                    "DAD failed",
                    Protocol, NL_ADDRESS(LocalAddress), Interface->Index);
            
    Interface->DadFailures++;

    if (IsLocalUnicastAddressValid(LocalAddress)) {
        //
        // This LocalAddress is no longer available as a source address.
        //
        ASSERT(Interface->ValidLocalUnicastAddressCount > 0);
        Interface->ValidLocalUnicastAddressCount--;
        if (Interface->ValidLocalUnicastAddressCount == 0) {
            IppRestartLinkLocalAddressConfiguration(Interface);
        }   
        //
        // Remove address from route table. 
        //
        IppDeleteAutoConfiguredRoutesForAddress(
            (PIP_LOCAL_ADDRESS) LocalAddress, 
            FALSE);
    
        IppInvalidateDestinationCache(Interface->Compartment);
    }

    LocalAddress->DadState = NldsDuplicate;
    LocalAddress->DadCount = 0;

    //
    // Stop the timer if it was running. The timer might not be running in case
    // we had already completed DAD. 
    //
    if (TtIsTimerActive(&LocalAddress->Timer)) {
        TtStopTimer(Interface->UnicastAddressEventTable, &LocalAddress->Timer);
    }

    if (LocalAddress->AddressOrigin == ADDR_CONF_LINK) {
        //
        // Try to regenerate a link local address with a random identifer like 
        // temporary addresses. Limit number of retries.
        //
        if ((Interface->DadFailures < IP_LINKLOCAL_MAX_CONFLICTS) && 
            (IppRandomizeIdentifier(Interface))) {
            
            IppRemoveLocalAddressUnderLock(
                (PIP_LOCAL_ADDRESS)LocalAddress, 
                FALSE);
            
            Status = 
                Interface->Compartment->Protocol->
                    AddLinkLayerSuffixAddresses(Interface);

            if (IS_IPV4_PROTOCOL(Interface->Compartment->Protocol)) {     
                IppNotifyLinkLocalAddressChange(
                    Interface, 
                    NsiParameterNotification);
            }
        } else {
            LocalAddress->Interface->Disabled = TRUE;            
            //
            // Remove all the addresses and notify the client about it.
            //
            IppUnAddressInterfaceUnderLock(LocalAddress->Interface);
        }
    } else if (LocalAddress->PrefixOrigin == NlpoRouterAdvertisement) {
        if (LocalAddress->SuffixOrigin == NlsoRandom) {
            PublicAddress = ((PIP_LOCAL_TEMPORARY_ADDRESS) LocalAddress)->
                PublicAddress;

            //
            // Should we create a new temporary address? Check here if we have 
            // failed DAD multiple times. All the other checks (for instance,
            // is the preferred lifetime of the public address long enough) are
            // done in IppCreateLocalTemporaryAddress. 
            //
            if (Interface->DadFailures < Protocol->MaxTemporaryDadAttempts) {
                //
                // Force the creation of a new random identifier. 
                //
                Interface->TemporaryStateCreationTime = 0;
                
                //
                // Configure the new temporary address.
                //
                Status =
                    IppCreateLocalTemporaryAddress(
                        NL_ADDRESS(LocalAddress), 
                        Interface, 
                        PublicAddress, 
                        FALSE,
                        &TemporaryAddress);
                if (NT_SUCCESS(Status)) {
                    IppDereferenceLocalTemporaryAddress(TemporaryAddress);
                } 
            } else {
                IppAddressTrace(TRACE_LEVEL_WARNING, 
                                "DAD failures creating anonymous address",
                                Protocol, 
                                NL_ADDRESS(PublicAddress), 
                                Interface->Index);
            }
        }
        //
        // Remove the old router generated address. This also notifies the
        // clients. 
        //
        IppRemoveLocalAddressUnderLock((PIP_LOCAL_ADDRESS)LocalAddress, FALSE);
    } else {
        //
        // For all other addresses, inform clients that this is a duplicate
        // address. 
        //
        IppNotifyAddressChange(LocalAddress, NsiParameterNotification);
    }
}

VOID
IppAddressSetTimeout(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Handle Duplicate Address Detection timeouts for local addresses.
    Compare DADTimeout() in the XP IPv6 stack.

Arguments:

    Interface - Supplies a pointer to a interface.

Locks:

    Assumes caller holds no locks.
    Locks the interface for updating.

Caller IRQL:

    Called at DISPATCH level.

--*/
{
#define DEFAULT_COUNT 10
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    PLIST_ENTRY Head, Next;
    PIP_LOCAL_UNICAST_ADDRESS DefaultAddress[DEFAULT_COUNT],
        *Address = DefaultAddress;
    ULONG i, AddressCount = 0;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG FiredCount;
    LIST_ENTRY FiredList;
    PTIMER_ENTRY Timer;

    RtlAcquireWriteLockAtDpcLevel(&Interface->Lock, &LockHandle);

    //
    // Determine which timers fired.
    //
    FiredCount = 
        TtFireTimer(
            Interface->UnicastAddressEventTable,  
            &FiredList);

    if (FiredCount > DEFAULT_COUNT) {
        //
        // Allocate enough space to hold the action for each address which
        // we need to handle outside the lock.
        //
        Address =
            ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(*Address) * FiredCount,
                IpGenericPoolTag);
        if (Address == NULL) {
            //
            // Allocation failed!  Restart timers so we'll try again later.
            //
            while (!IsListEmpty(&FiredList)) {
                Timer = (PTIMER_ENTRY) CONTAINING_RECORD(
                    RemoveHeadList(&FiredList), TIMER_ENTRY, Link);
                TtStartTimer(
                    Interface->UnicastAddressEventTable,
                    Timer,
                    1);
            }
            RtlReleaseWriteLockFromDpcLevel(&Interface->Lock, &LockHandle);
            return;
        }
    }

    //
    // First process all the link-local addresses.  Then in the next loop,
    // process all the rest of the addresses.  This is because a non-link-local
    // address timeout might lead to the removal of a link local address.  When
    // a link-local address is removed, we try to stop its timer (because the
    // timer link is still non-empty) but as far as the timer table is
    // concerned, the link local address might not be in the table if its timer
    // has fired as well.  
    // TODO: This is only a temporary fix.  The longer term fix is to either
    // change the timer table to explicitly stop the timer even for fired
    // timers or combine the two loops below. 
    // 
    for (Head = FiredList.Flink ; Head != &FiredList; Head = Next) {
        Next = Head->Flink;
        
        LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Head, IP_LOCAL_UNICAST_ADDRESS, Timer.Link);
        if (LocalAddress->AddressOrigin != ADDR_CONF_LINK) {
            continue;
        }
        RemoveEntryList(&LocalAddress->Timer.Link);
        TtInitializeTimer(&LocalAddress->Timer);

        ASSERT(LocalAddress->DadState != NldsInvalid);

        if (LocalAddress->DadCount > 0) {
            LocalAddress->DadCount--;
            if (LocalAddress->DadCount == 0) {
                //
                // The address has passed Duplicate Address Detection.
                // Because we have passed DAD, reset the failure count. 
                //
                Interface->DadFailures = 0;
                IppDadComplete(LocalAddress);
            } else {
                Address[AddressCount] = LocalAddress;
                IppReferenceLocalUnicastAddress(LocalAddress);
                
                //
                // Time to send another solicit.
                //
                TtStartTimer(
                    Interface->UnicastAddressEventTable,
                    &LocalAddress->Timer,
                    Interface->RetransmitTicks);
                
                AddressCount++;
            }
        } else {
            //
            // This is a non DAD timeout, related to the lifetime of the
            // address. 
            //
            IppHandleAddressLifetimeTimeout(LocalAddress);
        }
    }

    while (!IsListEmpty(&FiredList)) {
        Head = RemoveHeadList(&FiredList);

        LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Head, IP_LOCAL_UNICAST_ADDRESS, Timer.Link);
        TtInitializeTimer(&LocalAddress->Timer);

        ASSERT(LocalAddress->DadState != NldsInvalid);

        if (LocalAddress->DadCount > 0) {
            LocalAddress->DadCount--;
            if (LocalAddress->DadCount == 0) {
                //
                // The address has passed Duplicate Address Detection.
                // Because we have passed DAD, reset the failure count. 
                //
                Interface->DadFailures = 0;
                IppDadComplete(LocalAddress);
            } else {
                Address[AddressCount] = LocalAddress;
                IppReferenceLocalUnicastAddress(LocalAddress);
                
                //
                // Time to send another solicit.
                //
                TtStartTimer(
                    Interface->UnicastAddressEventTable,
                    &LocalAddress->Timer,
                    Interface->RetransmitTicks);
                
                AddressCount++;
            }
        } else {
            //
            // This is a non DAD timeout, related to the lifetime of the
            // address. 
            //
            IppHandleAddressLifetimeTimeout(LocalAddress);
        }
    }
    
    RtlReleaseWriteLockFromDpcLevel(&Interface->Lock, &LockHandle);

    //
    // Now that we've released the lock, we can walk our list and safely take
    // any actions which may entail calling outside our own module.
    //
    for (i = 0; i < AddressCount; i++) {
        LocalAddress = Address[i];

        IppSendDadSolicitation(LocalAddress);
        IppDereferenceLocalUnicastAddress(LocalAddress);
    }

    if (Address != DefaultAddress) {
        ExFreePool(Address);
    }
}


NTSTATUS
IppGetNextAddress(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address OPTIONAL,
    IN PNLA_SET AddressSet,
    OUT PIP_LOCAL_ADDRESS *AddressPointer
    )
/*++

Routine Description:

    Find the next entry for an address that is just higher than the specified
    value in the list of addresses.  This works for unicast as well as anycast
    addresses. 

Arguments:

    Interface - Supplies a pointer to an interface.

    Address - Supplies an address value.

    AddressSet - Supplies the address set to search in.

    AddressPointer - Receives a pointer to an address entry found, on success.

Return Value:

    STATUS_SUCCESS
    STATUS_NO_MORE_ENTRIES

Locks:

    Locks interface for reading.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;
    KIRQL OldIrql;
    PNLA_LINK Pointer;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PIP_LOCAL_ADDRESS LocalAddress, Found = NULL;
    ULONG AddressBytes =
        Interface->Compartment->Protocol->Characteristics->AddressBytes;

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);
    {
        //
        // Walk the set looking for the first entry after the 
        // address passed in.
        //
        IppInitializeAddressEnumerationContext(&Context);
        for (;;) {
            Pointer = IppEnumerateNlaSetEntry(
                AddressSet, 
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
            if (Pointer == NULL) {
                break;
            }
            
            LocalAddress = (PIP_LOCAL_ADDRESS)CONTAINING_RECORD(
                Pointer, IP_LOCAL_ADDRESS, Link);
            
            if ((Address != NULL) &&
                (memcmp(NL_ADDRESS(LocalAddress), Address, AddressBytes) <= 
                 0)) {
                continue;
            }
            
            if ((Found == NULL) ||
                (memcmp(
                    NL_ADDRESS(LocalAddress), NL_ADDRESS(Found), AddressBytes)
                 < 0)) {
                //
                // We have a (more) appropriate match.
                //
                Found = LocalAddress;
            }
        }
    }
        
    if (Found != NULL) {
        IppReferenceLocalAddress(Found);
        Status = STATUS_SUCCESS;
    } else {
        Status = STATUS_NO_MORE_ENTRIES;
    }
    
    RtlReleaseReadLock(&Interface->Lock, OldIrql);
    
    *AddressPointer = Found;
    return Status;
}


NTSTATUS
IppGetNextUnicastAddress(
    IN PIP_INTERFACE Interface, 
    IN CONST UCHAR *Address OPTIONAL,
    OUT PIP_LOCAL_UNICAST_ADDRESS *AddressPointer
    )
/*++

Routine Description:

    Find the next entry for a unicast address that is just higher than the 
    specified value in the list of addresses.

Arguments:

    Interface - Supplies a pointer to an interface.

    Address - Supplies an address value.

    AddressPointer - Receives a pointer to an address entry found, on success.

Return Value:

    STATUS_SUCCESS
    STATUS_NO_MORE_ENTRIES

Locks:

    Locks interface for reading.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    return IppGetNextAddress(Interface, 
                             Address,
                             &Interface->LocalUnicastAddressSet,
                             (PIP_LOCAL_ADDRESS *) AddressPointer);
}


NTSTATUS
IppGetNextMulticastAddress(
    IN PIP_INTERFACE Interface, 
    IN CONST UCHAR *Address OPTIONAL,
    OUT PIP_LOCAL_MULTICAST_ADDRESS *AddressPointer
    )
/*++

Routine Description:

    Find the next entry for a multicast address that is just higher than the 
    specified value in the list of addresses.

Arguments:

    Interface - Supplies a pointer to an interface.

    Address - Supplies an address value.

    AddressPointer - Receives a pointer to an address entry found, on success.

Return Value:

    STATUS_SUCCESS
    STATUS_NO_MORE_ENTRIES

Locks:

    Locks interface for reading.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    return IppGetNextAddress(Interface, 
                             Address,
                             &Interface->LocalMulticastAddressSet, 
                             (PIP_LOCAL_ADDRESS *) AddressPointer);
}

NTSTATUS
IppGetFirstAddress(
    IN PIP_INTERFACE Interface,
    IN PNLA_SET AddressSet,
    OUT PIP_LOCAL_ADDRESS *AddressPointer
    )
/*++

Routine Description:

    Returns a referenced pointer to the first address on a given interface of a
    given type.

Arguments:

    Interface - Supplies a pointer to an interface.

    AddressSet - Supplies the address set. 

    AddressPointer - On success, receives a pointer to a unicast address entry.

Return Value:

    STATUS_SUCCESS
    STATUS_NO_MORE_ENTRIES

Locks:

    Locks interface for reading.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    return IppGetNextAddress(Interface, NULL, AddressSet, AddressPointer);
}


NTSTATUS
IppGetFirstUnicastAddress(
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *AddressPointer
    )
/*++

Routine Description:

    Returns a referenced pointer to the first unicast address on a given
    interface.

Arguments:

    Interface - Supplies a pointer to an interface.

    AddressPointer - On success, receives a pointer to a unicast address entry.

Return Value:

    STATUS_SUCCESS
    STATUS_NO_MORE_ENTRIES

Locks:

    Locks interface for reading.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    return IppGetFirstAddress(Interface, 
                              &Interface->LocalUnicastAddressSet, 
                              (PIP_LOCAL_ADDRESS*) AddressPointer);
}


NTSTATUS
IppGetFirstMulticastAddress(
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_MULTICAST_ADDRESS *AddressPointer
    )
/*++

Routine Description:

    Returns a referenced pointer to the first multicast address on a given
    interface.

Arguments:

    Interface - Supplies a pointer to an interface.

    AddressPointer - On success, receives a pointer to a multicast address 
        entry.

Return Value:

    STATUS_SUCCESS
    STATUS_NO_MORE_ENTRIES

Locks:

    Locks interface for reading.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    return IppGetFirstAddress(Interface, 
                              &Interface->LocalMulticastAddressSet, 
                              (PIP_LOCAL_ADDRESS*) AddressPointer);
}

PIP_LOCAL_ADDRESS
IppFindAddressInAddressSetUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    This routine checks to see whether a given address is assigned to
    a particular interface.

Arguments:

    Interface - Supplies a pointer to the interface to check.

    Address - Supplies the IP address to search for.

    AddressType - Supplies the type of the address.  This determines the
        address set on the interface that will be searched. 

Return Value:

    Returns a pointer to the local address object if found.

Locks:

    Assumes caller holds a read or write lock on the interface.
    Assumes caller holds at least a reference on the interface.
    Caller is responsible for dereferencing AddressPointer on success.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress = NULL;
    PVOID NodeOrParent, Pointer;
    TABLE_SEARCH_RESULT SearchResult;
    PNLA_SET AddressSet;
    ULONG AddressEntrySize;
    ULONG AddressBytes =
        Interface->Compartment->Protocol->Characteristics->AddressBytes;

    ASSERT_ANY_LOCK_HELD(&Interface->Lock);

    AddressSet = IppGetAddressSet(Interface, AddressType);
    AddressEntrySize = IppGetAddressEntrySize(AddressType);
    
    Pointer = IppFindNlaSetEntry(
        AddressSet,
        Address,
        AddressEntrySize - FIELD_OFFSET(IP_LOCAL_ADDRESS, Link), 
        AddressBytes,
        &NodeOrParent,
        &SearchResult);

    if (Pointer != NULL) {
        LocalAddress =
            CONTAINING_RECORD(Pointer, IP_LOCAL_ADDRESS, Link);
        IppReferenceLocalAddress(LocalAddress);
    }

    return LocalAddress;
}

PIP_LOCAL_ADDRESS
IppFindAddressInAddressSet(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    This routine checks to see whether a given address is assigned to
    a particular interface.

Arguments:

    Interface - Supplies a pointer to the interface to check.

    Address - Supplies the IP address to search for.

    AddressType - Supplies the type of the address.  This determines the
        address set on the interface that will be searched. 

Return Value:

    Returns a pointer to the local address object if found.

Locks:

    Assumes caller holds at least a reference on the interface.
    Caller is responsible for dereferencing AddressPointer on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress;
    KIRQL OldIrql;

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);
    LocalAddress = IppFindAddressInAddressSetUnderLock(
        Interface,
        Address, 
        AddressType);
    RtlReleaseReadLock(&Interface->Lock, OldIrql);

    return LocalAddress;
}

BOOLEAN
IppIsScopeIdCanonicalized(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST UCHAR *Address, 
    IN SCOPE_ID ScopeId
    )
/*++

Routine Description:
    
    This routine checks whether a given scope ID is in the canonicalized form
    or not. 

Arguments:

    Compartment - Supplies the compartment.

    Address - Supplies the address. 

    ScopeId - Supplies the scope ID to check.

Return Value:

    TRUE if the scope ID is canonicalized. FALSE otherwise.

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_PROTOCOL Protocol = Compartment->Protocol;

    if (ScopeLevel(ScopeId) != Protocol->AddressScope(Address)) {
        return FALSE;
    }
    
    if ((INET_IS_ADDR_LOOPBACK(Protocol->Family, Address) &&
         (ScopeId.Zone != Compartment->LoopbackIndex)) ||
        ((ScopeId.Level == ScopeLevelGlobal) &&
         (ScopeId.Zone != (ULONG)Compartment->CompartmentId))) {
        return FALSE;
    }
    
    return TRUE;
}


BOOLEAN
IppCanonicalizeScopeId(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Address,
    IN OUT SCOPE_ID *ScopeId
    )
/*++

Routine Description:

    Given an address and ScopeId, converts the ScopeId for internal usage.
    Also returns the address scope.

Arguments:

    Compartment - Supplies the compartment.  The canonicalized scope zone for
        global and loopback addresses depends on the compartment. 

    Address - Supplies an IP address.

    ScopeId - Supplies a scope id.  Returns a canonicalized scope id.

Return Value:

    Returns FALSE if the ScopeId is invalid.

--*/
{
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    
    //
    // The loopback address and global-scope addresses are special:
    // callers can supply a zero ScopeId without ambiguity.
    // See also DetermineScopeId and RouteToDestination.
    // For the moment, we enforce a zero ScopeId for those addresses
    // lest we confuse TCP & UDP by having two legal ScopeId values
    // for a single address which should be considered the same and
    // for which DetermineScopeId returns zero.
    //

    if (ScopeId->Level == 0) {
        ScopeId->Level = Protocol->AddressScope(Address);
    } else if (ScopeLevel(*ScopeId) != Protocol->AddressScope(Address)) {
        return FALSE;
    }

    if (ScopeId->Level == ScopeLevelGlobal) {
        if (ScopeId->Zone == 0) {
            ScopeId->Zone = Compartment->CompartmentId;
        } else {
            return FALSE;
        }
    } else if (INET_IS_ADDR_LOOPBACK(Protocol->Family, Address)) {
        if (ScopeId->Zone == 0) {
            ScopeId->Zone = Compartment->LoopbackIndex;
        } else {
            return FALSE;
        }
    }

    return TRUE;
}

PIP_LOCAL_ADDRESS
IppFindAddressInScopeEx(
    IN PIP_COMPARTMENT Compartment,
    IN SCOPE_ID ScopeId,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    See whether a given address is assigned to the local (virtual) machine.
    This is done whenever the classification handle can't be used to
    do this lookup.

Arguments:

    Compartment - Supplies a pointer to the compartment.
    
    ScopeId - Supplies the scope id in which to find an address.

    Address - Supplies the address to find.
        
Return Value:
    
    Returns a pointer to the local address structure found.
    Caller is responsible for dereferencing the address returned on success.
    
Locks:

    Assumes caller holds at least a reference on the compartment.
    Acquires a read lock on the per-compartment interface set.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PLIST_ENTRY Link;
    PIP_INTERFACE Interface;
    PIP_LOCAL_ADDRESS LocalAddress = NULL;
    KIRQL OldIrql;

    ASSERT(IppIsScopeIdCanonicalized(Compartment, Address, ScopeId));
    
    RtlAcquireReadLock(&Compartment->InterfaceSet.Lock,  &OldIrql);

    //
    // TODO: find a way to optimize this lookup.
    // Strong host lookup doesn't need to call this.
    // For weak host lookup, only need to search iif, and then could
    // use routing table lookup with host routes.
    //

    // for each interface in component
    //    if interface is not in scope, continue
    //        find address on interface

    for (Link = Compartment->InterfaceSet.Set.Flink;
         Link != &Compartment->InterfaceSet.Set;
         Link = Link->Flink) {

        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Link, IP_INTERFACE, CompartmentLink);
        if (!IppIsInterfaceInScope(Interface, ScopeId)) {
            continue;
        }

        LocalAddress = 
            IppFindAddressOnInterfaceEx(Interface, Address);
        if (LocalAddress != NULL) {
            break;
        }
    }

    RtlReleaseReadLock(&Compartment->InterfaceSet.Lock, OldIrql);

    return LocalAddress;
}

PIP_LOCAL_ADDRESS
IppFindLocalAddress(
    IN PIP_COMPARTMENT Compartment,
    IN PNL_LOCAL_ADDRESS_ARG Arg
    )
/*++

Routine Description:

    Searches for a given IP address within a compartment.  This function is not
    called directly by external NL clients.  But we consider it to part of the
    network layer NPI since is only called as a result of external client calls
    and it gets passed a NLNPI structure.  

    Note that if the address is a unicast address, only valid address is 
    returned.

Arguments:

    Compartment - Supplies a pointer to the compartment to search in.

    Arg - Supplies information identifying an address to find.  The scope ID in
        the structure is uncanonicalized since this is at the boundary. 

Return Value:

    Returns a pointer to the address entry found, on success.

Locks:

    Caller is responsible for dereferencing the address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress;
    SCOPE_ID ScopeId;
    
    if (Arg->LocalAddress != NULL) {
        LocalAddress = IppCast(Arg->LocalAddress, IP_LOCAL_ADDRESS);
        if ((NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast) && 
            !IsLocalUnicastAddressValid((PIP_LOCAL_UNICAST_ADDRESS) 
                LocalAddress)) {
            return NULL;
        }
        IppReferenceLocalAddress(LocalAddress);
        return LocalAddress;
    } else if (Arg->Address == NULL) {
        return NULL;
    } else {
        //
        // This routine is called by external clients; so we need to
        // canonicalize the scope ID.  
        //
        ScopeId = Arg->ScopeId;
        if (!IppCanonicalizeScopeId(Compartment, Arg->Address, &ScopeId)) {
            return NULL;
        }
        return IppFindAddressInScope(Compartment, ScopeId, Arg->Address);
    }
}

SCOPE_ID
IppGetScopeId(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    Construct the scope id corresponding to a given address.

Arguments:

    Interface - Supplies a pointer to an interface in the scope zone.

    Address - Supplies the IP address.

Return Value:

    Returns the scope id corresponding to the address.

Locks:

    Assumes caller holds a reference on Interface.  If the caller 
    requires consistency of the scope id, it should hold at least
    a read lock on the protocol's ZoneUpdateLock.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    SCOPE_ID ScopeId;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;

    ScopeId.Level = Protocol->AddressScope(Address);

    ScopeId.Zone = IppGetInterfaceScopeZone(Interface, ScopeId.Level);

    return ScopeId;
}

SCOPE_ID
IppGetExternalScopeId(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    Construct the scope id corresponding to a given address for external
    clients.  The scope level in the scope ID is always 0 while the scope zone
    is the un-canonicalized scope zone. 

Arguments:

    Interface - Supplies a pointer to an interface in the scope zone.

    Address - Supplies the IP address.

Return Value:

    Returns the scope id corresponding to the address for external clients of
    the network layer.

Locks:

    Assumes caller holds a reference on Interface.  If the caller 
    requires consistency of the scope id, it should hold at least
    a read lock on the protocol's ZoneUpdateLock.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    SCOPE_ID ScopeId = {0};
    ULONG ScopeLevel = Protocol->AddressScope(Address);
    
    //
    // For external clients, always return a scope zone of 0 for global
    // addresses and loopback addresses. 
    //
    if ((ScopeLevel != ScopeLevelGlobal) &&
        !INET_IS_ADDR_LOOPBACK(Protocol->Family, Address)) {
        ScopeId.Zone = IppGetInterfaceScopeZone(Interface, ScopeLevel);
    }
    
    return ScopeId;
}

PIP_LOCAL_ADDRESS
IppFindAddressOnInterfaceEx(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    This routine checks to see whether a given address is assigned to
    a particular interface.  The address may be of any type.

Arguments:

    Interface - Supplies a pointer to the interface to check.

    Address - Supplies the IP address to search for.
    
Return Value:

    Returns a pointer to the local address object if found.

Locks:

    Assumes caller holds at least a reference on the interface.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress;
    KIRQL OldIrql;    

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);       
    LocalAddress = 
        IppFindAddressOnInterfaceExUnderLock(
            Interface, 
            Address);
    RtlReleaseReadLock(&Interface->Lock, OldIrql);        

    return LocalAddress;
}

PIP_LOCAL_ADDRESS
IppFindAddressOnInterfaceExUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    This routine checks to see whether a given address is assigned to
    a particular interface.  The address may be of any type.

Arguments:

    Interface - Supplies a pointer to the interface to check.

    Address - Supplies the IP address to search for. 
        
Return Value:

    Returns a pointer to the local address object if found.

Locks:

    Assumes caller holds a read or write lock on the interface.
    Caller is responsible for dereferencing AddressPointer on success.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIP_LOCAL_ADDRESS LocalAddress;
    
    ASSERT_ANY_LOCK_HELD(&Interface->Lock);

    if (Protocol->AddressType(Address) == NlatMulticast) {
        return (PIP_LOCAL_ADDRESS)IppFindMulticastAddressOnInterfaceUnderLock(
            Interface, Address);
    } 

    //
    // Try unicast addresses. 
    //
    LocalAddress = IppFindAddressInAddressSetUnderLock(
        Interface,
        Address, 
        NlatUnicast);
    if (LocalAddress != NULL) {
        return LocalAddress;
    }
    
    //
    // Try broadcast addresses. 
    // 
    LocalAddress = IppFindAddressInAddressSetUnderLock(
        Interface, 
        Address, 
        NlatBroadcast);
    if (LocalAddress != NULL) {
        return LocalAddress;
    }

    //
    // Try anycast addresses. 
    // 
    LocalAddress = IppFindAddressInAddressSetUnderLock(
        Interface, 
        Address, 
        NlatAnycast);
    if (LocalAddress != NULL) {
        return LocalAddress;
    }

    return NULL;
}

PIP_LOCAL_ADDRESS
IppCreateLocalAddress(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN ULONG PreferredLifetime,
    IN ULONG ValidLifetime,
    IN ULONG PrefixLength,
    IN OPTIONAL PIP_LOCAL_UNICAST_ADDRESS PublicAddress
    )
/*++

Routine Description:

    Create a local unicast address, but don't add it to any data structure.
    Besides being used for normal address addition before adding to
    an interface, this can be used for cases where we want state for
    things other than valid addresses, such as in the validate phase
    of a transaction. This works for unicast, temporary, broadcast and
    multicast addresses. 

Arguments:

    Protocol - Supplies a pointer to the global protocol state.

    Address - Supplies the unicast address to add.

    AddressType - Supplies the type of the address. 

    Interface - Supplies a pointer to the interface to put the interface on.
    
    AddressOrigin - Supplies the origin of the address. 

    PreferredLifetime - Supplies the preferred lifetime of the address. 
    
    ValidLifetime - Supplies the valid lifetime of the address. 
    
    PrefixLength - Supplies the prefix length of the on-link route
        corresponding to the address. 

    PublicAddress - Supplies the public address corresponding to a temporary
        address. Relevant only when a temporary address is created. 

Return Value:

    Returns the address added, or NULL on failure.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress;
    PIP_LOCAL_UNICAST_ADDRESS LocalUnicastAddress;
    PIP_LOCAL_MULTICAST_ADDRESS LocalMulticastAddress;
    ULONG AddressEntrySize = IppGetAddressEntrySize(AddressType);
    HANDLE AllocationPool = 
        IppGetAddressAllocationPool(Protocol, AddressType);
     
    ASSERT(AllocationPool != NULL);
    ASSERT(Protocol == Interface->Compartment->Protocol);
    ASSERT((AddressType == NlatUnicast) || 
           (AddressType == NlatAnycast) ||
           (AddressType == NlatBroadcast) ||
           (AddressType == NlatMulticast));
    
    LocalAddress = (PIP_LOCAL_ADDRESS)FsbAllocate(AllocationPool);
    if (LocalAddress == NULL) {
        IppAddressTrace(TRACE_LEVEL_WARNING, 
                        "Error allocating address",
                        Protocol, Address, Interface->Index);
        return NULL;
    }

    RtlZeroMemory(LocalAddress, AddressEntrySize);

    LocalAddress->Identifier = IppFindOrCreateLocalAddressIdentifier(
        Interface->Compartment,
        Address, 
        IppGetScopeId(Interface, Address));
    if (LocalAddress->Identifier == NULL) {
        IppAddressTrace(TRACE_LEVEL_WARNING, 
                        "Error allocating address identifier",
                        Protocol, Address, Interface->Index);
        FsbFree((PUCHAR) LocalAddress);
        return NULL;
    }

    LocalAddress->Interface = Interface;
    IppReferenceInterface(LocalAddress->Interface);

    LocalAddress->Type = AddressType;
    
    //
    // Also copy the address into the local address structure.  This is only
    // for the purpose of the adaptive table because it is easier to have a
    // constant offset rather than dereferencing the address pointer. 
    // $$REVIEW: This should be changed by making the implementation of
    // adaptive table more specific to addresses. 
    //
    RtlCopyMemory(((PUCHAR) LocalAddress) + AddressEntrySize, 
                  Address, 
                  Protocol->Characteristics->AddressBytes);
    
    LocalAddress->Signature = IP_LOCAL_ADDRESS_SIGNATURE;
    LocalAddress->AddressOrigin = AddressOrigin;
    LocalAddress->ReferenceCount = 1;
    InitializeListHead(&LocalAddress->Link.ListLink);
    
    if (AddressType == NlatUnicast) {
        //
        // Set unicast address specific fields (e.g. DAD state). 
        //
        LocalUnicastAddress = (PIP_LOCAL_UNICAST_ADDRESS)LocalAddress;
        
        if ((LocalAddress->AddressOrigin == ADDR_CONF_DHCP) ||
            ((Protocol->Level == IPPROTO_IPV6) &&
             ((LocalAddress->SuffixOrigin == IpSuffixOriginLinkLayerAddress) ||
              (LocalAddress->SuffixOrigin == IpSuffixOriginRandom)))) {
            //
            // The address is extremely likely to be unique, so do  
            // optimistic DAD.  The behavior here is the same as if we
            // already had the address and just reconnected to the link.
            //
            LocalUnicastAddress->DadState = NldsPreferred;
        } else {
            LocalUnicastAddress->DadState = NldsTentative;
        }

        TtInitializeTimer(&LocalUnicastAddress->Timer);
        LocalUnicastAddress->ValidLifetime = ValidLifetime; 
        LocalUnicastAddress->PreferredLifetime = PreferredLifetime;
        LocalUnicastAddress->LifetimeBaseTime = 
            LocalUnicastAddress->CreationTime = IppTickCount;
        LocalUnicastAddress->PrefixLength = PrefixLength;
        
        //
        // Set the public address for temporary addresses. 
        // 
        if (AddressOrigin == ADDR_CONF_TEMPORARY) {
            IppReferenceLocalUnicastAddress(PublicAddress);
            ((PIP_LOCAL_TEMPORARY_ADDRESS)LocalAddress)->PublicAddress = 
                PublicAddress;
        }
    } else if (AddressType == NlatMulticast) {
        LocalMulticastAddress = (PIP_LOCAL_MULTICAST_ADDRESS) LocalAddress;
        
        IppInitializeNliSet(&LocalMulticastAddress->SourceList);
        TtInitializeTimer(&LocalMulticastAddress->ReportTimer);
        TtInitializeTimer(&LocalMulticastAddress->GeneralQueryTimer);
        TtInitializeTimer(&LocalMulticastAddress->SpecificQueryTimer);

        LocalMulticastAddress->Pending = FALSE;
    }

    return LocalAddress;
}

NTSTATUS
IppFindOrCreateLocalAddress(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN ULONG PreferredLifetime,
    IN ULONG ValidLifetime,
    IN ULONG PrefixLength,
    IN BOOLEAN CreateOnLinkRoute,
    IN PIP_LOCAL_UNICAST_ADDRESS PublicAddress,
    IN BOOLEAN RouteSetLockHeld,
    IN PIP_LOCAL_ADDRESS PreAllocatedAddress OPTIONAL,
    OUT PIP_LOCAL_ADDRESS *ReturnLocalAddress
    )
/*++

Routine Description:

    Searches for an address on a given interface.  If not found, an
    entry is created.  The routine works for all flavors of unicast addresses
    including temporary addresses as well as broadcast (and potentially
    anycast) addresses. Note that if the address is already in the
    address set, it is NOT updated (the lifetime values, address origin
    etc. are NOT changed to the new values; the caller is responsible for doing
    this). If the address is not already present, then the routine allocates
    memory for the unicast address, sets the various fields in it and starts
    DAD if needed. So, the lifetime values etc. are relevant only when creating
    a new address. 

Arguments:

    Protocol - Supplies a pointer to the global protocol state.

    Address - Supplies the unicast address to search for.

    AddressType - Supplies the type of the address. 

    Interface - Supplies a pointer to the interface to search on.

    AddressOrigin - Supplies the origin of the address. 

    PreferredLifetime - Supplies the preferred lifetime of the address. 
    
    ValidLifetime - Supplies the valid lifetime of the address. 
    
    PrefixLength - Supplies the length of the prefix associated with the
        address.  

    CreateOnLinkRoute - Supplies a boolean indicating whether an on-link route
        should be created or not. 

    PublicAddress - Supplies the public address corresponding to a temporary
        address. Relevant only when a temporary address is created. 

    RouteSetLockHeld - Supplies a boolean indicating whether the route set lock
        is already held or not.

    PreAllocatedAddress - In case this routine is called from a
        transaction, the address might have been preallocated. This parameter 
        passes the pre allocated address to the routine. 

    ReturnLocalAddress - Receives a pointer to the entry found or created.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS

Locks:

    Assumes caller holds a write lock on the interface.
    Caller is responsible for releasing the refcount on ReturnLocalAddress when
        it is deleted.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    NTSTATUS Status;
    PIP_LOCAL_ADDRESS LocalAddress;
    PVOID NodeOrParent;
    TABLE_SEARCH_RESULT SearchResult;
    ULONG AddressEntrySize, 
        AddressBytes = Protocol->Characteristics->AddressBytes;
    PNLA_LINK Link;
    IN PNLA_SET AddressSet;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    //
    // PublicAddress is only relevant for temporary addresses. 
    //
    ASSERT(((PublicAddress == NULL) &&
            (AddressOrigin != ADDR_CONF_TEMPORARY)) ||
           ((PublicAddress != NULL) &&
            (AddressOrigin == ADDR_CONF_TEMPORARY)));
    
    AddressSet = IppGetAddressSet(Interface, AddressType);
    AddressEntrySize = IppGetAddressEntrySize(AddressType);

    Link =
        IppFindNlaSetEntry(
            AddressSet, 
            Address,
            AddressEntrySize -
            FIELD_OFFSET(IP_LOCAL_UNICAST_ADDRESS, Link),
            AddressBytes,
            &NodeOrParent, 
            &SearchResult);
    if (Link != NULL) {
        //
        // We found an already existing address entry. 
        //
        LocalAddress = CONTAINING_RECORD(Link, IP_LOCAL_ADDRESS, Link);
        IppReferenceLocalAddress(LocalAddress);
        goto Done;
    }

    if (PreAllocatedAddress != NULL) {
        LocalAddress = PreAllocatedAddress;
    } else {
        LocalAddress =
            IppCreateLocalAddress(
                Protocol,
                Address, 
                AddressType,
                Interface,
                AddressOrigin, 
                PreferredLifetime, 
                ValidLifetime, 
                PrefixLength,
                PublicAddress);
        if (LocalAddress == NULL) {
            IppAddressTrace(TRACE_LEVEL_WARNING, 
                            "Error allocating address", 
                            Protocol, Address, Interface->Index);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ErrorCreation;
        }
    }

    //
    // A new address was created.  Call the protocol specific helper routine. 
    // 
    if (Protocol->AddressCreationHelper != NULL) {
        //
        // This may return STATUS_PENDING if it causes an asynchronous
        // multicast group join, but we'll treat that the same as success,
        // keeping our reference.
        // REVIEW: This means we currently ignore a failure if it's 
        // asynchronous, but fail to create the address if the failure is
        // synchronous.
        //
        Status = Protocol->AddressCreationHelper(Interface, Address);
        if (!NT_SUCCESS(Status)) {
            IppAddressTrace(TRACE_LEVEL_WARNING, 
                            "Error creating address: Protocol helper failed", 
                            Protocol, Address, Interface->Index);
            goto ErrorHelper;
        }
    }
    
    LocalAddress->CreateOnLinkRoute = CreateOnLinkRoute;
    
    //
    // We are now going to add routes for non-unicast addresses. 
    // For unicast addresses, add routes for optimistic DAD scenario.
    //
    if ((AddressType != NlatUnicast) || 
        IsLocalUnicastAddressValid((PIP_LOCAL_UNICAST_ADDRESS) LocalAddress)) {
        Status = 
            IppAddAutoConfiguredRoutesForAddress(
                LocalAddress, 
                RouteSetLockHeld);
        if (!NT_SUCCESS(Status)) {
            goto ErrorUpdatingRoute;
        }
    }
    
    //
    // Add a reference for storing in the table.
    // Return the other to the caller.
    //
    IppReferenceLocalAddress(LocalAddress);

    KeQuerySystemTime(&LocalAddress->CreationTimestamp);        
        
    //
    // Insert address into the table. 
    //
    IppInsertNlaSetEntry(
        AddressSet, 
        &LocalAddress->Link,
        AddressEntrySize - FIELD_OFFSET(IP_LOCAL_ADDRESS, Link), 
        AddressBytes,
        NodeOrParent, 
        SearchResult);

    IppAddressTrace(TRACE_LEVEL_WARNING, 
                    "Created address", 
                    Protocol, Address, Interface->Index);

    //
    // Notify NSI clients and start Duplicate Address 
    // Detection for unicast addresses.
    //
    if (AddressType == NlatUnicast) {
        PIP_LOCAL_UNICAST_ADDRESS UnicastAddress = 
            (PIP_LOCAL_UNICAST_ADDRESS)LocalAddress;

        IppNotifyAddressChange(UnicastAddress, NsiAddInstance);
        IppStartDad(UnicastAddress);
    } 
    
Done:
    *ReturnLocalAddress = LocalAddress;

    return STATUS_SUCCESS;

ErrorUpdatingRoute:
    if (Protocol->AddressDeletionHelper != NULL) {
        Protocol->AddressDeletionHelper(Interface, Address);
    }
ErrorHelper:
    IppCleanupLocalAddress((PIP_LOCAL_ADDRESS)LocalAddress);
ErrorCreation:
    return Status;
}

NTSTATUS
IppFindOrCreateLocalUnicastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN ULONG PreferredLifetime, 
    IN ULONG ValidLifetime,
    IN ULONG PrefixLength,
    IN BOOLEAN CreateOnLinkRoute,
    OUT PIP_LOCAL_UNICAST_ADDRESS *ReturnLocalAddress
    )
/*++

Routine Description:

    This routine searches for a unicast address on a given interface.  If not
    found, an entry is created.  It just calls IppFindOrCreateLocalAddress with
    the right parameters. 

Arguments:

    Address - Supplies the unicast address to search for.

    Interface - Supplies a pointer to the interface to search on.

    AddressOrigin - Supplies the origin of the address. 

    PreferredLifetime - Supplies the preferred lifetime of the address. 
    
    ValidLifetime - Supplies the valid lifetime of the address. 
    
    PrefixLength - Supplies the length of the prefix associated with the
        address.  

    CreateOnLinkRoute - Supplies a boolean indicating whether an on-link route
        should be created or not. 

    ReturnLocalAddress - Receives a pointer to the entry found or created.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS

Locks:

    Assumes caller holds a write lock on the interface.
    Caller is responsible for releasing the refcount on ReturnLocalAddress when
        it is deleted.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    return
        IppFindOrCreateLocalAddress(
            Protocol,
            Address,
            NlatUnicast,
            Interface, 
            AddressOrigin, 
            PreferredLifetime, 
            ValidLifetime, 
            PrefixLength,
            CreateOnLinkRoute,
            NULL,
            FALSE,
            NULL,
            (PIP_LOCAL_ADDRESS*)ReturnLocalAddress);
}

NTSTATUS
IppFindOrCreateLocalBroadcastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN BOOLEAN RouteSetLockHeld, 
    OUT PIP_LOCAL_BROADCAST_ADDRESS *ReturnLocalAddress
    )
/*++

Routine Description:

    This routine searches for a broadcast address on a given interface.  If not
    found, an entry is created.  It just calls IppFindOrCreateLocalAddress with
    the right parameters. 

Arguments:

    Address - Supplies the unicast address to search for.

    Interface - Supplies a pointer to the interface to search on.

    AddressOrigin - Supplies the origin of the address. 

    RouteSetLockHeld - Supplies a boolean indicating whether the route set lock
        is held or not.

    ReturnLocalAddress - Receives a pointer to the entry found or created.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS

Locks:

    Assumes caller holds a write lock on the interface.
    Caller is responsible for releasing the refcount on ReturnLocalAddress when
        it is deleted.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    return
        IppFindOrCreateLocalAddress(
            Protocol,
            Address,
            NlatBroadcast,
            Interface, 
            AddressOrigin, 
            INFINITE_LIFETIME, 
            INFINITE_LIFETIME, 
            8 * Protocol->Characteristics->AddressBytes,
            FALSE,
            NULL,
            RouteSetLockHeld,
            NULL,
            (PIP_LOCAL_ADDRESS*)ReturnLocalAddress);
}

NTSTATUS
IppFindOrCreateLocalAnycastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN BOOLEAN RouteSetLockHeld,
    OUT PIP_LOCAL_ANYCAST_ADDRESS *ReturnLocalAddress
    )
/*++

Routine Description:

    This routine searches for an anycast address on a given interface.  If not
    found, an entry is created.  It just calls IppFindOrCreateLocalAddress with
    the right parameters. 

Arguments:

    Address - Supplies the unicast address to search for.

    Interface - Supplies a pointer to the interface to search on.

    AddressOrigin - Supplies the origin of the address. 

    RouteInstance - Supplies the route instance to update with the host
        route. This is non-NULL if the route set is already locked for
        update. Otherwise, the routine locks the route set for adding the
        route.  

    ReturnLocalAddress - Receives a pointer to the entry found or created.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS

Locks:

    Assumes caller holds a write lock on the interface.
    Caller is responsible for releasing the refcount on ReturnLocalAddress when
        it is deleted.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    return
        IppFindOrCreateLocalAddress(
            Protocol,
            Address,
            NlatAnycast,
            Interface, 
            AddressOrigin, 
            INFINITE_LIFETIME, 
            INFINITE_LIFETIME, 
            8 * Protocol->Characteristics->AddressBytes,
            FALSE,
            NULL,
            RouteSetLockHeld,
            NULL,
            (PIP_LOCAL_ADDRESS*)ReturnLocalAddress);
}

NTSTATUS
IppFindOrCreateLocalUnspecifiedAddress(
    IN PIP_INTERFACE Interface, 
    OUT PIP_LOCAL_UNICAST_ADDRESS *UnspecifiedAddress
    )
/*++

Routine Description:

    This routine looks for the unspecified address on a given interface.  If not
    found, an address is created.  

Arguments:

    Interface - Supplies a pointer to the interface on which to create the
        unspecified address. 

    UnspecifiedAddress - Receives a pointer to the entry found or created.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS

Locks:

    None. 
    Acquires the interface write lock. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_PROTOCOL Protocol;
    KLOCK_QUEUE_HANDLE LockHandle;
    NTSTATUS Status;
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    if (Interface->UnspecifiedAddress == NULL) {
        Protocol = Interface->Compartment->Protocol;
        Interface->UnspecifiedAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            IppCreateLocalAddress(
                Protocol, 
                (PUCHAR) &in6addr_any,
                NlatUnicast, 
                Interface, 
                ADDR_CONF_MANUAL, 
                INFINITE_LIFETIME, 
                INFINITE_LIFETIME, 
                8 * Protocol->Characteristics->AddressBytes,
                NULL);
        if (Interface->UnspecifiedAddress != NULL) {
            //
            // Making the unspecified address Preferred as this will allow it 
            // to pass path validation tests.
            //
            Interface->UnspecifiedAddress->DadState = NldsPreferred;
        }
    }
    
    if (Interface->UnspecifiedAddress == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        IppReferenceLocalUnicastAddress(Interface->UnspecifiedAddress);
        *UnspecifiedAddress = Interface->UnspecifiedAddress;
        Status = STATUS_SUCCESS;
    }
    
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    return Status;
}

NTSTATUS
IppCreateLocalTemporaryAddress(
    IN CONST UCHAR *Prefix,
    IN PIP_INTERFACE Interface,
    IN PIP_LOCAL_UNICAST_ADDRESS PublicAddress,
    IN BOOLEAN RouteSetLockHeld,
    OUT PIP_LOCAL_TEMPORARY_ADDRESS *ReturnTemporaryAddress
    )
/*++

Routine Description:

    This routine generates a temporary address for a given prefix. For this,
    it generates a random interface identifier if required. It then creates the
    address and returns the new address. Also, the routine checks if a
    temporary address needs to be generated. If not, it just returns without
    creating the address.

Arguments:

    Prefix - Supplies the prefix from which to create the temporary address. 

    Interface - Supplies a pointer to the interface on which to find/create the
        temporary address.

    PublicAddress - Supplies the public address corresponding to the local
        address. 

    RouteSetLockHeld - Supplies a boolean indicating whether the route set lock
        is held or not.

    ReturnLocalAddress - Receives a pointer to the entry found or created.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS
    STATUS_NOT_FOUND: if there is no need to create a temporary address.

Locks:

    Assumes caller holds a write lock on the interface.
    Caller is responsible for releasing the refcount on ReturnLocalAddress when
        it is deleted.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG IdentifierLength = Interface->FlCharacteristics->IdentifierLength;
    ULONG TemporaryPreferredLifetime;
    IN6_ADDR Address;
    ULONG Now = IppTickCount;
    PUCHAR AddressBuffer = (PUCHAR)&Address;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT(PublicAddress != NULL);
    //
    // Assert that the identifier length is a multiple of 8 for now. 
    // This just works for IPv6.
    // 
    ASSERT(Protocol->Characteristics->AddressBytes == 16);
    ASSERT((IdentifierLength % 8) == 0);
    IdentifierLength = IdentifierLength / 8;

    //
    // Refresh the lifetimes in the address.  This makes the processing below
    // easier since all the timeouts in the address are w.r.t the current
    // time. 
    //
    IppRefreshAddressLifetimes(Now, PublicAddress);

    //
    // First figure out if a temporary address should be created. 
    // $$REVIEW: Should this check for DadFailures and if the number of DAD
    // failures is greater than 5, not try to generate any temporary
    // addresses?
    //
    if ((Protocol->UseTemporaryAddresses == UseTemporaryNo) ||
        !Interface->FlCharacteristics->TemporaryAddresses ||
        (PublicAddress->PreferredLifetime <=
         Protocol->TemporaryRegenerateAdvance)) {
        return STATUS_NOT_FOUND;
    }
    
    //
    // First create the address from the prefix and the interface identifier. A
    // new random interface identifier is generated if the last one was
    // generated (MaxTemporaryPreferredLifetime - TemporaryRegenerateAdvance -
    // TemporaryDesyncFactor) ticks ago (Note: MaxTemporaryPreferredLifetime -
    // TemporaryRegenerateAdvance - TemporaryDesyncFactor never underflows
    // since we validate these parameters before setting them). Temporary
    // addresses are created in 3 ways: 
    // 1) The initial creation on receiving a router advertisment. There is no
    // need to generate a new random identifier in that case. 
    // 2) Regeneration once the original temporary address is about to be
    // deprecated. The above condition covers the case and ensures that in case
    // of regeneration, a new identifier is used. Note that a temporary
    // address can have a lifetime < MaxTemporaryPreferredLifetime but in that
    // case it won't be regenerated. 
    // 3) DAD failure: We force the creation of a new identifier
    // by setting the creation time to 0. Note that the assumption here is that
    // the DAD failure occurs before MaxTemporaryPreferredLifetime, so a new
    // identifier has already not been generated. 
    // 
    if ((Interface->TemporaryStateCreationTime == 0) ||
        (Protocol->UseTemporaryAddresses == UseTemporaryAlways) ||
        ((Now - Interface->TemporaryStateCreationTime) >= 
         (Protocol->MaxTemporaryPreferredLifetime - 
          Protocol->TemporaryRegenerateAdvance))) {
        Interface->TemporaryStateCreationTime = Now;
TryAgain:
        if (Protocol->UseTemporaryAddresses == UseTemporaryCounter) {
            //
            // When testing, it's convenient to use interface identifiers
            // that aren't actually random.
            //
            ULONG OldValue = RtlUlongByteSwap(
                ((ULONG UNALIGNED *)&Interface->TemporaryState)[3]);
            
            ((ULONG UNALIGNED *)&Interface->TemporaryState)[3] =
                RtlUlongByteSwap(OldValue + 1);
        } else {
            MD5_CTX Context;
            
            //
            // The high half of IF->TempState is our history value.
            // The low half is the temporary interface identifier.
            //
            // Append the history value to the usual interface identifier,
            // and calculate the MD5 digest of the resulting quantity.
            // Note MD5 digests and IPv6 addresses are both 16 bytes,
            // while our history value and the interface identifer are 8 bytes.
            //
            ASSERT(IdentifierLength <= sizeof(Interface->TemporaryState));
            RtlCopyMemory(
                ((PUCHAR) &Interface->TemporaryState) +
                sizeof(Interface->TemporaryState) - IdentifierLength, 
                Interface->Identifier,
                IdentifierLength);
            MD5Init(&Context);
            MD5Update(
                &Context,
                (PUCHAR)&Interface->TemporaryState, 
                sizeof(Interface->TemporaryState));
            MD5Final(&Context);
            RtlCopyMemory(
                (PUCHAR) &Interface->TemporaryState, 
                Context.digest, 
                sizeof(Interface->TemporaryState));
        }
        //
        // Clear the universal/local bit to indicate local significance.
        // $$REVIEW: The RFC says that the 6th bit from the left should be set
        // to 0 and the leftmost part of the digest should be used as the
        // interface identifier. Instead, the XP stack (and we) use the
        // rightmost part for constructing the address. 
        //
        ((PUCHAR)&Interface->TemporaryState)[8] &= ~0x2;
    }
    
    //
    // First copy the prefix onto the final address and then copy the
    // new random identifier. The caller is supposed to make sure that the
    // identifier does not overwrite the prefix. 
    //
    RtlCopyMemory(AddressBuffer, Prefix, 8);
    RtlCopyMemory(
        AddressBuffer + 8,
        ((PUCHAR)&Interface->TemporaryState) + 8,
        8);
        
    //
    // Check that we have not generated an existing address on the
    // interface or a known anycast address format. 
    //
    if ((IppFindAddressInAddressSetUnderLock(
             Interface,
             AddressBuffer,
             NlatUnicast) != NULL) ||
        (IN6_IS_ADDR_ANYCAST((CONST IN6_ADDR*)&Address))) {
        goto TryAgain;
    }

    //
    // We never create a temporary address whose preferred lifetime is <= the
    // TemporaryRegenerateAdvance.  Doing so would cause an infinite number of
    // temporary addresses to be generated. 
    // This is ensured because (a) before setting the global parameters, we
    // ensure that  MaxTemporaryPreferredLifetime > TemporaryRegenerateAdvance
    // and (b) we check the condition PublicAddress->PreferredLifetime >
    // TemporaryRegenerateAdvance on entry to this routine. 
    //
    TemporaryPreferredLifetime =
        min(PublicAddress->PreferredLifetime,
            Protocol->MaxTemporaryPreferredLifetime);
    ASSERT(TemporaryPreferredLifetime > Protocol->TemporaryRegenerateAdvance);

    return
        IppFindOrCreateLocalAddress(
            Protocol,
            AddressBuffer, 
            NlatUnicast,
            Interface, 
            ADDR_CONF_TEMPORARY,
            TemporaryPreferredLifetime,
            min(PublicAddress->ValidLifetime,
                Protocol->MaxTemporaryValidLifetime),
            8 * Protocol->Characteristics->AddressBytes,
            FALSE,
            PublicAddress, 
            RouteSetLockHeld,
            NULL,
            (PIP_LOCAL_ADDRESS *) ReturnTemporaryAddress);
}

NL_LOCAL_UNICAST_ADDRESS_RW IpDefaultLocalUnicastAddressRw = {
    INFINITE_LIFETIME,          // PreferredLifetime.
    INFINITE_LIFETIME,          // ValidLifetime.
    IpPrefixOriginUnchanged,    // PrefixOrigin.
    IpSuffixOriginUnchanged,    // SuffixOrigin.
    (UINT8) -1,                 // OnLinkPrefixLength.
    FALSE                       // SkipAsSource.
};

NTSTATUS
IppValidateSetAllLocalAddressParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args, 
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    Validates a set all local address parameters request.

Arguments:

    Args - Pointer to argument structure.

Return Value:

    Status of the validation.

Locks:

    No lock is required.

Caller IRQL:

    PASSIVE through DISPATCH.
    
--*/
{
    PIP_PROTOCOL Protocol;
    PNL_LOCAL_ADDRESS_KEY Key = 
        (PNL_LOCAL_ADDRESS_KEY)Args->KeyStructDesc.KeyStruct;
    PIP_INTERFACE Interface;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_LOCAL_ADDRESS LocalAddress;
    PNL_LOCAL_UNICAST_ADDRESS_RW Rw = &IpDefaultLocalUnicastAddressRw;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength == 
           SIZEOF_NL_LOCAL_ADDRESS_KEY(
               Protocol->Characteristics->NetworkProtocolId));
    ASSERT(Key != NULL);

    Args->ProviderTransactionContext = NULL;

    //
    // It is not valid to add non-unicast addresses.  This takes care of
    // clients trying to add the unspecified as well. 
    //
    if (Protocol->AddressType(Key->Address) != NlatUnicast) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // RW struct validation. 
    //
    if ((AddressType == NlatUnicast) && 
        (Args->RwStructDesc.RwParameterStructLength > 0)) {
        Rw = (PNL_LOCAL_UNICAST_ADDRESS_RW)
            Args->RwStructDesc.RwParameterStruct;

        ASSERT(Args->RwStructDesc.RwParameterStructLength == sizeof(*Rw));

        if (Rw->ValidLifetime < Rw->PreferredLifetime) {
            return STATUS_INVALID_PARAMETER;
        }

        if ((Rw->PrefixOrigin != IpPrefixOriginUnchanged) !=
            (Rw->SuffixOrigin != IpSuffixOriginUnchanged)) {
            //
            // Prefix and Suffix origin must both be specified together.
            //
            return STATUS_INVALID_PARAMETER;
        }
        
        if (Rw->PrefixOrigin > IpPrefixOriginUnchanged) {
            return STATUS_INVALID_PARAMETER;
        }

        if (Rw->SuffixOrigin > IpSuffixOriginUnchanged) {
            return STATUS_INVALID_PARAMETER;
        }

        if ((Rw->OnLinkPrefixLength != (UINT8) -1) &&
            (Rw->OnLinkPrefixLength >
             (8 * Protocol->Characteristics->AddressBytes))) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    //
    // All operations require a valid interface.
    //
    Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Now try to find the address.
    //
    LocalAddress = 
        (PIP_LOCAL_ADDRESS) IppFindAddressOnInterfaceEx(
            Interface, 
            Key->Address);

    if (LocalAddress != NULL) {
        if ((Args->Action == NsiSetCreateOnly) ||
            (NL_ADDRESS_TYPE(LocalAddress) != AddressType)) {
            IppDereferenceLocalAddress(LocalAddress);
            LocalAddress = NULL;
            Status = STATUS_DUPLICATE_OBJECTID;
        } else {
            //
            // Do not allow modifications to this address if
            // we are using it to boot from a remote disk.
            //
            if (LocalAddress->SystemCritical) {
                Status = STATUS_ACCESS_DENIED;
            }
        }        
    } else {
        if ((Args->Action == NsiSetCreateOnly) ||
            (Args->Action == NsiSetCreateOrSet)) {
            IN_ADDR BroadcastAddress;
            SCOPE_ID ScopeId;
            //
            // Check that the specified unicast address
            // doesn't match the corresponding subnet
            // broadcast.
            //
            if ((AddressType == NlatUnicast) && 
                (Protocol->Characteristics->NetworkProtocolId == 
                 AF_INET) &&
                (Rw->OnLinkPrefixLength != (UINT8) -1) &&
                (Rw->OnLinkPrefixLength != 
                 8 * Protocol->Characteristics->AddressBytes)) {

                CreateBroadcastAddress(
                    Key->Address, 
                    Rw->OnLinkPrefixLength, 
                    sizeof(IN_ADDR), 
                    (BOOLEAN)Interface->UseZeroBroadcastAddress,
                    (PUCHAR)&BroadcastAddress);

                if (RtlEqualMemory(
                        Key->Address, 
                        &BroadcastAddress, 
                        Protocol->Characteristics->AddressBytes)){
                    Status = STATUS_INVALID_PARAMETER;
                    goto Done;
                }
            }

            //
            // Test whether the address exist in the scope.
            //           
            ScopeId = IppGetScopeId(Interface, Key->Address);
            
            if ((INET_IS_ADDR_LOOPBACK(
                    Interface->Compartment->Protocol->Family, 
                    Key->Address)) &&
                (ScopeId.Zone != Interface->Compartment->LoopbackIndex)) {
                //
                // Can't add loopback onto other interfaces.
                // Otherwise IppFindAddressInScope asserts.
                //
                Status = STATUS_INVALID_PARAMETER;
                goto Done;
            } else {
                LocalAddress =
                    IppFindAddressInScopeEx(
                        Interface->Compartment, 
                        ScopeId,
                        Key->Address);
                if (LocalAddress != NULL) {
                    IppDereferenceLocalAddress(LocalAddress);
                    Status = STATUS_DUPLICATE_OBJECTID;
                    goto Done;
                }
            }

            //
            // We need to preallocate this local address here.
            //
            LocalAddress = (PIP_LOCAL_ADDRESS)
                IppCreateLocalAddress(
                    Protocol, 
                    Key->Address, 
                    AddressType,
                    Interface,
                    (Rw->PrefixOrigin == IpPrefixOriginUnchanged)
                    ? ADDR_CONF_MANUAL
                    : (Rw->PrefixOrigin << 4) | Rw->SuffixOrigin,
                    Rw->PreferredLifetime, 
                    Rw->ValidLifetime, 
                    (Rw->OnLinkPrefixLength == (UINT8) -1)
                    ? 8 * Protocol->Characteristics->AddressBytes
                    : Rw->OnLinkPrefixLength,
                    NULL);
            if (LocalAddress == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Done;
            }
        } else {
            Status = STATUS_INVALID_PARAMETER;
        }
    }
Done:    
    if (NT_SUCCESS(Status)) {
        Args->ProviderTransactionContext = LocalAddress;
    } 
    IppDereferenceInterface(Interface);
    return Status;
}

NTSTATUS
IppCommitSetAllLocalAddressParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args, 
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    Commits an already validated set all local address parameters request.

Arguments:

    Args - Pointer to set all parameters structure.

    AddressType - Supplies the type of the address. 

Return Value:

    None.

Locks:

    No lock is required.

Caller IRQL:

    PASSIVE through DISPATCH level.
    
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_LOCAL_ADDRESS LocalAddress, NewLocalAddress = NULL;
    PIP_LOCAL_UNICAST_ADDRESS UnicastAddress;
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    KLOCK_QUEUE_HANDLE LockHandle;
    PNL_LOCAL_ADDRESS_KEY Key = 
        (PNL_LOCAL_ADDRESS_KEY)Args->KeyStructDesc.KeyStruct;
    BOOLEAN Created = FALSE, Notify = FALSE;
    PNL_LOCAL_UNICAST_ADDRESS_RW Rw = &IpDefaultLocalUnicastAddressRw;
    
    LocalAddress = (PIP_LOCAL_ADDRESS)Args->ProviderTransactionContext;
    Interface = LocalAddress->Interface;
    ASSERT(Interface != NULL);

    Protocol = Interface->Compartment->Protocol;

    if (Args->RwStructDesc.RwParameterStructLength != 0) {
        Rw = (PNL_LOCAL_UNICAST_ADDRESS_RW)
            Args->RwStructDesc.RwParameterStruct;
    }
    
    //
    // Acquire the lock and looking for the address in address set.
    //
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    NewLocalAddress = 
        IppFindAddressOnInterfaceExUnderLock(
            Interface, 
            Key->Address);
     
    switch (Args->Action) {
    case NsiSetDelete:
        if (NewLocalAddress != NULL) {
            IppRemoveLocalAddressUnderLock(
                (PIP_LOCAL_ADDRESS) NewLocalAddress, FALSE);
        }
        break;
    case NsiSetCreateOnly:
    case NsiSetCreateOrSet:
        if (NewLocalAddress == NULL) {
            //
            // The reference we already have on the LocalAddress is used to add
            // it to the address set; so add another reference. 
            //
            IppReferenceLocalAddress(LocalAddress);
            
            Status =
                IppFindOrCreateLocalAddress(
                    Protocol, 
                    Key->Address, 
                    AddressType, 
                    Interface,
                    LocalAddress->AddressOrigin,
                    Rw->PreferredLifetime, 
                    Rw->ValidLifetime, 
                    (Rw->OnLinkPrefixLength == (UINT8) -1)
                    ? 8 * Protocol->Characteristics->AddressBytes
                    : Rw->OnLinkPrefixLength,
                    TRUE, 
                    NULL,
                    FALSE, 
                    LocalAddress,
                    &NewLocalAddress);
            if (!NT_SUCCESS(Status)) {
                //
                // IppFindOrCreateLocalAddress should have cleaned up the local
                // address. 
                //
                LocalAddress = NULL;
            } else {
                Created = TRUE;
            }
        }
        //
        // Fall through.
        //
    case NsiSetDefault:
        if ((NewLocalAddress != NULL) &&
            (NL_ADDRESS_TYPE(NewLocalAddress) == NlatUnicast)) {
            UnicastAddress = (PIP_LOCAL_UNICAST_ADDRESS) NewLocalAddress;
            
            ASSERT(NewLocalAddress->AddressOrigin != ADDR_CONF_TEMPORARY);

            if ((Rw->OnLinkPrefixLength != (UINT8) -1) &&
                (Rw->OnLinkPrefixLength != UnicastAddress->PrefixLength)) {

                //
                // Go through some hoops to get transaction semantics.
                //
                ULONG PrefixLength = UnicastAddress->PrefixLength;
                USHORT NewRouteCreated, OldRouteCreated = 
                    UnicastAddress->OnLinkRouteCreated;
                
                ASSERT(!Created);
                UnicastAddress->PrefixLength = Rw->OnLinkPrefixLength;
                UnicastAddress->OnLinkRouteCreated = 0;

                if (IsLocalUnicastAddressValid(UnicastAddress) && 
                    UnicastAddress->CreateOnLinkRoute) {
                    Status = 
                        IppUpdateOnLinkRouteForAddress(
                            Protocol, 
                            UnicastAddress, 
                            NsiSetCreateOrSetWithReference);
                    if (!NT_SUCCESS(Status)) {
                        //
                        // Restore to old state.
                        //
                        UnicastAddress->PrefixLength = PrefixLength;
                        UnicastAddress->OnLinkRouteCreated = 
                            OldRouteCreated;
                        break;
                    }
                    //
                    // Now remove the old onlink route.
                    //
                    NewRouteCreated = UnicastAddress->OnLinkRouteCreated;
                    UnicastAddress->PrefixLength = PrefixLength;
                    UnicastAddress->OnLinkRouteCreated = 
                        OldRouteCreated;
                    (VOID) IppUpdateOnLinkRouteForAddress(
                        Protocol, 
                        UnicastAddress, 
                        NsiSetDelete);
                    UnicastAddress->PrefixLength = Rw->OnLinkPrefixLength;
                    UnicastAddress->OnLinkRouteCreated = NewRouteCreated;
                }
            }
            
            //
            // Change the LifetimeBaseTime to the current time so that the
            // lifetimes make sense.  
            //
            UnicastAddress->LifetimeBaseTime = IppTickCount;
            UnicastAddress->ValidLifetime = 
                IppSecondsToTicks(Rw->ValidLifetime);
            UnicastAddress->PreferredLifetime = 
                IppSecondsToTicks(Rw->PreferredLifetime);
           
            if (UnicastAddress->SkipAsSource != !!Rw->SkipAsSource) {
                Notify = TRUE;
                UnicastAddress->SkipAsSource = !!Rw->SkipAsSource;
            }

            if (!Created && Notify) {
                IppNotifyAddressChange(
                    UnicastAddress, 
                    NsiParameterNotification);
            }
            
            //
            // Change any timeouts set for deprecation/invalidation. This needs
            // to be done only if the address already existed.  If we just
            // created the address, then the address lifetimes haven't
            // changed.  Also, if the address is added with a 0 lifetime and
            // DAD completes right away, we might already have removed the
            // address.  We don't want to call IppHandleAddressLifetimeTimeout
            // again in that case. 
            //
            if (!Created) {
                IppHandleAddressLifetimeTimeout(UnicastAddress);
            }
        } 
        break;
    default:
        ASSERT(0);
    }
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    
    if (LocalAddress != NULL) {
        IppDereferenceLocalAddress(LocalAddress);
    }
    if (NewLocalAddress != NULL) {
        IppDereferenceLocalAddress(NewLocalAddress);
    }
    Args->ProviderTransactionContext = NULL;

    return Status;
}

VOID
IppCancelSetAllLocalAddressParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Cancel an already validated set all local address parameters request.

Arguments:

    Args - Pointer to set all parameters request structure.

 Return Value:

    None.

Locks:

    No lock is required.

Caller IRQL:

    PASSIVE through DISPATCH level.
    
--*/
{
    PIP_LOCAL_ADDRESS LocalAddress;

    LocalAddress = (PIP_LOCAL_ADDRESS)Args->ProviderTransactionContext;
    ASSERT(LocalAddress != NULL);
    IppDereferenceLocalAddress(LocalAddress);
}

NTSTATUS
NTAPI
IppSetAllLocalAddressParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    This function sets all public read-write parameters of a local address,
    including supporting manual creation and deletion of addresses.  This works
    for both unicast and anycast addresses.

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (Args->Action == NsiSetReset) {
        return STATUS_NOT_IMPLEMENTED;
    }

    //
    // Handle transaction here.
    //
    switch (Args->Transaction) {
    case NsiTransactionNone:
        Status = IppValidateSetAllLocalAddressParameters(Args, AddressType);
        if (NT_SUCCESS(Status)) {
            Status = IppCommitSetAllLocalAddressParameters(Args, AddressType);
        }
        break;
    case NsiTransactionValidate:
        Status = IppValidateSetAllLocalAddressParameters(Args, AddressType);
        break;
    case NsiTransactionCommit:
        Status = IppCommitSetAllLocalAddressParameters(Args, AddressType);
        break;
    case NsiTransactionCancel:
        IppCancelSetAllLocalAddressParameters(Args);
        break;
    default:
        Status = STATUS_INVALID_PARAMETER;
    }

    return Status;
}


NTSTATUS
IpSetAllLocalUnicastAddressParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function sets all public read-write parameters of a local unicast
    address, including supporting manual creation and deletion of addresses. 

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

--*/
{
    return IppSetAllLocalAddressParameters(Args, NlatUnicast);
}


NTSTATUS
IpSetAllLocalAnycastAddressParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function sets all public read-write parameters of a local anycast
    address, including supporting manual creation and deletion of addresses. 

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

--*/
{
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);
    
    if (Client->Protocol->Characteristics->NetworkProtocolId == 
        AF_INET) {
        return STATUS_NOT_SUPPORTED;
    }
    return IppSetAllLocalAddressParameters(Args, NlatAnycast);
}


NTSTATUS
NTAPI
IppGetAllLocalAddressParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args, 
    IN NL_ADDRESS_TYPE AddressType, 
    OUT PIP_LOCAL_ADDRESS *ReturnAddress
    )
/*++

Routine Description:

    This function gets all public parameters of a given local address.  This
    works for unicast and anycast addresses.  The routine also sets the key
    (if required).

Arguments:

    Args - Supplies a pointer to a structure describing the operation to 
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PNL_LOCAL_ADDRESS_KEY Key =
        (PNL_LOCAL_ADDRESS_KEY) Args->KeyStructDesc.KeyStruct;
    NTSTATUS Status;
    PIP_LOCAL_ADDRESS Address = NULL; 
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength ==
           SIZEOF_NL_LOCAL_ADDRESS_KEY(
               Protocol->Characteristics->NetworkProtocolId));

    switch (Args->Action) {
    case NsiGetExact:
        Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
        if (Interface == NULL) {
            return STATUS_NOT_FOUND;
        }

        Address = IppFindAddressOnInterfaceEx(Interface, Key->Address);
        if (Address == NULL) {
            Status = STATUS_NOT_FOUND;
        } else if (NL_ADDRESS_TYPE(Address) != AddressType) {
            Status = STATUS_NOT_FOUND;
            IppDereferenceLocalAddress(Address);
            Address = NULL;
        } else {
            Status = STATUS_SUCCESS;
        }
        
        IppDereferenceInterface(Interface);
        break;

    case NsiGetFirst:
        RtlZeroMemory(Key, Args->KeyStructDesc.KeyStructLength);
        //
        // Fall through.
        //

    case NsiGetNext:
        Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
        if (Interface != NULL) {
            Status = IppGetNextAddress(
                Interface, 
                Key->Address,
                IppGetAddressSet(Interface, AddressType), 
                &Address);
            
            IppDereferenceInterface(Interface);

            if (NT_SUCCESS(Status)) {
                break;
            }
        }

        do {
            Interface = IppGetNextInterface(Protocol, &Key->InterfaceLuid);
            if (Interface == NULL) {
                return STATUS_NO_MORE_ENTRIES;
            }

            Key->InterfaceLuid = Interface->Luid;

            Status = IppGetFirstAddress(
                Interface, 
                IppGetAddressSet(Interface, AddressType), 
                &Address);

            IppDereferenceInterface(Interface);
        } while (!NT_SUCCESS(Status));
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (Args->Action != NsiGetExact) {
        Key->InterfaceLuid = Address->Interface->Luid;
        RtlCopyMemory(Key->Address, 
                      NL_ADDRESS(Address), 
                      Protocol->Characteristics->AddressBytes);
    }

    *ReturnAddress = Address;
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpGetAllLocalUnicastAddressParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters for a unicast address.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to 
        be performed.

Return Value:

    Status of the operation.

--*/
{
    NTSTATUS Status;
    PIP_LOCAL_UNICAST_ADDRESS Address;
     
    Status = IppGetAllLocalAddressParameters(
        Args, NlatUnicast, (PIP_LOCAL_ADDRESS *)&Address);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    if (Args->StructDesc.RwParameterStruct) {
        NL_LOCAL_UNICAST_ADDRESS_RW Data;
        ULONG Now = IppTickCount;
        
        ASSERT(Args->StructDesc.RwParameterStructLength == sizeof(Data));

        RtlZeroMemory(&Data, sizeof(Data));
        Data.PreferredLifetime = IppTicksToSeconds(
            IppRemainingLifetime(Now, 
                                 Address->LifetimeBaseTime, 
                                 Address->PreferredLifetime));
        Data.ValidLifetime = IppTicksToSeconds(
            IppRemainingLifetime(Now, 
                                 Address->LifetimeBaseTime, 
                                 Address->ValidLifetime));
        Data.PrefixOrigin = Address->PrefixOrigin;
        Data.SuffixOrigin = Address->SuffixOrigin;
        Data.OnLinkPrefixLength = (UINT8) Address->PrefixLength;
        Data.SkipAsSource = (BOOLEAN) Address->SkipAsSource;
        
        RtlCopyMemory(Args->StructDesc.RwParameterStruct,
                      &Data,
                      Args->StructDesc.RwParameterStructLength);
    }

    if (Args->StructDesc.RoDynamicParameterStruct) {
        NL_LOCAL_UNICAST_ADDRESS_ROD Data;

        ASSERT(Args->StructDesc.RoDynamicParameterStructLength == 
               sizeof(Data));

        RtlZeroMemory(&Data, sizeof(Data));
        Data.ScopeId = IppGetExternalScopeId(Address->Interface,
                                             NL_ADDRESS(Address));

        Data.DadState = IppGetEffectiveDadState(Address);

        RtlCopyMemory(Args->StructDesc.RoDynamicParameterStruct,
                      &Data,
                      Args->StructDesc.RoDynamicParameterStructLength);
    }

    if (Args->StructDesc.RoStaticParameterStruct) {
        NL_LOCAL_UNICAST_ADDRESS_ROS Data;

        ASSERT(Args->StructDesc.RoStaticParameterStructLength == sizeof(Data));

        RtlZeroMemory(&Data, sizeof(Data));
        Data.CreationTimestamp = Address->CreationTimestamp;
            
        RtlCopyMemory(
            Args->StructDesc.RoStaticParameterStruct,
            &Data,
            Args->StructDesc.RoStaticParameterStructLength);
    }

    IppDereferenceLocalUnicastAddress(Address);
    
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpGetAllLocalAnycastAddressParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters for an anycast address.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to 
        be performed.

Return Value:

    Status of the operation.

--*/
{
    NTSTATUS Status;
    PIP_LOCAL_ANYCAST_ADDRESS Address;
    
    Status = IppGetAllLocalAddressParameters(
        Args, NlatAnycast, (PIP_LOCAL_ADDRESS*)&Address);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    IppDereferenceLocalAnycastAddress(Address);
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpGetAllLocalMulticastAddressParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a given local multicast 
    address.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    NTSTATUS Status;
    PIP_LOCAL_MULTICAST_ADDRESS Address = NULL;
    PIP_INTERFACE Interface;
     
    Status = IppGetAllLocalAddressParameters(
        Args, NlatMulticast, (PIP_LOCAL_ADDRESS*)&Address);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    ASSERT(Args->StructDesc.RwParameterStructLength == 0);

    if (Args->StructDesc.RoDynamicParameterStruct) {
        UNALIGNED NL_LOCAL_MULTICAST_ADDRESS_ROD *Data =
            (UNALIGNED NL_LOCAL_MULTICAST_ADDRESS_ROD *)
            Args->StructDesc.RoDynamicParameterStruct;

        ASSERT(Args->StructDesc.RoDynamicParameterStructLength == 
               sizeof(*Data));

        Interface = Address->Interface;
        
        RtlZeroMemory(Data, sizeof(*Data));
        Data->ScopeId = IppGetExternalScopeId(Interface, NL_ADDRESS(Address));
        Data->JoinCount = Address->ExcludeCount;
        Data->LastReporter =
            (Interface->MulticastDiscoveryVersion ==
             MULTICAST_DISCOVERY_VERSION2)
            ? Address->MulticastReportFlag
            : TRUE;
    }

    if (Args->StructDesc.RoStaticParameterStruct) {
        UNALIGNED NL_LOCAL_MULTICAST_ADDRESS_ROS *Data =
            (UNALIGNED NL_LOCAL_MULTICAST_ADDRESS_ROS *)
            Args->StructDesc.RoStaticParameterStruct;

        ASSERT(Args->StructDesc.RoStaticParameterStructLength ==
               sizeof(*Data));

        Interface = Address->Interface;

        Data->InterfaceIndex = Interface->Index;
    }

    IppDereferenceLocalMulticastAddress(Address);

    return Status;
}

PIP_LOCAL_UNICAST_ADDRESS
IppFindLinkLocalUnicastAddress(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Find the link-local unicast address assigned to the interface.

    Returns a reference on the address to the caller.

Arguments:

    Interface - Supplies the interface whose link-local address is required.

Return Value:

    A valid link-local unicast address, or NULL.

Locks:

    Assumes caller holds a lock (read or write) on the interface.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PNLA_LINK Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;

    ASSERT_ANY_LOCK_HELD(&Interface->Lock);

    //
    // Search the list of addresses.
    // Return the first valid link-local unicast address we find (if any).
    //
    IppInitializeAddressEnumerationContext(&Context);
    do {
        Link =
            IppEnumerateNlaSetEntry(
                &Interface->LocalUnicastAddressSet,
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link != NULL) {
            LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS)
                CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);

            ASSERT(NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast);
            if ((NL_ADDRESS_SCOPE_LEVEL(LocalAddress) == ScopeLevelLink) &&
                IsLocalUnicastAddressValid(LocalAddress)) {
                IppReferenceLocalUnicastAddress(LocalAddress);
                return LocalAddress;
            }
        }
    } while (Link != NULL);

    return NULL;
}

VOID
IppDisconnectAddresses(
    IN PIP_INTERFACE Interface
    )
/*++

Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH since a lock is held.

--*/
{
    PNLA_LINK Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PIP_LOCAL_UNICAST_ADDRESS UnicastAddress;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    ASSERT(Interface->ConnectedSubInterfaces == 0);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
               "IPNG: [%u] Disconnecting %s addresses\n", 
               Interface->Index,
               Interface->Compartment->Protocol->TraceString);

    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link = IppEnumerateNlaSetEntry(
            &(Interface->LocalUnicastAddressSet), 
            (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        UnicastAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);

        ASSERT(NL_ADDRESS_TYPE(UnicastAddress) == NlatUnicast);

        if (UnicastAddress->DadState == NldsPreferred) {
            //
            // Tell clients that this address is going away.
            //
            ASSERT(IppGetEffectiveDadState(UnicastAddress) != NldsPreferred);
            IppNotifyAddressChange(UnicastAddress, NsiParameterNotification);
        }
    }
}

VOID
IppReconnectAddresses(
    IN PIP_INTERFACE Interface
    )
/*++

Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH since a lock is held.

--*/
{
    PNLA_LINK Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PIP_LOCAL_UNICAST_ADDRESS UnicastAddress;
    PIP_LOCAL_MULTICAST_ADDRESS MulticastAddress;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
               "IPNG: [%u] Reconnecting %s addresses\n", 
               Interface->Index, 
               Interface->Compartment->Protocol->TraceString);
    
    //
    // Restart the link-local address configuration state machine.
    //
    IppRestartLinkLocalAddressConfiguration(Interface);
  
    //
    // Reconnect unicast addresses.
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link = IppEnumerateNlaSetEntry(
            &(Interface->LocalUnicastAddressSet), 
            (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        UnicastAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);

        ASSERT(NL_ADDRESS_TYPE(UnicastAddress) == NlatUnicast);

        if (UnicastAddress->DadState != NldsInvalid) {
            //
            // Restart Duplicate Address Detection,
            // if it is enabled for this interface.
            //
            IppRestartDad(UnicastAddress);
        }
    }

    //
    // Reconnect multicast addresses.
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link = IppEnumerateNlaSetEntry(
            &(Interface->LocalMulticastAddressSet), 
            (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        MulticastAddress = (PIP_LOCAL_MULTICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_MULTICAST_ADDRESS, Link);

        ASSERT(NL_ADDRESS_TYPE(MulticastAddress) == NlatMulticast);

        IppReconnectMulticastAddress(MulticastAddress);
    }
}

NTSTATUS
NTAPI
IpRegisterAddressChangeNotification(
    IN PNM_REQUEST_REGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Enable address state change notifications via the NSI.

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
        &ClientContext->AddressNotificationContext;

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
IpDeregisterAddressChangeNotification(
    IN PNM_REQUEST_DEREGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Disable address state change notifications via the NSI.

Arguments:

    Request - Supplies a request to disable notifications.

Caller IRQL:

    Must be called at IRQL <= APC level.

--*/
{
    PNMP_CLIENT_CONTEXT ClientContext =
        (PNMP_CLIENT_CONTEXT) Request->ProviderHandle;
    PNMP_NOTIFICATION_CONTEXT NotificationContext =
        &ClientContext->AddressNotificationContext;

    PAGED_CODE();

    //
    // Initialize an event we can wait on until deregistering is complete.
    //
    KeInitializeEvent(&NotificationContext->DeregisterCompleteEvent,
                      NotificationEvent,
                      FALSE);

    if (!RoUnInitialize(&NotificationContext->ReferenceObject)) {
        //
        // Wait for notifications in progress to complete.
        //
        KeWaitForSingleObject(&NotificationContext->DeregisterCompleteEvent,
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


__inline
NTSTATUS
IppJoinGroupAtFl(
    IN PIP_LOCAL_MULTICAST_ADDRESS Group,
    IN PVOID RequestContext
    )
/*++

Routine Description:

    Join a multicast group at the framing layer.

Arguments:

    Group - Supplies the multicast group being joined.

    RequestContext - Supplies the context to return upon request completion.

Return Value:

    STATUS_SUCCESS, STATUS_PENDING, or a failure code.

Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    FL_REQUEST_ADD_GROUP Request = {0};
    NTSTATUS Status;
   
    ASSERT_WRITE_LOCK_HELD(&Group->Interface->Lock);
 
    Request.RequestComplete = IpFlcAddGroupComplete;
    Request.RequestContext = RequestContext;
    Request.ProviderInterfaceHandle = Group->Interface->FlContext;    
    Request.ClientGroupHandle = (HANDLE) Group;
    Request.NlGroup = NL_ADDRESS(Group);
    Request.ProviderGroupHandle = &Group->FlContext;

    //
    // Add a reference to the multicast group.  This reference is released when
    // the add group completes.  Adding a reference ensures that (1) the group
    // still exists when the completion routine is called and (2) the FL delete
    // group routine is not called until the add group completes. 
    //
    IppReferenceLocalAddress((PIP_LOCAL_ADDRESS)Group);
    
    Status = Group->Interface->FlModule->Npi.Dispatch->AddGroup(&Request);

    if (IS_IPV4_PROTOCOL(Group->Interface->Compartment->Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: [%u] Joined multicast group at FL "
                   "(%!IPV4! Status %x)\n", 
                   Group->Interface->Index,
                   NL_ADDRESS(Group), Status);
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: [%u] Joined multicast group at FL "
                   "(%!IPV6! Status %x)\n", 
                   Group->Interface->Index,
                   NL_ADDRESS(Group), Status);
    }

    if (Status != STATUS_PENDING) {
        IppDereferenceLocalMulticastAddressUnderLock(Group);
    }
    
    return Status;
}


__inline
VOID
IppLeaveGroupAtFl(
    IN PIP_LOCAL_MULTICAST_ADDRESS Group
    )
/*++

Routine Description:

    Leave a multicast group at the framing layer.

Arguments:

    Group - Supplies the multicast group being left.

Return Value:

    None.

--*/
{
    FL_REQUEST_DELETE_GROUP Request = {0};
    LONG i = Group->PendingCount;
    
    Request.ProviderGroupHandle = Group->FlContext;
        
    if (IS_IPV4_PROTOCOL(Group->Interface->Compartment->Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: [%u] Leaving multicast group at FL "
                   "%d times (%!IPV4!)\n", 
                   Group->Interface->Index, 
                   i, NL_ADDRESS(Group));
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: [%u] Leaving multicast group at FL "
                   "%d times (%!IPV6!)\n",
                   Group->Interface->Index,                    
                   i, NL_ADDRESS(Group));
    }
    
    while (i-- > 0) {
        //
        // Leave the group as many times as it was successfully joined.
        //
        Group->Interface->FlModule->Npi.Dispatch->DeleteGroup(&Request);
    }
}


VOID
IpFlcAddGroupComplete(
    IN PFL_INDICATE_COMPLETE Args
    )
/*++

Routine Description:

    FL_CLIENT_ADD_GROUP_COMPLETE Handler.

--*/
{
    PIP_LOCAL_MULTICAST_ADDRESS Group = (PIP_LOCAL_MULTICAST_ADDRESS)
        IppCast(Args->ClientObjectHandle, IP_LOCAL_ADDRESS);
    
    if (NT_SUCCESS(Args->Status)) {
        //
        // We are now joined at the lower layer.
        //
        InterlockedIncrement(&Group->PendingCount);
        Group->Pending = FALSE;
    } else {
        //
        // We do not remove the reference for the caller.  On asynchronous
        // failure, the caller is responsible for removing the reference
        // itself.
        //
    }

    if (IS_IPV4_PROTOCOL(Group->Interface->Compartment->Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: [%u] Join group at FL completed "
                   "(%!IPV4! Status %x)\n",
                   Group->Interface->Index, 
                   NL_ADDRESS(Group), Args->Status);
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: [%u] Join group at FL completed "
                   "(%!IPV6! Status %x)\n",
                   Group->Interface->Index, 
                   NL_ADDRESS(Group), Args->Status);
    }
    
    if (Args->RequestContext != NULL) {
        NTSTATUS Status;
        KIRQL OldIrql;
        PIP_SET_SESSION_INFO_CONTEXT Context =
            (PIP_SET_SESSION_INFO_CONTEXT) Args->RequestContext;
        PIP_SESSION_MULTICAST_STATE SessionGroup = Context->SessionGroup;
        PIP_SESSION_STATE Session = SessionGroup->Session;

        KeAcquireSpinLock(&Session->SpinLock, &OldIrql);
        {
            Status =
                IppCreateMulticastSessionStateComplete(
                    Group,
                    SessionGroup,
                    Args->Status);
        }
        KeReleaseSpinLock(&Session->SpinLock, OldIrql);

        if (Context->CompletionRoutine != NULL) {
            (*Context->CompletionRoutine)(
                Context->CompletionContext,
                Status,
                0);
        }

        ExFreePool(Context);
    }

    //
    // Release the reference that was added at the time of calling FL add
    // group.   
    //
    IppDereferenceLocalMulticastAddress(Group);
}

NTSTATUS
IppFindOrCreateLocalMulticastAddressUnderLock(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN PIP_SET_SESSION_INFO_CONTEXT RequestContext OPTIONAL,
    OUT PIP_LOCAL_MULTICAST_ADDRESS *Entry
    )
/*++

Routine Description:
    
    Find a given multicast address on the specified interface.

    Create one if the search is unsuccessful.

    If success or pending is returned, returns a reference on the 
    found/created entry to the caller.  The caller is responsible
    for releasing this reference, even if we asynchronously complete
    with failure.

Arguments:

    Address - Supplies the multicast address to search for.

    Interface - Supplies the interface on which the multicast address resides.

    RequestContext - Supplies the context used in asynchronous completion.

    Entry - Returns the multicast address entry on success.  NULL on failure.

Return Value:

    STATUS_SUCCESS, STATUS_PENDING, or failure code.

Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    PIP_LOCAL_MULTICAST_ADDRESS Group;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    PNLA_LINK Link;
    PVOID NodeOrParent;
    TABLE_SEARCH_RESULT SearchResult;
    NTSTATUS Status = STATUS_SUCCESS;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    *Entry = NULL;
    
    Link = IppFindNlaSetEntry(&Interface->LocalMulticastAddressSet,
                              Address,
                              sizeof(IP_LOCAL_MULTICAST_ADDRESS) - 
                                  FIELD_OFFSET(IP_LOCAL_ADDRESS, Link), 
                              AddressBytes,
                              &NodeOrParent,
                              &SearchResult);
    if (Link != NULL) {
        //
        // Found one.  Take another reference for the caller.
        //
        Group = CONTAINING_RECORD(Link, IP_LOCAL_MULTICAST_ADDRESS, Link);
        IppReferenceLocalAddress((PIP_LOCAL_ADDRESS) Group);
    } else {
        //
        // Allocate one.  Initialize with a single reference for the caller.
        //
        Group = (PIP_LOCAL_MULTICAST_ADDRESS) 
            IppCreateLocalAddress(
                Protocol,
                Address,
                NlatMulticast,
                Interface, 
                ADDR_CONF_MANUAL, 
                INFINITE_LIFETIME, 
                INFINITE_LIFETIME, 
                8 * Protocol->Characteristics->AddressBytes, 
                NULL);

        if (Group == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        IppInsertNlaSetEntry(
            &Interface->LocalMulticastAddressSet, 
            &Group->Link,
            sizeof(IP_LOCAL_MULTICAST_ADDRESS) -
                FIELD_OFFSET(IP_LOCAL_ADDRESS, Link), 
            AddressBytes,
            NodeOrParent,
            SearchResult);
        
        // Group->FlContext = NULL;
        // Group->PendingCount = 0;
        Group->Pending = TRUE;

        //
        // Even though this address is not used as a source, invalidate the
        // destination cache since there are no routes for multicast addresses
        // and we want to deliver packets locally for this multicast address.
        //
        IppInvalidateDestinationCache(Interface->Compartment);

        IppAddressTrace(TRACE_LEVEL_INFORMATION, 
                        "Created multicast address", 
                        Protocol, Address, Interface->Index);
    }
    
    if (Group->Pending) {
        //
        // The call down into the framing layer can be made with a lock held.
        //
        Status = IppJoinGroupAtFl(Group, RequestContext);
        if (NT_SUCCESS(Status)) {
            if (Status != STATUS_PENDING) {
                //
                // We are now joined at the lower layer.
                //
                InterlockedIncrement(&Group->PendingCount);
                Group->Pending = FALSE;
            }
        } else {            
            //
            // Remove the reference for the caller.
            //
            IppDereferenceLocalMulticastAddressUnderLock(Group);
            return Status;
        }
    }
 
    *Entry = Group;
    return Status;
}


NTSTATUS
IppFindOrCreateLocalMulticastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN PIP_SET_SESSION_INFO_CONTEXT RequestContext OPTIONAL,
    OUT PIP_LOCAL_MULTICAST_ADDRESS *Entry
    )
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;    

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    Status =
        IppFindOrCreateLocalMulticastAddressUnderLock(
            Address,
            Interface,
            RequestContext,
            Entry);
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    return Status;    
}
    
NTSTATUS
IppConfigureIscsiAddress(
    IN PIP_INTERFACE Interface,
    IN PNL_LOCAL_ADDRESS_KEY Key,
    IN PISCSI_BOOT_NIC TcpipIscsiBootParameters
    )
/*++
Routine Description:
    This routine configures an ip address on the interface from which 
    we intend to boot if applicable. The ip address is passed to us from 
    the firmware in  TcpipIscsiBootParameters. The MAC address in this 
    struct is used to identify the interface from which we are booting. 

Arguments :
    Interface - Interface that is being addressed.
    TcpipIscsiBootParameters - Boot parameters read from the firmware.

Return Value:
    Returns the STATUS_SUCCESS or the appropriate failure code.  
--*/        
{
    NM_REQUEST_SET_ALL_PARAMETERS Args = {0};
    NL_LOCAL_UNICAST_ADDRESS_RW AddressRw;        
    NTSTATUS Status;
    PIP_LOCAL_ADDRESS LocalAddressCreated;
        
    Args.ProviderHandle = Interface->Compartment->Protocol->NmClientContext;
    Args.KeyStructDesc.KeyStructLength = 
            SIZEOF_NL_LOCAL_ADDRESS_KEY(
                    Interface->Compartment->Protocol->Characteristics->NetworkProtocolId);
    Args.KeyStructDesc.KeyStruct = (PUCHAR) Key;
           
    NlInitializeLocalUnicastAddressRw(&AddressRw);  
    
    AddressRw.OnLinkPrefixLength = TcpipIscsiBootParameters->SubnetMaskPrefix;
    //
    // The address lifetime of a DHCP address will be set correctly when
    // dhcp client service comes up.
    //    
    AddressRw.PreferredLifetime = INFINITE_LIFETIME;
    //
    // The Origin is set to either DHCP or Manual. Effectively the 
    // address can only be ADDR_CONF_MANUAL or ADD_CONF_DHCP.
    //
    //ASSERT((TcpipIscsiBootParameters->Origin == IpPrefixOriginManual) ||
    //             (TcpipIscsiBootParameters->Origin == IpPrefixOriginDhcp));
    
    AddressRw.PrefixOrigin = TcpipIscsiBootParameters->Origin;
    AddressRw.SuffixOrigin = TcpipIscsiBootParameters->Origin;    
    AddressRw.ValidLifetime = INFINITE_LIFETIME;
   
    Args.RwStructDesc.RwParameterStructLength = sizeof(AddressRw);
    Args.RwStructDesc.RwParameterStruct = (PUCHAR) &AddressRw;
    Args.Action = NsiSetCreateOrSet;
    
    Status = IppSetAllLocalAddressParameters(&Args, NlatUnicast);    
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_DUPLICATE_OBJECTID) {
            return Status;
        }
    }

    LocalAddressCreated = IppFindAddressOnInterfaceEx(Interface, Key->Address);
    if (LocalAddressCreated == NULL) {
        return STATUS_NOT_FOUND;
    }
    LocalAddressCreated->SystemCritical = TRUE;
    IppDereferenceLocalAddress(LocalAddressCreated);

    return STATUS_SUCCESS;
}

#if ADDRESS_REFHIST
VOID
IppDereferenceLocalMulticastAddressUnderLockWithHistory(
    __in PIP_LOCAL_MULTICAST_ADDRESS Group, 
    __in ULONG Line, 
    __in PCHAR File
    )
#else 
VOID
IppDereferenceLocalMulticastAddressUnderLock(
    IN PIP_LOCAL_MULTICAST_ADDRESS Group
    )
#endif
/*++

Routine Description:

    Dereference and, if required, delete a multicast group.
    
    A multicast group remains in the multicast set until its last reference
    is released.  Dereference is performed under a lock since it may need to
    delete and destroy the multicast group.  An alternative to acquiring the
    lock for each dereference operation would be to use a reference object
    and acquire the lock only when the reference count falls to zero.
    
Arguments:

    Group - Supplies the multicast group to dereference.
    
Return Value:

    None.
    
Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_INTERFACE Interface = Group->Interface;
    ULONG ReferenceCount;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    ASSERT(NL_ADDRESS_TYPE(Group) == NlatMulticast);
    ASSERT(Group->ReferenceCount > 0);

    ReferenceCount = InterlockedDecrement(&Group->ReferenceCount);
    
#if ADDRESS_REFHIST
    if (IppAddressReferenceHistory != NULL) {
        RhAppendHistory(IppAddressReferenceHistory, 
                        ReferenceCount, 
                        Line, 
                        File, 
                        Group);
    }
#endif

    if (ReferenceCount == 0) {
        ASSERT(IsListEmpty(&Group->SourceList));
        
        if (!IsListEmpty(&Group->Link.ListLink)) {
            IppDeleteNlaSetEntry(
                &Interface->LocalMulticastAddressSet,
                &Group->Link);

            IppLeaveGroupAtFl(Group);
        }

        IppAddressTrace(
            TRACE_LEVEL_INFORMATION, 
            "Removing multicast group", 
            Interface->Compartment->Protocol,  
            NL_ADDRESS(Group), 
            Interface->Index);
        IppCleanupLocalAddress((PIP_LOCAL_ADDRESS) Group);
    }
}

#if ADDRESS_REFHIST
VOID
IppDereferenceLocalMulticastAddressWithHistory(
    __in PIP_LOCAL_MULTICAST_ADDRESS Group, 
    __in ULONG Line, 
    __in PCHAR File
    )
#else
VOID
IppDereferenceLocalMulticastAddress(
    IN PIP_LOCAL_MULTICAST_ADDRESS Group
    )
#endif
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PRTL_MRSW_LOCK Lock = &Group->Interface->Lock;
    
    RtlAcquireWriteLock(Lock, &LockHandle);
#if ADDRESS_REFHIST
    IppDereferenceLocalMulticastAddressUnderLockWithHistory(
        Group, Line, File);
#else
    IppDereferenceLocalMulticastAddressUnderLock(Group);
#endif

    RtlReleaseWriteLock(Lock, &LockHandle);
}


VOID
IppFindAndDereferenceMulticastGroup(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:
    
    Find the multicast group with the given addresss on the given interface,
    and leave the group.  Used to leave "permanent" groups (e.g. all-hosts
    group) for which the stack holds a reference, but not a pointer.
    
Arguments:

    Interface - Supplies the interface on which the group exists.

    Address - Supplies the multicast group address.

Return Value:

    None.
    
Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_LOCAL_MULTICAST_ADDRESS LocalAddress;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    PVOID NodeOrParent;
    TABLE_SEARCH_RESULT SearchResult;
    PNLA_LINK Link;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    Link = IppFindNlaSetEntry(&Interface->LocalMulticastAddressSet,
                              Address,
                              sizeof(IP_LOCAL_MULTICAST_ADDRESS) - 
                                  FIELD_OFFSET(IP_LOCAL_ADDRESS, Link),
                              AddressBytes,
                              &NodeOrParent, 
                              &SearchResult);
    if (Link == NULL) {
        return;
    }
    
    LocalAddress = CONTAINING_RECORD(Link, IP_LOCAL_MULTICAST_ADDRESS, Link);
    IppDereferenceLocalMulticastAddressUnderLock(LocalAddress);
}


PIP_LOCAL_MULTICAST_ADDRESS
IppFindMulticastAddressOnInterfaceUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:
    
    Search for a given multicast address on a particular interface.

Arguments:

    Interface - Supplies the interface on which the group exists.

    Address - Supplies the multicast group address.

Return Value:

    Returns the local multicast address object, if one is found.
    Caller is responsible for dereferencing the address object on success.

Locks:

    Assumes caller holds a lock (read or a write) on the interface.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    PIP_LOCAL_MULTICAST_ADDRESS LocalAddress;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    PVOID NodeOrParent;
    TABLE_SEARCH_RESULT SearchResult;
    PNLA_LINK Link;

    ASSERT_ANY_LOCK_HELD(&Interface->Lock);

    Link = IppFindNlaSetEntry(&Interface->LocalMulticastAddressSet,
                              Address,
                              sizeof(IP_LOCAL_MULTICAST_ADDRESS) - 
                                  FIELD_OFFSET(IP_LOCAL_ADDRESS, Link),
                              AddressBytes,
                              &NodeOrParent, 
                              &SearchResult);
    if (Link == NULL) {
        return NULL;
    }
    
    LocalAddress = CONTAINING_RECORD(Link, IP_LOCAL_MULTICAST_ADDRESS, Link);
    IppReferenceLocalAddress((PIP_LOCAL_ADDRESS) LocalAddress);

    return LocalAddress;
}


PIP_LOCAL_MULTICAST_ADDRESS
IppFindMulticastAddressOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
{
    PIP_LOCAL_MULTICAST_ADDRESS LocalAddress;
    KIRQL OldIrql;

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);

    LocalAddress =
        IppFindMulticastAddressOnInterfaceUnderLock(Interface, Address);

    RtlReleaseReadLock(&Interface->Lock, OldIrql);

    return LocalAddress;
}

NTSTATUS
IppInitializeEphemeralLoopbackAddressSet(
    OUT PIP_LOOPBACK_ADDRESS_LOCKED_SET Set
    ) 
/*++

Routine Description:

    Allocate and initialize ephemeral loopback address set for a compartment.
    
Arguments:

    Set - Returns the initialized ephemeral loopback address set.
    
Return Value:

    STATUS_SUCCESS or failure code.
    
--*/
{
    NTSTATUS Status;
    
    Status = IppInitializeNlaSet(&Set->AddressSet);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    RtlInitializeMrswLock(&Set->Lock);
    
    Set->EntriesAdded = 0;
    Set->TicksToGarbageCollection = 
        IppSecondsToTicks(MAX_EPHEMERAL_DECOMPOSITION_TIME);
    return STATUS_SUCCESS;
}

VOID
IppUninitializeEphemeralLoopbackAddressSet(
    OUT PIP_LOOPBACK_ADDRESS_LOCKED_SET Set
    ) 
/*++

Routine Description:

    Uninitialize ephemeral loopback address set for a compartment.
    
Arguments:

    Set - Returns the initialized ephemeral loopback address set.
    
Return Value:

    None.
    
--*/
{
    IppUninitializeNlaSet(&Set->AddressSet);
    RtlUninitializeMrswLock(&Set->Lock);
}


VOID
IppGarbageCollectLoopbackAddressSet(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    Cleanup the ephemeral loopback addresses. 

Arguments:

    Compartment - Supplies a pointer to the compartment.

Locks:

    Assumes caller holds no locks.

Caller IRQL:

    Called at DISPATCH level.

--*/
{
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    KLOCK_QUEUE_HANDLE LockHandle;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PNLA_LINK Link;    
    PIP_LOOPBACK_ADDRESS_LOCKED_SET LoopbackAddressSet = 
        &Compartment->EphemeralLoopbackAddressSet;
    
    RtlAcquireWriteLockAtDpcLevel(
        &LoopbackAddressSet->Lock, 
        &LockHandle);
    
    //
    // Scan the set and expire addresses.
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link =
            IppEnumerateNlaSetEntry(
                &LoopbackAddressSet->AddressSet,
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS) 
            CONTAINING_RECORD(Link, IP_LOCAL_ADDRESS, Link);
        ASSERT(LocalAddress->AddressOrigin == ADDR_CONF_EPHEMERAL);
        IppRemoveLocalEphemeralAddressUnderLock(LocalAddress);
    }

    RtlReleaseWriteLockFromDpcLevel(
        &LoopbackAddressSet->Lock, 
        &LockHandle);
}

VOID
IppEphemeralLoopbackAddressSetTimeout(
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    Perform periodic processing on the Address Set. Garbage collect addresses 
    on one of the following events:
    1. Time since last garbage collection exceeds a threshold.
    2. Number of new addresses added exceeds 
       IP_EPHEMERAL_LOOPBACK_ADDRESS_RATE.

Arguments:

    Compartment - Supplies a pointer to the compartment.

Locks:

    Assumes caller holds no locks.

Caller IRQL:

    Called at DISPATCH level.

--*/
{
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    KLOCK_QUEUE_HANDLE LockHandle;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PNLA_LINK Link;    
    PIP_LOOPBACK_ADDRESS_LOCKED_SET LoopbackAddressSet = 
        &Compartment->EphemeralLoopbackAddressSet;

    //
    // Ephemeral loopback addresses are valid only for Ipv4.
    //
    if (!IS_IPV4_PROTOCOL(Compartment->Protocol)) {
        return;
    }
    
    RtlAcquireWriteLockAtDpcLevel(
        &LoopbackAddressSet->Lock, 
        &LockHandle);

    LoopbackAddressSet->TicksToGarbageCollection--;

    if (LoopbackAddressSet->TicksToGarbageCollection > 0 && 
        LoopbackAddressSet->EntriesAdded < 
            IP_EPHEMERAL_LOOPBACK_ADDRESS_RATE) {
        RtlReleaseWriteLockFromDpcLevel(
            &LoopbackAddressSet->Lock, 
            &LockHandle);
        return;
    }
    
    //
    // Scan the set and expire unused addresses.
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link =
            IppEnumerateNlaSetEntry(
                &LoopbackAddressSet->AddressSet,
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS) 
            CONTAINING_RECORD(Link, IP_LOCAL_ADDRESS, Link);
        ASSERT(LocalAddress->AddressOrigin == ADDR_CONF_EPHEMERAL);
        if (LocalAddress->ReferenceCount == 1) {
            //
            // Expire the address.
            //
            IppRemoveLocalEphemeralAddressUnderLock(LocalAddress);
        }   
    }

    //
    // Reset counters.
    //
    LoopbackAddressSet->TicksToGarbageCollection = 
        IppSecondsToTicks(MAX_EPHEMERAL_DECOMPOSITION_TIME);
    LoopbackAddressSet->EntriesAdded = 0;
    
    RtlReleaseWriteLockFromDpcLevel(
        &LoopbackAddressSet->Lock, 
        &LockHandle);
}

NTSTATUS
IppFindOrCreateLocalEphemeralAddressUnderLock(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Entry
    )
/*++

Routine Description:
    
    Find a given ephemeral address on the specified interface.

    Create one if the search is unsuccessful.

    If success or pending is returned, returns a reference on the 
    found/created entry to the caller.  The caller is responsible
    for releasing this reference, even if we asynchronously complete
    with failure.

Arguments:

    Address - Supplies the unicast address to search for.

    Interface - Supplies the interface on which the unicast address resides.

    Entry - Returns the multicast address entry on success.  NULL on failure.

Return Value:

    STATUS_SUCCESS, or failure code.

Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    PIP_LOCAL_UNICAST_ADDRESS LocalEphemeralAddress;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    PIP_LOOPBACK_ADDRESS_LOCKED_SET LoopbackAddressSet = 
        &Compartment->EphemeralLoopbackAddressSet;
    PNLA_LINK Link;
    PVOID NodeOrParent;
    TABLE_SEARCH_RESULT SearchResult;

    ASSERT_WRITE_LOCK_HELD(&LoopbackAddressSet->Lock);
    ASSERT(IS_LOOPBACK_INTERFACE(Interface));

    *Entry = NULL;
    
    if (!IppIsEphemeralAddressCandidate(Protocol, Address)) {
        // 
        // This is just so that all code paths get flushed out.
        //
        ASSERT(FALSE); 
        return STATUS_NOT_SUPPORTED;
    }
    
    Link = 
        IppFindNlaSetEntry(
            &LoopbackAddressSet->AddressSet,
            Address,
            sizeof(IP_LOCAL_UNICAST_ADDRESS) - 
                FIELD_OFFSET(IP_LOCAL_ADDRESS, Link), 
            AddressBytes,
            &NodeOrParent,
            &SearchResult);
    if (Link != NULL) {
        //
        // Found one.  Take another reference for the caller.
        //
        LocalEphemeralAddress = 
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);
        IppReferenceLocalAddress((PIP_LOCAL_ADDRESS) LocalEphemeralAddress);
    } else {
        //
        // Allocate one.  Initialize with a single reference for the caller.
        //
        LocalEphemeralAddress = (PIP_LOCAL_UNICAST_ADDRESS) 
            IppCreateLocalAddress(
                Protocol,
                Address,
                NlatUnicast,
                Interface, 
                ADDR_CONF_EPHEMERAL, 
                INFINITE_LIFETIME, 
                INFINITE_LIFETIME, 
                8 * Protocol->Characteristics->AddressBytes, 
                NULL);

        if (LocalEphemeralAddress == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        LocalEphemeralAddress->DadState = NldsPreferred;

        IppInsertNlaSetEntry(
            &LoopbackAddressSet->AddressSet, 
            &LocalEphemeralAddress->Link,
            sizeof(IP_LOCAL_UNICAST_ADDRESS) -
                FIELD_OFFSET(IP_LOCAL_ADDRESS, Link), 
            AddressBytes,
            NodeOrParent,
            SearchResult);

        LoopbackAddressSet->EntriesAdded++;
        IppReferenceLocalAddress((PIP_LOCAL_ADDRESS) LocalEphemeralAddress);
    }       
    *Entry = LocalEphemeralAddress;
    return STATUS_SUCCESS;
}

NTSTATUS
IppFindOrCreateLocalEphemeralAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Entry
    )
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;    
    PIP_LOOPBACK_ADDRESS_LOCKED_SET LoopbackAddressSet = 
        &Interface->Compartment->EphemeralLoopbackAddressSet;
    
    RtlAcquireWriteLock(&LoopbackAddressSet->Lock, &LockHandle);
    Status =
        IppFindOrCreateLocalEphemeralAddressUnderLock(
            Address,
            Interface,
            Entry);
    RtlReleaseWriteLock(&LoopbackAddressSet->Lock, &LockHandle);
    return Status;    
}

NTSTATUS
IppFindOrCreateLocalEphemeralAddressAtDpc(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Entry
    )
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;    
    PIP_LOOPBACK_ADDRESS_LOCKED_SET LoopbackAddressSet = 
        &Interface->Compartment->EphemeralLoopbackAddressSet;
    
    RtlAcquireWriteLockAtDpcLevel(&LoopbackAddressSet->Lock, &LockHandle);
    Status =
        IppFindOrCreateLocalEphemeralAddressUnderLock(
            Address,
            Interface,
            Entry);
    RtlReleaseWriteLockFromDpcLevel(&LoopbackAddressSet->Lock, &LockHandle);
    return Status;    
}

NTSTATUS
IppStartLinkLocalAddressConfiguration(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Start link local address configuration on an interface.  Depending on the
    link local address behavior on the interface, this routine does different
    things: 
    (1) LinkLocalAlwaysOn: Add a link local address. 
    (2) LinkLocalAlwaysOff: No change.
    (3) LinkLocalDelayed: Set a timeout for adding link local addresses.  When
    the timeout fires, if there are no other addresses, we add the link local
    address. 
    
Arguments:

    Interface - Supplies the interface for which to start link local address
        configuration. 
        
Return Value:

    STATUS_SUCCESS on success; otherwise the appropriate failure code.
    
Locks: Exclusive interface lock. 

Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if (Interface->LinkLocalAddressBehavior == LinkLocalAlwaysOn) {
        //
        // LinkLocalAlwaysOn: Add the link local address. 
        //
        Status = Interface->Compartment->Protocol->
            AddLinkLayerSuffixAddresses(Interface);
    } else if (Interface->LinkLocalAddressBehavior == LinkLocalDelayed) {
        //
        // LinkLocalDelayed: Set a timeout. 
        //
        Interface->LinkLocalAddressTimer = Interface->LinkLocalAddressTimeout;
    } else {
        //
        // LinkLocalAlwaysOff: No change. 
        //
    }

    return Status;
}
     
VOID
IppRestartLinkLocalAddressConfiguration(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Restart link local address configuration on an interface.
    
Arguments:

    Interface - Supplies the interface.
        
Return Value:

    None.
    
Locks: Interface (exclusive).

Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    if (IS_LOOPBACK_INTERFACE(Interface)) {
        return;
    }
    
    if (Interface->LinkLocalAddressBehavior == LinkLocalDelayed) { 
        //
        // Restart the timer.
        //
        Interface->LinkLocalAddressTimer = Interface->LinkLocalAddressTimeout;
    }
}


VOID 
IppHandleLinkLocalAddressChangeAtPassiveLevel(
    IN PVOID Context
    )
/*++

Routine Description:

    Adds or removed the assigned link local address from the persistent store.

Arguments:
    Context - Interface object.
    
Locks:

    Must be called with no locks held.
    Assumes caller holds a reference on the interface, which we free.

Caller IRQL:

    Must be called at PASSIVE level.

--*/    
{
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem = 
        (PIP_NOTIFICATION_WORK_QUEUE_ITEM) Context;
    PIP_INTERFACE Interface = (PIP_INTERFACE) WorkItem->Object;
    
    NsiSetParameter(
        NsiPersistent,
        NsiSetCreateOrSet,
        &NPI_MS_IPV4_MODULEID,
        NlInterfaceObject,
        (PUCHAR) &Interface->Luid,
        sizeof(Interface->Luid),
        NsiStructRw,
        (PUCHAR) &Interface->LinkLocalAddress,
        sizeof(Interface->LinkLocalAddress),
        FIELD_OFFSET(NL_INTERFACE_RW, LinkLocalAddress));
    
    IppDereferenceInterface(Interface); 
    ExFreePoolWithTag(WorkItem, IpGenericPoolTag);
}

VOID 
IppNotifyLinkLocalAddressChange(
    IN PIP_INTERFACE Interface,
    IN NSI_NOTIFICATION NotificationType
    )
/*++

Routine Description:

    Adds or removed the assigned link local address from the persistent store.

Arguments:

    Interface - Supplies the interface whose link local address changed.

    NotificationType - Supplies the notification type.
    
Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/    
{
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem;
    WorkItem = 
        ExAllocatePoolWithTag(
            NonPagedPool, sizeof *WorkItem, IpGenericPoolTag);

    if (WorkItem != NULL) {
        RtlZeroMemory(WorkItem, sizeof(*WorkItem));
        WorkItem->WorkerRoutine = 
            IppHandleLinkLocalAddressChangeAtPassiveLevel;
        WorkItem->Object = Interface;
        WorkItem->EventCode = 0;
        WorkItem->NotificationType = NotificationType;
        IppReferenceInterface(Interface);    
        NetioInsertWorkQueue(
            &Interface->Compartment->WorkQueue, 
            &WorkItem->Link);
    }
}

VOID
IppStopLinkLocalAddressConfiguration(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    This routine stops the link local address configuration state machine.  If
    the link local address configuration behavior is LinkLocalDelayed, it
    stops the timer and removes any link local addresses. For
    LinkLocalAlwaysOn, it removes the link-local address.  Otherwise, no change
    is required. 
    
Arguments:

    Interface - Supplies the interface for which to stop link local address
        cofiguration. 
        
Return Value:

    None.
    
Locks: Exclusive interface lock. 

Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    PNLA_LINK Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    
    //
    // Currently, this is only called for IPv4. 
    //
    ASSERT(Interface->Compartment->Protocol->Level == IPPROTO_IP);
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    switch (Interface->LinkLocalAddressBehavior) {
    case LinkLocalDelayed:
        //
        // Disable the timer. 
        //
        Interface->LinkLocalAddressTimer = 0;
        
        //
        // Fall through. 
        //
    case LinkLocalAlwaysOn:
        //
        // Remove the link-local address. 
        //
        IppInitializeAddressEnumerationContext(&Context);
        for (;;) {
            Link = IppEnumerateNlaSetEntry(
                &Interface->LocalUnicastAddressSet, 
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
            if (Link == NULL) {
                break;
            }
            
            LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS)
                CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);
            if (LocalAddress->AddressOrigin == ADDR_CONF_LINK) {
                IppRemoveLocalAddressUnderLock(
                    (PIP_LOCAL_ADDRESS) LocalAddress, FALSE);
            }
        }
        if (IS_IPV4_PROTOCOL(Interface->Compartment->Protocol)) {
            
            RtlZeroMemory(
                &Interface->LinkLocalAddress,
                sizeof(Interface->LinkLocalAddress));

            IppNotifyLinkLocalAddressChange(
                Interface, 
                NsiParameterNotification);
        }
        break;

    case LinkLocalAlwaysOff:
        break;

    default:
        ASSERT(FALSE);
        break;
    }
}

VOID
IppLinkLocalAddressConfigurationTimeout(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Process the interface's link-local address configuration timeout.
    Called from IpvXpInterfaceSetTimeout.
    
Arguments:

    Interface - Supplies the interface whose link-local address configuration
        timeout potentially fired. 
        
Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    
    DISPATCH_CODE();
    
    RtlAcquireWriteLockAtDpcLevel(&Interface->Lock, &LockHandle);

    if (Interface->LinkLocalAddressTimer > 0) {
        ASSERT(Interface->LinkLocalAddressBehavior == LinkLocalDelayed);
        if (--Interface->LinkLocalAddressTimer == 0) {
            //
            // Link-local address configuration timeout fired.
            // Add the link-local address(es). 
            //
            Interface->Compartment->Protocol->
                AddLinkLayerSuffixAddresses(Interface);
            
            if (IS_IPV4_PROTOCOL(Interface->Compartment->Protocol)) {     
                IppNotifyLinkLocalAddressChange(
                    Interface, 
                    NsiParameterNotification);
            }
        }
    }

    RtlReleaseWriteLockFromDpcLevel(&Interface->Lock, &LockHandle);
}

VOID
IppInspectReferenceLocalAddress(
   IN OUT PNL_LOCAL_ADDRESS LocalAddress
   )
/*++

Routine Description:

    Reference NL local address on behalf of the inspection module.
    
Arguments:

    LocalAddress - Supplies a pointer to the address. 
        
Return Value:

    None.
    
--*/ 
{
   IppReferenceLocalAddress((PIP_LOCAL_ADDRESS)LocalAddress);
}

VOID
IppInspectDereferenceLocalAddress(
   IN OUT PNL_LOCAL_ADDRESS LocalAddress
   )
/*++

Routine Description:

    Dereference NL local address on behalf of the inspection module.
    
Arguments:

    LocalAddress - Supplies a pointer to the address. 
        
Return Value:

    None.
    
--*/ 
{
   IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS)LocalAddress);
}
