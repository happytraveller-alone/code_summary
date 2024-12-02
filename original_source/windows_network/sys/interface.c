/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    interface.c

Abstract:

    This module contains generic interface management code for
    network layer providers (IPv4 and IPv6).

Author:

    Dave Thaler (dthaler) 7-Oct-2000

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "interface.tmh"

#if INTERFACE_REFHIST
PREFERENCE_HISTORY IppInterfaceReferenceHistory;
PREFERENCE_HISTORY IppSubInterfaceReferenceHistory;
#endif

NTSTATUS
IppStartInterfaceManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Start the network interface manager.
    
Arguments:

    Protocol - Supplies the network layer protocol.    

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    RtlInitializeMrswLock(&Protocol->ZoneUpdateLock);
    IppInitializeLockedList(&Protocol->GlobalInterfaceSet);
    ExInitializeFastMutex(&Protocol->OffloadStatsMutex);

    IppDefaultStartRoutine(Protocol, IMS_INTERFACE_MANAGER);

    return STATUS_SUCCESS;
}

VOID
IppCleanupInterfaceManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Cleanup the network interface manager.
    
Arguments:

    Protocol - Supplies the network layer protocol.
    
Return Value:

    None.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    RtlUninitializeMrswLock(&Protocol->ZoneUpdateLock);

    ExUninitializeFastMutex(&Protocol->OffloadStatsMutex);

    //
    // The FL providers should have removed all interfaces.
    //
    ASSERT(Protocol->GlobalInterfaceSet.NumEntries == 0);
    IppUninitializeLockedList(&Protocol->GlobalInterfaceSet);
}

__inline 
VOID
IppInvalidateLinkState(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Invalidate link state cache. This allows any operations initiated on a 
    network change/reconnect to synchronize. Esp when many such 
    events occur close together, say in a wireless scenario.
    
Arguments:

    Interface - Supplies the interface that was reconnected.
    
Return Value:

    None.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    InterlockedIncrement(&Interface->LinkEpoch);
}

//
// Interface-Identifier management routines.
//

VOID
IppRegenerateLinkLayerSuffixAddresses(
    IN PIP_INTERFACE Interface
    )
{
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PNLA_LINK Link;
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    BOOLEAN LinkLocalAddressPresent = FALSE;
    
    //
    // Remove all the addresses that used the link layer address as the suffix.
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link =
            IppEnumerateNlaSetEntry(
                &Interface->LocalUnicastAddressSet, 
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }
            
        LocalAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);
        if (LocalAddress->SuffixOrigin == NlsoLinkLayerAddress) {
            if (LocalAddress->PrefixOrigin == NlpoWellKnown) {
                LinkLocalAddressPresent = TRUE;
            }
            IppRemoveLocalAddressUnderLock(
                (PIP_LOCAL_ADDRESS) LocalAddress,
                FALSE);
        }
    }

    //
    // If the interface had a link-local address or link local addresses
    // are always enabled, add it again.
    //
    if ((Interface->LinkLocalAddressBehavior == LinkLocalAlwaysOn) ||
        ((Interface->LinkLocalAddressBehavior == LinkLocalDelayed) &&
         LinkLocalAddressPresent)) {
        Interface->Compartment->Protocol->
            AddLinkLayerSuffixAddresses(Interface);
    }

    //
    // Start router discovery if it is enabled on this interface.
    // This would regenerate all addresses with the link layer address
    // as the suffix and a router advertisment as the prefix.
    //
    if (Interface->UseRouterDiscovery) {
        IppStartRouterDiscovery(Interface);
    }
}


BOOLEAN
IppRandomizeIdentifier(
    IN PIP_INTERFACE Interface
    )
{
    struct {
        GUID Guid;
        UCHAR Identifier[MAX_INTERFACE_IDENTIFIER_LENGTH];
    } InterfaceGuidAndIdentifier = {0};
    MD5_CTX Context;

    if (!Interface->FlCharacteristics->TemporaryAddresses) {
        //
        // The interface does not support random identifiers.
        //
        return FALSE;
    }


    //
    // The random identifier is a secure hash of the interface GUID and ID.
    // This ensures that we get the same value every time,
    // while obviating the need to store the random identifier in use.
    //
    InterfaceGuidAndIdentifier.Guid = Interface->Guid;
    RtlCopyMemory(
        InterfaceGuidAndIdentifier.Identifier,
        Interface->Identifier,
        sizeof(Interface->Identifier));
    
    MD5Init(&Context);

    MD5Update(
        &Context,
        (CONST UCHAR *) &InterfaceGuidAndIdentifier,
        sizeof(InterfaceGuidAndIdentifier));

    MD5Final(&Context);

    RtlCopyMemory(
        Interface->Identifier,
        &Context.digest,
        sizeof(Interface->Identifier));
    
    //
    // Clear the "u" bit to indicate local significance.
    //
    Interface->Identifier[0] &= ~0x2;

    return TRUE;
}


VOID
IppUpdateInterfaceIdentifier(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN Randomize
    )
{
    if (Randomize) {
        if (!RtlEqualMemory(
                Interface->Identifier,
                Interface->FlCharacteristics->Identifier,
                sizeof(Interface->Identifier))) {
            //
            // The interface identifier has already been randomized.
            //
            return;
        }

        if (!IppRandomizeIdentifier(Interface)) {
            return;
        }    
    } else {
        if (RtlEqualMemory(
                Interface->Identifier,
                Interface->FlCharacteristics->Identifier,
                sizeof(Interface->Identifier))) {
            //
            // The interface identifier is already not random.
            //
            return;
        }
        
        RtlCopyMemory(
            Interface->Identifier,
            Interface->FlCharacteristics->Identifier,
            sizeof(Interface->Identifier));
    }

    IppRegenerateLinkLayerSuffixAddresses(Interface);
}


//
// Internal Interface Management Routines.
//

PIP_INTERFACE
IppAllocateInterface(
    VOID
    )
/*++

Routine Description:

    Allocate an interface structure.
    
Arguments:

    None.
    
Return Value:

    Allocated Interface or NULL.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface;

    ULONG Size = sizeof(IP_INTERFACE) +
        (sizeof(PIP_INTERFACE_STATISTICS) * KeQueryMaximumProcessorCount());
        
    //
    // We can't use FSB here since fewer than 16 would fit in PAGE_SIZE.
    //
    Interface = ExAllocatePoolWithTag(NonPagedPool, Size, IpInterfacePoolTag);
    if (Interface != NULL) {
        RtlZeroMemory(Interface, Size);

        Interface->PerProcessorStatistics =
            (PIP_INTERFACE_STATISTICS *)(Interface + 1);
    }
    return Interface;
}

VOID
IppQueryInterface(
    IN PIP_INTERFACE Interface, 
    OUT PNL_INTERFACE_CHARACTERISTICS Characteristics
    )
/*++

Routine Description:

    This routine fills the interface characteristics structure for passing to
    the network layer client. 

Arguments:

    Interface - Supplies the interface.

    Characteristics - Returns the interface characteristics.

Return Value:

    None.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    //
    // Snapshot the NL mtu.  Since no lock is held, this value is volatile.
    //
    ULONG NlMtu = Interface->MinimumNlMtu;

    if (NlMtu == 0) {
        Characteristics->UlMtu = 0;
    } else {
        Characteristics->UlMtu = 
            NlMtu - Interface->Compartment->Protocol->HeaderSize;
    }
    
    Characteristics->Lso = &Interface->Lso;
    Characteristics->Gso = &Interface->Gso;
    Characteristics->FlCharacteristics = Interface->FlCharacteristics;
    Characteristics->Forwards = (BOOLEAN) Interface->Forward;

    Characteristics->NeighborReachabilityInMs = 
        IppTicksToSeconds(Interface->ReachableTicks) * 1000;
}

VOID
IppNotifyInterfaceChangeToNlClients(
    IN PIP_INTERFACE Interface,
    IN IP_INTERFACE_CHANGE_EVENT NotificationType
    )
/*++

Routine Description:

    Inform all network layer clients of interface state change.
    
    New clients should enumerate interfaces, we only guarantee indications
    to those clients already registered.
    Deleting clients voluntarily dereference interfaces, we only guarantee
    indications to those clients active at the time notification is made.

Arguments:

    Interface - Supplies the interface to notify clients about.

    NotificationType - Supplies the notification we will make to Nl clients.

Return Value:

    None.

Caller IRQL: PASSIVE_LEVEL

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    KIRQL OldIrql;
    PLIST_ENTRY Next, Head;
    PIP_CLIENT_CONTEXT Client;
    NL_INDICATE_INTERFACE Indicate;
    NL_INTERFACE_CHARACTERISTICS Characteristics = {0};
    
    PASSIVE_CODE();
    //
    // Inform all network layer clients about interface update.
    //
    IppQueryInterface(Interface, &Characteristics);

    Head = &Protocol->NlClientSet.Set;
    RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        //
        // The client is left in its set upon deletion and cleaned up with the
        // client set lock held.  Hence we can access Next without a reference.
        // Also, because new clients are only added at the head of the list,
        // we can unlock the list during our traversal
        // and know that the traversal will terminate properly.
        //
        
        Client = (PIP_CLIENT_CONTEXT)
            CONTAINING_RECORD(Next, IP_CLIENT_CONTEXT, Link);

        if (!IppReferenceNlClient(Client)) {
            //
            // We must be careful to not reference a deleted client.
            // c.f. IppInterfaceCleanup.
            //
            continue;
        }
        
        RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);

        //
        // Now that we have released all locks, we can provide the indication.
        //
        Indicate.ClientHandle = Client->Npi.ProviderHandle;
        Indicate.Interface = (PNL_INTERFACE) Interface;

        switch (NotificationType) {
        case IpAddInterfaceEvent: 
            if (Client->Npi.Dispatch->AddInterfaceNotification != NULL) {
                Client->Npi.Dispatch->AddInterfaceNotification(
                    &Indicate,
                    &Characteristics);
            }
            break;
        case IpUpdateInterfaceEvent: 
            if (Client->Npi.Dispatch->UpdateInterfaceNotification != NULL) {
                Client->Npi.Dispatch->UpdateInterfaceNotification(
                    &Indicate,
                    &Characteristics);
            }
            break;
        case IpDeleteInterfaceEvent:
            if (Client->Npi.Dispatch->DeleteInterfaceNotification != NULL) {
                Client->Npi.Dispatch->DeleteInterfaceNotification(&Indicate);
            }
            break;
        case IpCleanupInterfaceEvent:                        
            if (Client->Npi.Dispatch->CleanupInterfaceNotification != NULL) {
                Client->Npi.Dispatch->CleanupInterfaceNotification(&Indicate);
            }
            break;
        }
        //
        // We dereference the client after acquiring the client set lock.
        // Since we hold a reference on the client, it must belong to its set.
        //
        RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
        IppDereferenceNlClient(Client);
    }
    RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);
}

VOID
IppCleanupInterfaceWorkerRoutine(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    Cleanup and destroy an interface structure.

    We queue a worker thread so we can notify the framing layer provider
    of delete completion without holding any locks and at PASSIVE IRQL.

Arguments:

    DeviceObject - Supplies a pointer to the device object.

    Context - Supplies the interface in question.

Return Value:

    None.

Caller IRQL: PASSIVE_LEVEL

--*/
{
    FL_REQUEST_COMPLETE Request = {0};
    PFL_PROVIDER_DELETE_INTERFACE_COMPLETE FlDeleteComplete;
    PLIST_ENTRY Current, Next;
    PIP_POTENTIAL_ROUTER PotentialRouter;
    PIP_PROTOCOL Protocol;
    PIP_COMPARTMENT Compartment;
    ULONG i = 0;
    ULONG NumMaxProcessors;
    PIP_INTERFACE Interface = IppCast(Context, IP_INTERFACE);
    

    PASSIVE_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);
    
    ASSERT(Interface->ReferenceCount == 0);

    Compartment = Interface->Compartment;
    Protocol = Interface->FlModule->Protocol;

    IppNotifyInterfaceChangeToNlClients(Interface, IpCleanupInterfaceEvent);
    
    //
    // Prepare the FL delete interface completion request. Note that we have to
    // do this now before the interface gets deleted. 
    //
    Request.ProviderObjectHandle = Interface->FlContext;
    Request.Status = STATUS_SUCCESS;
    FlDeleteComplete = Interface->FlDeleteComplete;

    RtlUninitializeMrswLock(&Interface->Lock);

    IppUninitializeNliSet(&Interface->SubInterfaceSet);
    
    RtlUninitializeMrswLock(&Interface->NeighborSetLock);
    IppUninitializeNeighborSet(&Interface->NeighborSet);
    IppUninitializeProxyNeighborSet(&Interface->ProxyNeighborSet);

    IppUninitializeNlaSet(&Interface->LocalUnicastAddressSet);
    IppUninitializeNlaSet(&Interface->LocalAnycastAddressSet);
    IppUninitializeNlaSet(&Interface->LocalBroadcastAddressSet);
    IppUninitializeNlaSet(&Interface->LocalMulticastAddressSet);

    //
    // Remove all the potential routers from the potential router list. 
    // 
    for (Current = Interface->PotentialRouterList.Flink; 
         Current != &Interface->PotentialRouterList; 
         Current = Next) {
        PotentialRouter = (PIP_POTENTIAL_ROUTER)
            CONTAINING_RECORD(Current, IP_POTENTIAL_ROUTER, Link);
        Next = Current->Flink;
        ExFreePool(PotentialRouter);
    }

    if (Interface->UnicastAddressEventTable != NULL) {
        TtDestroyTable(Interface->UnicastAddressEventTable);
    }
    if (Interface->AnycastAdvertisementTimerTable != NULL) {
        TtDestroyTable(Interface->AnycastAdvertisementTimerTable);
    }
    if (Interface->MulticastReportTimerTable != NULL) {
        TtDestroyTable(Interface->MulticastReportTimerTable);
    }
    if (Interface->MulticastGeneralQueryTimerTable != NULL) {
        TtDestroyTable(Interface->MulticastGeneralQueryTimerTable);
    }
    if (Interface->MulticastSpecificQueryTimerTable != NULL) {
        TtDestroyTable(Interface->MulticastSpecificQueryTimerTable);
    }
    
    ASSERT(!Interface->MulticastWorkItemScheduled);
    IoFreeWorkItem(Interface->MulticastWorkItem);
    
    IoFreeWorkItem(Interface->WorkItem);

    NetioShutdownWorkQueue(&Interface->WorkQueue);

    IppDereferenceCompartment(Interface->Compartment);

    //
    // Initialize the uninitialized per proc structures to point to NULL
    // TODO: Clean this up when we fix the incorrect per proc
    // statistics bug.
    //
    NumMaxProcessors = KeQueryMaximumProcessorCount();
    for (i = 1; i < NumMaxProcessors; i++) {
        if (Interface->PerProcessorStatistics[i] == 
            Interface->PerProcessorStatistics[0]) {
            Interface->PerProcessorStatistics[i] = NULL;
        }
    }
    NetioFreeOpaquePerProcessorContext(
        Interface->PerProcessorStatistics, 
        NULL);
    
    ExFreePool((PUCHAR) Interface);    

    //
    // Indicate delete completion to the framing layer provider. This has to be
    // the last step to make sure that when we complete the deletion, we have
    // removed all references stored in the interface. Once the deletion is
    // completed, the driver might become ready for unload and go in to the
    // cleanup phase, which assumes that there are no outstanding references
    // (on the compartment, for instance).
    //
    (*FlDeleteComplete)(&Request);

}


VOID
IppCleanupInterface(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Cleanup and destroy an interface structure.
    
Arguments:

    Interface - Supplies the interface to cleanup.
    
Return Value:

    None.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ASSERT(Interface->ReferenceCount == 0);

    //
    // Cleanup at passive level.
    //
    IoQueueWorkItem(
        Interface->WorkItem,
        IppCleanupInterfaceWorkerRoutine,
        DelayedWorkQueue,
        (PVOID) Interface);
}


PIP_INTERFACE
IppCreateInterface(
    IN PIP_COMPARTMENT Compartment,
    IN CONST FL_INTERFACE_IDENTIFIERS *Identifiers,
    IN CONST FL_INTERFACE_CHARACTERISTICS *Characteristics,
    IN PVOID FlContext,
    IN PFL_PROVIDER_CONTEXT FlModule,
    IN PNL_INTERFACE_RW InterfaceRw
    )
/*++

Routine Description:
    
    Create and initialize a new interface structure.
    
Arguments:

    Compartment - Supplies the compartment in which to create the interface.
        The caller must hold a reference on the compartment.

    Identifiers - Supplies the interface identifers.

    Characteristics - Supplies the interface characteristics.

    FlContext - Supplies the framing layer's handle to the interface.
        
    FlModule - Supplies the framing layer module.
    
    InterfaceRw - Supplies the interface's configuration information.

Return Value:

    New interface or NULL.

Caller IRQL: < DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;
    PLIST_ENTRY Next, Head;
    PIP_INTERFACE Interface, NextInterface;
    SCOPE_LEVEL Level;
    ULONG RetransmitTicks =
        IppMillisecondsToTicks(InterfaceRw->RetransmitTime);
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG i = 0;
    ULONG NumMaxProcessors;
    KAFFINITY Affinity;
    
    PASSIVE_CODE();
   

    //
    // Allocate the interface structure.
    //
    Interface = IppAllocateInterface();
    if (Interface == NULL) {
        return NULL;
    }
    Interface->Signature = IP_INTERFACE_SIGNATURE;

    Status = 
        NetioInitializeWorkQueue(
            &Interface->WorkQueue, 
            IppInterfaceDelayedWorker, 
            NULL, 
            IppDeviceObject);
    if (!NT_SUCCESS(Status)) {
        goto ErrorWorkQueue;
    }

    //
    // Initialize meta-fields.
    //
    Interface->WorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (Interface->WorkItem == NULL) {
        goto ErrorWorkItem;
    }
    
    Status = IppInitializeNliSet(&Interface->SubInterfaceSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorSubInterfaceSet;
    }
    
    Status =
        IppInitializeNeighborSet(
            &Interface->NeighborSet,
            (USHORT) RetransmitTicks);
    if (!NT_SUCCESS(Status)) {
        goto ErrorNeighborSet;
    }    

    IppInitializeProxyNeighborSet(&Interface->ProxyNeighborSet);    

    Interface->ValidLocalUnicastAddressCount = 0;
    
    Status = IppInitializeNlaSet(&Interface->LocalUnicastAddressSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorUnicastAddressSet;
    }

    Status = IppInitializeNlaSet(&Interface->LocalAnycastAddressSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorAnycastAddressSet;
    }

    Status = IppInitializeNlaSet(&Interface->LocalBroadcastAddressSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorBroadcastAddressSet;
    }

    Status = IppInitializeNlaSet(&Interface->LocalMulticastAddressSet);
    if (!NT_SUCCESS(Status)) {
        goto ErrorMulticastAddressSet;
    }

    Interface->UnicastAddressEventTable = 
        TtCreateTable((USHORT) RetransmitTicks, FALSE);
    if (Interface->UnicastAddressEventTable == NULL) {
        goto ErrorUnicastTable;
    }

    Interface->AnycastAdvertisementTimerTable =
        TtCreateTable(IppTimerTicks(MAX_ANYCAST_DELAY_TIME), FALSE);
    if (Interface->AnycastAdvertisementTimerTable == NULL) {
        goto ErrorAnycastTable;
    }
    
    Interface->MulticastReportTimerTable = TtCreateTable(2, TRUE);
    if (Interface->MulticastReportTimerTable == NULL) {
        goto ErrorReportTable;
    }

    Interface->MulticastGeneralQueryTimerTable = TtCreateTable(32, TRUE);
    if (Interface->MulticastGeneralQueryTimerTable == NULL) {
        goto ErrorGeneralQueryTable;
    }

    Interface->MulticastSpecificQueryTimerTable = TtCreateTable(32, TRUE);
    if (Interface->MulticastSpecificQueryTimerTable == NULL) {
        goto ErrorSpecificQueryTable;
    }

    Interface->MulticastWorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (Interface->MulticastWorkItem == NULL) {
        goto ErrorMulticastWorkItem;
    }

    RtlInitializeMrswLock(&Interface->Lock);
    RtlInitializeMrswLock(&Interface->NeighborSetLock);

    //
    // The worker lock serializes some heavy-weight
    // calls to upper layers.
    //
    KeInitializeMutex(&Interface->WorkerLock, 0);

    //
    // Initialize scalar fields.
    //
    Interface->Compartment = Compartment;
    IppReferenceCompartment(Compartment);

    Interface->Luid = Identifiers->Luid;
    Interface->Index = Identifiers->Index;
    
    Interface->FlContext = FlContext;
    Interface->FlModule = FlModule;
    Interface->FlCharacteristics = Characteristics;
    Interface->FlBackfill = (USHORT)
        ALIGN_UP(
            Interface->FlCharacteristics->HeaderLength,
            MAX_NATURAL_ALIGNMENT);

    //
    // Attempt to obtain the interface GUID,
    // but continue initialization regardless of status.
    //
    (VOID) ConvertInterfaceLuidToGuid(&Interface->Luid, &Interface->Guid);
    
    //
    // Interface->FlDeleteComplete = NULL;
    //
    
    //
    // One reference for initialization, another for the caller.
    //
    Interface->ReferenceCount = 2;

    //
    // Interface->ConnectedSubInterfaces = 0;
    // Interface->Flags = 0;
    // Interface->FragmentId = 0;
    //

    RtlCopyMemory(
        Interface->Identifier,
        Interface->FlCharacteristics->Identifier,
        sizeof(Interface->Identifier));
    if (Protocol->RandomizeIdentifiers) {
        (VOID) IppRandomizeIdentifier(Interface);
    }
    
    Interface->LinkLocalAddressBehavior = 
        InterfaceRw->LinkLocalAddressBehavior;
    Interface->LinkLocalAddressTimeout = 
        IppMillisecondsToTicks(InterfaceRw->LinkLocalAddressTimeout);
    
    //
    // Initialize some random state for temporary addresses.
    //
    *(UINT UNALIGNED *)Interface->TemporaryState = RandomNumber(0, MAXULONG);

    //
    // Update parameters that affect router discovery. 
    //
    Interface->RouterDiscoveryBehavior =
        InterfaceRw->RouterDiscoveryBehavior;
    Interface->DhcpRouterDiscoveryEnabled = 
        InterfaceRw->DhcpRouterDiscoveryEnabled;
    Interface->UseBroadcastForRouterDiscovery = 
        InterfaceRw->UseBroadcastForRouterDiscovery;
    
    Interface->UseRouterDiscovery =
        IppIsRouterDiscoveryEnabled(Interface);

    Interface->Advertise = 
        Interface->UseRouterDiscovery && InterfaceRw->AdvertisingEnabled;

    Interface->AdvertiseDefaultRoute =
        InterfaceRw->AdvertiseDefaultRoute;
    
    if (!Interface->UseRouterDiscovery || Interface->Advertise) {
        Interface->ManagedAddressConfiguration =
            InterfaceRw->ManagedAddressConfigurationSupported;
        Interface->OtherStatefulConfiguration =
            InterfaceRw->OtherStatefulConfigurationSupported;
    }

    Interface->Forward = InterfaceRw->ForwardingEnabled;
    Interface->ForwardMulticast = InterfaceRw->MulticastForwardingEnabled;

    Interface->WeakHostSend = InterfaceRw->WeakHostSend;
    Interface->WeakHostReceive = InterfaceRw->WeakHostReceive;
    
    Interface->UseNeighborUnreachabilityDetection =
        InterfaceRw->UseNeighborUnreachabilityDetection;
    
    Interface->UseZeroBroadcastAddress = InterfaceRw->UseZeroBroadcastAddress;
    
    IppSetInterfaceType(Interface, InterfaceRw->TypeOfInterface);

    Interface->Metric = InterfaceRw->Metric;
    Interface->AutoMetric = InterfaceRw->UseAutomaticMetric;

    Interface->BaseReachableTime =
        InterfaceRw->BaseReachableTime;
    Interface->ReachableTicks =
        IppNeighborReachableTicks(Interface->BaseReachableTime);

    if (InterfaceRw->PathMtuDiscoveryTimeout == INFINITE_LIFETIME) {
        Interface->PathMtuDiscoveryTicks = INFINITE_LIFETIME;
    } else {
        Interface->PathMtuDiscoveryTicks = 
            IppMillisecondsToTicks(InterfaceRw->PathMtuDiscoveryTimeout);
    }

    Interface->MinimumNlMtu = InterfaceRw->NlMtu;            

    Interface->RetransmitTicks = RetransmitTicks;
    Interface->DadTransmits = InterfaceRw->DadTransmits;

    //
    // Interface->LinkLocalAddressTimeout = 0; 
    // Interface->LinkLocalAddressTimer = 0; 
    //

    //
    // Interface->CurrentHopLimit = 0;
    // Interface-> MulticastForwardingHopLimit = 0;
    //
    Interface->DisableDefaultRoutes=
        InterfaceRw->DisableDefaultRoutes;
        
    Interface->DefaultSitePrefixLength = 64;
    
    Interface->MinimumReceivedHopCount = RECEIVED_HOP_COUNT_MASK + 1;

    InitializeListHead(&Interface->PotentialRouterList);
    //
    // Interface->RouterDiscoveryCount = 0;
    // Interface->RouterDiscoveryTimer = 0;
    // Interface->LastRouterAdvertisement = 0;
    //

    Interface->MulticastDiscoveryVersion = MULTICAST_DISCOVERY_VERSION3;
    if (Interface->MulticastDiscoveryVersion > Protocol->MaximumMldVersion) {
        Interface->MulticastDiscoveryVersion = Protocol->MaximumMldVersion;
    }
    Interface->MulticastQuerierPresent[0] = 
        Interface->MulticastQuerierPresent[1] = 0;
    Interface->RobustnessVariable = DEFAULT_MULTICAST_DISCOVERY_ROBUSTNESS;

    //
    // Initialize zone indices for all levels.
    // Note that some levels have constant zone indices so we don't store them.
    // - ZoneIndex(ScopeLevelInterface) = Index;
    // - ZoneIndex(ScopeLevelGlobal) = 1;
    //
    for (Level = ScopeLevelLink; Level < ScopeLevelGlobal; Level++) {
        ULONG Index = Level - ScopeLevelLink;        
        Interface->ZoneIndices[Index].Level = Level;
        Interface->ZoneIndices[Index].Zone = InterfaceRw->ZoneIndices[Level];
    }

    //
    // TODO: (bug# 840353). We should start advertising if required when the
    // interface is created. 
    //

    //
    // Insert the interface in various sets.
    // Done last so that the interface is only accessed once initialized.
    //
    
    //
    // Insert the interface into the global interface set.
    // The interface goes before any interface in the list with a greater LUID.
    //
    RtlAcquireWriteLock(&Protocol->GlobalInterfaceSet.Lock, &LockHandle);
#ifndef USER_MODE
    Affinity = TcpipGetAllocatedProcessorCount();
#else
    Affinity = (1 << KeNumberProcessors) - 1;
#endif    
    
    if (!NT_SUCCESS(
            NetioAllocateOpaquePerProcessorContext(
                Interface->PerProcessorStatistics,
                sizeof(IP_INTERFACE_STATISTICS),
                IpInterfacePoolTag,
                Affinity,
                NULL,
                NULL,
                NULL))) {
            goto ErrorPerProcessorInitialization;
    }
    //
    // Initialize the uninitialized per proc structures to point to the 
    // first processor. 
    // TODO: Clean this up when we fix the incorrect per proc
    // structures.
    //
    NumMaxProcessors = KeQueryMaximumProcessorCount();
    for (i = 1; i < NumMaxProcessors; i++) {
        if (Interface->PerProcessorStatistics[i] == NULL) {
            Interface->PerProcessorStatistics[i] = 
                Interface->PerProcessorStatistics[0];
        }
    }

    Head = &Protocol->GlobalInterfaceSet.Set;
    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        NextInterface = (PIP_INTERFACE)
            CONTAINING_RECORD(Next, IP_INTERFACE, GlobalLink);

        if (memcmp(&NextInterface->Luid, &Interface->Luid, sizeof(IF_LUID)) >
            0) {
            break;
        }
    }
    Protocol->GlobalInterfaceSet.NumEntries++;
    InsertTailList(Next, &Interface->GlobalLink);
    RtlReleaseWriteLock(&Protocol->GlobalInterfaceSet.Lock, &LockHandle);

    //
    // Insert the interface into the the compartment interface set.
    // The interface goes at the head of the list.
    //
    RtlAcquireWriteLock(&Compartment->InterfaceSet.Lock, &LockHandle);
    {
        Compartment->InterfaceSet.NumEntries++;
        InsertHeadList(&Compartment->InterfaceSet.Set,
                       &Interface->CompartmentLink);
    }
    RtlReleaseWriteLock(&Compartment->InterfaceSet.Lock, &LockHandle);
    
    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_INFORMATION,
               "IPNG: [%u] Created %s interface index %u\n", 
               Identifiers->Index, 
               Protocol->TraceString, 
               Identifiers->Index);

    return Interface;

    //
    // Cleanup on failure depending upon point of failure.
    //
    
ErrorPerProcessorInitialization:
    RtlReleaseWriteLock(&Protocol->GlobalInterfaceSet.Lock, &LockHandle);
ErrorMulticastWorkItem:
    TtDestroyTable(Interface->MulticastSpecificQueryTimerTable);
ErrorSpecificQueryTable:
    TtDestroyTable(Interface->MulticastGeneralQueryTimerTable);
ErrorGeneralQueryTable:
    TtDestroyTable(Interface->MulticastReportTimerTable);
ErrorReportTable:
    TtDestroyTable(Interface->AnycastAdvertisementTimerTable);
ErrorAnycastTable:
    TtDestroyTable(Interface->UnicastAddressEventTable);
ErrorUnicastTable:
    IppUninitializeNlaSet(&Interface->LocalMulticastAddressSet);    
ErrorMulticastAddressSet:
    IppUninitializeNlaSet(&Interface->LocalBroadcastAddressSet);
ErrorBroadcastAddressSet:
    IppUninitializeNlaSet(&Interface->LocalAnycastAddressSet);
ErrorAnycastAddressSet:
    IppUninitializeNlaSet(&Interface->LocalUnicastAddressSet);
ErrorUnicastAddressSet:
    IppUninitializeNeighborSet(&Interface->NeighborSet);
    IppUninitializeProxyNeighborSet(&Interface->ProxyNeighborSet);
ErrorNeighborSet:
    IppUninitializeNliSet(&Interface->SubInterfaceSet);    
ErrorSubInterfaceSet:
    IoFreeWorkItem(Interface->WorkItem);
ErrorWorkItem:    
    NetioShutdownWorkQueue(&Interface->WorkQueue);
ErrorWorkQueue:    
    ExFreePool((PUCHAR) Interface);
    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_WARNING,
               "IPNG: [%u] Error creating %s\n", 
               Identifiers->Index, 
               Protocol->TraceString);
    return NULL;
}

VOID
IppInterfaceDelayedWorker(
    IN PSINGLE_LIST_ENTRY WorkQueueHead
    )
/*++

Routine Description:

    Handles work items for an interface.

Arguments:

    WorkQueueHead - Supplies a pointer to a structure that holds information
                    about the function and its corresponding parametres, 
                    that has to be called for the work item.

Return Value:

    None.

Caller Lock:

    Caller should not hold any lock(s). Caller should hold a reference
    on either the address or the interface, depending on which is valid.

Caller IRQL:

    Must be invoked at PASSIVE level.

--*/
{
    PIP_DELAYED_WORK_QUEUE_ITEM WorkItem;

    ASSERT(WorkQueueHead != NULL);

    do {

        WorkItem = 
            CONTAINING_RECORD(
                WorkQueueHead, IP_DELAYED_WORK_QUEUE_ITEM, Link);
        WorkQueueHead = WorkQueueHead->Next;

        //
        // WorkItem will be freed by the WorkerRoutine.
        //
        WorkItem->WorkerRoutine((PVOID) WorkItem);
        
    } while (WorkQueueHead != NULL);
}



PIP_INTERFACE
IppFindInterfaceByLuidUnderLock(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *Luid
    )
/*++

Routine Description:
    
    Search for an interface given its LUID.
    
Arguments:

    Protocol - Supplies the protocol state.

    Luid - Supplies the interface LUID to look for.

Return Value:

    Returns the interface (with a reference), if found.  NULL, if not.
    
Caller LOCK: Global Interface Set Lock (Shared).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    PLIST_ENTRY Next, Head = &Protocol->GlobalInterfaceSet.Set;
    PIP_INTERFACE Interface;

    ASSERT_ANY_LOCK_HELD(&Protocol->GlobalInterfaceSet.Lock);

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Next, IP_INTERFACE, GlobalLink);

        if (RtlEqualMemory(Luid, &Interface->Luid, sizeof(IF_LUID))) {
            IppReferenceInterface(Interface);
            return Interface;
        }
    }
    return NULL;
}


PIP_INTERFACE
IppFindInterfaceByLuid(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *Luid
    )
{
    PIP_INTERFACE Interface;
    KIRQL OldIrql;

    RtlAcquireReadLock(&Protocol->GlobalInterfaceSet.Lock, &OldIrql);
    {
        Interface = IppFindInterfaceByLuidUnderLock(Protocol, Luid);
    }
    RtlReleaseReadLock(&Protocol->GlobalInterfaceSet.Lock, OldIrql);

    return Interface;
}


PIP_INTERFACE
IppFindInterfaceByIndexUnderLock(
    IN PIP_COMPARTMENT Compartment,
    IN IF_INDEX Index
    )
/*++

Routine Description:
    
    Search the specified compartment for an interface given its index.
    
Arguments:

    Compartment - Supplies the compartment to search.
        The caller must hold a reference on the compartment.

    Index - Supplies the interface index to look for.

Return Value:

    Returns the interface (with a reference), if found.  NULL, if not.
    
Caller LOCK: Compartment's Interface Set Lock (Shared).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    PLIST_ENTRY Next, Head = &Compartment->InterfaceSet.Set;
    PIP_INTERFACE Interface;

    ASSERT_ANY_LOCK_HELD(&Compartment->InterfaceSet.Lock);

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Next, IP_INTERFACE, CompartmentLink);

        if (Interface->Index == Index) {
            IppReferenceInterface(Interface);
            return Interface;
        }
    }
    return NULL;
}


PIP_INTERFACE
IppFindInterfaceByIndex(
    IN PIP_COMPARTMENT Compartment,
    IN IF_INDEX Index
    )
{
    PIP_INTERFACE Interface;
    KIRQL OldIrql;

    RtlAcquireReadLock(&Compartment->InterfaceSet.Lock, &OldIrql);
    {
        Interface = IppFindInterfaceByIndexUnderLock(Compartment, Index);
    }
    RtlReleaseReadLock(&Compartment->InterfaceSet.Lock, OldIrql);

    return Interface;
}


PIP_INTERFACE
IppFindInterfaceByRequest(
    IN PNL_REQUEST_INTERFACE Args
    )
{
    PIP_CLIENT_CONTEXT Client;
    PIP_COMPARTMENT Compartment;
    PIP_INTERFACE Interface =
        IppCast(Args->NlInterface.Interface, IP_INTERFACE);

    if (Interface != NULL) {
        //
        // If the request supplies an interface handle, we are done.
        //
        IppReferenceInterface(Interface);
        return Interface;
    }

    Client =  IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);
    
    Compartment = IppGetCompartment(Client->Protocol, &Args->NlCompartment);
    if (Compartment == NULL) {
        return NULL;
    }
    
    Interface = IppFindInterfaceByIndex(Compartment, Args->NlInterface.Index);
    
    IppDereferenceCompartment(Compartment);

    return Interface;
}

PIP_INTERFACE
IppFindInterfaceByAddress(
    IN PIP_COMPARTMENT Compartment,
    IN PUCHAR Address
    )
/*++

Routine Description:
    
    Search the specified compartment for an interface given an IP address on 
        this interface.
    
Arguments:

    Compartment - Supplies the compartment to search.
        The caller must hold a reference on the compartment.

    Address - Supplies the IP address to look for.

Return Value:

    Returns the interface (with a reference), if found.  NULL, if not. The 
        caller needs to release the reference.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL. 

--*/ 
{
    PIP_INTERFACE Interface = NULL;
    PIP_LOCAL_ADDRESS LocalAddress;
    KIRQL OldIrql;
    PLIST_ENTRY Next, Head = &Compartment->InterfaceSet.Set;
    
    RtlAcquireReadLock(&Compartment->InterfaceSet.Lock, &OldIrql);
    Head = &Compartment->InterfaceSet.Set;

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Next, IP_INTERFACE, CompartmentLink);
        LocalAddress = 
            IppFindAddressOnInterface(Interface, Address);

        if (LocalAddress != NULL) {
            IppReferenceInterface(Interface);
            IppDereferenceLocalAddress(LocalAddress);
            RtlReleaseReadLock(&Compartment->InterfaceSet.Lock, OldIrql);
            return Interface;
        }
    }
    RtlReleaseReadLock(&Compartment->InterfaceSet.Lock, OldIrql);
    return NULL;
}

PIP_INTERFACE
IppGetFirstInterface(
    IN PIP_PROTOCOL Protocol
    )
{
    KIRQL OldIrql;
    PLIST_ENTRY Next, Head = &Protocol->GlobalInterfaceSet.Set;
    PIP_INTERFACE Interface = NULL;
    
    RtlAcquireReadLock(&Protocol->GlobalInterfaceSet.Lock, &OldIrql);
    {
        Next = Head->Flink;
        if (Next != Head) {
            Interface = (PIP_INTERFACE)
                CONTAINING_RECORD(Next, IP_INTERFACE, GlobalLink);
            
            IppReferenceInterface(Interface);
        }
    }
    RtlReleaseReadLock(&Protocol->GlobalInterfaceSet.Lock, OldIrql);

    return Interface;
}


PIP_INTERFACE
IppGetNextInterface(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *Luid
    )
{
    KIRQL OldIrql;
    PLIST_ENTRY Next, Head = &Protocol->GlobalInterfaceSet.Set;
    PIP_INTERFACE Interface, Found = NULL;

    RtlAcquireReadLock(&Protocol->GlobalInterfaceSet.Lock, &OldIrql);
    {
        //
        // Look for the first interface with a LUID greater than that
        // supplied. 
        //
        for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
            Interface = (PIP_INTERFACE)
                CONTAINING_RECORD(Next, IP_INTERFACE, GlobalLink);
            
            if (memcmp(&Interface->Luid, Luid, sizeof(IF_LUID)) > 0) {
                Found = Interface;
                IppReferenceInterface(Found);
                break;
            }
        }
    }
    RtlReleaseReadLock(&Protocol->GlobalInterfaceSet.Lock, OldIrql);

    return Found;
}
    

PIP_INTERFACE
IppGetInterface(
    IN PIP_COMPARTMENT Compartment,
    IN PNL_INTERFACE_ARG Args
    )
{
    PIP_INTERFACE Interface;

    if (Args->Interface != NULL) {
        Interface = IppCast(Args->Interface, IP_INTERFACE);
        IppReferenceInterface(Interface);
    } else if (Args->Index != IFI_UNSPECIFIED) {
        Interface = IppFindInterfaceByIndex(Compartment, Args->Index);
    } else {
        Interface = NULL;
    }

    return Interface;
}


ULONG
IppGetInterfaceScopeZone(
    IN CONST IP_INTERFACE *Interface,
    IN SCOPE_LEVEL Level
    )
/*++

Routine Description:
    
    Determine the zone id, for a given level, in which an interface
    resides. This function returns the internal scope zone. 
    
Arguments:

    Interface - Supplies the interface in question.

    Level - Supplies the scope level for which to find the zone id.

Return Value:

    Zone Identifier.
    
Caller LOCK: May be called with no locks held.  To guarantee consistency, the
    caller should hold at least a read lock on the protocol's ZoneUpdateLock.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    return IppGetInterfaceScopeZoneInline(Interface, Level);
}

VOID
IppLogMediaSenseEvent(
    IN PIP_INTERFACE Interface, 
    IN ULONG EventCode
    )
/*++

Routine Description:

    This routine logs a media sense event on an interface. 
    
Arguments:

    Interface - Supplies the interface.

    EventCode - Supplies the event.

Return Value:

    None.

--*/ 
{
    NTSTATUS Status;
    PIO_ERROR_LOG_PACKET ErrorLogEntry;
    NDIS_IF_COUNTED_STRING Alias;
    NET_LUID Key = Interface->Luid;
    CONST WCHAR Ellipses[] = L"...";
    PWCHAR TerminatePosition, EndPosition, Str;
    SIZE_T EllipsesLength, EndSize;
    
    //
    // We can store part of the string in DumpData because it is unused.
    // This makes maximum use of the limited size of ERROR_LOG_MAXIMUM_SIZE.
    //
    USHORT MaxLength = 
        ((ERROR_LOG_MAXIMUM_SIZE - sizeof(IO_ERROR_LOG_PACKET) + 
          RTL_FIELD_SIZE(IO_ERROR_LOG_PACKET, DumpData)) & 0xFFFFFFFC);
        
    Status =
        NsiGetParameter(
            NsiActive,
            &NPI_MS_NDIS_MODULEID,
            NdisNsiObjectInterfaceInformation,
            &Key, sizeof(Key),
            NsiStructRw,
            &Alias, sizeof(NDIS_IF_COUNTED_STRING),
            FIELD_OFFSET(NDIS_NSI_INTERFACE_INFORMATION_RW, ifAlias));
    if (!NT_SUCCESS(Status)) {
        return;
    }

    //
    // Null terminate the string. 
    //
    // Alias.String always has one extra WCHAR left for the null-terminator,
    // and Alias.Length does not include the null-terminator.
    //
    ASSERT(RTL_NUMBER_OF(Alias.String) == NDIS_IF_MAX_STRING_SIZE + 1);    
    ASSERT(Alias.Length <= NDIS_IF_MAX_STRING_SIZE * sizeof(WCHAR));
    
    Alias.String[Alias.Length / sizeof(WCHAR)] = L'\0';
    
    if (Alias.Length > MaxLength) {
        //
        // We want to keep the first word and truncate after it. 
        //
        EllipsesLength = wcslen(Ellipses) * sizeof(WCHAR);
        TerminatePosition = wcschr(Alias.String, L' ');

        if ((TerminatePosition == NULL) ||
            (TerminatePosition + EllipsesLength / sizeof(WCHAR) >= 
             Alias.String + MaxLength / sizeof(WCHAR))) {
            
            Alias.String[MaxLength / sizeof(WCHAR)] = L'\0';
            Alias.Length = MaxLength;
            
            memcpy(Alias.String + 
                   ((MaxLength - EllipsesLength) / sizeof(WCHAR)),
                   Ellipses, 
                   sizeof(Ellipses));
        } else {
            //
            // Add ellipses.  The check above guarantees that we do not
            // overflow.
            //
            memcpy(
                TerminatePosition, Ellipses, sizeof(Ellipses));
            TerminatePosition += EllipsesLength / sizeof(WCHAR);
            
            //
            // We have to scrap Alias.Length - MaxLength number of bytes from
            // the original buffer.  Skip these many bytes from the current
            // position and copy the rest of the string to the final string.
            //
            EndPosition = TerminatePosition + 
                (Alias.Length - MaxLength) / sizeof(WCHAR);
            
            Str = wcschr(EndPosition, L' ');
            if (Str != NULL) {
                EndPosition = Str + 1;
            }

            //
            // The size of the end piece is the size of the original alias
            // including null terminator minus the size of the characters we're
            // skipping.
            //
            EndSize = (Alias.Length + sizeof(WCHAR)) -
                      ((EndPosition - Alias.String) * sizeof(WCHAR));
            
            //
            // REVIEW: This might be copying over overlapping buffer.
            //
            memcpy(TerminatePosition, EndPosition, EndSize);
            Alias.Length = (USHORT) wcslen(Alias.String) * sizeof(WCHAR);
        }
    } 
    
    //
    // Allocate an error log entry.  Add the size of the log packet to the
    // alias string and it's NULL terminator.  Part of the string is stored
    // in IO_ERROR_LOG_PACKET::DumpData so we can subtract that from the size
    // calculation.
    //
    ErrorLogEntry =
        IoAllocateErrorLogEntry(
            IppDeviceObject, 
            (UCHAR)
            (Alias.Length + sizeof(WCHAR) + sizeof(IO_ERROR_LOG_PACKET) - 
             RTL_FIELD_SIZE(IO_ERROR_LOG_PACKET, DumpData)));
    if (ErrorLogEntry == NULL) {
        return;
    }
    
    ErrorLogEntry->UniqueErrorValue = 2;
    ErrorLogEntry->ErrorCode = EventCode;
    ErrorLogEntry->NumberOfStrings = 1;
    ErrorLogEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET) - 
        RTL_FIELD_SIZE(IO_ERROR_LOG_PACKET, DumpData);
    ErrorLogEntry->DumpDataSize = 0;

    memcpy(((PUCHAR)ErrorLogEntry + ErrorLogEntry->StringOffset), 
           Alias.String, Alias.Length);
    
    IoWriteErrorLogEntry(ErrorLogEntry);
}

VOID
IppNotifyInterfaceChangeAtPassive(
    IN PVOID Context
    )
/*++

Routine Description:

    Notify clients of a change in the connected state of an interface.

Arguments:
    Relevant fields of Context:
    
    Object - Supplies an interface to notify clients about.

    NotificationType - Supplies the type of notification we will make to NSI.
    
    EventCode - Supplies EVENT_TCPIP_MEDIA_CONNECT if the media 
        sense state of the interface changed. Supplies 0 otherwise.
    
Locks:

    Must be called with no locks held.
    Assumes caller holds a reference on the interface, which we free.
    Assumes caller holds a reference on the NSI notification context, which
    we free before returning.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem = 
        (PIP_NOTIFICATION_WORK_QUEUE_ITEM) Context;
    NM_INDICATE_PARAMETER_CHANGE NsiArgs;
    NL_INTERFACE_KEY Key;
    PIP_INTERFACE Interface = (PIP_INTERFACE) WorkItem->Object;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PNMP_CLIENT_CONTEXT ClientContext = Protocol->NmClientContext;
    PNMP_NOTIFICATION_CONTEXT NotificationContext = 
        &ClientContext->InterfaceNotificationContext;
    ULONG ConnectedSubInterfaces;

    PASSIVE_CODE();

    if (!Protocol->DisableMediaSenseEventLog && (WorkItem->EventCode != 0)) {
        IppLogMediaSenseEvent(Interface, WorkItem->EventCode);
    }

    //
    // WorkerQueue is serialized so we don't need to get a lock here.
    //

    ConnectedSubInterfaces = Interface->ConnectedSubInterfaces;

    //
    // Notify NSI clients regardless of the state of the interface.
    //
    // To call NSI, we have to first reference the NSI attachment to
    // see if the client context is valid.  If it is, we then
    // reference the notification registration.  This prevents
    // deregistration from completing until we're done.
    //
    if (RoReference(&Protocol->NmClientReferenceObject)) {
        //
        // Take a reference on the notification registration.
        // This prevents deregistration from completing until we're done.
        //
        if (RoReference(&NotificationContext->ReferenceObject)) {
            RtlZeroMemory(&NsiArgs, sizeof(NsiArgs));
            NsiArgs.ProviderHandle = ClientContext->Npi.ProviderHandle;
            NsiArgs.ObjectIndex = NlInterfaceObject;
            
            NsiArgs.KeyStructDesc.KeyStruct = (PUCHAR) &Key;
            Key.Luid = Interface->Luid;
            NsiArgs.KeyStructDesc.KeyStructLength = sizeof(Key);
            NsiArgs.NotificationType = WorkItem->NotificationType;

            //
            // ParameterDescription is all zero, typically if multiple 
            // parameters changed or its an add/delete notification. 
            // In that case, the client should query down to see what changed.
            //

            NsiArgs.ParamDesc = WorkItem->ParameterDescription;
            
            ClientContext->Npi.Dispatch->ParameterChange(&NsiArgs);
            
            if (RoDereference(&NotificationContext->ReferenceObject)) {
                KeSetEvent(
                    &NotificationContext->DeregisterCompleteEvent, 
                    0, 
                    FALSE);
            }
        }
        IppDereferenceNsiClientContext(Protocol);
    }

    //
    // Inform all network layer clients about interface update.
    // As the interface update happens at dispatch, this notification is made 
    // in a worker thread.
    //
    if (WorkItem->NotificationType == NsiParameterNotification) {
        IppNotifyInterfaceChangeToNlClients(Interface, IpUpdateInterfaceEvent);
    }
    
    IppDereferenceInterface(Interface);
    ExFreePoolWithTag(WorkItem, IpGenericPoolTag);
}

VOID
IppNotifyInterfaceChange(
    IN PIP_INTERFACE Interface, 
    IN ULONG EventCode,
    IN NSI_NOTIFICATION NotificationType,
    IN OPTIONAL PNSI_SINGLE_PARAM_DESC ParameterDescription
    )
/*++

Routine Description:

    Tell clients about the current status of an interface.
    We queue up a work item which calls IppNotifyInterfaceChangeAtPassive.

Arguments:

    Interface - Supplies the interface to notify clients about.

    EventCode - Supplies EVENT_TCPIP_MEDIA_CONNECT if the media 
        sense state of the interface changed. Supplies 0 otherwise.

    NotificationType - Supplies the type of notification we will make to NSI. 

    ParameterDescription - Supplies the parameter that changed.

Locks:

    Assumes caller holds at least a reference on the interface.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_NOTIFICATION_WORK_QUEUE_ITEM WorkItem;

    //
    // Even if we're at passive, queue a work item.  This is because
    // the notification may take a long period of time, and we don't
    // want to hold up interface addition.
    //
    WorkItem = 
        ExAllocatePoolWithTag(
            NonPagedPool, sizeof *WorkItem, IpGenericPoolTag);

    if (WorkItem != NULL) {
        RtlZeroMemory(WorkItem, sizeof(*WorkItem));
        WorkItem->WorkerRoutine = IppNotifyInterfaceChangeAtPassive;
        WorkItem->Object = Interface;
        WorkItem->EventCode = EventCode;
        WorkItem->NotificationType = NotificationType;
        if (ParameterDescription != NULL) {
            WorkItem->ParameterDescription = *ParameterDescription;
        } 
        IppReferenceInterface(Interface);    
        NetioInsertWorkQueue(
            &Interface->Compartment->WorkQueue, 
            &WorkItem->Link);
    }
}

VOID
IppUpdateZoneIndices(
    IN PIP_INTERFACE Interface,
    IN UNALIGNED ULONG *ZoneIndices
    )
/*++

Routine Description:

    Helper function for updating zone indices on an interface.
    Compare UpdateZoneIndices() in the XP IPv6 stack.

Arguments:

    Interface - Supplies a pointer to the interface to update.

    ZoneIndices - Supplies an array of 16 zone indices (not full scope ids).

Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.
    
--*/
{
    SCOPE_LEVEL Level;
    BOOLEAN SiteIdChanged, LinkIdChanged;
    PVOID Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    LinkIdChanged =
        ((ZoneIndices[ScopeLevelLink] != (ULONG) -1) &&
         (ZoneIndices[ScopeLevelLink] != Interface->ZoneIndices[0].Zone));
    SiteIdChanged =
        ((ZoneIndices[ScopeLevelSite] != (ULONG) -1) &&
         (ZoneIndices[ScopeLevelSite] !=
          Interface->ZoneIndices[ScopeLevelSite - ScopeLevelLink].Zone));

    for (Level = ScopeLevelLink; Level < ScopeLevelGlobal; Level++) {
        ULONG Index = Level - ScopeLevelLink;
        if (ZoneIndices[Level] != (ULONG) -1) {
            Interface->ZoneIndices[Index].Level = Level;
            Interface->ZoneIndices[Index].Zone = ZoneIndices[Level];
       }            
    }

    //
    // The following checks are just optimizations to avoid the for loop
    // and to avoid unnecessarily queueing work items.
    //
    if ((Interface->ConnectedSubInterfaces == 0) ||
        (!LinkIdChanged && !SiteIdChanged)) {
        return;
    }

    //
    // Invalidate the destination cache.  Since the zone indices have changed,
    // some paths might have become invalid. 
    //
    IppInvalidateDestinationCache(Interface->Compartment);
    
    //
    // Notify NSI clients that the interface has been reconnected to
    // a new zone.
    //
    IppNotifyInterfaceChange(Interface, 0, NsiParameterNotification, NULL);

    //
    // Media is connected and the scope id has changed for unicast addresses.
    // We need to inform NL clients of the change in any relevant addresses.
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

        ASSERT(NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast);

        if (((NL_ADDRESS_SCOPE_LEVEL(LocalAddress) == ScopeLevelLink) && 
             LinkIdChanged) ||
            ((NL_ADDRESS_SCOPE_LEVEL(LocalAddress) == ScopeLevelSite) &&
             SiteIdChanged)) {
            NL_ADDRESS_SCOPE_ZONE(LocalAddress) = 
                IppGetInterfaceScopeZone(
                    Interface, NL_ADDRESS_SCOPE_LEVEL(LocalAddress));
            if (LocalAddress->DadState == NldsPreferred) {
                //
                // Queue worker to tell clients that this address has changed.
                //
                IppNotifyAddressChange(LocalAddress, NsiParameterNotification);
            }
        }
    }
}

BOOLEAN
IppIsInterfaceInScope(
    IN PIP_INTERFACE Interface,
    IN SCOPE_ID ScopeId
    )
/*++

Routine Description:
    
    Test whether an interface is within a given scope zone.
    
Arguments:

    Interface - Supplies the interface in question.

    ScopeId - Supplies the scope identifier.

Return Value:

    TRUE if interface is within the specified scope, FALSE if not.

Caller LOCK: May be called with no locks held.  To guarantee consistency, the
    caller should hold at least a read lock on the protocol's ZoneUpdateLock.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ASSERT(ScopeId.Value != 0);
    
    //
    // The scope zone is unspecified.  The caller does not know the interface
    // on which the address is.  So, match all interfaces. 
    //
    if (ScopeId.Zone == 0) {
        return TRUE;
    }
    
    if (ScopeId.Level <= ScopeLevelInterface) {
        return (ScopeId.Zone == (ULONG) Interface->Index);
    }

    if (ScopeId.Level >= ScopeLevelGlobal) {
        return TRUE;
    }

    return (ScopeId.Value ==
            Interface->ZoneIndices[ScopeId.Level - ScopeLevelLink].Value);
}

PIP_INTERFACE
IppFindDefaultInterfaceForZone(
    IN PIP_COMPARTMENT Compartment,
    IN SCOPE_ID ScopeId
    )
/*++

Routine Description:
    
    Given a scope level and a zone index, find the default interface belonging
    to the specified zone.  The default interface is the one that we assume
    destinations in the zone are on-link to, if there are no routes matching
    the destination.
  
Arguments:

    Compartment - Supplies the compartment in question.

    ScopeId - Supplies the scope level and zone index.  It is an error for the
        zone index to be zero, unless all our interfaces are in the same zone
        at that scope level.  In this case zero (meaning unspecified) is
        actually not ambiguous.
    
Return Value:

    The default interface is returned as NULL upon failure,
    and with a reference upon success.

Locks:

    Assumes caller holds a reference on the compartment.
    Locks the compartment's interface set for reading.

Caller IRQL: 

    Must be called at DISPATCH level.
  
--*/
{
    PIP_INTERFACE FirstInterface = NULL;
    PIP_INTERFACE FoundInterface = NULL;
    PIP_INTERFACE Interface;
    PLIST_ENTRY Next, Head = &Compartment->InterfaceSet.Set;

    //
    // Start by assuming the ScopeId is invalid.
    // We will return this status value if we find no interface with the
    // specified ScopeId, or if ScopeId is zero and that is ambiguous.
    //

    RtlAcquireReadLockAtDpcLevel(&Compartment->InterfaceSet.Lock);

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Next, IP_INTERFACE, CompartmentLink);

        //
        // Skip disconnected interfaces.
        //
        if (Interface->ConnectedSubInterfaces == 0) {
            continue;
        }            

        //
        // Skip loopback interfaces.
        //
        if (IS_LOOPBACK_INTERFACE(Interface)) {
            continue;
        }

        if (ScopeId.Zone == 0) {
            //
            // Do we have interfaces in two zones at this scope level? 
            //
            if (FirstInterface == NULL) {
                FirstInterface = Interface;
            } else if (IppGetInterfaceScopeZone(
                           Interface, ScopeId.Level) != 
                       IppGetInterfaceScopeZone(
                           FirstInterface, ScopeId.Level)) {
                //
                // Stop now with an error.
                //
                ASSERT(FoundInterface != NULL);
                IppDereferenceInterface(FoundInterface);
                FoundInterface = NULL;
                break;
            } 
        }

        //
        // Can we potentially use this interface?
        //
        if ((ScopeId.Zone == 0) ||
            (ScopeId.Zone ==
             IppGetInterfaceScopeZone(Interface, ScopeId.Level))) {

            if (FoundInterface == NULL) {
FoundInterface:
                IppReferenceInterface(Interface);
                FoundInterface = Interface;
            } else {
                //
                // Is this new interface better than the previous one?
                //
                if (Interface->Metric < FoundInterface->Metric) {
                    IppDereferenceInterface(FoundInterface);
                    goto FoundInterface;
                }
            }
        }
    }

    RtlReleaseReadLockFromDpcLevel(&Compartment->InterfaceSet.Lock);

    return FoundInterface;
}

VOID
IppStartNud(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is not currently using neighbor unreachability detection,
    makes it start doing so.
    
Arguments:

    Interface - Supplies the interface to start doing NUD on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if (!Interface->UseNeighborUnreachabilityDetection) {
        Interface->UseNeighborUnreachabilityDetection = TRUE;
        
        //
        // Neighbor Discovery uses the NUD flag, hence any change in this
        // behavior requires us to reset the neighbor cache.
        //
        IppResetNeighborsAtDpc(Interface, NULL, FALSE);
    }
}


VOID
IppStopNud(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is currently using neighbor unreachability detection,
    makes it stop doing so.
    
Arguments:

    Interface - Supplies the interface to stop doing NUD on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if (Interface->UseNeighborUnreachabilityDetection) {
        Interface->UseNeighborUnreachabilityDetection = FALSE;
        
        //
        // Neighbor Discovery uses the NUD flag, hence any change in this
        // behavior requires us to reset the neighbor cache.
        //
        IppResetNeighborsAtDpc(Interface, NULL, FALSE);
    }
}


VOID
IppStartForwarding(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is not currently forwarding, makes it start forwarding.
    
Arguments:

    Interface - Supplies the interface to start forwarding on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if (!Interface->Forward) {
        //
        // FindNextHop uses the Forward flag, hence any change in forwarding
        // behavior requires us to invalidate the destination cache. Also force
        // the next Router Advertisement for all advertising interfaces to be
        // sent quickly, their content might depend on forwarding behavior.
        //
        Interface->Forward = TRUE;
        IppInvalidateDestinationCache(Compartment);
        Compartment->ForceRouterAdvertisement = TRUE;
    }
}


VOID
IppStopForwarding(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is currently forwarding, makes it stop forwarding.
    
Arguments:

    Interface - Supplies the interface to stop forwarding on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if (Interface->Forward) {
        //
        // FindNextHop uses the Forward flag, hence any change in forwarding
        // behavior requires us to invalidate the destination cache. Also force
        // the next Router Advertisement for all advertising interfaces to be
        // sent quickly, their content might depend on forwarding behavior.
        //
        Interface->Forward = FALSE;
        IppInvalidateDestinationCache(Compartment);
        Compartment->ForceRouterAdvertisement = TRUE;
    }
}

VOID
IppStartMulticastForwarding(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is not currently forwarding multicast traffic, makes it 
    start forwarding.
    
Arguments:

    Interface - Supplies the interface to start multicast forwarding on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{   
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if (!Interface->ForwardMulticast) {
        //
        // Enable receiving multicast promiscuous also.
        //
        Interface->ForwardMulticast = TRUE;
        //
        // FUTURE-2005/08/05-sgarg - Provide a completion routine and handle 
        // scenario if adding promiscuous filter fails.
        //
        IppAddFlAllMulticastReferenceUnderLock(Interface, NULL, NULL);
    }
}

VOID
IppStopMulticastForwarding(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is currently forwarding multicast traffic, makes it stop 
    forwarding.
    
Arguments:

    Interface - Supplies the interface to stop multicast forwarding on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if (Interface->ForwardMulticast) {
        //
        // Disable receiving multicast promiscuous also.
        //
        Interface->ForwardMulticast = FALSE;
        IppRemoveFlAllMulticastReferenceUnderLock(Interface, NULL, NULL);
    }
}

VOID
IppUpdateInterfaceConfigurationFlags(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN ManagedAddressConfigurationSupported,
    IN BOOLEAN OtherStatefulConfigurationSupported
    )
/*++

Routine Description:

    Update Managed Address and Other Stateful configuration flags of the 
    interface.
    
Arguments:

    Interface - Supplies the interface.

    ManagedAddressConfigurationSupported - Supplies TRUE or FALSE.

    OtherStatefulConfigurationSupported - Supplies TRUE or FALSE.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    BOOLEAN Notify = FALSE; 

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    if ((ManagedAddressConfigurationSupported != (BOOLEAN) -1) && 
        (ManagedAddressConfigurationSupported != 
            Interface->ManagedAddressConfiguration)) {
        Interface->ManagedAddressConfiguration =
            ManagedAddressConfigurationSupported;
        Notify = TRUE;

        Interface->Compartment->ForceRouterAdvertisement = TRUE;        
    }

    if ((OtherStatefulConfigurationSupported != (BOOLEAN) -1) && 
        (OtherStatefulConfigurationSupported != 
            Interface->OtherStatefulConfiguration)) {
        Interface->OtherStatefulConfiguration =
            OtherStatefulConfigurationSupported;
        Notify = TRUE;

        Interface->Compartment->ForceRouterAdvertisement = TRUE;        
    }

    if (Notify) {    
        IppNotifyInterfaceChange(Interface, 0, NsiParameterNotification, NULL);
    }
}

VOID
IppUpdateInterface(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN Advertise,
    IN BOOLEAN AdvertiseDefaultRoute,
    IN BOOLEAN ManagedAddressConfigurationSupported,
    IN BOOLEAN OtherStatefulConfigurationSupported,
    IN BOOLEAN Forward,
    IN BOOLEAN WeakHostSend,
    IN BOOLEAN WeakHostReceive,
    IN BOOLEAN ForwardMulticast,
    IN BOOLEAN UseNud,
    IN BOOLEAN RandomizeIdentifier
    )
/*++

Routine Description:

    Alter the advertising and forwarding attributes of an interface.

    Use (BOOLEAN) -1 for properties that should not be updated.
    
Arguments:

    Interface - Supplies the interface to update.

    Advertise - Supplies TRUE if the interface should advertise, FALSE o/w.

    AdvertiseDefaultRoute - Supplies TRUE if the interface should advertise
       itself as a default router regardless of whether the node has a default
       route itself, FALSE o/w.

    ManagedAddressConfigurationSupported - Supplies TRUE or FALSE.

    OtherStatefulConfigurationSupported - Supplies TRUE or FALSE.

    Forward - Supplies TRUE if the interface should forward, FALSE o/w.

    WeakHostSend - Supplies TRUE to enable weak host sends, FALSE o/w.

    WeakHostReceive - Supplies TRUE to enable weak host receives, FALSE o/w.

    ForwardMulticast - Supplies TRUE if the interface should forward multicast,
        FALSE o/w.
        
    UseNud - Supplies TRUE if the interface should use NUD, FALSE o/w.

    RandomizeIdentifier - Supplies TRUE if the identifier should be randomized,
        FALSE o/w.
    
Return Value:

    None.
    
Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;    

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    Interface->UseRouterDiscovery = IppIsRouterDiscoveryEnabled(Interface);
    
    //
    // Control the advertising behavior of the interface.
    // This can only be done on interfaces that support Router Discovery.
    //
    if (Interface->UseRouterDiscovery && (Advertise != (BOOLEAN) -1)) {
        if (Advertise) {
            //
            // Become an advertising interface, if we are not one already.
            //
            Protocol->StartAdvertising(Interface);
        } else {
            //
            // Stop being an advertising interface, if we are one currently.
            //
            Protocol->StopAdvertising(Interface);
        }
    }    

    if ((AdvertiseDefaultRoute != (BOOLEAN) -1) &&
        (Interface->AdvertiseDefaultRoute != AdvertiseDefaultRoute)) {

        Interface->AdvertiseDefaultRoute = AdvertiseDefaultRoute;

        Interface->Compartment->ForceRouterAdvertisement = TRUE;
    }
    
    //
    // The "managed address config" and "other stateful config" flags
    // can not be set on interfaces using router discovery to discover these.
    //
    if (!Interface->UseRouterDiscovery || Interface->Advertise) {
        IppUpdateInterfaceConfigurationFlags(
            Interface,
            ManagedAddressConfigurationSupported,
            OtherStatefulConfigurationSupported);
    }    
    
    //
    // Control the forwarding behavior of the interface.
    //
    if (Forward != (BOOLEAN) -1) {
        if (Forward) {
            //
            // If the interface is not currently forwarding, enable forwarding.
            //
            IppStartForwarding(Interface);
        } else {
            //
            // If the interface is currently forwarding, disable forwarding.
            //
            IppStopForwarding(Interface);
        }

        //
        // Notify clients that the forwarding setting
        // of the interface has changed.
        //
        IppNotifyInterfaceChange(Interface, 0, NsiParameterNotification, NULL);
    }

    //
    // Control the weak host send and receive behaviors of the interface.    
    // Any change to the weak host send behavior requires invalidation of the
    // destination cache because it affects the results of RouteToDestination.
    //
    if (WeakHostSend != (BOOLEAN) -1) {
        if (WeakHostSend) {
            if (!Interface->WeakHostSend) {
                Interface->WeakHostSend = TRUE;
                IppInvalidateDestinationCache(Interface->Compartment);
            }
        } else {
            if (Interface->WeakHostSend) {
                Interface->WeakHostSend = FALSE;
                IppInvalidateDestinationCache(Interface->Compartment);
            }
        }
    }

    if (WeakHostReceive != (BOOLEAN) -1) {
        Interface->WeakHostReceive = WeakHostReceive;
    }
    
    if (ForwardMulticast != (BOOLEAN) -1) {
        if (ForwardMulticast) {
            //
            // If the interface is not currently forwarding, enable forwarding.
            //
            IppStartMulticastForwarding(Interface);
        } else {
            //
            // If the interface is currently forwarding, disable forwarding.
            //
            IppStopMulticastForwarding(Interface);
        }
    }
    
    //
    // Control the Neighbor Unreachability Detection behavior of the interface.
    //
    if (UseNud != (BOOLEAN) -1) {
        if (UseNud) {
            //
            // If the interface is not currently using NUD, enable NUD.
            //
            IppStartNud(Interface);
        } else {
            //
            // If the interface is currently using NUD, disable NUD.
            //
            IppStopNud(Interface);
        }
    }

    if (RandomizeIdentifier != (BOOLEAN) -1) {
        IppUpdateInterfaceIdentifier(Interface, RandomizeIdentifier);
    }    
}


NETIO_INLINE
VOID    
IppUpdateNetworkCategoryState(
    IN PIP_INTERFACE Interface,
    IN NL_NETWORK_CATEGORY NetworkCategory
    )
/*++

Routine Description:

    Alter the "Network Category State" of an interface.

    If the second parameter "NetworkCategory" is -1, then there is no change
    to this state.

    This information is provided by the Network Location  Awareness (NLA)
    service through the NSI set call on  the NlInterfaceObject.
    
Arguments:

    Interface - Supplies the interface to update.

    NetworkCategory - Enumeration identifying type of network connected to by
        the interface.  Supplies -1 to indicate no change.

Return Value:

    None.
    
Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    if (NetworkCategory != NetworkCategoryUnchanged) {
        NSI_SINGLE_PARAM_DESC ParameterDescription = {
            NsiStructRw,
            NULL,
            0,
            FIELD_OFFSET(NL_INTERFACE_RW, NetworkCategory)};

        ASSERT(Interface->NetworkCategory <= NlincCategoryStateMax);

        if (NetworkCategory == NetworkCategoryDomainAuthenticated) {
            Interface->NetworkCategory = NlincDomainAuthenticated;
        }
        else if (NetworkCategory == NetworkCategoryPrivate) {
            Interface->NetworkCategory = NlincPrivate;
        }
        else if (NetworkCategory == NetworkCategoryPublic) {
            Interface->NetworkCategory = NlincPublic;
        }
        else {
            //
            // Invalid setting, don't change the category
            //
            return;
        }

        IppNotifyInterfaceChange(
            Interface,
            0,
            NsiParameterNotification,
            &ParameterDescription);
    }
}

//
// Automatic metric routines.
//

typedef struct _IP_SPEED_METRIC {
    ULONG DefaultMetric;
    ULONG64 MinimumSpeed;
} IP_SPEED_METRIC, *PIP_SPEED_METRIC;

IP_SPEED_METRIC IpSpeedMetric[] = {
    {  5, 2000000000 },         // Speed >= 2 Gbps.
    { 10,  200000000 },         // 200 Mbps <= Speed < 2 Gbps.
    { 20,   80000000 },         // 80 Mbps <= Speed < 200 Mbps.
    { 25,   20000000 },         // 20 Mbps <= Speed < 80 Mbps.
    { 30,    4000000 },         // 4 Mbps <= Speed < 20 Mbps.
    { 40,     500000 },         // 500 Kbps <= Speed < 4 Mbps.
    { 50,          0 },         // Speed < 500 Kbps.
};

ULONG
IppGetAutoMetric(
    ULONG64 Speed
    )
/*++

Routine Description:

    Get the corresponding metric of a speed value.  

    Compare GetAutoMetric in the XP IPv4 stack.

Arguments:

    Speed - Supplies the speed of a subinterface, in bits per second.

Return Value:

    Returns the default metric value to use.

--*/
{
    ULONG i;

    //
    // The last entry in the above table must be 0, which ensures this
    // loop will terminate.
    //
    for (i = 0; ; i++) {
        if (Speed >= IpSpeedMetric[i].MinimumSpeed) {
            return IpSpeedMetric[i].DefaultMetric;
        }
    }
}

VOID
IppRecomputeMetric(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Recompute the metric for an interface using automatic metrics,
    based on the characteristics of the subinterfaces.

    We use the average metric for all subinterfaces.

Arguments:

    Interface - Supplies a pointer to the interface to update.

Locks:

    Assumes caller holds a write lock on the interface, protecting
    the AutoMetric and Metric fields.

    Assumes caller holds at least a read lock on the interface's
    NeighborSetLock, protecting the subinterface set.

Caller IRQL:

    Must be called DISPATCH since a lock is held.

--*/
{
    ULONG Metric, Total = 0;
    ULONG SubInterfaceCount = 0;
    PLIST_ENTRY Current, Head;
    PIP_SUBINTERFACE SubInterface;
    ULONG64 LinkSpeed;

    //
    // Wireless interfaces ideally should report themselves as half-duplex. In 
    // case some dont, we have additional check.
    //
    BOOLEAN HalfDuplex = 
        ((Interface->FlCharacteristics->MediaDuplexState == 
             MediaDuplexStateHalf) || 
         (Interface->FlCharacteristics->PhysicalMediumType == 
             NdisPhysicalMediumWirelessLan) || 
         (Interface->FlCharacteristics->PhysicalMediumType ==
             NdisPhysicalMediumWirelessWan) ||
         (Interface->FlCharacteristics->PhysicalMediumType ==
             NdisPhysicalMediumNative802_11));
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT_ANY_LOCK_HELD(&Interface->NeighborSetLock);
    ASSERT(Interface->AutoMetric);

    Head = &Interface->SubInterfaceSet;
    for (Current = Head->Flink; Current != Head; Current = Current->Flink) {
        SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Current, IP_SUBINTERFACE, Link);

        LinkSpeed = SubInterface->FlCharacteristics->TransmitSpeed;
        //
        // For half duplex (mostly wireless) interfaces, take effective speed 
        // as half.
        //
        if (HalfDuplex) {
            LinkSpeed = LinkSpeed >> 1;
        }
        
        Metric = IppGetAutoMetric(LinkSpeed);
        Total += Metric;
        SubInterfaceCount++;
    }

    if (SubInterfaceCount > 0) {
        Interface->Metric = Total / SubInterfaceCount;
    } else {
        Interface->Metric = 1;
    }
}

//
// Internal Sub-Interface Management Routines.
//

PIP_SUBINTERFACE
IppAllocateSubInterface(
    VOID
    )
/*++

Routine Description:

    Allocate a subinterface structure.
    
Arguments:

    None.
    
Return Value:

    Allocated SubInterface or NULL.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_SUBINTERFACE SubInterface;

    ULONG Size = sizeof(IP_SUBINTERFACE) +
        (sizeof(PIP_SUBINTERFACE_STATISTICS) * KeQueryMaximumProcessorCount());
        
    //
    // We can't use FSB here since fewer than 16 would fit in PAGE_SIZE.
    //
    SubInterface = ExAllocatePoolWithTag(NonPagedPool,
                                         Size,
                                         IpSubInterfacePoolTag);
    if (SubInterface != NULL) {
        RtlZeroMemory(SubInterface, Size);
        
        SubInterface->PerProcessorStatistics =
            (PIP_SUBINTERFACE_STATISTICS *)(SubInterface + 1);
    }
    return SubInterface;
}


__inline
VOID
IppCleanupSubInterfaceWorkerRoutine(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    Cleanup and destroy a subinterface structure.

    We queue a worker thread so we can notify the framing layer provider
    of delete completion without holding any locks and at PASSIVE IRQL.

Arguments:

    DeviceObject - Supplies a pointer to the device object.

    Context - Supplies the subinterface in question.

Return Value:

    None.

Caller IRQL: PASSIVE_LEVEL

--*/
{
    FL_REQUEST_COMPLETE Request = {0};
    ULONG i = 0;
    ULONG NumMaxProcessors;
    
    PIP_SUBINTERFACE SubInterface = IppCast(Context, IP_SUBINTERFACE);


    
    PASSIVE_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);
    
    //
    // Indicate delete completion to the framing layer provider if required.
    // The delete complete handler can be NULL if the sub-interface is getting
    // deleted because of initialization failure. 
    //
    if (SubInterface->FlDeleteComplete != NULL) {
        Request.ProviderObjectHandle = SubInterface->FlContext;
        Request.Status = STATUS_SUCCESS;
        (SubInterface->FlDeleteComplete)(&Request);
    }
    
    IoFreeWorkItem(SubInterface->WorkItem);

    IppDereferenceInterface(SubInterface->Interface);
    //
    // Initialize the uninitialized per proc structures to point to NULL
    // TODO: Clean this up when we fix the incorrect per proc
    // statistics bug.
    //    
    NumMaxProcessors = KeQueryMaximumProcessorCount();
    for (i = 1; i < NumMaxProcessors; i++) {
        if (SubInterface->PerProcessorStatistics[i] == 
            SubInterface->PerProcessorStatistics[0]) {
            SubInterface->PerProcessorStatistics[i] = NULL;
        }
    }
    
    NetioFreeOpaquePerProcessorContext(
        SubInterface->PerProcessorStatistics, 
        NULL);

    ExFreePool((PUCHAR) SubInterface);
}


VOID
IppCleanupSubInterface(
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    Cleanup and destroy a subinterface structure.
    
Arguments:

    SubInterface - Supplies the interface to cleanup.
    
Return Value:

    None.
    
Caller LOCK: None.
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ASSERT(SubInterface->ReferenceCount == 0);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        IoQueueWorkItem(SubInterface->WorkItem,
                        IppCleanupSubInterfaceWorkerRoutine,
                        DelayedWorkQueue,
                        (PVOID) SubInterface);
    } else {
        IppCleanupSubInterfaceWorkerRoutine(IppDeviceObject,
                                            (PVOID) SubInterface);
    }
}

VOID
IppInsertSubInterfaceInSet(
    IN PNLI_SET SubInterfaceSet, 
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    Inserts the subinterface into the ordered list.

Arguments:

    SubInterfaceSet - Supplies the the set where to insert the SubInterface.

    SubInterface - New SubInterface to be inserted in the set.

Return Value:

    none.

Locks:

    Caller holds the neighbor set lock. 

Caller IRQL: 

    DISPATCH_LEVEL since the lock is held.

--*/
{
    PLIST_ENTRY Next, Head = SubInterfaceSet;
    PIP_SUBINTERFACE CurrSubInterface;

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        CurrSubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Next, IP_SUBINTERFACE, Link);

        if (memcmp(&CurrSubInterface->Luid, 
                   &SubInterface->Luid, 
                   sizeof(SubInterface->Luid)) > 0) {
            break;
        }
    }

    InsertTailList(Next, &SubInterface->Link);
}

PIP_SUBINTERFACE
IppCreateSubInterface(
    IN PIP_INTERFACE Interface,
    IN CONST FL_INTERFACE_IDENTIFIERS *Identifiers,
    IN CONST FL_SUBINTERFACE_CHARACTERISTICS *Characteristics,
    IN CONST NL_SUBINTERFACE_RW *SubInterfaceRw,
    IN PVOID FlContext,
    OUT BOOLEAN *FirstSubInterface
    )
/*++

Routine Description:

    Create and initialize a new subinterface structure.

Arguments:

    Interface - Supplies the interface on which to create the subinterface.
        The caller must hold a reference on the interface.

    Identifiers - Supplies the subinterface identifers.

    Characteristics - Supplies the subinterface characteristics.

    SubInterfaceRw - Supplies the subinterface's configuration information.

    FlContext - Supplies the framing layer's handle to the subinterface.
    
    FirstSubInterface - Returns TRUE iff the interface had no subinterfaces.

Return Value:

    New subinterface or NULL.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_SUBINTERFACE SubInterface;
    KLOCK_QUEUE_HANDLE LockHandle, NeighborSetLockHandle;
    
    SubInterface = IppAllocateSubInterface();
    if (SubInterface == NULL) {
        goto Error;
    }
    SubInterface->Signature = IP_SUBINTERFACE_SIGNATURE;

    SubInterface->WorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (SubInterface->WorkItem == NULL) {
        ExFreePool((PUCHAR) SubInterface);
        goto Error;
    }
    
    SubInterface->Interface = Interface;
    IppReferenceInterface(Interface);

    SubInterface->Luid = Identifiers->Luid;
    SubInterface->Index = Identifiers->Index;

    SubInterface->FlContext = FlContext;
    
    //
    // SubInterface->FlDeleteComplete = NULL;
    //

    //
    // One reference for initialization, another for the caller.
    //
    SubInterface->ReferenceCount = 2;

    SubInterface->NlMtu = SubInterfaceRw->NlMtu;
    SubInterface->FlCharacteristics = Characteristics;

    //
    // Insert subinterface into per-interface list.
    // Done last so that the subinterface is only accessed once initialized.
    //
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    RtlAcquireWriteLockAtDpcLevel(
        &Interface->NeighborSetLock, &NeighborSetLockHandle);
    {        
        ULONG i = 0;
        KAFFINITY Affinity;
        ULONG NumMaxProcessors;    
#ifndef USER_MODE
    Affinity = TcpipGetAllocatedProcessorCount();
#else
    Affinity = (1 << KeNumberProcessors) - 1;
#endif    

        if (!NT_SUCCESS(
            NetioAllocateOpaquePerProcessorContext(
                SubInterface->PerProcessorStatistics,
                sizeof(IP_SUBINTERFACE_STATISTICS),
                IpSubInterfacePoolTag,
                Affinity,
                NULL,
                NULL,
                NULL))) {

            RtlReleaseWriteLockFromDpcLevel(
                &Interface->NeighborSetLock, &NeighborSetLockHandle);
            RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
            
            ExFreePool((PUCHAR) SubInterface);                            
            goto Error;            
        }
        //
        // Initialize the uninitialized per proc structures to point to the 
        // first processor. 
        // TODO: Clean this up when we fix the incorrect per proc
        // structures.
        //
        NumMaxProcessors = KeQueryMaximumProcessorCount();
        for (i = 1; i < NumMaxProcessors; i++) {
            if (SubInterface->PerProcessorStatistics[i] == NULL) {
                SubInterface->PerProcessorStatistics[i] = 
                    SubInterface->PerProcessorStatistics[0];
            }
        }
        //
        // Initialize the operational status of the sub-interface.  It is set
        // to up if the media sense is disabled.  Also, this is done under the
        // interface lock to make sure the sub-interface operational status is
        // consistent with the DisableMediaSense state.
        // 
        SubInterface->OperationalStatus = 
            Interface->Compartment->Protocol->DisableMediaSense
            ? IfOperStatusUp
            : Characteristics->OperationalStatus;

        *FirstSubInterface = IsListEmpty(&Interface->SubInterfaceSet);

        IppInsertSubInterfaceInSet(&Interface->SubInterfaceSet, SubInterface);

        if ((Interface->MinimumNlMtu == 0) ||
            (Interface->MinimumNlMtu > SubInterface->NlMtu)) {
            Interface->MinimumNlMtu = SubInterface->NlMtu;
        }

        if (Interface->AutoMetric) {
            IppRecomputeMetric(Interface);
        }

        if (SubInterface->OperationalStatus == IfOperStatusUp) {
            Interface->ConnectedSubInterfaces++;

            if (Interface->ConnectedSubInterfaces == 1) {
                //
                // The interface has become operational, so notify clients.
                //
                NSI_SINGLE_PARAM_DESC ParameterDescription = {
                    NsiStructRoDynamic,
                    NULL,
                    sizeof(Interface->ConnectedSubInterfaces),
                    FIELD_OFFSET(NL_INTERFACE_ROD, ConnectedSubInterfaces)};
                ParameterDescription.Parameter = 
                    (PUCHAR) &Interface->ConnectedSubInterfaces;
                IppNotifyInterfaceChange(
                    Interface, 
                    EVENT_TCPIP_MEDIA_CONNECT, 
                    NsiParameterNotification,
                    &ParameterDescription);
            }
        
            //
            // Start router discovery if it is enabled on this interface. 
            //
            if (Interface->UseRouterDiscovery) {
                IppStartRouterDiscovery(Interface);
            }
        }
    }
    RtlReleaseWriteLockFromDpcLevel(
        &Interface->NeighborSetLock, &NeighborSetLockHandle);
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_INFORMATION,
               "IPNG: [%u] Created %s sub-interface index %u ",
               Interface->Index, 
               Interface->Compartment->Protocol->TraceString, 
               Identifiers->Index);

    return SubInterface;
Error:
    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_WARNING, 
               "IPNG: [%u] Error allocating %s sub-interface index %u\n", 
               Interface->Index,
               Interface->Compartment->Protocol->TraceString, 
               Identifiers->Index);
    return NULL;
}

PIP_SUBINTERFACE
IppFindSubInterfaceByLuid(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *InterfaceLuid,
    IN CONST IF_LUID *SubInterfaceLuid
    )
/*++

Routine Description:

    Search for a subinterface given its LUID.

Arguments:

    Protocol - Supplies the protocol state.

    InterfaceLuid - Supplies the interface LUID to look for.

    SubInterfaceLuid - Supplies the subinterface LUID on the interface.

Return Value:

    Returns the subinterface (with a reference), if found.  NULL, if not.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    KIRQL OldIrql;
    PLIST_ENTRY Next, Head;
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface, Found = NULL;

    Interface = IppFindInterfaceByLuid(Protocol, InterfaceLuid);
    if (Interface == NULL) {
        return NULL;
    }

    RtlAcquireReadLock(&Interface->NeighborSetLock, &OldIrql);

    Head = &Interface->SubInterfaceSet;
    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Next, IP_SUBINTERFACE, Link);

        if (RtlEqualMemory(&SubInterface->Luid, 
                           SubInterfaceLuid, 
                           sizeof(*SubInterfaceLuid))) {
            Found = SubInterface;
            IppReferenceSubInterface(Found);
            break;
        }
    }

    RtlReleaseReadLock(&Interface->NeighborSetLock, OldIrql);
    
    IppDereferenceInterface(Interface);

    return Found;
}

PIP_SUBINTERFACE
IppFindSubInterfaceOnInterfaceByIndexUnderLock(
    IN PIP_INTERFACE Interface,
    IN IF_INDEX SubInterfaceIndex
    )
/*++

Routine Description:

    Find the given subinterface on the specified interface.

Arguments:

    Interface - Supplies the interface on which the subinterface exists.

    SubInterfaceIndex - Supplies the subinterface's index.

Return Value:

    Returns the subinterface (with a reference), if found.  NULL, if not.
    
Locks:

    Assumes caller holds at least a read lock on the interface's
    NeighborSetLock, protecting the subinterface set.

Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PLIST_ENTRY Next, Head = &Interface->SubInterfaceSet;
    PIP_SUBINTERFACE SubInterface;

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Next, IP_SUBINTERFACE, Link);

        if (SubInterfaceIndex != SubInterface->Index) {
            continue;
        }

        //
        // We have a match.
        //
        IppReferenceSubInterface(SubInterface);
        return SubInterface;
    }

    return NULL;
}

PIP_SUBINTERFACE
IppFindSubInterfaceByIndexUnderLock(
    IN PIP_COMPARTMENT Compartment,
    IN CONST IF_INDEX InterfaceIndex,
    IN CONST IF_INDEX SubInterfaceIndex
    )
/*++

Routine Description:

    Search for a subinterface given its index.

Arguments:

    Compartment - Supplies the compartment in which to search.

    InterfaceIndex - Supplies the interface index to look for.

    SubInterfaceIndex - Supplies the subinterface index on the interface.

Return Value:

    Returns the subinterface (with a reference), if found.  NULL, if not.

Caller IRQL: DISPATCH_LEVEL (Since Compartment's InterfaceSet Lock is held).

--*/
{
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface;

    ASSERT_ANY_LOCK_HELD(&Compartment->InterfaceSet.Lock);
    
    Interface = IppFindInterfaceByIndexUnderLock(Compartment, InterfaceIndex);
    if (Interface == NULL) {
        return NULL;
    }

    RtlAcquireReadLockAtDpcLevel(&Interface->NeighborSetLock);
    SubInterface = 
        IppFindSubInterfaceOnInterfaceByIndexUnderLock(
            Interface, 
            SubInterfaceIndex);  
    RtlReleaseReadLockFromDpcLevel(&Interface->NeighborSetLock);

    IppDereferenceInterface(Interface);

    return SubInterface;
}

PIP_SUBINTERFACE
IppGetNextSubInterfaceOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST IF_LUID *SubInterfaceLuid OPTIONAL,
    PIP_SUBINTERFACE StartSubInterface OPTIONAL
    )
/*++

Routine Description:

    Find the next subinterface on the specified interface.

Arguments:

    Interface - Supplies the interface on which the subinterface exists.

    SubInterfaceLuid - Supplies the previous subinterface's LUID.
        A value of NULL would return the first subinterface after
        StartSubInterface, if that is specified and in the list - otherwise
        the head of the list.

    StartSubInterface - Supplies the subinterface, after which we will
        start the search in the list, if this subinterface is still in the list.

Return Value:

    Returns the subinterface (with a reference), if found.  NULL, if not.
    The reference on StartSubInterface, if one is supplied, is consumed
    in any case, for convenience of the iterator callers.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    KIRQL OldIrql;
    PLIST_ENTRY Next, Head = &Interface->SubInterfaceSet;
    PIP_SUBINTERFACE SubInterface = NULL;

    RtlAcquireReadLock(&Interface->NeighborSetLock, &OldIrql);

    Next = Head;

    //
    // If a starting point somewhere in the list is specified by the user,
    // try to start from there, if the item is still in the list.
    //
    if (StartSubInterface != NULL) { 
        if (!IppIsSubInterfaceDisabled(StartSubInterface)) {
            Next = &StartSubInterface->Link;
        }
    }

    for (Next = Next->Flink; Next != Head; Next = Next->Flink) {
        SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Next, IP_SUBINTERFACE, Link);

        if (SubInterfaceLuid != NULL) {
            if (memcmp(&SubInterface->Luid, 
                       SubInterfaceLuid, 
                       sizeof(*SubInterfaceLuid)) > 0) {
                break;
            }
        } else {
            break;
        }

    }

    if (Next == Head) {
        SubInterface = NULL;
    }

    if (SubInterface != NULL) {
        IppReferenceSubInterface(SubInterface);
    }

    if (StartSubInterface != NULL) {
        IppDereferenceSubInterface(StartSubInterface);
    }

    RtlReleaseReadLock(&Interface->NeighborSetLock, OldIrql);

    return SubInterface;
}


PIP_SUBINTERFACE
IppGetFirstSubInterface(
    IN PIP_PROTOCOL Protocol
    )
{
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface;
    IF_LUID Luid;

    Interface = IppGetFirstInterface(Protocol);
    while (Interface != NULL) {
        //
        // Remember the LUID in case we need it again.
        //
        Luid = Interface->Luid;

        //
        // Search for the first subinterface on this interface.
        //
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 0, NULL);

        IppDereferenceInterface(Interface);
        
        if (SubInterface != NULL) {
            return SubInterface;
        }

        //
        // If there isn't one, look at the next interface.
        //
        Interface = IppGetNextInterface(Protocol, &Luid);
    }

    return NULL;
}


PIP_SUBINTERFACE
IppGetNextSubInterface(
    IN PIP_PROTOCOL Protocol,
    IN CONST IF_LUID *InterfaceLuid,
    IN CONST IF_LUID *SubInterfaceLuid
    )
{
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface;
    IF_LUID Luid = *InterfaceLuid;

    //
    // Find the next subinterface on the specified interface.
    //
    Interface = IppFindInterfaceByLuid(Protocol, &Luid);
    if (Interface != NULL) {
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface,
                                                         SubInterfaceLuid, 
                                                         NULL);
        IppDereferenceInterface(Interface);
        if (SubInterface != NULL) {
            return SubInterface;
        }
    }

    //
    // Failing which, find the first subinterface on the next interface.
    //
    Interface = IppGetNextInterface(Protocol, &Luid);
    while (Interface != NULL) {
        //
        // Remember the LUID in case we need it again.
        //
        Luid = Interface->Luid;

        //
        // Search for the first subinterface on this interface.
        //
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 0, NULL);

        IppDereferenceInterface(Interface);

        if (SubInterface != NULL) {
            return SubInterface;
        }
        
        //
        // If there isn't one, look at the next interface.
        //        
        Interface = IppGetNextInterface(Protocol, &Luid);
    }

    return NULL;
}

VOID
IppSetInterfaceMtuAtDpc(
    IN PIP_INTERFACE Interface,
    IN ULONG NlMtu
    )
/*++

Routine Description:

    Set the MTU of all subinterfaces.  A subinterface's MTU cannot 
    be raised above its "true" MTU.

Arguments:

    Interface - Supplies the interface to set the MTU for.

    NlMtu - Supplies the network-layer MTU value to set.

Locks:

    Assumes the caller holds at least a reference on the interface.
    Internally takes a write lock on the interface's neighbor set.

Caller IRQL:

    Must be called at DISPATCH level.

--*/
{
    PLIST_ENTRY Head, Current;
    PIP_SUBINTERFACE SubInterface;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG MinimumNlMtu = NlMtu;
    PIP_PATH Path = NULL;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;
    PIPP_PATH_SET PathSet = &Compartment->PathSet;
    PRTL_HASH_TABLE_ENTRY PathEntry;

    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    Head = &Interface->SubInterfaceSet;
    for (Current = Head->Flink; Current != Head; Current = Current->Flink) {
        SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Current, IP_SUBINTERFACE, Link);

        if (NlMtu > SubInterface->FlCharacteristics->Mtu) {
            SubInterface->NlMtu = SubInterface->FlCharacteristics->Mtu;
            if (MinimumNlMtu > SubInterface->NlMtu) {
                MinimumNlMtu = SubInterface->NlMtu;
            }
        } else {
            SubInterface->NlMtu = NlMtu;
        }
    }

    Interface->MinimumNlMtu = MinimumNlMtu;

    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &LockHandle);

    //
    // Now that the interface has been updated,
    // update all paths that go over this interface.
    //
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

    RtlInitEnumerationHashTable(&PathSet->Table, &Enumerator);

    for (PathEntry = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator);
         PathEntry != NULL;
         PathEntry = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator)) {
        PIP_NEIGHBOR Neighbor;

        Path = IppGetPathFromPathLink(PathEntry);

        //
        // Skip if not on this interface.
        //
        Neighbor = IppGetNeighborFromPathUnderLock(Path);
        if (Neighbor == NULL) {
            continue;
        }

        if ((Neighbor->Interface == Interface) &&
            (Neighbor->SubInterface->NlMtu < Path->PathMtu)) {
            Path->PathMtu = Neighbor->SubInterface->NlMtu;
            Path->PathMtuLastSet = 0;
            IppInvalidatePathCachedInformation(Path);
        }
        
        IppDereferenceNeighbor(Neighbor);
    }

    RtlEndEnumerationHashTable(&PathSet->Table, &Enumerator);

    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);   
}

VOID
IppUpdateInterfaceMtuUnderLock(
    IN PIP_INTERFACE Interface
    )
/*++
    
Routine Description:

    Update interface with the minimum MTU among all its subinterfaces.  

Arguments:

    Interface - Supplies the interface to update the MTU on.

Locks:

    Assumes caller holds a write lock on the interface neighbor set.

--*/
{
    PLIST_ENTRY Head, Current;
    PIP_SUBINTERFACE SubInterface;
    ULONG Mtu = 0;

    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    Head = &Interface->SubInterfaceSet;
    for (Current = Head->Flink; Current != Head; Current = Current->Flink) {
        SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Current, IP_SUBINTERFACE, Link);

        if ((Mtu == 0) || (SubInterface->NlMtu < Mtu)) {
            Mtu = SubInterface->NlMtu;
        }
    }

    Interface->MinimumNlMtu = Mtu;
}

VOID
IppUpdateOffloadCapabilities(
    IN PIP_INTERFACE Interface,
    IN PNDIS_OFFLOAD OffloadCapabilities
    )
/*++
    
Routine Description:

    Update interface with the offload information. Call the NL Clients
    such as TCP with the new offload capabilities

Arguments:

    Interface - Supplies the interface to update the offload capabilities on.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PNDIS_TCP_IP_CHECKSUM_OFFLOAD Xsum;
    PNDIS_TCP_LARGE_SEND_OFFLOAD_V1 LSO;
    PNDIS_TCP_LARGE_SEND_OFFLOAD_V2 GSO;
    
    Xsum = &OffloadCapabilities->Checksum;
    LSO  = &OffloadCapabilities->LsoV1;
    GSO  = &OffloadCapabilities->LsoV2;
    
    Interface->TransmitOffload.FastPathCompatible = FALSE;
    Interface->TlDatagramFastPathCompatible = FALSE;
    
    if (IS_IPV4_PROTOCOL(Protocol)) {
        Interface->TransmitOffload.TlDatagramChecksumSupported = (BOOLEAN) 
            (Xsum->IPv4Transmit.UdpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.TlStreamChecksumSupported = (BOOLEAN)
            (Xsum->IPv4Transmit.TcpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.TlStreamOptionsSupported = (BOOLEAN)
            (Xsum->IPv4Transmit.TcpOptionsSupported == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.NlChecksumSupported = (BOOLEAN)
            (Xsum->IPv4Transmit.IpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.NlOptionsSupported = (BOOLEAN)
            (Xsum->IPv4Transmit.IpOptionsSupported == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.TlLargeSendOffloadSupported = (BOOLEAN)
            (LSO->IPv4.MaxOffLoadSize != 0);
        Interface->TransmitOffload.TlGiantSendOffloadSupported = (BOOLEAN)
            (GSO->IPv4.MaxOffLoadSize != 0);
        
        Interface->ReceiveOffload.TlDatagramChecksumSupported = (BOOLEAN)
            (Xsum->IPv4Receive.UdpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->ReceiveOffload.TlStreamChecksumSupported = (BOOLEAN)
            (Xsum->IPv4Receive.TcpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->ReceiveOffload.TlStreamOptionsSupported = (BOOLEAN)
            (Xsum->IPv4Receive.TcpOptionsSupported == NDIS_OFFLOAD_SUPPORTED);
        Interface->ReceiveOffload.NlChecksumSupported = (BOOLEAN)
            (Xsum->IPv4Receive.IpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->ReceiveOffload.NlOptionsSupported = (BOOLEAN)
            (Xsum->IPv4Receive.IpOptionsSupported == NDIS_OFFLOAD_SUPPORTED);

        //
        // Copy over the Segmentation offload structures
        //

        Interface->Lso = OffloadCapabilities->LsoV1;
        Interface->Gso.IPv4 = OffloadCapabilities->LsoV2.IPv4;

        if (Interface->TransmitOffload.NlChecksumSupported) {
            if (Interface->TransmitOffload.TlStreamChecksumSupported) {
                Interface->TransmitOffload.FastPathCompatible = TRUE;
            }
            
            if (Interface->TransmitOffload.TlDatagramChecksumSupported) {
                Interface->TlDatagramFastPathCompatible = TRUE;
            }
        }
        
    } else {

        ASSERT(IS_IPV6_PROTOCOL(Protocol));
        Interface->TransmitOffload.TlDatagramChecksumSupported = (BOOLEAN)
            (Xsum->IPv6Transmit.UdpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.TlStreamChecksumSupported = (BOOLEAN)
            (Xsum->IPv6Transmit.TcpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.TlStreamOptionsSupported = (BOOLEAN)
            (Xsum->IPv6Transmit.TcpOptionsSupported == NDIS_OFFLOAD_SUPPORTED);
        Interface->TransmitOffload.NlChecksumSupported = (BOOLEAN)
            (NDIS_OFFLOAD_NOT_SUPPORTED);
        Interface->TransmitOffload.NlOptionsSupported = (BOOLEAN)
            (NDIS_OFFLOAD_NOT_SUPPORTED);
        Interface->TransmitOffload.TlGiantSendOffloadSupported = (BOOLEAN)
            (GSO->IPv6.MaxOffLoadSize != 0);
        
        Interface->ReceiveOffload.TlDatagramChecksumSupported = (BOOLEAN)
            (Xsum->IPv6Receive.UdpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->ReceiveOffload.TlStreamChecksumSupported = (BOOLEAN)
            (Xsum->IPv6Receive.TcpChecksum == NDIS_OFFLOAD_SUPPORTED);
        Interface->ReceiveOffload.TlStreamOptionsSupported = (BOOLEAN)
            (Xsum->IPv6Receive.TcpOptionsSupported == NDIS_OFFLOAD_SUPPORTED);
        Interface->ReceiveOffload.NlChecksumSupported = (BOOLEAN)
            (NDIS_OFFLOAD_NOT_SUPPORTED);
        Interface->ReceiveOffload.NlOptionsSupported = (BOOLEAN)
            (NDIS_OFFLOAD_NOT_SUPPORTED);
        //
        // Copy over the Segmentation offload structures
        //

        Interface->Gso.IPv6 = OffloadCapabilities->LsoV2.IPv6;

        if (Interface->TransmitOffload.TlStreamChecksumSupported) {
            Interface->TransmitOffload.FastPathCompatible = TRUE;
        }

        if (Interface->TransmitOffload.TlDatagramChecksumSupported) {
            Interface->TlDatagramFastPathCompatible = TRUE;
        }

    }

    //
    // Update the NL clients with the new offload capabilities
    //    
    IppNotifyInterfaceChange(Interface, 0, NsiParameterNotification, NULL);    
}

NTSTATUS
IppValidateSetAllInterfaceParametersHelper(
    IN CONST IP_PROTOCOL *Protocol,
    IN CONST FL_INTERFACE_CHARACTERISTICS *FlCharacteristics,
    IN NL_INTERFACE_RW UNALIGNED *Data, 
    IN PIP_INTERFACE Interface OPTIONAL
    )
/*++

Routine Description:

    Helper for IppValidateSetAllInterfaceParameters.

Arguments:

    Protocol - Supplies the network layer protocol characteristics.
    
    FlCharacteristics - Supplies the framing layer interface characteristics.

    Data - Supplies the configured read-write parameters.

    Interface - Optionally supplies the interface for which to perform the
        validation.  Some parameters can only be modified at
        initialization time (e.g. UseZeroBroadcastAddress) to prevent
        inconsistent state.  For such parameters, the routine checks the new
        value of the parameter with the value stored in the interface to make
        sure that it is not changed.  At initialization time, we pass a NULL
        interface so that this check is skipped.

Return Value:

    STATUS_SUCCESS or STATUS_INVALID_PARAMETER.
    
--*/
{
    //
    // UseNeighborUnreachabilityDetection implies use of ND packets to probe
    // neighbor reachability.  DiscoversNeighbor implies use of ND packets to
    // resolve neighbor addresses, it indirectly implies use of NUD as well.
    //
    if (FlCharacteristics->DiscoversNeighbors) {
        if ((Data->UseNeighborUnreachabilityDetection != (BOOLEAN) -1) &&
            !Data->UseNeighborUnreachabilityDetection) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    
    if (!FlCharacteristics->DiscoversRouters) {
        if ((Data->AdvertisingEnabled != (BOOLEAN) -1) &&
            Data->AdvertisingEnabled) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if ((Data->RouterDiscoveryBehavior != RouterDiscoveryUnchanged) &&
        ((Data->RouterDiscoveryBehavior < RouterDiscoveryDisabled) ||
         (Data->RouterDiscoveryBehavior > RouterDiscoveryDhcp))) {
        return STATUS_INVALID_PARAMETER;
    }
    
    //
    // DhcpRouterDiscoveryEnabled is not relevant for IPv6. 
    //
    if ((Protocol->Level == IPPROTO_IPV6) &&
        (Data->DhcpRouterDiscoveryEnabled != (BOOLEAN) -1) &&
        (Data->DhcpRouterDiscoveryEnabled != FALSE)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    //
    // UseBroadcastForRouterDiscovery can not be set to TRUE for IPv6.  
    //
    if ((Protocol->Level == IPPROTO_IPV6) &&
        (Data->UseBroadcastForRouterDiscovery != (BOOLEAN) -1) &&
        (Data->UseBroadcastForRouterDiscovery != FALSE)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // UseZeroBroadcastAddress can not be set to TRUE for IPv6.  Also,
    // its value cannot be changed after interface initialization.
    //
    if ((Data->UseZeroBroadcastAddress != (BOOLEAN) -1) &&
        (((Protocol->Level == IPPROTO_IPV6) &&
          (Data->UseZeroBroadcastAddress != FALSE)) ||
         ((Interface != NULL) && 
          (Data->UseZeroBroadcastAddress != 
           Interface->UseZeroBroadcastAddress)))) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((Data->TypeOfInterface != InterfaceUnchanged) &&
        ((Data->TypeOfInterface > InterfaceDisallowAll) ||
         (Data->TypeOfInterface < InterfaceAllowAll))) {
        return STATUS_INVALID_PARAMETER;
    }
    
    //
    // If the metric is specified, UserAutomaticMetric should be false.
    //
    if (Data->UseAutomaticMetric != FALSE) {
        //
        // Metric must not be specified.
        //
        if (Data->Metric != (ULONG) -1) {
            return STATUS_INVALID_PARAMETER;
        }
    } else {
        //
        // A valid metric must be specified.
        //
        if ((Data->Metric == (ULONG) -1) || 
            (Data->Metric > NL_MAX_METRIC_COMPONENT)) { 
            return STATUS_INVALID_PARAMETER;
        }
    }
    
    if ((Data->BaseReachableTime != (ULONG) 0) &&
        (Data->BaseReachableTime > MAX_REACHABLE_TIME)) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((Data->NlMtu != (ULONG) 0) &&
        (Data->NlMtu < Protocol->MinimumMtu)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (Data->SitePrefixLength != (ULONG) -1) {
        if (Data->SitePrefixLength >
            (ULONG) Protocol->Characteristics->AddressBytes * 8) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (Data->MulticastForwardingHopLimit != (ULONG) -1) {
        if (Data->MulticastForwardingHopLimit > 255) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    //
    // For IPv6, link local address auto-configuration will always be on,
    // unless not supported by the interface characteristics.
    //
    if ((Data->LinkLocalAddressBehavior != LinkLocalUnchanged) &&
        (Data->LinkLocalAddressBehavior != LinkLocalAlwaysOn) &&
        (Protocol->Level == IPPROTO_IPV6)) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}


NTSTATUS
IppValidateSetAllInterfaceParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will validate a set all interface parameter request.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    Status of the operation.
    
--*/
{
    PNL_INTERFACE_KEY Key = (PNL_INTERFACE_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    PIP_INTERFACE Interface;    
    NTSTATUS Status;

    IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_INTERFACE_KEY));
    Args->ProviderTransactionContext = NULL;
    if ((Args->Action != NsiSetDefault) && (Args->Action != NsiSetReset)) {
        //
        // We don't administratively create or delete interfaces @ NL.
        //
        return STATUS_INVALID_PARAMETER;
    }

    Interface = IppFindInterfaceByLuid(Protocol, &Key->Luid);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (Args->RwStructDesc.RwParameterStruct != NULL) {
        NL_INTERFACE_RW UNALIGNED *Data = (NL_INTERFACE_RW UNALIGNED *)
            Args->RwStructDesc.RwParameterStruct;            

        ASSERT(Args->RwStructDesc.RwParameterStructLength == sizeof(*Data));

        //
        // Validate parameters.
        //
        Status =
            IppValidateSetAllInterfaceParametersHelper(
                Protocol,
                Interface->FlCharacteristics,
                Data, 
                Interface);
        if (!NT_SUCCESS(Status)) {
            IppDereferenceInterface(Interface);
            return Status;
        }

        //
        // Don't allow clients to change the link-local address configuration
        // behavior once the interface has been configured.  This check is not
        // in IppValidateSetAllInterfaceParametersHelper because it is called
        // on interface initialization as well and we are okay setting the
        // behavior of the interface to a non-default value at that time. 
        //
        if ((Data->LinkLocalAddressBehavior != LinkLocalUnchanged) &&
            (Data->LinkLocalAddressBehavior != 
             Interface->LinkLocalAddressBehavior)) {
            IppDereferenceInterface(Interface);
            return STATUS_INVALID_PARAMETER;
        }
    }
    
    Args->ProviderTransactionContext = Interface;
    return STATUS_SUCCESS;
}


VOID
IppCancelSetAllInterfaceParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will cancel a validated set all interface parameters
    request. 

Arguments:

    Args - Pointer to a parameter structure.

Return value:

    None.
    
--*/
{
    PIP_INTERFACE Interface;

    Interface = (PIP_INTERFACE)Args->ProviderTransactionContext;
    ASSERT(Interface != NULL);
    
    IppDereferenceInterface(Interface);
    Args->ProviderTransactionContext = NULL;
}


NTSTATUS
IppCommitSetAllInterfaceParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This routine will commit a validated set all interface parameters request. 

Arguments:

    Args - Pointer to the set all parameter request.

Return Value:

    None.
    
--*/
{
    PIP_INTERFACE Interface;
    KLOCK_QUEUE_HANDLE LockHandle;
    NL_INTERFACE_RW UNALIGNED *Data = (NL_INTERFACE_RW UNALIGNED *)
        Args->RwStructDesc.RwParameterStruct;

    Interface = (PIP_INTERFACE)Args->ProviderTransactionContext;
    ASSERT(Interface != NULL);

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    if (Args->Action == NsiSetReset) {
        if (Interface->UseRouterDiscovery) {
            IppStartRouterDiscovery(Interface);
        }
        goto Done;
    }
    //
    // Update parameters that affect router discovery. 
    //
    if (Data->UseBroadcastForRouterDiscovery != (BOOLEAN) -1) {
        Interface->UseBroadcastForRouterDiscovery = 
            Data->UseBroadcastForRouterDiscovery;
    }
    
    if (Data->DhcpRouterDiscoveryEnabled != (BOOLEAN) -1) {
        Interface->DhcpRouterDiscoveryEnabled =
            Data->DhcpRouterDiscoveryEnabled;
    }

    if (Data->RouterDiscoveryBehavior != RouterDiscoveryUnchanged) {
        Interface->RouterDiscoveryBehavior =
            Data->RouterDiscoveryBehavior;
        Interface->UseRouterDiscovery = IppIsRouterDiscoveryEnabled(Interface);
        
        //
        // Start/Reset RouterDiscovery.
        //
        if (Interface->UseRouterDiscovery) {
            IppStartRouterDiscovery(Interface);
        } else {
            IppStopRouterDiscovery(Interface);
            IppResetAutoConfiguredSettings(Interface, 0);
        }
    }
    
    //
    // Update interface properties.
    //
    IppUpdateInterface(
        Interface,
        Data->AdvertisingEnabled,
        Data->AdvertiseDefaultRoute,
        Data->ManagedAddressConfigurationSupported,
        Data->OtherStatefulConfigurationSupported,
        Data->ForwardingEnabled,
        Data->WeakHostSend,
        Data->WeakHostReceive,
        Data->MulticastForwardingEnabled,
        Data->UseNeighborUnreachabilityDetection,
        (BOOLEAN) -1);
    
    if (Data->UseAutomaticMetric != (BOOLEAN) -1) {
        if (Data->UseAutomaticMetric) {
            Interface->AutoMetric = TRUE;

            RtlAcquireReadLockAtDpcLevel(&Interface->NeighborSetLock);

            IppRecomputeMetric(Interface);

            RtlReleaseReadLockFromDpcLevel(&Interface->NeighborSetLock);
        } else {
            Interface->AutoMetric = FALSE;
            Interface->Metric = Data->Metric;
        }
    }
    
    if (Data->UseZeroBroadcastAddress != (BOOLEAN) -1) {
        Interface->UseZeroBroadcastAddress = Data->UseZeroBroadcastAddress;
    }
    
    if (Data->TypeOfInterface != InterfaceUnchanged) {
        IppSetInterfaceType(Interface, Data->TypeOfInterface);
    }
    
    if (Data->BaseReachableTime != (ULONG) 0) {
        Interface->BaseReachableTime = Data->BaseReachableTime;
        Interface->ReachableTicks =
            IppNeighborReachableTicks(Data->BaseReachableTime);
    }   
    
    if (Data->PathMtuDiscoveryTimeout != (ULONG) 0) {
        if (Data->PathMtuDiscoveryTimeout == INFINITE_LIFETIME) {
            Interface->PathMtuDiscoveryTicks = INFINITE_LIFETIME;
        } else {
            Interface->PathMtuDiscoveryTicks = 
                IppMillisecondsToTicks(Data->PathMtuDiscoveryTimeout);
        }
    }    

    if (Data->RetransmitTime != (ULONG) 0) {
        Interface->RetransmitTicks =
            IppMillisecondsToTicks(Data->RetransmitTime);
    }
    
    if (Data->DadTransmits != (ULONG) -1) {
        Interface->DadTransmits = Data->DadTransmits;
    }

    if (Data->LinkLocalAddressTimeout != (ULONG) -1) {
        Interface->LinkLocalAddressTimeout = 
            IppMillisecondsToTicks(Data->LinkLocalAddressTimeout);
    }
    
    IppUpdateZoneIndices(Interface, Data->ZoneIndices);
    
    if (Data->NlMtu != (ULONG) 0) {
        IppSetInterfaceMtuAtDpc(Interface, Data->NlMtu);
    }
    
    if (Data->SitePrefixLength != (ULONG) -1) {
        Interface->DefaultSitePrefixLength = (UINT8) Data->SitePrefixLength;
    }

    if (Data->MulticastForwardingHopLimit != (ULONG) -1) {
        Interface->MulticastForwardingHopLimit = 
            (UCHAR) Data->MulticastForwardingHopLimit;
    }    

    if (Data->DisableDefaultRoutes != (BOOLEAN) -1) {
        if (Interface->DisableDefaultRoutes != 
            Data->DisableDefaultRoutes) {
            Interface->DisableDefaultRoutes = 
                Data->DisableDefaultRoutes;
            IppInvalidateDestinationCache(Interface->Compartment);
        }
    }

    if (Data->SendUnsolicitedNeighborAdvertisementOnDad != (BOOLEAN) -1) {
        Interface->SendUnsolicitedNeighborAdvertisementOnDad = 
            Data->SendUnsolicitedNeighborAdvertisementOnDad;
    }
    
    //
    // Update network category state.
    //

    IppUpdateNetworkCategoryState(
        Interface, 
        Data->NetworkCategory);

Done:    

    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    IppDereferenceInterface(Interface);
    Args->ProviderTransactionContext = NULL;

    return STATUS_SUCCESS;
}


NTSTATUS
IppValidateSetAllSubInterfaceParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Validate a set all subinterface request.

Arguments:

    Args - Pointer to the set all parameters structure.

Return Value:

    Status of the validation.
    
--*/
{
    PNL_SUBINTERFACE_KEY Key =
        (PNL_SUBINTERFACE_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    PIP_SUBINTERFACE SubInterface;
    
    IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    //
    // Guaranteed by the NSI since we register with this requirement.
    //    
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_SUBINTERFACE_KEY));
    Args->ProviderTransactionContext = NULL;
    if ((Args->Action != NsiSetDefault) && (Args->Action != NsiSetReset)) {
        //
        // We don't administratively create or delete subinterfaces @ NL.
        //
        return STATUS_INVALID_PARAMETER;
    }

    SubInterface =
        IppFindSubInterfaceByLuid(
            Protocol, &Key->InterfaceLuid, &Key->SubInterfaceLuid);
    if (SubInterface == NULL) {
        return STATUS_NOT_FOUND;
    } else {
        Args->ProviderTransactionContext = SubInterface;
        return STATUS_SUCCESS;
    }
}


VOID
IppCancelSetAllSubInterfaceParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Cancel a validated set all subinterface parameters request.

Arguments:

    Args - Pointer to the set all parameter structure.

Return Value:

    None.
    
--*/
{
    PIP_SUBINTERFACE SubInterface;

    SubInterface = (PIP_SUBINTERFACE)Args->ProviderTransactionContext;
    ASSERT(SubInterface != NULL);
    IppDereferenceSubInterface(SubInterface);
    Args->ProviderTransactionContext = NULL;
}


VOID
IppCommitSetAllSubInterfaceParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Commit a validated set all subinterface parameters request.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    None.
    
--*/
{
    PIP_SUBINTERFACE SubInterface = 
        (PIP_SUBINTERFACE)Args->ProviderTransactionContext;
    NL_SUBINTERFACE_RW UNALIGNED *Data = (NL_SUBINTERFACE_RW UNALIGNED *)
        Args->RwStructDesc.RwParameterStruct;
    ULONG OldMtu;
    PIP_INTERFACE Interface = SubInterface->Interface;
    KLOCK_QUEUE_HANDLE InterfaceLockHandle, NeighborSetLockHandle;

    if (Args->Action == NsiSetReset) {
        RtlAcquireWriteLock(&Interface->Lock, &InterfaceLockHandle);
        RtlAcquireWriteLockAtDpcLevel(
            &Interface->NeighborSetLock, 
            &NeighborSetLockHandle);

        IppReconnectSubInterface(SubInterface, TRUE);

        RtlReleaseWriteLockFromDpcLevel(
            &Interface->NeighborSetLock, 
            &NeighborSetLockHandle);
        RtlReleaseWriteLock(&Interface->Lock, &InterfaceLockHandle);
        goto Done;
    }

    ASSERT(Args->Action == NsiSetDefault);
    if (Data == NULL) {
        goto Done;
    }
    
    ASSERT(Args->RwStructDesc.RwParameterStructLength == sizeof(*Data));
    
    RtlAcquireWriteLock(&Interface->NeighborSetLock, &NeighborSetLockHandle);
    {
        OldMtu = SubInterface->NlMtu;
        SubInterface->NlMtu = Data->NlMtu;
        IppUpdateInterfaceMtuUnderLock(Interface);
    }
    RtlReleaseWriteLock(&Interface->NeighborSetLock, &NeighborSetLockHandle);
    
    if (OldMtu > Data->NlMtu) {
        KLOCK_QUEUE_HANDLE PathSetLockHandle;
        PIP_PATH Path;
        ULONG LinkMtu, PathMtu;
        PIP_NEIGHBOR Neighbor;
        PIP_SUBINTERFACE PathSubInterface;
        PIP_COMPARTMENT Compartment = Interface->Compartment;
        PIPP_PATH_SET PathSet = &Compartment->PathSet;
        RTL_HASH_TABLE_ENUMERATOR Enumerator;
        PRTL_HASH_TABLE_ENTRY Current;
        
        //
        // The Link MTU has shrunk, so we need to run through all
        // our paths looking for a too big Path MTU.  The XP stack
        // used a lazy check in the equivalent of IppGetMtuFromPath.
        // However, Link MTUs rarely (if ever) shrink, whereas
        // IppGetMtuFromPath is done on every packet send.
        //
        Path = NULL;
        RtlAcquireScalableWriteLock(
            &Compartment->PathSet.Lock,
            &PathSetLockHandle);

        RtlInitEnumerationHashTable(&PathSet->Table, &Enumerator);

        for (Current =
                 RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator);
             Current != NULL;
             Current =
                 RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator)) {

            Path = IppGetPathFromPathLink(Current);

            //
            // Skip if not on this subinterface.
            //
            Neighbor = IppGetNeighborFromPathUnderLock(Path);
            if (Neighbor == NULL) {
                continue;
            }

            PathSubInterface = Neighbor->SubInterface;
            if (PathSubInterface != SubInterface) {
                IppDereferenceNeighbor(Neighbor);
                continue;
            }
            
            LinkMtu = PathSubInterface->NlMtu;
            PathMtu = Path->PathMtu;
            if (PathMtu > LinkMtu) {
                Path->PathMtu = LinkMtu;
                Path->PathMtuLastSet = 0;
                IppInvalidatePathCachedInformation(Path);
            }

            IppDereferenceNeighbor(Neighbor);
        }

        RtlEndEnumerationHashTable(&PathSet->Table, &Enumerator);

        RtlReleaseScalableWriteLock(
            &Compartment->PathSet.Lock,
            &PathSetLockHandle);
    }

Done:
    IppDereferenceSubInterface(SubInterface);
    Args->ProviderTransactionContext = NULL;    
}

//
// Network Layer Provider Handlers.
//

NTSTATUS
NTAPI
IpNlpQueryInterface(
    IN PNL_REQUEST_INTERFACE Args,
    OUT PNL_INTERFACE_CHARACTERISTICS Characteristics
    )
{
    PIP_INTERFACE Interface;

    if (Args->NlInterface.Interface != NULL) {
        Interface = IppCast(Args->NlInterface.Interface, IP_INTERFACE);
        IppQueryInterface(Interface, Characteristics);
        return STATUS_SUCCESS;
    }

    Interface = IppFindInterfaceByRequest(Args);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    IppQueryInterface(Interface, Characteristics);
    //
    // It is not safe to pass the interface characteristics to the NL client on
    // a query unless the client holds a reference to the interface. 
    //
    if (Args->NlInterface.Interface == NULL) {
        Characteristics->FlCharacteristics = NULL;
    }
    
    IppDereferenceInterface(Interface);
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpNlpSetInterfaceProperty(
    IN PNL_REQUEST_INTERFACE Args,
    IN OUT PNL_REQUEST_INTERFACE_PROPERTY Property
    )
{
    PIP_INTERFACE Interface;
    NTSTATUS Status;
    FL_REQUEST_SET_INTERFACE Request = {0};

    Interface = IppFindInterfaceByRequest(Args);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    Request.ProviderInterfaceHandle = Interface->FlContext;
    Request.RequestCode = Property->FlicCode;
    Request.Oid = Property->Oid;
    Request.RequestBuffer = Property->RequestBuffer;
    Request.RequestLength = Property->RequestLength;

    Status = Interface->FlModule->Npi.Dispatch->SetInterface(&Request);
    ASSERT(Status != STATUS_PENDING);

    IppDereferenceInterface(Interface);
    return Status;
}

NTSTATUS
IppQueryInterfaceProperty(
    IN PIP_INTERFACE Interface,
    IN FLIC_CODE RequestCode,
    IN NDIS_OID Oid,
    IN PVOID RequestBuffer,
    IN OUT PULONG RequestLength
    )
/*++

Routine Description:

    This function retrieves information about an interface.

Arguments:

    InterfaceHandle - Supplies the interface to query.

    RequestCode - Supplies the code identifying the request type.

    Oid - Supplies the NDIS_OID (optionally) that needs to be used in the
        query request.

    RequestBuffer - Returns, in this caller supplied buffer, the
        requested interface property.

    RequestLength - Supplies the size, in bytes, of RequestBuffer.
        Returns, on STATUS_BUFFER_TOO_SMALL, the minimum size buffer
        required to return the interface's properties.  Otherwise, the
        value of RequestLength remains unchanged.

Return Value:

    Completes synchronously with STATUS_SUCCESS or a failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (!Interface->Compartment->Protocol->DisableTaskOffload) {
        FL_REQUEST_QUERY_INTERFACE Request = {0};

        Request.ProviderInterfaceHandle = Interface->FlContext;
        Request.RequestCode = RequestCode;
        Request.Oid = Oid;
        Request.RequestBuffer = RequestBuffer;
        Request.RequestLength = *RequestLength;
        
        Status = Interface->FlModule->Npi.Dispatch->QueryInterface(&Request);
        ASSERT(Status != STATUS_PENDING);
        
        *RequestLength = Request.RequestLength;
    }

    return Status;
}


NTSTATUS
NTAPI
IpNlpQueryInterfaceProperty(
    IN PNL_REQUEST_INTERFACE Args,
    IN OUT PNL_REQUEST_INTERFACE_PROPERTY Property
    )
{
    PIP_INTERFACE Interface;
    NTSTATUS Status;

    Interface = IppFindInterfaceByRequest(Args);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    Status =
        IppQueryInterfaceProperty(
            Interface, 
            Property->FlicCode,
            Property->Oid,
            Property->RequestBuffer,
            &Property->RequestLength);

    IppDereferenceInterface(Interface);
    return Status;
}


NTSTATUS
NTAPI
IpNlpReferenceInterface(
    IN PNL_REQUEST_INTERFACE Args
    )
{
    PIP_INTERFACE Interface;
    PIP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);

    Interface = IppFindInterfaceByRequest(Args);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }
    
    //
    // Reference the network layer client binding. If the network layer client
    // already has a reference to the interface, then guarantee that the
    // reference succeeds. 
    //
    if (Args->NlInterface.Interface != NULL) {
        IppReferenceValidNlClient(Client);
    } else {
        if (!IppReferenceNlClient(Client)) {
            IppDereferenceInterface(Interface);
            return STATUS_NOT_FOUND;
        }
        
        Args->NlInterface.Interface = (PNL_INTERFACE) Interface;
    }

    return STATUS_SUCCESS;
}


VOID
NTAPI
IpNlpDereferenceInterface(
    IN PNL_REQUEST_INTERFACE Args
    )
{
    PIP_CLIENT_CONTEXT Client;
    PIP_INTERFACE Interface =
        IppCast(Args->NlInterface.Interface, IP_INTERFACE);

    //
    // Client should supply the object pointer
    // either returned from a previous request (ReferenceObject)
    // or supplied in a previous indication (AddObject).
    //
    ASSERT(Interface != NULL);
    
    //
    // Dereference the network layer client binding.
    //
    Client = IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);
    IppDereferenceNlClient(Client);

    IppDereferenceInterface(Interface);    
}


VOID
IpNlpPnpEventCompleteInterface(
    IN PNL_REQUEST_PNP_EVENT_COMPLETE Args
    )
/*++

Routine Description:

    Completes a pnp event indicated to a client at an earlier point. This
    function takes down the references taken when the pnp event was indicated
    and completes the pnp event to the framing layer.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    None.
    
--*/
{
    FL_REQUEST_COMPLETE Request = {0};
    PIP_PROTOCOL Protocol;
    PNET_PNP_EVENT NetPnpEvent = Args->NetPnpEvent;
    PFL_PROVIDER_PNP_EVENT_COMPLETE FlPnpEventComplete =
        (PFL_PROVIDER_PNP_EVENT_COMPLETE) NetPnpEvent->TransportReserved[0];
    PIP_INTERFACE Interface = IppCast(Args->ProviderContext, IP_INTERFACE);

    Protocol = Interface->Compartment->Protocol;
    
    Request.ProviderObjectHandle = Interface->FlContext;
    Request.RequestContext = (PVOID) NetPnpEvent;
    Request.Status = Args->Status;
    
    (*FlPnpEventComplete)(&Request);

    IppDereferencePnpEventClientContext(Protocol);
}


VOID
IppInitializeZoneIndices(
    IN ULONG *ZoneIndices,
    IN IF_INDEX Index
    )
/*++

Routine Description:

    Initializes an array of zone indices to default values.
    Compare InitZoneIndices() in the XP IPv6 stack.

--*/
{
    SCOPE_LEVEL Level;

    for (Level = 0; Level < ScopeLevelCount; Level++) {
        if (ZoneIndices[Level] == (ULONG) -1) {
            if (Level <= ScopeLevelSubnet) {
                ZoneIndices[Level] = Index;
            } else {
                ZoneIndices[Level] = 1;
            }
        }
    }
}

NTSTATUS
IppSetOffloadEncapsulation(
    IN PIP_INTERFACE Interface,
    IN ULONG SuppliesOffOrOn
    )
/*++

Routine Description:

    Enable/Disable offload for this protocol on this interface. This function
    also handles the case where the interface gets deleted while processing
    the request. It does this be reissuing the OID with offloads turned off.
    
Arguments:

    Interface - Supplies the interface whose encapsulations are set.

    SuppliesOffOrOn - either NDIS_OFFLOAD_SET_OFF or NDIS_OFFLOD_SET_ON to turn
         offload off or on.
    
Return Value:

    STATUS_SUCCESS or error code.

--*/
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    NDIS_OFFLOAD_ENCAPSULATION Encapsulation;
    FL_REQUEST_SET_INTERFACE SetInterfaceArgs;
    NTSTATUS Status;
    BOOLEAN DeleteOffload;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // Inform the nic of the encapsulation in use by this interface
    //
    if (Protocol->DisableTaskOffload) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&Encapsulation, sizeof(NDIS_OFFLOAD_ENCAPSULATION));

    Encapsulation.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD_ENCAPSULATION;
    Encapsulation.Header.Size = sizeof(NDIS_OFFLOAD_ENCAPSULATION);
    Encapsulation.Header.Revision  = NDIS_OFFLOAD_ENCAPSULATION_REVISION_1;

    if (IS_IPV4_PROTOCOL(Protocol)) {
        Encapsulation.IPv4.Enabled = SuppliesOffOrOn;
    }

    if (IS_IPV6_PROTOCOL(Protocol)) {
        Encapsulation.IPv6.Enabled = SuppliesOffOrOn;
    }

    SetInterfaceArgs.ProviderInterfaceHandle = Interface->FlContext;
    SetInterfaceArgs.RequestCode = FlicEncapsulation;
    SetInterfaceArgs.RequestBuffer = &Encapsulation;
    SetInterfaceArgs.RequestLength = sizeof(Encapsulation);

    Status = Interface->FlModule->Npi.Dispatch->SetInterface(&SetInterfaceArgs);
    ASSERT(Status != STATUS_PENDING);        

    //
    // Update the offload flags on the interface structure
    //
    DeleteOffload = FALSE;
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    Interface->SettingOffload = FALSE;
    if ((NT_SUCCESS(Status)) && (SuppliesOffOrOn == NDIS_OFFLOAD_SET_ON)) {
        if (Interface->OffloadDeleted == FALSE) {
            Interface->OffloadSet = TRUE;
        } else { 
            DeleteOffload = TRUE;
            Interface->OffloadSet = FALSE;
        }
    } else {
        Interface->OffloadSet = FALSE;
    }
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    //
    // The Interface is being deleted. Reissue an OID turning off 
    // the offload
    //
    if (DeleteOffload == TRUE) {
        if (IS_IPV4_PROTOCOL(Protocol)) {
            Encapsulation.IPv4.Enabled = NDIS_OFFLOAD_SET_OFF;
        }

        if (IS_IPV6_PROTOCOL(Protocol)) {
            Encapsulation.IPv6.Enabled = NDIS_OFFLOAD_SET_OFF;
        }
        
        Status = Interface->FlModule->Npi.Dispatch->SetInterface(
            &SetInterfaceArgs);
        ASSERT(Status != STATUS_PENDING);        

        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
        Interface->OffloadSet = FALSE;
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        Status = STATUS_UNSUCCESSFUL;
    }
    return Status;
}

VOID
IppSetOffloadEncapsulationAtPassive(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Set offload encapsulation on the NIC. This will signal the NIC to 
    begin offloads.

Arguments:

    Interface - Supplies an interface to notify clients about.

Locks:

    Must be called with no locks held.
    Assumes caller holds a reference on the interface.
    Assumes caller holds a reference on the NSI notification context, which
    we free before returning.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    NTSTATUS Status;
    NDIS_OFFLOAD OffloadCapabilities;

    PASSIVE_CODE();

    Status = IppSetOffloadEncapsulation(Interface,NDIS_OFFLOAD_SET_ON);

    if (NT_SUCCESS(Status)) {
        //
        // Inform TCP of the new capabilities
        //
        OffloadCapabilities = 
            Interface->FlCharacteristics->OffloadCapabilities;
        IppUpdateOffloadCapabilities(Interface, &OffloadCapabilities);
    } 

}

VOID
IppSetOffloadEncapsulationWorker(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    Worker function for calling IppNotifyInterfaceChangeAtPassive.

Arguments:

    DeviceObject - Unused.  Wish they passed the WorkItem instead.

    Context - Supplies an IP_WORK_QUEUE_ITEM struct.

Locks:

    The work item holds a reference on the interface and on the
    NSI notification context, both of which we release on exit.

Caller IRQL:

    Called at PASSIVE level from a work item.

--*/
{
    PIP_WORK_QUEUE_ITEM MyContext = Context;
    PIP_INTERFACE Interface = MyContext->Context;
    
    UNREFERENCED_PARAMETER(DeviceObject);

    IoFreeWorkItem(MyContext->WorkQueueItem);
    ExFreePool(MyContext);

    IppSetOffloadEncapsulationAtPassive(Interface);

    IppDereferenceInterface(Interface);
}



VOID
IppSetOffloadChange(
    IN PIP_INTERFACE Interface 
    )
/*++

Routine Description:

    Set the offload encapsulation type on an interface via a workitem.
    This is only called from the Status Indication code path.
    Normally, the offload capabilties will come through IpAddFlcInterface.

Arguments:

    Interface - Supplies the interface to notify clients about.

Locks:

    Assumes caller holds at least a reference on the interface.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIO_WORKITEM WorkItem;
    PIP_WORK_QUEUE_ITEM Context;

    //
    // Even if we're at passive, queue a work item.  This is because
    // the notification may take a long period of time, and we don't
    // want to hold up interface addition.
    //
    Context =
        ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(IP_WORK_QUEUE_ITEM),
            IpGenericPoolTag);
    if (Context == NULL) {
        //
        // REVIEW: Should we do anything on failure?
        // The XP IPv6 stack doesn't.
        //
        return;
    }

    WorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (WorkItem == NULL) {
        ExFreePool(Context);
        return;
    }


    Context->WorkQueueItem = WorkItem;
    IppReferenceInterface(Interface);
    Context->Context = Interface;

    IoQueueWorkItem(
        WorkItem,
        IppSetOffloadEncapsulationWorker,
        DelayedWorkQueue,
        Context);
}


VOID
IppDeleteOffloadEncapsulation(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Disables offload on this interface. It sets the OffloadDeleted flag
    on the interface so that if a request is currently outstanding in the FL
    than the request thread will delete the offload settings before completing
    
Arguments:

    Interface - Supplies the interface whose encapsulations are set.

Return Value:

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    Interface->OffloadDeleted = TRUE;
    if ((Interface->OffloadSet == TRUE) && 
        (Interface->SettingOffload == FALSE)) {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        IppSetOffloadEncapsulation(Interface, NDIS_OFFLOAD_SET_OFF);
    } else {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }
}

//
// Framing Layer Client Handlers.
//

NTSTATUS
NTAPI
IpFlcAddInterface(
    IN PFL_INDICATE_ADD_INTERFACE Args
    )
/*++

Routine Description:
    
    FL_CLIENT_ADD_INTERFACE Handler.

--*/
{
    NTSTATUS Status;

    PFL_PROVIDER_CONTEXT FlModule = (PFL_PROVIDER_CONTEXT) Args->ClientHandle;
    PIP_PROTOCOL Protocol = FlModule->Protocol;

    PIP_COMPARTMENT Compartment;
    PIP_INTERFACE Interface;

    NL_INTERFACE_KEY InterfaceKey = {0};
    NL_INTERFACE_RW InterfaceRw = {0};
    
    KLOCK_QUEUE_HANDLE LockHandle;
    
    PASSIVE_CODE();

    ASSERT(Args->Characteristics->AccessType != NET_IF_ACCESS_LOOPBACK ||
           Args->Characteristics->InterfaceType == IF_TYPE_SOFTWARE_LOOPBACK);
    
    //
    // Find/Create a compartment for the interface to live in.
    //
    Compartment =
        IppFindOrCreateCompartmentById(
            Protocol,
            Args->Characteristics->CompartmentId);
    if (Compartment == NULL) {
        NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_WARNING,
                   "IPNG: [%u] Error creating %s interface: "
                   "Can not find compartment %d\n",
                   Args->Identifiers->Index,
                   Protocol->TraceString, 
                   Args->Characteristics->CompartmentId);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read persistent interface configuration.  Initialize the RW to the
    // default values.  NSI will set the values that have been changed in
    // persistent store and leave the rest unchanged.
    //
    InterfaceKey.Luid = Args->Identifiers->Luid;
    NlInitializeInterfaceRw(&InterfaceRw);
    Status =
        NsiGetAllParameters(
            NsiPersistent,
            Protocol->ModuleId,
            NlInterfaceObject,
            &InterfaceKey, sizeof(InterfaceKey),
            &InterfaceRw, sizeof(InterfaceRw),            
            NULL, 0,
            NULL, 0);
    if (NT_SUCCESS(Status)) {
        Status =
            IppValidateSetAllInterfaceParametersHelper(
                Protocol,
                Args->Characteristics,
                &InterfaceRw, 
                NULL);
    }

    if (!NT_SUCCESS(Status)) {
        //
        // Proceed with default values if we do not have a valid configuration.
        //
        NlInitializeInterfaceRw(&InterfaceRw);
    }

    if (InterfaceRw.LinkLocalAddressBehavior == LinkLocalUnchanged) {
        InterfaceRw.LinkLocalAddressBehavior =
            Args->Characteristics->AutoconfigureLinkLocalAddress
            ? Protocol->LinkLocalAddressBehavior
            : LinkLocalAlwaysOff;
    }
    if (InterfaceRw.LinkLocalAddressTimeout == (ULONG) -1) {
        InterfaceRw.LinkLocalAddressTimeout =
            IppTicksToMilliseconds(Protocol->LinkLocalAddressTimeout);
    }
    if (InterfaceRw.AdvertisingEnabled == (BOOLEAN) -1) {
        InterfaceRw.AdvertisingEnabled =
            FALSE;
    }
    if (InterfaceRw.ManagedAddressConfigurationSupported == (BOOLEAN) -1) {
        InterfaceRw.ManagedAddressConfigurationSupported =
            Protocol->DefaultDhcpEnabled;
    }
    if (InterfaceRw.OtherStatefulConfigurationSupported == (BOOLEAN) -1) {
        InterfaceRw.OtherStatefulConfigurationSupported =
            Protocol->DefaultDhcpEnabled;
    }
    if (InterfaceRw.AdvertiseDefaultRoute == (BOOLEAN) -1) {
        InterfaceRw.AdvertiseDefaultRoute =
            FALSE;
    }    
    if (InterfaceRw.ForwardingEnabled == (BOOLEAN) -1) {
        InterfaceRw.ForwardingEnabled =
            (Compartment->Forwarding == ForwardingEnabled);
    }
    if (InterfaceRw.MulticastForwardingEnabled == (BOOLEAN) -1) {
        InterfaceRw.MulticastForwardingEnabled = 
            Compartment->MulticastForwarding;
    }
    if (InterfaceRw.WeakHostSend == (BOOLEAN) -1) {
        InterfaceRw.WeakHostSend =
            Compartment->WeakHostSend;
    }
    if (InterfaceRw.WeakHostReceive == (BOOLEAN) -1) {
        InterfaceRw.WeakHostReceive =
            Compartment->WeakHostReceive;
    }
    if (InterfaceRw.UseNeighborUnreachabilityDetection == (BOOLEAN) -1) {
        InterfaceRw.UseNeighborUnreachabilityDetection =
            Args->Characteristics->UseNud;
    }    
    if (InterfaceRw.RouterDiscoveryBehavior == RouterDiscoveryUnchanged) {
        InterfaceRw.RouterDiscoveryBehavior = 
            Protocol->DefaultRouterDiscoveryBehavior;
    }
    if (InterfaceRw.DhcpRouterDiscoveryEnabled == (BOOLEAN) -1) {
        InterfaceRw.DhcpRouterDiscoveryEnabled =
            FALSE;
    }
    if (InterfaceRw.UseBroadcastForRouterDiscovery == (BOOLEAN) -1) {
        InterfaceRw.UseBroadcastForRouterDiscovery =
            FALSE;
    }
    if (InterfaceRw.UseZeroBroadcastAddress == (BOOLEAN) -1) {
        InterfaceRw.UseZeroBroadcastAddress =
            FALSE;
    }
    if (InterfaceRw.TypeOfInterface == InterfaceUnchanged) {
        InterfaceRw.TypeOfInterface =
            InterfaceAllowAll;
    }
    if (InterfaceRw.UseAutomaticMetric == (BOOLEAN) -1) {
        InterfaceRw.UseAutomaticMetric =
            TRUE;
    }
    if (InterfaceRw.Metric == (ULONG) -1) {
        InterfaceRw.Metric =
            0;
    }
    if (InterfaceRw.BaseReachableTime == (ULONG) 0) {
        InterfaceRw.BaseReachableTime =
            REACHABLE_TIME;
    }
    if (InterfaceRw.RetransmitTime == (ULONG) 0) {
        InterfaceRw.RetransmitTime =
            IppTicksToMilliseconds(RETRANS_TIMER);
    }
    if (InterfaceRw.PathMtuDiscoveryTimeout == (ULONG) 0) {
        InterfaceRw.PathMtuDiscoveryTimeout =
            PATH_MTU_DISCOVERY_TIMEOUT;
    }
    if (InterfaceRw.DadTransmits == (ULONG) -1) {
        //
        // Protocol default is only effective during interface initialization.
        //
        InterfaceRw.DadTransmits =
            (Protocol->DadTransmits == (ULONG) -1)
            ? Args->Characteristics->DadTransmits
            : Protocol->DadTransmits;
    }
    IppInitializeZoneIndices(
        InterfaceRw.ZoneIndices, Args->Identifiers->Index);
    if (InterfaceRw.NlMtu == (ULONG) 0) {
        InterfaceRw.NlMtu =
            0;
    }
    if (InterfaceRw.SitePrefixLength == (ULONG) -1) {
        InterfaceRw.SitePrefixLength =
            0;
    }
    if (InterfaceRw.MulticastForwardingHopLimit == (ULONG) -1) {
        InterfaceRw.MulticastForwardingHopLimit =
            0;
    }

    if (InterfaceRw.DisableDefaultRoutes == (BOOLEAN)-1) {
        InterfaceRw.DisableDefaultRoutes = FALSE;
    } 

    if (InterfaceRw.SendUnsolicitedNeighborAdvertisementOnDad == (BOOLEAN)-1) {
        InterfaceRw.SendUnsolicitedNeighborAdvertisementOnDad = FALSE;
    }

    //
    // Create the interface and insert in various access structures.
    //
    Interface =
        IppCreateInterface(
            Compartment,
            Args->Identifiers,
            Args->Characteristics,
            Args->ProviderInterfaceHandle,
            FlModule,
            &InterfaceRw);

    IppDereferenceCompartment(Compartment);    

    if (Interface == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    *Args->ClientInterfaceHandle = (HANDLE) Interface;

    if (Interface->ForwardMulticast) {
        //
        // Enable receiving multicast promiscuous.        
        // Take a lock to serialize calls down to the FL.
        //
        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
        IppAddFlAllMulticastReferenceUnderLock(Interface, NULL, NULL);
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    //
    // Set the offload encapsulation type on this interface
    //
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    if ((Interface->SettingOffload == FALSE) && 
        (Interface->OffloadSet == FALSE)) {
        Interface->SettingOffload = TRUE;
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        (VOID)IppSetOffloadEncapsulation(Interface, NDIS_OFFLOAD_SET_ON);
        
    } else {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }        

    //
    // Inform NSI and Nl clients of interface addition.
    //
    // Notify Nl client in this thread in case the interface goes away before 
    // the client has the chance to process the notification.
    //
    IppNotifyInterfaceChangeToNlClients(Interface, IpAddInterfaceEvent);
    
    IppNotifyInterfaceChange(Interface, 0, NsiAddInstance, NULL);
    
    IppDereferenceInterface(Interface);

    return STATUS_SUCCESS;
}

NTSTATUS
IppAddInterfaceStats(
    IN PIP_INTERFACE Interface,
    IN OUT PIP_OFFLOAD_STATS GlobalStats
    )
{
    NTSTATUS Status;
    IP_OFFLOAD_STATS InterfaceStats = {0}; 
    ULONG Length;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    NDIS_OID Oid = (Protocol->Level == IPPROTO_IPV6) ?
                        OID_IP6_OFFLOAD_STATS :
                        OID_IP4_OFFLOAD_STATS;

    Length = sizeof(InterfaceStats);

    Status =
        IppQueryInterfaceProperty(
            Interface,
            FlicReferOid,
            Oid,
            &InterfaceStats,
            &Length);

    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_WARNING,
                   "IPNG: [%u] Error %x querying %s offload statistics\n",
                   Interface->Index,
                   Status,
                   Protocol->TraceString);
    } else {
        GlobalStats->InReceives += InterfaceStats.InReceives;
        GlobalStats->InDelivers += InterfaceStats.InDelivers;
        GlobalStats->InOctets += InterfaceStats.InOctets;
        GlobalStats->OutRequests += InterfaceStats.OutRequests;
        GlobalStats->OutOctets += InterfaceStats.OutOctets;
        GlobalStats->InTruncatedPackets += InterfaceStats.InTruncatedPackets;
        GlobalStats->InHeaderErrors += InterfaceStats.InHeaderErrors;
        GlobalStats->InDiscards += InterfaceStats.InDiscards;
        GlobalStats->OutDiscards += InterfaceStats.OutDiscards;
        GlobalStats->OutNoRoutes += InterfaceStats.OutNoRoutes;
    }

    return Status;
}

NTSTATUS
NTAPI
IpFlcDeleteInterface(
    IN PFL_INDICATE_DELETE_INTERFACE Args
    )
/*++

Routine Description:
    
    FL_CLIENT_DELETE_INTERFACE Handler.

--*/
{
    PIP_PROTOCOL Protocol;
    PIP_COMPARTMENT Compartment;
    PIP_INTERFACE Interface;

    KLOCK_QUEUE_HANDLE LockHandle;
  
    PASSIVE_CODE();

    Interface = IppCast(Args->ClientInterfaceHandle, IP_INTERFACE);
    Compartment = Interface->Compartment;
    Protocol = Interface->FlModule->Protocol;

    //
    // Completion will be asynchronous.
    //
    ASSERT(Interface->FlDeleteComplete == NULL);
    Interface->FlDeleteComplete = Args->IndicateComplete;

    //
    // Serialize deletions with statistics queries.  This must be held
    // across both the list removal (since the statistics query walks
    // the interface set) and retrieving the final offload statistics from
    // this interface.
    //
    ExAcquireFastMutex(&Protocol->OffloadStatsMutex);

    //
    // Delete the interface from its sets.
    //
    // An alternative design would be to leave the interface in its set
    // upon deletion and attempt to cleanup all unreferenced interfaces
    // when processing the interface timeout.  While this also helps in
    // debugging (one can always find all interfaces currently allocated),
    // it requires care to not reference a deleted interface.
    //
    RtlAcquireWriteLock(&Protocol->GlobalInterfaceSet.Lock, &LockHandle);
    {
        RemoveEntryList(&Interface->GlobalLink);
        Protocol->GlobalInterfaceSet.NumEntries--;
    }
    RtlReleaseWriteLock(&Protocol->GlobalInterfaceSet.Lock, &LockHandle);

    //
    // Get the final offload statistics and add them to our global
    // offload counters.
    //
    IppAddInterfaceStats(Interface, &Protocol->OffloadStats);

    ExReleaseFastMutex(&Protocol->OffloadStatsMutex);

    RtlAcquireWriteLock(&Compartment->InterfaceSet.Lock, &LockHandle);
    {
        Interface->Disabled = TRUE;
        RemoveEntryList(&Interface->CompartmentLink);
        Compartment->InterfaceSet.NumEntries--;
    }
    RtlReleaseWriteLock(&Compartment->InterfaceSet.Lock, &LockHandle);

    //
    // Clean up multicast forwarding entries associated with the interface.
    // (mfe -> neighbor -> subinterface -> interface).
    //
    IppDeleteMfes(Compartment, Interface, NULL);

    //
    // Inform the neighbor manager (neighbor set -> packets -> interface).
    //
    IppDeleteNeighborSet(Interface);
    
    //
    // Inform the route manager (route -> interface).
    //
    IppGarbageCollectRoutes(Compartment);
    
    //
    // Inform the paths (path -> source address -> interface).
    //
    IppGarbageCollectPaths(Compartment);
    
    //
    // Garbage collect site prefix entries. 
    //
    IppDeleteSitePrefixes(Compartment, Interface);
     
    //
    // Clean up reassembly buffers associated with the interface.
    //
    IppReassemblyInterfaceCleanup(Interface);

    //
    // Clean up the Offload encapsulation that this protocol set on the NIC
    //
    IppDeleteOffloadEncapsulation(Interface);
    
    //
    // Inform NSI and Nl clients of interface deletion.
    //
    IppNotifyInterfaceChangeToNlClients(Interface, IpDeleteInterfaceEvent);
    IppNotifyInterfaceChange(Interface, 0, NsiDeleteInstance, NULL);

    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_INFORMATION, 
               "IPNG: [%u] Deleted %s interface index %d\n", 
               Interface->Index, 
               Protocol->TraceString,
               Interface->Index);
    
    //
    // Release the reference held for initialization.
    //
    IppDereferenceInterface(Interface);

    return STATUS_PENDING;
}


NTSTATUS
NTAPI
IpFlcUpdateInterface(
    IN PFL_INDICATE_UPDATE_INTERFACE Args
    )
{
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    Interface = IppCast(Args->ClientInterfaceHandle, IP_INTERFACE);
    Protocol = Interface->FlModule->Protocol;

    if (Args->Flags.DlAddressChange) {
        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

        RtlCopyMemory(
            Interface->Identifier,
            Args->Characteristics->Identifier,
            sizeof(Interface->Identifier));
        if (Protocol->RandomizeIdentifiers) {
            IppRandomizeIdentifier(Interface);
        }

        IppRegenerateLinkLayerSuffixAddresses(Interface);
        
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    if (Args->Flags.TaskOffloadChange) {
        //
        // TODO: Do we need to acquire the interface lock here
        //
        NDIS_OFFLOAD OffloadCapabilities  = 
            Args->Characteristics->OffloadCapabilities;

        if (!Protocol->DisableTaskOffload) {
            if (Interface->OffloadSet) {
                IppUpdateOffloadCapabilities(Interface,&OffloadCapabilities);
            } else {
                //
                // If our ealier attempt to set offload had failed,
                // retry by queuing a work item.
                //
                RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
                if (!Interface->SettingOffload && !Interface->OffloadSet) {
                    Interface->SettingOffload = TRUE;
                    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

                    IppSetOffloadChange(Interface);
                } else {
                    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
                }
            }
        }
    }

    return STATUS_SUCCESS;
}


VOID
NTAPI
IpFlcIndicateOffloadEvent(
    IN HANDLE ClientInterfaceHandle,
    IN FL_OFFLOAD_EVENT EventCode,
    IN PVOID OffloadBuffer,
    IN UINT OffloadBufferSize
    )
{
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    PLIST_ENTRY Next, Head;
    KIRQL OldIrql;
    PIP_CLIENT_CONTEXT Client;
    NL_INDICATE_INTERFACE Indicate;

    Interface = IppCast(ClientInterfaceHandle, IP_INTERFACE);
    Protocol = Interface->FlModule->Protocol;
    //
    // Walk the client list, indicating the event to each interested client.
    //
    Head = &Protocol->NlClientSet.Set;
    RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {        
        Client = (PIP_CLIENT_CONTEXT)
            CONTAINING_RECORD(Next, IP_CLIENT_CONTEXT, Link);

        if ((Client->Npi.Dispatch->IndicateOffloadEvent == NULL) ||
            !IppReferenceNlClient(Client)) {
            continue;
        }

        Indicate.ClientHandle = Client->Npi.ProviderHandle;
        Indicate.Interface = (PNL_INTERFACE) Interface;

        RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);

        //
        // Now that we have released all locks, we can provide the indication.
        //
        Client->Npi.Dispatch->IndicateOffloadEvent(
            &Indicate, 
            EventCode, 
            OffloadBuffer, 
            OffloadBufferSize);

        RtlAcquireReadLock(&Protocol->NlClientSet.Lock, &OldIrql);
        IppDereferenceNlClient(Client);
    }
    RtlReleaseReadLock(&Protocol->NlClientSet.Lock, OldIrql);
}


NTSTATUS
NTAPI
IpFlcAddSubInterface(
    IN PFL_INDICATE_ADD_SUBINTERFACE Args
    )
/*++

Routine Description:
    
    FL_CLIENT_ADD_SUBINTERFACE Handler.

--*/
{
    NTSTATUS Status;

    PIP_PROTOCOL Protocol;
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface;

    NL_SUBINTERFACE_KEY SubInterfaceKey = {0};
    NL_SUBINTERFACE_RW SubInterfaceRw = {0};

    BOOLEAN FirstSubInterface;


    PASSIVE_CODE();

    Interface = IppCast(Args->ClientInterfaceHandle, IP_INTERFACE);
    Protocol = Interface->FlModule->Protocol;

    //
    // The interface is guaranteed to exist since the FL serializes
    // addition and deletion of and interface with its subinterfaces.
    // Hence we do not take a reference on the interface.
    //

    //
    // Read persistent subinterface configuration.
    //
    SubInterfaceKey.InterfaceLuid = Interface->Luid;
    SubInterfaceKey.SubInterfaceLuid = Args->Identifiers->Luid;
    Status =
        NsiGetAllParameters(
            NsiPersistent,
            Protocol->ModuleId,
            NlSubInterfaceObject,
            &SubInterfaceKey, sizeof(SubInterfaceKey),
            &SubInterfaceRw, sizeof(SubInterfaceRw),
            NULL, 0,
            NULL, 0);
    if (!NT_SUCCESS(Status)) {
        //
        // Proceed with default values if none are configured.
        //
        SubInterfaceRw.NlMtu = Args->Characteristics->Mtu;        
    }

    if ((Interface->MinimumNlMtu != 0) && 
        (SubInterfaceRw.NlMtu > Interface->MinimumNlMtu)) {
        //
        // Limit this to the Interface minimum.
        //
        SubInterfaceRw.NlMtu = Interface->MinimumNlMtu;
    }
        
    //
    // Create the subinterface and insert in various access structures.
    //    
    SubInterface =
        IppCreateSubInterface(
            Interface,
            Args->Identifiers,
            Args->Characteristics,
            &SubInterfaceRw,
            Args->ProviderSubInterfaceHandle,
            &FirstSubInterface);
    if (SubInterface == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    *Args->ClientSubInterfaceHandle = (HANDLE) SubInterface;

    //
    // Inform the address manager when the interface may be addressed.
    //
    if (FirstSubInterface) {
        Status = Protocol->AddressInterface(Interface);
        if (!NT_SUCCESS(Status)) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                       "IPNG: [%u] Addressing interface failed; deleting it\n",
                       Interface->Index);
            goto Done;
        }
    }

    Status = Protocol->InitializeSubInterface(SubInterface);
    if (!NT_SUCCESS(Status)) {
        goto Done;
    }
    
    //
    // TODO (bug# 842000): Inform NSI for event notification. 
    //

Done:
    //
    // Release the extra reference given to us when the sub-interface was
    // initialized. 
    //
    IppDereferenceSubInterface(SubInterface);

    if (!NT_SUCCESS(Status)) {
        //
        // Sub-interface addition failed. Delete the sub-interface. 
        //
        IppDeleteSubInterface(SubInterface);
        IppDereferenceSubInterface(SubInterface);
        return Status;
    }
        
    return STATUS_SUCCESS;
}


VOID
IppDeleteSubInterface(
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    This routine deletes a sub-interface from the list, and cleans up the
    corresponding neighbors, paths and routes.  This can be called as a result
    of the framing layer deleting the sub-interface or because of sub-interface
    intialization failing.  This does not remove the initial reference on the
    sub-interface. 
    
Arguments:

    SubInterface - Supplies the sub-interface to delete.

Return Value:

    None. 

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    KLOCK_QUEUE_HANDLE LockHandle, NeighborSetLockHandle;
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    {
        RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, 
                                      &NeighborSetLockHandle);

        //
        // Delete the subinterface from its set.
        //
        // An alternative design would be to leave the subinterface in its set
        // upon deletion and attempt to cleanup all unreferenced subinterfaces
        // when processing the subinterface timeout.  While this also helps in
        // debugging, it requires care to not reference a deleted subinterface.
        //
        RemoveEntryList(&SubInterface->Link);

        if (Interface->AutoMetric) {
            IppRecomputeMetric(Interface);
        }

        if (SubInterface->OperationalStatus == IfOperStatusUp) {
            Interface->ConnectedSubInterfaces--;
            if (Interface->ConnectedSubInterfaces == 0) {
                //
                // The operational state of the interface just changed
                // to disconnected, so notify clients.
                //
                NSI_SINGLE_PARAM_DESC ParameterDescription = {
                    NsiStructRoDynamic,
                    NULL,
                    sizeof(Interface->ConnectedSubInterfaces),
                    FIELD_OFFSET(NL_INTERFACE_ROD, ConnectedSubInterfaces)};
                ParameterDescription.Parameter = 
                    (PUCHAR) &Interface->ConnectedSubInterfaces;
                IppNotifyInterfaceChange(
                    Interface, 
                    EVENT_TCPIP_MEDIA_DISCONNECT, 
                    NsiParameterNotification,
                    &ParameterDescription);
            }
        }
        
        //
        // Inform the neighbor manager (neighbor -> subinterface).
        //
        IppDeleteNeighborsUnderLock(Interface, SubInterface);

        RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, 
                                        &NeighborSetLockHandle);

        //
        // Unaddress the interface if there are no more sub-interfaces left on
        // the interface. 
        // 
        if (IsListEmpty(&Interface->SubInterfaceSet)) {
            Compartment->Protocol->UnAddressInterface(Interface);
        }
    }
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    // 
    // Inform the mfe manager (mfe -> neighbor -> subinterface).
    //
    IppDeleteMfes(Compartment, NULL, SubInterface);
    
    //
    // Inform the route manager (route -> neighbor -> subinterface).
    //
    IppGarbageCollectRoutes(Compartment);
    
    //
    // Inform the path manager (path -> neighbor -> subinterface).  Do this
    // after the routes have been garbage collected so that the validation does
    // not use the invalid routes.
    //
    IppValidatePaths(Compartment);
}

NTSTATUS
NTAPI
IpFlcDeleteSubInterface(
    IN PFL_INDICATE_DELETE_SUBINTERFACE Args
    )
/*++

Routine Description:
    
    FL_CLIENT_DELETE_SUBINTERFACE Handler.

--*/
{
    PIP_COMPARTMENT Compartment;
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface;

    PASSIVE_CODE();

    SubInterface = IppCast(Args->ClientSubInterfaceHandle, IP_SUBINTERFACE);
    Interface = SubInterface->Interface;
    Compartment = Interface->Compartment;
    
    //
    // Completion will be asynchronous.
    //
    ASSERT(SubInterface->FlDeleteComplete == NULL);    
    SubInterface->FlDeleteComplete = Args->IndicateComplete;

    //
    // Delete the sub-interface from the list of sub-interface.  Cleanup
    // routes, paths and neighbors. 
    //
    IppDeleteSubInterface(SubInterface);
    
    //
    // TODO (bug# 842000): Inform NSI for event notification
    //

    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_INFORMATION, 
               "IPNG: [%u] Deleted %s sub-interface %I64x\n",
               SubInterface->Interface->Index, 
               Compartment->Protocol->TraceString, 
               SubInterface->Luid.Value);

    //
    // Release the reference held for initialization.
    //
    IppDereferenceSubInterface(SubInterface);

    return STATUS_PENDING;
}

VOID
IppValidateSettingsOnReconnectWorker(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:

    Validate interface settings: address/routes on media reconnect. The routine 
    tries to resolve the link layer address of the configured default gateways 
    and if resolution fails, the configured settings are cleared.

    It takes into account the scenario when settings got updated before the 
    unreachability detection returns. 
    
    As this operation can take a second, it needs to be performed at PASSIVE. 
    
Arguments:

    Interface - Supplies the interface that had operational status change.
    
Caller IRQL:

    PASSIVE.

--*/
{
    BOOLEAN SameNetwork;
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_WORK_QUEUE_ITEM MyContext = Context;
    PIP_INTERFACE Interface = (PIP_INTERFACE) MyContext->Context;
    ULONG LinkEpoch = *(ULONG *)(MyContext + 1);
    KIRQL OldIrql;
    
    UNREFERENCED_PARAMETER(DeviceObject);

    IoFreeWorkItem(MyContext->WorkQueueItem);
    ExFreePool(MyContext);

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);
    if (!Interface->MediaReconnected || 
        !IS_LINK_UNCHANGED(Interface, LinkEpoch)) {
        //
        // Perform validation only if media just got reconnected, because we 
        // will fail to remove settings later anyways.
        //
        RtlReleaseReadLock(&Interface->Lock, OldIrql);
        goto Done;
    }
    RtlReleaseReadLock(&Interface->Lock, OldIrql);

    SameNetwork = IppDetectGatewayReachability(Interface);

    if (SameNetwork) {
        goto Done;
    }
    
    //
    // Unable to reach a default gateway. Remove settings.
    //
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    if (!Interface->MediaReconnected || 
        !IS_LINK_UNCHANGED(Interface, LinkEpoch)) {
        //
        // Settings have already been updated or the link changed again.
        //
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        goto Done;
    }
    
    NetioTrace(
        NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
        "IPNG: [%u] failed to reach default gateway. Cleaning settings.\n",
        Interface->Index);

    IppResetAutoConfiguredSettings(Interface, 0);
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

Done:
    IppDereferenceInterface(Interface);
}


VOID
IppValidateSettingsOnReconnect(
    PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Validate interface settings: address/routes on media reconnect.
    We queue up a work item to perform the operation at PASSIVE.

Arguments:

    Interface - Supplies the interface that had operational status change.

Locks: 

    Interface lock is held.
    
Caller IRQL: DISPATCH (Since a lock is held).

--*/
{
    PIO_WORKITEM WorkItem;
    PIP_WORK_QUEUE_ITEM Context;
    ULONG* LinkEpoch;
    
    if (!Interface->FlCharacteristics->DiscoversNeighbors) {
        return;
    }

    Context =
        ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(IP_WORK_QUEUE_ITEM) + sizeof(ULONG),
            IpGenericPoolTag);
    if (Context == NULL) {
        return;
    }
    
    WorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (WorkItem == NULL) {
        ExFreePool(Context);
        return;
    }

    Context->WorkQueueItem = WorkItem;
    IppReferenceInterface(Interface);
    Context->Context = Interface;
    LinkEpoch = (ULONG *)(Context + 1);
    *LinkEpoch = Interface->LinkEpoch;
    
    IoQueueWorkItem(
        WorkItem,
        IppValidateSettingsOnReconnectWorker,
        DelayedWorkQueue,
        Context);
}


VOID
IppReconnectSubInterface(
    IN PIP_SUBINTERFACE SubInterface,
    IN BOOLEAN LogEvent
    )
/*++

Routine Description:

    Reconnect the subinterface.  Called when a media connect notification
    is received (SetSubInterfaceLinkStatus) or when processing a renew
    request by IOCTL_IPV6_UPDATE_INTERFACE (IoctlUpdateInterface).

    Compare ReconnectInterface() in the XP IPv6 stack.

Arguments:

    Interface - Supplies a pointer to an interface.

    LogEvent - Supplies if the event should be logged.

Return Value:

    Packets from the wait queues of deleted neighbors.

Locks:

    Called with the interface already locked.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    ULONG EventCode;
    
    ASSERT(!IppIsInterfaceDisabled(Interface));
    ASSERT(Interface->ConnectedSubInterfaces > 0);
    ASSERT(SubInterface->OperationalStatus == IfOperStatusUp);

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_INFORMATION, 
               "IPNG: [%u] Reconnecting %s sub-interface %I64x\n", 
               Interface->Index,
               Interface->Compartment->Protocol->TraceString,
               SubInterface->Luid.Value);

    IppInvalidateLinkState(Interface);
    
    //
    // Purge potentially obsolete link-layer information.
    // Things might have changed while we were unplugged.
    //
    IppResetNeighborsUnderLock(Interface, SubInterface, FALSE);

    //
    // Rejoin multicast groups and restart Duplicate Address Detection.
    //
    // Preferred unicast addresses are registered with TDI when
    // duplicate address detection completes (or is disabled).
    //
    IppReconnectAddresses(Interface);

    if (Interface->UseRouterDiscovery) {
        IppStartRouterDiscovery(Interface);

        if (!Interface->Advertise) {
            //
            // Remember that this interface was just reconnected,
            // so when we receive a Router Advertisement
            // we can take special action.
            //
            Interface->MediaReconnected = TRUE;
        }
    }

    IppValidateSettingsOnReconnect(Interface);
    
    //
    // We might have moved to a new link.
    // Force the generation of a new temporary interface identifier.
    // This only really makes a difference if we generate
    // new addresses on this link - if it's the same link then
    // we continue to use our old addresses, both public & temporary.
    //
    Interface->TemporaryStateCreationTime = 0;

    EventCode = 
        (LogEvent && (Interface->ConnectedSubInterfaces == 1)) ? 
            EVENT_TCPIP_MEDIA_CONNECT : 0;

    {
        NSI_SINGLE_PARAM_DESC ParameterDescription = {
            NsiStructRoDynamic,
            NULL,
            sizeof(Interface->ConnectedSubInterfaces),
            FIELD_OFFSET(NL_INTERFACE_ROD, ConnectedSubInterfaces)};
        ParameterDescription.Parameter =
            (PUCHAR) &Interface->ConnectedSubInterfaces;
        IppNotifyInterfaceChange(
            Interface, 
            EventCode, 
            NsiParameterNotification,
            &ParameterDescription);
    }
}

VOID
IppDisconnectInterface(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    Disconnect the interface.  Called when a media disconnect
    notification is received (SetSubInterfaceLinkStatus) for a connected
    interface.

    Compare DisconnectInterface() in the XP IPv6 stack.

Arguments:

    Interface - Supplies a pointer to an interface.

Locks: 

    Assumes caller holds a write lock on the interface.

Caller IRQL: 

    Must be called at DISPATCH level since a lock is held.

--*/
{
    ASSERT(! IppIsInterfaceDisabled(Interface));
    ASSERT(Interface->ConnectedSubInterfaces == 0);

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    NetioTrace(NETIO_TRACE_INTERFACE, TRACE_LEVEL_INFORMATION, 
               "IPNG: [%u] Disconnecting %s interface %u\n", 
               Interface->Index, 
               Interface->Compartment->Protocol->TraceString,
               Interface->Index);
    
    //
    // Deregister any preferred unicast addresses from clients.
    //
    IppDisconnectAddresses(Interface);
    {
        NSI_SINGLE_PARAM_DESC ParameterDescription = {
            NsiStructRoDynamic,
            NULL,
            sizeof(Interface->ConnectedSubInterfaces),
            FIELD_OFFSET(NL_INTERFACE_ROD, ConnectedSubInterfaces)};
        ParameterDescription.Parameter =
            (PUCHAR) &Interface->ConnectedSubInterfaces;

        IppNotifyInterfaceChange(
            Interface, 
            0, 
            NsiParameterNotification,
            &ParameterDescription);
    }
}

VOID
IppSetSubInterfaceLinkStatusUnderLock(
    IN PIP_SUBINTERFACE SubInterface,
    IN IF_OPER_STATUS OperationalStatus,
    IN ULONG OperationalStatusFlags
    )
/*++

Routine Description:

    Change the interface's link status. In particular,
    set whether the media is connected or disconnected.
  
    May be called when the interface has zero references
    and is already being destroyed.

    Compare SetInterfaceLinkStatus() in the XP IPv6 stack.

Arguments:

    SubInterface - Supplies a pointer to a subinterface.

    OperationalStatus - Supplies the new operational state.

    OperationalStatusFlags - Supplies the operational state flags.

Lock:

    Assumes caller holds the interface lock and the neighbor set lock.

--*/
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    BOOLEAN LogEvent = FALSE;
    
    //
    // Note that media-connect/disconnect events 
    // can be "lost".  We are not informed if the
    // cable is unplugged/replugged while we are
    // shutdown, hibernating, or on standby.
    //

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);

    if (IppIsInterfaceDisabled(Interface)) {
        return;
    }
        
    //
    // Process changes to the subinterface's connected state.
    //
    if (OperationalStatus == IfOperStatusUp) {
        if (SubInterface->OperationalStatus != IfOperStatusUp) {
            //
            // The cable was plugged back in.
            //

            //
            // To reduce noise, log only for physical adapters.
            //
            if (Interface->FlCharacteristics->TunnelType == TUNNEL_TYPE_NONE) {
                LogEvent = TRUE;
            }
            SubInterface->OperationalStatus = OperationalStatus;
            Interface->ConnectedSubInterfaces++;
            
            //
            // Changes in OperationalStatus must
            // invalidate the destination cache.
            //
            IppInvalidateDestinationCache(Interface->Compartment);
        }
        
        //
        // A connect event implies a change in the interface state
        // regardless of whether the interface is already connected.
        // Hence we process it outside the 'if' clause.
        // However, dont log this event unless operational status toggled, as 
        // this may be frequent for wireless NICs.
        //            
        IppReconnectSubInterface(SubInterface, LogEvent);
    } else {

        if (OperationalStatus == IfOperStatusDormant && 
            OperationalStatusFlags == NET_IF_OPER_STATUS_DORMANT_PAUSED) {
            //
            // Stack is being paused. This is expected to be a transient 
            // condition when an LWF comes up. So let it go.
            //
        } else if (SubInterface->OperationalStatus == IfOperStatusUp) {
            //
            // The cable was unplugged.
            //
            SubInterface->OperationalStatus = OperationalStatus;
            Interface->ConnectedSubInterfaces--;
            Interface->MediaReconnected = FALSE;
            
            //
            // Changes in OperationalStatus must
            // invalidate the destination cache.
            //
            IppInvalidateDestinationCache(Interface->Compartment);
            
            if (Interface->ConnectedSubInterfaces == 0) {
                //
                // A disconnect event implies a change in the interface
                // state only if the interface is already connected.
                // Hence we process it inside the 'if' clause.
                //
                // Furthermore, an interface is only disconnected if
                // all subinterfaces are disconnected.
                //
                IppDisconnectInterface(Interface);
            }
        }
    }

    if (Interface->AutoMetric) {
        IppRecomputeMetric(Interface);
    }
}

VOID
IppSetDhcpOperationalStatus(
    IN PIP_PROTOCOL Protocol, 
    IN BOOLEAN DisableMediaSense
    )
/*++

Routine Description:

    This routine sets the global DisableMediaSense to TRUE of FALSE.  The
    routine goes over all the interfaces, updates the DisableMediaSense
    state for each interface and then updates the media sense state for each
    sub-interface.  If DHCP media sense is being disabled, all sub-interfaces
    are moved to connected state.  If it is being enabled, all sub-interfaces
    are moved to their true media sense state.
      
Arguments:

    Protocol - Supplies the protocol.

    DisableMediaSense - Supplies the new value of DisableMediaSense.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    PLIST_ENTRY InterfaceEntry, SubInterfaceEntry;
    PLIST_ENTRY InterfaceList, SubInterfaceList;
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface;
    KLOCK_QUEUE_HANDLE LockHandle, InterfaceLockHandle, NeighborSetLockHandle;
    FL_SUBINTERFACE_CHARACTERISTICS Characteristics;
    FL_REQUEST_QUERY_SUBINTERFACE Request;

    RtlAcquireWriteLock(&Protocol->GlobalInterfaceSet.Lock, &LockHandle);

    if (Protocol->DisableMediaSense == DisableMediaSense) {
        goto Done;
    }

    Protocol->DisableMediaSense = DisableMediaSense;
    InterfaceList = &Protocol->GlobalInterfaceSet.Set;
    for (InterfaceEntry = InterfaceList->Flink; 
         InterfaceEntry != InterfaceList; 
         InterfaceEntry = InterfaceEntry->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(InterfaceEntry, IP_INTERFACE, GlobalLink);
        
        RtlAcquireWriteLockAtDpcLevel(&Interface->Lock, &InterfaceLockHandle);
        RtlAcquireWriteLockAtDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);

        SubInterfaceList = &Interface->SubInterfaceSet;
        for (SubInterfaceEntry = SubInterfaceList->Flink; 
             SubInterfaceEntry != SubInterfaceList;
             SubInterfaceEntry = SubInterfaceEntry->Flink) {
            SubInterface = (PIP_SUBINTERFACE)
                CONTAINING_RECORD(SubInterfaceEntry, IP_SUBINTERFACE, Link);
            
            //
            // If media sense is enabled, set the media sense status to the
            // true media sesnse status.  Otherwise, set the status to
            // connected. 
            //
            if (DisableMediaSense) {
                IppSetSubInterfaceLinkStatusUnderLock(
                    SubInterface, IfOperStatusUp, 0);
            } else {
                Request.ProviderSubInterfaceHandle = SubInterface->FlContext;
                Request.Characteristics = &Characteristics;
                Request.CharacteristicsLength = sizeof(Characteristics);
                
                Status = Interface->FlModule->Npi.Dispatch->
                    QuerySubInterface(&Request);
                if (NT_SUCCESS(Status)) {
                    IppSetSubInterfaceLinkStatusUnderLock(
                        SubInterface, 
                        Characteristics.OperationalStatus,
                        Characteristics.OperationalStatusFlags);
                }
            }
        }

        RtlReleaseWriteLockFromDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);
        RtlReleaseWriteLockFromDpcLevel(
            &Interface->Lock, &InterfaceLockHandle);
    }

Done:
    RtlReleaseWriteLock(&Protocol->GlobalInterfaceSet.Lock, &LockHandle);
}


NTSTATUS
NTAPI
IpFlcUpdateSubInterface(
    IN PFL_INDICATE_UPDATE_SUBINTERFACE Args
    )
/*++

Routine Description:

    Process a change in operational status, MTU, or link speed.

Arguments:

    Args - Supplies the update indication.

Return Value:

    STATUS_SUCCESS

--*/
{
    PIP_SUBINTERFACE SubInterface;
    PIP_INTERFACE Interface;
    KLOCK_QUEUE_HANDLE LockHandle, NeighborSetLockHandle;

    SubInterface = IppCast(Args->ClientSubInterfaceHandle, IP_SUBINTERFACE);
    Interface = SubInterface->Interface;

    if (Args->Flags.OperationalStatusChange) {
        //
        // Handle operational status change.
        //
        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
        RtlAcquireWriteLockAtDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);

        if (!Interface->Compartment->Protocol->DisableMediaSense) {
            IppSetSubInterfaceLinkStatusUnderLock(
                SubInterface, 
                Args->Characteristics->OperationalStatus,
                Args->Characteristics->OperationalStatusFlags);
            Interface->LowPowerMode = 
                (Args->Characteristics->OperationalStatusFlags == 
                    NET_IF_OPER_STATUS_DORMANT_LOW_POWER);
        }

        RtlReleaseWriteLockFromDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    if (Args->Flags.MtuChange) {
        //
        // Handle link MTU change.
        //
        RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);
        SubInterface->NlMtu = Args->Characteristics->Mtu;
        IppUpdateInterfaceMtuUnderLock(Interface);
        RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);
    }       

    if (Args->Flags.SpeedChange) {
        ULONG OldMetric;
        //
        // Handle link speed change.
        //
        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
        RtlAcquireWriteLockAtDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);

        if (Interface->AutoMetric) {
            OldMetric = Interface->Metric;
            IppRecomputeMetric(Interface);

            if (OldMetric != Interface->Metric) {
                //
                // A metric change impacts routing.
                //
                IppInvalidateDestinationCache(Interface->Compartment);
            }
        }        
        RtlReleaseWriteLockFromDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpFlcPnpEvent(
    IN PFL_INDICATE_PNP_EVENT Args
    )
/*++

Routine Description:
    
    FL_CLIENT_PNP_EVENT Handler.

--*/
{
    NTSTATUS Status;
    NL_INDICATE_PNP_EVENT Indication = {0};
    PIP_PROTOCOL Protocol;
    PIP_INTERFACE Interface =
        IppCast(Args->ClientInterfaceHandle, IP_INTERFACE);

    ASSERT(Interface != NULL);
    
    Protocol = Interface->Compartment->Protocol;
    
    //
    // Traditionally only IPv4 indicated PnP events to its clients,
    // we keep the same behavior.
    //
    if ((Protocol->Level != IPPROTO_IP) ||
        (Protocol->PnpClientContext == NULL)) {
        return STATUS_SUCCESS;
    }
    
    //
    // Reference the client's context to be released when this pnp event is
    // completed.
    //
    if (IppReferencePnpEventClientContext(Protocol) != TRUE) {
        return STATUS_SUCCESS;
    }
    
    //
    // Save the context needed for completion and call into the client.
    // TransportReserved is an array of 4 PVOIDs, NL reserves 1 for its own use
    // and the callee may use the rest (Note - callee should only be tdx).
    //
    Args->NetPnpEvent->TransportReserved[0] =
        (ULONG_PTR) Args->IndicateComplete;
        
    Indication.ProviderProtocol = Protocol->Level;
    if (Interface != NULL) {
        Indication.Luid = Interface->Luid;
    }
    Indication.PhysicalDeviceObject = Args->PhysicalDeviceObject;
    Indication.NetPnpEvent = Args->NetPnpEvent;
    Indication.ProviderContext = Interface;
    
    Status = Protocol->PnpClientContext->Npi.Dispatch->
        PnpEventInterfaceNotification(&Indication);

    if (Status != STATUS_PENDING) {
        IppDereferencePnpEventClientContext(Protocol);
    }

    return Status;
}


//
// Network Layer Management Provider Handlers.
//
    

NTSTATUS
NTAPI
IpGetAllInterfaceParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Retreive all public parameters of an interface.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNL_INTERFACE_KEY Key = (PNL_INTERFACE_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    PIP_INTERFACE Interface;
    KIRQL OldIrql;
    
    IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_INTERFACE_KEY));

    switch (Args->Action) {
    case NsiGetExact:
        Interface = IppFindInterfaceByLuid(Protocol, &Key->Luid);
        break;

    case NsiGetFirst:
        Interface = IppGetFirstInterface(Protocol);
        break;

    case NsiGetNext:
        Interface = IppGetNextInterface(Protocol, &Key->Luid);
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    if (Interface == NULL) {
        return (Args->Action == NsiGetExact)
            ? STATUS_NOT_FOUND
            : STATUS_NO_MORE_ENTRIES;
    }

    if (Args->Action != NsiGetExact) {
        Key->Luid = Interface->Luid;
    }

    //
    // Take a read lock on the interface so we get a consistent snapshot
    // of the interface configuration.
    //
    RtlAcquireReadLock(&Interface->Lock, &OldIrql);

    if (Args->StructDesc.RwParameterStruct) {
        NL_INTERFACE_RW UNALIGNED *Data = (NL_INTERFACE_RW UNALIGNED *)
            Args->StructDesc.RwParameterStruct;
        SCOPE_LEVEL Level;

        ASSERT(Args->StructDesc.RwParameterStructLength == sizeof(*Data));

        //
        // Caveat: Be sure to initialize all fields.
        //
        Data->AdvertisingEnabled =
            (BOOLEAN) Interface->Advertise;
        Data->ForwardingEnabled =
            (BOOLEAN) Interface->Forward;
        Data->MulticastForwardingEnabled = 
            (BOOLEAN) Interface->ForwardMulticast;
        Data->WeakHostSend =
            (BOOLEAN) Interface->WeakHostSend;
        Data->WeakHostReceive =
            (BOOLEAN) Interface->WeakHostReceive;
        Data->UseNeighborUnreachabilityDetection =
            (BOOLEAN) Interface->UseNeighborUnreachabilityDetection;
        Data->UseAutomaticMetric =
            (BOOLEAN) Interface->AutoMetric;
        Data->UseZeroBroadcastAddress = 
            (BOOLEAN) Interface->UseZeroBroadcastAddress;
        Data->UseBroadcastForRouterDiscovery = 
            (BOOLEAN) Interface->UseBroadcastForRouterDiscovery;
        Data->DhcpRouterDiscoveryEnabled = 
            (BOOLEAN) Interface->DhcpRouterDiscoveryEnabled;
        Data->ManagedAddressConfigurationSupported =
            (BOOLEAN) Interface->ManagedAddressConfiguration;
        Data->OtherStatefulConfigurationSupported =
            (BOOLEAN) Interface->OtherStatefulConfiguration;
        Data->AdvertiseDefaultRoute =
            (BOOLEAN) Interface->AdvertiseDefaultRoute;            

        if (Interface->NetworkCategory == NlincDomainAuthenticated) {
            Data->NetworkCategory = NetworkCategoryDomainAuthenticated;
        }
        else if (Interface->NetworkCategory == NlincPublic) {
            Data->NetworkCategory = NetworkCategoryPublic;
        }
        else if (Interface->NetworkCategory == NlincPrivate) {
            Data->NetworkCategory = NetworkCategoryPrivate;
        }
        else {
            //
            // The network category is unknown in this case. It is up to
            // the caller to interpret this value as she sees fit.
            //
            Data->NetworkCategory = NetworkCategoryUnknown;
        }

        Data->RouterDiscoveryBehavior = Interface->RouterDiscoveryBehavior;

        Data->TypeOfInterface = IppGetInterfaceType(Interface);
        Data->Metric = Interface->Metric;
        Data->BaseReachableTime = Interface->BaseReachableTime;
        Data->RetransmitTime =
            IppTicksToMilliseconds(Interface->RetransmitTicks);
        if (Interface->PathMtuDiscoveryTicks == INFINITE_LIFETIME) {
            Data->PathMtuDiscoveryTimeout = INFINITE_LIFETIME;
        } else {
            Data->PathMtuDiscoveryTimeout = 
                IppTicksToMilliseconds(Interface->PathMtuDiscoveryTicks);
        }
        Data->DadTransmits = Interface->DadTransmits;        
        Data->LinkLocalAddressBehavior = Interface->LinkLocalAddressBehavior;
        Data->LinkLocalAddressTimeout =
            IppTicksToMilliseconds(Interface->LinkLocalAddressTimeout);
        Data->NlMtu = Interface->MinimumNlMtu;
        Data->SitePrefixLength = Interface->DefaultSitePrefixLength;
        Data->MulticastForwardingHopLimit = 
            Interface->MulticastForwardingHopLimit;
        Data->DisableDefaultRoutes =
            Interface->DisableDefaultRoutes;
        Data->SendUnsolicitedNeighborAdvertisementOnDad = 
            Interface->SendUnsolicitedNeighborAdvertisementOnDad;
        Data->LinkLocalAddress= 
                Interface->LinkLocalAddress;

        for (Level = 0; Level < ScopeLevelCount; Level++) {
            //
            // Returns the un-canonicalized zone indices.
            // This means that the zone index for ScopeLevelGlobal is always 0.
            //
            if (Level == ScopeLevelGlobal) {
                Data->ZoneIndices[Level] = 0;
            } else {
                Data->ZoneIndices[Level] =
                    IppGetInterfaceScopeZone(Interface, Level);
            }
        }
    }
    
    if (Args->StructDesc.RoDynamicParameterStruct != NULL) {
        ULONG ExpiryTickCount;

        NL_INTERFACE_ROD UNALIGNED *Data = (NL_INTERFACE_ROD UNALIGNED *)
            Args->StructDesc.RoDynamicParameterStruct;

        ASSERT(Args->StructDesc.RoDynamicParameterStructLength ==
               sizeof(*Data));

        //
        // Caveat: Be sure to initialize all fields.
        //
        Data->Index = Interface->Index;
        Data->CompartmentId = Interface->Compartment->CompartmentId;
        Data->PhysicalDeviceObject =
            (ULONG64)Interface->FlCharacteristics->PhysicalDeviceObject;
        Data->SupportsWakeUpPatterns =
            Interface->FlCharacteristics->WakeUpPatterns;
            
        Data->ReachableTime =
            IppTicksToMilliseconds(Interface->ReachableTicks);
        Data->ConnectedSubInterfaces = Interface->ConnectedSubInterfaces;

        ExpiryTickCount =
            Interface->MulticastQuerierPresent[MULTICAST_DISCOVERY_VERSION1];

        Data->Version1QuerierPresentTime =
            (ExpiryTickCount == 0)
            ? 0
            : IppTicksToMilliseconds(ExpiryTickCount - IppTickCount);
        
        Data->TransmitOffload = Interface->TransmitOffload;
        Data->ReceiveOffload = Interface->ReceiveOffload;        
    }   

    if (Args->StructDesc.RoStaticParameterStruct != NULL) {
        NL_INTERFACE_ROS UNALIGNED *Data = (NL_INTERFACE_ROS UNALIGNED *)
            Args->StructDesc.RoStaticParameterStruct;

        ASSERT(Args->StructDesc.RoStaticParameterStructLength ==
               sizeof(*Data));

        Args->StructDesc.RoStaticParameterStructLength = sizeof(*Data);
        Data->SupportsNeighborDiscovery =
            Interface->FlCharacteristics->DiscoversNeighbors;
        Data->SupportsRouterDiscovery =
            Interface->FlCharacteristics->DiscoversRouters;

        Data->InterfaceType = Interface->FlCharacteristics->InterfaceType;
        Data->TunnelType = Interface->FlCharacteristics->TunnelType;
    }

    RtlReleaseReadLock(&Interface->Lock, OldIrql);

    IppDereferenceInterface(Interface);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IpGetAllInterfaceHopParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Retreive the hop count parameter of an interface.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNL_INTERFACE_KEY Key = (PNL_INTERFACE_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    PIP_INTERFACE Interface;
    KIRQL OldIrql;
    
    IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_INTERFACE_KEY));

    switch (Args->Action) {
    case NsiGetExact:
        Interface = IppFindInterfaceByLuid(Protocol, &Key->Luid);
        break;

    case NsiGetFirst:
        Interface = IppGetFirstInterface(Protocol);
        break;

    case NsiGetNext:
        Interface = IppGetNextInterface(Protocol, &Key->Luid);
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    if (Interface == NULL) {
        return (Args->Action == NsiGetExact)
            ? STATUS_NOT_FOUND
            : STATUS_NO_MORE_ENTRIES;
    }

    if (Args->Action != NsiGetExact) {
        Key->Luid = Interface->Luid;
    }

    //
    // Take a read lock on the interface so we get a consistent snapshot
    // of the interface configuration.
    //
    RtlAcquireReadLock(&Interface->Lock, &OldIrql);

    if (Args->StructDesc.RoDynamicParameterStruct != NULL) {
        NL_INTERFACE_HOP_ROD UNALIGNED *Data = 
            (NL_INTERFACE_HOP_ROD UNALIGNED *)
                Args->StructDesc.RoDynamicParameterStruct;

        ASSERT(Args->StructDesc.RoDynamicParameterStructLength ==
               sizeof(*Data));

        //
        // Caveat: Be sure to initialize all fields.
        //
        Data->EstimatedHopCountToRemoteDestinations =
            (RECEIVED_HOP_COUNT_MASK + 1 - Interface->MinimumReceivedHopCount)
            & RECEIVED_HOP_COUNT_MASK;
        Interface->MinimumReceivedHopCount = RECEIVED_HOP_COUNT_MASK + 1;
    }   

    RtlReleaseReadLock(&Interface->Lock, OldIrql);

    IppDereferenceInterface(Interface);

    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpSetAllInterfaceParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Updates public parameters of an interface.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{   
    NTSTATUS Status = STATUS_SUCCESS;
    
    switch (Args->Transaction) {
        case NsiTransactionNone:
            Status = IppValidateSetAllInterfaceParameters(Args);
            if (NT_SUCCESS(Status)) {
                Status = IppCommitSetAllInterfaceParameters(Args);
            }
            break;
        case NsiTransactionCancel:
            IppCancelSetAllInterfaceParameters(Args);
            break;
        case NsiTransactionCommit:
            Status = IppCommitSetAllInterfaceParameters(Args);
            break;
        case NsiTransactionValidate:
            Status = IppValidateSetAllInterfaceParameters(Args);
            break;
        default:
            Status = STATUS_INVALID_PARAMETER;
    }
    return Status;
}

NTSTATUS
NTAPI
IpGetAllSubInterfaceParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Retreive all public parameters of a subinterface.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNL_SUBINTERFACE_KEY Key =
        (PNL_SUBINTERFACE_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client = (PNMP_CLIENT_CONTEXT) Args->ProviderHandle;
    PIP_PROTOCOL Protocol = Client->Protocol;
    PIP_SUBINTERFACE SubInterface;

    IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(NL_SUBINTERFACE_KEY));

    switch (Args->Action) {
    case NsiGetExact:
        SubInterface = IppFindSubInterfaceByLuid(Protocol,
                                           &Key->InterfaceLuid,
                                           &Key->SubInterfaceLuid);
        break;

    case NsiGetFirst:
        SubInterface = IppGetFirstSubInterface(Protocol);
        break;

    case NsiGetNext:
        SubInterface = IppGetNextSubInterface(Protocol,
                                              &Key->InterfaceLuid, 
                                              &Key->SubInterfaceLuid);
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    if (SubInterface == NULL) {
        return (Args->Action == NsiGetExact)
            ? STATUS_NOT_FOUND
            : STATUS_NO_MORE_ENTRIES;
    }

    if (Args->Action != NsiGetExact) {
        Key->InterfaceLuid = SubInterface->Interface->Luid;
        Key->SubInterfaceLuid = SubInterface->Luid;
    }

    if (Args->StructDesc.RwParameterStruct) {
        NL_SUBINTERFACE_RW UNALIGNED *Data = (NL_SUBINTERFACE_RW UNALIGNED *)
            Args->StructDesc.RwParameterStruct;

        ASSERT(Args->StructDesc.RwParameterStructLength == sizeof(*Data));

        //
        // Caveat: Be sure to initialize all fields.
        //
        Data->NlMtu = SubInterface->NlMtu;
    }

    if (Args->StructDesc.RoDynamicParameterStruct) {
        NL_SUBINTERFACE_ROD UNALIGNED *Data = (NL_SUBINTERFACE_ROD UNALIGNED *)
            Args->StructDesc.RoDynamicParameterStruct;
        LONG ProcessorIndex = -1;
        PIP_SUBINTERFACE_STATISTICS Statistics;

        ASSERT(Args->StructDesc.RoDynamicParameterStructLength ==
               sizeof(*Data));

        RtlZeroMemory(Data, sizeof(*Data));
        
        Data->OperationalStatus = SubInterface->OperationalStatus;

        //
        // Total up per-processor statistics.
        //
        while (NetioGetNextActiveProcessor(&ProcessorIndex)) {
            Statistics = SubInterface->PerProcessorStatistics[ProcessorIndex];
            //
            // TODO: Fix this up when we clean up Incorrect statistics.
            //
            if ((ProcessorIndex != 0) && 
                Statistics == SubInterface->PerProcessorStatistics[0]) {
                //
                // This is required for a small inconsistency during driver entry.
                //
                continue;
            }
            Data->InOctets += Statistics->InOctets;
            Data->OutOctets += Statistics->OutOctets;
            Data->InReceives += Statistics->InReceives;
            Data->OutTransmits += Statistics->OutTransmits;
            Data->InHeaderErrors += Statistics->InHeaderErrors;
            Data->InTruncatedPackets += Statistics->InTruncatedPackets;
            Data->InDiscards += Statistics->InDiscards;
            Data->FragmentOks += Statistics->FragmentOks;
            Data->FragmentFails += Statistics->FragmentFailures;
            Data->FragmentCreates += Statistics->FragmentsCreated;
        }

        //
        // If the card supports offload, query offload statistics.
        // TODO: embed IP_OFFLOAD_STATS in NL_SUBINTERFACE_ROD and
        // just call IppAddInterfaceStats.
        //
        {
            NTSTATUS Status;
            IP_OFFLOAD_STATS OffloadStats = {0};
            ULONG Length = sizeof(OffloadStats);
            NDIS_OID Oid = (Protocol->Level == IPPROTO_IPV6) ? 
                                OID_IP6_OFFLOAD_STATS :
                                OID_IP4_OFFLOAD_STATS;

            //
            // Note that we really want subinterface statistics,
            // but the NDIS OID only gets interface statistics.
            // We'll assume for now that there's only one subinterface
            // on an offload-capable interface.
            //
            Status = IppQueryInterfaceProperty(SubInterface->Interface,
                                               FlicReferOid,
                                               Oid,
                                               &OffloadStats,
                                               &Length);
            if (NT_SUCCESS(Status)) {
                Data->InReceives += OffloadStats.InReceives;
                Data->OutTransmits += OffloadStats.OutRequests - 
                                      OffloadStats.OutDiscards -
                                      OffloadStats.OutNoRoutes;
                Data->OutOctets += OffloadStats.OutOctets;
                Data->InHeaderErrors += OffloadStats.InHeaderErrors;
                Data->InTruncatedPackets += OffloadStats.InTruncatedPackets;
                Data->InDiscards += OffloadStats.InDiscards;
            }
        }
    }

    Args->StructDesc.RoStaticParameterStructLength = 0;

    IppDereferenceSubInterface(SubInterface);

    return STATUS_SUCCESS;
}

VOID
IppAddGlobalOffloadStatistics(
    IN PIP_PROTOCOL Protocol,
    IN OUT PNL_GLOBAL_ROD Rod
    )
/*++

Routine Description:

    Adds the statistics for offloaded packets to the global counters.

Arguments:

    Protocol - Supplies the global protocol state.

    Rod - Supplies the statistics without counting offloaded packets.
        Returns the updated statistics taking offload into account.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    IP_OFFLOAD_STATS GlobalStats;
    PIP_INTERFACE Interface;
    IF_LUID Luid;

    PASSIVE_CODE();

    //
    // Synchronize statistics reading with interface deletion.
    // This is so we get consistent values in Protocol->OffloadStats.
    //
    ExAcquireFastMutex(&Protocol->OffloadStatsMutex);

    GlobalStats = Protocol->OffloadStats;

    for (Interface = IppGetFirstInterface(Protocol);
         Interface != NULL;
         Interface = IppGetNextInterface(Protocol, &Luid)) {
        Luid = Interface->Luid;

        IppAddInterfaceStats(Interface, &GlobalStats);

        IppDereferenceInterface(Interface);
    }

    ExReleaseFastMutex(&Protocol->OffloadStatsMutex);

    Rod->InReceives += GlobalStats.InReceives;
    Rod->InOctets += GlobalStats.InOctets;
    Rod->InDelivers += GlobalStats.InDelivers;
    Rod->OutRequests += GlobalStats.OutRequests;
    Rod->OutTransmits += GlobalStats.OutRequests - 
                         GlobalStats.OutDiscards -
                         GlobalStats.OutNoRoutes;
    Rod->OutOctets += GlobalStats.OutOctets;
    Rod->InTruncatedPackets += GlobalStats.InTruncatedPackets;
    Rod->InHeaderErrors += GlobalStats.InHeaderErrors;
    Rod->InDiscards += GlobalStats.InDiscards;
    Rod->OutDiscards += GlobalStats.OutDiscards;
    Rod->OutNoRoutes += GlobalStats.OutNoRoutes;
}

NTSTATUS
NTAPI
IpSetAllSubInterfaceParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Updates public parameters of a subinterface.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    switch (Args->Transaction) {
        case NsiTransactionNone:
            Status = IppValidateSetAllSubInterfaceParameters(Args);
            if (NT_SUCCESS(Status)) {
                IppCommitSetAllSubInterfaceParameters(Args);
            }
            break;
        case NsiTransactionCancel:
            IppCancelSetAllSubInterfaceParameters(Args);
            break;
        case NsiTransactionCommit:
            IppCommitSetAllSubInterfaceParameters(Args);
            break;
        case NsiTransactionValidate:
            Status = IppValidateSetAllSubInterfaceParameters(Args);
            break;
        default:
            Status = STATUS_INVALID_PARAMETER;
    }
    return Status;
}

NTSTATUS
NTAPI
IpRegisterInterfaceChangeNotification(
    IN PNM_REQUEST_REGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Enable interface state change notifications via the NSI.

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
        &ClientContext->InterfaceNotificationContext;

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
IpDeregisterInterfaceChangeNotification(
    IN PNM_REQUEST_DEREGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Disable interface state change notifications via the NSI.

Arguments:

    Request - Supplies a request to disable notifications.

Caller IRQL:

    Must be called at IRQL <= APC level.

--*/
{
    PNMP_CLIENT_CONTEXT ClientContext = 
        (PNMP_CLIENT_CONTEXT) Request->ProviderHandle;
    PNMP_NOTIFICATION_CONTEXT NotificationContext = 
        &ClientContext->InterfaceNotificationContext;

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

NTSTATUS
NTAPI
IpSetAllWakeUpPatternParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Create or delete a wake up pattern.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;
    FLIC_CODE Code;
    PIP_INTERFACE Interface;
    FL_REQUEST_SET_INTERFACE Request = {0};
    
    PNL_WAKE_UP_PATTERN_KEY Key =
        (PNL_WAKE_UP_PATTERN_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);
    
    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength ==
           sizeof(NL_WAKE_UP_PATTERN_KEY));

    if (Args->Transaction != NsiTransactionNone) {
        //
        // Transactions are not supported on the WakeUpPattern.
        //
        return STATUS_INVALID_PARAMETER;
    }

    switch (Args->Action) {
    case NsiSetCreateOrSet:
        Code = FlicAddWakeUpPattern;
        break;

    case NsiSetDelete:
        Code = FlicRemoveWakeUpPattern;
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }
    
    //
    // All operations require a valid interface.
    //
    Interface = IppFindInterfaceByLuid(Client->Protocol, &Key->InterfaceLuid);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    Request.ProviderInterfaceHandle = Interface->FlContext;
    Request.RequestCode = Code;
    Request.RequestBuffer = (PVOID) Key;
    Request.RequestLength = sizeof(*Key);

    Status = Interface->FlModule->Npi.Dispatch->SetInterface(&Request);
    ASSERT(Status != STATUS_PENDING);

    IppDereferenceInterface(Interface);
    
    return Status;
}

VOID
IppFlcUpdatePacketFilterComplete(
    IN PFL_INDICATE_COMPLETE Args
    )
{
    PIP_SET_SESSION_INFO_CONTEXT Context =
        (PIP_SET_SESSION_INFO_CONTEXT) Args->RequestContext;

    if (Context->CompletionRoutine != NULL) {
        (*Context->CompletionRoutine)(
            Context->CompletionContext,
            Args->Status,
            0);
    }

    ExFreePool(Context);
}

NTSTATUS
IppUpdateFlPacketFilter(
    IN PIP_INTERFACE Interface,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    Call down to the framing layer to update the packet filter on
    a given interface.

Arguments:

    Interface - Supplies a pointer to an interface whose packet filter 
        we wish to update.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Locks:

    Assumes caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH_LEVEL since a lock is held.

--*/
{
    FL_REQUEST_SET_INTERFACE Request;
    ULONG RequestedPacketFilter;
    PIP_SET_SESSION_INFO_CONTEXT RequestContext;
    NTSTATUS Status;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // Allocate a request context since the request may pend.
    //
    RequestContext =
        ExAllocatePoolWithTagPriority(
            NonPagedPool,
            sizeof(*RequestContext),
            IpGenericPoolTag,
            LowPoolPriority);
    if (RequestContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RequestContext->CompletionContext = CompletionContext;
    RequestContext->CompletionRoutine = CompletionRoutine;
    
    //
    // The FL will ignore all the other fields so we only initialize
    // the one the FL will look at.
    //
    RequestedPacketFilter = 0;
    if (Interface->FlPromiscuousCount > 0) {
        RequestedPacketFilter |= NDIS_PACKET_TYPE_PROMISCUOUS;
    }
    if (Interface->FlAllMulticastCount > 0) {
        RequestedPacketFilter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
    }

    Request.RequestComplete = IppFlcUpdatePacketFilterComplete;
    Request.RequestContext = RequestContext;
    Request.ProviderInterfaceHandle = Interface->FlContext;
    Request.RequestCode = FlicRequestedPacketFilter;
    Request.RequestBuffer = &RequestedPacketFilter;
    Request.RequestLength = sizeof(RequestedPacketFilter);

    Status = Interface->FlModule->Npi.Dispatch->SetInterface(&Request);

    if (Status != STATUS_PENDING) {
        ExFreePool(RequestContext);
    }

    return Status;
}

NTSTATUS
IppAddPromiscuousReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    Update the promiscuous state of an interface for a session
    moving from RCVALL_OFF to the indicated mode.

Arguments:

    Interface - Supplies a pointer to an interface.

    Mode - Supplies the new mode of the session.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_SUCCESS
    STATUS_PENDING

Locks:

    Assumes caller holds a lock on the session state.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if ((Mode == RCVALL_OFF) || (Mode == RCVALL_SOCKETLEVELONLY)) {
        return STATUS_SUCCESS;
    }

    InterlockedIncrement(&Interface->IpPromiscuousCount);

    if (Mode == RCVALL_ON) {
        KLOCK_QUEUE_HANDLE LockHandle;

        //
        // Take a lock to serialize calls down to the FL.
        //
        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

        Interface->FlPromiscuousCount++;
        if (Interface->FlPromiscuousCount == 1) {
            Status = IppUpdateFlPacketFilter(Interface, 
                                             CompletionContext, 
                                             CompletionRoutine);
        }

        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    return Status;
}

NTSTATUS
IppRemovePromiscuousReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    Update the promiscuous state of an interface for a session
    moving to RCVALL_OFF from the indicated mode.

Arguments:

    Interface - Supplies a pointer to an interface.

    Mode - Supplies the new mode of the session.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_SUCCESS
    STATUS_PENDING

Locks:

    Assumes caller holds a lock on the session state.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if ((Mode == RCVALL_OFF) || (Mode == RCVALL_SOCKETLEVELONLY)) {
        return STATUS_SUCCESS;
    }

    InterlockedDecrement(&Interface->IpPromiscuousCount);

    if (Mode == RCVALL_ON) {
        KLOCK_QUEUE_HANDLE LockHandle;
    
        //
        // Take a lock to serialize calls down to the FL.
        //
        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

        Interface->FlPromiscuousCount--;
        if (Interface->FlPromiscuousCount == 0) {
            Status = IppUpdateFlPacketFilter(Interface, 
                                             CompletionContext, 
                                             CompletionRoutine);
        }

        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    return Status;
}

NTSTATUS
IppAddFlAllMulticastReferenceUnderLock(
    IN PIP_INTERFACE Interface,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    Update the all-multicast state of an interface.

Arguments:

    Interface - Supplies a pointer to an interface.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_SUCCESS
    STATUS_PENDING

Locks:

    Assumes caller holds a lock on the interface.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Caller should take a lock to serialize calls down to the FL.
    //
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    Interface->FlAllMulticastCount++;
    if (Interface->FlAllMulticastCount == 1) {
        Status = IppUpdateFlPacketFilter(Interface, 
                                         CompletionContext, 
                                         CompletionRoutine);
    }

    return Status;
}

NTSTATUS
IppAddAllMulticastReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    Update the all-multicast state of an interface for a session
    moving from RCVALL_OFF to the indicated mode.

Arguments:

    Interface - Supplies a pointer to an interface.

    Mode - Supplies the new mode of the session.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_SUCCESS
    STATUS_PENDING

Locks:

    Assumes caller holds a lock on the session state.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if ((Mode == RCVALL_OFF) || (Mode == RCVALL_SOCKETLEVELONLY)) {
        return STATUS_SUCCESS;
    }

    InterlockedIncrement(&Interface->IpAllMulticastCount);

    if (Mode == RCVALL_ON) {
        KLOCK_QUEUE_HANDLE LockHandle;
        
        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
        Status = 
            IppAddFlAllMulticastReferenceUnderLock(
                Interface, 
                CompletionContext, 
                CompletionRoutine);
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    return Status;
}

NTSTATUS
IppRemoveFlAllMulticastReferenceUnderLock(
    IN PIP_INTERFACE Interface,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    Update the all-multicast state of an interface.

Arguments:

    Interface - Supplies a pointer to an interface.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_SUCCESS
    STATUS_PENDING

Locks:

    Assumes caller holds a lock on the interface.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Caller should take a lock to serialize calls down to the FL.
    //
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    Interface->FlAllMulticastCount--;
    if (Interface->FlAllMulticastCount == 0) {
        Status = IppUpdateFlPacketFilter(Interface, 
                                         CompletionContext, 
                                         CompletionRoutine);
    }

    return Status;
}

NTSTATUS
IppRemoveAllMulticastReference(
    IN PIP_INTERFACE Interface,
    IN RCVALL_VALUE Mode,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    Update the all-multicast state of an interface for a session
    moving to RCVALL_OFF from the indicated mode.

Arguments:

    Interface - Supplies a pointer to an interface.

    Mode - Supplies the old mode of the session.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_SUCCESS
    STATUS_PENDING

Locks:

    Assumes caller holds a lock on the session state.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if ((Mode == RCVALL_OFF) || (Mode == RCVALL_SOCKETLEVELONLY)) {
        return STATUS_SUCCESS;
    }

    InterlockedDecrement(&Interface->IpAllMulticastCount);

    if (Mode == RCVALL_ON) {
        KLOCK_QUEUE_HANDLE LockHandle;

        RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
        Status = 
            IppRemoveFlAllMulticastReferenceUnderLock(
                Interface, 
                CompletionContext, 
                CompletionRoutine);
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    }

    return Status;
}

//
// Following are routines shared internally between eQoS and NL. 
// Declared in nlnpip.h. 
//

NL_INTERFACE_NETWORK_CATEGORY_STATE
NlppQueryNetworkCategoryState(
    IN CONST PNL_INTERFACE Interface
    ) 
/*++

Routine Description:

    This routine returns the network category property to the caller. 

Arguments:

    Interface - Supplies a pointer to an interface. Caller guarantees its 
    validity.

Return Value:

    NL_INTERFACE_NETWORK_CATEGORY_STATE

Comments:

    Reading from that flag doesn't require lock. Caller just needs a 
    snapshot of whatever value the flag is at the time of query.

--*/
{
    PIP_INTERFACE IpInterface = IppCast(Interface, IP_INTERFACE);

    ASSERT(IpInterface !=  NULL);
    ASSERT(IpInterface->NetworkCategory <= NlincCategoryStateMax);

    return (NL_INTERFACE_NETWORK_CATEGORY_STATE)
        IpInterface->NetworkCategory;
}

NTSTATUS
IppAddRemoveSubinterfacesProcessorContext(
    IN PIP_INTERFACE Interface,
    IN ULONG ProcessorIndex,
    IN BOOLEAN ProcessorAdded
    )
/*++

Routine Description:

    Subinterface Processor Add Handler. It calls the subinterface 
    handler for each subinterface.

Arguments:
    Interface - Interface to expand.
    ProcessorIndex - Index of the processor that is being modified.

    ProcessorAdded - Added or removed. Remove is not supported today.
        But we can get called to remove due to an add failure.
        
Return Value:
    NTSTATUS. On the remove path this should return success.

Locks Held:
    Global Inteface Set, InterfaceLock.

IRQL == DISPATCH
--*/              
{
    NTSTATUS Status = STATUS_SUCCESS;
    PLIST_ENTRY NextSubInterface, HeadSubInterface;
    KLOCK_QUEUE_HANDLE  NeighborSetLockHandle;
    PIP_SUBINTERFACE SubInterface;

    //
    // You cannot hot add the very first processor!
    //
    ASSERT(ProcessorIndex != 0);

    RtlAcquireWriteLockAtDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);
    HeadSubInterface = &Interface->SubInterfaceSet;
    for (NextSubInterface = HeadSubInterface->Flink; 
           NextSubInterface != HeadSubInterface; 
           NextSubInterface = NextSubInterface->Flink) {
            
        SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(NextSubInterface, IP_SUBINTERFACE, Link);

        if (ProcessorAdded) {
            //
            // Check if the context is already allocated. This check is required
            // for race conditions between updating the processor count
            // and the NL specific handler running and a sub-interface getting added.
            // Unallocated contexts will point to the first processor context.
            //
            if (SubInterface->PerProcessorStatistics[ProcessorIndex] == 
                SubInterface->PerProcessorStatistics[0]) {                
                SubInterface->PerProcessorStatistics[ProcessorIndex] = 
                    ExAllocatePoolWithTag(
                        NonPagedPool,
                        sizeof(IP_SUBINTERFACE_STATISTICS),
                        IpSubInterfacePoolTag);
                if (SubInterface->PerProcessorStatistics[ProcessorIndex] == NULL) {
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    SubInterface->PerProcessorStatistics[ProcessorIndex] = 
                        SubInterface->PerProcessorStatistics[0];   
                    goto ReleaseLock;
                }
                
                RtlZeroMemory(
                    SubInterface->PerProcessorStatistics[ProcessorIndex],
                    sizeof(IP_SUBINTERFACE_STATISTICS));
            }            
        } else {            
            if (SubInterface->PerProcessorStatistics[ProcessorIndex] != 
                 SubInterface->PerProcessorStatistics[0]) {
                ExFreePool(SubInterface->PerProcessorStatistics[ProcessorIndex]);
                SubInterface->PerProcessorStatistics[ProcessorIndex] = 
                    SubInterface->PerProcessorStatistics[0];            
            }
        }            
    }

ReleaseLock:           
    RtlReleaseWriteLockFromDpcLevel(
        &Interface->NeighborSetLock, &NeighborSetLockHandle);    
    return Status;        
}

NTSTATUS
IppAddRemoveInterfaceProcessorContext (
    IN PIP_INTERFACE Interface,
    IN ULONG ProcessorIndex,
    IN BOOLEAN ProcessorAdded
    )
/*++

Routine Description:

    Interface Processor Add Handler. It calls the subinterface 
    handler for each subinterface.

Arguments:
    Interface - Interface to expand.
    ProcessorIndex - Index of the processor that is being modified.

    ProcessorAdded - Added or removed. Remove is not supported today.
        But we can get called to remove due to an add failure.
        
Return Value:
    NTSTATUS. On the remove path this should return success.

Locks Held:
    Global Inteface Set.

IRQL == DISPATCH
--*/          
{
    KLOCK_QUEUE_HANDLE InterfaceLockHandle;
    NTSTATUS Status = STATUS_SUCCESS;
    RtlAcquireWriteLockAtDpcLevel(&Interface->Lock, &InterfaceLockHandle);

    if (ProcessorAdded) {
        //
        // Check if the context is already allocated. This check is required
        // for race conditions between updating the processor count
        // and the NL specific handler running and an interface getting added.
        // Unallocated contexts will point to the first processor context.
        //
        // You cannot hot add the very first processor!
        //
        ASSERT(ProcessorIndex != 0);
        if (Interface->PerProcessorStatistics[ProcessorIndex] == 
            Interface->PerProcessorStatistics[0]) {
            Interface->PerProcessorStatistics[ProcessorIndex] = 
                ExAllocatePoolWithTag(
                    NonPagedPool, 
                    sizeof(IP_INTERFACE_STATISTICS), 
                    IpInterfacePoolTag);

            if (Interface->PerProcessorStatistics[ProcessorIndex]  == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;            
                Interface->PerProcessorStatistics[ProcessorIndex]  = 
                    Interface->PerProcessorStatistics[0];
                goto ReleaseLock;
            }
            
            RtlZeroMemory(
                Interface->PerProcessorStatistics[ProcessorIndex],
                sizeof(IP_INTERFACE_STATISTICS));        
        }
    } else {
        if (Interface->PerProcessorStatistics[ProcessorIndex] != 
            Interface->PerProcessorStatistics[0]) {
            ExFreePool(Interface->PerProcessorStatistics[ProcessorIndex]);
            Interface->PerProcessorStatistics[ProcessorIndex]  = 
                Interface->PerProcessorStatistics[0];
        }
    }    

    Status = 
        IppAddRemoveSubinterfacesProcessorContext(
            Interface, ProcessorIndex, ProcessorAdded);
    if (!NT_SUCCESS(Status)) {
            goto ReleaseLock;
        }        
    
ReleaseLock:
    RtlReleaseWriteLockFromDpcLevel(
        &Interface->Lock, &InterfaceLockHandle);
    return Status;
}
NTSTATUS
IppInterfaceListProcessorAddRemoveHandler(
    IN PIP_PROTOCOL Protocol,
    IN ULONG ProcessorIndex,
    IN BOOLEAN ProcessorAdded
    )
/*++

Routine Description:

    Interface/Subinterface Processor Add Handler.

Arguments:
    Protocol - Ipv4/Ipv6 global.
    ProcessorIndex - Index of the processor that is being modified.

    ProcessorAdded - Added or removed. Remove is not supported today.
        But we can get called to remove due to an add failure.
        
Return Value:
    NTSTATUS. On the remove path this should return success.
--*/                     
{
    NTSTATUS Status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE GlobalLockHandle;    
    PLIST_ENTRY Next, Head;
    PIP_INTERFACE Interface;
        
    RtlAcquireWriteLock(&Protocol->GlobalInterfaceSet.Lock, &GlobalLockHandle);

    Head = &Protocol->GlobalInterfaceSet.Set;
    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Next, IP_INTERFACE, GlobalLink);
        
        Status = 
            IppAddRemoveInterfaceProcessorContext(
                Interface, ProcessorIndex, ProcessorAdded);        
        if (!NT_SUCCESS(Status)) {
            goto ReleaseLock;
        }                                
    }

ReleaseLock:
    RtlReleaseWriteLock(&Protocol->GlobalInterfaceSet.Lock, &GlobalLockHandle);        
    return Status;
}
