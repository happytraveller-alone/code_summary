/*++

Copyright (c) Microsoft Corporation

Module Name:

    ctrl.c

Abstract:

    This module implements various miscellaneous ICMP functions for the send
    and receive path that is protocol independent.

Author:

    Stephanie Song (weiyings) 16-May-2003

Environment:

    kernel mode only

--*/

#include "precomp.h"

IP_SESSION_STATE IcmpEchoRequestSessionState = {
    NULL,                       // InterfaceList.
    NULL,                       // MulticastInterface.
    NULL,                       // UnicastInterface.
    NULL,                       // PromiscuousInterface.
    NULL,                       // AllMulticastInterface.
    0,                          // MulticastHopLimit.
    0,                          // UnicastHopLimit.
    {
        FALSE,                  // HeaderInclude.
        FALSE,                  // MulticastLoopback.
        FALSE,                  // DontFragment.
        FALSE,                  // ReceivePacketInfo.
        FALSE,                  // ReceiveHopLimit.
        FALSE,                  // ReceiveInterface.
        FALSE,                  // ReceiveDestination.
        FALSE,                  // ReceiveBroadcast.
        FALSE,                  // TcpOptions.
        FALSE,                  // UseIpSec.
        TRUE,                   // ReceiveRoutingHeader.
        FALSE,                  // DontFragmentSet.        
        FALSE                   // FastPathCompatible.
    },
    0,                          // ProtectionLevel.
};

C_ASSERT((IP_ECHO_REQUEST_TIMER_TABLE_SIZE & (IP_ECHO_REQUEST_TIMER_TABLE_SIZE - 1)) == 0);

BOOLEAN
IppEchoRequestCleanupElement(
    PIP_ECHO_REQUEST_CONTEXT Request,
    PIP_PROTOCOL Protocol
    );


NTSTATUS
IppStartEchoRequestManager(
    PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Initializes all the variables necessary for echo requests to work.

Arguments:

    Protocol - Supplies the IP protocol for which to initialize the request

Return Value:

    STATUS_INSUFFICIENT_RESOURCES or
    STATUS_SUCCESS

--*/
{
    ULONG Counter;
    SID_IDENTIFIER_AUTHORITY SidAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SECURITY_DESCRIPTOR Descriptor = {0};
    PISID EveryoneSid = NULL;
    ULONG AclLength = 0;
    PACL Acl = NULL;
    NA_REQUEST_SET_OBJECT_SECURITY SetSecurity = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN Success;
   
    Protocol->EchoRequestTimerTable = 
        ExAllocatePoolWithTagPriority(NonPagedPool, 
                                      sizeof(RTL_TIMER_WHEEL) +
                                      sizeof(RTL_TIMER_WHEEL_SLOT) * 
                                      IP_ECHO_REQUEST_TIMER_TABLE_SIZE,
                                      TwTableTag,
                                      NormalPagePriority);
    
    if (Protocol->EchoRequestTimerTable == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Success = RtlInitializeTimerWheel(
                Protocol->EchoRequestTimerTable,
                IP_ECHO_REQUEST_TIMER_TABLE_SIZE,
                1, 1, 0);

    ASSERT(Success);
                              
    for (Counter = 0; Counter < IP_ECHO_REQUEST_TABLE_SIZE; Counter++) {
        InitializeListHead(&Protocol->EchoRequestTable[Counter]);
    }
        
    KeInitializeSpinLock(&Protocol->EchoRequestTableLock);
    KeInitializeSpinLock(&Protocol->EchoRequestTimerWheelLock);
    
    Protocol->EchoRequestSequence = IP_ECHO_REQUEST_MIN_SEQUENCE;
    Protocol->EchoShutdown = FALSE;
    Protocol->EchoFailedNotifications = 0;
    Protocol->EchoRequestTimerTableInitialized = 1;

    //
    // Update ACL to allow all clients to create echo requests.
    //
    Status = RtlCreateSecurityDescriptor(&Descriptor,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status)) {
        goto cleanup;
    }

    //
    // Create a SID for everyone group.
    //
    EveryoneSid = ExAllocatePoolWithTag(NonPagedPool,
                                        RtlLengthRequiredSid(1),
                                        IpGenericPoolTag);
    if (EveryoneSid == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    EveryoneSid->SubAuthorityCount = 1;
    EveryoneSid->Revision = 1;
    EveryoneSid->IdentifierAuthority = SidAuthWorld;
    EveryoneSid->SubAuthority[0] = SECURITY_WORLD_RID;

    //
    // Compute the acl length.
    //
    AclLength = sizeof(ACL) + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
        RtlLengthSid(EveryoneSid);

    //
    // Allocate memory for the ACL.
    //
    Acl = ExAllocatePoolWithTag(NonPagedPool,
                                AclLength,
                                IpGenericPoolTag);
    if (Acl == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    //
    // Create ACL.
    //
    Status = RtlCreateAcl(Acl, AclLength, ACL_REVISION);
    if (!NT_SUCCESS(Status)) {
        goto cleanup;
    }

    //
    // Add ACE to ACL.
    //
    Status = RtlAddAccessAllowedAceEx(Acl,
                                      ACL_REVISION,
                                      CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                                      KEY_WRITE | KEY_READ,
                                      EveryoneSid);
    ASSERT(NT_SUCCESS(Status));
    if (!NT_SUCCESS(Status)) {
        goto cleanup;
    }

    //
    // Set this ACL to be the security descriptor.
    //
    Status = RtlSetDaclSecurityDescriptor(&Descriptor,
                                          TRUE,
                                          Acl,
                                          FALSE);
    ASSERT(NT_SUCCESS(Status));
    
    SetSecurity.ModuleDesc.ModuleId = Protocol->ModuleId;
    SetSecurity.ModuleDesc.ObjectIndex = NlEchoRequestObject;
    SetSecurity.SecurityDescriptor = &Descriptor;
    SetSecurity.Length = AclLength;

    Status = NsiSetObjectSecurity(&SetSecurity);
    if (Status != STATUS_SUCCESS) {
        goto cleanup;
    }
    
    IppDefaultStartRoutine(Protocol, IMS_ECHO_REQUEST_MANAGER);

  cleanup:

    if (Acl != NULL) {
        ExFreePool(Acl);
    }
    if (EveryoneSid != NULL) {
        ExFreePool(EveryoneSid);
    }

    if (!NT_SUCCESS(Status)) {
        KeUninitializeSpinLock(&Protocol->EchoRequestTableLock);
        KeUninitializeSpinLock(&Protocol->EchoRequestTimerWheelLock);
        RtlCleanupTimerWheel(Protocol->EchoRequestTimerTable);
        ExFreePool(Protocol->EchoRequestTimerTable);
    }

    return Status;
}

NTSTATUS
IppCleanupEchoRequestManager(
    PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Called at shutdown time to cleanup context associated with echo clients.

Arguments:

    Protocol - Supplies the protocol for which we are to deinitialize.

Return Value:

    STATUS_DELETE_PENDING if we're trying to deregister with the NSI.
    STATS_SUCCESS on success.

--*/
{
    KIRQL OldIrql;
    ULONG Counter;
    PLIST_ENTRY ListEntry, NextEntry;
    PIP_ECHO_REQUEST_CONTEXT EchoRequest;
    BOOLEAN Cleanup;
    BOOLEAN Wait = FALSE;
    ULONG PoolTag = 0;
    
    //
    // Clear all requests by notifying the clients first then cleaning up.
    //
    if (Protocol->Level == IPPROTO_IP) {
        PoolTag = Ip4EchoPoolTag;
    } else if (Protocol->Level == IPPROTO_IPV6) {
        PoolTag = Ip6EchoPoolTag;
    } else {
        ASSERT(FALSE);
    }
    
    KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
    for (Counter = 0; Counter < IP_ECHO_REQUEST_TABLE_SIZE; Counter++) {
        ListEntry = Protocol->EchoRequestTable[Counter].Flink;
        
        if (ListEntry == &Protocol->EchoRequestTable[Counter]) {
            break;
        }

        NextEntry = ListEntry->Flink;
        EchoRequest = CONTAINING_RECORD(ListEntry,
                                           IP_ECHO_REQUEST_CONTEXT,
                                           Link);
            
        KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);
        
        //
        // If object has been completed simply remove it.
        //
        if (EchoRequest->RequestCompleted &&
            EchoRequest->ClientNotified) {

            IppRemoveEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
            KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
            IppDereferenceEchoRequest(EchoRequest);
        } else if (EchoRequest->RequestCompleted &&
                   !EchoRequest->ClientNotified) {
            //  
            // If object has been completed but due to memory problems we
            // didn't notify the client simply go to the next entry and let
            // the timer routine take care of this entry.
            //
            Wait = TRUE;
        } else {
            Cleanup = IppEchoRequestCleanupElement(EchoRequest, Protocol);

            if (Cleanup) {
                IppRemoveEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
                KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
                IppDereferenceEchoRequest(EchoRequest);
            } else {
                Wait = TRUE;
            }
        }
        
        ListEntry = NextEntry;
    }
    
    if (Wait) {
        KeInitializeEvent(&Protocol->EchoShutdownEvent, NotificationEvent, FALSE);
        Protocol->EchoShutdown = TRUE;
    }
    
    KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
    if (Wait) {
        KeWaitForSingleObject(&Protocol->EchoShutdownEvent, Executive,
                              KernelMode, FALSE, NULL);
    }
    
    InterlockedDecrement(&Protocol->EchoRequestTimerTableInitialized);
    Protocol->EchoShutdown = FALSE;
   
    KeUninitializeSpinLock(&Protocol->EchoRequestTableLock);
    KeUninitializeSpinLock(&Protocol->EchoRequestTimerWheelLock); 

    RtlCleanupTimerWheel(Protocol->EchoRequestTimerTable);
    ExFreePool(Protocol->EchoRequestTimerTable);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IpRegisterEchoRequestChangeNotification(
    IN PNM_REQUEST_REGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Enable echo request state change notifications via the NSI.

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
        &ClientContext->EchoRequestNotificationContext;

    //
    // Take a reference on the attachment.
    //
    if (!RoReference(&ClientContext->Protocol->NmClientReferenceObject)) {
        return STATUS_DELETE_PENDING;
    }

    ASSERT(RoIsUnInitialized(&NotificationContext->ReferenceObject));
    RoInitialize(&NotificationContext->ReferenceObject);

    return STATUS_SUCCESS;
}

VOID
NTAPI
IpDeregisterEchoRequestChangeNotification(
    IN PNM_REQUEST_DEREGISTER_CHANGE_NOTIFICATION Request
    )
/*++

Routine Description:

    Disable ping  change notifications via the NSI.

Arguments:

    Request - Supplies a request to disable notifications.

Caller IRQL:

    Must be called at IRQL <= APC level.

--*/
{
    PNMP_CLIENT_CONTEXT ClientContext =
        (PNMP_CLIENT_CONTEXT) Request->ProviderHandle;
    PNMP_NOTIFICATION_CONTEXT NotificationContext =
        &ClientContext->EchoRequestNotificationContext;

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



PNET_BUFFER_LIST
IppAllocateNetBufferListForEcho(
    ULONG AllocationSize,
    PNETIO_NET_BUFFER_LIST_COMPLETION_ROUTINE CompletionRoutine,
    PVOID CompletionContext
    )
/*++

Routine Description:

    Allocates a net buffer list describing the echo data passed in by the
    client.

Arguments:

    AllocationSize - Supplies the number of bytes to allocate.
    
    CompletionRoutine - Supplies the completion routine to set in the net
        buffer list
    
    CompletionContext - Supplies the context to use when calling the completion
        routine.
    
Return Value:

    Either a pointer to the net buffer list if successful or NULL.
    
Caller IRQL:

    PASSIVE to DISPATCH

--*/
{
    PMDL Mdl;
    PCHAR Data;
    PNET_BUFFER_LIST NetBufferList = NULL;
    PNET_BUFFER NetBuffer = NULL;
    
    Data = ExAllocatePoolWithTag(NonPagedPool,
                                 AllocationSize,
                                 NlClientRequestPoolTag);
    if (Data == NULL) {
        return NULL;
    }

    //
    // Allocate MDL to describe the buffer.
    //
    Mdl = IoAllocateMdl(Data,
                        AllocationSize,
                        FALSE,
                        FALSE,
                        NULL);
    
    if (Mdl == NULL) {
        ExFreePoolWithTag(Data, NlClientRequestPoolTag);
        return NULL;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    //
    // Now allocate the net buffer and the net buffer list.
    //
    NetBuffer = NetioAllocateNetBuffer(Mdl,
                                       AllocationSize,
                                       0,
                                       FALSE);
                          
    if (NetBuffer == NULL) {
        IoFreeMdl(Mdl);
        ExFreePoolWithTag(Data, NlClientRequestPoolTag);
        return NULL;
    }

    NetBufferList = NetioAllocateAndReferenceNetBufferList(CompletionRoutine,
                                                           CompletionContext,
                                                           FALSE);
    
    if (NetBufferList == NULL) {
        NetioFreeNetBuffer(NetBuffer, FALSE);
        IoFreeMdl(Mdl);
        ExFreePoolWithTag(Data, NlClientRequestPoolTag);
        return NULL;
    }

    NetBufferList->FirstNetBuffer = NetBuffer;

    return NetBufferList;
}

VOID
IppFreeNetBufferListForEcho(
    PNET_BUFFER_LIST NetBufferList,
    BOOLEAN DispatchLevel
    )
/*++

Routine Description:

    Frees a net buffer list that was allocated using
    IppAllocateNetBufferListForEcho.

Arguments:

    NetBufferList - Supplies the net buffer list to free.

    DispatchLevel - Supplies whether the calling process is at DISPATCH_LEVEL
        or not.
    
Return Value:

    None
    
Caller IRQL:

    PASSIVE to DISPATCH

--*/
{
    PVOID DataBuffer;
    PNET_BUFFER Nb = NetBufferList->FirstNetBuffer;

    ASSERT(Nb->Next == NULL);

    //
    // Restore the net buffer list, it started with no bytes.
    //
    NetioRestoreNetBuffer(Nb);
    
    DataBuffer = MmGetSystemAddressForMdlSafe(Nb->MdlChain, LowPagePriority);

    ExFreePoolWithTag(DataBuffer, NlClientRequestPoolTag);
    IoFreeMdl(Nb->MdlChain);
    
    NetioFreeNetBuffer(Nb, DispatchLevel);
    NetioFreeNetBufferList(NetBufferList, DispatchLevel);
}       


#if ECHO_REFHIST
__inline
VOID
IppCleanupEchoRequest(
    PIP_ECHO_REQUEST_CONTEXT EchoRequest
    )
{
    ULONG PoolTag = Ip4EchoPoolTag;

    if (EchoRequest->Protocol->Level != IPPROTO_IP) {
        PoolTag = Ip6EchoPoolTag;
    }
    ASSERT (!EchoRequest->InTable);    
    KeUninitializeSpinLock(&EchoRequest->Lock);
    ExFreePoolWithTag(EchoRequest, PoolTag);
}

#else
__inline
VOID
IppDereferenceEchoRequest(
    PIP_ECHO_REQUEST_CONTEXT EchoRequest
    )
{
    ULONG PoolTag = Ip4EchoPoolTag;

    if (EchoRequest->Protocol->Level != IPPROTO_IP) {
        PoolTag = Ip6EchoPoolTag;
    }
    
    if (InterlockedDecrement(&EchoRequest->ReferenceCount) == 0) {
        ASSERT (!EchoRequest->InTable);
        
        KeUninitializeSpinLock(&EchoRequest->Lock);
        ExFreePoolWithTag(EchoRequest, PoolTag);
    }    
}
#endif

VOID
IppNotifyEchoRequestChangeWorker(
    PDEVICE_OBJECT DeviceObject,
    PVOID Context
    )
/*++

Routine Description:

    This routine is called to notify clients of an echo request's change in
    state. The context is parsed to obtain the key and NSI is called for
    notification.
    
Arguments:

    DeviceObject - Supplies the device object on which the work item was
        created.

    Context - Supplies the context created when the work item was queued.

Return Value:

    None

Caller LOCK:

    None. 

Caller IRQL:

    < DISPATCH_LEVEL.

--*/
{
    NM_INDICATE_PARAMETER_CHANGE NsiArgs = {0};
    PIP_WORK_QUEUE_ITEM MyContext = Context;
    PIP_PROTOCOL Protocol = (PIP_PROTOCOL) MyContext->Context;
    PNMP_CLIENT_CONTEXT ClientContext = Protocol->NmClientContext;
    PNMP_NOTIFICATION_CONTEXT NotificationContext = 
        &ClientContext->EchoRequestNotificationContext;

    PASSIVE_CODE();
    
    UNREFERENCED_PARAMETER(DeviceObject);

    IoFreeWorkItem(MyContext->WorkQueueItem);

    //
    // Create the Nsi notification structure. Both the key and the full ROD
    // structure is passed back up to the client for inspection. This prevents
    // the client from having to call back down at all.
    //
    NsiArgs.ProviderHandle = ClientContext->Npi.ProviderHandle;
    NsiArgs.ObjectIndex = NlEchoRequestObject;
    
    NsiArgs.KeyStructDesc.KeyStructLength = sizeof(NL_ECHO_REQUEST_KEY);
    NsiArgs.KeyStructDesc.KeyStruct =  (PUCHAR) (MyContext + 1);
    NsiArgs.ParamDesc.StructType = NsiStructRoDynamic;
    if (Protocol->Level == IPPROTO_IP) {
        NsiArgs.ParamDesc.ParameterLength = sizeof(IPV4_ECHO_REQUEST_ROD);
    } else {
        NsiArgs.ParamDesc.ParameterLength = sizeof(IPV6_ECHO_REQUEST_ROD);
    }
    NsiArgs.ParamDesc.ParameterOffset = 0;
    NsiArgs.ParamDesc.Parameter = NsiArgs.KeyStructDesc.KeyStruct +
        NsiArgs.KeyStructDesc.KeyStructLength;

    ClientContext->Npi.Dispatch->ParameterChange(&NsiArgs);
    
    if (RoDereference(&NotificationContext->ReferenceObject)) {
        KeSetEvent(&NotificationContext->DeregisterCompleteEvent, 0, FALSE);
    }

    IppDereferenceNsiClientContext(Protocol);
    
    ExFreePool(MyContext);
}


NTSTATUS
IppNotifyEchoRequestChange(
    PIP_ECHO_REQUEST_CONTEXT EchoRequest,
    PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    This routine is called to notify clients of an echo request's change in
    state. This function saves the key structure needed then postpones the
    actual work to an workitem.
    
Arguments:

    EchoRequest - Supplies the echo request for which to notify clients.

    Protocol - Supplies the protocol on which the request was created.

Return Value:

    Status of change request.

Caller LOCK:

    The lock on the EchoRequest structure should be held.

Caller IRQL:

    <= DISPATCH_LEVEL

--*/
{
    PNMP_NOTIFICATION_CONTEXT NotificationContext;
    PIP_WORK_QUEUE_ITEM Context;
    PIO_WORKITEM WorkItem;
    PNL_ECHO_REQUEST_KEY Key;
    PNL_ECHO_REQUEST_ROD Rod;
    ULONG RodSize = sizeof(IPV4_ECHO_REQUEST_ROD);

    if (Protocol->Level != IPPROTO_IP) {
        RodSize = sizeof(IPV6_ECHO_REQUEST_ROD);
    }
    
    //
    // Take a reference on the attachment.  If this succeeds,
    // then we can safely access the NmClientContext.
    //
    if (!RoReference(&Protocol->NmClientReferenceObject)) {
        return STATUS_UNSUCCESSFUL;
    }

    NotificationContext = 
        &Protocol->NmClientContext->EchoRequestNotificationContext;

    //
    // Take a reference on the notification registration.
    // This prevents deregistration from completing until we're done.
    //
    if (!RoReference(&NotificationContext->ReferenceObject)) {
        //
        // There's no one to notify.
        //
        IppDereferenceNsiClientContext(Protocol);
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Queue a workitem.
    //
    Context = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(IP_WORK_QUEUE_ITEM) +
                                    sizeof(NL_ECHO_REQUEST_KEY) +
                                    RodSize,
                                    IpGenericPoolTag);
    if (Context == NULL) {
        RoDereference(&NotificationContext->ReferenceObject);
        IppDereferenceNsiClientContext(Protocol);
        return STATUS_UNSUCCESSFUL;
    }
    
    WorkItem = IoAllocateWorkItem(IppDeviceObject);

    if (WorkItem == NULL) {
        ExFreePool(Context);
        RoDereference(&NotificationContext->ReferenceObject);
        IppDereferenceNsiClientContext(Protocol);
        return STATUS_UNSUCCESSFUL;
    }

    Context->WorkQueueItem = WorkItem;
    Context->Context = Protocol;
    Key = (PNL_ECHO_REQUEST_KEY) (Context + 1);
    Rod = (PNL_ECHO_REQUEST_ROD) (Key + 1);
    
    //
    // Fill in the key structure.
    //
    RtlCopyMemory(Key, &EchoRequest->Key, sizeof(NL_ECHO_REQUEST_KEY));
    RtlCopyMemory(Rod, (EchoRequest + 1), RodSize);
    
    IoQueueWorkItem(WorkItem,
                    IppNotifyEchoRequestChangeWorker,
                    DelayedWorkQueue,
                    Context);
    
    return STATUS_SUCCESS;
}



VOID
IppNotificationTimeoutRoutine(
    KSPIN_LOCK * TableLock,
    PLIST_ENTRY Table,
    ULONG TableSize,
    BOOLEAN ShutdownEventSet,
    KEVENT * ShutdownEvent,
    PULONG NotificationCounter
    )
/*++

Routine Description:

    Runs at dpc to retry notifications that have failed.

Arguments:

    TableLock - Supplies the lock to acquire to ensure exclusive access to the
        table.

    Table - Supplies a pointer to the table to cleanup.

    TableSize - Supplies the number of entries in the table array.

    ShutdownEventSet - Supplies the boolean indicating whether shutdown is waiting
        or not.

    ShutdownEventEvent - Supplies the event to set if shutdown can be
        unblocked.

    NotificationCounter - Supplies the counter which indicates how many
        requests were not successfully indicated to the client.
    
Return Value:

    None
    
Caller Locks:

    No lock should be held when calling this function.

--*/
{
    PIP_ECHO_REQUEST_CONTEXT EchoRequest;
    PLIST_ENTRY CurrentEntry, NextEntry;
    NTSTATUS Status;
    ULONG Counter;
    
    KeAcquireSpinLockAtDpcLevel(TableLock);

    for (Counter = 0; Counter < TableSize; Counter++) {
        CurrentEntry = Table[Counter].Flink;

        while (CurrentEntry != &Table[Counter]) {
            EchoRequest = (PIP_ECHO_REQUEST_CONTEXT)
                CONTAINING_RECORD(CurrentEntry,
                                  IP_ECHO_REQUEST_CONTEXT,
                                  Link);
            KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);
            NextEntry = CurrentEntry->Flink;
            //
            // Notify only the completed requests.
            //
            if (!EchoRequest->ClientNotified && 
                EchoRequest->RequestCompleted) {
                Status = IppNotifyEchoRequestChange((PIP_ECHO_REQUEST_CONTEXT)
                                                    EchoRequest,
                                                    EchoRequest->Protocol);
                if (Status != STATUS_SUCCESS) {
                    KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
                    KeReleaseSpinLockFromDpcLevel(TableLock);
                    return;
                }
                
                EchoRequest->Deleted = TRUE;
                EchoRequest->ClientNotified = TRUE;
                
                IppRemoveEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
                KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
        
                IppDereferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT)
                                          EchoRequest);
                
                if (InterlockedDecrement(NotificationCounter) == 0) {
                    
                    if (ShutdownEventSet) {
                        KeSetEvent(ShutdownEvent, 0, FALSE);
                    }
                    
                    KeReleaseSpinLockFromDpcLevel(TableLock);
                    return;
                }   
            } else {
                KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
            }
            CurrentEntry = NextEntry;
        }
    }   
    KeReleaseSpinLockFromDpcLevel(TableLock);
}


VOID
IppEchoRequestSetTimeout(
    PIP_PROTOCOL Protocol
    )
{
    PIP_ECHO_REQUEST_CONTEXT EchoRequest, NewEchoRequest;
    PNL_ECHO_REQUEST_ROD EchoRequestRod;
    PRTL_TIMER_WHEEL_ENTRY TwEntry;
    NTSTATUS Status;
    
    if (InterlockedCompareExchange(
            &Protocol->EchoRequestTimerTableInitialized,
            1,
            1) != 1) {
        return;
    }

    //
    // First update the Tick Count.
    //
    NewEchoRequest = NULL;
    KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTimerWheelLock);

    RtlUpdateCurrentTimerWheelTick(
        Protocol->EchoRequestTimerTable,
        RtlGetCurrentTimerWheelTick(Protocol->EchoRequestTimerTable) + 1);

    TwEntry = RtlGetNextExpiredTimerWheelEntry(Protocol->EchoRequestTimerTable);
        
    if (NULL != TwEntry) {
        NewEchoRequest = 
            CONTAINING_RECORD(TwEntry, IP_ECHO_REQUEST_CONTEXT, TimerEntry);
        //
        // Obtain a reference, so that the request may not go away.
        //
        IppReferenceEchoRequest(NewEchoRequest);
    }

    KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTimerWheelLock);


    while (NewEchoRequest != NULL) {
        EchoRequest = NewEchoRequest;
        NewEchoRequest = NULL;
                
        KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTableLock);
        KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);

        //
        // Make sure this request has not been completed yet.
        //
        if (!EchoRequest->Deleted && !EchoRequest->RequestCompleted) {
            Protocol = EchoRequest->Protocol;
            
            MmUnlockPages(EchoRequest->ReplyMdl);
            IoFreeMdl(EchoRequest->ReplyMdl);
            EchoRequest->ReplyMdl = NULL;

            EchoRequest->RequestCompleted = TRUE;
            EchoRequestRod = (PNL_ECHO_REQUEST_ROD) (EchoRequest + 1);
            EchoRequestRod->Status = STATUS_TIMEOUT;
            
            //
            // Notify the clients.
            //
            Status = 
                IppNotifyEchoRequestChange(
                    (PIP_ECHO_REQUEST_CONTEXT) EchoRequest,
                    Protocol);

            if (Status == STATUS_SUCCESS) {
                EchoRequest->Deleted = TRUE;
                EchoRequest->ClientNotified = TRUE;

                IppRemoveEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);

                IppDereferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT)
                                          EchoRequest);
            } else {
                InterlockedIncrement(&Protocol->EchoFailedNotifications);
            }
        }

        KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTimerWheelLock);
        //
        // Remove this request from the timer wheel.
        // Note: it is ok to call even if the entry has already been removed 
        // from timer table.
        //
        RtlCleanupTimerWheelEntry(
            Protocol->EchoRequestTimerTable,
            &EchoRequest->TimerEntry);

        KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
        KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTableLock);
        
        TwEntry = 
            RtlGetNextExpiredTimerWheelEntry(Protocol->EchoRequestTimerTable);

        if (TwEntry != NULL) {
            NewEchoRequest =
                CONTAINING_RECORD(TwEntry, IP_ECHO_REQUEST_CONTEXT, TimerEntry);
            //
            // Obtain a reference, so that the request may not go away.
            //
            IppReferenceEchoRequest(NewEchoRequest);
        }
        KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTimerWheelLock);

        IppDereferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
    }

    if (InterlockedCompareExchange(
            &Protocol->EchoFailedNotifications,
            0,
            0) != 0) {
        IppNotificationTimeoutRoutine(
            &Protocol->EchoRequestTableLock,
            Protocol->EchoRequestTable,
            IP_ECHO_REQUEST_TABLE_SIZE,
            Protocol->EchoShutdown,
            &Protocol->EchoShutdownEvent,
            &Protocol->EchoFailedNotifications);
    }
}

BOOLEAN
IppEchoRequestCleanupElement(
    PIP_ECHO_REQUEST_CONTEXT Context,
    PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Purges a request element from the table.

Arguments:

    Context - Supplies the echo request context to cleanup.

    Protocol - Supplies the protocol for which to execute the request.

Return Value:

    If the element is successfully removed, TRUE is returned to indicate the
    caller should clean the element up. Otherwise FALSE is returned.

Caller Locks:

    The lock on the element must be held before calling.

--*/
{
    BOOLEAN Cleanup = FALSE;
    NTSTATUS Status;
    PNL_ECHO_REQUEST_ROD EchoRequestRod;
    
    MmUnlockPages(Context->ReplyMdl);
    IoFreeMdl(Context->ReplyMdl);
    EchoRequestRod = (PNL_ECHO_REQUEST_ROD) (Context + 1);
    
    Context->ReplyMdl = NULL;
    Context->RequestCompleted = TRUE;
    EchoRequestRod->Status = STATUS_CANCELLED;
    
    //
    // Notify the clients.
    //
    Status = IppNotifyEchoRequestChange(Context,
                                        Context->Protocol);
    if (NT_SUCCESS(Status)) {
        Context->ClientNotified = TRUE;
        Cleanup = TRUE;
    } else {
        InterlockedIncrement(&Protocol->EchoFailedNotifications);
    }

    return Cleanup;
}


NTSTATUS
NTAPI
IppGetAllEchoSequenceRequestParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function retrieves the next sequence number to use for sending echo
    packets.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PIP_PROTOCOL Protocol;
    PNL_ECHO_SEQUENCE_REQUEST_ROD Rod;
    PNMP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle,
                                         NMP_CLIENT_CONTEXT);
    
    Protocol = Client->Protocol;

    switch (Args->Action) {
    case NsiGetExact:
        break;
    case NsiGetFirst:
    case NsiGetNext:
        return STATUS_NOT_SUPPORTED;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Only ROD parameter exist for this object.
    //
    if (Args->StructDesc.RoDynamicParameterStructLength != 0) {
        ULONG EchoSequence;
        Rod = (PNL_ECHO_SEQUENCE_REQUEST_ROD)
            Args->StructDesc.RoDynamicParameterStruct;
        
        EchoSequence = InterlockedIncrement(&Protocol->EchoRequestSequence);
        //
        // Some IGDs will munge the Identification field in the request if it 
        // is sent as 0. Hence, bump up the Sequence counter just enough.
        // This may be reverted once IGD's are fixed.
        //
        if (EchoSequence < IP_ECHO_REQUEST_MIN_SEQUENCE) {
            InterlockedExchangeAdd(
                &Protocol->EchoRequestSequence, 
                IP_ECHO_REQUEST_MIN_SEQUENCE);
            EchoSequence += IP_ECHO_REQUEST_MIN_SEQUENCE;
        }        
        Rod->Sequence = EchoSequence;
    }
    
    return STATUS_SUCCESS;
}
