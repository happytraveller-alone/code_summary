/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    binding.c

Abstract:

    This module contains generic NMR binding management code for
    network layer providers (IPv4 and IPv6).

Author:

    Mohit Talwar (mohitt) Mon Dec 16 18:22:58 2002

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "binding.tmh"

BOOLEAN
IppRegisterNlClientReceiver(
    IN PIP_CLIENT_CONTEXT NlClient,
    IN HANDLE LocalEndpoint
    )
/*++

Routine Description:

    Register a network layer client in the array of protocols
    (one for each next header value).
    
Arguments:

    NlClient - Supplies the network layer client to register.
    
Return Value:

    TRUE if the client is successfully registered, FALSE otherwise.
    
Caller LOCK: Client Set Lock (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    ULONG ProtocolId = NlClient->Npi.Dispatch->UpperLayerProtocolId;
    PIP_PROTOCOL Protocol = NlClient->Protocol;
    PIP_RECEIVE_DEMUX Demux = &Protocol->ReceiveDemux[ProtocolId];

    ASSERT_WRITE_LOCK_HELD(&Protocol->NlClientSet.Lock);

    if (!RoIsDeleted(&Demux->Reference)) {
        //
        // There is already a client registered.
        //
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Failed duplicate receive handler for %s %x\n", 
                   Protocol->TraceString, ProtocolId);
        return FALSE;
    }
    Demux->NlClient = NlClient;
    Demux->IsExtensionHeader = FALSE;
    Demux->LocalEndpoint = LocalEndpoint;
    RoInitialize(&Demux->Reference);
    return TRUE;
}


BOOLEAN
IppDeregisterNlClientReceiver(
    IN PIP_CLIENT_CONTEXT NlClient
    )
/*++

Routine Description:

    Deregister a network layer client from the array of protocols
    (one for each next header value).
    
Arguments:

    NlClient - Supplies the network layer client to deregister.
    
Return Value:

    TRUE if the client has successfully deregistered, FALSE otherwise.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ULONG ProtocolId = NlClient->Npi.Dispatch->UpperLayerProtocolId;
    PIP_PROTOCOL Protocol = NlClient->Protocol;
    PIP_RECEIVE_DEMUX Demux = &Protocol->ReceiveDemux[ProtocolId];

    ASSERT(Demux->InternalReceiveDatagrams == NULL);
    
    return RoUnInitialize(&Demux->Reference);
}

BOOLEAN
IppReferenceNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    )
/*++

Routine Description:

    This routine adds a reference to the network layer client binding. The
    reference might fail if the client binding is in the process of getting
    deleted. 
    
Arguments:

    NlClient - Supplies the network layer client to reference.
    
Return Value:

    TRUE if the client is successfully referenced, FALSE otherwise.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ULONG ProtocolId = NlClient->Npi.Dispatch->UpperLayerProtocolId;
    PIP_PROTOCOL Protocol = NlClient->Protocol;
    PIP_RECEIVE_DEMUX Demux = &Protocol->ReceiveDemux[ProtocolId];

    return RoReference(&Demux->Reference);
}

VOID
IppReferenceValidNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    )
/*++

Routine Description:

    This routine adds a reference to the network layer client binding. The
    difference between IppReferenceValidNlClient and IppReferenceNlClient is
    that this routine can never fail (even if the binding is in the process of
    getting deleted). However, this can only be called if the client has at
    least one reference to the binding (i.e. the binding is valid).
    
Arguments:

    NlClient - Supplies the network layer client to reference.
    
Return Value:

    None. The reference always succeeds.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ULONG ProtocolId = NlClient->Npi.Dispatch->UpperLayerProtocolId;
    PIP_PROTOCOL Protocol = NlClient->Protocol;
    PIP_RECEIVE_DEMUX Demux = &Protocol->ReceiveDemux[ProtocolId];

    RoReferenceValidObject(&Demux->Reference, 1);
}

VOID
IppDereferenceNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    )
{
    ULONG ProtocolId = NlClient->Npi.Dispatch->UpperLayerProtocolId;
    PIP_PROTOCOL Protocol = NlClient->Protocol;
    PIP_RECEIVE_DEMUX Demux = &Protocol->ReceiveDemux[ProtocolId];

    if (RoDereference(&Demux->Reference)) {
        //
        // The client's detach is complete.
        //
        IppDetachNlClientComplete(NlClient);
    }
}


VOID
IppInsertNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    )
{
    PIP_PROTOCOL Protocol = NlClient->Protocol;
    
    ASSERT_WRITE_LOCK_HELD(&Protocol->NlClientSet.Lock);

    InsertHeadList(&Protocol->NlClientSet.Set, &NlClient->Link);
    Protocol->NlClientSet.NumEntries++;
}


VOID
IppRemoveNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    )
{
    PIP_PROTOCOL Protocol = NlClient->Protocol;
    
    ASSERT_WRITE_LOCK_HELD(&Protocol->NlClientSet.Lock);

    RemoveEntryList(&NlClient->Link);
    Protocol->NlClientSet.NumEntries--;
}


VOID
IppDetachNlClientCompleteWorkerRoutine(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_RECEIVE_DEMUX Demux;
    PIP_CLIENT_CONTEXT NlClient = IppCast(Context, IP_CLIENT_CONTEXT);

    Demux = 
        &(NlClient->Protocol->ReceiveDemux
          [NlClient->Npi.Dispatch->UpperLayerProtocolId]);
    
    PASSIVE_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);
    RtlAcquireWriteLock(&NlClient->Protocol->NlClientSet.Lock, &LockHandle);
    {
        IppRemoveNlClient(NlClient);
    }
    RtlReleaseWriteLock(&NlClient->Protocol->NlClientSet.Lock, &LockHandle);

    if (NlClient->Npi.Dispatch->Flags.CreateLocalEndpoint) {
        ASSERT(Demux->LocalEndpoint != NULL);
        WfpAleEndpointTeardownHandler(Demux->LocalEndpoint);
        Demux->LocalEndpoint = NULL;
    }        
    
    IoFreeWorkItem(NlClient->WorkItem);    
    NmrProviderDetachClientComplete(NlClient->PendingDetachBindingHandle);
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: %s NL Client detach complete\n", 
               NlClient->Protocol->TraceString);
}


VOID
FASTCALL
IppDetachNlClientComplete(
    IN PIP_CLIENT_CONTEXT NlClient
    )
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        IoQueueWorkItem(NlClient->WorkItem,
                        IppDetachNlClientCompleteWorkerRoutine,
                        DelayedWorkQueue,
                        (PVOID) NlClient);
    } else {
        IppDetachNlClientCompleteWorkerRoutine(IppDeviceObject,
                                               (PVOID) NlClient);
    }
}


NTSTATUS
NTAPI
IpAttachNlClient(
    IN HANDLE  NmrBindingHandle,
    IN PVOID  ProviderContext,
    IN PNPI_REGISTRATION_INSTANCE  ClientRegistrationInstance,
    IN PVOID  ClientBindingContext,
    IN CONST VOID *ClientDispatch,
    OUT PVOID  *ProviderBindingContext,
    OUT CONST VOID*  *ProviderDispatch
    )
/*++

Routine Description:

    Process a request to attach a client to this provider.

Arguments:

    NmrBindingHandle - Supplies the handle NMR uses to represent a binding.

    ProviderContext - Supplies a pointer to our per provider registration
        context.

    ClientRegistrationInstance - Supplies a pointer to client's registration
        information.

    ClientBindingContext - Supplies a pointer to context client uses to
        represent this binding.

    ClientDispatch - Supplies a pointer to client's dispatch table.

    ReturnProviderBindingContext - On return will contain pointer to provider's
        per binding context.

    ReturnProviderDispatch - On return will contain pointer to provider's
        dispatch table.
        
Return Value:

    STATUS_SUCCESS on success, error code on failure.

Caller IRQL: PASSIVE_LEVEL.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_PROTOCOL Protocol =
        CONTAINING_RECORD(ProviderContext, IP_PROTOCOL, NlProviderNotify);
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_CLIENT_CONTEXT NlClient;
    HANDLE LocalEndpoint = NULL;    

    PASSIVE_CODE();

    UNREFERENCED_PARAMETER(ClientRegistrationInstance);
    //
    // Allocate context for this binding.
    //
    NlClient = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(*NlClient), NlClientContextPoolTag);
    if (NlClient == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    //
    // Remember the client's NPI in our context block.
    //
    RtlZeroMemory(NlClient, sizeof(*NlClient));
    NlClient->Protocol = Protocol;
    NlClient->Signature = IP_CLIENT_CONTEXT_SIGNATURE;
    NlClient->Npi.Dispatch = ClientDispatch;
    NlClient->Npi.ProviderHandle = ClientBindingContext;
    NlClient->NmrBindingHandle = NmrBindingHandle;

    if (NlClient->Npi.Dispatch->Flags.CreateLocalEndpoint) {
        Status = 
            WfpAleEndpointCreationHandler(
                NULL,
                Protocol->Characteristics->NetworkProtocolId,
                0,
                NlClient->Npi.Dispatch->UpperLayerProtocolId,
                PsGetCurrentProcess(),
                NULL,
                NULL,
                NULL,
                &LocalEndpoint);        
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }        
        
    //
    // Instead of creating a work item for every client,
    // we could attempt to cleanup unreferenced clients on a timeout.
    //
    NlClient->WorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (NlClient->WorkItem == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Failure attaching NL Client for %s: "
                   "Could not allocate WorkItem\n",
                   Protocol->TraceString);
        ExFreePool(NlClient);
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Our NPI that the client will use when it calls on us will have
    // this context block as its handle.
    //
    *ProviderBindingContext = NlClient;
    *ProviderDispatch = Protocol->NlProviderDispatch;

    //
    // Insert the client if there is not one already registered.
    //
    RtlAcquireWriteLock(&Protocol->NlClientSet.Lock, &LockHandle);
    {
        if (IppRegisterNlClientReceiver(NlClient, LocalEndpoint)) {
            IppInsertNlClient(NlClient);
        } else {
            Status = STATUS_UNSUCCESSFUL;
            IoFreeWorkItem(NlClient->WorkItem);    
        }
    }
    RtlReleaseWriteLock(&Protocol->NlClientSet.Lock, &LockHandle);

    if (NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Attached NL Client for %s\n", 
                   Protocol->TraceString);
    } else {
        ExFreePool(NlClient);
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error attaching NL Client for %s (0x%x)\n", 
                   Protocol->TraceString, Status);
    }
        
    return Status;
}


NTSTATUS
NTAPI
IpDetachNlClient(
    IN PVOID  ProviderBindingContext
    )
/*++

Routine Description:

    Process a request to detach a client from this provider.

Arguments:

    ProviderBindingContext - Supplies the pointer to context provider uses
        to represent this binding.
        
Return Value:

    STATUS_PENDING.  Completion is always asynchronous.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_CLIENT_CONTEXT NlClient = 
        IppCast(ProviderBindingContext , IP_CLIENT_CONTEXT);


    NlClient->PendingDetachBindingHandle = NlClient->NmrBindingHandle;
        
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: %s NL Client detach started\n", 
               NlClient->Protocol->TraceString);

    if (IppDeregisterNlClientReceiver(NlClient)) {
        //
        // The client's detach is complete.
        //
        IppDetachNlClientCompleteWorkerRoutine(IppDeviceObject,
                                               (PVOID) NlClient);
    }
    return STATUS_PENDING;
}


VOID
NTAPI
IpCleanupNlClient(
    IN PVOID  ProviderBindingContext
    )
{
    ExFreePool(ProviderBindingContext);
}


VOID
NTAPI
IpDeregisterNlProviderComplete(
    IN PVOID  ProviderContext
    )
{
    PIP_PROTOCOL Protocol =
        CONTAINING_RECORD(ProviderContext, IP_PROTOCOL, NlProviderNotify);

    IppDefaultStopRoutine(Protocol);
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: %s NL Provider deregistration complete\n",
               Protocol->TraceString);
}


NTSTATUS
IppStartNlp(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    IppInitializeLockedList(&Protocol->NlClientSet);
    
    //
    // Register as a network layer provider.
    //
    Status = NmrRegisterProvider(&Protocol->NlProviderNotify,
                                 &Protocol->NlProviderNotify,
                                 &Protocol->NlProviderHandle);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error registering as an %s NL Provider (0x%x)\n",
                   Protocol->TraceString, Status);
        IppUninitializeLockedList(&Protocol->NlClientSet);
        return Status;
    }

    IppDefaultStartRoutine(Protocol, IMS_NL_PROVIDER);
    return STATUS_SUCCESS;
}


NTSTATUS
IppStopNlp(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Protocol);

    Status = NmrDeregisterProvider(Protocol->NlProviderHandle);
    ASSERT(Status == STATUS_PENDING);

    return Status;
}

NTSTATUS
IppWaitNlp(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Protocol);

    Status = NmrWaitForProviderDeregisterComplete(Protocol->NlProviderHandle);
    ASSERT(Status == STATUS_SUCCESS);
    IpDeregisterNlProviderComplete(&Protocol->NlProviderNotify);

    return Status;
}

VOID
IppCleanupNlp(
    IN PIP_PROTOCOL Protocol
    )
{
    IppUninitializeLockedList(&Protocol->NlClientSet);
}
