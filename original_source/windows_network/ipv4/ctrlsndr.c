/*++

Copyright (c) Microsoft Corporation

Module Name:

    ctrlsndr.c

Abstract:

    This module implements the functions of the IPv4 Control Sender module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "ctrlsndr.tmh"
#include "ctrlv4.h"

NTSTATUS
Ipv4SetEchoRequestCreate(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args,
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
NTAPI
Ipv4GetAllEchoRequestParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a given echo request.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PIP_PROTOCOL Protocol;
    PIPV4_ECHO_REQUEST_CONTEXT EchoRequest;
    KIRQL OldIrql;
    NL_ECHO_REQUEST_KEY RequestKey;
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
    // Only RW and ROD data exist for echo request objects. First lookup the
    // echo request corresponding to the key passed in then copy any
    // information over.
    //
    RtlCopyMemory(&RequestKey,
                  Args->KeyStructDesc.KeyStruct,
                  sizeof(NL_ECHO_REQUEST_KEY));
    RequestKey.ClientPid = (ULONG) (ULONG_PTR) PsGetCurrentProcessId();
    
    KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
    EchoRequest = (PIPV4_ECHO_REQUEST_CONTEXT)
        IppFindEchoRequest(Protocol->EchoRequestTable,
                           IP_ECHO_REQUEST_TABLE_SIZE,
                           &RequestKey);
        
    if (EchoRequest == NULL) {
        KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);
    KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTableLock);
    
    if (Args->StructDesc.RwParameterStructLength != 0) {
        RtlCopyMemory(Args->StructDesc.RwParameterStruct,
                      &EchoRequest->Rw,
                      sizeof(IPV4_ECHO_REQUEST_RW));
    }

    if (Args->StructDesc.RoDynamicParameterStructLength != 0) {
        RtlCopyMemory(Args->StructDesc.RoDynamicParameterStruct,
                      &EchoRequest->Rod,
                      sizeof(NL_ECHO_REQUEST_ROD));
    }
    KeReleaseSpinLock(&EchoRequest->Lock, OldIrql);
    
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
Ipv4SetAllEchoRequestParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function is actually used to create an echo request. The client passes
    in all the information for the packet, the ICMP packet is created and
    dispatched.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PIP_PROTOCOL Protocol;
    PIP_ECHO_REQUEST_CONTEXT EchoRequest;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;
    NL_ECHO_REQUEST_KEY RequestKey;
    PNMP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle,
                                         NMP_CLIENT_CONTEXT);
    
    Protocol = Client->Protocol;
    RtlCopyMemory(&RequestKey,
                  Args->KeyStructDesc.KeyStruct,
                  sizeof(NL_ECHO_REQUEST_KEY));
    RequestKey.ClientPid = (ULONG) (ULONG_PTR) PsGetCurrentProcessId();
    
    //
    // There are only 2 legal operations using set - create or delete.
    //
    switch (Args->Action) {
    case NsiSetCreateOrSetWithReference:
        
        Status = Ipv4SetEchoRequestCreate(Args, Protocol);
        break;
        
    case NsiSetDeleteWithReference:
        //
        // Locate the matching request and remove it. Stop any timers running
        // on it and remove it from the timer table.
        //
        KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
        
        EchoRequest =
            IppFindEchoRequest(Protocol->EchoRequestTable,
                               IP_ECHO_REQUEST_TABLE_SIZE,
                               &RequestKey);
        
        if (EchoRequest == NULL) {
            KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
            Status = STATUS_NOT_FOUND;
            break;
        }
        
        IppRemoveEchoRequest(EchoRequest);
        
        //
        // The receive path could be accessing the same element, for all
        // calls that access this element, it is required to hold the table
        // lock when it acquires the lock on the request itself. This means
        // the following three lines of code guarantees that there will be
        // no thread accessing the context field when it is completed.
        //
        KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);
        
        EchoRequest->Deleted = TRUE;
        if (EchoRequest->ReplyMdl != NULL) {
            MmUnlockPages(EchoRequest->ReplyMdl);
            IoFreeMdl(EchoRequest->ReplyMdl);
        }
       
        KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTimerWheelLock);

        RtlCleanupTimerWheelEntry(Protocol->EchoRequestTimerTable,
                                  &EchoRequest->TimerEntry);

        KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTimerWheelLock);

        KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
        KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
        
        IppDereferenceEchoRequest(EchoRequest);
        Status = STATUS_SUCCESS;
        break;
        
    default:
        return STATUS_INVALID_PARAMETER;
    }
    
    return Status;
}


NTSTATUS
Ipv4SetEchoRequestCreate(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args,
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    This function handles the NsiCreate portion of the nsi set all parameters
    call.
    
Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

    Protocol - Supplies the protocol pointer.

Return Value:

    Status of the operation.

--*/
{
    PIPV4_ECHO_REQUEST_CONTEXT EchoRequest = NULL;
    PIPV4_ECHO_REQUEST_RW EchoRequestRw;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;

    NL_ECHO_REQUEST_KEY RequestKey;
    BOOLEAN EchoDataMdlLocked = FALSE;
    BOOLEAN OptionsMdlLocked = FALSE;
    BOOLEAN ReplyMdlLocked = FALSE;
    BOOLEAN IndicationNeeded;
    PMDL EchoDataMdl = NULL, OptionsMdl = NULL, ReplyMdl = NULL;
    PVOID InputData, HopByHopOptions = NULL;
    PUCHAR AncilliaryData = NULL;
    USHORT AncilliaryDataLength = 0;
    ULONG AncilliaryDataOffset = 0;
    PNET_BUFFER_LIST NetBufferList = NULL;
    USHORT HopByHopOptionsLength = 0, FirstHopOffset = 0;
    
    SIZE_T BytesCopied;
    PUCHAR RoutingHeader = NULL;
    USHORT RoutingHeaderLength = 0;
    
    PIP_COMPARTMENT Compartment = NULL;
    
    NL_COMPARTMENT_ARG GetCompartmentArgs = {0};
    NL_REQUEST_GENERATE_CONTROL_MESSAGE ControlMessageRequest = {0};
    
    PIP_PATH Path = NULL;
    NL_REQUEST_JOIN_PATH JoinPathArgs = {0};
    
    CONST UCHAR *DestinationAddress;
    SCOPE_ID DestinationScopeId;

    ULONG EchoRequestPacketSize;
    ULONG EchoSequence;
    
    //
    // Before performing actions, first verify that the request makes
    // sense, that the buffers passed in can actually be mapped.
    //
    EchoRequestRw = (PIPV4_ECHO_REQUEST_RW)
        Args->RwStructDesc.RwParameterStruct;
    
    if (EchoRequestRw == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (EchoRequestRw->Timeout == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&RequestKey,
                  Args->KeyStructDesc.KeyStruct,
                  sizeof(NL_ECHO_REQUEST_KEY));
    RequestKey.ClientPid = (ULONG) (ULONG_PTR) PsGetCurrentProcessId();

    if (((PVOID) ((ULONG_PTR) EchoRequestRw->ReplyBuffer) == NULL) || 
        (EchoRequestRw->ReplyBufferOffset > 
         EchoRequestRw->ReplyBufferLength)) {
        return STATUS_INVALID_PARAMETER;
    }
        
    __try {
        if (EchoRequestRw->EchoDataLength > 0) {
            EchoDataMdl = IoAllocateMdl((PCHAR) ((ULONG_PTR)
                                                 EchoRequestRw->EchoDataBuffer),
                                        EchoRequestRw->EchoDataLength,
                                        FALSE, 
                                        TRUE, 
                                        NULL);
            if (EchoDataMdl == NULL) {
                Status = STATUS_NO_MEMORY;
                goto EchoCleanup;
            }
            MmProbeAndLockPages(EchoDataMdl, KernelMode, IoReadAccess);
            EchoDataMdlLocked = TRUE;
            InputData = MmGetSystemAddressForMdlSafe(
                EchoDataMdl, NormalPagePriority);
            
            if (InputData == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto EchoCleanup;
            }
        }
        if (EchoRequestRw->HopByHopOptionsLength > 0) {
            OptionsMdl = IoAllocateMdl((PCHAR) ((ULONG_PTR)
                                                EchoRequestRw->HopByHopOptions),
                                       EchoRequestRw->HopByHopOptionsLength,
                                       FALSE, 
                                       TRUE, 
                                       NULL);
            if (OptionsMdl == NULL) {
                Status = STATUS_NO_MEMORY;
                goto EchoCleanup;
            }
            MmProbeAndLockPages(OptionsMdl, KernelMode, IoReadAccess);
            OptionsMdlLocked = TRUE;
            HopByHopOptions = MmGetSystemAddressForMdlSafe(
                OptionsMdl, NormalPagePriority);                        
            if (HopByHopOptions == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto EchoCleanup;
            }
            HopByHopOptionsLength = EchoRequestRw->HopByHopOptionsLength;
            AncilliaryDataLength += CMSG_SPACE(HopByHopOptionsLength);
        }
        
        ReplyMdl = IoAllocateMdl((PCHAR) ((ULONG_PTR)
                                          EchoRequestRw->ReplyBuffer),
                                 EchoRequestRw->ReplyBufferLength,
                                 FALSE, 
                                 TRUE, 
                                 NULL);
        if (ReplyMdl == NULL) {
            Status = STATUS_NO_MEMORY;
            goto EchoCleanup;
        }
        MmProbeAndLockPages(ReplyMdl, KernelMode, IoReadAccess);
        ReplyMdlLocked = TRUE;
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        goto EchoCleanup;
    }
    
    //
    // Now that the request is okay, allocate a context to track this
    // request.
    //
    EchoRequest = ExAllocatePoolWithTag(NonPagedPool,
                                        sizeof(*EchoRequest),
                                        Ip4EchoPoolTag);
    if (EchoRequest == NULL) { 
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EchoCleanup;
    }
    RtlZeroMemory(EchoRequest, sizeof(*EchoRequest));
    EchoRequest->ReferenceCount = 1;

    RtlInitializeTimerWheelEntry(NULL, &EchoRequest->TimerEntry, 0, FALSE);

    InitializeListHead(&EchoRequest->Link);
    KeInitializeSpinLock(&EchoRequest->Lock);
    EchoRequest->ReplyMdl = ReplyMdl;
    EchoRequest->Protocol = Protocol;
    
    //
    // Allocate a net buffer list with a buffer large enough to accomodate
    // the entire packet. Note that the offset field is set to the end of
    // the space.
    //
    if (EchoRequestRw->Reverse) {
        if (HopByHopOptions != NULL) {
            //
            // In IPv4, source routing is done in the IP options.
            // We don't currently support specifying both simultaneously.
            //
            Status = STATUS_INVALID_PARAMETER;
            goto EchoCleanup;
        }
    
        //
        // Set RoutingHeaderLength to the size of a source routing option 
        // with one address, plus one byte of padding for alignment.
        // 
        FirstHopOffset = 4;
        RoutingHeaderLength = FirstHopOffset + sizeof(IN_ADDR);
        AncilliaryDataLength += CMSG_SPACE(RoutingHeaderLength);
    }    
    //
    // Calculate packet size with overflow checking.
    //
    
    Status = 
        RtlULongAdd(
            EchoRequestRw->EchoDataLength,
            sizeof(ICMPV4_MESSAGE),
            &EchoRequestPacketSize);
    if (!NT_SUCCESS(Status)) {
        goto EchoCleanup;
    }                        
    Status = 
        RtlULongAdd(
            EchoRequestPacketSize,
            ALIGN_UP(HopByHopOptionsLength, UINT32),
            &EchoRequestPacketSize);
    if (!NT_SUCCESS(Status)) {
        goto EchoCleanup;
    }                        
    Status = 
        RtlULongAdd(
            EchoRequestPacketSize,
            RoutingHeaderLength,
            &EchoRequestPacketSize);
    if (!NT_SUCCESS(Status)) {
        goto EchoCleanup;
    }                        
    Status = 
        RtlULongAdd(
            EchoRequestPacketSize,
            Protocol->Characteristics->DefaultDataBackfill,
            &EchoRequestPacketSize);
    if (!NT_SUCCESS(Status)) {
        goto EchoCleanup;
    }                        
    
    NetBufferList = 
        IppAllocateNetBufferListForEcho(
            EchoRequestPacketSize,
            Ipv4SendEchoRequestComplete,
            EchoRequest);
    
    if (NetBufferList == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EchoCleanup;
    }
    
    //
    // Copy the ICMP echo data into the net buffer list.
    //
    if (EchoRequestRw->EchoDataLength > 0) {
        NetioRetreatNetBuffer(NetBufferList->FirstNetBuffer,
                              EchoRequestRw->EchoDataLength,
                              0);
        RtlCopyBufferToMdl((PCHAR) ((ULONG_PTR)
                                    EchoRequestRw->EchoDataBuffer),
                           NetBufferList->FirstNetBuffer->CurrentMdl,
                           NetBufferList->FirstNetBuffer->CurrentMdlOffset,
                           EchoRequestRw->EchoDataLength,
                           &BytesCopied);
    }


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
    ControlMessageRequest.Parameter = EchoRequest->Sequence =
        RtlUlongByteSwap(EchoSequence);

    GetCompartmentArgs.Id = NdisGetCurrentThreadCompartmentId();
    Compartment = IppGetCompartment(Protocol, &GetCompartmentArgs);
    
    //
    // Get the source address to send from.
    //
    DestinationAddress = (PUCHAR) &EchoRequestRw->DestinationAddress;

    JoinPathArgs.NlCompartment.Compartment = (NL_COMPARTMENT *) Compartment;
    JoinPathArgs.RemoteAddress = DestinationAddress;
    JoinPathArgs.RemoteScopeId = EchoRequestRw->DestinationScopeId;
    if (!IN4_IS_ADDR_UNSPECIFIED(&EchoRequestRw->SourceAddress)) {
        JoinPathArgs.NlLocalAddress.ScopeId = EchoRequestRw->SourceScopeId;
        JoinPathArgs.NlLocalAddress.Address = 
            (CONST UCHAR *) &EchoRequestRw->SourceAddress;
    }
    
    Status = IppJoinPath(Protocol, &JoinPathArgs);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_SEND, TRACE_LEVEL_VERBOSE, 
                   "IPNG: V4Echo request - can't find path to use.\n");
        goto EchoCleanup;
    }
    Path = (PIP_PATH) JoinPathArgs.Path;

    //
    // Calculate the size of the ancilliary data. The ancilliary data looks 
    // like this. 
    // ----------------------------------------------------
    // | Hop by Hop Options/Routing header|Don' fragment| TTL     | 
    // ----------------------------------------------------
    //
    if (EchoRequestRw->DontFragment) {
        AncilliaryDataLength += CMSG_SPACE(sizeof(INT));
    }

    if (EchoRequestRw->Ttl != IP_UNSPECIFIED_HOP_LIMIT) {
        AncilliaryDataLength += CMSG_SPACE(sizeof(INT));
    }
                
    AncilliaryData = ExAllocatePoolWithTag(NonPagedPool,
                                              AncilliaryDataLength,
                                              Ip4EchoPoolTag);
    if (AncilliaryData == NULL) {
        goto EchoCleanup;
    }

    RtlZeroMemory(AncilliaryData, AncilliaryDataLength);
    AncilliaryDataOffset = 0;        
    //
    // If we need to create a source routing option, do that here.
    //
    if (RoutingHeaderLength > 0) {
        PCMSGHDR Object = (PCMSGHDR) AncilliaryData;
        
        Object->cmsg_len = CMSG_SPACE(RoutingHeaderLength);
        Object->cmsg_level = Protocol->Level;
        Object->cmsg_type = IP_OPTIONS;
        
        AncilliaryDataOffset = (ULONG) Object->cmsg_len ;
            
        RoutingHeader = WSA_CMSG_DATA(Object);

        //
        // Put a NOP option first so that the IP address will tend to be 
        // aligned for convenience.
        //
        RoutingHeader[0] = IP_OPT_NOP;

        //
        // Add an LSRR option in receiver format.
        //
        RoutingHeader[1] = IP_OPT_LSRR;
        RoutingHeader[2] = 7;
        RoutingHeader[3] = 8;

        //
        // The destination address specified is actually an intermediate
        // destination.  The final destination is ourselves.
        //
        RtlCopyMemory(&RoutingHeader[FirstHopOffset], 
                      DestinationAddress, 
                      sizeof(IN_ADDR));

        DestinationAddress = NL_ADDRESS(Path->SourceAddress);
        DestinationScopeId = NL_ADDRESS_SCOPE_ID(Path->SourceAddress);
        IN4_UNCANONICALIZE_SCOPE_ID((PIN_ADDR) DestinationAddress, 
                                    &DestinationScopeId);
    }

    //
    // Copy Hop by Hop Options.    
    //
    if (HopByHopOptionsLength > 0) {
        PCMSGHDR Object = (PCMSGHDR) AncilliaryData;
        ASSERT(RoutingHeaderLength == 0);        
        Object->cmsg_len = CMSG_SPACE(HopByHopOptionsLength);
        Object->cmsg_level = Protocol->Level;
        Object->cmsg_type = IP_OPTIONS;
        AncilliaryDataOffset = (ULONG) Object->cmsg_len ;
        RtlCopyMemory(
            WSA_CMSG_DATA(Object), 
            HopByHopOptions,
            HopByHopOptionsLength);
    }

    if (EchoRequestRw->DontFragment) {
        PCMSGHDR Object = (PCMSGHDR)(AncilliaryData + AncilliaryDataOffset);        
        Object->cmsg_len = CMSG_SPACE(sizeof(INT));
        Object->cmsg_level = Protocol->Level;
        Object->cmsg_type = IP_DONTFRAGMENT;
        AncilliaryDataOffset += (ULONG) Object->cmsg_len ;
        (*((PINT)WSA_CMSG_DATA(Object))) = 1;
    }
    
    if (EchoRequestRw->Ttl != IP_UNSPECIFIED_HOP_LIMIT) {
        PCMSGHDR Object = (PCMSGHDR)(AncilliaryData + AncilliaryDataOffset);        
        Object->cmsg_len = CMSG_SPACE(sizeof(INT));
        Object->cmsg_level = Protocol->Level;
        Object->cmsg_type = IP_HOPLIMIT;
        AncilliaryDataOffset += (ULONG) Object->cmsg_len ;
        (*((PINT)WSA_CMSG_DATA(Object))) = EchoRequestRw->Ttl;
    }
    
    ASSERT(AncilliaryDataOffset == AncilliaryDataLength);
    
    //
    // Insert the context into queue and send off the datagram.
    //
    RtlCopyMemory(&EchoRequest->Key,
                  &RequestKey,
                  sizeof(NL_ECHO_REQUEST_KEY));
        
    RtlCopyMemory(&EchoRequest->Rw,
                  EchoRequestRw,
                  sizeof(IPV4_ECHO_REQUEST_RW));
        
    EchoRequest->Rod.Status = STATUS_PENDING;
        
    //
    // Insert the echo request.
    //
    KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
    if (IppFindEchoRequest(Protocol->EchoRequestTable,
                           IP_ECHO_REQUEST_TABLE_SIZE,
                           &RequestKey) != NULL) {
        KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);
        Status = STATUS_DUPLICATE_OBJECTID;
        goto EchoCleanup;
    }

    IppInsertEchoRequest(Protocol->EchoRequestTable,
                         IP_ECHO_REQUEST_TABLE_SIZE,
                         (PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
    IppReferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);


    //
    // Start a timer to expire this echo request.
    //
    EchoRequest->StartTime = KeQueryPerformanceCounter(NULL);
   
    KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);
 
    IndicationNeeded = 
        RtlStartTimerWheelEntryTimer(
                &EchoRequest->TimerEntry, 0,
                RtlGetCurrentTimerWheelTick(Protocol->EchoRequestTimerTable) +
                        IppMillisecondsToTicks(EchoRequestRw->Timeout));

    if (IndicationNeeded) {
        KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTimerWheelLock);

        RtlIndicateTimerWheelEntryTimerStart(
                                Protocol->EchoRequestTimerTable,
                                &EchoRequest->TimerEntry);

        KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTimerWheelLock);
    }

    KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
    KeReleaseSpinLock(&Protocol->EchoRequestTableLock, OldIrql);

    //
    // Send the control message. 
    //
    ControlMessageRequest.NetBufferList = NetBufferList;
    ControlMessageRequest.Type = ICMP4_ECHO_REQUEST;
    ControlMessageRequest.DestProtocol = IPPROTO_ICMP;
    ControlMessageRequest.RemoteScopeId = EchoRequestRw->DestinationScopeId;
    ControlMessageRequest.RemoteAddress = DestinationAddress;
    ControlMessageRequest.Path = (NL_PATH *) Path;
    ControlMessageRequest.AncillaryData = AncilliaryData;
    ControlMessageRequest.AncillaryDataLength = AncilliaryDataLength;
    
    IppSendControl(FALSE, Protocol, &ControlMessageRequest);
    Status = STATUS_SUCCESS;
    
  EchoCleanup:
    
    //
    // Note that the reply mdl is not unlocked until one of the following four
    // conditions occur.
    // 1) request times out.
    // 2) request completes due to a reponse.
    // 3) request is cancelled by caller.
    // 4) request is never sent.
    //
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);
    }
    if (Path != NULL) {
        IppDereferencePath(Path);
    }
    if (EchoDataMdl != NULL) {
        if (EchoDataMdlLocked) {
            MmUnlockPages(EchoDataMdl);
        }
        IoFreeMdl(EchoDataMdl);
    }
    if (OptionsMdl != NULL) {
        if (OptionsMdlLocked) {
            MmUnlockPages(OptionsMdl);
        }
        IoFreeMdl(OptionsMdl);
    }    
    if (AncilliaryData != NULL) {
        ExFreePool(AncilliaryData);
    }
    
    //
    // If status is not success, then the buffers were never sent, we need
    // to cleanup the reply mdl, net buffer list and requestcontext.
    //
    if (!NT_SUCCESS(Status)) {
        
        //
        // Free the buffer allocated for the echo request.
        //
        if (NetBufferList != NULL) {
            NetBufferList->Status = Status;
            EchoRequest->ClientNotified = TRUE;
            NetioDereferenceNetBufferList(NetBufferList, FALSE);
        } else {
        
            //
            // Failure occured before net buffer list was allocated.
            // Unlock reply mdl and free request context.
            //
            if (ReplyMdl != NULL) {
                if (ReplyMdlLocked) {
                    MmUnlockPages(ReplyMdl);
                }
                IoFreeMdl(ReplyMdl);
            }
            if (EchoRequest != NULL) {
                IppDereferenceEchoRequest(
                    (PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
            }
        }
    }
    return Status;
}

VOID
Ipv4SendEchoRequestComplete(
    IN PNET_BUFFER_LIST NetBufferList,
    IN ULONG Count,
    IN BOOLEAN DispatchLevel
    )
/*++

Routine Description:

    This is the completion request for the net buffer list sent via echo. Free
    the net buffer list.

Arguments:

    NetBufferList - Supplies the net buffer list which is being completed.
    
    Count - Supplies the count for the net buffer list.

    DispatchLevel - Supplies whether the calling process is at DISPATCH_LEVEL.
    
Return Value:

    None

--*/
{
    PCHAR Data;
    PIP_PROTOCOL Protocol;
    PIPV4_ECHO_REQUEST_CONTEXT EchoRequest;
    NTSTATUS Status = NetBufferList->Status;
    KIRQL OldIrql;
    ULONG Deleted;
    
    UNREFERENCED_PARAMETER(Count);

    EchoRequest = (PIPV4_ECHO_REQUEST_CONTEXT)
        NetioQueryNetBufferListCompletionContext(NetBufferList);
    Protocol = EchoRequest->Protocol;
    
    Data = MmGetSystemAddressForMdlSafe(NetBufferList->FirstNetBuffer->MdlChain,
                                        LowPagePriority);
    ASSERT(Data != NULL);

    //
    // Free the data buffer allocated for the request.
    //
    IppFreeNetBufferListForEcho(NetBufferList, DispatchLevel);
    
    //
    // If status wasn't successful, complete the request back to the user.
    //
    if (Status != STATUS_SUCCESS) {
        KeAcquireSpinLock(&Protocol->EchoRequestTableLock, &OldIrql);
        IppRemoveEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
        KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);
        KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTableLock);
        
        Deleted = EchoRequest->Deleted;
        
        if (!Deleted && !EchoRequest->RequestCompleted) {
            MmUnlockPages(EchoRequest->ReplyMdl);
            IoFreeMdl(EchoRequest->ReplyMdl);
            EchoRequest->ReplyMdl = NULL;
            
            EchoRequest->RequestCompleted = TRUE;
            EchoRequest->Rod.Status = Status;
            
            //
            // Notify the clients if necessary.
            //
            if (!EchoRequest->ClientNotified) {
                Status = IppNotifyEchoRequestChange((PIP_ECHO_REQUEST_CONTEXT)
                                                    EchoRequest,
                                                    Protocol);
                if (Status == STATUS_SUCCESS) {
                    EchoRequest->ClientNotified = TRUE;
                    IppDereferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT)
                                              EchoRequest);
                } else {
                    //
                    // Note that because the item is pulled from the request
                    // table, no other process can find this item, except the 
                    // timeout routine. Since the timeout processing is safe 
                    // for a completed request, it is ok to release request 
                    // lock and acquire locks in proper order at this point.
                    //
                    KeReleaseSpinLockFromDpcLevel(&EchoRequest->Lock);
                    
                    KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTableLock);
                    KeAcquireSpinLockAtDpcLevel(&EchoRequest->Lock);
                    IppInsertEchoRequest(
                        Protocol->EchoRequestTable,
                        IP_ECHO_REQUEST_TABLE_SIZE,
                        (PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
                    KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTableLock);
                    InterlockedIncrement(&Protocol->EchoFailedNotifications);
                }
            }

           
            KeAcquireSpinLockAtDpcLevel(&Protocol->EchoRequestTimerWheelLock);

            RtlCleanupTimerWheelEntry(Protocol->EchoRequestTimerTable,
                                      &EchoRequest->TimerEntry);

            KeReleaseSpinLockFromDpcLevel(&Protocol->EchoRequestTimerWheelLock);
        }

        KeReleaseSpinLock(&EchoRequest->Lock, OldIrql);
    }
    IppDereferenceEchoRequest((PIP_ECHO_REQUEST_CONTEXT) EchoRequest);
}
