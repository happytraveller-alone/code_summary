/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    receive.c

Abstract:

    This module contains IP version-independent functions for a network
    layer module's Packet Validater module.

Author:

    Dave Thaler (dthaler) 21-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "nlmnpip.h"
#include "receive.tmh"
#if DBG

//
// The packet pattern on which to break into the debugger.
// May be set using NSI or modified in the debugger.
//
NLP_DBG_PACKET_PATTERN_RW DbgPacketPattern;

NTSTATUS
NTAPI
IpSetAllDbgPacketPatternParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Updates the packet pattern.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNLP_DBG_PACKET_PATTERN_RW Rw =
        (PNLP_DBG_PACKET_PATTERN_RW) Args->RwStructDesc.RwParameterStruct;
    ULONG PatternLength;

    if (Args->Transaction != NsiTransactionNone) {
        //
        // Transactions are not supported on the WakeUpPattern.
        //
        return STATUS_INVALID_PARAMETER;
    }

    switch (Args->Action) {
    case NsiSetCreateOrSet:
        PatternLength = Rw->PatternLength;

        if (PatternLength > MAX_NL_DBG_PACKET_PATTERN_LENGTH) {
            return STATUS_INVALID_PARAMETER;
        }
        
        RtlCopyMemory(DbgPacketPattern.Mask, Rw->Mask, PatternLength);
        RtlCopyMemory(DbgPacketPattern.Pattern, Rw->Pattern, PatternLength);
        DbgPacketPattern.PatternLength = PatternLength;
        return STATUS_SUCCESS;

    case NsiSetDelete:
        DbgPacketPattern.PatternLength = 0;
        return STATUS_SUCCESS;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}


BOOLEAN
IppDbgPacketPatternMatch(
    IN PNET_BUFFER NetBuffer
    )
{
    UCHAR *Data, DataBuffer[MAX_NL_DBG_PACKET_PATTERN_LENGTH];
    ULONG i, PatternLength = DbgPacketPattern.PatternLength;
    
    if (PatternLength == 0) {
        return FALSE;
    }

    if (PatternLength > NetBuffer->DataLength) {
        return FALSE;
    }
    
    Data = NetioGetDataBuffer(NetBuffer, PatternLength, DataBuffer, 1, 0);
    if (Data == NULL) {
        return FALSE;
    }
    
    //
    // Since we perform the pattern match without holding any lock,
    // we might get a spurious hit if the pattern is changing.  That is okay.
    //
    for (i = 0; ; i++) {
        if (i == PatternLength) {
            return TRUE;
        }
        
        if ((Data[i] & DbgPacketPattern.Mask[i]) !=
            (DbgPacketPattern.Pattern[i] & DbgPacketPattern.Mask[i])) {
            return FALSE;
        }
    }
}

#else // DBG

NTSTATUS
NTAPI
IpSetAllDbgPacketPatternParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
{
    UNREFERENCED_PARAMETER(Args);    
    return STATUS_INVALID_PARAMETER;
}

#endif // DBG


//
// The number of packets that we process in one shot.
// This number should be a power of two.
//
#define PACKETS_PER_RECEIVE_INDICATION 32
C_ASSERT(IS_POWER_OF_TWO(PACKETS_PER_RECEIVE_INDICATION));

//
// We limit the number of receive indications in a single call stack.
// This limits the number of levels of decapsulation a packet might go through.
//
#define MAX_RECEIVE_STACK_LEVEL 3

//
// We halve the number of packets processed in one shot at subsequent levels.
// But we should process at least one packet at each level.
//
C_ASSERT((PACKETS_PER_RECEIVE_INDICATION / (1<<MAX_RECEIVE_STACK_LEVEL)) > 0);

//
// Hence we need at most the following number of controls per processor.
//
#define CONTROL_POOL_SIZE (2 * PACKETS_PER_RECEIVE_INDICATION)


//
// Per processor receive path state.
//
typedef struct _RECEIVE_PER_PROCESSOR_STATE  {
    //
    // Control pool used by receive indications.
    //
    IP_REQUEST_CONTROL_DATA ControlPool[CONTROL_POOL_SIZE];

    //
    // Index into the processor's receive control pool.
    // Since there can be multiple receive indications in a single call stack,
    // this count is used to indicate the next available control.
    //
    ULONG ControlIndex;

    //
    // Count of receive indications made in the current call stack.
    // Incremented on entry into IpFlcReceivePackets and decremented on exit.
    //
    ULONG StackLevel;
} RECEIVE_PER_PROCESSOR_STATE, *PRECEIVE_PER_PROCESSOR_STATE;

typedef DECLSPEC_CACHEALIGN struct PREVALIDATED_RECEIVE_PER_PROCESSOR_STATE {
    BOOLEAN IndicationInProgress;
    NLC_RECEIVE_DATAGRAM ReceiveDatagram[PACKETS_PER_RECEIVE_INDICATION];
} PREVALIDATED_RECEIVE_PER_PROCESSOR_STATE;

typedef PREVALIDATED_RECEIVE_PER_PROCESSOR_STATE 
    *PPREVALIDATED_RECEIVE_PER_PROCESSOR_STATE;

static PRECEIVE_PER_PROCESSOR_STATE *ReceivePerProcessorState;
static PPREVALIDATED_RECEIVE_PER_PROCESSOR_STATE 
    *PreValidatedReceivePerProcessorState;

PIP_FORWARD_INJECTION_PER_PROCESSOR_STATE ForwardInjectionPerProcessorState;

BOOLEAN
IppInReceiveIndication()    
{
    return (ReceivePerProcessorState[KeGetCurrentProcessorNumber()]->StackLevel
            > 0);
}    

NTSTATUS
IppStartControlPoolManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Initialize the session module.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    ULONG Processor;
    //
    // Allocate the pointers to hold the per processor contexts.
    //
    ULONG MaxNumberCpus = KeQueryMaximumProcessorCount();
    
    ULONG Size = 
        MaxNumberCpus * sizeof(PRECEIVE_PER_PROCESSOR_STATE);
    
    KAFFINITY Affinity;
    
    UNREFERENCED_PARAMETER(Protocol);
    ASSERT(Protocol == NULL);

    PASSIVE_CODE();

    ReceivePerProcessorState =
        ExAllocatePoolWithTag(NonPagedPool, Size, IpRequestControlPoolTag);
    if (ReceivePerProcessorState == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting validater: "
                   "Cannot allocate per-processor receive state\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ReceivePerProcessorState, Size);

    Size = 
        MaxNumberCpus * sizeof(PPREVALIDATED_RECEIVE_PER_PROCESSOR_STATE);

    PreValidatedReceivePerProcessorState =
        ExAllocatePoolWithTag(
            NonPagedPool, 
            Size, 
            IpPreValidatedReceivePoolTag);
    if (PreValidatedReceivePerProcessorState == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
            "IPNG: Error starting validater: "
            "Cannot allocate per-processor pre-validated receive state\n");
        ExFreePool(ReceivePerProcessorState);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(PreValidatedReceivePerProcessorState, Size);

    Size = 
        MaxNumberCpus * 
        sizeof(IP_FORWARD_INJECTION_PER_PROCESSOR_STATE);

    ForwardInjectionPerProcessorState =
        ExAllocatePoolWithTag(
            NonPagedPool, 
            Size, 
            IpGenericPoolTag);
    if (ForwardInjectionPerProcessorState == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
            "IPNG: Error starting validater: "
            "Cannot allocate per-processor injection cache.\n");
        ExFreePool(PreValidatedReceivePerProcessorState);
        ExFreePool(ReceivePerProcessorState);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ForwardInjectionPerProcessorState, Size);
    for (Processor = 0; Processor < MaxNumberCpus; Processor++) {
        IppInitializeGenericList(
            &ForwardInjectionPerProcessorState[Processor].Ipv4DelayQueue);
        IppInitializeGenericList(
            &ForwardInjectionPerProcessorState[Processor].Ipv6DelayQueue);
    }            

#ifndef USER_MODE
    Affinity = TcpipGetAllocatedProcessorCount();
#else
    Affinity = (1<< KeNumberProcessors) - 1;
#endif    

    if (!NT_SUCCESS(
        NetioAllocateOpaquePerProcessorContext(
            ReceivePerProcessorState,
            sizeof(RECEIVE_PER_PROCESSOR_STATE),
            IpRequestControlPoolTag,
            Affinity,
            NULL,
            NULL,
            NULL))) {
            goto Fail;
    }

    if (!NT_SUCCESS(
        NetioAllocateOpaquePerProcessorContext(
            PreValidatedReceivePerProcessorState,
            sizeof(PREVALIDATED_RECEIVE_PER_PROCESSOR_STATE),
            IpRequestControlPoolTag,
            Affinity,
            NULL,
            NULL,
            NULL))) {
            goto Fail;
    }    
    return STATUS_SUCCESS;

Fail:
    if (ForwardInjectionPerProcessorState != NULL) {
        ExFreePool(ForwardInjectionPerProcessorState);
    }    
    if (ReceivePerProcessorState != NULL) {
        NetioFreeOpaquePerProcessorContext(ReceivePerProcessorState, NULL);                        
        ExFreePool(ReceivePerProcessorState);
        ReceivePerProcessorState = NULL;
    }

    if (PreValidatedReceivePerProcessorState != NULL) {
        NetioFreeOpaquePerProcessorContext(
            PreValidatedReceivePerProcessorState, NULL);            
        ExFreePool(PreValidatedReceivePerProcessorState);
        PreValidatedReceivePerProcessorState = NULL;
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}


VOID
IppCleanupControlPoolManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Called when the stack is unloading.

--*/
{
    UNREFERENCED_PARAMETER(Protocol);    
    ASSERT(Protocol == NULL);
    NetioFreeOpaquePerProcessorContext(
        PreValidatedReceivePerProcessorState, 
        NULL);

    NetioFreeOpaquePerProcessorContext(
        ReceivePerProcessorState, 
        NULL);
    ExFreePool(PreValidatedReceivePerProcessorState);    
    ExFreePool(ReceivePerProcessorState);
    ExFreePool(ForwardInjectionPerProcessorState);
}


NTSTATUS
IppStartValidater(
    IN PIP_PROTOCOL Protocol
    )
{
    ULONG Size = sizeof(IP_GLOBAL_STATISTICS) * KeQueryMaximumProcessorCount();

    Protocol->PerProcessorStatistics = 
        ExAllocatePoolWithTag(NonPagedPool, Size, IpGenericPoolTag);
    if (Protocol->PerProcessorStatistics == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting %s validater :"
                   "Cannot allocate per-processor statistics\n", 
                   Protocol->TraceString);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Protocol->PerProcessorStatistics, Size);

    //
    // TODO: No need to have a control data pool for each protocol.
    //
    Protocol->ControlPool =
        FsbCreatePool(
            sizeof(IP_REQUEST_CONTROL_DATA),
            0,
            IpRequestControlPoolTag,
            NULL);
    if (Protocol->ControlPool == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting %s validater :"
                   "Cannot allocate control data pool\n", 
                   Protocol->TraceString);
        goto Bail;
    }
    
    IppDefaultStartRoutine(Protocol, IMS_VALIDATER);

    return STATUS_SUCCESS;

Bail:

    ExFreePool(Protocol->PerProcessorStatistics);
    Protocol->PerProcessorStatistics = NULL;
    return STATUS_INSUFFICIENT_RESOURCES;
}


VOID
IppCleanupValidater(
    IN PIP_PROTOCOL Protocol
    )
{
    FsbDestroyPool(Protocol->ControlPool);   
    ExFreePool(Protocol->PerProcessorStatistics);
}


NETIO_INLINE
VOID
IppUpdateMinimumReceivedHopCount(
    IN PIP_PROTOCOL Protocol,
    IN PIP_INTERFACE Interface,
    IN PIP_REQUEST_CONTROL_DATA Control
    )
{
    UINT8 ReceivedHopCount =
        *((PUCHAR) Control->IP +
          AddressFamilyInformation[ADDRESS_FAMILY_INDEX(Protocol->Family)].
          HopLimitOffset);

    if (Control->CurrentDestinationType != NlatUnicast) {
        return;
    }

    ReceivedHopCount &= RECEIVED_HOP_COUNT_MASK;
    if ((ReceivedHopCount < Interface->MinimumReceivedHopCount) &&
        (ReceivedHopCount > 0)) {

        if (IppIsNextHopLocalAddress(Control->NextHop) &&
            HasPrefix(
                Control->SourceAddress.Address,
                Control->CurrentDestinationAddress,
                ((PIP_LOCAL_UNICAST_ADDRESS)Control->NextHop)->PrefixLength)) {
            //
            // Some IGD's have been known to use a non-standard hop-limit.
            // E.g Linksys BEFSX41 sets the hop-limit of proxied DNS responses,
            // and of ICMP messages, to 150.
            // Hence, before updating the MinimumReceivedHopCount,
            // we attempt to determine if the remote address is on-link,
            // and adjust its hop-count accordingly.
            //
            ReceivedHopCount = RECEIVED_HOP_COUNT_MASK;
            if (ReceivedHopCount >= Interface->MinimumReceivedHopCount) {
                return;
            }
        }

        Interface->MinimumReceivedHopCount = ReceivedHopCount;
    }
}


NETIO_INLINE
VOID
IppReceivePacketForPromiscuousListener(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_LOCAL_ADDRESS ReferencedLocalAddress,
    IN PIP_GENERIC_LIST LocalDelivery
    ) 
/*++

Routine Description:

    Handle a packet destined to be received by a promiscuous listener. The 
    packet is cloned and the clone is added to the list of packets to be 
    delivered locally.
    
Arguments:

    Control - Supplies the control to be delivered.

    ReferencedLocalAddress - Supplies the local address for which to receive 
        the packet. The local address is already referenced.
    
    LocalDelivery - Returns an updated list of packets to be delivered locally.

Return Value:

    None.
    
Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_REQUEST_CONTROL_DATA Clone;
    PIP_PROTOCOL Protocol = ReferencedLocalAddress->Interface->Compartment->
        Protocol;
    
    Clone = IppCreateClonePacket(Control, Protocol);
    if (Clone == NULL) {
        IppDereferenceLocalAddress(ReferencedLocalAddress);
        NetioTrace(
            NETIO_TRACE_NETWORK, 
            TRACE_LEVEL_WARNING, 
            "IPNG: Failure cloning control for local delivery.\n");
        return;
    }
    //
    // Update the IP header pointers.
    //
    IppParseHeaderIntoPacket(Protocol, Clone);

    ASSERT(Clone->IsNextHopReferenced);
    IppDereferenceNextHop(Clone->NextHop);
    Clone->NextHop = (PIP_NEXT_HOP) ReferencedLocalAddress;
    Clone->PromiscuousOnlyReceive = TRUE;
    
    //
    // The packet has been accepted.  Update statistics.
    //
    IppUpdateMinimumReceivedHopCount(
        Protocol, 
        ReferencedLocalAddress->Interface, 
        Clone);
    
    //
    // Queue the packet local delivery.
    //
    IppAppendToGenericList(LocalDelivery, Clone);
    
}

NETIO_INLINE
VOID
IppDispatchReceivePacketHelper(
    IN PIP_PROTOCOL Protocol,
    IN PIP_COMPARTMENT Compartment, 
    IN PIP_INTERFACE ArrivalInterface, 
    IN PIP_GENERIC_LIST PendingArgs,
    IN ULONG PendingArgsCount,
    OUT PIP_GENERIC_LIST LocalArgs,
    OUT PIP_GENERIC_LIST RemoteArgs
    )
/*++

Routine Description:

    Dispatch a sequence of received packets destined to the same address.
    Such packets can either be forwarded out over another interface (returned
    in RemoteArgs) or delivered over a local interface (returned in LocalArgs).

    NOTE: We are walking the NetBufferList chain twice in the network layer,
    first to count the number of packets for the same destination,
    and then to initialize their control structures.  Sigh!
    
Arguments:

    Protocol - Supplies the protocol (IPv4 or IPv6).

    Compartment - Supplies the compartment.

    ArrivalInterface - Supplies the interface over which the packets arrived.

    PendingArgs - Supplies a sequence of packets destined to the same address.

    PendingArgsCount - Supplies the length of the PendingArgs sequence.
    
    LocalArgs - Returns an updated list of packets to be delivered locally.

    RemoteArgs - Returns an updated list of packets to be forwarded remotely.

Return Value:

    None.
    
    On success, packets are queued to either the LocalArgs or the RemoteArgs
    lists and their original references (Control + NetBufferList) maintained.
    On failure, these references are removed and the packet discarded.

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_REQUEST_CONTROL_DATA Control;
    CONST UCHAR *SourceAddress, *DestinationAddress;
    IP_PATH_FLAGS ReturnConstrained;
    PIP_NEXT_HOP NextHop;
    PIP_LOCAL_ADDRESS EphemeralLocalAddress = NULL;
    NL_ADDRESS_TYPE DestinationType;
    IP_DISCARD_REASON DiscardReason;
    PIP_GLOBAL_STATISTICS GlobalStatistics = 
        &Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()]; 
    
    DISPATCH_CODE();
    
    //
    // All packets should have the same destination address.
    // Determine the destination addresses from the first packet.
    //
    Control = PendingArgs->Head;
    DestinationAddress = Control->CurrentDestinationAddress;
    DestinationType = Control->CurrentDestinationType;
    SourceAddress = Control->SourceAddress.Address;
    
    //
    // Search for the destination address in the path cache.  The current
    // destination address was likely used previously to source packets to the
    // current source address.  That Path might still exist.    
    // TODO: Why should we not look up the address/route tables instead?
    //
    NextHop = (PIP_NEXT_HOP)
        IppFindAndUpdateLocalAddressInPathCacheAtDpcLevel(
            Compartment,
            SourceAddress,
            DestinationAddress, 
            ArrivalInterface, 
            PendingArgsCount);

    if (NextHop != NULL) {
        DestinationType = NL_ADDRESS_TYPE((PIP_LOCAL_ADDRESS) NextHop);
        goto Complete;
    }
    
    //
    // Heuristic failed :(  Do a route lookup.
    //
    IppFindNextHopAtDpc(
        Compartment,
        DestinationAddress,
        NULL, 
        ((ArrivalInterface->Forward || ArrivalInterface->WeakHostReceive) &&
         (DestinationType != NlatMulticast) &&
         (DestinationType != NlatBroadcast))
        ? NULL
        : ArrivalInterface,
        IppGetScopeId(ArrivalInterface, DestinationAddress),
        &NextHop,
        &ReturnConstrained,
        NULL);
    if ((NextHop != NULL) &&  IppIsNextHopLocalAddress(NextHop)) {
        IppReferenceNextHopEx(NextHop, PendingArgsCount - 1);
        DestinationType = NL_ADDRESS_TYPE((PIP_LOCAL_ADDRESS) NextHop);
        goto Complete;
    }
        
    //
    // If the route lookup fails, or if it yields a Neighbor,
    // see if there are any promiscuous receivers to be satisfied.
    //
    if ((ArrivalInterface->IpPromiscuousCount > 0) ||
        ((ArrivalInterface->IpAllMulticastCount > 0) &&
         (DestinationType == NlatMulticast))) {
        //
        // Create a LocalAddress with a single reference.
        //
        EphemeralLocalAddress = (PIP_LOCAL_ADDRESS)
            IppCreateLocalAddress(
                Protocol,
                DestinationAddress,
                (DestinationType == NlatUnicast ||
                 DestinationType == NlatAnycast ||
                 DestinationType == NlatMulticast ||
                 DestinationType == NlatBroadcast) ?
                DestinationType :
                NlatUnicast,
                ArrivalInterface, 
                ADDR_CONF_MANUAL, 
                INFINITE_LIFETIME, 
                INFINITE_LIFETIME, 
                8 * Protocol->Characteristics->AddressBytes, 
                NULL);
        
        if (EphemeralLocalAddress != NULL) {
            if (NextHop == NULL) {
                //
                // This way we avoid cloning.
                //
                NextHop = (PIP_NEXT_HOP) EphemeralLocalAddress;
            } else {
                // 
                // The control needs to be forwarded as well as delivered to a 
                // promiscuous listener locally. This path is taken only by 
                // unicast traffic.
                //
                IppReferenceNextHopEx(
                    (PIP_NEXT_HOP) EphemeralLocalAddress, 
                    PendingArgsCount - 1);
            }
        }
    }

    if (NextHop != NULL) {
        IppReferenceNextHopEx(NextHop, PendingArgsCount - 1);
    }        

Complete:    
    //
    // Loop through all packets, initializing their fields.
    //
    while ((Control = IppPopGenericList(PendingArgs)) != NULL) {
        ASSERT(PendingArgsCount-- > 0);
        
        Control->NextHop = NextHop;
        Control->IsNextHopReferenced = (NextHop != NULL);
        Control->CurrentDestinationType = DestinationType;
        Control->PromiscuousOnlyReceive = 
            ((EphemeralLocalAddress != NULL) && 
             ((PIP_NEXT_HOP) EphemeralLocalAddress == NextHop));
            
        switch (DestinationType) {
        case NlatMulticast:
            if (Protocol->MldLevel != MldLevelAll) {                
                DiscardReason = IpDiscardNotLocallyDestined;
                goto Discard;
            }
            
            GlobalStatistics->InMulticastPackets++;
            GlobalStatistics->InMulticastOctets += 
                Control->NetBufferList->FirstNetBuffer->DataLength;
            
            //
            // Forward Multicast packets based on MFE table lookup.
            // The Control is cloned, and the clones queued in RemoteArgs.
            // 
            if (ArrivalInterface->ForwardMulticast) {
                BOOLEAN Forwarded =
                    IppForwardMulticastPackets(
                        ArrivalInterface, 
                        Control,
                        RemoteArgs);
                if ((NextHop == NULL) && Forwarded) {
                    //
                    // Control should be dropped.
                    // However, since its clones are being forwarded,
                    // we should not invoke the discard inspection callout.
                    //
                    IppCompleteAndFreePacketList(Control, FALSE);
                    continue;
                }
            }
            break;

        case NlatBroadcast:
            GlobalStatistics->InBroadcastPackets++;
            break;
        }
        
        //
        // Handle local delivery of packet (if reqd.) that will also be 
        // forwarded.
        //
        if ((EphemeralLocalAddress != NULL) && 
            ((PIP_NEXT_HOP) EphemeralLocalAddress != NextHop)) {
            
            IppReceivePacketForPromiscuousListener(
                Control, 
                EphemeralLocalAddress, 
                LocalArgs);
        }

    
        //
        // At this point, we have determined where the packet is destined.
        // 1. Either the packet should be dropped (there is no valid NextHop).
        // 2. Or the packet should be delivered to a LocalAddress.
        // 3. Or the packet should be forwarded to a Neighbor.
        //
        if (NextHop == NULL) {            
            //
            // Drop the packet.
            //
            if (!ArrivalInterface->Forward || 
                NBL_TEST_PROT_RSVD_FLAG(
                    Control->NetBufferList, NBL_LINK_LAYER_NOT_UNICAST) ||
                (DestinationType != NlatUnicast)) {
                DiscardReason = IpDiscardNotLocallyDestined;
            } else {
                GlobalStatistics->InForwardedDatagrams++;
                DiscardReason = IpDiscardNoRoute;
            }

            goto Discard;
        }

        //
        // Determine if the packet is being forwarded to a Neighbor, or being
        // delivered on an interface different from the ArrivalInterface.  If
        // so, determine if forwarding is allowed and decrement the hop limit.
        //
        if (IppIsNextHopNeighbor(NextHop) ||
            (NextHop->Interface != ArrivalInterface)) {
            if (NBL_TEST_PROT_RSVD_FLAG(
                    Control->NetBufferList, NBL_LINK_LAYER_NOT_UNICAST) ||
                (DestinationType != NlatUnicast)) {
                DiscardReason = IpDiscardNotLocallyDestined;
                goto Discard;
            }

            //
            // IPv4 routers must not generate ICMP redirect when source route 
            // option is present. See section 5.2.7.2 of Rfc 1812.
            //
            if (!IppForwardPackets(
                    Protocol,
                    ArrivalInterface,
                    NextHop->Interface,
                    Control,
                    NextHop,
                    (Control->ReceiveRoutingHeaderOffset > 0),
                    Control->StrictSourceRouted,
                    &DiscardReason)) {
                goto Discard;
            }
        }

        //
        // The packet has been accepted.  Update statistics.
        //
        IppUpdateMinimumReceivedHopCount(Protocol, ArrivalInterface, Control);
        
        //
        // Queue the packet for remote or local delivery.
        //
        IppAppendToGenericList(
            IppIsNextHopNeighbor(NextHop) ? RemoteArgs : LocalArgs,
            Control);

        continue;
    
Discard:
        if (IppDiscardReceivedPackets(
                Protocol,
                DiscardReason,
                Control,            
                NULL,
                NULL) == IpDiscardAllowIcmp) {
            IppSendErrorListForDiscardReason(
                FALSE,
                Protocol,
                Control,
                DiscardReason,
                0);                
        }
        IppCompleteAndFreePacketList(Control, FALSE);                            
    }

    ASSERT(PendingArgsCount == 0);
}


//
// OldIrql is guaranteed to be initialized if !DispatchLevel,
// but the compiler is not smart enough to figure that out.
//
#pragma warning(push)
#pragma warning(disable:4701)
VOID
IpFlcReceivePackets(
    IN HANDLE ClientSubInterfaceHandle,
    IN PNET_BUFFER_LIST NetBufferListChain, 
    IN BOOLEAN DispatchLevel
    )
/*++

Routine Description:

    FL_CLIENT_RECEIVE_PACKETS handler.

--*/
{
    NTSTATUS Status;
    KIRQL OldIrql;
    
    PNET_BUFFER NetBuffer;
    PNET_BUFFER_LIST NetBufferList;
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo;

    ULONG Processor;
    PRECEIVE_PER_PROCESSOR_STATE ReceiveProcessorState;
    PIP_SUBINTERFACE_STATISTICS SubInterfaceStats;
    PIP_GLOBAL_STATISTICS GlobalStats;
    ULONG MaxControlIndex, OldControlIndex;
    ULONG PendingArgsCount;
    IP_GENERIC_LIST PendingArgs, LocalArgs, RemoteArgs, DropArgs;
    PIP_REQUEST_CONTROL_DATA Control;

    PIP_SUBINTERFACE SubInterface = (PIP_SUBINTERFACE)ClientSubInterfaceHandle;
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;    

    IppCast(ClientSubInterfaceHandle, IP_SUBINTERFACE);    
    
    //
    // Receive indications are processed at DISPATCH_LEVEL in the NL.
    //
    if (!DispatchLevel) {
        OldIrql = KeRaiseIrqlToDpcLevel();
        DispatchLevel = (OldIrql == DISPATCH_LEVEL);
    } else {
        DISPATCH_CODE();
    }    

    //
    // Now that we are at DISPATCH_LEVEL, obtain the processor state.
    //
    Processor = KeGetCurrentProcessorNumber();
    ReceiveProcessorState = ReceivePerProcessorState[Processor];
    SubInterfaceStats = SubInterface->PerProcessorStatistics[Processor];
    GlobalStats = &Protocol->PerProcessorStatistics[Processor];        

    //
    // All receive indications, except the first, must occur at DISPATCH_LEVEL.
    //
    ASSERT(DispatchLevel || (ReceiveProcessorState->StackLevel == 0));
    
    //
    // We limit the number of receive indications in a single call stack.
    // This limits the number of levels of decapsulation a packet might go
    // through and hence prevents stack overflow.
    //
    if (ReceiveProcessorState->StackLevel == MAX_RECEIVE_STACK_LEVEL) {
        if (!DispatchLevel) {
            KeLowerIrql(OldIrql);
        }

        for (NetBufferList = NetBufferListChain;
             NetBufferList != NULL;
             NetBufferList = NetBufferList->Next) {
            NetBuffer = NetBufferList->FirstNetBuffer;

            SubInterfaceStats->InReceives++;
            GlobalStats->InReceives++;
            
            SubInterfaceStats->InOctets += NetBuffer->DataLength;
            GlobalStats->InOctets += NetBuffer->DataLength;

            (VOID) IppDiscardReceivedPackets(
                       Protocol, 
                       IpDiscardTooManyDecapsulations,                
                       NULL,
                       SubInterface,
                       NetBufferList);

            NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        }

        NetioDereferenceNetBufferListChain(NetBufferListChain, DispatchLevel);
        return;
    }

    //
    // Increment the stack level to allow re-entrancy.
    // Both IppDispatchReceivePacketHelper (via reinjection) and 
    // IppReceiveHeaderBatch (via delivery) can reinvoke IpFlcReceivePackets.
    //
    ReceiveProcessorState->StackLevel++;

    //
    // Loop until all NetBufferLists in the indication are exhausted.
    // We have a chain of packets to process.
    // Split this chain into three, depending on whether the packet is
    // locally destined, remotely destined, or being dropped.
    //
    do {
        PendingArgsCount = 0;
        IppInitializeGenericList(&PendingArgs);
        IppInitializeGenericList(&LocalArgs);
        IppInitializeGenericList(&RemoteArgs);
        IppInitializeGenericList(&DropArgs);        

        //
        // We halve the number of controls available at subsequent levels.
        //
        MaxControlIndex =
            CONTROL_POOL_SIZE -
            PACKETS_PER_RECEIVE_INDICATION /
            (1 << (ReceiveProcessorState->StackLevel - 1));
        OldControlIndex = ReceiveProcessorState->ControlIndex;

        //
        // Loop over (MaxControlIndex - ControlIndex) NetBufferLists at a time.
        // We are guaranteed at least one available control.
        //
        ASSERT(ReceiveProcessorState->ControlIndex < MaxControlIndex);
        do {
            if (ReceiveProcessorState->ControlIndex == MaxControlIndex) {
                //
                // Complete processing packets received thus far.
                //
                break;
            }        

            //
            // Allocate a control from the per-processor control pool. 
            //
            Control = &ReceiveProcessorState->
                          ControlPool[ReceiveProcessorState->ControlIndex++];
            RtlZeroMemory(Control, sizeof(*Control));
            // Control->IsAllocated = FALSE;
            // Control->OnSendPath = FALSE;

            //
            // Obtain the next NetBufferList (and NetBuffer) to process.
            //
            NetBufferList = NetBufferListChain;
            NetBufferListChain = NetBufferListChain->Next;
            NetBufferList->Next = NULL;

            //
            // REVIEW: Process a NetBufferList with multiple NetBuffers.
            // For now, assume there's only one packet per list.
            //
            NetBuffer = NetBufferList->FirstNetBuffer;
            ASSERT(NetBuffer->Next == NULL);
            
#if DBG
            if (IppDbgPacketPatternMatch(NetBuffer)) {
                DbgBreakPoint();
            }
#endif // DBG
            
            Control->NetBufferList = NetBufferList;
            ASSERT(Control->IsOriginLocal == FALSE);
            Control->SourceSubInterface = SubInterface;
            ASSERT(Control->IsSourceReferenced == FALSE);

            //
            // The compartment need not be referenced (SourceSubInterface holds
            // an indirect reference when !IsOriginLocal).
            //
            Control->Compartment = Compartment;
            
            ChecksumInfo.Value = (ULONG) (ULONG_PTR)
                NET_BUFFER_LIST_INFO(
                    NetBufferList, TcpIpChecksumNetBufferListInfo);
            
            SubInterfaceStats->InReceives++;
            GlobalStats->InReceives++;
            
            SubInterfaceStats->InOctets += NetBuffer->DataLength;
            GlobalStats->InOctets += NetBuffer->DataLength;
            
            //
            // Begin by parsing and validating the IPv4/IPv6 header.
            //
            Status = Protocol->ValidateNetBuffer(Control, &ChecksumInfo);
            if (!NT_SUCCESS(Status)) {
                IppAppendToGenericList(&DropArgs, Control);
                continue;
            }

            ASSERT((Control->NextHopLocalAddress == NULL) && 
                   (Control->NextHopNeighbor == NULL) &&
                   (Control->Path == NULL));

            if ((PendingArgs.Head != NULL) &&
                !RtlEqualMemory(
                    ((PIP_REQUEST_CONTROL_DATA) PendingArgs.Head)->
                    CurrentDestinationAddress,
                    Control->CurrentDestinationAddress,
                    Protocol->Characteristics->AddressBytes)) {
                
                //
                // Determine whether the pending packets (which must have the
                // same destination address) are destined locally or remotely.
                //
                IppDispatchReceivePacketHelper(
                    Protocol,
                    Compartment, 
                    Interface,
                    &PendingArgs,
                    PendingArgsCount,
                    &LocalArgs,
                    &RemoteArgs);
            
                PendingArgsCount = 0;
                IppInitializeGenericList(&PendingArgs);
            }
            
            PendingArgsCount++;
            IppAppendToGenericList(&PendingArgs, Control);
        } while (NetBufferListChain != NULL);

        if (PendingArgs.Head != NULL) {
            IppDispatchReceivePacketHelper(
                Protocol,
                Compartment, 
                Interface,
                &PendingArgs,
                PendingArgsCount,
                &LocalArgs,
                &RemoteArgs);

            PendingArgsCount = 0;
            IppInitializeGenericList(&PendingArgs); 
        }
        
        //
        // Dispatch locally-destined and remotely-destined packets.
        // Both IppReceiveHeaderBatch and FragmentPackets consume
        // the control structure and the NetBufferList reference.
        // Finally, complete the dropped packets. 
        //
        if (LocalArgs.Head != NULL) {
            IppReceiveHeaderBatch(Protocol, &LocalArgs);
        }
        
        if (RemoteArgs.Head != NULL) {
            IppFragmentPackets(Protocol, RemoteArgs.Head);
        }
        
        if (DropArgs.Head != NULL) {
            IppCompleteAndFreePacketList(DropArgs.Head, TRUE);
        }
        
        //
        // All control structures (local, remote, drops) may now be reused.
        //
        ReceiveProcessorState->ControlIndex = OldControlIndex;
        
        if (!DispatchLevel && (NetBufferListChain != NULL)) {
            //
            // If the receive indication was not made at DISPATCH_LEVEL...
            //

            //
            // 1. Drop back stack level first, as we may switch processors.
            //
            IppDequeueForwardInjectedPacketsAtDpc();            
            ReceiveProcessorState->StackLevel--;

            //
            // 2. Lower the IRQL (giving other threads a chance to execute).
            //
            KeLowerIrql(OldIrql);

            //
            // 3. Raise the IRQL again. 
            //    We might now be executing on a different processor.
            //
            OldIrql = KeRaiseIrqlToDpcLevel();

            //
            // 4. Update the new processor's state.
            //
            Processor = KeGetCurrentProcessorNumber();
            ReceiveProcessorState = ReceivePerProcessorState[Processor];
            ReceiveProcessorState->StackLevel++;
            SubInterfaceStats =
                SubInterface->PerProcessorStatistics[Processor];
            GlobalStats = &Protocol->PerProcessorStatistics[Processor];
        }
    } while(NetBufferListChain != NULL);
    
    IppDequeueForwardInjectedPacketsAtDpc();    
    ReceiveProcessorState->StackLevel--;
        
    if (!DispatchLevel) {
        KeLowerIrql(OldIrql);
    }        
}
#pragma warning(pop)


VOID
IppInspectInjectReceive(
    IN IPPROTO IpProtocol,
    IN COMPARTMENT_ID CompartmentId,
    IN IF_INDEX InterfaceIndex,
    IN IF_INDEX SubInterfaceIndex,
    IN PNET_BUFFER_LIST NetBufferList
    )
/*++

Routine Description:

    This routine injects a packet into the receive path on behalf of the
    inspection module.

Arguments:

    IpProtocol - Identifies the IP protocol number for the injected packet.

    CompartmentId - Identifies the compartment into which the packet should
        be received.

    InterfaceIndex - Identifies the interface on which the packet should be
        received.

    SubInterfaceIndex - Optionally identifies the sub-interface on which the
        packet should be received. May be omitted as IFI_UNSPECIFIED on
        interfaces with only one sub-interface.

    NetBufferList - Supplies the packet to be injected.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_COMPARTMENT Compartment = NULL;
    PIP_INTERFACE Interface = NULL;
    PIP_SUBINTERFACE SubInterface = NULL;
    KIRQL OldIrql;
    PIP_PROTOCOL Protocol;

    //
    // We'll resolve the caller's target IP protocol, compartment, interface
    // and sub-interface, and use them to indicate the given NBL.
    //
    ASSERT(NetBufferList->Next == NULL);
    ASSERT(NetBufferList->FirstNetBuffer->Next == NULL);

    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;

    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        NetBufferList->Status = STATUS_NOT_FOUND;
        goto CleanupAndReturn;
    }

    Interface = IppFindInterfaceByIndex(Compartment, InterfaceIndex);
    if (Interface == NULL) {
        NetBufferList->Status = STATUS_INVALID_PARAMETER;
        goto CleanupAndReturn;
    }

    RtlAcquireReadLock(&Interface->NeighborSetLock, &OldIrql);

    if (SubInterfaceIndex == IFI_UNSPECIFIED) {

        SubInterface =
            IppFindAnySubInterfaceOnInterfaceUnderLock(Interface);
            
    } else {

        SubInterface =
            IppFindSubInterfaceOnInterfaceByIndexUnderLock(
                Interface, SubInterfaceIndex);
    }

    if (SubInterface == NULL) {
        RtlReleaseReadLock(&Interface->NeighborSetLock, OldIrql);
        NetBufferList->Status = STATUS_NETWORK_UNREACHABLE;
        goto CleanupAndReturn;
    }

    RtlReleaseReadLockFromDpcLevel(&Interface->NeighborSetLock);
        
    NBL_SET_PROT_RSVD_FLAG(NetBufferList, NBL_NAT_RESERVED);

    IpFlcReceivePackets(SubInterface, NetBufferList, TRUE);

    //
    // Our reference on NetBufferList is transferred to IpFlcReceivePackets.
    //
    NetBufferList = NULL;

    KeLowerIrql(OldIrql);

CleanupAndReturn:
    if (SubInterface != NULL) {
        IppDereferenceSubInterface(SubInterface);
    }

    if (Interface != NULL) {
        IppDereferenceInterface(Interface);
    }

    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);
    }

    if (NetBufferList != NULL) {
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
    }
}


NTSTATUS
NTAPI
IpSetAllDbgInjectReceiveParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Injects a receive packet.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNET_BUFFER_LIST NetBufferList;
    NTSTATUS Status;
    IPV6_HEADER UNALIGNED* Ipv6Header;
    
    PNLP_DBG_INJECT_RECEIVE_KEY Key =
        (PNLP_DBG_INJECT_RECEIVE_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    ASSERT(Client->Protocol == &Ipv6Global);
    
    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(*Key));

    if (Args->Transaction != NsiTransactionNone) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Args->Action != NsiSetDefault &&
        Args->Action != NsiSetCreateOnly &&
        Args->Action != NsiSetCreateOrSet) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Key->PayloadLength > MAX_IPV6_PAYLOAD) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Construct an NBL and NB to hold the injected packet.
    //
    Status =
        IppNetAllocate(
            &NetBufferList,
            (PUCHAR*)&Ipv6Header,
            0,
            sizeof(*Ipv6Header) + Key->PayloadLength);
    if (!NT_SUCCESS(Status)) {
        goto CleanupAndReturn;
    }

    //
    // Initialize an IP header in the space allocated.
    //
    Ipv6Header->VersionClassFlow = IPV6_VERSION;
    Ipv6Header->PayloadLength = RtlUshortByteSwap(Key->PayloadLength);
    Ipv6Header->NextHeader = Key->NextHeaderValue;
    Ipv6Header->HopLimit = Client->Protocol->DefaultHopLimit;
    Ipv6Header->SourceAddress = Key->SourceAddress;
    Ipv6Header->DestinationAddress = Key->DestinationAddress;

    RtlZeroMemory(Ipv6Header + 1, Key->PayloadLength);

    //
    // Inject the packet.
    //
    IppInspectInjectReceive(
        IPPROTO_IPV6,
        DEFAULT_COMPARTMENT_ID,
        Key->InterfaceIndex,
        IFI_UNSPECIFIED,
        NetBufferList);
    NetBufferList = NULL;

CleanupAndReturn:
    if (NetBufferList != NULL) {
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
    }

    return Status;
}

#pragma warning(push)
#pragma warning(disable:4701)
VOID
IpFlcReceivePreValidatedPackets(
    IN HANDLE ClientSubInterfaceHandle,
    IN PNET_BUFFER_LIST NetBufferListChain
    )
/*++

Routine Description:

    FL_CLIENT_RECEIVE_PREVALIDATED_PACKETS handler.

--*/
{
    PNET_BUFFER_LIST NetBufferList;
    PNET_BUFFER_LIST RejectedNblHead = NULL, RejectedNblTail = NULL; 
    PNET_BUFFER NetBuffer;
    PIP_SUBINTERFACE SubInterface;
    PIP_INTERFACE ArrivalInterface;
    PIP_PROTOCOL Protocol;
    PIP_CLIENT_CONTEXT NlClient;
    PPREVALIDATED_RECEIVE_PER_PROCESSOR_STATE ReceiveState;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram;
    PUCHAR DestinationAddress, CurrentDestinationAddress;
    PUCHAR SourceAddress, CurrentSourceAddress;
    PUCHAR IpHeaderAddress;
    USHORT SourceAddressOffset, DestinationAddressOffset, HopLimitOffset;
    USHORT TransportProtocolOffset;
    PIP_RECEIVE_DEMUX Demux;
    BOOLEAN UpdateDestinationAddress;
    ADDRESS_FAMILY Family;
    PIP_LOCAL_UNICAST_ADDRESS NextHop;
    USHORT Index;
    UINT8 ReceivedHopCount;
    UCHAR TransportProtocol, CurrentTransportProtocol;
    ULONG TransportHdrSize;
    ULONG IpHeaderSize;
    ULONG Processor;
    SCOPE_ID RemoteScopeId;   
    ULONG DatagramCount = 0;
    ULONG InOctets = 0;

    DISPATCH_CODE();

    Processor = KeGetCurrentProcessorNumber();
    SubInterface = (PIP_SUBINTERFACE) ClientSubInterfaceHandle;
    ArrivalInterface = (PIP_INTERFACE) SubInterface->Interface;
    Protocol = ArrivalInterface->Compartment->Protocol;
    Family = Protocol->Family;
    Index = ADDRESS_FAMILY_INDEX(Family);

    if(!KfdIsLayerEmpty(
        AddressFamilyInformation[Index].WfpInboundIpPacketLayerId)) {
        goto SlowPath;
    }

    IpHeaderSize = AddressFamilyInformation[Index].HeaderSize;
    SourceAddressOffset = 
        AddressFamilyInformation[Index].SourceAddressOffset;
    DestinationAddressOffset =
        AddressFamilyInformation[Index].DestinationAddressOffset;
    HopLimitOffset = 
        AddressFamilyInformation[Index].HopLimitOffset;
    TransportProtocolOffset = 
        AddressFamilyInformation[Index].NextHeaderOffset;
        
    ReceiveState = PreValidatedReceivePerProcessorState[Processor];
    IpHeaderAddress = (PUCHAR) NetBufferListChain->Scratch;
    TransportProtocol = *((UCHAR*)IpHeaderAddress + TransportProtocolOffset);

    Demux = &Protocol->ReceiveDemux[TransportProtocol];
    NlClient = Demux->NlClient;

    ASSERT(NlClient->Npi.Dispatch->Flags.CallReceiveInspectionHandler == FALSE);
    ASSERT(NlClient->Npi.Dispatch->ReceiveDatagrams != NULL);
    ASSERT(Demux->IsExtensionHeader == FALSE);
    ASSERT(Demux->InternalReceiveDatagrams == NULL);
    
    if (ReceiveState->IndicationInProgress ||
        (ArrivalInterface->IpPromiscuousCount > 0) ||
        !RoReference(&Demux->Reference)) {
        goto SlowPath;
    }

    SourceAddress = IpHeaderAddress + SourceAddressOffset;
    DestinationAddress = IpHeaderAddress + DestinationAddressOffset;
    
    NextHop = (PIP_LOCAL_UNICAST_ADDRESS) 
        IppFindAddressInAddressSet(
            ArrivalInterface,
            DestinationAddress,
            NlatUnicast);

    if (NextHop == NULL) {
        IppDereferenceNlClient(NlClient);
        goto SlowPath;
    }

    ASSERT (NL_ADDRESS_TYPE(NextHop) == NlatUnicast);

    if (NextHop->Interface != ArrivalInterface) {
        IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) NextHop);
        IppDereferenceNlClient(NlClient);
        goto SlowPath;
    }

    ReceiveState->IndicationInProgress = TRUE;
    RemoteScopeId = IppGetExternalScopeId(ArrivalInterface, SourceAddress);
    TransportHdrSize = 
        ((TransportProtocol == IPPROTO_TCP) ? 
            sizeof(TCP_HDR) : 
            sizeof(UDP_HDR));

    do {
        NetBufferList = NetBufferListChain;
        NetBuffer = NetBufferList->FirstNetBuffer;
        IpHeaderAddress = (PUCHAR) NetBufferList->Scratch;
        ReceivedHopCount = *((UINT8 *)(IpHeaderAddress + HopLimitOffset));

        UpdateDestinationAddress = FALSE;
        CurrentSourceAddress = IpHeaderAddress + SourceAddressOffset;
        CurrentDestinationAddress = IpHeaderAddress + DestinationAddressOffset;
        CurrentTransportProtocol = 
            *((UCHAR*)IpHeaderAddress + TransportProtocolOffset);

        if (!INET_ADDR_EQUAL(
                Family, 
                SourceAddress,
                CurrentSourceAddress)) {
            RemoteScopeId = 
                IppGetExternalScopeId(ArrivalInterface, CurrentSourceAddress);
            SourceAddress = CurrentSourceAddress;
        }

        UpdateDestinationAddress = 
            !INET_ADDR_EQUAL(
                Family, 
                DestinationAddress,
                CurrentDestinationAddress);

        if (UpdateDestinationAddress ||
            (CurrentTransportProtocol != TransportProtocol) ||
            (DatagramCount == PACKETS_PER_RECEIVE_INDICATION)) {

            ASSERT(DatagramCount > 0);

            //
            // Indicated up already processed packets.
            // At least one of the two conditions have failed.
            // 1.   The packet indication limit (32) has been reached.
            // 2.   The destination address of the current Nbl is 
            //      different that of the last processed Nbl.
            // 3.   The destination protocol of the current Nbl is 
            //      different than the last one.
            //
            
            ReceiveState->ReceiveDatagram[DatagramCount - 1].Next = NULL;
            IppDeliverPreValidatedListToProtocol(
                Demux,
                &ReceiveState->ReceiveDatagram[0],
                DatagramCount,
                TransportProtocol,
                &RejectedNblHead,
                &RejectedNblTail);

            if (RejectedNblHead != NULL) {
                ASSERT(RejectedNblTail != NULL);
                IppDereferenceNlClient(NlClient);
                IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) NextHop);
                ReceiveState->IndicationInProgress = FALSE;
                goto SlowPath;
            }

            DatagramCount = 0;

            if (CurrentTransportProtocol != TransportProtocol) {
                TransportProtocol = CurrentTransportProtocol;
                TransportHdrSize =
                    ((TransportProtocol == IPPROTO_TCP) ? 
                        sizeof(TCP_HDR) : 
                        sizeof(UDP_HDR));
                IppDereferenceNlClient(NlClient);
                Demux = &Protocol->ReceiveDemux[TransportProtocol];
                NlClient = Demux->NlClient;

                ASSERT(
                    NlClient->Npi.Dispatch->Flags.CallReceiveInspectionHandler 
                        == FALSE);
                ASSERT(NlClient->Npi.Dispatch->ReceiveDatagrams != NULL);
                ASSERT(Demux->IsExtensionHeader == FALSE);
                ASSERT(Demux->InternalReceiveDatagrams == NULL);

                if (!RoReference(&Demux->Reference)) {
                    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) NextHop);
                    ReceiveState->IndicationInProgress = FALSE;
                    goto SlowPath;
                }
            }

            if (UpdateDestinationAddress) {
                // 
                // Dereference the current local address.
                // Update the destination address and get corresponding
                // local address from the path cache.
                //
                IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) NextHop);
                DestinationAddress = CurrentDestinationAddress;

                NextHop = (PIP_LOCAL_UNICAST_ADDRESS)
                    IppFindAddressInAddressSet(
                        ArrivalInterface,
                        DestinationAddress,
                        NlatUnicast);

                if (NextHop == NULL) {
                    IppDereferenceNlClient(NlClient);
                    ReceiveState->IndicationInProgress = FALSE;
                    goto SlowPath;
                }

                ASSERT (NL_ADDRESS_TYPE(NextHop) == NlatUnicast);

                if (NextHop->Interface != ArrivalInterface) {
                    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) NextHop);
                    IppDereferenceNlClient(NlClient);
                    ReceiveState->IndicationInProgress = FALSE;
                    goto SlowPath;
                }
            }
        }

        //
        // InOctets must be updated before NetioAdvanceNetBuffer().
        //
        InOctets += (NetBuffer->DataLength - sizeof(ETHERNET_HEADER));

        NetioAdvanceNetBuffer(
            NetBuffer, 
            (sizeof(ETHERNET_HEADER) + IpHeaderSize + TransportHdrSize));

        ReceiveDatagram = &ReceiveState->ReceiveDatagram[DatagramCount];
        ReceiveDatagram->Next = ReceiveDatagram + 1;

        DatagramCount++;

        ASSERT(DatagramCount <= PACKETS_PER_RECEIVE_INDICATION);

        ReceiveDatagram->NetBufferList = NetBufferList;
        ReceiveDatagram->Loopback = FALSE;
        ReceiveDatagram->FastPath = TRUE;
        ReceiveDatagram->InspectFlags = 0;
        ReceiveDatagram->RemoteScopeId = RemoteScopeId;
        ReceiveDatagram->RemoteAddress = SourceAddress;
        ReceiveDatagram->LocalAddress = (PNL_LOCAL_ADDRESS) NextHop;

        //
        // Store the Destination address (which is our local address) prefix 
        // length in the datagram. WFP uses this information to determine
        // whether the packet originated in our subnet.
        //
        ReceiveDatagram->LocalAddressPrefixLength = NextHop->PrefixLength;
        
        ReceiveDatagram->NextHeaderValue = TransportProtocol;
        ReceiveDatagram->NetworkLayerHeadersSize = 
            IpHeaderSize + TransportHdrSize;
        ReceiveDatagram->SourceInterface = (PNL_INTERFACE) ArrivalInterface;
        ReceiveDatagram->SourceSubInterfaceIndex = SubInterface->Index;
        ReceiveDatagram->TransportLayerContext =
            ((PUCHAR)NetBufferList->Scratch) + IpHeaderSize;
        ReceiveDatagram->TransportLayerKey = NULL;

        //
        // Advance to the next NetBufferList in the chain.
        //
        NetBufferListChain = NetBufferListChain->Next;

        //
        // Clear fields in the current NBL and remove it 
        // from the head of the chain.
        //
        NetBufferList->Next = NULL;
        NetBufferList->Scratch = NULL;
        NetBufferList->Status = STATUS_MORE_ENTRIES;

        ReceivedHopCount &= RECEIVED_HOP_COUNT_MASK;

        if ((ReceivedHopCount < ArrivalInterface->MinimumReceivedHopCount) &&
            (ReceivedHopCount > 0)) {
            ArrivalInterface->MinimumReceivedHopCount = ReceivedHopCount;
        }

    } while (NetBufferListChain != NULL); 

    ReceiveState->ReceiveDatagram[DatagramCount - 1].Next = NULL;
    IppDeliverPreValidatedListToProtocol(
        Demux,
        &ReceiveState->ReceiveDatagram[0],
        DatagramCount,
        TransportProtocol,
        &RejectedNblHead,
        &RejectedNblTail);

    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) NextHop);
    IppDereferenceNlClient(NlClient);
    ReceiveState->IndicationInProgress = FALSE;

    if (RejectedNblHead != NULL) {
        ASSERT(RejectedNblTail != NULL);
        goto SlowPath;
    }

    goto Complete;

SlowPath:
    for (NetBufferList = NetBufferListChain;
         NetBufferList != NULL;
         NetBufferList = NetBufferList->Next) {

        NetBufferList->Scratch = NULL;
        NetioAdvanceNetBuffer(
            NetBufferList->FirstNetBuffer, 
            sizeof(ETHERNET_HEADER));
    }

    if (RejectedNblHead != NULL) {
        //
        // Re-attach rejected packets to the head of the
        // original NBL chain and fall to the slow path.
        //
        RejectedNblTail->Next = NetBufferListChain;
        NetBufferListChain = RejectedNblHead;
    }

    IpFlcReceivePackets(
        ClientSubInterfaceHandle,
        NetBufferListChain,
        TRUE);

Complete:
    SubInterface = (PIP_SUBINTERFACE) ClientSubInterfaceHandle;
    SubInterface->PerProcessorStatistics[Processor]->InReceives +=
        DatagramCount;
    SubInterface->PerProcessorStatistics[Processor]->InOctets += InOctets;

    Protocol->PerProcessorStatistics[Processor].InReceives +=
        DatagramCount;
    Protocol->PerProcessorStatistics[Processor].InDelivers +=
        DatagramCount;
    Protocol->PerProcessorStatistics[Processor].InOctets += InOctets;
}

NTSTATUS
IppAddRemoveReceivePerProcessorContexts(
    IN ULONG ProcessorIndex,
    IN BOOLEAN ProcessorAdded
    )
/*++

Routine Description:

    Receive context Processor Add Handler. 
    
Arguments:
    ProcessorIndex - Index of the processor that is being modified.

    ProcessorAdded - Added or removed. Remove is not supported today.
        But we can get called to remove due to an add failure.
        
Return Value:
    NTSTATUS. On the remove path this should return success.

--*/              
{
    if(ProcessorAdded) {
        ASSERT(ReceivePerProcessorState[ProcessorIndex] == NULL);
        ReceivePerProcessorState[ProcessorIndex]  = 
            ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(RECEIVE_PER_PROCESSOR_STATE),
                IpRequestControlPoolTag);

        if(ReceivePerProcessorState[ProcessorIndex] == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(
            ReceivePerProcessorState[ProcessorIndex],
            sizeof(RECEIVE_PER_PROCESSOR_STATE));
            
        ASSERT(PreValidatedReceivePerProcessorState[ProcessorIndex] == NULL);
        PreValidatedReceivePerProcessorState[ProcessorIndex]  = 
            ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(PREVALIDATED_RECEIVE_PER_PROCESSOR_STATE),
                IpRequestControlPoolTag);

        if(PreValidatedReceivePerProcessorState[ProcessorIndex] == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(
            PreValidatedReceivePerProcessorState[ProcessorIndex],
            sizeof(PREVALIDATED_RECEIVE_PER_PROCESSOR_STATE));
    }else {
        if (ReceivePerProcessorState[ProcessorIndex] != NULL) {
            ExFreePool(ReceivePerProcessorState[ProcessorIndex]);
            ReceivePerProcessorState[ProcessorIndex] = NULL;
        }
        if (PreValidatedReceivePerProcessorState[ProcessorIndex] != NULL) {
            ExFreePool(PreValidatedReceivePerProcessorState[ProcessorIndex]);
            PreValidatedReceivePerProcessorState[ProcessorIndex] = NULL;
        }
    }
    return STATUS_SUCCESS;
}
