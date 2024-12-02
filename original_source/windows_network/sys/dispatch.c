/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    dispatch.c

Abstract:

    This module implements the protocol-independent functions of the
    Packet Dispatcher module.

Author:

    Dave Thaler (dthaler) 17-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "ip4def.h"
#include "ip6def.h"
#include <nlmnpip.h>

VOID
IppLoopbackEnqueue(
    IN PIP_GENERIC_LIST PacketList,
    IN PIP_PROTOCOL Protocol,
    IN BOOLEAN DispatchLevel
    )
/*++

Routine Description:

    Queue a list of NetBufferLists (with a single NetBuffer in each) in the
    loopback queue if they pass inspection.  If required, schedule the work
    item that empties the queue and sends the packets.

Arguments:

    PacketList - Supplies a list of packets to be queued.

    Protocol - Supplies a pointer to the protocol (Ipv4 or Ipv6).

    DispatchLevel - Supplies TRUE if IRQL is known to be at DISPATCH level.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    KIRQL OriginalIrql;
    IP_GENERIC_LIST AllowedPacketList;
    PIP_REQUEST_CONTROL_DATA Control;
        
    UNREFERENCED_PARAMETER(DispatchLevel);
    
    ASSERT(PacketList->Head != NULL);

    //
    // First make sure WFP allows each loopback packet.
    //
    IppInitializeGenericList(&AllowedPacketList);
    while ((Control = IppPopGenericList(PacketList)) != NULL) {
        IP_FILTER_ACTION Action;        
        Control->OnSendPath = FALSE;                

        Action =
            IppInspectLocalPacketsOut(
                (IS_IPV4_PROTOCOL(Protocol) ? IPPROTO_IP : IPPROTO_IPV6), 
                (PNL_LOCAL_ADDRESS) Control->SourceLocalAddress,
                Control->FinalDestinationAddress.Buffer,
                Control->CurrentDestinationType,
                (PNL_INTERFACE) Control->DestLocalAddress->Interface,
                IFI_UNSPECIFIED,
                TRUE,
                Control->DestinationProtocol,
                Control->IpHeaderAndExtensionHeadersLength,
                LOOPBACK_MTU,
                Control->Flags.DontFragment,
                &Control->TransportData,
                Control->TransportHeaderLength,
                Control->NetBufferList);

        if (Action >= IpFilterDrop) {
            if ((Action == IpFilterDrop) || (Action == IpFilterDropAndSendIcmp)) {
                Control->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            } else {
                ASSERT(Action == IpFilterAbsorb);
            }
            IppCompleteAndFreePacketList(Control, DispatchLevel);
        } else {
            IppAppendToGenericList(&AllowedPacketList, Control);
        }
    }
    if (AllowedPacketList.Head == NULL) {
        return;
    }
        

    KeAcquireSpinLock(&Protocol->LoopbackQueueLock, &OriginalIrql);
    IppConcatenateGenericLists(&Protocol->LoopbackQueue, &AllowedPacketList);
    if (!Protocol->IsLoopbackTransmitScheduled) {
        IoQueueWorkItem(
            Protocol->LoopbackWorkItem,
            IppLoopbackTransmit,
            DelayedWorkQueue,
            Protocol);
        Protocol->IsLoopbackTransmitScheduled = TRUE;
    }
    KeReleaseSpinLock(&Protocol->LoopbackQueueLock, OriginalIrql);
}


PIP_REQUEST_CONTROL_DATA
IppCreateClonePacket(
    IN PIP_REQUEST_CONTROL_DATA OriginalControl,
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    This routine creates a clone of a NetBufferList.

Arguments:

    OriginalControl - The packet data to be cloned.

    Protocol - A pointer to the protocol (v4 or v6).

Return Value:

    Returns the clone NetBufferList. NULL on failure.

Caller IRQL:

--*/
{
    PNET_BUFFER_LIST Nbl, CloneNetBufferList;
    PIP_REQUEST_CONTROL_DATA CloneControl;

    Nbl = OriginalControl->NetBufferList;
     
    //
    // Clone the new NetBufferList.
    // TODO: There should be a parameter to NetioAllocateCloneNetBufferList
    // that allows some backfill data space.
    //
    CloneNetBufferList =
        NetioAllocateAndReferenceCloneNetBufferList(Nbl, FALSE);
    if (CloneNetBufferList == NULL) {
        return NULL;
    }

    CloneControl = IppCopyPacket(Protocol, OriginalControl);
    if (CloneControl == NULL) {
        NetioDereferenceNetBufferList(CloneNetBufferList, FALSE);
        return NULL;
    }

    //    
    // Propagate only flags that NL and its clients are interested in.
    //
    CloneNetBufferList->Flags |= 
	(Nbl->Flags & (NBL_LINK_LAYER_NOT_UNICAST | NBL_NAT_RESERVED));

    CloneControl->NetBufferList = CloneNetBufferList;

    return CloneControl;
}


PIP_REQUEST_CONTROL_DATA
IppCreateStrongClonePacket(
    IN PIP_REQUEST_CONTROL_DATA OriginalControl,
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    This routine creates a clone of a NetBufferList, where the header
    space cannot be shared between the original and the cloned lists.
    The header in the cloned NetBufferList will be in contiguous memory.

Arguments:

    OriginalControl - The packet data to be cloned.

    Protocol - A pointer to the protocol (v4 or v6).

Return Value:

    Returns the clone NetBufferList. NULL on failure.

Caller IRQL:

--*/
{
    NTSTATUS Status;
    PNET_BUFFER_LIST Nbl, CloneNetBufferList;
    PIP_REQUEST_CONTROL_DATA CloneControl;
    UCHAR *CloneHeader;
    ULONG BytesToCopy;
    SIZE_T BytesCopied;

    Nbl = OriginalControl->NetBufferList;

    BytesToCopy = OriginalControl->IpHeaderAndExtensionHeadersLength;

    ASSERT(BytesToCopy <= Nbl->FirstNetBuffer->DataLength);
     
    //
    // Pop the header from the NetBuffer before cloning it so
    // that the cloned NetBuffer does not reuse the same header.
    //
    NetioAdvanceNetBuffer(Nbl->FirstNetBuffer, BytesToCopy);
    
    CloneControl = IppCreateClonePacket(OriginalControl, Protocol);

    // 
    // Restore the headers.  This is done before checking for the return value
    // of IppCreateClonePacket so that we restore the original NetBufferList
    // even if the clone fails. 
    // 
    (VOID) NetioRetreatNetBuffer(Nbl->FirstNetBuffer, BytesToCopy, 0);

    if (CloneControl == NULL) {
        return NULL;
    }
    CloneNetBufferList = CloneControl->NetBufferList;

    Status =
        NetioRetreatNetBuffer(
            CloneNetBufferList->FirstNetBuffer, 
            BytesToCopy, 
            0);
    if (!NT_SUCCESS(Status)) {
        IppCompleteAndFreePacketList(CloneControl, FALSE);
        return NULL;
    }
    
    CloneHeader =
        NetioGetDataBufferSafe(
            CloneNetBufferList->FirstNetBuffer,
            BytesToCopy);

    RtlCopyMdlToBuffer(
        Nbl->FirstNetBuffer->MdlChain,
        Nbl->FirstNetBuffer->DataOffset,
        CloneHeader,
        BytesToCopy,
        &BytesCopied);
    ASSERT(BytesToCopy == BytesCopied);
        
    return CloneControl;
}


VOID
IppCreateSubInterfaceSplitList(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control, 
    OUT PIP_GENERIC_LIST RemotePackets
    )
/*++

Routine Description:
    
    Make a clone for each additional subinterface.
    
Arguments:

    Protocol - Supplies the protocol being used.

    Control - Supplies the packet to be split.

    RemotePackets - Returns the resulting list of IP_REQUEST_CONTROL_DATA's.

Return Value:

    None.
    
--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_NEIGHBOR Neighbor = Control->NextHopNeighbor;
    PIP_INTERFACE Interface = Neighbor->Interface;
    PLIST_ENTRY Current, Head = &Interface->SubInterfaceSet;
    PIP_REQUEST_CONTROL_DATA Clone;
    BOOLEAN WasNextHopReferenced = Control->IsNextHopReferenced;
    //
    // Set the NextHopNeighbor to NULL and IsNextHopReferenced to FALSE.
    // This ensures that we don't reference and copy it to cloned packets. 
    //
    Control->NextHopNeighbor = NULL;
    Control->IsNextHopReferenced = FALSE;
    
    ASSERT((Neighbor->AddressType == NlatMulticast) ||
           (Neighbor->AddressType == NlatBroadcast));
    
    IppInitializeGenericList(RemotePackets);
    
    //
    // Create a clone for each connected subinterface
    // (other than the one NextHopNeighbor points to).
    //
    RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

    for (Current = Head->Flink; Current != Head; Current = Current->Flink) {
        PIP_SUBINTERFACE SubInterface = (PIP_SUBINTERFACE)
            CONTAINING_RECORD(Current, IP_SUBINTERFACE, Link);

        if ((SubInterface->OperationalStatus != IfOperStatusUp) ||
            (SubInterface == Neighbor->SubInterface)) {
            continue;
        }

        Clone = IppCreateClonePacket(Control, Protocol);
        if (Clone != NULL) {
            ASSERT(Clone->NextHop == NULL);
            Clone->NextHopNeighbor =
                IppFindOrCreateNeighborUnderLock(
                    Interface,
                    SubInterface,
                    IP_NEIGHBOR_NL_ADDRESS(Neighbor),
                    Neighbor->AddressType);
            if (Clone->NextHopNeighbor == NULL) {
                IppCompleteAndFreePacketList(Clone, TRUE);
                continue;
            }
            
            Clone->IsNextHopReferenced = TRUE;
            IppAppendToGenericList(RemotePackets, Clone);
        }
    }

    RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);

    //
    // Always include the original NetBufferList.
    //
    Control->NextHopNeighbor = Neighbor;
    Control->IsNextHopReferenced = WasNextHopReferenced;
    IppAppendToGenericList(RemotePackets, Control);
}


__inline
VOID
IppSetNdisChecksumForLoopbackPacket(
    PNET_BUFFER_LIST Nbl,
    BOOLEAN SetTcpChecksum,
    BOOLEAN SetUdpChecksum,
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo
    )
/*++

Routine Description:

    For loopback packets. If we have decided at an earlier point to defer
    checksum for TCP or UDP (upper layer checksum) to the card, we must either
    compute the checksum or set the ndis checksum information to indicate the
    checksum is successful. The later options is performed in this function.

Arguments:

    Nbl - The NetBufferList to set the information for.

    SetTcpChecksum - If the TCP checksum for this loopback packet should be
        set.

    SetUdpChecksum - If the UDP checksum for this loopback packet should be
        set.

    ChecksumInfo - The actual check information structure obtained from the Nbl
         passed to be filled.

Return Value:

    None

Caller IRQL: 

    Any
--*/
{
    //
    // First we must check if we have enabled checksum offload. If so we
    // need to modify the NetBufferList information to reflect this.
    //
    if (SetTcpChecksum) {
        ChecksumInfo.Transmit.NdisPacketTcpChecksum = 0;
        ChecksumInfo.Transmit.NdisPacketChecksumV4 = 0;
        ChecksumInfo.Transmit.NdisPacketChecksumV6 = 0;
        
        ChecksumInfo.Receive.NdisPacketTcpChecksumSucceeded = 1;
        NET_BUFFER_LIST_INFO(Nbl, TcpIpChecksumNetBufferListInfo) =
            (PVOID) (ULONG_PTR) ChecksumInfo.Value;
        
    } else if (SetUdpChecksum) {
        ChecksumInfo.Transmit.NdisPacketUdpChecksum = 0;
        ChecksumInfo.Transmit.NdisPacketChecksumV4 = 0;
        ChecksumInfo.Transmit.NdisPacketChecksumV6 = 0;
        
        ChecksumInfo.Receive.NdisPacketUdpChecksumSucceeded = 1;
        NET_BUFFER_LIST_INFO(Nbl, TcpIpChecksumNetBufferListInfo) =
            (PVOID) (ULONG_PTR) ChecksumInfo.Value;
    }
}


BOOLEAN
IppCreateLoopbackSplitList(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN BOOLEAN Shared,
    IN PIP_PROTOCOL Protocol,
    OUT PIP_GENERIC_LIST SplitList
    ) 
/*++

Routine Description:

    This routine splits a NetBufferList with multiple NetBuffers
    into multiple NetBufferLists, each containing a single NetBuffer.
    For this, it creates clones of the original NetBufferList. 
    In case the input NetBufferList contains just one NetBuffer,
    then it is returned as it is unless the Shared parameter is 
    true.  In summary, the original NetBufferList is returned if (1) there is
    only one NetBuffer in the NetBufferList and (2) the NetBufferList is
    not shared (Shared == FALSE).  Otherwise, the NetBufferList is split into
    multiple NetBufferList each of which is a clone of the original
    one and contains at most one NetBuffer. While splitting, if the
    NetBufferList is shared, we do a strong clone (the original and cloned
    NetBuffers do not share the same IP header space).

    The IP header in all the input NetBuffers is assumed to be in contiguous
    memory.  This is guaranteed because IppCreateLoopbackSplitList is called
    on the send path, where the header added is contiguous (even in the case
    of header include).

Arguments:

    Control - The input containing the packet data to be split.

    Shared - Supplies a boolean indicating whether the NetBufferList is going
        to be sent on another path (other than the loopback path). If this is
        true, then (1) the input NetBufferList is cloned even if it contains
        just one NetBuffer and (2) the data headers are adjusted so that the
        original NetBuffer and the cloned one do not use the same header.  

    Protocol - Supplies the protocol being used.

    SplitList - Returns the resulting list of IP_REQUEST_CONTROL_DATA
        structures. 

Return Value:

    TRUE if the caller needs to free the original control data and NetBuffer
    list.  In this case, a reference is added to the original NetBufferList for
    each packet that needs to be sent. So, if 'n' packet are added to the
    loopback list, then 'n' references are added to the original NetBufferList
    (this is true even in the case that no clone is created). In case of
    failure, the reference count is unmodified. A new control structure copy is
    created for each packet added to the loopback list. So, the caller is
    responsible for freeing the original control structure as well as the
    original NetBufferList reference.

    FALSE if the caller should not free the original control data and net
    buffer list. 

--*/
{
    PNET_BUFFER CurrentOrigNetBuffer, FirstOrigNetBuffer, NextOrigNetBuffer;
    PIP_REQUEST_CONTROL_DATA Clone;
    PNET_BUFFER_LIST Nbl;
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo;
    BOOLEAN SetTcpChecksum = FALSE, SetUdpChecksum = FALSE;
    
    Nbl = Control->NetBufferList;
    
    ASSERT(Nbl->FirstNetBuffer != NULL);

    IppInitializeGenericList(SplitList);
    
    ChecksumInfo.Value = (ULONG) (ULONG_PTR)
            NET_BUFFER_LIST_INFO(Nbl, TcpIpChecksumNetBufferListInfo);
    if (ChecksumInfo.Transmit.NdisPacketTcpChecksum) {
        SetTcpChecksum = TRUE;
    } else if (ChecksumInfo.Transmit.NdisPacketUdpChecksum) {
        SetUdpChecksum = TRUE;
    }    

    //
    // Conditions when the packet does not need to be cloned. 
    // (1) The NetBufferList contains just one NetBuffer AND
    // (2) The NetBufferList is not shared i.e. it is not going to be sent on
    // another path AND 
    //
    if ((Nbl->FirstNetBuffer->Next == NULL) && !Shared) {
        //
        // There is no need to clone the NetBufferList. However, we do need
        // to pend the control structure since it might have been used from the
        // stack. 
        // 
        Clone = IppPendPacket(Control);
        if (Clone == NULL) {
            IppCompleteAndFreePacketList(Control, FALSE);            
            return FALSE;
        }

        IppSetNdisChecksumForLoopbackPacket(
            Nbl, SetTcpChecksum, SetUdpChecksum, ChecksumInfo);

        IppAppendToGenericList(SplitList, Clone);
        
        return FALSE;
    }

    FirstOrigNetBuffer = Nbl->FirstNetBuffer;
    
    //
    // Create a new NetBufferList for each NetBuffer in the original list.
    // 
    for (CurrentOrigNetBuffer = FirstOrigNetBuffer;
         CurrentOrigNetBuffer != NULL;
         CurrentOrigNetBuffer = CurrentOrigNetBuffer->Next) {
        // 
        // Set the original NetBufferList to point to the current 
        // NetBuffer and set the next link of the NetBuffer to
        // NULL.
        //       
        NextOrigNetBuffer = CurrentOrigNetBuffer->Next;
        CurrentOrigNetBuffer->Next = NULL;
        Nbl->FirstNetBuffer = CurrentOrigNetBuffer;

        //
        // Need a strong clone if the NetBufferList is shared.
        //
        if (Shared) {
            Clone = IppCreateStrongClonePacket(Control, Protocol);
        } else {
            Clone = IppCreateClonePacket(Control, Protocol);
        }

        //
        // Restore the original NetBufferList.
        //
        CurrentOrigNetBuffer->Next = NextOrigNetBuffer;
        Nbl->FirstNetBuffer = FirstOrigNetBuffer;

        if (Clone == NULL) {
            goto Error;
        }
        
        // 
        // Add the cloned NetBufferList to the result.
        //
        ChecksumInfo.Value = (ULONG) (ULONG_PTR)
            NET_BUFFER_LIST_INFO(Clone->NetBufferList,
                                 TcpIpChecksumNetBufferListInfo);


        IppSetNdisChecksumForLoopbackPacket(
            Clone->NetBufferList,
            SetTcpChecksum,
            SetUdpChecksum,
            ChecksumInfo);

        IppAppendToGenericList(SplitList, Clone);
    }

    return TRUE;

Error:
    if (SplitList->Head != NULL) {
        IppCompleteAndFreePacketList(SplitList->Head, FALSE);    
        IppInitializeGenericList(SplitList);
    }

    return TRUE;
}


VOID 
IppLoopbackTransmit(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    )
/*++

Routine Description:
    This routine dequeues all the packets from the loopback queue
    and sends them on the receive path. 

IRQL Level:
    System worker threads typically work run at PASSIVE LEVEL. So 
    this is called at PASSIVE level.

--*/
{
    PIP_PROTOCOL Protocol = (PIP_PROTOCOL)Context;
    IP_GENERIC_LIST LoopbackArgsList;
    KIRQL OriginalIrql;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    PASSIVE_CODE();

    KeAcquireSpinLock(&Protocol->LoopbackQueueLock, &OriginalIrql);
    ASSERT(Protocol->IsLoopbackTransmitScheduled == TRUE);
    ASSERT(Protocol->LoopbackQueue.Head != NULL);

    do {
        //
        // Get a handle to the loopback queue, re-initialize the queue,  
        // and set IsLoopbackTransmitScheduled to FALSE.
        // Instead of holding the lock while each packet is getting 
        // transmitted, this just gets a pointer to the queue under 
        // lock and then sends the packets without the queue lock. 
        //
        LoopbackArgsList = Protocol->LoopbackQueue;
        IppInitializeGenericList(&Protocol->LoopbackQueue);

        //
        // The packets need to be indicated without holding a lock.  Don't
        // lower the IRQL because receives need to be at dispatch.
        //
        KeReleaseSpinLockFromDpcLevel(&Protocol->LoopbackQueueLock);
        
        if (LoopbackArgsList.Head != NULL) {
            IppReceiveHeaderBatch(Protocol, &LoopbackArgsList);
        }

        //
        // Lower the IRQL to give other threads a chance to run.
        //
        KeLowerIrql(OriginalIrql);
        
        //
        // While the lock has been released, there might be more packets queued
        // up in the loopback queue. That is the reason we re-acquire the lock
        // and check again if the queue has more packets. Note that the new
        // packets that are queued won't schedule a new work item because at
        // any point we just want one work item to be running.
        //       
        KeAcquireSpinLock(&Protocol->LoopbackQueueLock, &OriginalIrql);
    } while (Protocol->LoopbackQueue.Head != NULL);

    //
    // At this point, we have verified that there are no packets in the
    // loopback queue. So, we can safely set IsLoopbackTransmitScheduled to
    // FALSE. Any new packets that are queued are going to schedule a work
    // item. 
    //
    Protocol->IsLoopbackTransmitScheduled = FALSE;
    KeReleaseSpinLock(&Protocol->LoopbackQueueLock, OriginalIrql);
}


NETIO_INLINE
BOOLEAN
IppDecrementHopLimit(
    IN PIP_REQUEST_CONTROL_DATA ControlData, 
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    This routine returns the hop limit of the packet after
    decrementing it first. The routine assumes that the IP header in the packet
    is contiguous. 

Arguments:
 
    ControlData - Supplies the input packet.
    
    Protocol - A pointer to the protocol. Used to determine the header size.

Return Value:
   
    Returns a boolean indicating whether the packet should be dropped or not. 

--*/
{
    UCHAR *Header;
    PNET_BUFFER NetBuffer;

    ASSERT(ControlData->NetBufferList->FirstNetBuffer != NULL);
    
    for (NetBuffer = ControlData->NetBufferList->FirstNetBuffer; 
         NetBuffer != NULL; 
         NetBuffer = NetBuffer->Next) {
        //
        // Get the header.
        // The IP header is guaranteed to be in contiguous memory, so we don't
        // need any local storage space and the call to NetioGetDataBuffer
        // should always succeed. It also guarantees that the memory is
        // writable, so we can directly modify the hop count in place. 
        //
        Header = NetioGetDataBufferSafe(NetBuffer, Protocol->HeaderSize);
        
        //
        // Decrement the hop limit and decide whether the packet can be
        // forwarded or not. Note that subsequent ICMP errors (Packet Too 
        // Big, Address Unreachable) will show the decremented hop limit. 
        // They are also generated from the perspective of the outgoing 
        // link.  That is, the source address in the ICMP error is an 
        // address assigned to the outgoing link.
        //
        if (Protocol->Level == IPPROTO_IP) {
            //
            // For non-locally originated packets, update the checksum so that
            // we don't have to recompute the checksum just before sending the
            // packet out.  Also, any ICMP errors sent after this point have
            // the correct checksum in the IP header. 
            //
            PIPV4_HEADER Ipv4Header = (PIPV4_HEADER) Header;
            ULONG Checksum;
            
            if (Ipv4Header->TimeToLive <= 1) {
                return FALSE;
            }
            
            Ipv4Header->TimeToLive--;
            
            //
            // Update checksum for non-locally originated packets.
            //
            if (!ControlData->IsOriginLocal) {
                Checksum = Ipv4Header->HeaderChecksum + 1;
                Checksum = Checksum + (Checksum >> 16);
                Ipv4Header->HeaderChecksum = (UINT16) Checksum;
            }
        } else {
            PIPV6_HEADER Ipv6Header = (PIPV6_HEADER) Header;
            
            if (Ipv6Header->HopLimit <= 1) {
                return FALSE;
            }
     
            Ipv6Header->HopLimit--;
        }
    }
    
    return TRUE;
}

IP_DISCARD_ACTION
IppDiscardReceivedPackets(
    IN PIP_PROTOCOL Protocol,
    IN IP_DISCARD_REASON DiscardReason,
    IN PIP_REQUEST_CONTROL_DATA Control OPTIONAL,    
    IN PIP_SUBINTERFACE SourceSubInterface OPTIONAL,
    IN PNET_BUFFER_LIST NetBufferList OPTIONAL
    )
/*++

Routine Description:

    Call the inspect handler for discarded packets, and updates global and
    sub-interface statistics.  If Control is completely filled in, then
    SourceSubInterface and NetBufferList are optional and ignored.  
    Alternatively only SourceSubInterface and NetBufferList need to be
    specified, and Control will be ignored.

Arguments:

    Protocol - Supplies the global protocol structure (IPv4 or IPv6).

    DiscardReason - Supplies the reason for discarding the packets.
    
    Control - Optionally supplies the metadata of the packets to discard.
        If this is specified, then SourceSubInterface and NetBufferList are
        ignored.  If not specified, then both SourceSubInterface and
        NetBufferList must be supplied.

    SourceSubInterface - Optionally supplies the source sub-interface of the
        packet.  Need not be specified if Control is supplied.

    NetBufferList - Optionally supplies the NetBufferList of the packet.       

Return value:

    Returns IpDiscardAllowIcmp if an ICMP error message may be sent by
    the caller.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG Processor = KeGetCurrentProcessorNumber();
    PIP_GLOBAL_STATISTICS GlobalStatistics = 
        &Protocol->PerProcessorStatistics[Processor];
    PIP_SUBINTERFACE_STATISTICS SubInterfaceStatistics = NULL; 

    BOOLEAN SendIcmpError = TRUE;
    IP_DISCARD_ACTION Action = IpDiscardAllowIcmp;

    ASSERT((Control != NULL) || 
           ((SourceSubInterface != NULL) && (NetBufferList != NULL)));
    if ((Control != NULL) && 
        Control->SourcePointer->Signature == IP_SUBINTERFACE_SIGNATURE) {
        SubInterfaceStatistics = 
            (((PIP_SUBINTERFACE) (Control->SourcePointer))->
              PerProcessorStatistics[Processor]);
    } else if (SourceSubInterface != NULL) {
        SubInterfaceStatistics = 
            SourceSubInterface->PerProcessorStatistics[Processor];    
    }        
        
    //
    // Update statistics based on the discard reason.
    // Also, We send ICMP errors for all errors except
    // IpDiscardNotLocallyDestined and IpDiscardInspectionDrop.
    //
    switch (DiscardReason) {
    case IpDiscardBadSourceAddress:
    case IpDiscardMalformedHeader:        
        GlobalStatistics->InHeaderErrors++;
        if (SubInterfaceStatistics != NULL) {        
            SubInterfaceStatistics->InHeaderErrors++;        
        }
        break;
    case IpDiscardNotLocallyDestined:
        SendIcmpError = FALSE;
        GlobalStatistics->InAddressErrors++;
        break;

    case IpDiscardNoRoute:
        GlobalStatistics->InNoRoutes++;
        break;

    case IpDiscardProtocolUnreachable:
        GlobalStatistics->InUnknownProtocols++;
        break;

    case IpDiscardBadLength:
        GlobalStatistics->InTruncatedPackets++;
        if (SubInterfaceStatistics != NULL) {
            SubInterfaceStatistics->InTruncatedPackets++;
        }            
        break;

    case IpDiscardInspectionDrop:
        SendIcmpError = FALSE;        
        GlobalStatistics->InFilterDrops++;
        break;

    case IpDiscardTooManyDecapsulations:
        SendIcmpError = FALSE;        
    case IpDiscardHopLimitExceeded:
    case IpDiscardAddressUnreachable:
    case IpDiscardBeyondScope:
    case IpDiscardPortUnreachable:
        GlobalStatistics->InDiscards++;
        if (SubInterfaceStatistics != NULL) {        
            SubInterfaceStatistics->InDiscards++;
        }
        break;
    default:
        break;
    }

    if (DiscardReason != IpDiscardInspectionDrop) {
        if (Control != NULL) {        
            NL_LOCAL_ADDRESS Destination, *InspectionDestination;
            NL_ADDRESS_IDENTIFIER DestinationIdentifier;
            PIP_INTERFACE DestinationInterface =
                (Control->NextHop == NULL) 
                ? Control->SourcePointer->Interface 
                : Control->NextHop->Interface;

            //
            // Need to fake Destination for packets that are received but
            // not locally destined.
            //
            if ((Control->NextHop == NULL) ||
                !IppIsNextHopLocalAddress(Control->NextHop)) {
                IppCreateInspectionAddress(
                    &Destination,
                    &DestinationIdentifier,
                    DestinationInterface,
                    Control->CurrentDestinationAddress,
                    Control->CurrentDestinationType);
                InspectionDestination = &Destination;
            } else {
                InspectionDestination = (PNL_LOCAL_ADDRESS) 
                    Control->DestLocalAddress;
            }            

            Action =
                IppInspectDiscardedPackets(
                Protocol->Level,
                (PNL_INTERFACE) Control->SourcePointer->Interface,
                !Control->IsOriginLocal
                ? Control->SourceSubInterface->Index
                : IFI_UNSPECIFIED,
                (PNL_INTERFACE) DestinationInterface,
                (Control->DestNeighbor != NULL)
                ?  Control->DestNeighbor->SubInterface->Index
                : IFI_UNSPECIFIED,
                Control->SourceAddress.Address,
                InspectionDestination,
                Control->NlcReceiveDatagram.NetworkLayerHeadersSize,
                &Control->NlcReceiveDatagram,
                Control->NetBufferList,
                Control->IsOriginLocal,            
                DiscardReason);
        } else {
            Action = IpDiscardAllowIcmp;
            DBG_UNREFERENCED_PARAMETER(SourceSubInterface);
            DBG_UNREFERENCED_PARAMETER(NetBufferList);
    
            /*
                TODO: Add when WFP can handle NULL values for these
                input parameters.
                IppInspectDiscardedPackets(
                    Protocol->Level,
                    (NL_INTERFACE *) SourceSubInterface->Interface,
                    NULL,
                    NULL,
                    NULL,
                    0,
                    NetBufferList,
                    FALSE,            
                    DiscardReason);
            */                    
        }
    }        

    if ((Action == IpDiscardAllowIcmp) && !SendIcmpError) {
        Action = IpDiscardSuppressIcmp;
    }            
        
    return Action;
}


NETIO_INLINE
BOOLEAN
IppForwardingAllowed(
    IN PIP_PROTOCOL Protocol,
    IN PIP_INTERFACE SourceInterface,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN BOOLEAN SourceRouted
    )
/*++

Routine Description:

    Determine if SourceInterface and packet characteristics allow forwarding.

Arguments:

    Protocol - Supplies a pointer to the global protocol structure.

    SourceInterface - Supplies the interface packets are being sourced from.

    Control - Supplies the packets to forward.

    SourceRouted - Supplies TRUE if the packets are being forwarded
        due to being source routed.

Return Value:

    Returns TRUE if forwarding is disallowed, FALSE if not.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.
    
--*/
{
    if (SourceInterface->Forward) {
        if (SourceRouted) {
            if (Protocol->SourceRoutingBehavior == SourceRoutingForward) {
                //
                // We forward source routed only if we are a router
                // and source routed forwarding is explicitly enabled 
                // (as down-level does). Below there are exceptions  
                // due to weak host local send/receive forwarding.
                //
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }
    
    if (Control->IsOriginLocal) {
        //
        // Weak host send behavior allows us to send packets on interfaces
        // other than the one the packet was originated from.
        //
        if (SourceInterface->WeakHostSend) {
            return TRUE;
        }
    } else {        
        //
        // Weak host receive behavior allows us to accept the packet,
        // but only if it will be received locally on another interface.
        //
        if (SourceInterface->WeakHostReceive &&
            IppIsNextHopLocalAddress(Control->NextHop)) {
            return TRUE;
        }
    }

    return FALSE;
}


BOOLEAN
IppForwardPackets(
    IN PIP_PROTOCOL Protocol,
    IN PIP_INTERFACE SourceInterface,
    IN PIP_INTERFACE OutgoingInterface,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_NEXT_HOP NextHop OPTIONAL,
    IN BOOLEAN SourceRouted,
    IN BOOLEAN StrictSourceRouted,
    OUT IP_DISCARD_REASON *DiscardReason
    )
/*++

Routine Description:

    Do behavior specific to the forwarding path.
    Compare IPv6Forward() in the XP IPv6 stack.

Arguments:

    Protocol - Supplies a pointer to the global protocol structure.

    SourceInterface - Supplies the interface the packets are being
        forwarded from.

    OutgoingInterface - Supplies the interface the packets are being
        forwarded to.

    Control - Supplies the packets to forward.

    NextHop - Supplies the nexthop, if any.

    SourceRouted - Supplies TRUE if the packets are being forwarded
        due to being source routed.

    StrictSourceRouted - Supplies TRUE if the packets are being forwarded
        due to being strictly source routed.
    
    DiscardReason - Returns the reason the packet should be discarded in case
        the return value of the routine is FALSE. 

Return Value:

    TRUE if the packet should be sent, or FALSE if it should be dropped.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_DISCARD_ACTION Action;
    CONST UCHAR *DestinationAddress = Control->CurrentDestinationAddress;
    SCOPE_LEVEL SourceScope;
    ULONG PacketCount;
    PIP_GLOBAL_STATISTICS Stats;
    
    if (!IppForwardingAllowed(
            Protocol,
            SourceInterface,
            Control,
            SourceRouted)) {
        *DiscardReason = IpDiscardNotLocallyDestined;
        return FALSE;
    }
    
    PacketCount = IppGetPacketCount(Control->NetBufferList);
    Stats = &Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()];
    Stats->InForwardedDatagrams += PacketCount;

    //
    // Check for "scope" errors.  We can't allow a packet with a scoped
    // source address to leave its scope.
    //
    SourceScope = Protocol->AddressScope(Control->SourceAddress.Address);
    if (IppGetInterfaceScopeZone(SourceInterface, SourceScope) !=
        IppGetInterfaceScopeZone(OutgoingInterface, SourceScope)) {
        *DiscardReason = IpDiscardBeyondScope;
        return FALSE;
    }

    //
    // Check that the hop limit allows the packet to be forwarded.
    //
    if (IppDecrementHopLimit(Control, Protocol) == 0) {
        //
        // Send ICMP hop limit exceeded message. This is not an
        // error. The hop limit check has failed but the packet might
        // still be delivered to destination for which the "strong
        // host" lookup succeeded. 
        //
        *DiscardReason = IpDiscardHopLimitExceeded;
        return FALSE;
    }
    
    //
    // Are we forwarding the packet out the link on which it arrived,
    // and we should consider a Redirect?
    //
    if ((SourceInterface == OutgoingInterface) && 
        !SourceRouted &&
        IppIsNextHopNeighbor(NextHop)) {
        //
        // We do not want to forward a packet back onto a p2p link,
        // because it will very often lead to a loop.
        // One example: a prefix is on-link to a p2p link between routers
        // and someone sends a packet to an address in the prefix
        // that is not assigned to either end of the link.
        //

        if (OutgoingInterface->FlCharacteristics->AccessType ==
            IF_ACCESS_POINT_TO_POINT) {
            *DiscardReason =
                RtlEqualMemory(
                    IP_NEIGHBOR_NL_ADDRESS(NextHop),
                    DestinationAddress,
                    Protocol->Characteristics->AddressBytes)
                ? IpDiscardAddressUnreachable
                : IpDiscardNoRoute;
            return FALSE;
        }

        //
        // We SHOULD send a Redirect, whenever
        // 1. The Source address of the packet specifies a neighbor, and
        // 2. A better first-hop resides on the same link, and
        // 3. The Destination address is not multicast.
        // See Section 8.2 of RFC 2461.
        //
        if (OutgoingInterface->FlCharacteristics->DiscoversRouters &&
            (Control->CurrentDestinationType == NlatUnicast)) {
            IppSendRedirect(Control, (PIP_NEIGHBOR) NextHop);
        }
    }

    //
    // Strict source routed packets must never be forwared to a neighbor
    // directly.  Instead they must take the local recieve path for
    // processing.  In other words a strict source routed received packet 
    // should always be meant for the local machine.
    //
    if (StrictSourceRouted && 
         NextHop != NULL && 
         IppIsNextHopNeighbor(NextHop)) {
        *DiscardReason = IpDiscardNotLocallyDestined;
        return FALSE;
    }

    //
    // Call inspection point for forwarded packets.
    //
    Action =
        IppInspectForwardedPacket(
            Protocol->Level,
            (PNL_INTERFACE) SourceInterface,
            !Control->IsOriginLocal
            ? Control->SourceSubInterface->Index
            : IFI_UNSPECIFIED,
            Control->IsOriginLocal,
            (PNL_INTERFACE) OutgoingInterface,
            ((NextHop != NULL) && 
            (IppIsNextHopNeighbor(NextHop)))
            ?  ((PIP_NEIGHBOR) NextHop)->SubInterface->Index
            : IFI_UNSPECIFIED,
            (!SourceRouted) && 
            (NextHop != NULL) && 
            (IppIsNextHopLocalAddress(NextHop)),
            Control->SourceAddress.Address,
            DestinationAddress,
            NlatUnicast,
            Control->NetBufferList);
    if (Action >= IpFilterDrop) {
        if ((Action == IpFilterDrop) || (Action == IpFilterDropAndSendIcmp)) {
            Control->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        } else {
            ASSERT(Action == IpFilterAbsorb);
        }
        *DiscardReason = IpDiscardInspectionDrop;
        return FALSE;
    }
    ASSERT(Action == IpFilterAllow);

    Stats->OutForwardedDatagrams += PacketCount;
    return TRUE;
}


__inline
VOID
IppDiscardSendPackets(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN IP_DISCARD_REASON DiscardReason,
    IN BOOLEAN SendIcmpError
    )
/*++

Routine Description:

    This routine updates statistics for discarded packets on the send path and
    sends an ICMP error if required. 

Arguments:

    Protocol - Supplies a pointer to the global protocol structure.

    Control - Supplies the metadata of the packets to discard.

    DiscardReason - Supplies the reason for discarding the packets.

    SendIcmpError - Supplies whether to send ICMP errors.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ASSERT(Control->IsOriginLocal);
    
    Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        OutDiscards += IppGetPacketCount(Control->NetBufferList);

    //
    // We send ICMP errors for all errors except
    // IpDiscardNotLocallyDestined and IpDiscardInspectionDrop.
    //
    switch (DiscardReason) {
    case IpDiscardNotLocallyDestined:
    case IpDiscardInspectionDrop:
        SendIcmpError = FALSE;
        break;
    }

    //
    // TODO: Work with WFP and hook up send discards also.  Currently not
    // high priority for WFP team.
    //

    if (SendIcmpError) {
        IppSendErrorListForDiscardReason(
            FALSE,
            Protocol,
            Control,
            DiscardReason,
            0);
    }

    IppCompleteAndFreePacketList(Control, FALSE);
}


VOID
IppDispatchSendPacketHelper(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control
    ) 
/*++

Routine Description:

    This routine dispatches a packet on the send path.
    There are three different possibilities for a packet on the send path: 
    1. The packet gets sent out to a remote address.
    2. The packet is destined for a local destination.
       A single NetBufferList may be coverted into multiple NetBufferLists in
       the loopback queue because of the invariant on the receive path that a
       NetBufferList can have a single NetBuffer.
    3. A multicast packet can be both looped back and sent out an interface.

    TODO: This function could be rewritten to be much more readable.
    
Arguments:

    Protocol - A pointer to the protocol (v4 or v6).

    Control - The input packet that needs to be dispatched.

Return Value:

    None.

    The routine receives a reference on the NetBufferList. On exit, the
    reference count on the NetBufferList is equal to the number of NetBuffer
    lists being sent (locally or remotely). If the NetBufferList had a ref
    count of r on entry and x NetBufferLists are sent on the loopback path
    and y on the remote path, then the reference count on exit is (r +
    x + y - 1). If there are no NetBufferLists being processed further (error 
    case), then the incoming reference count on the NetBufferList is released
    (the reference count on exit is r - 1). So, the caller does not have to
    worry about releasing any references. It just passes on the packets to the
    next processing routine. Control structures have similar semantics. Only,
    the packets that need to be processed further have to be freed. In case of 
    error, this routine frees the input control structure.

Caller IRQL:
    
    May be called at PASSIVE through DISPATCH level.

    TODO: Combine this with IppPacketizeDatagrams. 

--*/
{
    IP_GENERIC_LIST LoopbackPackets, RemotePackets;
    PIP_INTERFACE SourceInterface, DestinationInterface;
    PIP_NEXT_HOP NextHop;
    PIP_LOCAL_ADDRESS LocalAddress;
    PIP_NEIGHBOR Neighbor;
    NL_ADDRESS_TYPE LocalAddressType;
    IP_DISCARD_REASON DiscardReason;
    BOOLEAN SendError = TRUE;
    
    NextHop = Control->NextHop;
    SourceInterface = Control->SourceLocalAddress->Interface;
 
    if (IppIsNextHopNeighbor(NextHop)) {
        Neighbor = (PIP_NEIGHBOR) NextHop;

        if ((Neighbor->AddressType == NlatMulticast) && 
            (Protocol->MldLevel < MldLevelSendOnly)) {
            IppDiscardSendPackets(
                Protocol,
                Control,
                IpDiscardAddressUnreachable,
                SendError);
            return;
        }
        
ProcessRemotePacket:        
        DestinationInterface = Neighbor->Interface;
        if (DestinationInterface == SourceInterface) {
            //
            // Ensure that the hop limit is not zero.  This packet is going
            // out the same interface.  The hop limit should be > 0. 
            //
            if (*(UINT8*)(Control->IP + Protocol->TtlOffset) == 0) {
                IppDiscardSendPackets(
                    Protocol,
                    Control,
                    IpDiscardHopLimitExceeded,
                    SendError);
                return;
            }
        } else if (!IppForwardPackets(
                       Protocol,
                       SourceInterface,
                       Neighbor->Interface,
                       Control,
                       NextHop,
                       FALSE,
                       FALSE,
                       &DiscardReason)) {
            IppDiscardSendPackets(
                Protocol,
                Control,
                DiscardReason,
                SendError);
            return;
        }

        if (SourceInterface->ForwardMulticast && 
            (Control->CurrentDestinationType == NlatMulticast)) {
            IP_GENERIC_LIST RemoteArgs;
            KIRQL OldIrql;
            
            IppInitializeGenericList(&RemoteArgs);
            OldIrql = KeRaiseIrqlToDpcLevel();
            IppForwardMulticastPackets(SourceInterface, Control, &RemoteArgs);

            KeLowerIrql(OldIrql);
            if (RemoteArgs.Head != NULL) {
                //
                // Send packets on forward path.
                //
                // NTRAID#Longhorn-291001-2005/09/09-sgarg -- Multicast 
                // Forwarding should also handle delivery of packets to 
                // listeners on other local interfaces.
                //
                IppFragmentPackets(Protocol, RemoteArgs.Head);
            }
        }
         
        if (DestinationInterface->ConnectedSubInterfaces > 1) {
            NL_ADDRESS_TYPE DestinationType;
        
            DestinationType = Control->CurrentDestinationType;
            if ((DestinationType == NlatMulticast) ||
                (DestinationType == NlatBroadcast)) {
                IppCreateSubInterfaceSplitList(
                    Protocol,
                    Control,
                    &RemotePackets);
                IppFragmentPackets(Protocol, RemotePackets.Head);
                return;
            }
        }

        IppFragmentPackets(Protocol, Control);
        return;        
    } else if (IppIsNextHopLocalAddress(NextHop)) {
        LocalAddress = (PIP_LOCAL_ADDRESS) NextHop;
        LocalAddressType = NL_ADDRESS_TYPE(LocalAddress);
        if ((LocalAddressType != NlatBroadcast) &&
            (LocalAddressType != NlatMulticast)) {
ProcessLocalPacket:
            if (LocalAddress->Interface != SourceInterface) {
                //
                // The hop limit needs to be decremented and the source
                // interface needs to be forwarding because the source and
                // destination interfaces are different.
                // 
                if (!IppForwardPackets(
                        Protocol,
                        SourceInterface,
                        LocalAddress->Interface,
                        Control,
                        NextHop,
                        FALSE,
                        FALSE,
                        &DiscardReason)) {
                    IppDiscardSendPackets(
                        Protocol,
                        Control,
                        DiscardReason,
                        SendError);
                    return;
                }
            }
            
            if (IppCreateLoopbackSplitList(
                    Control, FALSE, Protocol, &LoopbackPackets)) {
                IppCompleteAndFreePacketList(Control, FALSE);
            }

            if (LoopbackPackets.Head != NULL) {
                IppLoopbackEnqueue(&LoopbackPackets, Protocol, FALSE);
            }                
            return;

        } else {
            if ((LocalAddressType == NlatMulticast) &&
                (Protocol->MldLevel < MldLevelSendOnly)) {
                IppDiscardSendPackets(
                    Protocol,
                    Control,
                    IpDiscardAddressUnreachable,
                    SendError);
                return;
            }
            
            Neighbor =
                IppFindOrCreateNeighbor(
                    SourceInterface, 
                    NULL,
                    NL_ADDRESS(LocalAddress),
                    LocalAddressType);
            if (Neighbor == NULL) {
                goto ProcessLocalPacket;
            }

            // 
            // The packet is also being sent remotely (Neighbor is not
            // NULL), do a strong clone (the packet is cloned even if there is
            // just one NetBuffer in the packet). Strong clone also makes sure
            // the clone does not share the header space.
            // TODO: The strong clone is needed for packets going out on the
            // interface which are fragmented (and only for V4) or if the hop
            // limit is changed. As an optimization, we can delay the strong
            // cloning until the point that fragmentation is actually required.
            //
            (VOID) IppCreateLoopbackSplitList(
                Control, TRUE, Protocol, &LoopbackPackets);
            if (LoopbackPackets.Head != NULL) {
                if (LocalAddress->Interface != SourceInterface) {
                    //
                    // The multicast packet will not be delivered to 
                    // a listener on a local interface other than the source 
                    // interface. Multicast forwarding will take care of that.
                    //
                    ASSERT(FALSE); 
                } else {
                    //
                    // The packet is being cloned and delivered locally.
                    // No ICMP error should be generated for the original.
                    //
                    SendError = FALSE;
                    IppLoopbackEnqueue(&LoopbackPackets, Protocol, FALSE);
                }
            }
            
            if (Control->IsPathReferenced) {
                IppDereferencePath(Control->Path);
                Control->IsPathReferenced = FALSE;
            }
            Control->Path = NULL;
            if (Control->IsNextHopReferenced) {
                IppDereferenceNextHop(Control->NextHop);
            }
            Control->NextHopNeighbor = Neighbor;
            Control->IsNextHopReferenced = TRUE;

            goto ProcessRemotePacket;
        }
    } else {
        IppFragmentPackets(Protocol, Control);
        return;
    }
}


VOID
IppClearForwardInjectionParametersAtDpc(
    ) 
/*++

Routine Description:

    This routine clears the per-processor forward injection cache. Called when 
    there is a cache-miss (to clear old cache content), or at the end of 
    one receive indiction (by IppDequeueForwardInjectedPackets).  

Arguments:

    None

Return Value:

    None.
    
Caller IRQL:

    DISPATCH level.

--*/
{
    ULONG Processor = KeGetCurrentProcessorNumber();

    PIP_FORWARD_INJECTION_CACHE_ENTRY Entry = 
        &ForwardInjectionPerProcessorState[Processor].ForwardInjectionCache;
    
    DISPATCH_CODE();    
    
    // 
    // Return immediately if the cache is already cleared.
    //
    if (!Entry->IsValid) {
        return;
    }
    if (Entry->Value.Compartment != NULL) {
        IppDereferenceCompartment(Entry->Value.Compartment);
    }

    if (Entry->Value.Interface != NULL) {
        IppDereferenceInterface(Entry->Value.Interface);
    }

    if (Entry->Value.SubInterface != NULL) {
        IppDereferenceSubInterface(Entry->Value.SubInterface);
    }

    if (Entry->Value.Path != NULL) {
        IppDereferencePath(Entry->Value.Path);
    }

    if (Entry->Value.Neighbor != NULL) {
        IppDereferenceNeighbor(Entry->Value.Neighbor);
    }

    RtlZeroMemory(Entry, sizeof(*Entry));
    //
    // ASSERT: Entry->IsValid == FALSE
    //
}

NTSTATUS 
IppGetForwardInjectionParameters(
    IN PIP_PROTOCOL Protocol,
    IN PNET_BUFFER NetBuffer,
    IN COMPARTMENT_ID CompartmentId,
    IN IF_INDEX InterfaceIndex,
    IN BOOLEAN InReceiveIndication,
    OUT PIP_COMPARTMENT* Compartment,
    OUT PIP_INTERFACE* Interface,
    OUT PIP_SUBINTERFACE* SubInterface,    
    OUT PIP_PATH* Path,
    OUT PIP_NEIGHBOR* Neighbor
    )
/*++

Routine Description:

    This routine retrieves parameters (pointers) for a forward injection 
    request. It will try the per-proc cache first, if there is a miss, it will 
    call various NL routines to obtain the parameters and re-populate the cache.

Arguments:

    Protocol - Identifies the IP protocol number for the injected packet.

    NetBuffer - Supplies the first netbuffer in the NBL.

    CompartmentId - Identifies the compartment from which the packet should
        be forwarded.

    InterfaceIndex - Identifies the interface onto which the packet should be
        forwarded.

    InReceiveIndication - Supplies whether this call is made in a receive 
        indication.

    Compartment - Returns a pointer to the compartment object, reference will 
        be taken on behalf of the caller.        

    Interface - Returns a pointer to the interface object, reference will 
        be taken on behalf of the caller.        

    SubInterface - Returns a pointer to the sub-interface object, reference will 
        be taken on behalf of the caller.        

    Path - Returns a pointer to the path object, reference will 
        be taken on behalf of the caller.        

    Neighbor - Returns a pointer to the Neighbor object, reference will 
        be taken on behalf of the caller.        

Return Value:

    NTSTATUS - Success or failure status..

Caller IRQL:

    <=DISPATCH level.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    UCHAR* Destination = NULL;
    ULONG Processor;
    PIP_FORWARD_INJECTION_CACHE_ENTRY Entry;    
    KIRQL OldIrql = 0;

    //
    // Cache is only protected per processor so we must be at DISPATCH_LEVEL.
    // Raise IRQL if we are not in receive indication.
    //
    
    if (InReceiveIndication == FALSE) {
        KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    }

    DISPATCH_CODE();
    
    Processor = KeGetCurrentProcessorNumber();
    Entry = 
        &ForwardInjectionPerProcessorState[Processor].ForwardInjectionCache;
    
    //
    // Parse the destination address.
    // The FL provider and lower layers guarantee that the IP header is in
    // contiguous memory, so we don't need any local storage space and
    // NetioGetDataBufferSafe should always succeed.
    //
    if (IS_IPV4_PROTOCOL(Protocol)) {
        PIPV4_HEADER Header;        
        if (NetBuffer->DataLength < sizeof(IPV4_HEADER)) {        
            Status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }            
        Header = NetioGetDataBufferSafe(NetBuffer, sizeof(IPV4_HEADER));
        Destination = (UCHAR *) &Header->DestinationAddress;
    } else {
        PIPV6_HEADER Header;    
        if (NetBuffer->DataLength < sizeof(IPV6_HEADER)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }            
        Header = NetioGetDataBufferSafe(NetBuffer, sizeof(IPV6_HEADER));
        Destination = (UCHAR *) &Header->DestinationAddress;
    }        
    
    if (Entry->IsValid &&
        (Entry->Key.Protocol == Protocol) &&
        (Entry->Key.CompartmentId == CompartmentId) && 
        (Entry->Key.InterfaceIndex == InterfaceIndex) &&
        RtlEqualMemory(
            Entry->Key.Destination.Buffer,
            Destination,
            Protocol->Characteristics->AddressBytes)) {
        //
        // Cache match.
        //
    } else {
        //
        // Cache miss. Determine and cache the new parameters.
        //
        IppClearForwardInjectionParametersAtDpc();

        Entry->IsValid = TRUE;
        Entry->Key.Protocol = Protocol;
        Entry->Key.CompartmentId = CompartmentId;
        Entry->Key.InterfaceIndex = InterfaceIndex;
        RtlCopyMemory(
            Entry->Key.Destination.Buffer,
            Destination,
            Protocol->Characteristics->AddressBytes);

        Entry->Value.Compartment = 
            IppFindCompartmentById(Protocol, CompartmentId);
        if (Entry->Value.Compartment == NULL) {
            Status = STATUS_NOT_FOUND;
            goto Exit;            
        }

        Entry->Value.Interface = 
            IppFindInterfaceByIndex(Entry->Value.Compartment, InterfaceIndex);
        if (Entry->Value.Interface == NULL) {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;                        
        }

        Entry->Value.SubInterface = 
            IppFindAnySubInterfaceOnInterface(Entry->Value.Interface);
        if (Entry->Value.SubInterface == NULL) {
            Status = STATUS_NETWORK_UNREACHABLE;
            goto Exit;                        
        }
        
        Status =
            IppRouteToDestination(
                Entry->Value.Compartment,
                Destination,
                IppGetScopeId(Entry->Value.Interface, Destination),
                Entry->Value.Interface,
                NULL,
                &Entry->Value.Path);
        if (!NT_SUCCESS(Status)) {
            ASSERT(Path == NULL);
                goto Exit;                        
        }
        
        Entry->Value.Neighbor = IppGetNeighborFromPath(Entry->Value.Path);
        if (Entry->Value.Neighbor == NULL) {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }        

    //
    // Add another reference to each of the parameters we are returning.
    // The existing reference is for the cache itself.
    //
    IppReferenceCompartment(Entry->Value.Compartment);
    IppReferenceInterface(Entry->Value.Interface);
    IppReferenceSubInterface(Entry->Value.SubInterface);
    IppReferencePath(Entry->Value.Path);
    IppReferenceNeighbor(Entry->Value.Neighbor);
        
    *Compartment = Entry->Value.Compartment;        
    *Interface = Entry->Value.Interface;
    *SubInterface = Entry->Value.SubInterface;
    *Path = Entry->Value.Path;
    *Neighbor = Entry->Value.Neighbor;

Exit:    
    if (!NT_SUCCESS(Status) || 
        (InReceiveIndication == FALSE)) {
        //
        // Clear the cache if we failed. Or if we are not in receive 
        // indication (slow path), we need to clear the cache at here.
        //
        IppClearForwardInjectionParametersAtDpc();    
    }

    if (InReceiveIndication == FALSE) {
        KeLowerIrql(OldIrql);
    }
    return Status;    
}    
        
VOID
IppQueueForwardInjectedPackets(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    This routine queues a forward-injected packet to per-processor 
    queue for later processing. The packet will be dequeued by 
    IppDequeueForwardInjectedPackets() at the end of a receive indication.

    Caller must make sure it only calls this routine in the context of a 
    receive indication.

Arguments:

    Protocol - Identifies the IP protocol number for the injected packet.

    Packet - Supplies a pointer to a fully initialized CONTROL structure which 
        represents a packet to be sent.

Return Value:

    None.
    
Caller IRQL:

    DISPATCH level.

--*/
{
    ULONG Processor;
    PIP_GENERIC_LIST Queue;

    //
    // If we are Queueing we should already be in the context of a receive
    // indication and hence already at DISPATCH_LEVEL.
    //
    DISPATCH_CODE();    
    
    Processor = KeGetCurrentProcessorNumber();
    if (IS_IPV4_PROTOCOL(Protocol)) {
        Queue = 
            &ForwardInjectionPerProcessorState[Processor].Ipv4DelayQueue;
    } else {
        Queue = 
            &ForwardInjectionPerProcessorState[Processor].Ipv6DelayQueue;
    }

    IppAppendToGenericList(Queue, Packet);
}

VOID
IppDequeueForwardInjectedPacketsAtDpc(
    )
/*++

Routine Description:

    This routine dequeues packets from per-processor queue and calls 
    IppFragmentPackets() to send them.  

Arguments:

    None.

Return Value:

    None.

--*/
{
    ULONG Processor;
    PIP_GENERIC_LIST Queue;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    //
    // Queue is only protected per processor so we must be at DISPATCH_LEVEL.
    //
    Processor = KeGetCurrentProcessorNumber();    
    Queue = 
        &ForwardInjectionPerProcessorState[Processor].Ipv4DelayQueue;
    if (!IppIsGenericListEmpty(Queue)) {    
        IppFragmentPackets(&Ipv4Global, Queue->Head);        
        IppInitializeGenericList(Queue);
    }    
    
    Queue = 
        &ForwardInjectionPerProcessorState[Processor].Ipv6DelayQueue;
    if (!IppIsGenericListEmpty(Queue)) {
        IppFragmentPackets(&Ipv6Global, Queue->Head);
        IppInitializeGenericList(Queue);        
    }

    //
    // We must clear our forward injection parameter cache at here otherwise 
    // we'll have leaks. This is the end of our receive indication.
    //

    IppClearForwardInjectionParametersAtDpc();

}

VOID
IppInspectInjectForward(
    IN IPPROTO IpProtocol,
    IN COMPARTMENT_ID CompartmentId,
    IN IF_INDEX InterfaceIndex,
    IN PNET_BUFFER_LIST NetBufferList
    )
/*++

Routine Description:

    This routine injects a packet into the forward path on behalf of the
    inspection module.

Arguments:

    IpProtocol - Identifies the IP protocol number for the injected packet.

    CompartmentId - Identifies the compartment from which the packet should
        be forwarded.

    InterfaceIndex - Identifies the interface onto which the packet should be
        forwarded.

    NetBufferList - Supplies the packet to be injected.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_COMPARTMENT Compartment = NULL;
    PIP_INTERFACE Interface = NULL;
    PIP_SUBINTERFACE SubInterface = NULL;
    PIP_PATH Path = NULL;
    PIP_NEIGHBOR Neighbor = NULL;
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo = {0};
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    PIP_PROTOCOL Protocol;
    PNET_BUFFER FirstNetBuffer;
    BOOLEAN InReceiveIndication = IppInReceiveIndication();
        
    //
    // We'll resolve the caller's target IP protocol, compartment,
    // and interface, and use them to forward the given NetBufferList.
    //
    ASSERT(NetBufferList->Next == NULL);

    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;

    Control = (PIP_REQUEST_CONTROL_DATA)
        FsbAllocate(Protocol->ControlPool);
    if (Control == NULL) {
        NetBufferList->Status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupAndReturn;
    }
    RtlZeroMemory(Control, sizeof(*Control));
    Control->IsAllocated = TRUE;

    //
    // Lookup up common cached results required for reinjection.
    //
    NetBufferList->Status =
        IppGetForwardInjectionParameters(
            Protocol,
            NetBufferList->FirstNetBuffer,
            CompartmentId, 
            InterfaceIndex,
            InReceiveIndication,
            &Compartment, 
            &Interface, 
            &SubInterface,
            &Path,
            &Neighbor);
    if (!NT_SUCCESS(NetBufferList->Status)) {
        goto CleanupAndReturn;
    }

    //
    // We'll now initialize its control structure.
    //
    NBL_SET_PROT_RSVD_FLAG(NetBufferList, NBL_NAT_RESERVED);

    Control->NetBufferList = NetBufferList;

    Control->SourceSubInterface = SubInterface;
    Control->IsSourceReferenced = TRUE;

    Control->Compartment = Compartment;
    FirstNetBuffer = NetBufferList->FirstNetBuffer;

    ChecksumInfo.Receive.NdisPacketIpChecksumSucceeded = TRUE;

    while (NetBufferList->FirstNetBuffer != NULL) {
        NetBufferList->Status =
            Protocol->ValidateNetBuffer(Control, &ChecksumInfo);
        if (!NT_SUCCESS(NetBufferList->Status)) {
            NetBufferList->FirstNetBuffer = FirstNetBuffer;
            goto CleanupAndReturn;
        }
        NetBufferList->FirstNetBuffer = NetBufferList->FirstNetBuffer->Next;
    }

    //
    // Reset the first NetBuffer
    //

    NetBufferList->FirstNetBuffer = FirstNetBuffer;

    Control->CurrentDestinationType =
        Protocol->AddressType(Control->CurrentDestinationAddress);

    Control->Path = Path;
    Control->IsPathReferenced = TRUE;

    Control->NextHop = (PIP_NEXT_HOP) Neighbor;
    Control->IsNextHopReferenced = TRUE;

    //
    // Fragment packets that are forward injected must not be grouped and 
    // indicated to WFP. This is for the common scenario of NATs where
    // performance is of a concern.  This is a similar reason why forward
    // injected non-fragments are not indicated at the forward layer,
    // but send-injected packets are reindicated at the send layer.
    // i.e it's consitent with forward injection semantics.
    //
    Control->NoFragmentGrouping = TRUE;

    if (InReceiveIndication) {
        IppQueueForwardInjectedPackets(Protocol, Control);
    } else {
        IppFragmentPackets(Protocol, Control);
    }        

    //
    // Our reference on these objects is (or will be) transferred to 
    // IppFragmentPackets.
    //
    Path = NULL;
    Neighbor = NULL;
    SubInterface = NULL;
    NetBufferList = NULL;

    //
    // "Control" will be free'd by IppFragmentPackets in non-error case.
    //
    Control = NULL;    

CleanupAndReturn:
    if (Neighbor != NULL) {
        IppDereferenceNeighbor(Neighbor);
    }

    if (Path != NULL) {
        IppDereferencePath(Path);
    }
    
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

    if (Control != NULL) {
        FsbFree((PUCHAR)Control);
    }
}


NTSTATUS
NTAPI
IpSetAllDbgInjectForwardParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Injects a forward packet.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    IPV6_HEADER UNALIGNED* Ipv6Header;
    PNET_BUFFER_LIST NetBufferList;
    NTSTATUS Status;
    
    PNLP_DBG_INJECT_FORWARD_KEY Key =
        (PNLP_DBG_INJECT_FORWARD_KEY) Args->KeyStructDesc.KeyStruct;
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
    IppInspectInjectForward(
        IPPROTO_IPV6,
        DEFAULT_COMPARTMENT_ID,
        Key->InterfaceIndex,
        NetBufferList);
    NetBufferList = NULL;

CleanupAndReturn:
    if (NetBufferList != NULL) {
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
    }

    return Status;
}

