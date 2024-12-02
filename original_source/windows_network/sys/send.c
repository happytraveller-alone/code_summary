/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    send.c

Abstract:

    This module implements the protocol-independent functions of the
    Fragmenter module.

Author:

    Dave Thaler (dthaler) 27-Sep-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"

IP_SESSION_STATE IppSendDirectSessionState;

NETIO_INLINE
VOID
IppUpdatePacketCounts(
    IN PIP_PROTOCOL Protocol,
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Update the packet and byte counts on a subinterface.

Arguments:

    Protocol - Supplies the protocol metadata.

    SubInterface - Supplies the sub-interface whose statistics to update.

    Control - Supplies the packets to use to update the counts.

--*/
{
    PIP_SUBINTERFACE_STATISTICS SubInterfaceStats;
    PIP_GLOBAL_STATISTICS GlobalStats;
    ULONG Index, PacketCount, ByteCount;

    ASSERT(Protocol == SubInterface->Interface->Compartment->Protocol);

    ASSERT(Control->Next == NULL);

    IppGetPacketAndByteCounts(
        Control->NetBufferList,
        &PacketCount,
        &ByteCount);

    Index = KeGetCurrentProcessorNumber();

    SubInterfaceStats = SubInterface->PerProcessorStatistics[Index];
    SubInterfaceStats->OutTransmits += PacketCount;
    SubInterfaceStats->OutOctets += ByteCount;

    GlobalStats = &Protocol->PerProcessorStatistics[Index];
    GlobalStats->OutTransmits += PacketCount;
    GlobalStats->OutOctets += ByteCount;

    switch (Control->CurrentDestinationType) {
    case NlatMulticast:
        GlobalStats->OutMulticastPackets += PacketCount;
        GlobalStats->OutMulticastOctets += ByteCount; 
        break;

    case NlatBroadcast:
        GlobalStats->OutBroadcastPackets += PacketCount;
        break;
    } 
}


VOID
IppSendDirect(
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface, 
    IN PIP_NEIGHBOR Neighbor OPTIONAL,
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress OPTIONAL,
    IN CONST UCHAR *RemoteAddress,
    IN IPPROTO TransportProtocol,
    IN PVOID TransportData,
    IN USHORT ChecksumOffset,
    IN PNET_BUFFER_LIST NetBufferList
    )
/*++

Routine Description:

    Used, for example, to force a packet to be sent from the unspecified
    (all-zeros) source address (during duplicate address detection).

Arguments:

    Interface - Supplies the interface over which to send the packet.

    SubInterface - Supplies the sub-interface over which to send the packet.
    
    Neighbor - Optionally supplies the neighbor to which to send the packet.
        NULL indicates that the RemoteAddress is onlink.
    
    LocalAddress - Optionally supplies the source address.
        NULL indicates that the packet must be sent with unspecified address.

    RemoteAddress - Supplies the destination address.

    TransportProtocol - Supplies the upper-layer protocol value.

    TransportData - Supplies the upper-layer data (for inspection callouts).

    ChecksumOffset - Supplies the upper-layer checksum offset.
    
    NetBufferList - Supplies the list of packets to be sent. 

--*/
{
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    BOOLEAN NeighborReferenced = FALSE, LocalAddressReferenced = FALSE;
    NL_REQUEST_SEND_DATAGRAMS Args = {0};

    ASSERT(NetBufferList->Next == NULL);
    
    if (Neighbor == NULL) {
        Neighbor =
            IppFindOrCreateNeighborWithoutType(
                Interface,
                SubInterface,
                RemoteAddress);
        if (Neighbor == NULL) {
            goto Bail;
        }
        NeighborReferenced = TRUE;
    }
    ASSERT(SubInterface == Neighbor->SubInterface);
    
    if (LocalAddress == NULL) {
        NetBufferList->Status =
            IppFindOrCreateLocalUnspecifiedAddress(Interface, &LocalAddress);
        if (!NT_SUCCESS(NetBufferList->Status)) {
            goto Bail;
        }
        LocalAddressReferenced = TRUE;
    } 

    //
    // Send the datagram.
    //
    Args.NetBufferList = NetBufferList;
    Args.DestProtocol = TransportProtocol;
    Args.TransportData = TransportData;
    Args.UlChecksumOffset = ChecksumOffset;
    Args.NlSessionState = &IppSendDirectSessionState;
    Args.NextHop = Neighbor;
    Args.NlLocalAddress.LocalAddress = (PNL_LOCAL_ADDRESS) LocalAddress;
    Args.RemoteAddress = RemoteAddress;
    Args.NlCompartment.Compartment = (PNL_COMPARTMENT) Compartment;
    
    IppSendDatagrams(Compartment->Protocol, &Args);
    NetBufferList = NULL;
    
Bail:
    if (NetBufferList != NULL) {
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
    }
    
    if (NeighborReferenced) {
        IppDereferenceNeighbor(Neighbor);    
    }

    if (LocalAddressReferenced) {
        IppDereferenceLocalUnicastAddress(LocalAddress);
    }
}


VOID
IppFragmentPackets(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:

    Given a set of packets, make one downcall to an FL provider for each
    set of consecutive packets destined to the same subinterface.

Arguments:

    Protocol - Supplies the protocol metadata.

    Args - Supplies a list of packets to send.

Return Value:

    None.

    Consumes the reference on the NetBufferLists by passing it to the framing
    layer or releasing it in case of error.  Frees IP_REQUEST_CONTROL_DATA's.

Caller Lock:

    Caller should hold no locks, since a call outside the module is made.

Caller IRQL:

    Callable at PASSIVE through DISPATCH level.

--*/
{
    PIP_REQUEST_CONTROL_DATA Control;
    IP_GENERIC_LIST DonePackets, SendPackets;
    PIP_SUBINTERFACE SubInterface, BatchSubInterface = NULL;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;

    IppInitializeGenericList(&DonePackets);
    IppInitializeGenericList(&SendPackets);

    while ((Control = Args) != NULL) {
        Args = Args->Next;
        Control->Next = NULL;

        ASSERT(Control->NetBufferList->Next == NULL);
        ASSERT(IppIsNextHopNeighbor(Control->NextHop));
        
        //
        // If this packet is a fragment of non-local origin,
        // we may need to group it with the other fragments
        // from its original datagram if we haven't done so already.
        //
        if (Protocol->GroupForwardedFragments &&
            !Control->IsOriginLocal &&
            !Control->NoFragmentGrouping &&
            IppGroupFragments(Protocol, Control, &Args)) {
            //
            // The fragment grouping logic accepted this fragment.
            // If the fragment was absorbed, it's been removed
            // from the input list.  Otherwise, if its group is complete,
            // the group's fragments are now chained onto the input list,
            // and we'll process them in the order given when we continue.
            //
            continue;
        }

        //
        // Update neighbor discovery state.
        //
        SubInterface = Control->NextHopNeighbor->SubInterface;
        if (IppDoesNeighborNeedResolution(
                Control->NextHopNeighbor, SubInterface->Interface)) {
            if (!IppResolveNeighbor(Control->NextHopNeighbor, Control)) {
                //
                // Both Control and NetBufferList have been consumed.
                //
                continue;
            }
        }
        
        Control->FlSendPackets.DlDestination =
            IP_NEIGHBOR_DL_ADDRESS(Control->NextHopNeighbor, AddressLength);
        Control->FlSendPackets.DlSourceRoute =
            &Control->NextHopNeighbor->DlSourceRoute;

        //
        // Be careful not to cache the NetBufferList!
        // FragmentPacketHelper can change Control::NetBufferList.
        //
        Protocol->FragmentPacketHelper(Control, SubInterface);
        if ((Control->NetBufferList == NULL) ||
            !NT_SUCCESS(Control->NetBufferList->Status)) {
            IppAppendToGenericList(&DonePackets, Control);
            continue;
        }

        if (SubInterface != BatchSubInterface) {
            if (BatchSubInterface != NULL) {
                //
                // Process the previous list and start a new one.
                //
                BatchSubInterface->Interface->FlModule->Npi.Dispatch->
                    SendPackets(
                        BatchSubInterface->FlContext, 
                        FALSE, 
                        (PFL_SEND_PACKETS) SendPackets.Head);
                //
                // Free the packets but don't complete the NetBufferLists.
                // The references to NetBufferLists is passed onto the FL.
                //
                IppFreePacketList(SendPackets.Head);
                IppInitializeGenericList(&SendPackets);
            }
            BatchSubInterface = SubInterface;
        }

        IppUpdatePacketCounts(Protocol, SubInterface, Control);
        IppAppendToGenericList(&SendPackets, Control);
    }

    //
    // Process the last list.
    //
    if (SendPackets.Head != NULL) {
        BatchSubInterface->Interface->FlModule->Npi.Dispatch->
            SendPackets(
                BatchSubInterface->FlContext, 
                FALSE, 
                (PFL_SEND_PACKETS) SendPackets.Head);
        //
        // Free the packets but don't complete the NetBufferLists.
        // The references to NetBufferLists is passed onto the framing layer.
        //
        IppFreePacketList(SendPackets.Head);
    }
    
    if (DonePackets.Head != NULL) {
        IppCompleteAndFreePacketList(DonePackets.Head, FALSE);
    }
}
