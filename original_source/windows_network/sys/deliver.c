/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    deliver.c

Abstract:

    This module contains protocol-independent functions for a network
    layer module's Next Header Processor.

Author:

    Dave Thaler (dthaler) 3-Oct-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "deliver.tmh"

#define NBL_FORWARD_TO_RAW IPPROTO_RAW

VOID
IppCleanupNextHeaderProcessor(
    IN PIP_PROTOCOL Protocol
    )
{
    ULONG i;
    PIP_RECEIVE_DEMUX Demux = Protocol->ReceiveDemux;
    
    IppUninitializeReassembler(&Protocol->ReassemblySet);
    
    for (i = 0; i < IPPROTO_RESERVED_MAX; i++) {
        if (Demux[i].LocalEndpoint != NULL) {
            WfpAleEndpointTeardownHandler(Demux[i].LocalEndpoint);
        }
    }    
}

VOID
IppFindNlClient(
    IN PIP_PROTOCOL Protocol,
    IN IPPROTO UpperLayerProtocolId,
    IN PNET_BUFFER_LIST NetBufferList,    
    OUT PIP_RECEIVE_DEMUX *DemuxPointer
    )
/*++

Routine Description:

    Given a next header value, finds the right NL client to call.  It
    also handles the special case of ESP-over-UDP.  In this case we
    use the passed in NetBufferList to examine the UDP header and
    payload to determine if it's normal UDP or ESP-over-UDP.
    ESP-over-UDP is required only for IPv4 today.

Arguments:

    UpperLayerProtocolId - Supplies a next header value.

    NetBufferList - Supplies the packet beginning at the header specified by
        UpperLayerProtocolId.  This is the recieve path so there'll be a
        single NetBuffer within the NetBufferList containing the packet.

    DemuxPointer - Receives a pointer to the Demux entry for the client.

Return Value:

    None.

Locks:

    Caller is responsible for dereferencing DemuxPointer on success, if
    its InternalReceiveDatagrams is non-NULL.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_RECEIVE_DEMUX Demux;

    if ((UpperLayerProtocolId == IPPROTO_UDP) &&
        (Protocol->Characteristics->NetworkProtocolId == AF_INET) &&
        IppIsUdpEspPacket(NetBufferList->FirstNetBuffer)) {
        Demux = &IpUdpEspDemux;
        ASSERT(NetBufferList->FirstNetBuffer->Next == NULL);
    } else {
        Demux = &Protocol->ReceiveDemux[UpperLayerProtocolId];
    }

    //
    // If the handler is internal or if we can take a reference, we are done.
    //
    if ((Demux->InternalReceiveDatagrams != NULL) ||
        RoReference(&Demux->Reference)) {
        *DemuxPointer = Demux;
    } else {
        *DemuxPointer = NULL;
    }
}

VOID
IppFindNlFinalHeaderClient(
    IN PIP_PROTOCOL Protocol,
    IN IPPROTO UpperLayerProtocolId,
    OUT PIP_RECEIVE_DEMUX *DemuxPointer
    )
/*++

Routine Description:

    Given a next header value, find the right final header NL client to call.
    If the next header is an extension header, the routine returns null.

Arguments:

    UpperLayerProtocolId - Supplies a next header value.

    DemuxPointer - Receives a pointer to the Demux entry for the client.

Return Value:

    None.

Locks:

    Caller is responsible for dereferencing DemuxPointer on success, if
    its InternalReceiveDatagrams is non-NULL.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_RECEIVE_DEMUX Demux = &Protocol->ReceiveDemux[UpperLayerProtocolId];

    //
    // If the handler is not an extension header handler and, is 
    // internal or if we can take a reference, we are done.
    //
    if ((!Demux->IsExtensionHeader) &&
        ((Demux->InternalReceiveDatagrams != NULL) ||
        RoReference(&Demux->Reference))) {
        *DemuxPointer = Demux;
    } else {
        *DemuxPointer = NULL;
    }
}

NETIO_INLINE
VOID
IppFindNlExtensionHeaderClient(
    IN PIP_PROTOCOL Protocol,
    IN IPPROTO UpperLayerProtocolId,
    IN PNET_BUFFER_LIST NetBufferList,
    OUT PIP_RECEIVE_DEMUX *DemuxPointer
    )
/*++

Routine Description:

    Given a next header value, find the right NL extension header
    client to call.  If the next header is not an extension header,
    the routine returns null. It also the handles the special case of
    ESP-over-UDP.  In this case we use the passed in NetBufferList to
    examine the UDP header and payload to determine if it's normal UDP
    or ESP-over-UDP.

Arguments:

    UpperLayerProtocolId - Supplies a next header value.

    NetBufferList - Supplies the packet beginning at the header specified by
        UpperLayerProtocolId.  This is the recieve path so there'll be a
        single NetBuffer within the NetBufferList containing the packet.

    DemuxPointer - Receives a pointer to the Demux entry for the extension
        header client.

Return Value:

    None.

Locks:

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_RECEIVE_DEMUX Demux;

    if ((UpperLayerProtocolId == IPPROTO_UDP) &&
        (Protocol->Characteristics->NetworkProtocolId == AF_INET) &&
        IppIsUdpEspPacket(NetBufferList->FirstNetBuffer)) {
        Demux = &IpUdpEspDemux;
        ASSERT(NetBufferList->FirstNetBuffer->Next == NULL);        
    } else {
        Demux = &Protocol->ReceiveDemux[UpperLayerProtocolId];
    }

    if (Demux->IsExtensionHeader) {
        //
        // There is no need to add a reference because this must be an internal
        // handler. 
        //
        ASSERT(Demux->InternalReceiveDatagrams != NULL);
        *DemuxPointer = Demux;
    } else {
        *DemuxPointer = NULL;
    }
}

VOID
IppDeliverListToProtocol(
    IN PIP_RECEIVE_DEMUX Demux,
    IN OUT PIP_GENERIC_LIST DeliverList
    )
/*++

Routine Description:

    Deliver a list of datagrams to a protocol.
    
Arguments:

    Demux - Supplies the protocol handler to deliver the packet to.

    DeliverList - Supplies a list of packets to deliver.  Returns the delivery
        status of each packet as an NTSTATUS code in the embedded
        NetBufferList->Status.

Return Value:

    None.
    
--*/
{

    PNLC_RECEIVE_DATAGRAM Datagram;
    NL_INDICATE_RECEIVE_DATAGRAMS ClientArgs;
    PIP_CLIENT_CONTEXT NlClient = Demux->NlClient;
    IP_GENERIC_LIST FilteredDeliveryList;
    IP_GENERIC_LIST DroppedList;
    IP_FILTER_ACTION Action;

#if DBG
        for (Datagram = DeliverList->Head; 
             Datagram != NULL; 
             Datagram = Datagram->Next) {

            //
            // On the receive/loopback paths, we only support one buffer
            // per list.
            //
            ASSERT(Datagram->NetBufferList->FirstNetBuffer->Next == NULL);
        }
#endif

    Datagram = DeliverList->Head;

    //
    // Deliver datagrams to internal handler if required and return.
    //
    if (Demux->InternalReceiveDatagrams) {
        Demux->InternalReceiveDatagrams(
            (PIP_REQUEST_CONTROL_DATA) Datagram);
        return;
    }

    //
    // Otherwise deliver datagrams to external handler that calls its own
    // inspection routine and return.
    //
    if (!NlClient->Npi.Dispatch->Flags.CallReceiveInspectionHandler) {
        ClientArgs.ClientHandle = NlClient->Npi.ProviderHandle;
        ClientArgs.FirstDatagramList = Datagram;

        if (NlClient->Npi.Dispatch->ReceiveDatagrams != NULL) {
            NlClient->Npi.Dispatch->ReceiveDatagrams(&ClientArgs);
        }            
        IppDereferenceNlClient(NlClient);
        return;
    }

    

    //
    // Otherwise deliver datagrams to external handler that does not call its
    // own inspection routine and return.
    //
    
    //
    // Determine which packets should be delivered to
    // the NL client and put them in the FilteredDeliveryList.
    // Put the dropped packets into the DroppedList. Later on we put back 
    // the DroppedList and FilteredDeliveryList packets into the
    // original DeliverList.  This is in keeping with the semantics
    // of the other TL clients that call the inspection handler
    // themselves: they always return the orignal DeliverList intact.
    //
    
    IppInitializeGenericList(&DroppedList);        
    IppInitializeGenericList(&FilteredDeliveryList);
    while ((Datagram = IppPopGenericList(DeliverList)) != NULL) {
        PIP_REQUEST_CONTROL_DATA Control =
            (PIP_REQUEST_CONTROL_DATA) Datagram;

        Action = 
            IppInspectLocalDatagramsIn(
                NlClient->Protocol->Level,
                Datagram->LocalAddress,
                Datagram->RemoteAddress,
                (PNL_INTERFACE) Control->SourcePointer->Interface,
                Control->IsOriginLocal
                ? IFI_UNSPECIFIED
                : Control->SourceSubInterface->Index,
                Datagram->Loopback,
                NlClient->Npi.Dispatch->UpperLayerProtocolId,
                NULL,
                Datagram->NetworkLayerHeadersSize,
                0,
                Demux->LocalEndpoint,
                Datagram,
                Datagram->NetBufferList);
        if (Action >= IpFilterDrop) {
            if (Action == IpFilterDrop) {
                NlClient->Protocol->PerProcessorStatistics
                [KeGetCurrentProcessorNumber()].InFilterDrops++;

                NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Inspection point dropped packet: "
                           "Protocol %d"
                           "Source %!IPV4! destination %!IPV4!\n", 
                           NlClient->Npi.Dispatch->
                           UpperLayerProtocolId,
                           Datagram->RemoteAddress,
                           NL_ADDRESS(Datagram->LocalAddress));

                //
                // Currently NL clients set status to STATUS_FWP_DROP_NOICMP
                // if their inspection hook drops the packet.
                //
                Datagram->NetBufferList->Status = STATUS_FWP_DROP_NOICMP;
            } else {

                if (Action == IpFilterDropAndSendIcmp) {
                    Datagram->NetBufferList->Status = STATUS_ACCESS_DENIED;   
                } else {
                    ASSERT(Action == IpFilterAbsorb);
                }
            }
            IppAppendToGenericList(&DroppedList, Datagram);
        }else {
            IppAppendToGenericList(&FilteredDeliveryList, Datagram);
        }
    }
    
    Datagram = FilteredDeliveryList.Head;
    //
    // Check if there is anything to deliver at all.
    //
    if (Datagram != NULL) {
        ClientArgs.ClientHandle = NlClient->Npi.ProviderHandle;
        ClientArgs.FirstDatagramList = Datagram;

        if (NlClient->Npi.Dispatch->ReceiveDatagrams != NULL) {
            NlClient->Npi.Dispatch->ReceiveDatagrams(&ClientArgs);
        }            
     }        

    IppConcatenateGenericLists(DeliverList, &DroppedList);
    IppConcatenateGenericLists(DeliverList, &FilteredDeliveryList);    
    IppDereferenceNlClient(NlClient);
}

VOID
IppDeliverPreValidatedListToProtocol(
    PIP_RECEIVE_DEMUX Demux,
    PNLC_RECEIVE_DATAGRAM ReceiveDatagramChain,
    ULONG ReceiveDatagramCount,
    UCHAR TransportProtocol,
    PNET_BUFFER_LIST* RejectedNblHead,
    PNET_BUFFER_LIST* RejectedNblTail
    )
 /*++

 Routine Description:

     Deliver a list of validated datagrams to a protocol.

 Arguments:

     Demux - Supplies the protocol handler to deliver the packet to.

     ReceiveDatagramChain - Supplies a list of validated packets to deliver.  
        Returns the deliver status of each packet as an NTSTATUS code in 
        the embedde NetBufferList->Status.

     ReceiveDatagramCount - Number of validated datagrams in the 
        receive datagram chain.

     TransportProtocol - Upper layer protocol to receive indicated packets.
     
     RejectedNblHead - Head of NBL list contain packet rejected by the upper
        transport protocol.

     RejectedNblTail  - Tail of rejected NBL list.

 Return Value:

     None.

 --*/
{
    PNET_BUFFER_LIST NetBufferList, NetBufferListChain, *NetBufferListTail;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram;    
    NL_INDICATE_RECEIVE_DATAGRAMS ReceiveDatagramList;

    DISPATCH_CODE();
    UNREFERENCED_PARAMETER(TransportProtocol);

    ASSERT((*RejectedNblHead == NULL) && (*RejectedNblTail == NULL));

    ReceiveDatagramList.ClientHandle = Demux->NlClient->Npi.ProviderHandle;
    ReceiveDatagramList.FirstDatagramList = ReceiveDatagramChain;
    NetBufferListChain = NULL;
    NetBufferListTail = &NetBufferListChain;    

    Demux->NlClient->Npi.Dispatch->ReceivePreValidatedDatagrams(
        &ReceiveDatagramList,
        ReceiveDatagramCount);

    do {
        ReceiveDatagram = ReceiveDatagramChain;
        ReceiveDatagramChain = ReceiveDatagramChain->Next;
        NetBufferList = ReceiveDatagram->NetBufferList;

        if (NetBufferList == NULL) {
            continue;
        } else if ((NetBufferList->Status == STATUS_PORT_UNREACHABLE) ||
                   (NetBufferList->Status == STATUS_ARBITRATION_UNHANDLED) ||
                   (NetBufferList->Status == STATUS_FASTPATH_REJECTED) ||
                   (NetBufferList->Status == STATUS_PROTOCOL_UNREACHABLE) ||
                   (NetBufferList->Status == STATUS_ACCESS_DENIED) ||
                   (NetBufferList->Status == STATUS_FWP_DROP_NOICMP)) {
            //
            // The listed status values can be set by transport (TCP or UDP).
            // Packets returning with any of these status value are chained up and 
            // forwarded to the slow path.
            //
            // Packets rejected by the transport because of the presence of 
            // session state information for that endpoint have a status value of 
            // (STATUS_FASTPATH_REJECTED) and will be re-indicated to the 
            // transport via the slow path.
            // 
            // All other packets with the status values other than 
            // STATUS_FASTPATH_REJECTED are to be given to the RAW transport 
            // for further processing.
            //
            
            //
            // Packets to be re-indicate to tranport must have there status
            // field set to STATUS_SUCCESS. 
            // Also the NBL must be marked in its scratch field with 
            // NBL_FORWARD_TO_RAW. This informs the slow path that the was already 
            // seen by the fast path.
            //
            if (NetBufferList->Status == STATUS_FASTPATH_REJECTED) {
                NetBufferList->Status = STATUS_SUCCESS;
            } else {
                NetBufferList->Scratch = (PVOID) (ULONG_PTR) NBL_FORWARD_TO_RAW;
            }
            
            //
            // Retreat to start of IP Header as the packets will
            // be forwarded to the slow path.
            //
            NetioRetreatNetBuffer(
                NetBufferList->FirstNetBuffer,
                ReceiveDatagram->NetworkLayerHeadersSize,
                0);

            //
            // Chain up the rejected NBL for forwarding to the
            // slow path.
            //
            if (*RejectedNblTail != NULL) {
                (*RejectedNblTail)->Next = NetBufferList;
                *RejectedNblTail = NetBufferList;
            } else {
                *RejectedNblHead = *RejectedNblTail = NetBufferList;
                ASSERT((*RejectedNblTail)->Next == NULL);
            }
            
            continue;
        } 
        
        *NetBufferListTail = NetBufferList;
        NetBufferListTail = &NetBufferList->Next;
        NetBufferList->Status = STATUS_SUCCESS;

    } while (ReceiveDatagramChain != NULL);

    //
    // Complete all NBLs that have been successfully processed by
    // transport.
    //
    if (NetBufferListChain != NULL) {
        *NetBufferListTail = NULL;
        NetioDereferenceNetBufferListChain(NetBufferListChain, TRUE);
    }
}

VOID
IppDeliverControlToProtocol(
    IN PIP_RECEIVE_DEMUX Demux,
    IN PNLC_RECEIVE_CONTROL_MESSAGE ControlMessage
    )
/*++

Routine Description:

    Deliver a control message to a protocol.

--*/
{
    if (!Demux->IsExtensionHeader) {
        //
        // For non-extension headers (TCP, ICMP etc.) always set the
        // status to STATUS_SUCCESS before giving the NetBufferList
        // to the protocol handler. 
        //
        ControlMessage->NetBufferList->Status = STATUS_SUCCESS;
    }        
    
    if (Demux->InternalReceiveControlMessage != NULL) {
        Demux->InternalReceiveControlMessage(
            (PIP_REQUEST_CONTROL_DATA)ControlMessage);
    } else if (Demux->NlClient != NULL) {
        NL_INDICATE_RECEIVE_CONTROL_MESSAGE ClientArgs;
        PIP_CLIENT_CONTEXT NlClient = Demux->NlClient;
        
        ClientArgs.ClientHandle = NlClient->Npi.ProviderHandle;
        ClientArgs.ControlMessage = ControlMessage;
 
        if (NlClient->Npi.Dispatch->ReceiveControlMessage != NULL) {
            NlClient->Npi.Dispatch->ReceiveControlMessage(
                &ClientArgs);
        } else {
            ControlMessage->NetBufferList->Status = 
                STATUS_PROTOCOL_UNREACHABLE;
        } 
        
        IppDereferenceNlClient(NlClient);
    } else {
        ControlMessage->NetBufferList->Status = 
            STATUS_PROTOCOL_UNREACHABLE;
    }
}

__inline
IP_DISCARD_REASON
IppNlClientStatusToDiscardReason(
    IN NTSTATUS Status
    )
{
    switch (Status) {
    case STATUS_PORT_UNREACHABLE:
        return IpDiscardPortUnreachable;
    case STATUS_PROTOCOL_UNREACHABLE:
        return IpDiscardProtocolUnreachable;
    case STATUS_ARBITRATION_UNHANDLED:
        return IpDiscardArbitrationUnhandled;
    case STATUS_ACCESS_DENIED:
        return IpDiscardAdministrativelyProhibited;
    case STATUS_FWP_DROP_NOICMP:
        return IpDiscardInspectionDrop;
    default:
        ASSERT(FALSE);
        return IpDiscardMax;
    }
}


__inline
VOID
IppFillDiscardReason(
    OUT PIP_REQUEST_CONTROL_DATA Control,
    IN NTSTATUS Status
    )
{
    Control->DiscardReason = IppNlClientStatusToDiscardReason(Status);

    //
    // Set DiscardParameter to the offset of the next header value
    // if the DiscardReason is IpDiscardProtocolUnreachable.
    //
    if (Control->DiscardReason == IpDiscardProtocolUnreachable &&
        IS_IPV6_PROTOCOL(Control->Compartment->Protocol)) {

       Control->DiscardParameter =
            RtlUlongByteSwap(Control->NextHeaderPosition);
    } else {
        //
        // No error offset should be specified for ICMPv4
        //
        Control->DiscardParameter = 0;
    }
}

VOID
IppReceiveHeadersHelper(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_GENERIC_LIST RcvList,
    IN OUT PIP_GENERIC_LIST RawList,
    IN OUT PIP_GENERIC_LIST ErrorList,
    IN OUT PIP_GENERIC_LIST DoneList
    )
/*++

Routine Description:

   Helper routine to bundle similar code in IppReceiveHeader and
   IppReceiveHeaderBatch. Processes the IP header (including v6 hop by hop).

Arguments:

    Control - Supplies the control structure for the request.

    Protocol - Supplies a pointer to the IP protocol for this request.

    RcvList - Supplies a list to put the deliverable datagrams.

    RawList - Supplies a list to store the datagrams that need to be forwarded
        to the RAW protocol. 

    ErrorList - Supplies a list to store the datagrams that need an icmp error.

    DoneList - Supplies a list to store the datagrams that are dropped by WFP.

Return Value:

    None.

Locks:

    None.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    PNET_BUFFER NetBuffer = NetBufferList->FirstNetBuffer;
    ULONG HeaderSize = Protocol->HeaderSize;
    PUCHAR Header;
    PNLC_RECEIVE_DATAGRAM ReceiveDatagram;
    PIP_INTERFACE ArrivalInterface;
    PUCHAR RemoteAddress;
    IP_FILTER_ACTION Action;

    Header = NetioGetDataBufferSafe(NetBuffer, HeaderSize);
    ASSERT(Header != NULL);
 
    ArrivalInterface = (PIP_INTERFACE) Control->SourcePointer->Interface;
    
    ReceiveDatagram = &Control->NlcReceiveDatagram;

    if (IS_IPV4_PROTOCOL(Protocol)) {
        IPV4_HEADER UNALIGNED *Ipv4Header = (IPV4_HEADER UNALIGNED *) Header;
        
        HeaderSize = Ip4HeaderLengthInBytes(Ipv4Header);
        RemoteAddress = (PUCHAR) &Ipv4Header->SourceAddress;
        ReceiveDatagram->NextHeaderValue = Ipv4Header->Protocol;
        Control->NextHeaderPosition = FIELD_OFFSET(IPV4_HEADER, Protocol);

        if (Control->ReceiveRoutingHeaderOffset > 0) {
            //
            // Treat IPv4 source routed packets as if they were packets with
            // a routing header. This makes the IPv4 and IPv6 fragment
            // processing logic similar.
            //
            ReceiveDatagram->NextHeaderValue = IPPROTO_ROUTING;
        } else if (IPV4_IS_FRAGMENT(Ipv4Header)) {
            //
            // Similarly treat IPv4 fragments as if they have a 0 size fragment
            // header.  For fragmented source routed packets, the routing next
            // header handler will transfer control to the fragment handler
            // if the packet is locally destined.
            //
            ReceiveDatagram->NextHeaderValue = IPPROTO_FRAGMENT;
        } 
    } else {
        IPV6_HEADER UNALIGNED *Ipv6Header = (IPV6_HEADER UNALIGNED *) Header;

        RemoteAddress = (PUCHAR) &Ipv6Header->SourceAddress;
        ReceiveDatagram->NextHeaderValue = Ipv6Header->NextHeader;
        Control->NextHeaderPosition = FIELD_OFFSET(IPV6_HEADER, NextHeader);
    }

    NetioAdvanceNetBuffer(NetBuffer, HeaderSize);

    ReceiveDatagram->Loopback = Control->IsOriginLocal;

    //
    // TODO: IppGetExternalScopeId is not very efficient!
    //
    ReceiveDatagram->RemoteScopeId =
        IppGetExternalScopeId(ArrivalInterface, RemoteAddress);
    ReceiveDatagram->RemoteAddress = RemoteAddress;
    ReceiveDatagram->LocalAddress =
        (PNL_LOCAL_ADDRESS) Control->DestLocalAddress;

    //
    // Store the Destination address (which is our local address) prefix 
    // length in the datagram. WFP uses this information to determine
    // whether the packet originated in our subnet.
    //
    ReceiveDatagram->LocalAddressPrefixLength =
        (Protocol->AddressType(Control->DestLocalAddress->Identifier->Address) == 
             NlatUnicast)
             ?
             ((PIP_LOCAL_UNICAST_ADDRESS)Control->DestLocalAddress)->PrefixLength
             : 0;        
    ReceiveDatagram->NetworkLayerHeadersSize = HeaderSize;
    
    //
    // Store the ArrivalInterface and SubInterfaceIndex in the ReceiveDatagram
    // to that we can pass it to WFP at other inspection points.
    //

    ReceiveDatagram->SourceInterface = (PNL_INTERFACE) ArrivalInterface;
    ReceiveDatagram->SourceSubInterfaceIndex = 
       (!Control->IsOriginLocal ? Control->SourceSubInterface->Index : 
        IFI_UNSPECIFIED);

    //
    // Since we use the NLC_RECEIVE_DATAGRAM structure in the control data for
    // storing other NL state, we can't assume that the fields are initialized.
    // We should initialize all the fields here.
    //
    ReceiveDatagram->TransportLayerContext = NULL;

    Action =
        IppInspectLocalPacketsIn(
            Protocol->Level, 
            ReceiveDatagram->SourceInterface, 
            ReceiveDatagram->SourceSubInterfaceIndex, 
            ReceiveDatagram->RemoteAddress, 
            (PNL_LOCAL_ADDRESS) ReceiveDatagram->LocalAddress,
            ReceiveDatagram->Loopback,
            Control->Reassembled,
            ReceiveDatagram->NetworkLayerHeadersSize,
            ReceiveDatagram,
            NetBufferList);
    if (Action >= IpFilterDrop) {
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Inspection point dropped incoming packet: "
                   "Source %!IPV4! destination %!IPV4!\n", 
                   RemoteAddress, NL_ADDRESS(ReceiveDatagram->LocalAddress));
    
        //
        // Clear scratch field if packet was previously rejected by the 
        // receive fast path.
        // 
        if (NetBufferList->Scratch &&
            (((ULONG_PTR) NetBufferList->Scratch) == NBL_FORWARD_TO_RAW)) {
            NetBufferList->Scratch = NULL;
        }

        if (Action == IpFilterDrop) {
            Control->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        } else {               
            if (Action == IpFilterDropAndSendIcmp) {
                Control->DiscardReason = IpDiscardAdministrativelyProhibited;
                IppAppendToGenericList(ErrorList, Control);
                return;
            } else {
                ASSERT(Action == IpFilterAbsorb);
            }
        }

        Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        InFilterDrops++;        
        IppAppendToGenericList(DoneList, Control);
        return;
    }

    //
    // Check if this packet was previously rejected by the receive fast path
    // and needs to be forwarded to RAW. Update the status and put it 
    // on the RAW list here.
    //
    if (NetBufferList->Scratch &&
        (((ULONG_PTR) NetBufferList->Scratch) == NBL_FORWARD_TO_RAW)) {
        IppFillDiscardReason(Control, NetBufferList->Status);
        NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        NetBufferList->Scratch = NULL;
        IppAppendToGenericList(RawList, Control);
        return;
    } else {
        NetBufferList->Status = STATUS_MORE_ENTRIES;
    }

    IppAppendToGenericList(RcvList, Control);
}


PIP_REQUEST_CONTROL_DATA
IppCreateClonePacketForRaw(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_PROTOCOL Protocol,
    IN BOOLEAN FreeOriginal
    )
/*++

Routine Description:

    This routine creates a clone packet suitable for sending to RAW.  It also
    takes a hint on whether the original packet can be freed after creating
    the clone packet.  This is an optimization that allows the routine to
    reuse the original packet for the clone if possible.
    In addition if the packet is an IPv4 packet that has IPSec processing
    done on it, the IPSec headers (AH and ESP) are removed.
    
Arguments:

    Control - Supplies the packet to create the clone from, beginning at the
        point where all network headers have been processed.

    Protocol - Supplies the protocol. 

    FreeOriginal - Supplies whether the function needs to preserve the original
        packet after cloning.  If there is no need to preserve the original,
        we can sometimes reuse the original to form the clone.  Regardless of
        whether this function succeeds or not, if FreeOriginal was true then
        Control will completed and freed.

Return Value:

    Returns the cloned packet.  The clone contains all the IP headers.  
    Returns NULL on failure.  

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_REQUEST_CONTROL_DATA Clone;
    IPV4_HEADER UNALIGNED *OriginalIpv4Header;
    NTSTATUS Status;
    ULONG HeaderSize = Control->NlcReceiveDatagram.NetworkLayerHeadersSize;

    if (IS_IPV4_PROTOCOL(Protocol) &&
        ((OriginalIpv4Header = (IPV4_HEADER UNALIGNED *) Control->IP) != NULL)
        &&
        ((OriginalIpv4Header->Protocol == IPPROTO_ESP) ||
         (OriginalIpv4Header->Protocol == IPPROTO_AH))) {
        // 
        //  This is an IPv4 IPSec packet that has been IPSec processed so
        //  we should remove the IPSec headers when cloning.
        //

        IPV4_HEADER UNALIGNED *CloneIpv4Header;
        UCHAR Ip4HeaderLength = Ip4HeaderLengthInBytes(OriginalIpv4Header);

        // 
        // Clone just the data.
        //
        Clone = IppCreateClonePacket(Control, Protocol);
        
        if (Clone == NULL) {
            if (FreeOriginal) {
                IpSecCleanupInboundPacketStateGuarded(Control->NetBufferList);
                IppCompleteAndFreePacketList(Control, FALSE);
            }            
            return NULL;
        }

        Clone->NlcReceiveDatagram.TransportLayerContext = NULL;

        //
        // Copy over only the IPv4 header and options.
        //
        Status = 
            NetioRetreatNetBuffer(
                Clone->NetBufferList->FirstNetBuffer, 
                Ip4HeaderLength,
                0);
        if (!NT_SUCCESS(Status)) {
            if (FreeOriginal) {
                IpSecCleanupInboundPacketStateGuarded(Control->NetBufferList);
                IppCompleteAndFreePacketList(Control, FALSE);
            }            
            IppCompleteAndFreePacketList(Clone, FALSE);
            return NULL;
        }    
        
        CloneIpv4Header =
            NetioGetDataBufferSafe(
                Clone->NetBufferList->FirstNetBuffer,
                Ip4HeaderLength);
        ASSERT(CloneIpv4Header != NULL);

        RtlCopyMemory(
            CloneIpv4Header,
            OriginalIpv4Header,
            Ip4HeaderLength);
        CloneIpv4Header->Protocol =
            (UINT8) Control->NlcReceiveDatagram.NextHeaderValue;
        CloneIpv4Header->TotalLength = 
            RtlUshortByteSwap(
                (UINT16) Clone->NetBufferList->FirstNetBuffer->DataLength);
        //
        // We are not recalculating the header checksum for the upper
        // layer raw client to see.  This is in keeping with XP and WS03.
        //
        CloneIpv4Header->HeaderChecksum = 0;
        Clone->IP = (UCHAR*) CloneIpv4Header;
        Clone->IpSecHeadersPresent = FALSE;

        NetioAdvanceNetBuffer(
            Clone->NetBufferList->FirstNetBuffer, 
            Ip4HeaderLength);

        Clone->NlcReceiveDatagram.NetworkLayerHeadersSize = Ip4HeaderLength;		

        if (FreeOriginal) {
            IppCopyNetBufferListInfo(
                Clone->NetBufferList,
                Control->NetBufferList);
            IppCompleteAndFreePacketList(Control, FALSE);
        }            
    } else {
        //
        // The packet is an IPv6 packet or an IPv4 packet with no 
        // IPsec processing done on it so do a trivial clone of
        // the entire packet including the IP header.  We further optimize
        // by checking if the original packet is needed; if it isn't
        // we reuse it to make the clone rather than allocate a new packet.
        //

        if (FreeOriginal) {
            Clone = Control;
            Clone->NlcReceiveDatagram.TransportLayerContext = NULL;
        } else {
            //
            // Retreat all the network layer headers.
            //
            Status = 
                NetioRetreatNetBufferList(
                    Control->NetBufferList,
                    HeaderSize,
                    0);
            ASSERT(NT_SUCCESS(Status));            
        
            Clone = IppCreateClonePacket(Control, Protocol);
            //
            // Restore the original packet. 
            //
            NetioAdvanceNetBufferList(
                Control->NetBufferList,
                HeaderSize);
            
            if (Clone == NULL) {
                return NULL;
            }

            Clone->NlcReceiveDatagram.TransportLayerContext = NULL;            

            //
            // The raw clone should also start after the network layer headers.
            //
            NetioAdvanceNetBufferList(
                Clone->NetBufferList,
                HeaderSize);
            Clone->NlcReceiveDatagram.NetworkLayerHeadersSize =  HeaderSize;
         }
    }        

    return Clone;
}

VOID
IppProcessDeliverList(
    IN PIP_PROTOCOL Protocol,
    IN IPPROTO UpperLayerProtocolId,
    IN OUT PIP_GENERIC_LIST DeliverList,
    IN OUT PIP_GENERIC_LIST RawList,
    IN OUT PIP_GENERIC_LIST ErrorList,
    IN OUT PIP_GENERIC_LIST DoneList
    )
/*++

Routine Description:

    Try to deliver a list of packets to a client.

Arguments:

    Protocol - Supplies the global protocol information.

    UpperLayerProtocolId - Supplies the protocol number of the client to
        deliver to.

    DeliverList - Supplies a list of packets to deliver.  On return,
        this list should be empty and all packets should be moved to
        one of the following lists.  In addition, each packet may also
        have a RawClone.  If so, on return the RawClone will also 
        have been moved to one of the following lists.

    RawList - Supplies the current list of packets to be delivered to Raw.
        NULL iff the UpperLayerProtocolLayerId is IPPROTO_RESERVED_RAW.

    ErrorList - Supplies the current list of packets to generate ICMP errors
        for.

    DoneList - Supplies the current list of packets with no further 
        processing required.
        
--*/
{
    NTSTATUS Status;
    PIP_RECEIVE_DEMUX Demux;
    PIP_REQUEST_CONTROL_DATA Control;
    
    //
    // If delivering to RAW then we'll not be required to keep a running
    // list of raw packets to be delivered.
    //
    ASSERT(
        (UpperLayerProtocolId == IPPROTO_RESERVED_RAW) == (RawList == NULL));
    
    IppFindNlFinalHeaderClient(
        Protocol,
        UpperLayerProtocolId,
        &Demux);
    if (Demux != NULL) {
        IppDeliverListToProtocol(Demux, DeliverList);
    } else { 
        // 
        // This is equivalent to getting a protocol unreachable status. 
        // 
        NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                   "IPNG: No handler for %s packet next header %u\n", 
                   Protocol->TraceString, 
                   UpperLayerProtocolId);
        for (Control = DeliverList->Head;
             Control != NULL;
             Control = Control->Next) {
            Control->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
        }
    }

    //
    // Now walk the list, and split into the ones we're done with,
    // and the ones we're not.
    //
    while ((Control = IppPopGenericList(DeliverList)) != NULL) {
        ASSERT((RawList != NULL) || (Control->RawClone == NULL));
        
        if (Control->NetBufferList == NULL) {
            if (Control->RawClone != NULL) {
                //
                // The regular protocol pended the packet.
                // Now deliver the raw promiscuous clone if needed.
                //
                ASSERT(RawList != NULL);
                IppInspectCloneDatagramsIn((PNLC_RECEIVE_DATAGRAM)Control,
                                           Control->RawClone->NetBufferList);
                IppAppendToGenericList(RawList, Control->RawClone);
                Control->RawClone = NULL;
            } 

            //
            // Cleanup the original packet. 
            //
            IppAppendToGenericList(DoneList, Control);
            continue;
        }

        Status = Control->NetBufferList->Status;
        
        if (RawList != NULL) {
            ASSERT(!Control->PromiscuousOnlyReceive);

            switch (Status) {
            case STATUS_PORT_UNREACHABLE:
            case STATUS_PROTOCOL_UNREACHABLE:
            case STATUS_ARBITRATION_UNHANDLED:
            case STATUS_ACCESS_DENIED:
            case STATUS_FWP_DROP_NOICMP:
                //
                // No regular protocol wants it.  Send the original to raw.
                //                
                NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_VERBOSE, 
                           "IPNG: Error %x from upper layer protocol\n", 
                           Status);
                
                if (Control->RawClone != NULL) {
                    //
                    // We won't need a raw clone anymore since we are going to
                    // attempt to deliver the original packet directly.
                    //
                    IppAppendToGenericList(DoneList, Control->RawClone);
                    Control->RawClone = NULL;
                }

                //
                // This will clone for IPv4 if there are IPsec Headers.
                // Otherwise it returns the original. For IPv6 it always 
                // returns the original.
                //
                Control = 
                    IppCreateClonePacketForRaw(
                        Control,
                        Protocol,
                        TRUE);

                if (Control != NULL) {
                    IppFillDiscardReason(Control, Status);
                    Control->NetBufferList->Status = 
                        STATUS_PROTOCOL_UNREACHABLE;
                    IppAppendToGenericList(RawList, Control);                
                    
                }                    
                    
                continue;

            default:
                //
                // The regular protocol handled it.  Deliver the raw
                // promiscuous clone if needed.
                //
                if (Control->RawClone != NULL) {
                    IppInspectCloneDatagramsIn(
                        (PNLC_RECEIVE_DATAGRAM)Control,
                        Control->RawClone->NetBufferList);
                    IppAppendToGenericList(RawList, Control->RawClone);
                }
                break;
            }
        } else if (!Control->PromiscuousOnlyReceive) {
            ASSERT(Control->RawClone == NULL);
            //
            // This packet was sent to RAW because the normal protocol did not
            // accept it.  If RAW rejects the packet as well, send the
            // appropriate error based on the status returned by the normal
            // protocol. RAW can override Status with STATUS_SUCCESS;
            // in such cases we still send ICMP message, if some earlier processing
            // resulted in DiscardReason == IpDiscardAdministrativelyProhibited.
            // (related to bug Windows OS#1071891).
            //
            if (!NT_SUCCESS(Status) ||
                (Control->DiscardReason == IpDiscardAdministrativelyProhibited)) {
                if ((Control->DiscardReason == IpDiscardPortUnreachable) ||
                    (Control->DiscardReason == IpDiscardProtocolUnreachable)||
                    (Control->DiscardReason == IpDiscardAdministrativelyProhibited)||
                    (Control->DiscardReason == IpDiscardInspectionDrop)) {
                    IP_DISCARD_ACTION Action;

                    Action =
                        IppDiscardReceivedPackets(
                            Protocol,
                            Control->DiscardReason,
                            Control,
                            NULL,
                            NULL);
                    
                    if (Action == IpDiscardAllowIcmp) {
                        //
                        // Get ready to send an ICMP error.
                        //
                        IppAppendToGenericList(ErrorList, Control);
                        continue;
                    } else {
                        //
                        // We are done, no need to send an ICMP error.
                        //
                        IppAppendToGenericList(DoneList, Control);
                        continue;
                    }
                } else {
                    ASSERT(Control->DiscardReason == 
                           IpDiscardArbitrationUnhandled);
                    Control->NetBufferList->Status = STATUS_SUCCESS;
                }
            }
        } else {
            //
            // Either we were not requested to deliver to IPPROTO_RAW_RESERVED
            // (i.e. RawList == NULL), or there are no raw listeners.
            //
            ASSERT(Control->RawClone == NULL);
        }

        //
        // Cleanup the original packet.  But set the status to success because
        // we don't want to propagate errors on the receive path (for loopback
        // packets).
        //
        // FUTURE-2005/01/25-RaymondS Set this status on LoopbackEnqueue
        // and split IppProcessDeliverList into raw delivery version
        // and normal transport delivery version.
        //

        Control->NetBufferList->Status = STATUS_SUCCESS;        
        IppAppendToGenericList(DoneList, Control);
    }
}

VOID
IppReceiveHeaderBatch(
    IN PIP_PROTOCOL Protocol,
    IN PIP_GENERIC_LIST List
    )
/*++

Routine Description:

    Process all subsequent headers (everything past the IP Header and
    IPv4 Options/IPv6 Hop by Hop headers).  In an attempt to batch calls to
    upper-layer protocols as much as possible, we process all extension headers
    before any upper-layer headers.

Arguments:

    Protocol - Supplies the protocol. 

    FirstArgs - Supplies the set of packets to process.

Locks: 

    Assumes caller holds no locks.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IPPROTO UpperLayerProtocolId;
    IP_GENERIC_LIST RcvList, ErrorList, DoneList, DeliverList, RawList;
    PIP_REQUEST_CONTROL_DATA Args, NextArgs;
    PNLC_RECEIVE_DATAGRAM ExtDatagram;
    PIP_LOCAL_ADDRESS LocalAddress;
    PIP_INTERFACE Interface = NULL;
    PIP_RECEIVE_DEMUX Demux;
    ULONG CurrNextHeaderValue, InDelivers;
    ULONG NextHeaderValue;
    PIP_REQUEST_CONTROL_DATA FirstArgs = List->Head;

    IppInitializeGenericList(&RcvList);
    IppInitializeGenericList(&RawList);
    IppInitializeGenericList(&ErrorList);
    IppInitializeGenericList(&DoneList);

    //
    // First skip all IP headers.
    // Also move packets already processed on the fast path to 
    // the RAW list.
    //
    for (Args = FirstArgs; Args != NULL; Args = NextArgs) {
        NextArgs = Args->Next;
        Args->Next = NULL;

        IppReceiveHeadersHelper(
            Args,
            Protocol,
            &RcvList,
            &RawList,
            &ErrorList,
            &DoneList);
    }

    //
    // Now process all intermediate headers (AH,ESP,IPv6 extension headers) 
    // in place.  Before calling each extension header handler, the status in
    // the net buffer list is STATUS_MORE_ENTRIES.  Packet processing stops if
    // the handler sets the status to anything other than STATUS_MORE_ENTRIES. 
    //
    for (Args = RcvList.Head; Args != NULL; ) {

        if ((Args->NetBufferList == NULL) ||
            (Args->NetBufferList->Status != STATUS_MORE_ENTRIES)) {
            goto NextDatagram;
        }

        //
        // Figure out who we need to call next.
        //
        UpperLayerProtocolId = Args->NlcReceiveDatagram.NextHeaderValue;
        
        IppFindNlExtensionHeaderClient(
            Protocol,
            UpperLayerProtocolId,
            Args->NetBufferList,
            &Demux);
        if (Demux == NULL) {
            //
            // There is no extension header receivers for this packet.  But
            // there might be upper layer receive handlers.  Process the next
            // datagram.  Even if there is no client (extension header or upper
            // layer header) for the next header value, leave the
            // status of the net buffer list as STATUS_MORE_ENTRIES so that the
            // net buffer list is processed while sending the packet to the
            // upper layer receivers (which in this case can be raw). A value
            // of success implies that the extension headers all worked fine
            // and the packet is set to be delivered to an upper layer
            // handler. 
            //
            goto NextDatagram;
        }

        ASSERT(Demux->IsExtensionHeader);

        //
        // We only support extension header clients that are internal clients.
        //
        ASSERT(Demux->InternalReceiveDatagrams);

        //
        // Deliver the packets to the extension header handler. Extension
        // headers are processed synchronously in the normal case. However, if
        // there is an error, they can return a pending status. A pending
        // status is treated just like an error code. The reason is that if the
        // header was processed successfully, the packet needs to be delivered
        // to the upper layer receive handlers and so it has to be completed
        // synchronously by the extension handler. However, if there is an
        // error, it doesn't have to be delivered to the upper layers and so
        // there is no reason for it to complete synchronously here. 
        //
        Demux->InternalReceiveDatagrams(Args);

        continue;

NextDatagram:
        Args = Args->Next;
    }


    //
    // Now process upper-layer headers.  We skip over any packets that
    // we've already found problems with, moving them to either the 
    // ErrorList or the DoneList.  We then process each consecutive sequence
    // with the same NextHeader value, trying to deliver to the actual
    // protocol.
    //
    IppInitializeGenericList(&DeliverList);
    CurrNextHeaderValue = 0;
    while ((Args = IppPopGenericList(&RcvList)) != NULL) {
        ExtDatagram = &Args->NlcReceiveDatagram;
        //
        // At this point, all the extension headers have been processed.  If
        // the extension header handler set the status to STATUS_MORE_ENTRIES,
        // then we need to continue processing.  Otherwise, there was an error
        // or the packet was pended.  In case of error, the handler is
        // responsible for sending the ICMP error if required. 
        //
        if ((ExtDatagram->NetBufferList == NULL) ||
            (ExtDatagram->NetBufferList->Status != STATUS_MORE_ENTRIES)) {
            //
            // Cleanup the original packet.  But set the status to success
            // because we don't want to propagate errors on the receive path
            // (for loopback packets).
            //
            if (ExtDatagram->NetBufferList != NULL) {
                ExtDatagram->NetBufferList->Status = STATUS_SUCCESS;
            }
            IppAppendToGenericList(&DoneList, Args);
            continue;
        }
        ExtDatagram->NetBufferList->Status = STATUS_SUCCESS;
        ExtDatagram->InspectFlags = 0;

        if (Args->PromiscuousOnlyReceive) {
            //
            // This is a promiscuous-only receive (which only goes to raw),
            // and we've now found the upper layer protocol number.
            //
            ExtDatagram->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
            IppAppendToGenericList(&RawList, Args);
            continue;
        }

        LocalAddress = Args->DestLocalAddress;
        Interface = LocalAddress->Interface;
        if ((Interface->IpPromiscuousCount > 0) ||
            ((NL_ADDRESS_TYPE(LocalAddress) == NlatMulticast) &&
             (Interface->IpAllMulticastCount > 0))) {
            //
            // This packet is destined to a specific client, but also
            // needs to be seen by raw.  We need to clone the packet
            // so we can deliver it to both if needed.
            //
            PIP_REQUEST_CONTROL_DATA RawClone;

            RawClone = 
                IppCreateClonePacketForRaw(
                    Args,
                    Protocol,
                    FALSE);
            if (RawClone != NULL) {
                //
                // Since we handle the real packet separately, make sure 
                // we never generate ICMP errors for the raw clone.
                //
                RawClone->PromiscuousOnlyReceive = TRUE;
                RawClone->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
                Args->RawClone = RawClone;
            }
        }

        NextHeaderValue = ExtDatagram->NextHeaderValue;
        IPsecMapTransProtoForInboundPkt(
            ExtDatagram->NetBufferList,
            (IPPROTO *)&NextHeaderValue);   
        
        if (NextHeaderValue != CurrNextHeaderValue) {
            if (DeliverList.Head != NULL) {
                //
                // We've found a new value.  Process the DeliverList now.
                //
                IppProcessDeliverList(
                    Protocol, 
                    CurrNextHeaderValue,
                    &DeliverList, 
                    &RawList, 
                    &ErrorList, 
                    &DoneList);
            }            
            CurrNextHeaderValue = NextHeaderValue;
        }

        //
        // Move it to the DeliverList.
        //
        IppAppendToGenericList(&DeliverList, ExtDatagram);
        }
    
    //
    // Process the last DeliverList.
    //
    if (DeliverList.Head) {
        IppProcessDeliverList(
            Protocol, 
            CurrNextHeaderValue,
            &DeliverList, 
            &RawList, 
            &ErrorList, 
            &DoneList);
    }

    //
    // Process the RawList.  This tries sending to raw anything that
    // a specific protocol didn't accept.
    //
    if (RawList.Head) {
        IppProcessDeliverList(
            Protocol, 
            IPPROTO_RESERVED_RAW,
            &RawList, 
            NULL, 
            &ErrorList, 
            &DoneList);
    }

    //
    // We can now count the number of successful deliveries.
    // Unsuccessful ones will be in the ErrorList.
    //
    InDelivers = 0;
    for (Args = DoneList.Head; Args != NULL; Args = Args->Next) {
        InDelivers++;
    }
    Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        InDelivers += InDelivers;

    //
    // Now send all the ICMP errors.
    //
    for (Args = ErrorList.Head; Args != NULL; Args = NextArgs) {
        NextArgs = Args->Next;
        Args->Next = NULL;
        Args->NetBufferList->Status = STATUS_SUCCESS;
        IppSendErrorListForDiscardReason(
            FALSE,
            Protocol,
            Args,
            Args->DiscardReason,
            Args->DiscardParameter);
        if (Args->NetBufferList != NULL) {
            Args->NetBufferList->Status = STATUS_SUCCESS;
        }
        IppAppendToGenericList(&DoneList, Args);
    }

    if (DoneList.Head != NULL) {
        IppClearInboundSecurityContext(DoneList.Head);
        IppCompleteAndFreePacketList(DoneList.Head, FALSE);
    }
}

NTSTATUS
IppFillHopLimitCmsg(
    IN IPPROTO Level,
    IN UINT8 HopLimit, 
    IN OUT UCHAR **CurrentPosition,
    IN OUT ULONG *BufferLength
    )
/*++

Routine Description:

    Create an ancillary data object and fill in IP{V6}_HOPLIMIT information.

    This is a helper function for the IP{V6}_HOPLIMIT socket option.
    The caller provides the hop limit as specified in the IP header of the 
    packet. This routine will create the proper ancillary data object and 
    fill in the hop limit.

Arguments:

    Level - Supplies the socket option level.

    HopLimit - Supplies the hop limit from the IP header.

    CurrentPosition - Supplies a pointer to the buffer that will be filled 
        in with the ancillary data object.

    BufferLength - Supplies the length of the buffer to update.

Return Value:

    STATUS_SUCCESS
    STATUS_BUFFER_TOO_SMALL

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG Size = CMSG_SPACE(sizeof(int));
    PCMSGHDR CmsgHeader = (PCMSGHDR)*CurrentPosition;
    INT *HopLimitPointer = (INT*)WSA_CMSG_DATA(CmsgHeader);

    if (*BufferLength < Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in the ancillary data object header information.
    //
    CmsgHeader->cmsg_level = Level;
    CmsgHeader->cmsg_type = IP_HOPLIMIT;
    CmsgHeader->cmsg_len = CMSG_LEN(sizeof(INT));

    *HopLimitPointer = HopLimit;
    *CurrentPosition += Size;
    *BufferLength -= Size;

    return STATUS_SUCCESS;
}

NTSTATUS
IppFillInterfaceCmsg(
    IN IPPROTO Level,
    IN IF_INDEX InterfaceIndex,
    IN OUT UCHAR **CurrentPosition,
    IN OUT ULONG *BufferLength
    )
/*++

Routine Description:

    Create an ancillary data object and fill in IP{V6}_RECVIF information.

    This is a helper function for the IP{V6}_RECVIF socket option.
    The caller provides the interface index of the arrival interface.
    This routine will create the proper ancillary data object and
    fill in the index.

Arguments:

    Level - Supplies the socket option level.

    InterfaceIndex - Supplies the interface index of the arrival interface.

    CurrentPosition - Supplies a pointer to the buffer that will be filled
        in with the ancillary data object.

    BufferLength - Supplies the length of the buffer to update.

Return Value:

    STATUS_SUCCESS
    STATUS_BUFFER_TOO_SMALL

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG Size = CMSG_SPACE(sizeof(IF_INDEX));
    PCMSGHDR CmsgHeader = (PCMSGHDR)*CurrentPosition;
    INT *Index = (INT*)WSA_CMSG_DATA(CmsgHeader);

    if (*BufferLength < Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in the ancillary data object header information.
    //
    CmsgHeader->cmsg_level = Level;
    CmsgHeader->cmsg_type = IP_RECVIF;
    CmsgHeader->cmsg_len = CMSG_LEN(sizeof(IF_INDEX));

    *Index = InterfaceIndex;

    *CurrentPosition += Size;
    *BufferLength -= Size;

    return STATUS_SUCCESS;
}

NTSTATUS
IppFillDestinationCmsg(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *DestinationAddress,
    IN OUT UCHAR **CurrentPosition,
    IN OUT ULONG *BufferLength
    )
/*++

Routine Description:

    Create an ancillary data object and fill in IP{V6}_RECVDSTADDR information.

    This is a helper function for the IP{V6}_RECVDSTADDR socket option.
    The caller provides the destination address as specified in the IP
    header of the packet.  This routine will create the
    proper ancillary data object and fill in the destination IP address.

Arguments:

    Protocol - Supplies a pointer to the global protocol information.

    DestinationAddress - Supplies the destination address from IP header
        of packet.

    CurrentPosition - Supplies a pointer to the buffer that will be filled
        in with the ancillary data object.

    BufferLength - Supplies the length of the buffer to update.

Return Value:

    STATUS_SUCCESS
    STATUS_BUFFER_TOO_SMALL

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    ULONG Size = CMSG_SPACE(AddressBytes);
    PCMSGHDR CmsgHeader = (PCMSGHDR)*CurrentPosition;
    UCHAR *Address = (PUCHAR)WSA_CMSG_DATA(CmsgHeader);

    if (*BufferLength < Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in the ancillary data object header information.
    //
    CmsgHeader->cmsg_level = Protocol->Level;
    CmsgHeader->cmsg_type = IP_RECVDSTADDR;
    CmsgHeader->cmsg_len = CMSG_LEN(AddressBytes);

    RtlCopyMemory(Address, DestinationAddress, AddressBytes);

    *CurrentPosition += Size;
    *BufferLength -= Size;

    return STATUS_SUCCESS;
}

NTSTATUS
IppFillPacketInfoCmsg(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *DestinationAddress,
    IN IF_INDEX LocalInterface,
    IN OUT UCHAR **CurrentPosition,
    IN OUT ULONG *BufferLength
    )
/*++

Routine Description:

    Create an ancillary data object and fill in IP_PKTINFO or IPV6_PKTINFO 
    information.

    This is a helper function for the IP_PKTINFO and IPV6_PKTINFO socket 
    options.  The caller provides the destination address as specified 
    in the IP header of the packet and the interface index of the local 
    interface the packet was delivered on. This routine will create the
    proper ancillary data object and fill in the destination IP address
    and the interface number of the local interface.

Arguments:

    Protocol = Supplies a pointer to the global protocol information.

    DestinationAddress - Supplies the destination address from IP header
                         of packet.

    LocalInterface - Supplies the index of the local interface on which packet
                     arrived.

    CurrentPosition - Supplies a pointer to the buffer that will be filled
                      in with the ancillary data object.

    BufferLength - Supplies the length of the buffer to update.

Return Value:

    STATUS_SUCCESS
    STATUS_BUFFER_TOO_SMALL

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    ULONG Size = CMSG_SPACE(AddressBytes + sizeof(IF_INDEX));
    PCMSGHDR CmsgHeader = (PCMSGHDR)*CurrentPosition;
    UCHAR *Address = (PUCHAR)WSA_CMSG_DATA(CmsgHeader);

    if (*BufferLength < Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in the ancillary data object header information.
    //
    CmsgHeader->cmsg_level = Protocol->Level;
    CmsgHeader->cmsg_type = IP_PKTINFO;
    CmsgHeader->cmsg_len = CMSG_LEN(AddressBytes + sizeof(IF_INDEX));

    RtlCopyMemory(Address, DestinationAddress, AddressBytes);
    RtlCopyMemory(Address + AddressBytes, &LocalInterface, sizeof(IF_INDEX));

    *CurrentPosition += Size;
    *BufferLength -= Size;

    return STATUS_SUCCESS;
}


NTSTATUS
IppFillRoutingHeaderCmsg(
    IN IPPROTO Level,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN OUT UCHAR **CurrentPosition,
    IN OUT ULONG *BufferLength
    )
/*++

Routine Description:

    Creates an ancillary data object and fills it in with the routing header
    from the packet.

Arguments:

    Level - Supplies the socket option level.
    
    Control - Supplies the packet from which to obtain the routing header.
    
    CurrentPosition - Supplies a pointer to the buffer that will be filled
        in with the ancillary data object.

    BufferLength - Supplies the length of the buffer to update.

Return Value:

    STATUS_SUCCESS
    STATUS_BUFFER_TOO_SMALL

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG Size = CMSG_SPACE(Control->ReceiveRoutingHeaderLength);
    PCMSGHDR CmsgHeader = (PCMSGHDR)*CurrentPosition;
    PUCHAR RoutingHeaderPointer = (PUCHAR) WSA_CMSG_DATA(CmsgHeader);
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;
    SIZE_T BytesCopied;
    ULONG BytesToRetreat;
    NTSTATUS Status;

    if (*BufferLength < Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Fill in the ancillary data object header information.
    //
    CmsgHeader->cmsg_level = Level;
    CmsgHeader->cmsg_type = IP_RTHDR;
    CmsgHeader->cmsg_len = WSA_CMSG_LEN(Control->ReceiveRoutingHeaderLength);

    //
    // We should be only called on the receive path, where there is a single
    // NetBuffer per NetBufferList.
    //
    ASSERT(NetBuffer->Next == NULL);


    //
    // Retreat to routing header and copy it into buffer.
    //
    BytesToRetreat = Control->NlcReceiveDatagram.NetworkLayerHeadersSize
        - Control->ReceiveRoutingHeaderOffset;        
    
    Status = 
        NetioRetreatNetBufferList(
            Control->NetBufferList,
            BytesToRetreat,
            0);
    //
    // Should succeed due to prior validation.
    //
    ASSERT(NT_SUCCESS(Status));

    RtlCopyMdlToBuffer(
        NetBuffer->CurrentMdl, 
        NetBuffer->CurrentMdlOffset,
        RoutingHeaderPointer,
        Control->ReceiveRoutingHeaderLength, 
        &BytesCopied);
    ASSERT(BytesCopied == Control->ReceiveRoutingHeaderLength);

    NetioAdvanceNetBufferList(Control->NetBufferList, BytesToRetreat);
        
    *CurrentPosition += Size;
    *BufferLength -= Size;

    return STATUS_SUCCESS;
}

NTSTATUS
IppInternalQueryAncillaryData(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_SESSION_STATE State,
    IN OUT PULONG BufferLength,
    OUT PUCHAR BufferPointer OPTIONAL
    )
/*++

Routine Description:

    Fill in ancillary data into a buffer supplied by the caller.  This
    is typically used by the recvmsg() api.

Arguments:

    Protocol - Supplies the protocol being used.

    Control - Supplies the packet received.
    
    Datagram - Supplies a pointer to the datagram received.
    
    NlSessionState - Supplies a pointer to the NL session state.

    BufferLength - Supplies the length in bytes of the ancillary data buffer,
        returns the number of bytes filled in.

    BufferPointer - Returns the modified ancillary data buffer.

--*/
   
{
    NTSTATUS Status;
    PIP_LOCAL_ADDRESS DestLocalAddress = Control->DestLocalAddress;

    if (BufferPointer == NULL) {
        //
        // Return number of bytes required.
        //
        *BufferLength = 
            IppGetAncillaryDataLength(
                Protocol,
                State,
                Control);
        return STATUS_SUCCESS;        
    }
    
    if (State->ReceivePacketInfo) {
        Status = IppFillPacketInfoCmsg(
                    Protocol,
                    NL_ADDRESS(DestLocalAddress), 
                    DestLocalAddress->Interface->Index, 
                    &BufferPointer, 
                    BufferLength);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }
    if (State->ReceiveDestination) {
        Status = IppFillDestinationCmsg(Protocol,
                                        NL_ADDRESS(DestLocalAddress), 
                                        &BufferPointer, 
                                        BufferLength);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }
    if (State->ReceiveInterface) {
        Status = IppFillInterfaceCmsg(Protocol->Level,
                                      DestLocalAddress->Interface->Index,
                                      &BufferPointer,
                                      BufferLength);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }
    if (State->ReceiveHopLimit) {
        UINT8 *HopLimit = (UINT8*)(Control->IP + Protocol->TtlOffset);
        Status = IppFillHopLimitCmsg(Protocol->Level,
                                     *HopLimit,
                                     &BufferPointer, 
                                     BufferLength);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    if (State->ReceiveRoutingHeader) {
        Status = 
            IppFillRoutingHeaderCmsg(
                Protocol->Level,
                Control,
                &BufferPointer,
                BufferLength);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }        

    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpNlpQueryAncillaryData(
    IN PNL_REQUEST_QUERY_ANCILLARY_DATA Args
    )
/*++

Routine Description:

    Fill in ancillary data into a buffer supplied by the caller.  This
    is typically used by the recvmsg() api.

Arguments:

    Args contains the following fields:

    ProviderHandle - Supplies a pointer to our client context.

    NlSessionState - Supplies a pointer to the NL session state.

    Datagram - Supplies a pointer to the datagram received.

    BufferLength - Supplies the length in bytes of the ancillary data buffer,
        returns the number of bytes filled in.

    Buffer - Supplies a pointer to the ancillary data buffer.

--*/
{
    NTSTATUS Status;
    ULONG BufferLength = Args->BufferLength;
    PIP_CLIENT_CONTEXT Client = 
        IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);

    Status = 
        IppInternalQueryAncillaryData(
            Client->Protocol,
            (PIP_REQUEST_CONTROL_DATA) Args->Datagram,
            (PIP_SESSION_STATE)Args->NlSessionState,
            &BufferLength,
            Args->Buffer);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }        

    //
    // Return number of bytes filled.
    //
    Args->BufferLength -= BufferLength;

    return STATUS_SUCCESS;
}

NL_SESSION_FILTER_ACTION
IpNlpFilterDatagramBySessionInformation(
    IN PNL_REQUEST_FILTER_DATAGRAM_BY_SESSION_INFORMATION Args
    )
/*++

Routine Description:

    Based on NL session state, determine whether a datagram should
    be delivered to an endpoint.

Arguments:

    NlSessionState - Supplies the session state for the endpoint.

    Datagram - Supplies a datagram to test.

Return Value:

    NlsfAllowAlways if the datagram is always deliverable
        (e.g., if SIO_RCVALL is set on the arrival interface).
    NlsfAllowIfBindMatches if the client should base its decision on
        how the endpoint is bound.
    NlsfDrop if the datagram is never deliverable
        (e.g., datagram is multicast and the group is not joined).

Locks:

    The NL client is responsible for ensuring that no call to
    CleanupSessionInformation for the same session is in progress during
    this call.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_SESSION_STATE State = (PIP_SESSION_STATE) Args->NlSessionState;
    PNLC_RECEIVE_DATAGRAM Datagram = Args->Datagram;
    PIP_LOCAL_ADDRESS LocalAddress = 
        (PIP_LOCAL_ADDRESS) Datagram->LocalAddress;
    NL_ADDRESS_TYPE AddressType = NL_ADDRESS_TYPE(LocalAddress);
    
    if (State == NULL) {
        if (AddressType == NlatMulticast) {
            return NlsfDrop;
        } else {
            return NlsfAllowIfBindMatches;
        }
    }

    //
    // If the session is in promiscuous mode on the arrival interface,
    // the packet is always accepted.  We do the comparison without
    // holding a lock.  As a result, a packet might not be delivered
    // while the interface is being updated.  This is fine.
    //
    if (State->PromiscuousInterface == LocalAddress->Interface) {
        return NlsfAllowAlways;
    }

    if (AddressType == NlatMulticast) {
        //
        // Check the multicast reception state of the session.
        //
        // We do the comparisons below without holding a lock.  As a result,
        // a packet might be delivered incorrectly while the interface is being
        // updated.  This is fine.
        //
        
        if (State->AllMulticastInterface == LocalAddress->Interface) {
            return NlsfAllowAlways;
        }

        //
        // According to MSDN, "In Winsock, the IP_MULTICAST_LOOP option applies
        // only to the receive path".  Unfortunately, these semantics are true
        // only for the legacy (XP/W2K3) IPv4 stack.  For the legacy IPv6
        // stack, Winsock semantics are the same as that of Unix: "In the UNIX
        // version, the IP_MULTICAST_LOOP option applies to the send path.".
        // However, the discrepency between the Windows IPv4 stack and the rest
        // of the industry was unintentional.
        // TODO: Implement Unix semantics for both IPv4 and IPv6.
        //
        if (!State->MulticastLoopback && Datagram->Loopback) {
            return NlsfDrop;
        }

        if (!IppDoesSessionStateIncludeGroupAndSource(
                State,
                (PIP_LOCAL_MULTICAST_ADDRESS) LocalAddress,
                Datagram->RemoteAddress)) {
            return NlsfDrop;
        }
    } else if (AddressType == NlatBroadcast) {
        //
        // Check the broadcast reception state of the session.
        //
        if (!State->ReceiveBroadcast) {
            return NlsfDrop;
        }
    }

    // 
    // Determine if the protection level allows the indication.
    // 
    if (State->ProtectionLevel == PROTECTION_LEVEL_RESTRICTED) {
        SCOPE_ID SiteId;

        ASSERT(
            IS_IPV6_PROTOCOL(LocalAddress->Interface->Compartment->Protocol));

        //
        // Teredo traffic has already been filtered. 
        // (See IpNlpFilterIndicationBySessionInformation).
        //

        // 
        // Drop any datagram that originated from outside this site.
        //
        if (Ipv6AddressScope(Datagram->RemoteAddress) > ScopeLevelSite) {            
            SiteId = 
                Ipv6SitePrefixMatch(
                    LocalAddress->Interface->Compartment, 
                    (IN6_ADDR *)Datagram->RemoteAddress);
            if (SiteId.Value == 0) {
                return NlsfDrop;
            }
        }
    }

    return NlsfAllowIfBindMatches;
}

NL_SESSION_FILTER_ACTION
IpNlpFilterIndicationBySessionInformation(
    IN PNL_REQUEST_FILTER_INDICATION_BY_SESSION_INFORMATION Args
    )
/*++

Routine Description:

    Based on NL session state, determine whether an indication should
    be delivered to an endpoint.

Arguments:

    NlSessionState - Supplies the session state for the endpoint.

    LocalAddress - Supplies the LocalAddress the endpoint is bound to.

    IndicationLocalAddress - Supplies the LocalAddress for the indication.

Return Value:

    NlsfAllowAlways if the indication is always deliverable
        (e.g., if there is no interface list specified for the session).
    NlsfDrop if the indication is never deliverable
        (e.g., if the indication is on an interface not in the interface list).

Locks:

    The client is responsible for ensuring that no call to SetSessionInfo
    for the same session is in progress during this call.

--*/
{
    ULONG i;
    PIP_SESSION_STATE State =
        (PIP_SESSION_STATE) Args->NlSessionState;
    CONST NL_LOCAL_ADDRESS *IndicationLocalAddress =
        Args->IndicationLocalAddress;
    
    //
    // We process filters applicable to all datagrams in an indication.
    // Individual datagrams might still go through per-datagram filters.
    //

    //
    // Multicast and broadcast indications may only be accepted by endpoints
    // bound to an address on the interface over which the indication arrives.
    // This filter only applies to endpoints bound to a specific address.
    //
    if (((IndicationLocalAddress->Type == NlatMulticast) ||
         (IndicationLocalAddress->Type == NlatBroadcast)) &&
        (Args->LocalAddress != NULL) &&
        (Args->LocalAddress->Interface != IndicationLocalAddress->Interface)) {
        return NlsfDrop;
    }
    
    if (State == NULL) {
        return NlsfAllowAlways;
    }
    
    //
    // Determine if the interface list allows the indication.
    // This filter only applies to endpoints bound to the unspecified address.
    //
    if ((Args->LocalAddress == NULL) && (State->InterfaceList != NULL)) {
        IF_INDEX Index = IndicationLocalAddress->Interface->Index;
        PIP_INTERFACE_LIST InterfaceList;
        ULONG Count;
        KIRQL OldIrql;

        KeAcquireSpinLock(&State->SpinLock, &OldIrql);

        InterfaceList = State->InterfaceList;
        Count = InterfaceList->Count;
        
        for (i = 0; ; i++) {
            if (i == Count) {
                //
                // The indication is on an interface not in the interface list.
                //
                KeReleaseSpinLock(&State->SpinLock, OldIrql);
                return NlsfDrop;
            }
                
            if (InterfaceList->Index[i] == Index) {
                //
                // The indication matches the interface-list filter.
                // Proceed to the next filter.
                //
                break;
            }
        }

        KeReleaseSpinLock(&State->SpinLock, OldIrql);
    }

    // 
    // Determine if the protection level allows the indication.
    // 
    if (State->ProtectionLevel != PROTECTION_LEVEL_UNRESTRICTED) {
        PIP_LOCAL_ADDRESS LocalAddress = 
            (PIP_LOCAL_ADDRESS) IndicationLocalAddress;

        ASSERT(
            IS_IPV6_PROTOCOL(LocalAddress->Interface->Compartment->Protocol));

        //
        // Do not indicate any teredo traffic.
        //
        if (IN6_IS_ADDR_TEREDO(
                (IN6_ADDR *)LocalAddress->Identifier->Address)) {
            return NlsfDrop;
        }
    }
    
    return NlsfAllowAlways;
}
