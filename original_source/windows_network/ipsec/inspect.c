/*++

Copyright (c) Microsoft Corporation

Module Name:

    inspect.c

Abstract:

    This is a dummy module containing stubs for functions relating to
    IP-layer inspection points.  The WFP team owns the actual module.

--*/

#include "precomp.h"

//
// "Outbound Transport" inspection point.
//
// This inspection point occurs just after a datagram has been given
// to the network layer for processing.  This allows the inspection
// point to work with 3rd party transports and RAW sends, since a
// network layer client can send packets for any transport protocol.
//
// Each packet is positioned at the start of the transport protocol
// header.
//
// This corresponds to the firewall and security policy lookups in the
// XP IPv6 stack.
//
IP_FILTER_ACTION
IppInspectLocalDatagramsOut(
    IN IPPROTO IpProtocol,              // IPv4 or IPv6.
    IN CONST NL_LOCAL_ADDRESS *SourceAddress, // Effective source address.
    IN CONST UCHAR *DestinationAddress, // Effective destination address.
    IN NL_ADDRESS_TYPE DestinationAddressType,     // Type of destination. 
    IN CONST NL_INTERFACE *DestinationInterface,   // Outgoing interface.        
    IN IF_INDEX DestinationSubInterface,       // Outgoing sub-interface index.    
    IN BOOLEAN IsLoopback,              // TRUE if going to local machine.    
    IN IPPROTO TransportProtocol,       // Upper-layer protocol.
    IN HANDLE InspectHandle,            // Inspection handle.
    IN PTRANSPORT_DATA TransportData,   // Upper-layer protocol-specific
                                        // metadata structure.
    IN ULONG TransportHeaderSize,       // Transport Header Length.
    IN PNET_BUFFER_LIST NetBufferList,  // List of packets.
    IN CONST IP_PATH_PRIVATE *Path OPTIONAL,     // Path the packet is using.    
    IN SCOPE_ID RemoteScopeId,          // If Path is NULL, scope-id is passed here 
    IN PVOID AncillaryData OPTIONAL,    // Socket control data
    IN ULONG AncillaryDataLength,
    IN PVOID HeaderIncludeHeader OPTIONAL,   // raw IP header
    IN ULONG HeaderIncludeHeaderLength
    )
{

    DBG_UNREFERENCED_PARAMETER(IpProtocol);
    DBG_UNREFERENCED_PARAMETER(SourceAddress);
    DBG_UNREFERENCED_PARAMETER(DestinationAddress);
    DBG_UNREFERENCED_PARAMETER(DestinationAddressType);
    DBG_UNREFERENCED_PARAMETER(DestinationInterface);
    DBG_UNREFERENCED_PARAMETER(DestinationSubInterface);
    DBG_UNREFERENCED_PARAMETER(IsLoopback);    
    DBG_UNREFERENCED_PARAMETER(InspectHandle);
    DBG_UNREFERENCED_PARAMETER(TransportData);
    DBG_UNREFERENCED_PARAMETER(TransportHeaderSize);
    DBG_UNREFERENCED_PARAMETER(RemoteScopeId);
    DBG_UNREFERENCED_PARAMETER(AncillaryData);
    DBG_UNREFERENCED_PARAMETER(AncillaryDataLength);
    DBG_UNREFERENCED_PARAMETER(HeaderIncludeHeader);
    DBG_UNREFERENCED_PARAMETER(HeaderIncludeHeaderLength);

#ifdef TEST_IPSEC
   if (TransportProtocol == 0xC9)
   {
      IpSecSetSecurityContext(NetBufferList, UlongToPtr(1));
   }
#else
   DBG_UNREFERENCED_PARAMETER(TransportProtocol);
   DBG_UNREFERENCED_PARAMETER(NetBufferList);
#endif
   DBG_UNREFERENCED_PARAMETER(Path);

   return IpFilterAllow;
}

//
// "Inbound Transport" inspection point.
//
// This inspection point occurs just after a datagram has been given
// to an "upper-layer" protocol which is implemented by the network protocol
// module (ICMP, IGMP, MLD, etc.)  The packet is positioned at the start
// of the upper-layer protocol header.
//
IP_FILTER_ACTION
IppInspectLocalDatagramsIn(
    IN IPPROTO IpProtocol,              // IPv4 or IPv6.
    IN CONST NL_LOCAL_ADDRESS *DestinationAddress,
                                        // Effective destination address.
    IN CONST UCHAR *SourceAddress,      // Effective source address.
    IN CONST NL_INTERFACE *SourceInterface,   // Source interface.        
    IN IF_INDEX SourceSubInterface,     // Source sub-interface.
    IN BOOLEAN IsLoopback,              // TRUE if from local machine.
    IN IPPROTO TransportProtocol,       // Upper-layer protocol.
    IN PTRANSPORT_DATA TransportData,   // Upper-layer protocol-specific
                                        // metadata structure.
    IN ULONG NlHeadersSize,             // Bytes of network-layer headers.
    IN ULONG TlHeaderSize,              // Bytes of transport-layer headers
                                        // already parsed.  
    IN HANDLE InspectHandle,            // Inspect handle.
    IN PNLC_RECEIVE_DATAGRAM Datagram,  // Receive Datagram.
    IN PNET_BUFFER_LIST NetBufferList   // Packet.
    )
{

    DBG_UNREFERENCED_PARAMETER(IpProtocol);
    DBG_UNREFERENCED_PARAMETER(DestinationAddress);
    DBG_UNREFERENCED_PARAMETER(SourceAddress);
    DBG_UNREFERENCED_PARAMETER(SourceInterface);
    DBG_UNREFERENCED_PARAMETER(SourceSubInterface);
    DBG_UNREFERENCED_PARAMETER(IsLoopback);
    DBG_UNREFERENCED_PARAMETER(TransportProtocol);
    DBG_UNREFERENCED_PARAMETER(TransportData);
    DBG_UNREFERENCED_PARAMETER(NlHeadersSize);
    DBG_UNREFERENCED_PARAMETER(TlHeaderSize);
    DBG_UNREFERENCED_PARAMETER(InspectHandle);
    DBG_UNREFERENCED_PARAMETER(Datagram);
    DBG_UNREFERENCED_PARAMETER(NetBufferList);

    return IpFilterAllow;
}

//
// "Inbound Transport Clone" inspection point.
//
// This inspection point occurs just after a datagram has been processed
// by an "upper-layer protocol but before a clone of the datagram is passed
// to the raw IP protocol module.
//
VOID
IppInspectCloneDatagramsIn(
    IN struct _NLC_RECEIVE_DATAGRAM* Datagram,  // Original datagram.
    IN PNET_BUFFER_LIST CloneNetBufferList      // Cloned packet.
    )
{
    DBG_UNREFERENCED_PARAMETER(Datagram);
    DBG_UNREFERENCED_PARAMETER(CloneNetBufferList);
}


//
// "Outbound IP Packet" inspection point.
//
// This inspection point is called for all locally-originated
// packets just before being evaluated for fragmentation.  All
// other extension headers are already in place.  IPsec authentication
// and encryption will already have occurred at this time.
//
IP_FILTER_ACTION
IppInspectLocalPacketsOut(
    IN IPPROTO IpProtocol,              // IPPROTO_IP or IPPROTO_IPV6.
    IN CONST NL_LOCAL_ADDRESS *SourceAddress, 
                                        // Effective source address.
    IN CONST UCHAR *DestinationAddress, // Effective destination address.
    IN NL_ADDRESS_TYPE DestinationAddressType, 
                                        // Type of destination. 
    IN CONST NL_INTERFACE *Interface,   // Outgoing interface.
    IN IF_INDEX SubInterfaceIndex,      // Outgoing sub-interface index.
    IN BOOLEAN IsLoopback,              // TRUE if going to local machine.    
    IN IPPROTO TransportProtocol,       // Upper-layer protocol.
    IN ULONG NlHeadersSize,             // Bytes of network-layer headers.
    IN ULONG PathMtu,                   // MTU for this path.
    IN BOOLEAN DontFragment,
    IN PTRANSPORT_DATA TransportData,   // Upper-layer protocol-specific
                                        // metadata structure.
    IN ULONG TransportHeaderLength,     // Transport header length.
    IN PNET_BUFFER_LIST NetBufferList   // List of packets.
    )
{

    DBG_UNREFERENCED_PARAMETER(IpProtocol);
    DBG_UNREFERENCED_PARAMETER(SourceAddress);
    DBG_UNREFERENCED_PARAMETER(DestinationAddress);
    DBG_UNREFERENCED_PARAMETER(DestinationAddressType);
    DBG_UNREFERENCED_PARAMETER(Interface);
    DBG_UNREFERENCED_PARAMETER(SubInterfaceIndex);
    DBG_UNREFERENCED_PARAMETER(IsLoopback);    
    DBG_UNREFERENCED_PARAMETER(TransportProtocol);
    DBG_UNREFERENCED_PARAMETER(NlHeadersSize);
    DBG_UNREFERENCED_PARAMETER(PathMtu);
    DBG_UNREFERENCED_PARAMETER(DontFragment);
    DBG_UNREFERENCED_PARAMETER(TransportData);
    DBG_UNREFERENCED_PARAMETER(TransportHeaderLength);
    DBG_UNREFERENCED_PARAMETER(NetBufferList);

    return IpFilterAllow;
}

//
// "Inbound IP Fragment" inspection point.
//
// Called on the arrival interface for all received fragments.
//
IP_FILTER_ACTION
IppInspectFragmentIn(
    IN IPPROTO IpProtocol,              // IPv4 or IPv6.
    IN CONST UCHAR *SourceAddress,      // Source address for routing.
    IN CONST NL_LOCAL_ADDRESS *DestinationAddress, 
    // Destination address for routing.
    IN NL_INTERFACE* Interface,         // Interface.
    IN ULONG SubInterfaceIndex,         // Sub interface Index.
    IN BOOLEAN IsLoopback,              // TRUE if locally generated packet.
    IN ULONG NlHeadersSize,             // Network Headers Length.
    IN UINT32 Identification,           // Packet identification.
    IN UINT16 FragmentOffset,           // Fragment offset.
    IN ULONG FragmentLength,            // Length of data in bytes.
    IN PNET_BUFFER_LIST NetBufferList   // Fragment.
                    )
{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(SourceAddress);
   DBG_UNREFERENCED_PARAMETER(DestinationAddress);
   DBG_UNREFERENCED_PARAMETER(Interface);
   DBG_UNREFERENCED_PARAMETER(SubInterfaceIndex);
   DBG_UNREFERENCED_PARAMETER(IsLoopback);
   DBG_UNREFERENCED_PARAMETER(NlHeadersSize);
   DBG_UNREFERENCED_PARAMETER(Identification);
   DBG_UNREFERENCED_PARAMETER(FragmentOffset);
   DBG_UNREFERENCED_PARAMETER(FragmentLength);
   DBG_UNREFERENCED_PARAMETER(NetBufferList);

   return IpFilterAllow;
}

//
// "IP Forward" inspection point.
//
IP_FILTER_ACTION
IppInspectForwardedPacket(
    IN IPPROTO IpProtocol,                  
                               // IPPROTO_IP or IPPROTO_IPV6.
    IN CONST NL_INTERFACE *SourceInterface, 
                               // Arrival interface.
    IN IF_INDEX SourceSubInterfaceIndex,  
                               // Arrival sub-interface index.
    IN BOOLEAN IsLoopback,
                               // Locally originated.
    IN CONST NL_INTERFACE *DestinationInterface, 
                               // Outgoing interface.
    IN IF_INDEX DestinationSubInterfaceIndex,   
                               // Outgoing sub-interface index.
    IN BOOLEAN IsLocallyDestined,
                               // Not source routed, next hop local address.
    IN CONST UCHAR *SourceAddress,          
                               // Source address for routing.
    IN CONST UCHAR *DestinationAddress,     
                               // Destination address for routing.
    IN NL_ADDRESS_TYPE DestinationAddressType,
                               // Type of destination address.
    IN PNET_BUFFER_LIST NetBufferList       
                               // Packet.
    )

{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(SourceInterface);
   DBG_UNREFERENCED_PARAMETER(SourceSubInterfaceIndex);
   DBG_UNREFERENCED_PARAMETER(IsLoopback);
   DBG_UNREFERENCED_PARAMETER(DestinationInterface);
   DBG_UNREFERENCED_PARAMETER(DestinationSubInterfaceIndex);
   DBG_UNREFERENCED_PARAMETER(IsLocallyDestined);
   DBG_UNREFERENCED_PARAMETER(SourceAddress);
   DBG_UNREFERENCED_PARAMETER(DestinationAddress);
   DBG_UNREFERENCED_PARAMETER(DestinationAddressType);
   DBG_UNREFERENCED_PARAMETER(NetBufferList);

   return IpFilterAllow;
}

IP_FILTER_ACTION
IppInspectForwardedFragmentGroup(
    IN IPPROTO IpProtocol,                          // IPPROTO_IP or
                                                    // IPPROTO_IPV6.
    IN CONST NL_INTERFACE *SourceInterface,         // Arrival interface.
    IN IF_INDEX SourceSubInterfaceIndex,            // Arrival sub-interface
                                                    // index.
    IN CONST NL_INTERFACE *DestinationInterface,    // Outgoing interface.
    IN IF_INDEX DestinationSubInterfaceIndex,       // Outgoing sub-interface
                                                    // index.
    IN CONST UCHAR *SourceAddress,                  // Source address for
                                                    // routing.
    IN CONST UCHAR *DestinationAddress,             // Destination address for
                                                    // routing.
    IN NL_ADDRESS_TYPE DestinationAddressType,      // Type of destination
                                                    // address.
    IN PNET_BUFFER_LIST NetBufferListChain          // Packet list.
    )
{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(SourceInterface);
   DBG_UNREFERENCED_PARAMETER(SourceSubInterfaceIndex);
   DBG_UNREFERENCED_PARAMETER(DestinationInterface);
   DBG_UNREFERENCED_PARAMETER(DestinationSubInterfaceIndex);
   DBG_UNREFERENCED_PARAMETER(SourceAddress);
   DBG_UNREFERENCED_PARAMETER(DestinationAddress);
   DBG_UNREFERENCED_PARAMETER(DestinationAddressType);
   DBG_UNREFERENCED_PARAMETER(NetBufferListChain);

   return IpFilterAllow;
}

//
// "Inbound IP Packet" inspection point.
//
IP_FILTER_ACTION
IppInspectLocalPacketsIn(
    IN IPPROTO IpProtocol,              // IPPROTO_IP or IPPROTO_IPV6.
    IN CONST NL_INTERFACE *Interface,   // Arrival interface.
    IN IF_INDEX SubInterfaceIndex,      
                                        // Arrival sub-interface index.
    IN CONST UCHAR *SourceAddress,      // Effective source address.
    IN CONST NL_LOCAL_ADDRESS *DestinationAddress, 
                                        // Effective destination address.
    IN BOOLEAN IsLoopback,              // TRUE if from local machine.
    IN BOOLEAN IsReassembled,           // TRUE if reassembled.
    IN ULONG NlHeadersSize,             // Bytes of network-layer headers.
    IN PNLC_RECEIVE_DATAGRAM Datagram,  // Receive Datagram.
    IN PNET_BUFFER_LIST NetBufferList   // Packet.
    )
{

    DBG_UNREFERENCED_PARAMETER(IpProtocol);
    DBG_UNREFERENCED_PARAMETER(Interface);
    DBG_UNREFERENCED_PARAMETER(SubInterfaceIndex);
    DBG_UNREFERENCED_PARAMETER(SourceAddress);
    DBG_UNREFERENCED_PARAMETER(DestinationAddress);
    DBG_UNREFERENCED_PARAMETER(IsLoopback);
    DBG_UNREFERENCED_PARAMETER(IsReassembled);
    DBG_UNREFERENCED_PARAMETER(NlHeadersSize);
    DBG_UNREFERENCED_PARAMETER(Datagram);
    DBG_UNREFERENCED_PARAMETER(NetBufferList);

    return IpFilterAllow;
}

//
// "Discarded Packets" inspection point.
//
IP_DISCARD_ACTION
IppInspectDiscardedPackets(
    IN IPPROTO IpProtocol,              // IPPROTO_IP or IPPROTO_IPV6.
    IN CONST OPTIONAL NL_INTERFACE *SourceInterface, 
                                        // Arrival interface.
    IN IF_INDEX sourceSubInterfaceIndex,// Arrival sub interface index.
    IN CONST OPTIONAL NL_INTERFACE *DestinationInterface, 
                                        // Outgoing interface.
    IN IF_INDEX destinationSubInterfaceIndex,
                                        // Outgoing sub interface index.
    IN CONST UCHAR *SourceAddress,      // Source address for routing.
    IN CONST NL_LOCAL_ADDRESS *DestinationAddress,
                                        // Destination address for routing.
    IN ULONG NlHeadersSize,             // Bytes of network-layer headers.
    IN PNLC_RECEIVE_DATAGRAM Datagram,  // Receive Datagram.
    IN PNET_BUFFER_LIST NetBufferList,  // Packet.
    IN BOOLEAN IsLoopback,              // TRUE if locally generated packet.
    IN IP_DISCARD_REASON Reason         // Reason for discard.
    )
{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(SourceInterface);
   DBG_UNREFERENCED_PARAMETER(sourceSubInterfaceIndex);
   DBG_UNREFERENCED_PARAMETER(DestinationInterface);
   DBG_UNREFERENCED_PARAMETER(destinationSubInterfaceIndex);
   DBG_UNREFERENCED_PARAMETER(SourceAddress);
   DBG_UNREFERENCED_PARAMETER(DestinationAddress);
   DBG_UNREFERENCED_PARAMETER(NlHeadersSize);
   DBG_UNREFERENCED_PARAMETER(Datagram);
   DBG_UNREFERENCED_PARAMETER(NetBufferList);
   DBG_UNREFERENCED_PARAMETER(IsLoopback);
   DBG_UNREFERENCED_PARAMETER(Reason);

   return IpDiscardAllowIcmp;
}

NTSTATUS
IppInspectJoin(
    IN IPPROTO IpProtocol,                  // IPPROTO_IP or IPPROTO_IPV6.
    IN HANDLE InspectHandle,                // Endpoint handle.
    IN CONST NL_INTERFACE *Interface,       // Interface joining on.
    IN CONST UCHAR *GroupAddress,           // Group address to join.
    IN ULONG SourceCount,                   // Number of sources to join.
    IN CONST UCHAR *SourceAddress OPTIONAL, // Source addresses to join.
    IN PIPP_INSPECT_REQUEST_COMPLETE CompletionRoutine,
    IN PVOID CompletionContext              // Completion context.
    )
{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(InspectHandle);
   DBG_UNREFERENCED_PARAMETER(Interface);
   DBG_UNREFERENCED_PARAMETER(GroupAddress);
   DBG_UNREFERENCED_PARAMETER(SourceCount);
   DBG_UNREFERENCED_PARAMETER(SourceAddress);
   DBG_UNREFERENCED_PARAMETER(CompletionRoutine);
   DBG_UNREFERENCED_PARAMETER(CompletionContext);

   return STATUS_SUCCESS;
}

NTSTATUS
IppInspectPromiscuousRequest(
    IN IPPROTO IpProtocol,                  // IPPROTO_IP or IPPROTO_IPV6.
    IN HANDLE InspectHandle,                // Endpoint handle.
    IN CONST NL_INTERFACE *Interface,       // Interface to affect.
    IN RCVALL_VALUE Mode,                   // Promiscuous mode to set.
    IN PIPP_INSPECT_REQUEST_COMPLETE CompletionRoutine,
    IN PVOID CompletionContext              // Completion context.
    )
{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(InspectHandle);
   DBG_UNREFERENCED_PARAMETER(Interface);
   DBG_UNREFERENCED_PARAMETER(Mode);
   DBG_UNREFERENCED_PARAMETER(CompletionRoutine);
   DBG_UNREFERENCED_PARAMETER(CompletionContext);

   return STATUS_SUCCESS;
}

NTSTATUS
IppInspectAllMulticastRequest(
    IN IPPROTO IpProtocol,                  // IPPROTO_IP or IPPROTO_IPV6.
    IN HANDLE InspectHandle,                // Endpoint handle.
    IN CONST NL_INTERFACE *Interface,       // Interface to affect.
    IN RCVALL_VALUE Mode,                   // All-multicast mode to set.
    IN PIPP_INSPECT_REQUEST_COMPLETE CompletionRoutine,
    IN PVOID CompletionContext              // Completion context.
    )
{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(InspectHandle);
   DBG_UNREFERENCED_PARAMETER(Interface);
   DBG_UNREFERENCED_PARAMETER(Mode);
   DBG_UNREFERENCED_PARAMETER(CompletionRoutine);
   DBG_UNREFERENCED_PARAMETER(CompletionContext);

   return STATUS_SUCCESS;
}

NTSTATUS
IppInspectEnableHeaderInclude(
    IN IPPROTO IpProtocol,                  // IPPROTO_IP or IPPROTO_IPV6.
    IN HANDLE InspectHandle,                // Endpoint handle.
    IN PIPP_INSPECT_REQUEST_COMPLETE CompletionRoutine,
    IN PVOID CompletionContext              // Completion context.
    )
{
   DBG_UNREFERENCED_PARAMETER(IpProtocol);
   DBG_UNREFERENCED_PARAMETER(InspectHandle);
   DBG_UNREFERENCED_PARAMETER(CompletionRoutine);
   DBG_UNREFERENCED_PARAMETER(CompletionContext);

   return STATUS_SUCCESS;
}


NTSTATUS
KfdDriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT* KfdDeviceObject,
    IN PDRIVER_DISPATCH* DevControlDispatchFn
    )
{
   UNREFERENCED_PARAMETER(DriverObject);
   UNREFERENCED_PARAMETER(KfdDeviceObject);
   UNREFERENCED_PARAMETER(DevControlDispatchFn);

   return STATUS_SUCCESS;
}

VOID
KfdUnload(IN PDEVICE_OBJECT DeviceObject)
{
   UNREFERENCED_PARAMETER(DeviceObject);

}

NTSTATUS
WfpAleInitializeIo(
   IN  PDRIVER_OBJECT DriverObject,
   OUT PDEVICE_OBJECT* DeviceObject,
   OUT PDRIVER_DISPATCH* DeviceControlDispatchFunction)
{
   UNREFERENCED_PARAMETER(DriverObject);
   UNREFERENCED_PARAMETER(DeviceObject);
   UNREFERENCED_PARAMETER(DeviceControlDispatchFunction);

   return STATUS_SUCCESS;
}

void
WfpAleShutdownIo(
   IN  PDEVICE_OBJECT DeviceObject)
{
   UNREFERENCED_PARAMETER(DeviceObject);
}


NTSTATUS
WfpAleEndpointCreationHandler(
    IN HANDLE ParentInspectHandle,
    IN ADDRESS_FAMILY AddressFamily,
    IN USHORT SocketType,
    IN IPPROTO IpProto,
    IN PEPROCESS OwningProcess,
    IN PETHREAD OwningThread OPTIONAL,
    IN struct _INET_SS* sessionState OPTIONAL,
    IN HANDLE endpointHandle OPTIONAL,
    OUT HANDLE* InspectHandle
    )
{
   UNREFERENCED_PARAMETER(ParentInspectHandle);
   UNREFERENCED_PARAMETER(AddressFamily);
   UNREFERENCED_PARAMETER(SocketType);
   UNREFERENCED_PARAMETER(IpProto);
   UNREFERENCED_PARAMETER(OwningProcess);
   UNREFERENCED_PARAMETER(OwningThread);
   UNREFERENCED_PARAMETER(sessionState);
   UNREFERENCED_PARAMETER(endpointHandle);
   UNREFERENCED_PARAMETER(InspectHandle);

   *InspectHandle = (HANDLE) -1;
   
   return STATUS_SUCCESS;
}

VOID 
WfpAleEndpointTeardownHandler(
    IN PVOID Context)
{
   UNREFERENCED_PARAMETER(Context);
}
