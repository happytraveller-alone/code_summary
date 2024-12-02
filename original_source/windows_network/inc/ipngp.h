/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    ipngp.h

Abstract:

    This module contains declarations for the network layer module's
    common definitions and structures.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    Kernel mode only.

--*/

#ifndef _IPNGP_
#define _IPNGP_
#pragma once

//
// Disable certain warnings that are common to the NT coding style.
//
#pragma warning(disable:4055) // from data pointer 'PVOID' to function pointer
#pragma warning(disable:4057) // 'LONG *' differs in indirection to slightly
                              // different base types from 'ULONG *'
#pragma warning(disable:4115) // named type definition in parentheses
#pragma warning(disable:4152) // function/data pointer conversion in expression
#pragma warning(disable:4200) // zero-sized array in struct/union
#pragma warning(disable:4244) // conversion from 'int' to 'BOOLEAN'

//
// Disable certain prefast warnings.
//
#pragma prefast(disable:255, "we use _alloca with only small values which would be fine as stack variables, but we wish to avoid using a specific constant size everywhere")
#pragma prefast(disable:394, "prefast has bugs in this warning.  It's not in winpft anyway.")

#ifdef USER_MODE
#include <usermodep.h>
#else
#include <ntosp.h>
#include <wmikm.h>
#include <zwapi.h>
#endif
#include <ntddksec.h>
#include <netiocore.h>
#include <flnpi.h>
#include <nlnpi.h>
#include <nlnpip.h>
#include <nlmnpi.h>
#include <nlsnpi.h>
#include <netioapi.h>
#include <avltable.h>
#include <refhist.h>
#include <ipsecdef.h>
#include <kfdentry.h>
#include <alepio.h>
#include <eqosinit.h>
#include "generic.h"
#include "timer.h"
#include <ipinspect.h>
#include <ipipsec.h>
#include <modules.h>
#include <wsnetiop.h>
#include <limits.h>
#include <ntintsafe.h>
#include <disabledcomponents.h>


#if PERFNET_BUILD
#define INTERFACE_REFHIST 0
#define COMPARTMENT_REFHIST 0
#define PATH_REFHIST 0
#define NEIGHBOR_REFHIST 0
#define ADDRESS_REFHIST 0
#define ECHO_REFHIST 0
#define MFE_REFHIST 0
#else
#define INTERFACE_REFHIST 1
#define COMPARTMENT_REFHIST 1
#define PATH_REFHIST 1
#define NEIGHBOR_REFHIST 1
#define ADDRESS_REFHIST 1
#define ECHO_REFHIST 1
#define MFE_REFHIST 1
#endif

//
// Forward declarations.
//

typedef struct _IP_SESSION_STATE *PIP_SESSION_STATE;
typedef struct _IP_SUBINTERFACE *PIP_SUBINTERFACE;
typedef struct _IP_INTERFACE *PIP_INTERFACE;
typedef union _IP_PATH_FLAGS *PIP_PATH_FLAGS;
typedef struct _IP_COMPARTMENT *PIP_COMPARTMENT;
typedef struct _IP_PROTOCOL *PIP_PROTOCOL;
typedef struct _IP_REQUEST_CONTROL_DATA *PIP_REQUEST_CONTROL_DATA;

//
// Global variable containing a pointer to the device object. Used by
// IoAllocateWorkItem. 
//
extern PDEVICE_OBJECT IppDeviceObject;

//
// A NULL handle is considered a valid structure.
//
#define IppCast(Pointer, TYPE) \
    ((TYPE *) (Pointer)); \
    ASSERT(!(Pointer) || (((TYPE *) (Pointer))->Signature == TYPE##_SIGNATURE))

//
// Network Layer Signatures.
//

#define IP_CLIENT_CONTEXT_SIGNATURE 'ccpI'  // 'Ipcc'
#define NMP_CLIENT_CONTEXT_SIGNATURE 'ccmN' // 'Nmcc'

#define IP_COMPARTMENT_SIGNATURE 'mcpI'     // 'Ipcm'
#define IP_INTERFACE_SIGNATURE 'fipI'       // 'Ipif'
#define IP_PATH_SIGNATURE 'appI'            // 'Ippa'
#define IP_PROXY_NEIGHBOR_SIGNATURE 'nppI'  // 'Ippn'
#define IP_ROUTE_SIGNATURE 'trpI'           // 'Iprt'
#define IP_SUBINTERFACE_SIGNATURE 'ispI'    // 'Ipsi'

#include "refhist.h"
#include "timeout.h"
#include "offload.h"
#include "twtimer.h"

#include "binding.h"
#include "address.h"
#include "multicast.h"
#include "neighbor.h"
#include "proxy.h"
#include "interface.h"
#include "route.h"
#include "router.h"
#include "multicastfwd.h"
#include "compartment.h"
#include "ping.h"
#include "session.h"
#include "subr.h"

//
// Module IDs for protocol independent modules. 
//
#define IMS_SESSION      0x0001
#define IMS_CONTROL_POOL 0x0002
#define IMS_PROTOCOLS    0x0004

//
// Module status for the protocol independent modules. 
//
extern ULONG IpModuleStatus;

//
// IP's notion of time, in ticks.
//
extern ULONG IppTickCount;

//
// If this is server or client SKU.
//
extern BOOLEAN IppIsServerSKU;

extern ULONG IppNeighborCacheLimit;

extern CONST NL_PROVIDER_DISPATCH IpNlProviderDispatch;

NL_PROVIDER_CHECKSUM_DATAGRAM IpNlpChecksumDatagram;
NL_PROVIDER_CANCEL_SEND_DATAGRAMS IpNlpCancelSendDatagrams;
NL_PROVIDER_REVERSE_ROUTING_HEADER IpNlpReverseRoutingHeader;

typedef struct _NL_MODULE {
    LONG Bit;
    CONST UCHAR *ModuleString;
    NTSTATUS (*StartFcn)(PIP_PROTOCOL Protocol);
    NTSTATUS (*StopFcn)(PIP_PROTOCOL Protocol);
    NTSTATUS (*WaitFcn)(PIP_PROTOCOL Protocol);
    VOID (*CleanupFcn)(PIP_PROTOCOL Protocol);
} NL_MODULE, *PNL_MODULE;

VOID
FASTCALL
IpngpReferenceDriver(
    VOID
    );

VOID
FASTCALL
IpngpDereferenceDriver(
    VOID
    );

__inline
VOID
DriverInitializeAllowUnloadEvent(
    VOID
    );

//
// Note that this structure wouldn't be needed if IoQueueWorkItem
// had been designed to call the user's routine with the WorkItem
// as an additional argument along with the DeviceObject and Context.
// Sigh.
//
typedef struct _IP_WORK_QUEUE_ITEM {
    PIO_WORKITEM WorkQueueItem;
    PVOID Context;
} IP_WORK_QUEUE_ITEM, *PIP_WORK_QUEUE_ITEM;

typedef 
VOID
(IP_WORK_QUEUE_ITEM_ROUTINE)(
    IN PVOID WorkItem
    );
typedef IP_WORK_QUEUE_ITEM_ROUTINE *PIP_WORK_QUEUE_ITEM_ROUTINE;

//
// Define a structure to store context for interface/address/route 
// change notifications.  Apart from the interface/address/route pointer, 
// this stores the event code to be logged for interfaces (0 in 
// case nothing needs to be logged)  and the type of notification.
//
typedef struct _IP_NOTIFICATION_WORK_QUEUE_ITEM {
    SINGLE_LIST_ENTRY Link;
    PIP_WORK_QUEUE_ITEM_ROUTINE WorkerRoutine;
    PVOID Object;
    NSI_NOTIFICATION NotificationType;
    ULONG EventCode;
    NSI_SINGLE_PARAM_DESC ParameterDescription;
} IP_NOTIFICATION_WORK_QUEUE_ITEM, *PIP_NOTIFICATION_WORK_QUEUE_ITEM;

//
// Define a structure used to create a work item
// for the per interface work queue. This contains
// the worker routine called when processing the work item
// and the object used by the worker routine.
//
typedef struct _IP_DELAYED_WORK_QUEUE_ITEM {
    SINGLE_LIST_ENTRY Link;
    PIP_WORK_QUEUE_ITEM_ROUTINE WorkerRoutine;
    PVOID Object;
} IP_DELAYED_WORK_QUEUE_ITEM, *PIP_DELAYED_WORK_QUEUE_ITEM;

//
// Define a structure used to store the information
// needed to add/ delete a persistant route
//
typedef struct _IP_ADD_DELETE_PERSISTENT_ROUTE {
    PIP_LOCAL_ADDRESS LocalAddress;
    NSI_SET_ACTION Action;        
} IP_ADD_DELETE_PERSISTENT_ROUTE, *PIP_ADD_DELETE_PERSISTENT_ROUTE;

typedef struct _IP_REQUEST_CONTROL_DATA {
    //
    // The union holds information exported to other modules.
    // We embed the structure so that we can easily retrieve our own
    // private information (past the union below) when the other
    // module passes a pointer back to us (e.g. on completion, and in 
    // QueryAncillaryData).
    //
    union {
        //
        // The struct contains fields we use internally.  The first two
        // fields are common to all of the structures in this union.
        //
        struct {
            struct _IP_REQUEST_CONTROL_DATA *Next;
            PNET_BUFFER_LIST NetBufferList;

            //
            // These fields are used during packetization, and are here
            // so we can pend certain calls to NL services prior to
            // packetization.  The fields are unused after 
            // IppPacketizeDatagrams returns.
            // 
            PVOID Reserved[3]; // Don't overlap with FlSendPackets.
            IPPROTO DestinationProtocol;
            INT HopLimit;
            INT TypeOfService;

            ULONG HeaderIncludeHeaderLength;
            USHORT HopByHopOptionsLength;
            USHORT RoutingHeaderLength;
            USHORT JumbogramHopByHopOptionsLength;
            USHORT IpHeaderAndExtensionHeadersLength;
            PVOID HeaderIncludeHeader;
            PVOID HopByHopOptions;
            PVOID RoutingHeader; // Stored in receiver format.

            IP_SESSION_FLAGS Flags;
        };

        //
        // This is the structure passed to NL clients on receives.
        //
        NLC_RECEIVE_DATAGRAM NlcReceiveDatagram;

        //
        // This is the control structure passed to NL clients on ICMP errors. 
        //
        NLC_RECEIVE_CONTROL_MESSAGE NlcControlMessage;
         
        //
        // This is the structure passed to FL providers on sends.
        //
        FL_SEND_PACKETS FlSendPackets;
    };

    struct {
        BOOLEAN IcmpError : 1;
        BOOLEAN HeaderInclude : 1;
        BOOLEAN PromiscuousOnlyReceive : 1;
        BOOLEAN Reassembled : 1;
        BOOLEAN IsOriginLocal : 1;
        BOOLEAN IsPathReferenced : 1;
        BOOLEAN IsSourceReferenced : 1;
        BOOLEAN IsNextHopReferenced : 1;
        BOOLEAN IsAllocated : 1;
        BOOLEAN RouterAlert : 1;
        BOOLEAN Jumbogram : 1;
        BOOLEAN EnforceHeaderIncludeChecks : 1;
        BOOLEAN StrictSourceRouted : 1;
        BOOLEAN NoFragmentGrouping : 1;
        BOOLEAN OnSendPath : 1;
        BOOLEAN IpSecHeadersPresent : 1;
    };

    //
    // Transport data for passing to WFP. 
    //
    TRANSPORT_DATA TransportData;
    ULONG TransportHeaderLength;
    
    //
    // Valid on the send and receive path.  Never holds a reference.  On the
    // send path, indirect reference held by Path (or SourceLocalAddress if
    // there is no Path).  On the receive path, indirect reference held by
    // SourceSubInterface.  
    //
    PIP_COMPARTMENT Compartment;

    //
    // Send: Path is valid except in case of SendDirect.  Reference held on
    // path if IsPathReferenced is TRUE.
    //
    PIP_PATH Path;

    //
    // Pointer to destination structure (valid for send and receive path).
    // Holds a reference if IsNextHopReferenced is TRUE.
    // IsNextHopReferenced is FALSE, for instance, on the receive path if
    // we are already holding the path instance atomic set read lock (implying
    // that the path cannot go away and so the local address pointer in the
    // path cannot go away).
    //
    union {
        PIP_LOCAL_ADDRESS DestLocalAddress;
        PIP_NEIGHBOR DestNeighbor;

        PIP_NEXT_HOP NextHop;
        PIP_NEIGHBOR NextHopNeighbor;
        PIP_LOCAL_ADDRESS NextHopLocalAddress;        
    };

    //
    // SourceLocalAddress is valid on the send path (if the Path is
    // also valid, then SourceLocalAddress = Path->SourceAddress).
    // SourceSubInterface is valid on the receive path for
    // non-loopback packets.  A reference is held on the source if
    // IsSourceReferenced is TRUE.  On the send path,
    // IsSourceReferenced can only be TRUE if there is no Path.  If
    // there is a Path, then the Path holds an indirect reference to
    // the SourceLocalAddress.
    //
    union {
        PIP_LOCAL_UNICAST_ADDRESS SourceLocalAddress; // If IsOriginLocal.
        PIP_SUBINTERFACE SourceSubInterface;          // Otherwise.
        PIP_NEXT_HOP SourcePointer;
    };

    //
    // The final destination address is the one seen by the upper-layer
    // protocol.  This comes from the NL client on a send.  On a receive, it
    // comes from the IP header or IPv4 source route option or IPv6 routing
    // header.
    //
    IP_ADDRESS_STORAGE FinalDestinationAddress;
    
    //
    // The current destination address is the one that appears in the
    // IP header and is used for the routing lookup.
    //
    CONST UCHAR *CurrentDestinationAddress;
    NL_ADDRESS_TYPE CurrentDestinationType;
    
    //
    // On the receive path, this is not necessarily a "local" address, but
    // we need to keep the type, interface etc anyway.
    //
    NL_ADDRESS_IDENTIFIER SourceAddress;

    UCHAR *IP; // IP header for this packet.
    USHORT SkippedHeaderLength; // Headers skipped in AH validation.

    //
    // Offset of current "NextHeader" value from start of the IP header. This 
    // is only used during next header processing on the receive path.
    //
    USHORT NextHeaderPosition; 

    struct _IP_REQUEST_CONTROL_DATA *RawClone; // Used only in receive path.

    //
    // Saved state when discarding a packet and optionally sending an ICMP
    // error.  If the upper layer protocol returns an error, the packet is sent
    // to RAW.  If RAW rejects it as well, then an ICMP error is generated
    // based on the initial error code saved here.
    //

    IP_DISCARD_REASON DiscardReason;
    ULONG DiscardParameter;

    //
    // Valid only on the receive path.  Offset into the single NetBuffer at
    // which the routing header (IPv6) or source route option (IPv4) can be
    // found.
    //
    UINT8 ReceiveRoutingHeaderOffset;
    ULONG ReceiveRoutingHeaderLength;
} IP_REQUEST_CONTROL_DATA, *PIP_REQUEST_CONTROL_DATA;

//
// $TODO: Restore this once the NLC_RECEIVE_DATAGRAM is unionized.
//
//C_ASSERT(sizeof(IP_REQUEST_CONTROL_DATA) < PAGE_SIZE / 16);
C_ASSERT(FIELD_OFFSET(IP_REQUEST_CONTROL_DATA, DestinationProtocol) ==
         sizeof(FL_SEND_PACKETS));

__inline
PIP_INTERFACE
IppGetPacketSourceInterface(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:
    
    This routine returns the source interface of the packet (the interface on
    which the packet was received for received packets and the interface on
    which it was sent for the send path).  It uses the IsOriginLocal flag to
    determine the appropriate source interface. 
    
Arguments:

    Packet - Supplies the packet.

Return Value:

    Returns the source interface. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    if (Packet->IsOriginLocal) {
        if (Packet->SourceLocalAddress != NULL) {
            return (PIP_INTERFACE) Packet->SourceLocalAddress->Interface;
        }
    } else {
        if (Packet->SourceSubInterface != NULL) {
            return Packet->SourceSubInterface->Interface;
        }
    }
    
    return NULL;
}

typedef
VOID
(IP_INTERNAL_RECEIVE_DATAGRAMS)(
    IN PIP_REQUEST_CONTROL_DATA FirstDatagramList
    );

typedef IP_INTERNAL_RECEIVE_DATAGRAMS *PIP_INTERNAL_RECEIVE_DATAGRAMS;

typedef
VOID
(IP_INTERNAL_RECEIVE_CONTROL_MESSAGE)(
    IN PIP_REQUEST_CONTROL_DATA ControlMessage
    );

typedef IP_INTERNAL_RECEIVE_CONTROL_MESSAGE 
    *PIP_INTERNAL_RECEIVE_CONTROL_MESSAGE;

typedef
NTSTATUS
(IP_INTERNAL_VALIDATE_NET_BUFFER)(
    IN OUT PIP_REQUEST_CONTROL_DATA ControlData,
    IN PNDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo
    );

typedef IP_INTERNAL_VALIDATE_NET_BUFFER *PIP_INTERNAL_VALIDATE_NET_BUFFER;

typedef
NTSTATUS
(IP_INTERNAL_ADDRESS_INTERFACE)(
    IN PIP_INTERFACE Interface
    );

typedef IP_INTERNAL_ADDRESS_INTERFACE *PIP_INTERNAL_ADDRESS_INTERFACE;

typedef
VOID
(IP_INTERNAL_INTERFACE_SET_TIMEOUT)(
    IN PNLI_LOCKED_SET InterfaceSet,
    IN BOOLEAN RecalculateReachableTime,
    IN BOOLEAN ForceRouterAdvertisement
    );

typedef IP_INTERNAL_INTERFACE_SET_TIMEOUT *PIP_INTERNAL_INTERFACE_SET_TIMEOUT;

typedef
NTSTATUS
(IP_INTERNAL_ADD_LINK_LAYER_SUFFIX_ADDRESSES)(
    IN PIP_INTERFACE Interface
    );

typedef IP_INTERNAL_ADD_LINK_LAYER_SUFFIX_ADDRESSES 
    *PIP_INTERNAL_ADD_LINK_LAYER_SUFFIX_ADDRESSES;

typedef
VOID
(IP_INTERNAL_UNADDRESS_INTERFACE)(
    IN PIP_INTERFACE Interface
    );
typedef IP_INTERNAL_UNADDRESS_INTERFACE *PIP_INTERNAL_UNADDRESS_INTERFACE;

typedef
NTSTATUS
(IP_INTERNAL_INITIALIZE_SUBINTERFACE)(
    IN PIP_SUBINTERFACE SubInterface
    );
typedef IP_INTERNAL_INITIALIZE_SUBINTERFACE 
    *PIP_INTERNAL_INITIALIZE_SUBINTERFACE;

typedef
NTSTATUS
(IP_INTERNAL_ADD_ADDRESS_HELPER)(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    );

typedef IP_INTERNAL_ADD_ADDRESS_HELPER *PIP_INTERNAL_ADD_ADDRESS_HELPER;

typedef
VOID
(IP_INTERNAL_DELETE_ADDRESS_HELPER)(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    );

typedef IP_INTERNAL_DELETE_ADDRESS_HELPER *PIP_INTERNAL_DELETE_ADDRESS_HELPER;

typedef
NTSTATUS
(IP_INTERNAL_START_ADVERTISING)(
    IN PIP_INTERFACE Interface
    );
typedef IP_INTERNAL_START_ADVERTISING *PIP_INTERNAL_START_ADVERTISING;

typedef
VOID
(IP_INTERNAL_STOP_ADVERTISING)(
    IN PIP_INTERFACE Interface
    );
typedef IP_INTERNAL_STOP_ADVERTISING *PIP_INTERNAL_STOP_ADVERTISING;

typedef
SCOPE_LEVEL
(IP_INTERNAL_ADDRESS_SCOPE)(
    IN CONST UCHAR *Address
    );
typedef IP_INTERNAL_ADDRESS_SCOPE *PIP_INTERNAL_ADDRESS_SCOPE;

//
// REVIEW: NL_ADDRESS_TYPE is both a type (nldef.h) and a macro (nlnpi.h)!!!
//
typedef NL_ADDRESS_TYPE IP_ADDRESS_TYPE;
typedef
IP_ADDRESS_TYPE
(IP_INTERNAL_ADDRESS_TYPE)(
    IN CONST UCHAR *Address
    );
typedef IP_INTERNAL_ADDRESS_TYPE *PIP_INTERNAL_ADDRESS_TYPE;

typedef
BOOLEAN
(IP_INTERNAL_IS_LOOPBACK_ADDRESS)(
    IN CONST UCHAR *Address
    );
typedef IP_INTERNAL_IS_LOOPBACK_ADDRESS *PIP_INTERNAL_IS_LOOPBACK_ADDRESS;

typedef
VOID
(IP_INTERNAL_NOTIFY_ROUTE_CHANGE)(
    IN PIP_UNICAST_ROUTE Route,
    IN NSI_NOTIFICATION NotificationType,
    OUT PIP_ROUTE_NOTIFY_CONTEXT RouteContext
    );
typedef IP_INTERNAL_NOTIFY_ROUTE_CHANGE *PIP_INTERNAL_NOTIFY_ROUTE_CHANGE;

typedef
PUCHAR
(IP_INTERNAL_GET_ROUTE_NEXTHOP_ADDRESS)(
    IN PIP_UNICAST_ROUTE Route
    );
typedef IP_INTERNAL_GET_ROUTE_NEXTHOP_ADDRESS
    *PIP_INTERNAL_GET_ROUTE_NEXTHOP_ADDRESS;

typedef
VOID
(IP_INTERNAL_PROCESS_NET_BUFFER_LISTS)(
    IN PIP_REQUEST_CONTROL_DATA Args
    );

typedef IP_INTERNAL_PROCESS_NET_BUFFER_LISTS
    *PIP_INTERNAL_PROCESS_NET_BUFFER_LISTS;

typedef
NTSTATUS
(IP_INTERNAL_VALIDATE_ROUTING_HEADER_FOR_SEND) (
    IN CONST UCHAR *Buffer,
    IN ULONG BufferLength,
    OUT PUSHORT BytesToCopy
    );

typedef IP_INTERNAL_VALIDATE_ROUTING_HEADER_FOR_SEND 
    *PIP_INTERNAL_VALIDATE_ROUTING_HEADER_FOR_SEND;
    
typedef
VOID
(IP_INTERNAL_AUTHENTICATE_HEADER)(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PNET_BUFFER Buffer,
    IN OUT PUINT8 NextHeaderPointer,
    IN OUT PUINT8 DeferredHeaderPointer,
    IN OUT PVOID *DeferredDataPointer,
    IN OUT BOOLEAN *FreeData
    );

typedef IP_INTERNAL_AUTHENTICATE_HEADER *PIP_INTERNAL_AUTHENTICATE_HEADER;

typedef
NTSTATUS
(IP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER)(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PUCHAR Data,
    IN UINT8 NextHeader
    );

typedef IP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER 
      *PIP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER;

typedef struct _IP_PACKETIZE_DATA {
    //
    // These fields are needed during the packetization process.
    //
    IPSEC_SESSION_INFORMATION;

    UINT8 EspPadLength;

    ULONG IpHeaderLengthAppended;

    BOOLEAN AhHeaderPresent;
} IP_PACKETIZE_DATA, *PIP_PACKETIZE_DATA;

typedef
NTSTATUS
(IP_INTERNAL_ADD_HEADER)(
    IN PIP_REQUEST_CONTROL_DATA ControlData,
    IN PNET_BUFFER NetBuffer,
    IN UINT8 NextHeader, 
    IN OUT PIP_PACKETIZE_DATA Data
    );

typedef IP_INTERNAL_ADD_HEADER 
      *PIP_INTERNAL_ADD_HEADER;


typedef struct _IP_RECEIVE_DEMUX {
    
    //
    // Fields used for internal handlers.
    //
    
    PIP_INTERNAL_RECEIVE_DATAGRAMS InternalReceiveDatagrams; 
    PIP_INTERNAL_RECEIVE_CONTROL_MESSAGE InternalReceiveControlMessage;
    PIP_INTERNAL_AUTHENTICATE_HEADER InternalAuthenticateHeader;
    PIP_INTERNAL_DEFERRED_AUTHENTICATE_HEADER 
        InternalDeferredAuthenticateHeader;
    PIP_INTERNAL_ADD_HEADER InternalAddHeader;

    BOOLEAN IsExtensionHeader;

    //
    // Fields used for external handlers.
    //
    REFERENCE_OBJECT Reference;
    PIP_CLIENT_CONTEXT NlClient;

    // For clients that don't provide their own local endpoint for 
    // firewall inspection on the send path.
    //
    HANDLE LocalEndpoint;
} IP_RECEIVE_DEMUX, *PIP_RECEIVE_DEMUX;

//
// Internal data-path defines.
//
typedef
NTSTATUS
(IP_INTERNAL_VALIDATE_HOP_BY_HOP_OPTIONS_FOR_SEND) (
    IN CONST UCHAR *OptionsBuffer,
    IN ULONG OptionsLength,
    OUT PUSHORT FirstHopOffset,
    OUT PUSHORT BytesToCopy
    );

typedef IP_INTERNAL_VALIDATE_HOP_BY_HOP_OPTIONS_FOR_SEND
    *PIP_INTERNAL_VALIDATE_HOP_BY_HOP_OPTIONS_FOR_SEND;

typedef
VOID
(IP_INTERNAL_FILL_HEADER_INCLUDE_PROTOCOL_HEADER)(
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN OUT PUCHAR IpHeader,
    IN PNET_BUFFER NetBuffer,
    IN ULONG HeaderLength,
    IN UINT8 NextHeader
    );

typedef IP_INTERNAL_FILL_HEADER_INCLUDE_PROTOCOL_HEADER
    *PIP_INTERNAL_FILL_HEADER_INCLUDE_PROTOCOL_HEADER;

typedef
NTSTATUS
(IP_INTERNAL_FILL_PROTOCOL_HEADER)(
    IN OUT PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader,
    IN PNET_BUFFER NetBuffer,
    IN ULONG HeaderLength, 
    IN UINT8 NextHeader
    );

typedef IP_INTERNAL_FILL_PROTOCOL_HEADER
    *PIP_INTERNAL_FILL_PROTOCOL_HEADER;

typedef
VOID
(IP_INTERNAL_UPDATE_PROTOCOL_HEADER)(
    IN PIP_REQUEST_CONTROL_DATA Control, 
    IN OUT PUCHAR IpHeader,
    IN PNET_BUFFER NetBuffer
    );

typedef IP_INTERNAL_UPDATE_PROTOCOL_HEADER
    *PIP_INTERNAL_UPDATE_PROTOCOL_HEADER;


typedef 
NTSTATUS
(IP_INTERNAL_SKIP_NETWORK_LAYER_HEADERS)(
    IN PNET_BUFFER NetBuffer, 
    OUT PUCHAR SourceAddress OPTIONAL, 
    OUT PUCHAR CurrentDestinationAddress OPTIONAL, 
    OUT PUCHAR FinalDestinationAddress OPTIONAL, 
    OUT UINT8 *TransportLayerHeader,
    OUT ULONG *SkippedLength
    );

typedef IP_INTERNAL_SKIP_NETWORK_LAYER_HEADERS 
    *PIP_INTERNAL_SKIP_NETWORK_LAYER_HEADERS;


//
// This is per-buffer control information
//
typedef struct _IP_BUFFER_DATA {
    PVOID NlHeader;
} IP_BUFFER_DATA, *PIP_BUFFER_DATA;

UINT16
IppChecksumDatagram(
    IN PNET_BUFFER NetBuffer,
    IN ULONG DataLength,
    IN CONST UCHAR *Source,
    IN CONST UCHAR *Dest,
    IN ULONG AddressLength,
    IN ULONG NextHeaderValue,
    IN ULONG PartialPseudoHeaderChecksum OPTIONAL
    );

NETIO_INLINE
UINT16
IppChecksumBuffer(
    IN PNET_BUFFER NetBuffer, 
    IN ULONG DataLength
    )
/*++

Routine Description:

    This routine computes the checksum of a net buffer with the given data
    length.  No pseudo-header checksum is included. 
    
Arguments:

    NetBuffer - Supplies the buffer for which to compute the checksum.

    DataLength - Supplies the data length of the buffer. 

--*/ 
{
    return IppChecksumDatagram(NetBuffer, DataLength, NULL, NULL, 0, 0, 0);
}

ULONG
tcpxsum(
    IN ULONG Checksum, 
    IN PUCHAR Source, 
    IN ULONG Length
    );

#define IppChecksum(Buffer, Length) \
    ((USHORT) tcpxsum(0, (PUCHAR) (Buffer), (Length)))

//
// Dispatcher functions
//

PIP_REQUEST_CONTROL_DATA
IppCreateClonePacket(
    IN PIP_REQUEST_CONTROL_DATA OriginalPacket,
    IN PIP_PROTOCOL Protocol
    );

PIP_REQUEST_CONTROL_DATA
IppCreateStrongClonePacket(
    IN PIP_REQUEST_CONTROL_DATA OriginalPacket,
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupSendState(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN BOOLEAN CleanupIpSec
    );

NTSTATUS
IppCopySendState(
    IN PIP_REQUEST_CONTROL_DATA Src,
    OUT PIP_REQUEST_CONTROL_DATA Dst
    );

PIP_REQUEST_CONTROL_DATA
IppCopyPacket(
    IN PIP_PROTOCOL Protocol, 
    IN PIP_REQUEST_CONTROL_DATA Packet
    );

VOID
IppParseHeaderIntoPacket(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Packet
    );

PIP_REQUEST_CONTROL_DATA
IppPendPacket(
    IN PIP_REQUEST_CONTROL_DATA Packet
    );

PIP_REQUEST_CONTROL_DATA
IppStrongPendPacket(
    IN PIP_REQUEST_CONTROL_DATA Packet
    );

PIP_REQUEST_CONTROL_DATA
IppStrongCopyPacket(
    IN PIP_REQUEST_CONTROL_DATA Packet
    );

VOID
IppCopyNetBufferListInfo(
    IN PNET_BUFFER_LIST Destination,
    IN PNET_BUFFER_LIST Source
    );

VOID
IppFreePacketList(
    IN PIP_REQUEST_CONTROL_DATA Packet
    );

VOID
IppCompleteAndFreePacketList(
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN BOOLEAN DispatchLevel
    );

VOID
IppClearInboundSecurityContext(
    IN PIP_REQUEST_CONTROL_DATA PacketList
    );
    
VOID
IppDispatchSendPacketHelper(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control
    );

VOID
IppLoopbackEnqueue(
    IN PIP_GENERIC_LIST PacketList,
    IN PIP_PROTOCOL Protocol,
    IN BOOLEAN DispatchLevel
    );

NTSTATUS
IppStartLoopback(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupLoopback(
    IN PIP_PROTOCOL Protocol
    );

VOID 
IppLoopbackTransmit(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    );

BOOLEAN
IppForwardPackets(
    IN PIP_PROTOCOL Protocol,
    IN PIP_INTERFACE SourceInterface,
    IN PIP_INTERFACE OutgoingInterface,
    IN PIP_REQUEST_CONTROL_DATA ControlData,
    IN PIP_NEXT_HOP NextHop OPTIONAL,
    IN BOOLEAN SourceRouted,
    IN BOOLEAN StrictSourceRouted,    
    OUT IP_DISCARD_REASON *DiscardReason
    );

IP_DISCARD_ACTION
IppDiscardReceivedPackets(
    IN PIP_PROTOCOL Protocol,
    IN IP_DISCARD_REASON DiscardReason,
    IN PIP_REQUEST_CONTROL_DATA Control,    
    IN PIP_SUBINTERFACE SourceSubInterface,
    IN PNET_BUFFER_LIST NetBufferList
    );

//
// Control pool manager functions. 
//
NTSTATUS
IppStartControlPoolManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupControlPoolManager(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppAddRemoveReceivePerProcessorContexts(
    IN ULONG ProcessorIndex,
    IN BOOLEAN ProcessorAdded
    );
    
//
// Internal Packetizer functions
//

NL_PROVIDER_SEND_DATAGRAMS IpNlpSendDatagrams;
NL_PROVIDER_FAST_SEND_DATAGRAM IpNlpFastSendDatagram;

#define HAS_PATH_MTU_TIMEOUT_FIRED(Protocol, Interface, SubInterface) \
    (((Path)->PathMtu < (SubInterface)->NlMtu) && \
    ((IppTickCount - (Path)->PathMtuLastSet) >= \
        ((IS_IPV4_PROTOCOL(Protocol) && \
            !(Path)->Flags.LastPathMtuChangeWasDecrease) ? \
         IPV4_PATH_MTU_INCREASE_TIME : \
         Interface->PathMtuDiscoveryTicks)))

VOID
IppSendDatagrams(
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_SEND_DATAGRAMS Args
    );

NTSTATUS
IppAuthenticatePacket(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PNET_BUFFER NetBuffer,
    IN PIP_PACKETIZE_DATA Data
    );

VOID
IppReceiveHeaderBatch(
    IN PIP_PROTOCOL Protocol,
    IN PIP_GENERIC_LIST List
    );

NETIO_INLINE
VOID
IppReceiveHeaders(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Process all subsequent headers (everything past the IP Header and
    Options).

Arguments:

    Control - Supplies the net buffer list to process.

Locks:

    Assumes caller holds no locks.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    IP_GENERIC_LIST List;

    IppInitializeGenericList(&List);
    IppAppendToGenericList(&List, Control);
    IppReceiveHeaderBatch(Protocol, &List);
}

typedef
NTSTATUS
(IP_INTERNAL_CREATE_MULTICAST_REPORT)(
    IN PIP_INTERFACE Interface,
    IN ULONG ReportSize,
    IN PIP_MULTICAST_RECORD_ENTRY Records, 
    IN OUT PNL_REQUEST_SEND_DATAGRAMS SendArgs
    );
typedef IP_INTERNAL_CREATE_MULTICAST_REPORT 
    *PIP_INTERNAL_CREATE_MULTICAST_REPORT;

typedef
BOOLEAN
(IP_INTERNAL_IS_MULTICAST_DISCOVERY_ALLOWED)(
    IN CONST UCHAR *Address
    );
typedef IP_INTERNAL_IS_MULTICAST_DISCOVERY_ALLOWED
    *PIP_INTERNAL_IS_MULTICAST_DISCOVERY_ALLOWED;

typedef
VOID
(IP_INTERNAL_PATH_MTU_TIMEOUT)(
    IN PIP_PATH Path,
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface
    );
typedef IP_INTERNAL_PATH_MTU_TIMEOUT
    *PIP_INTERNAL_PATH_MTU_TIMEOUT;

typedef
VOID
(IP_INTERNAL_SEND_REDIRECT)(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_NEIGHBOR Target
    );
typedef IP_INTERNAL_SEND_REDIRECT
    *PIP_INTERNAL_SEND_REDIRECT;

//
// Internal Fragmenter (send.c) functions.
//

VOID
IppFragmentPackets(
    IN PIP_PROTOCOL Protocol,
    __notnull IN PIP_REQUEST_CONTROL_DATA Args
    );

typedef
VOID
(IP_INTERNAL_FRAGMENT_PACKET_HELPER)(
    IN PIP_REQUEST_CONTROL_DATA Args,
    IN PIP_SUBINTERFACE SubInterface
    );
typedef IP_INTERNAL_FRAGMENT_PACKET_HELPER 
    *PIP_INTERNAL_FRAGMENT_PACKET_HELPER;

VOID
IppUpdatePacketCounts(
    IN PIP_PROTOCOL Protocol,
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_REQUEST_CONTROL_DATA ControlData
    );

VOID
IppSendDirect(
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface, 
    IN PIP_NEIGHBOR Neighbor OPTIONAL,
    IN PIP_LOCAL_UNICAST_ADDRESS NlSourceAddress,
    IN CONST UCHAR *NlDestinationAddress,
    IN IPPROTO TransportProtocol,
    IN PVOID TransportData,
    IN USHORT ChecksumOffset,
    IN PNET_BUFFER_LIST Nbl
    );

VOID
IppCleanUpFragments(
    IN PNET_BUFFER_LIST NetBufferList
    );

#if DBG
__inline
IppVerifyDataLength(
    PNET_BUFFER Nb
    )
{
    ULONG VerifyCount = 0;
    PMDL Mdl;

    for (Mdl = Nb->MdlChain; Mdl != NULL; Mdl = Mdl->Next) {
        VerifyCount += MmGetMdlByteCount(Mdl);
    }

    //
    // The router advertisement algorithm generates packets for
    // which there are unused bytes in the MDL chain.
    //
    ASSERT(VerifyCount >= Nb->DataLength + Nb->DataOffset);
}
#else
#define IppVerifyDataLength(Nb)
#endif

NETIO_INLINE
VOID
IppGetPacketAndByteCounts(
    IN PNET_BUFFER_LIST Nbl,
    OUT PULONG PacketCount,
    OUT PULONG ByteCount
    )
{
    PNET_BUFFER Nb = Nbl->FirstNetBuffer;

    *PacketCount = *ByteCount = 0;

    if (NET_BUFFER_LIST_INFO(Nbl, TcpLargeSendPacketInfo) != 0) {
        ULONG CumulativeHeaderSize, PayloadSize, CurrentPacketCount;

        ASSERT(Nb != NULL);
        ASSERT(Nb->Next == NULL);

        PayloadSize = NetioQueryNetBufferOriginalDataLength(Nb);
        CumulativeHeaderSize = Nb->DataLength - PayloadSize;
        CurrentPacketCount = IppGetSegmentationOffloadPacketCount(Nbl);

        (*PacketCount) += CurrentPacketCount;
        (*ByteCount) += CurrentPacketCount * CumulativeHeaderSize + 
                        PayloadSize;

        IppVerifyDataLength(Nb);
        return;
    }

    for (; Nb != NULL; Nb = Nb->Next) {
        (*PacketCount)++;
        (*ByteCount) += Nb->DataLength;
        IppVerifyDataLength(Nb);
    }
}

NETIO_INLINE
ULONG
IppGetPacketCount(
    IN PNET_BUFFER_LIST Nbl
    )
{
    PNET_BUFFER Nb = Nbl->FirstNetBuffer;
    ULONG PacketCount;

    if (NET_BUFFER_LIST_INFO(Nbl, TcpLargeSendPacketInfo) != 0) {
        ASSERT(Nb != NULL);
        ASSERT(Nb->Next == NULL);

        return IppGetSegmentationOffloadPacketCount(Nbl);
    }

    for (PacketCount = 0; Nb != NULL; Nb = Nb->Next) {
        PacketCount++;
    }
    return PacketCount;
}

//
// Internal Control Receiver routines.
//

IP_INTERNAL_RECEIVE_CONTROL_MESSAGE IppReceiveAhControl;
IP_INTERNAL_RECEIVE_CONTROL_MESSAGE IppReceiveEspControl;

//
// Internal Validater routines.
//
NTSTATUS
IppStartValidater(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupValidater(
    IN PIP_PROTOCOL Protocol
    );

FL_CLIENT_RECEIVE_PACKETS IpFlcReceivePackets;
FL_CLIENT_RECEIVE_PREVALIDATED_PACKETS IpFlcReceivePreValidatedPackets;

//
// Internal Next Header Processor routines.
//

VOID
IppCleanupNextHeaderProcessor(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppFindNlClient(
    IN PIP_PROTOCOL Protocol,
    IN IPPROTO UpperLayerProtocolId,
    IN PNET_BUFFER_LIST NetBufferList,
    OUT PIP_RECEIVE_DEMUX *DemuxPointer
    );

VOID
IppFindNlFinalHeaderClient(
    IN PIP_PROTOCOL Protocol,
    IN IPPROTO UpperLayerProtocolId,
    OUT PIP_RECEIVE_DEMUX *DemuxPointer
    );

VOID
IppProcessDeliverList(
    IN PIP_PROTOCOL Protocol,
    IN IPPROTO UpperLayerProtocolId,
    IN PIP_GENERIC_LIST DeliverList,
    IN PIP_GENERIC_LIST RawList,
    IN PIP_GENERIC_LIST ErrorList,
    IN PIP_GENERIC_LIST DoneList
    );

VOID
IppDeliverListToProtocol(
    IN PIP_RECEIVE_DEMUX Demux,
    __notnull IN OUT PIP_GENERIC_LIST DeliverList
    );

VOID
IppDeliverPreValidatedListToProtocol(
    PIP_RECEIVE_DEMUX Demux,
    PNLC_RECEIVE_DATAGRAM ReceiveDatagramChain,
    ULONG ReceiveDatagramCount,
    UCHAR TransportProtocol,
    PNET_BUFFER_LIST* RejectedNblHead,
    PNET_BUFFER_LIST* RejectedNblTail
    );

VOID
IppDeliverControlToProtocol(
    IN PIP_RECEIVE_DEMUX Demux,
    IN PNLC_RECEIVE_CONTROL_MESSAGE ControlMessage
    );

BOOLEAN
IppIsUdpEspPacket(
    IN PNET_BUFFER NetBuffer
    );

NL_PROVIDER_QUERY_ANCILLARY_DATA IpNlpQueryAncillaryData;

NL_PROVIDER_FILTER_DATAGRAM_BY_SESSION_INFORMATION
    IpNlpFilterDatagramBySessionInformation;

NL_PROVIDER_FILTER_INDICATION_BY_SESSION_INFORMATION
    IpNlpFilterIndicationBySessionInformation;

extern IP_RECEIVE_DEMUX IpAhDemux;
extern IP_RECEIVE_DEMUX IpEspDemux;
extern IP_RECEIVE_DEMUX IpUdpEspDemux;
extern CONST UCHAR Zero[];

NTSTATUS
IppPerformDeferredAhProcessing(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN PVOID Data,
    IN BOOLEAN FreeData,
    IN UINT8 ThisHeader,
    IN UINT8 NextHeader
    );

//
// Framing layer client routines. 
//
NTSTATUS
IppStartFlc(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopFlc(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppWaitFlc(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupFlc(
    IN PIP_PROTOCOL Protocol
    );

NPI_CLIENT_DETACH_PROVIDER_FN IpDetachFlProvider;
NPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN IpCleanupFlProviderContext;

VOID
IpDeregisterFlClientComplete(
    IN PVOID  ClientContext
    );

NTSTATUS
IppStartNsip(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopNsip(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppWaitNsip(
    IN PIP_PROTOCOL Protocol
    );

NPI_PROVIDER_ATTACH_CLIENT_FN IpAttachNsiClient;
NPI_PROVIDER_DETACH_CLIENT_FN IpDetachNsiClient;
NPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN IpCleanupNsiClientContext;

VOID
IpDeregisterNsiProviderComplete(
    IN PVOID  ProviderContext
    );

NTSTATUS
IppStartNsic(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopNsic(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppWaitNsic(
    IN PIP_PROTOCOL Protocol
    );

NPI_CLIENT_ATTACH_PROVIDER_FN IpAttachNaProvider;
NPI_CLIENT_DETACH_PROVIDER_FN IpDetachNaProvider;
NPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN IpCleanupNaProviderContext;

NTSTATUS
IppNetAllocate(
    OUT PNET_BUFFER_LIST *NetBufferList,
    OUT PUCHAR* FlatBuffer,
    IN ULONG Offset,
    IN ULONG Length
    );

#define NbAllocMem(Size, Pointer) ExAllocatePoolWithTagPriority( \
    NonPagedPool, (Size), (Pointer), LowPoolPriority)
#define NbFreeMem(Pointer) ExFreePool(Pointer)

#define INFINITE_LIFETIME NL_INFINITE_LIFETIME

UINT32
IppGetMillisecondsFromMidnight(
    VOID
    );

__inline
ULONG 
IppRemainingLifetime(
    IN ULONG Now, 
    IN ULONG LifetimeBaseTime, 
    IN ULONG Lifetime
    )
/*++

Routine Description:

    This routine returns the remaining lifetime given the current lifetime and
    the base time from which the current lifetime is calculated. 
    
Arguments:

    Now - Supplies the current tick.

    LifetimeBaseTime - Supplies the basetime from which the current lifetime
       starts. 

    Lifetime - Supplies the current lifetime.

Return Value:

    Returns the remaining lifetime.

--*/ 
{
    ULONG TicksSinceBaseLifetime;
    
    //
    // Must be careful of overflows in this computation.
    //          N    Now.
    //          V    Current Lifetime.
    //          NV   New (Remaining) Lifetime.
    //          C    LifetimeBaseTime.
    // Then NV =  V - (N - C). N - C does not overflow because the
    // tick count wraps. 
    //
    if (Lifetime != NL_INFINITE_LIFETIME) {
        TicksSinceBaseLifetime = Now - LifetimeBaseTime;
        if (TicksSinceBaseLifetime >= Lifetime) {
            return 0;
        } else {
            return (Lifetime - TicksSinceBaseLifetime);
        }
    } else {
        return NL_INFINITE_LIFETIME;
    }
}


__inline
VOID
IppRefreshAddressLifetimes(
    IN ULONG Now,
    IN PIP_LOCAL_UNICAST_ADDRESS Address
    )
/*++

Routine Description:

    This routine "refreshes" address lifetimes stored in an address.  The
    lifetimes stored in an address (ValidLifetime and PreferredLifetime) are
    w.r.t to LifetimeBaseTime.  So, for instance, the address expires at time
    (LifetimeBaseTime + ValidLifetime) ticks.  This routine sets the
    LifetimeBaseTime to the current time and appropriately updates the
    lifetimes. 

Arguments:

    Now - Supplies the current tick.

    Address - Supplies the address. 

Return Value:

    None.

--*/ 
{
    Address->PreferredLifetime = IppRemainingLifetime(
        Now, Address->LifetimeBaseTime, Address->PreferredLifetime);
    Address->ValidLifetime = IppRemainingLifetime(
        Now, Address->LifetimeBaseTime, Address->ValidLifetime);
    Address->LifetimeBaseTime = Now;
}


__inline
VOID
IppRefreshSitePrefixLifetime(
    IN ULONG Now,
    IN PIP_SITE_PREFIX_ENTRY SitePrefix
    )
/*++

Routine Description:

    This routine "refreshes" lifetime stored in a site prefix entry.  The
    lifetime stored in an entry is w.r.t to LifetimeBaseTime.  So, the entry
    expires at (LifetimeBaseTime + ValidLifetime) ticks.  This routine sets the 
    LifetimeBaseTime to the current time and appropriately updates the
    lifetime. 

Arguments:

    Now - Supplies the current tick.

    SitePrefix - Supplies the site prefix entry.

Return Value:

    None.

--*/ 
{
    SitePrefix->ValidLifetime = IppRemainingLifetime(
        Now, SitePrefix->LifetimeBaseTime, SitePrefix->ValidLifetime);
    SitePrefix->LifetimeBaseTime = Now;
}


#include "prefixpolicy.h"
#include "select.h"
#include "reassembly.h"
#include "protocol.h"
#include "control.h"

#define IS_IPV4_PROTOCOL(Protocol) ((Protocol) == &Ipv4Global)
#define IS_IPV6_PROTOCOL(Protocol) ((Protocol) == &Ipv6Global)

#define IS_LOOPBACK_INTERFACE(Interface) \
    ((Interface)->FlCharacteristics->InterfaceType == \
     IF_TYPE_SOFTWARE_LOOPBACK)

//
// Macro to determine if an IPv4 packet is a fragment.
//
#define IPV4_IS_FRAGMENT(IpHeader) \
    ((Ip4FragmentOffset(IpHeader) != 0) || IpHeader->MoreFragments)

#define IPV4_PATH_MTU_INCREASE_TIME  IppTimerTicks(2 * MINUTES)  // 2 minutes.
    
C_ASSERT(NlatAnycast > NlatUnspecified);
C_ASSERT(NlatAnycast > NlatUnicast);
C_ASSERT(NlatAnycast < NlatMulticast);
C_ASSERT(NlatAnycast < NlatBroadcast);
C_ASSERT(NlatAnycast < NlatInvalid);

__inline
BOOLEAN
IppIsInvalidSourceAddress(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *Address
    )
{
    //
    // Is this address illegal to use as a source address?
    // We currently flag multicast, broadcast, and invalid addresses.
    //
    // Note that this function doesn't flag anycast addresses.  Whether or not
    // to allow them to be valid source addresses has been a matter of some
    // debate in the working group.  We let them pass since we can't tell them
    // all by inspection and we don't see any real problems accepting them.
    //    
    return (Protocol->AddressType(Address) > NlatAnycast);
}

__inline
BOOLEAN
IppIsInvalidSourceAddressStrict(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *Address
    )
{
    NL_ADDRESS_TYPE AddressType = Protocol->AddressType(Address);

    //
    // Flag loopback, unspecified, multicast, broadcast, and invalid addresses.
    //
    return (INET_IS_ADDR_LOOPBACK(Protocol->Family, Address) || 
            (AddressType == NlatUnspecified) ||
            (AddressType > NlatUnicast));
}

#define IppIsInvalidSourceRouteDestinationAddress \
    IppIsInvalidSourceAddressStrict

__inline
NL_ADDRESS_TYPE
IppUpdateAddressTypeUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
/*++

Routine Description:

    Update the AddressType (as determined by parsing the address literal).

    Note that IPv4 subnet-broadcast addresses appear as unicast addresses,
    and hence we need to lookup the broadcast address table to confirm them.
    
Arguments:

    Interface - Supplies the interface over which the address lies.

    Address - Supplies the address literal.

    AddressType - Supplies the address type determined through address parsing.
    
Return Value:

    Returns the updated value of AddressType.
    
Locks:

    Assumes caller holds a read or write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/ 
{
    PIP_LOCAL_ADDRESS LocalAddress;
    
    ASSERT_ANY_LOCK_HELD(&Interface->Lock);    

    if (!IS_IPV4_PROTOCOL(Interface->Compartment->Protocol) ||
        (AddressType != NlatUnicast)) {
        return AddressType;
    }
    
    LocalAddress = 
        IppFindAddressOnInterfaceUnderLock(Interface, Address);
    if (LocalAddress != NULL) {
        AddressType = NL_ADDRESS_TYPE(LocalAddress);
        IppDereferenceLocalAddress(LocalAddress);
    }

    return AddressType;
}

__inline
NL_ADDRESS_TYPE
IppUpdateAddressTypeAtDpc(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    )
{
    DISPATCH_CODE();
    
    if (!IS_IPV4_PROTOCOL(Interface->Compartment->Protocol) ||
        (AddressType != NlatUnicast)) {
        return AddressType;
    }

    //
    // Lock the interface to get the type of the address. 
    //
    RtlAcquireReadLockAtDpcLevel(&Interface->Lock);

    AddressType =
        IppUpdateAddressTypeUnderLock(Interface, Address, AddressType);

    RtlReleaseReadLockFromDpcLevel(&Interface->Lock);
    
    return AddressType;
}

__inline
BOOLEAN
IppIsEphemeralAddressCandidate(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *Address
    )
{
    static IN_ADDR LoopbackBroadcast1 = {0x7f,}; 
    static IN_ADDR LoopbackBroadcast2 = {0x7f, 0xff, 0xff, 0xff};

    // 
    // Address may be UNALIGNED.
    //
    return 
        (IS_IPV4_PROTOCOL(Protocol) && 
         IN4_IS_UNALIGNED_ADDR_LOOPBACK((PIN_ADDR) Address) &&
         !IN4_UNALIGNED_ADDR_EQUAL((IN_ADDR *)Address, &in4addr_loopback) &&
         !IN4_UNALIGNED_ADDR_EQUAL((IN_ADDR *)Address, &LoopbackBroadcast1) &&
         !IN4_UNALIGNED_ADDR_EQUAL((IN_ADDR *)Address, &LoopbackBroadcast2));
}

__inline
VOID
IppDefaultStartRoutine(
    IN PIP_PROTOCOL Protocol,
    IN LONG ModuleId
    )
{
    IpngpReferenceDriver();
    InterlockedExchangeAdd(&Protocol->ModuleStatus, ModuleId);
}

__inline
NTSTATUS
IppDefaultStopRoutine(
    IN PIP_PROTOCOL Protocol
    )
{
    UNREFERENCED_PARAMETER(Protocol);
    IpngpDereferenceDriver();
    
    return STATUS_SUCCESS;
}

NETIO_INLINE
ULONG
IppGetInterfaceScopeZoneInline(
    IN CONST IP_INTERFACE *Interface,
    IN SCOPE_LEVEL Level
    )
/*++

Routine Description:
    
    Determine the zone id, for a given level, in which an interface
    resides. This function returns the internal scope zone. This is the inline
    version of the routine.
    
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
    if (Level <= ScopeLevelInterface) {
        return Interface->Index;
    }

    if (Level >= ScopeLevelGlobal) {
        //
        // Return the canonicalized scope id. 
        //
        return Interface->Compartment->CompartmentId;
    }

    return Interface->ZoneIndices[Level - ScopeLevelLink].Zone;
}

NETIO_INLINE
VOID
IppRefreshNeighbor(
    IN PIP_NEIGHBOR Neighbor
    )
/*++

Routine Description:

    Refresh a neighbor belonging to the neighbor set, thus ensuring
    that the LRU cache replacement algorithm picks it last.

Arguments:

    Protocol - Supplies the protocol to consider.

    Neighbor - Supplies a recently used neighbor.

Return Value:

    None.

Caller LOCK: None.

--*/
{
    //
    // Timestamp the neighbor.
    //
    Neighbor->LastUsed = IppTickCount;
}

NETIO_INLINE
BOOLEAN
IppDoesNeighborNeedResolution(
    IN PIP_NEIGHBOR Neighbor,
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
    
    This routines checks whether the neighbor is ready for use or needs to be
    resolved.  If it returns FALSE, then the neighbor can be used as is,
    otherwise IppResolveNeighbor has to be called.  This is the common lock
    free path for outgoing data packets.  Since these checks are made without
    holding the interface lock, there is a small possibility that the
    neighbor's state or datalink layer address might change from underneath us.
    The worst that can happen is that we'll send a packet somewhere strange.

Arguments:

    Neighbor - Supplies the neighbor to resolve.
    
    Interface - Supplies the interface.

Return Value:

    TRUE, if the packet can be sent.
    FALSE, otherwise.  The caller needs to call IppResolveNeighbor before
    sending the packet.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    switch (Neighbor->State) {
    case NlnsReachable:
        //
        // The following arithmetic correctly handles wraps of TickCount.
        //
        if (((ULONG) (IppTickCount - Neighbor->LastReachable)) >
            Interface->ReachableTicks) {
            //
            // It has been too long since the last reachability confirmation.
            // Return TRUE and resolve the neighbor normally.
            //
            return TRUE;
        }
        //
        // Fall through and send the packet.
        //

    case NlnsPermanent:
        //
        // The neighbor can be used as is.  Return FALSE. 
        //
        IppRefreshNeighbor(Neighbor);
        return FALSE;
    }

    //
    // The neighbor needs to be resolved. 
    //
   
    return TRUE;
}

NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllDbgPacketPatternParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllDbgInjectRawSendParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllDbgInjectReceiveParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllDbgInjectForwardParameters;

ULONG
IppGetAncillaryDataLength(
    IN PIP_PROTOCOL Protocol,
    IN PIP_SESSION_STATE State,
    IN PIP_REQUEST_CONTROL_DATA Control OPTIONAL
    );

NTSTATUS
IppInternalQueryAncillaryData(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_SESSION_STATE State,
    IN OUT PULONG BufferLength,
    OUT PUCHAR BufferPointer
    );

ULONG
Ipv6pFindPreviousNextHeaderOffset(
    IN PNET_BUFFER NetBuffer, 
    IN ULONG CurrentHeaderOffset
    );

VOID
IppRestructureHashTableUnderLock(
    PRTL_HASH_TABLE HashTable
    );

NETIO_INLINE
ULONG
IppComputeHashKeyFromAddress(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST UCHAR *DestinationAddress
    )
/*++

Routine Description:

    This is a  wrapper that uses a generic hash code 
    function to calculate the hash code for a single IP address in a
    protocol-agnostic manner.
    
Arguments:

    Compartment - Supplies the compartment.

    DestinationAddress - Supplies the destination address for which to find the
        bucket index. 

Return Value:

    Returns the index of the bucket that contains the entry for the given
    destination. 

--*/ 
{

    ULONG Key;

    Key = 
        RtlCompute37Hash(
            g_37HashSeed, 
            (CONST PCHAR) DestinationAddress, 
            Compartment->Protocol->Characteristics->AddressBytes);

    Key |= 0x80000000;

    return Key;
}

//
// Define a structure to store forward injection parameters in a per-processor 
// cache. The cache entry is only accessed at DISPATCH_LEVEL.
//
// Forward injection cache is used to improve performance on forward injection 
// path, particularly for the ISA NAT scenario. In that scenario, a 
// consecutive sequence of receive packets will be inspected by ISA and 
// in the same call context the ISA driver will forward inject those 
// packets into NL one by one. All these packets will have the same 
// forward injection parameters (compartment, interface, neighbor). 
// We will retrieve forward injection parameters for the first packet, cache 
// the parameters in the per-proc cache, and use them later for all subsequent 
// packets.
//
// The cache is cleared when the processing of one receive indication ends 
// or before a forward injection call returns (if it's not called in context 
// of a receive indication).
//
typedef struct _IP_FORWARD_INJECTION_CACHE_KEY {
    PIP_PROTOCOL Protocol;
    COMPARTMENT_ID CompartmentId;
    IF_INDEX InterfaceIndex;
    IP_ADDRESS_STORAGE Destination;    
} IP_FORWARD_INJECTION_CACHE_KEY, *PIP_FORWARD_INJECTION_CACHE_KEY;

typedef struct _IP_FORWARD_INJECTION_CACHE_VALUE {
    PIP_COMPARTMENT Compartment;
    PIP_INTERFACE Interface;
    PIP_SUBINTERFACE SubInterface;
    PIP_PATH Path;
    PIP_NEIGHBOR Neighbor;
} IP_FORWARD_INJECTION_CACHE_VALUE, *PIP_FORWARD_INJECTION_CACHE_VALUE;

typedef struct _IP_FORWARD_INJECTION_CACHE_ENTRY {
    BOOLEAN IsValid;
    IP_FORWARD_INJECTION_CACHE_KEY Key;
    IP_FORWARD_INJECTION_CACHE_VALUE Value;
} IP_FORWARD_INJECTION_CACHE_ENTRY, *PIP_FORWARD_INJECTION_CACHE_ENTRY;

typedef struct _IP_FORWARD_INJECTION_PER_PROCESSOR_STATE {
    IP_FORWARD_INJECTION_CACHE_ENTRY ForwardInjectionCache;
    IP_GENERIC_LIST Ipv4DelayQueue;    
    IP_GENERIC_LIST Ipv6DelayQueue;        
} IP_FORWARD_INJECTION_PER_PROCESSOR_STATE,
  *PIP_FORWARD_INJECTION_PER_PROCESSOR_STATE;

extern PIP_FORWARD_INJECTION_PER_PROCESSOR_STATE 
    ForwardInjectionPerProcessorState;

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
    );

VOID
IppDequeueForwardInjectedPacketsAtDpc(
    );

BOOLEAN
IppInReceiveIndication(
    );

//
// Computation routine and variable for memory limits of buffers. 
//
ULONG
IppDefaultMemoryLimit(
    VOID
    );

ULONG IppDefaultMemoryLimitOfBuffers;

NETIO_INLINE
NTSTATUS 
IppValidateRouteLookup(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Destination,
    IN OUT SCOPE_ID *DestinationScopeId,
    IN PIP_INTERFACE ConstrainInterface OPTIONAL,
    IN CONST IP_LOCAL_ADDRESS *ConstrainLocalAddress OPTIONAL
)
/*++

    This routine validates the parameters before performing a route lookup. 
    Validates destination and the constraints on the route lookup.

Arguments:
  
    Compartment - Supplies the compartment.

    Destination - Supplies the destination to route to. 

    DestinationScopeId - Supplies the scope ID of the destination.  The scope
        ID is assumed to be canonicalized. 

    ConstrainInterface - Optionally supplies the interface that should be used
        to reach the destination.

    ConstrainLocalAddress - Optionally supplies the source address that should
        be used to reach the destination.

Return Value:

    Return value must be an NTSTATUS code which matches a TDI status code.


--*/
{
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    NL_ADDRESS_TYPE AddressType;
    
    //
    // There is no need to lookup the route for the unspecified destination. 
    // 
    AddressType = Protocol->AddressType(Destination);
    if (AddressType == NlatUnspecified) {
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    
    ASSERT(IppIsScopeIdCanonicalized(Compartment, 
                                     Destination, 
                                     *DestinationScopeId));

    if (ConstrainLocalAddress != NULL) {
        if (NL_ADDRESS_TYPE(ConstrainLocalAddress) != NlatUnicast) {
            return STATUS_INVALID_ADDRESS_COMPONENT; 
        }
        if (ConstrainInterface == NULL) {
            ConstrainInterface = ConstrainLocalAddress->Interface;
        } else if (ConstrainInterface != ConstrainLocalAddress->Interface) {
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }
    }

    if (ConstrainInterface != NULL) {
        ULONG DestZone;

        //
        // Our caller is constraining the originating interface.
        //

        //
        // First, check this against ScopeId.
        //
        DestZone =
            IppGetInterfaceScopeZone(
                ConstrainInterface, 
                DestinationScopeId->Level);
        if (DestinationScopeId->Zone == 0) {
            DestinationScopeId->Zone = DestZone;
        } else if (DestinationScopeId->Zone != DestZone) {
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }
    }
    return STATUS_SUCCESS;
}

#endif // _IPNGP_
