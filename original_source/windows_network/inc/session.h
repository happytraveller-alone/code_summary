/*++

Copyright (c) 2005-2006  Microsoft Corporation

Module Name:

    session.h

Abstract:

    This module contains definitions for session state management.

Author:

    Mohit Talwar (mohitt) Wed Jul 27 12:31:12 2005

Environment:

    Kernel mode only.

--*/

#ifndef _SESSION_
#define _SESSION_

#pragma once


//
// IP_INTERFACE_LIST
//
// Define a structure to represent a list of interface indicies.
//

typedef struct _IP_INTERFACE_LIST {
    ULONG Count;
    IF_INDEX Index[0];
} IP_INTERFACE_LIST, *PIP_INTERFACE_LIST;
#define SIZEOF_IP_INTERFACE_LIST(Count) \
    FIELD_OFFSET(IP_INTERFACE_LIST, Index[Count])


//
// IP_SESSION_STATE
//
// Define a structure for the session state.
//

typedef union _IP_SESSION_FLAGS {
    struct {
        BOOLEAN HeaderInclude : 1;
        BOOLEAN MulticastLoopback : 1;
        BOOLEAN DontFragment : 1;
        BOOLEAN ReceivePacketInfo : 1;
        BOOLEAN ReceiveHopLimit : 1;
        BOOLEAN ReceiveInterface : 1;
        BOOLEAN ReceiveDestination : 1;
        BOOLEAN ReceiveBroadcast : 1;
        BOOLEAN TcpOptions : 1;
        BOOLEAN UseIpSec : 1;
        BOOLEAN ReceiveRoutingHeader : 1;        
        BOOLEAN DontFragmentSet : 1;        
        BOOLEAN FastPathCompatible : 1;    
    };
    ULONG Flags;
} IP_SESSION_FLAGS;

typedef struct _IP_SESSION_STATE {
    PIP_INTERFACE_LIST InterfaceList;
    PIP_INTERFACE MulticastInterface;
    PIP_INTERFACE UnicastInterface;
    PIP_INTERFACE PromiscuousInterface;
    PIP_INTERFACE AllMulticastInterface;
    SHORT MulticastHopLimit;    // Aka TTL.
    SHORT UnicastHopLimit;      // Aka TTL.

    IP_SESSION_FLAGS;

    UINT8 ProtectionLevel;
    UINT8 TypeOfService;
    UCHAR PromiscuousMode;      // See RCVALL_VALUE for values.
    UCHAR AllMulticastMode;     // See RCVALL_VALUE for values.

    //
    // Hop-by-hop options.
    //
    USHORT HopByHopOptionsLength;
    __field_ecount(HopByHopOptionsLength)
    PVOID HopByHopOptions;
    USHORT FirstHopOffset;      // Offset of first hop address, or 0 if none.

    //
    // Routing header.
    //
    USHORT RoutingHeaderLength;
    __field_ecount(RoutingHeaderLength)
    PVOID RoutingHeader;

    //
    // Multicast state information. 
    //
    LIST_ENTRY MulticastState;

    //
    // Multicast Interface Option value specified. This is only for appcompat.
    //
    UINT MulticastInterfaceOption;

    //
    // This lock protects the fields above.
    // REVIEW: Should we use a reader-writer lock here?
    //
    KSPIN_LOCK SpinLock;
} IP_SESSION_STATE, *PIP_SESSION_STATE;

#define IS_SESSION_STATE_FAST_PATH_COMPATIBLE(Protocol, State) \
    ((Protocol == IPPROTO_TCP) && \
     !(State)->MulticastInterface && \
     !(State)->PromiscuousInterface && \
     !(State)->AllMulticastInterface && \
     !(State)->HopByHopOptions && \
     !(State)->RoutingHeader && \
     IsListEmpty(&(State)->MulticastState) && \
     ((State)->HeaderInclude == FALSE) && \
     ((State)->TcpOptions == FALSE) && \
     ((State)->UseIpSec == FALSE) && \
     ((State)->MulticastHopLimit == IP_UNSPECIFIED_HOP_LIMIT))

//
// IP_SESSION_MULTICAST_STATE
//
// Define a structure for the multicast group session state.
//

typedef struct _IP_SESSION_MULTICAST_SOURCE {
    LIST_ENTRY Link;
} IP_SESSION_MULTICAST_SOURCE, *PIP_SESSION_MULTICAST_SOURCE;

#define IP_SESSION_MULTICAST_SOURCE_ADDRESS(Source) \
    (((PUCHAR)(Source)) + sizeof(IP_SESSION_MULTICAST_SOURCE))

typedef struct _IP_SESSION_MULTICAST_STATE {
    LIST_ENTRY Link;

    PIP_SESSION_STATE Session;

    //
    // Mode of the session (MCAST_INCLUDE or MCAST_EXCLUDE). 
    //
    MULTICAST_MODE_TYPE Mode;

    //
    // Source list (include or exclude depending on the mode).
    //
    LIST_ENTRY SourceList;

    //
    // Number of sources in the source list. 
    //
    ULONG SourceCount;
    
    //
    // Referenced pointer to the local multicast address entry.
    //
    PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup;
} IP_SESSION_MULTICAST_STATE, *PIP_SESSION_MULTICAST_STATE;


//
// IP_SET_SESSION_INFO_CONTEXT
//
// Define a structure used with outstanding set session information requests.
//

typedef struct _IP_SET_SESSION_INFO_CONTEXT {
    //
    // Used only with multicast group adds.
    //
    struct _IP_SESSION_MULTICAST_STATE *SessionGroup;

    PVOID CompletionContext;
    PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine;
} IP_SET_SESSION_INFO_CONTEXT, *PIP_SET_SESSION_INFO_CONTEXT;
        

//
// Pool handles for session state and multicast session state. 
//

extern HANDLE SessionStatePool;
extern HANDLE MulticastSessionStatePool;


//
// Session state used by IppSendDirect.
//

extern IP_SESSION_STATE IppSendDirectSessionState;


//
// NPI functions.
//

NL_PROVIDER_INITIALIZE_SESSION_INFO IpNlpInitializeSessionInfo;
NL_PROVIDER_QUERY_SESSION_INFO IpNlpQuerySessionInfo;
NL_PROVIDER_SET_SESSION_INFO IpNlpSetSessionInfo;
NL_PROVIDER_CLEANUP_SESSION_INFO IpNlpCleanupSessionInfo;
NL_PROVIDER_INHERIT_SESSION_INFO IpNlpInheritSessionInfo;


//
// Session Manager functions.
//

NTSTATUS
IppStartSessionManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupSessionManager(
    IN PIP_PROTOCOL Protocol
    );


//
// Helper functions.
//

VOID
IppInitializeSessionState(
    OUT PIP_SESSION_STATE State
    );

VOID
IppUninitializeSessionState(
    IN PIP_SESSION_STATE State
    );

PIP_SESSION_MULTICAST_STATE
IppFindMulticastSessionState(
    IN PIP_SESSION_STATE State,
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *MulticastAddress,
    IN CONST IF_INDEX InterfaceIndex
    );

NTSTATUS
IppCreateMulticastSessionState(
    IN HANDLE InspectHandle,
    IN PIP_SESSION_STATE State,
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *MulticastAddress,
    IN CONST IF_INDEX InterfaceIndex,    
    IN MULTICAST_MODE_TYPE FilterMode, 
    IN ULONG SourceCount,
    IN CONST UCHAR *SourceList,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    );

NTSTATUS
IppCreateMulticastSessionStateComplete(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    IN NTSTATUS Status
    );

NTSTATUS
IppSetMulticastSessionState(
    IN HANDLE InspectHandle,
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    IN MULTICAST_MODE_TYPE Mode, 
    IN ULONG SourceCount,
    IN CONST UCHAR *SourceList
    );

NTSTATUS
IppModifyMulticastSessionState(
    IN HANDLE InspectHandle,
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    IN ULONG DeleteCount,
    IN CONST UCHAR *DeleteList,
    IN MULTICAST_MODE_TYPE NewMode, 
    IN ULONG AddCount,
    IN CONST UCHAR *AddList
    );

VOID
IppGetMulticastSessionStateSourceList(
    IN PIP_SESSION_MULTICAST_STATE MulticastState,
    OUT PUCHAR List
    );

BOOLEAN
IppDoesSessionStateIncludeGroupAndSource(
    IN PIP_SESSION_STATE State,
    IN PIP_LOCAL_MULTICAST_ADDRESS Group,
    IN CONST UCHAR *SourceAddress
    );

#endif // _SESSION_
