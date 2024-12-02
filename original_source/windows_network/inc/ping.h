/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    ping.h

Abstract:

    This module contains declarations for the network layer module's
    icmp code.

Author:

    Stephanie Song (weiyings) 14-May-2003

Environment:

    Kernel mode only.

--*/

#ifndef _PING_
#define _PING_

#pragma once


#define IP_ECHO_REQUEST_TABLE_SIZE            7
#define IP_ECHO_REQUEST_TIMER_TABLE_SIZE      8

#define IP_ECHO_REQUEST_MIN_SEQUENCE 0x10000

PREFERENCE_HISTORY IppEchoRequestReferenceHistory;

    
typedef struct _IP_ECHO_REQUEST_TIMEOUT_TABLE {
    KDPC Dpc;
    KTIMER Timer;
    LONG LastTick;   
} IP_ECHO_REQUEST_TIMER_CONTEXT, *PIP_ECHO_REQUEST_TIMER_CONTEXT;


typedef struct _IP_ECHO_REQUEST_CONTEXT {
    KSPIN_LOCK Lock;
    ULONG ReferenceCount;
    
    LIST_ENTRY Link;
    RTL_TIMER_WHEEL_ENTRY TimerEntry;

    PIP_PROTOCOL Protocol;
    ULONG Sequence; // Identifies the echo request.
    struct {
        ULONG RequestCompleted : 1;
        ULONG ClientNotified : 1;
        ULONG Deleted : 1;
        ULONG InTable: 1;
    };

    PMDL ReplyMdl; // Locked output buffer.
    LARGE_INTEGER StartTime; // Used for timer expiration.
    
    NL_ECHO_REQUEST_KEY Key;
} IP_ECHO_REQUEST_CONTEXT, *PIP_ECHO_REQUEST_CONTEXT;


#if ECHO_REFHIST

VOID
IppCleanupEchoRequest(
    PIP_ECHO_REQUEST_CONTEXT EchoRequest
    );

DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_ECHO_REQUEST_CONTEXT, EchoRequest, Ipp, IppEchoRequestReferenceHistory)
#define IppDereferenceEchoRequest(Request) \
    _IppDereferenceEchoRequest((Request), __LINE__, __FILE__)
#define IppReferenceEchoRequest(Request) \
    _IppReferenceEchoRequest((Request), __LINE__, __FILE__)
#else // ECHO_REFHIST
    
__inline
VOID
IppReferenceEchoRequest(
    PIP_ECHO_REQUEST_CONTEXT Request
    )
{
    InterlockedIncrement(&Request->ReferenceCount);
}

VOID
IppDereferenceEchoRequest(
    PIP_ECHO_REQUEST_CONTEXT Request
    );

#endif // ECHO_REFHIST


NTSTATUS
IppStartEchoRequestManager(
    PIP_PROTOCOL Protocol
    );

NTSTATUS
IppCleanupEchoRequestManager(
    PIP_PROTOCOL Protocol
    );

NTSTATUS
NTAPI
IppGetAllEchoSequenceRequestParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    );

VOID
IppEchoRequestSetTimeout(
    PIP_PROTOCOL Protocol
    );


NM_PROVIDER_REGISTER_CHANGE_NOTIFICATION IpRegisterEchoRequestChangeNotification;
NM_PROVIDER_DEREGISTER_CHANGE_NOTIFICATION IpDeregisterEchoRequestChangeNotification;


VOID
IppEchoRequestTimeoutTimerElement(
    PVOID ClientContext,
    PRTL_TIMER_WHEEL_ENTRY TwTimerElement,
    ULONG TwExpiredTimers
    );

VOID
Ipv6EchoRequestTimeoutTimerElement(
    PVOID ClientContext,
    PRTL_TIMER_WHEEL_ENTRY TwTimerElement,
    ULONG TwExpiredTimers
    );

__inline
PIP_ECHO_REQUEST_CONTEXT
IppFindEchoRequestForReply(
    PLIST_ENTRY EchoRequestTable,
    ULONG EchoRequestTableSize,
    ULONG SequenceNumber
    )
/*++

Routine Description:

    Given an ICMP echo reply packet, use the sequence number in the packet to
    find the matching request context.

Arguments:

    EchoRequestTable - Supplies the table in which to find the echo request.
    
    EchoRequestTableSize - Supplies the number of slots in the table.

    SequenceNumber - Supplies the sequence number to match.

Return Value:

    The matching request context or NULL if not found.

Locks:

    The user must be holding the lock for modifying table linkage.

--*/
{
    ULONG Counter;
    PIP_ECHO_REQUEST_CONTEXT Request;
    PLIST_ENTRY List;
    
    for (Counter = 0; Counter < EchoRequestTableSize; Counter++) {
        List = EchoRequestTable[Counter].Flink;

        while (List != &EchoRequestTable[Counter]) {
            Request = (PIP_ECHO_REQUEST_CONTEXT)
                CONTAINING_RECORD(List, IP_ECHO_REQUEST_CONTEXT, Link);
            if (Request->Sequence == SequenceNumber &&
                !Request->RequestCompleted) {
                return Request;
            }
            List = List->Flink;
        }
    }
    return NULL;
}

__inline
PIP_ECHO_REQUEST_CONTEXT
IppFindEchoRequest(
    PLIST_ENTRY EchoRequestTable,
    ULONG EchoRequestTableSize,
    PNL_ECHO_REQUEST_KEY Key
    )
/*++

Routine Description:

    Given a key provided by NSI clients, find the matching request context.

Arguments:

    EchoRequestTable - Supplies the table in which to find the echo request.

    EchoRequestTableSize - Supplies the number of slots in the table.

    Key - The key to match.

Return Value:

    The matching request context or NULL if not found.

Locks:

    The user must be holding the lock for modifying table linkage.

--*/
{
    ULONG TableSlot;
    PIP_ECHO_REQUEST_CONTEXT Request;
    PLIST_ENTRY Entry, List;

    //
    // First locate the table slot the request is in.
    //
    TableSlot = (((ULONG) (ULONG_PTR) Key->RequestHandle) ^
                 Key->ClientPid) % EchoRequestTableSize;
    List = EchoRequestTable + TableSlot;

    Entry = List->Flink;
    
    while (Entry != List) {
        Request = (PIP_ECHO_REQUEST_CONTEXT)
            CONTAINING_RECORD(Entry, IP_ECHO_REQUEST_CONTEXT, Link);
        if (RtlEqualMemory(Key, &Request->Key, sizeof(*Key))) {
            return Request;
        }
        
        Entry = Entry->Flink;
    }
    
    return NULL;
}


__inline
VOID
IppInsertEchoRequest(
    PLIST_ENTRY EchoRequestTable,
    ULONG EchoRequestTableSize,
    PIP_ECHO_REQUEST_CONTEXT Context
    )
/*++

Routine Description:

    Inserts an echo request context into the table supplied.

Arguments:

    EchoRequestTable - Supplies the table in which to insert the request.

    EchoRequestTableSize - Supplies the number of slots in the table.

    Context - Supplies the entry to insert into the table.

Return Value:

    None

Locks:

    The user must be holding the lock for modifying table linkage.

--*/
{
    ULONG TableSlot;
    PLIST_ENTRY List;
    
    //
    // Find the slot and insert.
    //
    TableSlot = (((ULONG) (ULONG_PTR) Context->Key.RequestHandle) ^
                 Context->Key.ClientPid) % EchoRequestTableSize;
    List = EchoRequestTable + TableSlot;

    InsertHeadList(List, &Context->Link);
    Context->InTable = TRUE;
}

__inline
VOID
IppRemoveEchoRequest(
    PIP_ECHO_REQUEST_CONTEXT Context
    )
/*++

Routine Description:

    Removes an echo request context from its table.
    
Arguments:
    
    Context - Supplies the entry to remove.

Return Value:

    None

Locks:

    The user must be holding the lock for modifying table linkage.

--*/
{
    if (Context->InTable) {
        RemoveEntryList(&Context->Link);
        Context->InTable = FALSE;
    }
}

PNET_BUFFER_LIST
IppAllocateNetBufferListForEcho(
    ULONG AllocationSize,
    PNETIO_NET_BUFFER_LIST_COMPLETION_ROUTINE CompletionRoutine,
    PVOID CompletionContext
    );

VOID
IppFreeNetBufferListForEcho(
    PNET_BUFFER_LIST NetBufferList,
    BOOLEAN DispatchLevel
    );

NTSTATUS
IppNotifyEchoRequestChange(
    PIP_ECHO_REQUEST_CONTEXT EchoRequest,
    PIP_PROTOCOL Protocol
    );

VOID
IppNotificationTimeoutRoutine(
    KSPIN_LOCK * TableLock,
    PLIST_ENTRY Table,
    ULONG TableSize,
    BOOLEAN ShutdownEventSet,
    KEVENT * ShutdownEvent,
    PULONG NotificationCounter
    );

#endif // _PING_
