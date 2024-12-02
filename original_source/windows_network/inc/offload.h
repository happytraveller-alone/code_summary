/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    offload.h

Abstract:

    This module contains declarations for the network layer module's
    offload management.

Author:

    Mohit Talwar (mohitt) Tue Nov 19 10:01:25 2002

Environment:

    Kernel mode only.

--*/

#ifndef _OFFLOAD_
#define _OFFLOAD_

#pragma once

//
// IP_OFFLOAD_STATE
//
// Enumerate offload states.
//

typedef enum {
    NotOffloaded = 0,
    OffloadInProgress,
    Offloaded,
    TerminateInProgress,
    UpdateInProgress,
    UpdateBlocked,
    InvalidateInProgress,
    OffloadInvalid,
    NumStates
} IP_OFFLOAD_STATE, *PIP_OFFLOAD_STATE;

#define IP_OFFLOAD_STATE_BITS 3

C_ASSERT(NumStates <= (1 << IP_OFFLOAD_STATE_BITS));

#define IP_OFFLOAD_REFERENCE (1 << (IP_OFFLOAD_STATE_BITS + 1))


//
// IP_OFFLOAD_OBJECT
//
// Define the structure of an offload object.
//

typedef union _IP_OFFLOAD_OBJECT {
    struct {
        //
        // Least significant bits.
        //
        ULONG State : IP_OFFLOAD_STATE_BITS;
        ULONG Dirty : 1;

        //
        // Counts the number of entries at the next higher layer
        // that are desired to be offloaded.
        //
        ULONG Count : (RTL_BITS_OF(LONG) - 2 - IP_OFFLOAD_STATE_BITS);

        //
        // Most significant bit, used to check for Count overflow.
        //
        ULONG Overflow : 1;
    };
    LONG Value;
} IP_OFFLOAD_OBJECT, *PIP_OFFLOAD_OBJECT;

//
// Ensure that interlocked operations are valid on the entire object above.
//
C_ASSERT(sizeof(IP_OFFLOAD_OBJECT) == sizeof(ULONG));


// #define _IP_OFFLOAD_LOGGING 1

//
// Extra logging to debug NL offload issues, disabled
// on both checked and free builds by default.
//
#ifdef _IP_OFFLOAD_LOGGING

#define IP_OFFLOAD_EVENTLOG_SIZE 64


typedef enum _IP_OFFLOAD_EVENT_TYPE {
    IpoeQueueForDowncall = 1,
    IpoeTransitionToInProgress,
    IpoePendOffloadRequest,
    IpoeInitiateProcessPendingList,
    IpoeProcessPendingRequests,
    IpoeNoPendingRequest,
    IpoeInitiateOffloadResources,
    IpoeTransitionFromInProgress,
    IpoeStartTerminate,
    IpoeInvokeUpperCompletion,
    IpoeSaveInitiateBlock,
    IpoeDowncallForPendedRequest,
    IpoePendedRequestFailure,
    IpoeInsertPlaceHolder,
    IpoeInvalidNeighborState,
    IpoeAddInitiateReference,
    IpoeOffloadComplete,
    IpoeInitiateOffloadFailure
} IP_OFFLOAD_EVENT_TYPE;


typedef struct _IP_OFFLOAD_EVENT {
    IP_OFFLOAD_EVENT_TYPE Event;   // Caller should make sure these are unique.
    PVOID Path;
    PVOID Neighbor;
    PVOID Block;
} IP_OFFLOAD_EVENT, *PIP_OFFLOAD_EVENT;

typedef struct _IP_OFFLOAD_LOG {
  IP_OFFLOAD_EVENT Events[IP_OFFLOAD_EVENTLOG_SIZE];
  ULONG Index;
} IP_OFFLOAD_LOG, *PIP_OFFLOAD_LOG;

#define IP_OFFLOAD_LOG_EVENT(_E, _O, _P, _N, _B) \
    if (_O->OffloadLog == NULL) { \
        PIP_OFFLOAD_LOG TempLog = \
            (PIP_OFFLOAD_LOG) ExAllocatePoolWithTag( \
                NonPagedPool, sizeof(IP_OFFLOAD_LOG), IpOffloadLogPoolTag); \
        if (InterlockedCompareExchangePointer( \
                &_O->OffloadLog, TempLog, NULL) != NULL) { \
            ExFreePoolWithTag(TempLog, IpOffloadLogPoolTag); \
        } \
    } \
    if (_O->OffloadLog != NULL) { \
        ULONG Index = InterlockedIncrement(&((_O)->OffloadLog->Index)) - 1; \
        Index %= IP_OFFLOAD_EVENTLOG_SIZE; \
        (_O)->OffloadLog->Events[Index].Event = _E; \
        (_O)->OffloadLog->Events[Index].Path = _P; \
        (_O)->OffloadLog->Events[Index].Neighbor = _N; \
        (_O)->OffloadLog->Events[Index].Block = _B; \
    }
#else
#define IP_OFFLOAD_LOG_EVENT(_E, _O, _P, _N, _B)
#endif // _IP_OFFLOAD_LOGGING


VOID
IppSetDependentBlockStatus(
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST BlockList,
    IN NTSTATUS Status
    );

#endif // _OFFLOAD_


