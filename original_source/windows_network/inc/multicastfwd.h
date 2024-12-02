/*++

Copyright (c) 2002-2005  Microsoft Corporation

Module Name:

    multicastfwd.h

Abstract:

    This module contains declarations for the network layer module's
    multicast forwarding.

Environment:

    Kernel mode only.

--*/

#ifndef _MULTICASTFWD_
#define _MULTICASTFWD_

#pragma once


typedef enum {
    MF_FORWARD = 0,
    MF_QUEUE,
    MF_DROP
} MFE_STATE;

//
// The information for each outgoing interface.
//

typedef struct _IP_MFE_NEXT_HOP
{
    LIST_ENTRY Link;    
    PIP_NEIGHBOR CurrentNextHop; 
    ULONG OutPackets;           // Statistics kept for this next hop.
} IP_MFE_NEXT_HOP, *PIP_MFE_NEXT_HOP;

//
// Multicast Forwarding Entry (Mfe). 
//
typedef struct _IP_MFE {
    LIST_ENTRY HashLink;
    
    LONG ReferenceCount;

    UCHAR* GroupAddress;
    UCHAR* SourceAddress;
    
    IF_INDEX IncomingInterfaceIndex;
    PIP_COMPARTMENT Compartment;
    SCOPE_ID Scope;

    //
    // Action to take (forward, queue, drop).
    //
    MFE_STATE State;
    
    TIMER_ENTRY TimerEntry;
    ULONG TimeOut;

    //
    // This corresponds to the number of outgoing interfaces.
    //
    ULONG NumberOfNextHops;    
    LIST_ENTRY NextHopList;
    
    //
    // Queued Packets.
    //
    ULONG NumberOfPendingPackets;
    IP_GENERIC_LIST PendingPackets;
    ULONG SizeOfPendingPackets;
        
    //
    // Statistics for this entry.
    //
    ULONG InPackets;
    ULONG64 InOctets;
    ULONG DifferentInInterfacePackets;    
} IP_MFE, *PIP_MFE;

typedef struct _NL_MFE_NOTIFICATION_ROD {
    NL_MFE_NOTIFICATION_TYPE NotificationType;

    union {
        NL_MFE_PACKET_NOTIFICATION Packet;
        struct {
            ULONG NumberOfMfes;
            UCHAR MfeKey[1];
        }; 
    };
} NL_MFE_NOTIFICATION_ROD, *PNL_MFE_NOTIFICATION_ROD;

//
// Mfes are stored in a hash table.
//
typedef IP_HT_ENTRY IP_MFE_HASH_BUCKET, *PIP_MFE_HASH_BUCKET;

//
// Hash table lock protects the timer table as well.
//
typedef struct _IP_MFE_LOCKED_SET {
    LOCKED_HASH_TABLE;
    PTIMER_TABLE TimerTable;
    ULONG TotalLimitOfQueuedPackets;
    ULONG TotalSizeOfQueuedPackets; 
} IP_MFE_LOCKED_SET, *PIP_MFE_LOCKED_SET;

#define IP_MFE_TIMER_TABLE_SLOTS 128
#define DEFAULT_LIFETIME 180000 // 3 minutes in millisecs. 

//
// The number of packets pending per (S,G) entry when queuing is being done.
//
#define MAX_MFE_QUEUED_PACKETS 4

NTSTATUS
IppInitializeMfeSet(
    PIP_MFE_LOCKED_SET *Set
    );

VOID
IppUninitializeMfeSet(
    PIP_MFE_LOCKED_SET Set
    ); 

BOOLEAN
IppIsMfeSetMemoryQuotaExceeded(
    IN PIP_MFE_LOCKED_SET MfeSet
    );

// 
// Mfe Management Routines.
//
VOID 
IppCleanupMfe(
    IN PIP_MFE Mfe
    );

VOID 
IppDeleteMfeSetUnderLock(
    PIP_COMPARTMENT Compartment
    );

VOID 
IppDeleteMfes(
    PIP_COMPARTMENT Compartment,
    PIP_INTERFACE Interface,
    PIP_SUBINTERFACE SubInterface
    ); 
    
#if MFE_REFHIST
extern PREFERENCE_HISTORY IppMfeReferenceHistory;
DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_MFE, Mfe, Ipp, IppMfeReferenceHistory)
#define IppDereferenceMfe(Mfe) \
    _IppDereferenceMfe((Mfe), __LINE__, __FILE__)
#define IppReferenceMfe(Mfe) \
    _IppReferenceMfe((Mfe), __LINE__, __FILE__)
#define IppReferenceMfeEx(Mfe, Count) \
    _IppReferenceMfeEx((Mfe), Count, __LINE__, __FILE__)
#else  // MFE_REFHIST
DEFINE_REFERENCE_ROUTINES(PIP_MFE, Mfe, Ipp)
#endif // MFE_REFHIST

#define IsListEntry(link) (!IsListEmpty(link))
#define InitializeListEntry(link) InitializeListHead(link)

BOOLEAN
IppForwardMulticastPackets(
    IN PIP_INTERFACE ArrivalInterface, 
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_GENERIC_LIST RemoteArgs
    );

NTSTATUS
NTAPI
IppGetAllMulticastForwardingParameters(
    IN PIP_PROTOCOL Protocol,
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    );

VOID
IppMfeSetTimeOut(
    PIP_COMPARTMENT Compartment
    );

NTSTATUS
NTAPI
IppSetAllMulticastForwardingParameters(
    IN NSI_SET_ACTION Action,
    IN NSI_TRANSACTION Transaction,
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId,
    IN CONST UCHAR *Group,
    IN CONST UCHAR *SourcePrefix,
    IN ULONG SourcePrefixLength,
    IN PNL_MFE_RW Rw,
    OUT PVOID *ProviderTransactionContext
    );

NTSTATUS
IppNotifyMfeChange(
    PIP_PROTOCOL Protocol,
    NL_MFE_NOTIFICATION_TYPE NotificationType,
    PIP_REQUEST_CONTROL_DATA Control OPTIONAL,
    PIP_INTERFACE ArrivalInterface OPTIONAL,
    PIP_SUBINTERFACE ArrivalSubInterface OPTIONAL,
    ULONG NumExpiredMfes OPTIONAL,
    PIP_MFE *ExpiredMfes OPTIONAL
    );

NM_PROVIDER_REGISTER_CHANGE_NOTIFICATION 
    IpRegisterMulticastForwardingChangeNotification;
NM_PROVIDER_DEREGISTER_CHANGE_NOTIFICATION
    IpDeregisterMulticastForwardingChangeNotification;

#endif // _MULTICASTFWD_
