/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    multicast.h

Abstract:

    This module contains declarations for the network layer module's
    multicast address management.

Author:

    Amit Aggarwal (amitag)

Environment:

    Kernel mode only.

--*/

#ifndef _MULTICAST_ADDRESS_
#define _MULTICAST_ADDRESS_

#pragma once

#include "address.h"

#define DEFAULT_MULTICAST_DISCOVERY_ROBUSTNESS 2
#define DEFAULT_MULTICAST_DISCOVERY_QUERY_INTERVAL 125000 // 125s (RFC 3376).

//
// We define an upper limit on the number of sources per multicast group in
// order to prevent overflow in arithmetic operations related to the source
// count. 
// (1) Multicast report size is : Protocol->MulticastRecordHeaderSize +
// Protocol->MulticastReportHeaderSize + SourceCount * AddressBytes. 
// (2) Multicast record entry size is: sizeof(IP_MULTICAST_RECORD_ENTRY) +
// SourceCount * AddressBytes. 
// (3) IP_MSFILTER_SIZE: sizeof(IP_MSFILTER) + NumSources * sizeof(IN_ADDR). 
// (4) GROUP_FILTER_SIZE: sizeof(GROUP_FILTER) + NumSources * sizeof(struct
// sockaddr_storage). 
// So the maximum size for all the source addresses is approximately: 
// MAXULONG - MAX(sizeof(IP_MSFILTER), sizeof(GROUP_FILTER), ...)
// ~ MAXULONG - sizeof(GROUP_FILTER)
// So, the maximum source count is: (MAXULONG -
// sizeof(GROUP_FILTER))/sizeof(struct sockaddr_storage) 
//
#define MAX_MULTICAST_SOURCE_COUNT \
    ((MAXULONG - (sizeof(GROUP_FILTER)))/ sizeof(struct sockaddr_storage))

//
// If the Multicast group already has
// MAX_MULTICAST_SOURCES_CREATED_FOR_QUERY number of sources
// marked to be reported in the next Report then 
// we return with STATUS_INSUFFICIENT_RESOURCES. We are using 
// the upper limit at this place as sources can be added repeatedly by an 
// attacker using Query messages. RFC 3376 sec 9.1/RFC 3810 sec 10.1.
//
#define MAX_MULTICAST_SOURCES_CREATED_FOR_QUERY 1000

//
// Version of the multicast discovery algorithm. Version 1 corresponds to
// IGMPv1, version 2 to IGMPv2 and MLD and version 3 to IGMPv3 and MLDv2. 
//
typedef enum {
    MULTICAST_DISCOVERY_VERSION1 = 1, 
    MULTICAST_DISCOVERY_VERSION2,
    MULTICAST_DISCOVERY_VERSION3
} MULTICAST_DISCOVERY_VERSION;

//
// Type of the report being sent to the multicast router. The first six types
// (MODE_IS_INCLUDE to BLOCK_OLD_SOURCES) have the same value as the actual
// report type field on the IGMP/MLD messages. The last two (JOIN_GROUP and
// LEAVE_GROUP) are defined here only for internal use. 
//
typedef enum {
    MODE_IS_INCLUDE = 1,
    MODE_IS_EXCLUDE,
    CHANGE_TO_INCLUDE_MODE,
    CHANGE_TO_EXCLUDE_MODE,
    ALLOW_NEW_SOURCES,
    BLOCK_OLD_SOURCES,
    JOIN_GROUP,
    LEAVE_GROUP
} MULTICAST_RECORD_TYPE;

typedef struct _IP_LOCAL_MULTICAST_SOURCE {
    LIST_ENTRY Link;

    //
    // The number of sessions including/excluding this source. These counts are
    // used to determine if a source should be allowed or blocked. For
    // instance, if the include count is non-zero, the source should be
    // allowed. 
    //
    ULONG IncludeCount;
    ULONG ExcludeCount;
    
    //
    // Number of transmissions left indicating state change for this source
    // (from allowed to blocked or vice versa).
    //
    ULONG TransmitsLeft;

    //
    // Whether the source is marked for the next response to a query. 
    //
    BOOLEAN MarkedForQuery;

    // 
    // Whether the source is in the overall State that is reported.
    //
    BOOLEAN MemberOfState;
} IP_LOCAL_MULTICAST_SOURCE, *PIP_LOCAL_MULTICAST_SOURCE;

#define IP_LOCAL_MULTICAST_SOURCE_ADDRESS(Source) \
    (((PUCHAR)(Source)) + sizeof(IP_LOCAL_MULTICAST_SOURCE))

typedef struct _IP_LOCAL_MULTICAST_ADDRESS {
    IP_LOCAL_ADDRESS;

    //
    // List of sources. 
    //
    LIST_ENTRY SourceList;
    
    //
    // Number of sessions in exclude mode. If any session is in exclude mode,
    // the whole group is in exclude mode as well. Otherwise, it is in include
    // mode. 
    // 
    ULONG ExcludeCount;
    
    union {
        //
        // MULTICAST_DISCOVERY_VERSION3.
        //
        struct {
            //
            // Number of transmissions remaining for a mode change
            // message. This count is only relevant for messages indicating a
            // change of mode from include to exclude or vice versa. For
            // changes in the source list, each source has a count of
            // transmissions left.
            //
            ULONG ModeChangeTransmitsLeft;
            
            //
            // Maximum number of transmits left for any source in this group or
            // the group itself. This is used to determine if a timer needs to
            // be scheduled for the group.
            //
            ULONG MaximumTransmitsLeft;
            
            //
            // Number of sources marked for a query response. 
            //
            ULONG MarkedForQueryCount;
        };
        //
        // MULTICAST_DISCOVERY_VERSION2.
        //
        struct {
            //
            // Indicates if the first join or leave message is outstanding or
            // not. This cannot be cancelled by an incoming report from another
            // host. 
            //
            BOOLEAN StateChangeReport;

            //
            // Keeps count of the number of responses to queries
            // outstanding. These responses can be cancelled by incoming
            // reports from other hosts. Retransmissions of state change
            // reports (joins) are also treated as responses to queries. So,
            // this value can be greater than 1.
            //
            ULONG QueryResponses;
            
            //
            // Flag for indicating if the last multicast discovery report for
            // the group was sent by us or not. Set to TRUE if the last report
            // was sent by us, FALSE otherwise. 
            //
            ULONG MulticastReportFlag;
        };
    };
    
    //
    // Timeout state for reports (trigerred by membership changes). 
    //
    TIMER_ENTRY ReportTimer; 

    //
    // Timeout state for responses to general queries. 
    //
    TIMER_ENTRY GeneralQueryTimer;

    //
    // Timeout state for response to group-specific and group-and-source
    // specific queries.
    //
    TIMER_ENTRY SpecificQueryTimer;

    HANDLE FlContext;
    LONG PendingCount;          // # join requests made at the lower layer.
    BOOLEAN Pending;            // Has this group been joined at a lower layer?
} IP_LOCAL_MULTICAST_ADDRESS, *PIP_LOCAL_MULTICAST_ADDRESS;

//
// MULTICAST_REPORT_RECORD. 
// 
// A structure defining a single record in a multicast report. 
//
typedef struct _IP_MULTICAST_RECORD_ENTRY {
    struct _IP_MULTICAST_RECORD_ENTRY *Next;
    MULTICAST_RECORD_TYPE Type;
    ULONG SourceCount;
    UCHAR Addresses[sizeof(IN6_ADDR)];
} IP_MULTICAST_RECORD_ENTRY, *PIP_MULTICAST_RECORD_ENTRY;

//
// Size of the IP_MULTICAST_RECORD_ENTRY. Size depends on the number of sources 
// and the protocol address bytes. 
//
#define MULTICAST_RECORD_ENTRY_SIZE(SourceCount, AddressBytes) \
    (sizeof(IP_MULTICAST_RECORD_ENTRY) +                       \
        ((AddressBytes) * (SourceCount)))

//
// The address of the multicast group within the record entry.
//
#define MULTICAST_RECORD_ENTRY_GROUP(RecordEntry) \
    ((RecordEntry)->Addresses)

//
// The address of the nth source within record entry. 
//
#define MULTICAST_RECORD_ENTRY_SOURCE(RecordEntry, Source, AddressBytes) \
    (MULTICAST_RECORD_ENTRY_GROUP(RecordEntry) +                         \
     (((Source) + 1) * (AddressBytes)))

//
// The size of a protocol specific record or report (for instance, IGMPv3
// report/record). This depends on the protocol (IPv4 or IPv6) and the number
// of sources in the report/record.
//
#define MULTICAST_RECORD_SIZE(Protocol, SourceCount) \
    (((Protocol)->MulticastRecordHeaderSize) +       \
        ((SourceCount) * ((Protocol)->Characteristics->AddressBytes)))

#define MULTICAST_REPORT_SIZE(Protocol, SourceCount)  \
    (MULTICAST_RECORD_SIZE(Protocol, SourceCount) +    \
        ((Protocol)->MulticastReportHeaderSize))

VOID
IpFlcAddGroupComplete(
    IN PFL_INDICATE_COMPLETE Args
    );

NTSTATUS
IppFindOrCreateLocalMulticastAddressUnderLock(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN struct _IP_SET_SESSION_INFO_CONTEXT *CompletionContext OPTIONAL,
    OUT PIP_LOCAL_MULTICAST_ADDRESS *Entry
    );

NTSTATUS
IppFindOrCreateLocalMulticastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN struct _IP_SET_SESSION_INFO_CONTEXT *CompletionContext OPTIONAL,
    OUT PIP_LOCAL_MULTICAST_ADDRESS *Entry
    );

#if ADDRESS_REFHIST
VOID
IppDereferenceLocalMulticastAddressUnderLockWithHistory(
    IN PIP_LOCAL_MULTICAST_ADDRESS Multicast, 
    IN ULONG Line,
    __in IN PCHAR File
    );

VOID
IppDereferenceLocalMulticastAddressWithHistory(
    IN PIP_LOCAL_MULTICAST_ADDRESS Multicast,
    IN ULONG Line,
    __in IN PCHAR File
    );

#define IppDereferenceLocalMulticastAddress(Group) \
    IppDereferenceLocalMulticastAddressWithHistory(Group, __LINE__, __FILE__) 

#define IppDereferenceLocalMulticastAddressUnderLock(Group)  \
    IppDereferenceLocalMulticastAddressUnderLockWithHistory( \
        Group, __LINE__, __FILE__)

#else 

VOID
IppDereferenceLocalMulticastAddressUnderLock(
    IN PIP_LOCAL_MULTICAST_ADDRESS Multicast
    );

VOID
IppDereferenceLocalMulticastAddress(
    IN PIP_LOCAL_MULTICAST_ADDRESS Multicast
    );
#endif

VOID
IppFindAndDereferenceMulticastGroup(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    );

NTSTATUS
IppModifyMulticastGroupUnderLock(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup,
    IN MULTICAST_MODE_TYPE OldMode,
    IN ULONG DeleteCount,
    IN CONST UCHAR *DeleteList,
    IN MULTICAST_MODE_TYPE NewMode, 
    IN ULONG AddCount,
    IN CONST UCHAR *AddList,
    IN CONST LIST_ENTRY *SessionSources
    );

PIP_LOCAL_MULTICAST_ADDRESS
IppFindMulticastAddressOnInterfaceUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *AddressString
    );

PIP_LOCAL_MULTICAST_ADDRESS
IppFindMulticastAddressOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *AddressString
    );

NTSTATUS
IppProcessMulticastDiscoveryQuery(
    IN PIP_INTERFACE Interface,
    IN MULTICAST_DISCOVERY_VERSION Version,
    IN PUCHAR MulticastAddress, 
    IN ULONG SourceCount,
    IN PUCHAR SourceList,
    IN ULONG MaxResponseTime
    );

NTSTATUS
IppProcessMulticastDiscoveryReport(
    IN PIP_INTERFACE Interface, 
    IN MULTICAST_DISCOVERY_VERSION Version,
    IN PUCHAR MulticastAddress
    );

VOID
IppMulticastDiscoveryTimeout(
    IN PIP_INTERFACE Interface,
    IN PTIMER_TABLE TimerTable
    );

VOID 
IppMulticastDiscoveryVersionTimeout(
    IN PIP_INTERFACE Interface, 
    IN MULTICAST_DISCOVERY_VERSION Version
    );

VOID
IppSendMulticastDiscoveryReportComplete(
    IN PNET_BUFFER_LIST NetBufferList
    );

VOID
IppReconnectMulticastAddress(
    IN PIP_LOCAL_MULTICAST_ADDRESS MulticastGroup
    );

VOID
IppResetAllMulticastGroups(
    IN PIP_INTERFACE Interface
    );

#endif // _MULTICAST_ADDRESS_
