/*++

Copyright (c) Microsoft Corporation

Module Name:

    reassembly.h

Abstract:

    This module contains the private (internal) definitions and structures
    for the IP reassembly module.

Author:

    Dave Thaler (dthaler) 10-July-2002

Environment:

    kernel mode only

--*/

#ifndef _REASSEMBLY_
#define _REASSEMBLY_
#pragma once

//
// Structure used to link fragments together.  Compare PacketShim in the
// XP IPv6 stack, and IPRcvBuf in the XP IPv4 stack.
//
// The fragment data follows the MDL in memory.  Also, since an MDL
// structure is actually variable-length, sizeof this structure is
// mostly meaningless.
//
typedef struct _IP_FRAGMENT {
    struct _IP_FRAGMENT *Next;    // Next packet on list.
    USHORT Length;
    USHORT Offset;
    MDL Mdl;
} IP_FRAGMENT, *PIP_FRAGMENT;


//
// A reassembly starts in ReassemblyStateNormal.
// If you want to remove it, then change the state
// to ReassemblyStateDeleting. This prevents someone else
// from freeing it while you unlock the reassembly,
// get the global reassembly list lock, and relock the assembly.
// Someone else can remove the deleting reassembly
// from the global list, in which case the state becomes
// ReassemblyStateRemoved.
//
typedef enum {
    ReassemblyStateNormal = 0,
    ReassemblyStateDeleting = 1,
    ReassemblyStateRemoved = 2,
} REASSEMBLY_STATE;

//
// Types of elements in a reassembly set.
//
typedef enum {
    ReassemblyTypeUndefined = 0,
    ReassemblyTypeRecord = 1,
    ReassemblyTypeGroup = 2
} REASSEMBLY_TYPE;

//
// Common fields for elements of a reassembly set.
//
typedef struct _REASSEMBLY_ELEMENT {
    union {                       
        LIST_ENTRY Link;        // Used when the element is in a list.      
        RTL_HASH_TABLE_ENTRY TLink; // Used when the element is in a tree.
                                    // Protected by global reassembly lock.
    };
    TIMER_ENTRY Timer;          // Expiration timer.  Protected by global lock.
    KSPIN_LOCK Lock;            // Protects reassembly fields below.
    union {                     // Does not hold a reference.
        PIP_INTERFACE Interface;
        PIP_COMPARTMENT Compartment;
        PVOID InterfaceOrCompartment;
    };
    REASSEMBLY_TYPE Type;       // See values above.
    REASSEMBLY_STATE State;     // See values above.
    ULONG Size;                 // Memory consumed in this reassembly.
    ULONG StartTime;            // Time when we started rate measurement.
    ULONG DataReceived;         // Amount of useful data received since then.
} REASSEMBLY_ELEMENT, *PREASSEMBLY_ELEMENT;


//
// Structure used to keep track of the fragments
// being reassembled into a single IPv6 datagram.
//
// REVIEW: Some of these fields are bigger than they need to be.
//
typedef struct _REASSEMBLY {
    REASSEMBLY_ELEMENT;         // Common fields.
    ULONG Id;                   // Unique (along w/ addrs) datagram identifier.
    __field_ecount(UnfragmentableLength)
    PUCHAR UnfragmentableData;  // Pointer to unfragmentable data.
    USHORT UnfragmentableLength;// Length of the unfragmentable part.
    ULONG DataLength;           // Length of the fragmentable part.
    PIP_FRAGMENT ContiguousList;// Sorted, contiguous frags (from offset zero).
    PIP_FRAGMENT ContiguousEnd; // Last shim on ContigList (for quick access).
    PIP_FRAGMENT GapList;       // Other fragments (sorted but non-contiguous).
    IP_HEADER_STORAGE IpHeader; // Large enough to hold an IPv4 or IPv6 header.
    union {
        ULONG Flags;
        struct {
            ULONG EcnNotEctPresent : 1; // ECN Flags:
            ULONG EcnEct1Present : 1;   // These flags are updated based on
            ULONG EcnEct0Present : 1;   // received codepoint. Rearrange with
            ULONG EcnCePresent : 1;     // care.
            ULONG Unused : 25;
            ULONG PacketFlags : 3;      // Packet flags.
        };
    };
    USHORT Marker;              // The current marker for contiguous data.
    USHORT MaxGap;              // Largest data offset in the gap list.
    USHORT NextHeaderOffset;    // Offset from IpHeader to pre-FH NextHeader.
    UCHAR NextHeader;           // Header type following the fragment header.
    PVOID IPSecContext;         // Maintained by IPSec to ensure integrity.
} REASSEMBLY, *PREASSEMBLY;

//
// Structure used to track fragment groups being collected
// for simultaneous handling in the forwarding path.
//
typedef struct _FRAGMENT_GROUP {
    REASSEMBLY_ELEMENT;                     // Common fields.
    ULONG PayloadLength;                    // Length expected for packet.
    ULONG PayloadAvailable;                 // Length received so far.
    ULONG Id;                               // Unique fragment group identifier.
    IP_ADDRESS_STORAGE SourceAddress;       // Source of group.
    IP_ADDRESS_STORAGE DestinationAddress;  // Destination of group.
    PIP_FRAGMENT ArrivalList;               // Fragments in order of arrival.
} FRAGMENT_GROUP, *PFRAGMENT_GROUP;

typedef struct _REASSEMBLY_SET {
    KSPIN_LOCK Lock;                // Protects Reassembly List.
    RTL_HASH_TABLE ReassemblyTable; // Packets being reassembled.
    RTL_HASH_TABLE FragmentGroupTable; // Fragments being grouped.
    PTIMER_TABLE TimerTable;        // Priority queue of reassembly timeout
                                    // events.
    
    KSPIN_LOCK LockSize;            // Protects the Size field.
    ULONG Size;                     // Total size of the waiting fragments.
    ULONG Limit;                    // Upper bound for Size.
} REASSEMBLY_SET, *PREASSEMBLY_SET;

//
// Per-packet and per-fragment overhead sizes.
// These are in addition to the actual size of the buffered data.
// They should be at least as large as the Reassembly
// and IP_FRAGMENT struct sizes.
//
#define REASSEMBLY_SIZE_PACKET  1024
#define REASSEMBLY_SIZE_FRAG    256

#define DEFAULT_REASSEMBLY_TIMEOUT IppTimerTicks(60)  // 60 seconds.

ULONG 
IppReassemblyHashKey(
    IN PIP_COMPARTMENT Compartment, 
    IN ULONG Id, 
    IN PUCHAR IP
    );

NL_ECN_CODEPOINT
IppReassembleEcnField(
    IN PREASSEMBLY Reassembly
    );

NTSTATUS
IppInitializeReassembler(
    OUT PREASSEMBLY_SET Set
    );

VOID
IppUninitializeReassembler(
    IN PREASSEMBLY_SET Set
    );

PREASSEMBLY
IppCreateInReassemblySet(
    IN PREASSEMBLY_SET Set,
    IN PUCHAR IpHeader,
    IN PIP_INTERFACE Interface,
    IN ULONG Id, 
    IN KIRQL OldIrql
    );

VOID
IppRemoveFromReassemblySet(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element,
    IN KIRQL OldIrql    
    );

VOID
IppDeleteFromReassemblySet(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element,
    IN KIRQL OldIrql
    );

VOID
IppIncreaseReassemblySize(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element,
    IN ULONG Size,
    IN ULONG NetSize
    );

VOID
IppCheckReassemblyQuota(
    IN PREASSEMBLY_SET Set,
    IN PREASSEMBLY_ELEMENT Element, 
    IN KIRQL OldIrql
    );

BOOLEAN
IppGroupFragments(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Packet,
    IN OUT PIP_REQUEST_CONTROL_DATA* List
    );

VOID
IppReassemblyInterfaceCleanup(
    IN PIP_INTERFACE Interface
    );

VOID
IppFragmentGroupCompartmentCleanup(
    IN PIP_COMPARTMENT Compartment
    );

VOID
IppReassemblyTimeout(
    IN PIP_PROTOCOL Protocol
    );

NETIO_NET_BUFFER_LIST_COMPLETION_ROUTINE IppReassemblyNetBufferListsComplete;

VOID
IppReassembledReceiveComplete(
    IN PNET_BUFFER_LIST NetBufferList
    );

VOID
IppReassembledReceiveAtDpc(
    IN PIP_REQUEST_CONTROL_DATA Control
    );

VOID
IppReassembledReceive(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context
    );

typedef
VOID
(IP_INTERNAL_REASSEMBLY_TIMEOUT)(
    IN PREASSEMBLY_ELEMENT Element
    );

typedef IP_INTERNAL_REASSEMBLY_TIMEOUT *PIP_INTERNAL_REASSEMBLY_TIMEOUT;

typedef
BOOLEAN
(IP_INTERNAL_IS_FRAGMENT)(
    IN PNET_BUFFER_LIST NetBufferList,
    IN PVOID HeaderBuffer,
    OUT PUCHAR* SourceAddress,
    OUT PUCHAR* CurrentDestinationAddress,
    OUT PULONG Identification,
    OUT PULONG FragmentOffset,
    OUT PULONG FragmentLength,
    OUT PULONG PayloadLength
    );

typedef IP_INTERNAL_IS_FRAGMENT *PIP_INTERNAL_IS_FRAGMENT;

#endif // _REASSEMBLY_
