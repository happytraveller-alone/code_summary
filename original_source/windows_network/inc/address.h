/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    address.h

Abstract:

    This module contains declarations for the network layer module's
    address management.

Author:

    Mohit Talwar (mohitt) Tue Nov 19 09:43:28 2002

Environment:

    Kernel mode only.

--*/

#ifndef _ADDRESS_
#define _ADDRESS_

#pragma once
#include "iscsiibf.h"
//
// Defines a table for address identifiers. 
//
typedef SPIN_LOCKED_LIST IP_ADDRESS_IDENTIFIER_SET, 
    *PIP_ADDRESS_IDENTIFIER_SET;

//
// IP_ADDRESS_IDENTIFIER. 
//
// Defines a structure for the IP local address identifier. 
//
typedef struct _IP_ADDRESS_IDENTIFIER {
    //
    // Address literal, type and scope ID.
    //
    NL_ADDRESS_IDENTIFIER;

    //
    // Link for linking into the per-compartment set of address identifiers. 
    //
    LIST_ENTRY Link;

    //
    // Reference count. Each NL_LOCAL_ADDRESS holds a reference to this. 
    //
    ULONG ReferenceCount;
} IP_ADDRESS_IDENTIFIER, *PIP_ADDRESS_IDENTIFIER;

//
// Define this to use an adaptive table (BBT) for addresses.
// This doubles the size of the NLA_LINK structure (compared to a 
// LIST_ENTRY), but lookups are O(log N) rather than O(N).
//
typedef ADAPTIVE_TABLE NLA_SET, *PNLA_SET;
typedef ADAPTIVE_LINK NLA_LINK, *PNLA_LINK;

typedef struct _IP_ADDRESS_ORIGIN {
    //
    // Bit fields are listed from low to high.
    //
    NL_SUFFIX_ORIGIN SuffixOrigin : 4;
    NL_PREFIX_ORIGIN PrefixOrigin : 4;
} IP_ADDRESS_ORIGIN, *PIP_ADDRESS_ORIGIN;

//
// Values for AddressOrigin - must fit in 8 bits.
// We can't make this an enum since enums consume 32 bits.
//
#define ADDR_CONF_MANUAL    ((NlpoManual << 4) | NlsoManual)
#define ADDR_CONF_PUBLIC    \
    ((NlpoRouterAdvertisement << 4) | NlsoLinkLayerAddress)
#define ADDR_CONF_TEMPORARY ((NlpoRouterAdvertisement << 4) | NlsoRandom)
#define ADDR_CONF_DHCP      ((NlpoDhcp << 4) | NlsoDhcp)
#define ADDR_CONF_WELLKNOWN ((NlpoWellKnown << 4) | NlsoWellKnown)
#define ADDR_CONF_LINK      ((NlpoWellKnown << 4) | NlsoLinkLayerAddress)
#define ADDR_CONF_EPHEMERAL ((NlpoWellKnown << 4) | NlsoManual)

#define MAX_EPHEMERAL_DECOMPOSITION_TIME 30   // 30 seconds.
#define IP_EPHEMERAL_LOOPBACK_ADDRESS_RATE 30 

//
// Per RFC 3927.
//
#define IP_LINKLOCAL_MAX_CONFLICTS 10

typedef struct _IP_DAD_WORK_QUEUE_ITEM {
    PIO_WORKITEM WorkQueueItem;
    IP_ADDRESS_STORAGE NlAddress;
    UCHAR DlAddress[DL_ADDRESS_LENGTH_MAXIMUM];
    SCOPE_ID ScopeId;
    ULONG NlAddressLength;
    ULONG DlAddressLength;
    ULONG EventCode;
} IP_DAD_WORK_QUEUE_ITEM, *PIP_DAD_WORK_QUEUE_ITEM;

typedef struct _IP_LOCAL_ADDRESS {
    //
    // Read-only fields visible to clients.
    //
    ULONG Signature;                // IP_LOCAL_ADDRESS_SIGNATURE
    LONG ReferenceCount;
    PIP_INTERFACE Interface;

    PIP_ADDRESS_IDENTIFIER Identifier;
    NL_ADDRESS_TYPE Type;

    //
    // Private fields between TCP and IP.
    //
    PVOID TcpContext1;
    PVOID TcpContext;

    union {
        struct {
            //
            // Do not use the address as source address for any outgoing 
            // packet unless explictly asked to.  This is used for
            // transient addresses, and is only modified via the NSI.
            //
            USHORT SkipAsSource : 1;

            //
            // NL clients' view of whether the address is connected, i.e.
            // is both valid and on an interface which is connected.
            //
            USHORT Connected : 1;

            //
            // Was this temporary address already regenerated. Used only for 
            // temporary addresses. 
            //
            USHORT TemporaryAddressRegenerated : 1;

            //
            // Whether an on-link route needs to be added for this address. 
            // This is used to add on-link route if the address becomes valid.
            //
            USHORT CreateOnLinkRoute : 1;

            //
            // Whether an on-link route was added for this address. 
            //
            USHORT OnLinkRouteCreated : 1;
            
            //
            // Whether the address has been deleted from the list of
            // addresses. 
            //
            USHORT Deleted : 1;

            //
            // Whether the address is being used to boot from a remote 
            // disk.
            //
            USHORT SystemCritical : 1;
        };
        USHORT Flags;
    };

    union {
        IP_ADDRESS_ORIGIN;
        UCHAR AddressOrigin; 
    };

    //
    // Time of creation.  This can serve as an additional identifier.
    //
    LARGE_INTEGER CreationTimestamp;    
    
    //
    // Internal read-write fields protected by interface lock.
    //
    NLA_LINK Link;
} IP_LOCAL_ADDRESS, *PIP_LOCAL_ADDRESS;

C_ASSERT(FIELD_OFFSET(IP_LOCAL_ADDRESS, Signature) == 0);
C_ASSERT(FIELD_OFFSET(NL_LOCAL_ADDRESS, Interface) ==
         FIELD_OFFSET(IP_LOCAL_ADDRESS, Interface));
C_ASSERT(FIELD_OFFSET(NL_LOCAL_ADDRESS, Identifier) ==
         FIELD_OFFSET(IP_LOCAL_ADDRESS, Identifier));
C_ASSERT(FIELD_OFFSET(NL_LOCAL_ADDRESS, Type) ==
         FIELD_OFFSET(IP_LOCAL_ADDRESS, Type));

typedef IP_LOCAL_ADDRESS IP_LOCAL_BROADCAST_ADDRESS, 
    *PIP_LOCAL_BROADCAST_ADDRESS;

typedef IP_LOCAL_ADDRESS IP_LOCAL_ANYCAST_ADDRESS, 
    *PIP_LOCAL_ANYCAST_ADDRESS;

typedef struct _IP_LOCAL_UNICAST_ADDRESS {
    IP_LOCAL_ADDRESS;

    //
    // Internal read-write fields protected by interface lock.
    //
    NL_DAD_STATE DadState;

    //
    // Timer for the unicast address. This is used for the DAD timeouts as well
    // as for deprecating and invalidating the address.
    //
    TIMER_ENTRY Timer; 
    
    //
    // The number of timeouts left for DAD. This is one more than the
    // number of DAD transmits because we wait one extra timeout after
    // sending the last solicitation. 
    //
    USHORT DadCount;

    //
    // Valid and preferred lifetime of the address (in ticks) staring from
    // LifetimeBaseTime.  e.g. The address is deprecated at (LifetimeBaseTime +
    // PreferredLifetime) ticks and invalidated at (LifetimeBaseTime +
    // ValidLifetime) ticks.
    //
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG LifetimeBaseTime;
    
    //
    // The creation time of the address (in tick count).  This is used
    // primarily for anonymous addresses since the total lifetime (since
    // creation) of an anonymous address can not exceed a certain threshold. 
    //
    ULONG CreationTime;

    //
    // Prefix length (in bits) of the address. 
    //
    ULONG PrefixLength;
    
    //
    // The public address corresponding to this address (used only for
    // temporary addresses). When the temporary address becomes invalid and we
    // want to create a new temporary address, this helps in determining the
    // lifetime of the new address. Holds a reference to the PublicAddress.
    //
    struct _IP_LOCAL_UNICAST_ADDRESS *PublicAddress;
} IP_LOCAL_UNICAST_ADDRESS, *PIP_LOCAL_UNICAST_ADDRESS;

//
// Since temporary addresses and unicast addresses go in the same address set,
// it is necessary that their size be the same so that the key offset for all
// elements in the set is the same. Another way of accomplishing this would be
// to make space for the IP address in the IP_LOCAL_ADDRESS structure at the
// expense of wasting 12 bytes for IPv4 or having separate code for IPv4 and
// IPv6. 
//
typedef struct _IP_LOCAL_UNICAST_ADDRESS 
    IP_LOCAL_TEMPORARY_ADDRESS, *PIP_LOCAL_TEMPORARY_ADDRESS;

C_ASSERT(sizeof(IP_LOCAL_UNICAST_ADDRESS) == sizeof(IP_LOCAL_TEMPORARY_ADDRESS));

//
// IP_ANYCAST_ADVERTISEMENT. 
//
// Defines a structure for holding information about deferred neighbor
// advertisements for anycast addresses.  For anycast addresses, we respond to
// neighbor solicitations after a random delay. 
//
typedef struct _IP_ANYCAST_ADVERTISEMENT {
    //
    // Timer entry for scheduling neighbor advertisements for anycast
    // addresses.  
    //
    TIMER_ENTRY Timer;

    //
    // Link for linking to the anycast address list of pending solicitations. 
    //
    LIST_ENTRY Link;
    
    //
    // Sub-interface on which the advertisement will go out.  Holds a reference
    // to the sub-interface.
    //
    PIP_SUBINTERFACE SubInterface;

    //
    // The local anycast address for which to send the neighbor advertisment.
    // Holds a reference to the address.
    //
    PIP_LOCAL_ANYCAST_ADDRESS AnycastAddress;
} IP_ANYCAST_ADVERTISEMENT, *PIP_ANYCAST_ADVERTISEMENT;


__inline 
BOOLEAN
IsLocalUnicastAddressValid(
    IN CONST IP_LOCAL_UNICAST_ADDRESS *Address
    )
{
    ASSERT(NL_ADDRESS_TYPE(Address) == NlatUnicast);
    return (Address->DadState >= NldsDeprecated);
}


__inline 
BOOLEAN
IsLocalUnicastAddressTentative(
    IN CONST IP_LOCAL_UNICAST_ADDRESS *Address
    )
{
    ASSERT(NL_ADDRESS_TYPE(Address) == NlatUnicast);    
    return (Address->DadState == NldsTentative);
}

__inline
BOOLEAN
IsLocalUnicastAddressOptimistic(
    IN CONST IP_LOCAL_UNICAST_ADDRESS *Address
    )
{
    ASSERT(NL_ADDRESS_TYPE(Address) == NlatUnicast);    
    return 
        ((Address->DadState == NldsPreferred) &&
         (Address->DadCount > 0));

}

//
// Internal Address Manager functions
//
extern NL_LOCAL_UNICAST_ADDRESS_RW IpDefaultLocalUnicastAddressRw;

PIP_LOCAL_ADDRESS
IppFindAddressInAddressSet(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    );

PIP_LOCAL_ADDRESS
IppFindAddressInAddressSetUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType
    );

PIP_LOCAL_ADDRESS
IppFindAddressOnInterfaceEx(
    IN PIP_INTERFACE If,
    IN CONST UCHAR *AddressString
    );

PIP_LOCAL_ADDRESS
IppFindAddressOnInterfaceExUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    );

NTSTATUS
IppFindOrCreateLocalUnicastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN ULONG PreferredLifetime, 
    IN ULONG ValidLifetime, 
    IN ULONG PrefixLength,
    IN BOOLEAN CreateOnLinkRoute,
    OUT PIP_LOCAL_UNICAST_ADDRESS *ReturnLocalAddress
    );

NTSTATUS
IppFindOrCreateLocalBroadcastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN BOOLEAN RouteSetLockHeld,
    OUT PIP_LOCAL_BROADCAST_ADDRESS *ReturnLocalAddress
    );

NTSTATUS
IppFindOrCreateLocalAnycastAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN BOOLEAN RouteSetLockHeld,
    OUT PIP_LOCAL_ANYCAST_ADDRESS *ReturnLocalAddress
    );

NTSTATUS
IppFindOrCreateLocalUnspecifiedAddress(
    IN PIP_INTERFACE Interface, 
    OUT PIP_LOCAL_UNICAST_ADDRESS *UnspecifiedAddress
    );

NTSTATUS
IppCreateLocalTemporaryAddress(
    IN CONST UCHAR *Prefix,
    IN PIP_INTERFACE Interface,
    IN PIP_LOCAL_UNICAST_ADDRESS PublicAddress,
    IN BOOLEAN RouteSetLockHeld,
    OUT PIP_LOCAL_TEMPORARY_ADDRESS *ReturnTemporaryAddress
    );

VOID
IppHandleAddressLifetimeTimeout(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    );

NTSTATUS
IppStartLinkLocalAddressConfiguration(
    IN PIP_INTERFACE Interface
    );

VOID
IppRestartLinkLocalAddressConfiguration(
    IN PIP_INTERFACE Interface
    );

VOID
IppStopLinkLocalAddressConfiguration(
    IN PIP_INTERFACE Interface
    );

VOID
IppLinkLocalAddressConfigurationTimeout(
    IN PIP_INTERFACE Interface
    );

PIP_LOCAL_UNICAST_ADDRESS
IppFindLinkLocalUnicastAddress(
    IN PIP_INTERFACE Interface
    );

VOID
IppCleanupAddressManager(
    IN PIP_PROTOCOL Protocol
    );

__inline
NTSTATUS
IppInitializeNlaSet(
    IN OUT PNLA_SET Set
    )
{
    IppInitializeAdaptiveTable(Set);
    return STATUS_SUCCESS;
}

NTSTATUS
IppConfigureIscsiAddress(
    IN PIP_INTERFACE Interface,
    IN PNL_LOCAL_ADDRESS_KEY Key,
    IN PISCSI_BOOT_NIC TcpipIscsiBootParameters
    );

#define IppIsNlaSetEmpty        IppIsAdaptiveTableEmpty
#define IppUninitializeNlaSet   IppUninitializeAdaptiveTable
#define IppFindNlaSetEntry      IppFindAdaptiveTableEntry
#define IppDeleteNlaSetEntry    IppDeleteAdaptiveTableEntry
#define IppInsertNlaSetEntry    IppInsertAdaptiveTableEntry
#define IppEnumerateNlaSetEntry IppEnumerateAdaptiveTableEntry

typedef struct _IP_ADDRESS_ENUMERATION_CONTEXT {
    ULONG DeleteCount;
    PVOID RestartKey;
    IP_ADDRESS_STORAGE Buffer;
} IP_ADDRESS_ENUMERATION_CONTEXT, *PIP_ADDRESS_ENUMERATION_CONTEXT;

C_ASSERT(FIELD_OFFSET(IP_ADDRESS_ENUMERATION_CONTEXT, DeleteCount) ==
         FIELD_OFFSET(ADAPTIVE_TABLE_ENUMERATION_CONTEXT, DeleteCount));
C_ASSERT(FIELD_OFFSET(IP_ADDRESS_ENUMERATION_CONTEXT, RestartKey) ==
         FIELD_OFFSET(ADAPTIVE_TABLE_ENUMERATION_CONTEXT, RestartKey));
C_ASSERT(FIELD_OFFSET(IP_ADDRESS_ENUMERATION_CONTEXT, Buffer) ==
         FIELD_OFFSET(ADAPTIVE_TABLE_ENUMERATION_CONTEXT, Buffer));

__inline
IppInitializeAddressEnumerationContext(
    IN PIP_ADDRESS_ENUMERATION_CONTEXT Context
    )
{
    RtlZeroMemory(Context, sizeof(*Context));
}

VOID
IppCleanupLocalAddress(
    PIP_LOCAL_ADDRESS Address
    );

#if ADDRESS_REFHIST

extern PREFERENCE_HISTORY IppAddressReferenceHistory;
DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_LOCAL_ADDRESS, LocalAddress, Ipp, IppAddressReferenceHistory)
#define IppReferenceLocalAddress(Address) \
    _IppReferenceLocalAddress((Address), __LINE__, __FILE__)
#define IppReferenceLocalAddressEx(Address, RefIncr) \
    _IppReferenceLocalAddressEx((Address), (RefIncr), __LINE__, __FILE__)
#define IppDereferenceLocalAddress(Address) \
    IppDereferenceLocalAddressWithHistory((Address), __LINE__, __FILE__)

VOID
IppDereferenceLocalAddressWithHistory(
    IN PIP_LOCAL_ADDRESS LocalAddress,
    IN ULONG Line,
    __in IN PCHAR File
    );

#else

#define IppCleanupAddressPrimitive IppCleanupLocalAddress
DEFINE_REFERENCE_ROUTINES(PIP_LOCAL_ADDRESS, AddressPrimitive, Ipp)
#define IppReferenceLocalAddress IppReferenceAddressPrimitive
#define IppReferenceLocalAddressEx IppReferenceAddressPrimitiveEx

VOID
IppDereferenceLocalAddress(
    IN PIP_LOCAL_ADDRESS LocalAddress
    );

#endif

__inline
VOID
IppReferenceLocalUnicastAddress(
    IN PIP_LOCAL_UNICAST_ADDRESS UnicastAddress
    )
{
    IppReferenceLocalAddress((PIP_LOCAL_ADDRESS) UnicastAddress);
}

__inline
VOID
IppDereferenceLocalUnicastAddress(
    IN PIP_LOCAL_UNICAST_ADDRESS UnicastAddress
    )
{
    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) UnicastAddress);
}

__inline
VOID
IppDereferenceLocalTemporaryAddress(
    IN PIP_LOCAL_TEMPORARY_ADDRESS TemporaryAddress
    )
{
    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) TemporaryAddress);
}

__inline
VOID
IppDereferenceLocalAnycastAddress(
    IN PIP_LOCAL_ANYCAST_ADDRESS AnycastAddress
    )
{
    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) AnycastAddress);
}

__inline
VOID
IppDereferenceLocalBroadcastAddress(
    IN PIP_LOCAL_BROADCAST_ADDRESS BroadcastAddress
    )
{
    IppDereferenceLocalAddress((PIP_LOCAL_ADDRESS) BroadcastAddress);
}

NTSTATUS
IppSetAllLocalAddressParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args, 
    IN NL_ADDRESS_TYPE AddressType
    );

NL_PROVIDER_REFERENCE_LOCAL_ADDRESS IpNlpReferenceLocalAddress;
NL_PROVIDER_DEREFERENCE_LOCAL_ADDRESS IpNlpDereferenceLocalAddress;
NL_PROVIDER_VALIDATE_LOCAL_ADDRESS IpNlpValidateLocalAddress;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllLocalUnicastAddressParameters;
NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllLocalUnicastAddressParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllLocalAnycastAddressParameters;
NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllLocalAnycastAddressParameters;
NM_PROVIDER_REGISTER_CHANGE_NOTIFICATION IpRegisterAddressChangeNotification;
NM_PROVIDER_DEREGISTER_CHANGE_NOTIFICATION
    IpDeregisterAddressChangeNotification;

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllLocalMulticastAddressParameters;

VOID
IppFreeLocalAddress(
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_LOCAL_ADDRESS *AddressPointer
    );

PIP_LOCAL_ADDRESS
IppAllocateLocalNonUnicastAddress(
    IN PIP_PROTOCOL Protocol
    );

VOID 
IppRemoveLocalAddressUnderLock(
    IN PIP_LOCAL_ADDRESS LocalAddress, 
    IN BOOLEAN RouteSetLockHeld
    );

VOID
IppRemoveLocalAddress(
    IN PIP_LOCAL_ADDRESS LocalAddress,
    IN BOOLEAN RouteSetLockHeld
    );

PIP_LOCAL_UNICAST_ADDRESS
IppFindUnicastAddressOnInterfaceUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *AddressString
    );

PIP_LOCAL_UNICAST_ADDRESS
IppFindUnicastAddressOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *AddressString
    );

VOID
IppUnAddressInterfaceUnderLock(
    IN PIP_INTERFACE Interface
    );

VOID
IppRestartDad(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    );

VOID
IppDadComplete(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    );

VOID
IppNotifyDad(
    __in_bcount(NlAddressLength) CONST UCHAR *NlAddress,
    IN ULONG NlAddressLength,
    IN SCOPE_ID ScopeId, 
    __in_bcount(DlAddressLength) CONST UCHAR *DlAddress,  
    IN ULONG DlAddressLength,
    IN ULONG EventCode
    );

VOID
IppDadFailed(
    IN PIP_LOCAL_UNICAST_ADDRESS LocalAddress
    );

NTSTATUS
IppGetFirstUnicastAddress(
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *AddressPointer
    );

NTSTATUS
IppGetNextUnicastAddress(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    OUT PIP_LOCAL_UNICAST_ADDRESS *AddressPointer
    );

SCOPE_ID
IppGetScopeId(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    );

SCOPE_ID
IppGetExternalScopeId(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    );

BOOLEAN
IppIsScopeIdCanonicalized(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Address,
    IN SCOPE_ID ScopeId
    );

BOOLEAN
IppCanonicalizeScopeId(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *Address,
    IN OUT SCOPE_ID *ScopeId
    );

PIP_LOCAL_ADDRESS
IppFindAddressInScopeEx(
    IN PIP_COMPARTMENT Compartment,
    IN SCOPE_ID ScopeId,
    IN CONST UCHAR *Address
    );

PIP_LOCAL_ADDRESS
IppFindLocalAddress(
    IN PIP_COMPARTMENT Compartment,
    IN PNL_LOCAL_ADDRESS_ARG Arg
    );

VOID
IppAddressSetTimeout(
    IN PIP_INTERFACE Interface
    );

VOID
IppReconnectAddresses(
    IN PIP_INTERFACE Interface
    );

VOID
IppDisconnectAddresses(
    IN PIP_INTERFACE Interface
    );

VOID
IppNotifyAddressChange(
    IN PIP_LOCAL_UNICAST_ADDRESS UnicastAddress,
    IN NSI_NOTIFICATION NotificationType
    );

VOID
IppNotifyAddressChangeAtPassive(
    IN PVOID WorkItem
    );    

PIP_LOCAL_ADDRESS
IppCreateLocalAddress(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *Address,
    IN NL_ADDRESS_TYPE AddressType,
    IN PIP_INTERFACE Interface,
    IN UCHAR AddressOrigin,
    IN ULONG PreferredLifetime,
    IN ULONG ValidLifetime,
    IN ULONG PrefixLength,
    IN PIP_LOCAL_UNICAST_ADDRESS PublicAddress
    );

__inline
VOID
IppCreateInspectionAddress(
    OUT NL_LOCAL_ADDRESS *LocalAddress, 
    OUT NL_ADDRESS_IDENTIFIER *Identifier, 
    IN PIP_INTERFACE Interface, 
    IN CONST UCHAR *Address, 
    IN NL_ADDRESS_TYPE Type
    )
{
    LocalAddress->Identifier = Identifier;
    LocalAddress->Interface = (PNL_INTERFACE) Interface;
    LocalAddress->Type = Type;
    
    Identifier->Address = Address;
    Identifier->ScopeId = IppGetScopeId(Interface, Address);
}

__inline
PIP_LOCAL_ADDRESS
IppFindAddressInScope(
    IN PIP_COMPARTMENT Compartment,
    IN SCOPE_ID ScopeId,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    See whether a given address is assigned to the local (virtual) machine.
    This is done whenever the classification handle can't be used to
    do this lookup.
    
    The routine returns the local address only if the address is valid.
    
Arguments:

    Compartment - Supplies a pointer to the compartment.
    
    ScopeId - Supplies the scope id in which to find an address.

    Address - Supplies the address to find.
        
Return Value:
    
    Returns a pointer to the local address structure found.
    Caller is responsible for dereferencing the address returned on success.
    
Locks:

    Assumes caller holds at least a reference on the compartment.
    Acquires a read lock on the per-compartment interface set.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress = NULL;
    
    LocalAddress = IppFindAddressInScopeEx(Compartment, ScopeId, Address);
    if (LocalAddress != NULL && 
        NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast && 
        !IsLocalUnicastAddressValid(
            (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress)) {
        IppDereferenceLocalAddress(LocalAddress);
        LocalAddress = NULL;
    }
    return LocalAddress;
}

__inline
PIP_LOCAL_ADDRESS
IppFindAddressOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    This routine checks to see whether a given address is assigned to
    a particular interface.  The address may be of any type.

    The routine returns the local address only if the address is valid.

Arguments:

    Interface - Supplies a pointer to the interface to check.

    Address - Supplies the IP address to search for. 
    
Return Value:

    Returns a pointer to the local address object if found.

Locks:

    Assumes caller holds at least a reference on the interface.
    Caller is responsible for dereferencing address returned on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress = NULL;
    
    LocalAddress = IppFindAddressOnInterfaceEx(Interface, Address);
    if (LocalAddress != NULL && 
        NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast && 
        !IsLocalUnicastAddressValid(
            (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress)) {
        IppDereferenceLocalAddress(LocalAddress);
        LocalAddress = NULL;
    }
    return LocalAddress;
}

__inline
PIP_LOCAL_ADDRESS
IppFindAddressOnInterfaceUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    This routine checks to see whether a given address is assigned to
    a particular interface.  The address may be of any type.

    The routine returns the local address only if the address is valid.

Arguments:

    Interface - Supplies a pointer to the interface to check.

    Address - Supplies the IP address to search for. 
        
Return Value:

    Returns a pointer to the local address object if found.

Locks:

    Assumes caller holds a read or write lock on the interface.
    Caller is responsible for dereferencing AddressPointer on success.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/
{
    PIP_LOCAL_ADDRESS LocalAddress = NULL;
    
    LocalAddress = IppFindAddressOnInterfaceExUnderLock(Interface, Address);
    if (LocalAddress != NULL &&
        NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast && 
        !IsLocalUnicastAddressValid(
            (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress)) {
        IppDereferenceLocalAddress(LocalAddress);
        LocalAddress = NULL;
    }
    return LocalAddress;
}

//
// Address set for caching addresses in range 127.x.x.x.
//
typedef struct _IP_LOOPBACK_ADDRESS_LOCKED_SET {
    RTL_MRSW_LOCK Lock;
    NLA_SET AddressSet;
    ULONG TicksToGarbageCollection;
    ULONG EntriesAdded;
} IP_LOOPBACK_ADDRESS_LOCKED_SET, *PIP_LOOPBACK_ADDRESS_LOCKED_SET;

NTSTATUS
IppFindOrCreateLocalEphemeralAddressUnderLock(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Entry
    );

NTSTATUS
IppFindOrCreateLocalEphemeralAddress(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Entry
    );

NTSTATUS
IppFindOrCreateLocalEphemeralAddressAtDpc(
    IN CONST UCHAR *Address,
    IN PIP_INTERFACE Interface,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Entry
    );

VOID
IppGarbageCollectLoopbackAddressSet(
    IN PIP_COMPARTMENT Compartment
    );

VOID
IppEphemeralLoopbackAddressSetTimeout(
    IN PIP_COMPARTMENT Compartment
    );

NTSTATUS
IppInitializeEphemeralLoopbackAddressSet(
    IN PIP_LOOPBACK_ADDRESS_LOCKED_SET Set
    );

VOID
IppUninitializeEphemeralLoopbackAddressSet(
    IN PIP_LOOPBACK_ADDRESS_LOCKED_SET Set
    );

VOID 
IppNotifyLinkLocalAddressChange(
    IN PIP_INTERFACE Interface,
    IN NSI_NOTIFICATION NotificationType
    );

#endif // _ADDRESS_
