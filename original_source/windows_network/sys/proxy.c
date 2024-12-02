/*++

Copyright (c) 2003-2004  Microsoft Corporation

Module Name:

    proxy.c

Abstract:

    This module contains generic proxy neighbor management functions.

    A fully functional proxy neighbor router requires the following:

    1. A proxy neighbor prefix set up on the public interface.

    2. Forwarding enabled on both the public and the private interfaces.

    3. Receipt of neighbor solicitation messages (for IPv6).
    
        On the public interface, the IPv6 router needs to receive neighbor
        solicitation messages for the neighbors being proxied.  Once
        neighbor-resolution completes, unicast neighbor solicitation messages
        will arrive on the routers MAC address and will be received normally.
        However, multicast neighbor-solicitation messages are sent to the
        solicited-node multicast address for a neighbor's address and need
        additional configuration to be received.

        This configuration can be one of the following...

        A. Use IPV6_ADD_MEMBERSHIP to join the solicited-node multicast address
           for each neighbor (IN6_SET_ADDR_SOLICITEDNODE).

        B. Use SIO_RCVALL_MCAST or SIO_RCVALL_MCAST_IF to enable
           multicast-promiscuous mode.
           
        C. Use SIO_RCVALL or SIO_RCVALL_IF to enable promiscuous mode

    Note that the node functions as a router (Router-mode MLSR), not a bridge.

    MLSR is the preferred method of extending a subnet.  Proxy neighbors exist
    primarily for backwards compatibility (CreateProxyArpEntry) and for the
    routing and remote accesss service, which uses this functionality when
    assigning on-subnet addresses to remote access clients.
    
Author:

    Mohit Talwar (mohitt) Mon Jun 30 23:12:30 2003

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "proxy.tmh"

VOID
IppInitializeProxyNeighborSet(
    OUT PIP_PROXY_NEIGHBOR_SET ProxyNeighborSet
    )
/*++

Routine Description:

    Initialize a proxy neighbor set.

Arguments:

    ProxyNeighborSet - Returns an initialized proxy neighbor set.

Return Value:

    None.
    
Caller LOCK: None.  Exclusive access as the interface is being created.
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    InitializeListHead(&ProxyNeighborSet->Head);    
}


VOID
IppUninitializeProxyNeighborSet(
    IN OUT PIP_PROXY_NEIGHBOR_SET ProxyNeighborSet
    )
/*++

Routine Description:

    Uninitialize a proxy neighbor set.

Arguments:

    ProxyNeighborSet - Returns an uninitialized proxy neighbor set.

Return Value:

    None.

Caller LOCK: None.  Exclusive access as the interface is being destroyed.
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PLIST_ENTRY Next, Head = &ProxyNeighborSet->Head;
    PIP_PROXY_NEIGHBOR ProxyNeighbor;
    
    for (Next = Head->Flink; Next != Head; ) {
        ProxyNeighbor = (PIP_PROXY_NEIGHBOR)
            CONTAINING_RECORD(Next, IP_PROXY_NEIGHBOR, Link);
        Next = Next->Flink;
        RemoveEntryList(&ProxyNeighbor->Link);
        ExFreePool(ProxyNeighbor);    
    }    
}


__inline
BOOLEAN
IppMatchProxyNeighbor(
    IN PIP_PROXY_NEIGHBOR ProxyNeighbor,
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN BOOLEAN Exact
    )
{
    PUCHAR Prefix = IP_PROXY_NEIGHBOR_PREFIX(ProxyNeighbor);
    USHORT AddressLength =
        Interface->Compartment->Protocol->Characteristics->AddressBytes;
        
    if (Exact) {
        return RtlEqualMemory(Address, Prefix, AddressLength);
    } else {
        return HasPrefix(Address, Prefix, ProxyNeighbor->PrefixLength);
    }
}


PIP_PROXY_NEIGHBOR
IppFindProxyNeighbor(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address,
    IN BOOLEAN Exact    
    )
/*++

Routine Description:

    Find a proxy neighbor entry matching the address.
    
Arguments:

    Interface - Supplies the interface on which the proxy neighbor exists.

    Address - Supplies the address to match.

    Exact - Supplies a boolean indicating whether an exact match is required.
    
Return Value:

    ProxyNeighbor or NULL.
    
Caller LOCK: Interface (Shared).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PLIST_ENTRY Next, Head = &Interface->ProxyNeighborSet.Head;
    PIP_PROXY_NEIGHBOR ProxyNeighbor;
    
    ASSERT_ANY_LOCK_HELD(&Interface->Lock);
    
    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        ProxyNeighbor = (PIP_PROXY_NEIGHBOR)
            CONTAINING_RECORD(Next, IP_PROXY_NEIGHBOR, Link);

        if (IppMatchProxyNeighbor(ProxyNeighbor, Interface, Address, Exact)) {
            //
            // The supplied address matches this ProxyNeighbor.
            //
            return ProxyNeighbor;
        }
    }
    return NULL;
}


NTSTATUS
IppCreateProxyNeighbor(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Prefix,
    IN UINT8 PrefixLength
    )
/*++

Routine Description:

    Creates a proxy neighbor entry.
    
Arguments:

    Interface - Supplies the interface on which the proxy neighbor exists.

    Prefix - Supplies the proxy neighbor prefix.

    PrefixLength - Supplies the length of the proxy neighbor prefix (in bits).
    
Return Value:

    STATUS_SUCCESS or failure code.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_PROXY_NEIGHBOR ProxyNeighbor;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // Find the exact matching proxy neighbor prefix.
    //    
    if (IppFindProxyNeighbor(Interface, Prefix, TRUE) != NULL) {
        return STATUS_DUPLICATE_OBJECTID;
    }
    
    //
    // Allocate the proxy neighbor structure from the system pool.
    //
    ProxyNeighbor = (PIP_PROXY_NEIGHBOR)
        ExAllocatePoolWithTagPriority(
            NonPagedPool,
            SIZEOF_IP_PROXY_NEIGHBOR(Protocol),
            IpGenericPoolTag,
            LowPoolPriority);
    if (ProxyNeighbor == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Failure allocating %s proxy neighbor\n", 
                   Interface->Compartment->Protocol->TraceString);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
#if DBG
    ProxyNeighbor->Signature = IP_PROXY_NEIGHBOR_SIGNATURE;
#endif
    InsertTailList(&Interface->ProxyNeighborSet.Head, &ProxyNeighbor->Link);
    ProxyNeighbor->PrefixLength = PrefixLength;
    RtlCopyMemory(IP_PROXY_NEIGHBOR_PREFIX(ProxyNeighbor),
                  Prefix,
                  AddressLength);

    return STATUS_SUCCESS;
}


NTSTATUS
IppDestroyProxyNeighbor(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Prefix
    )
/*++

Routine Description:

    Destroy a proxy neighbor entry.
    
Arguments:

    Interface - Supplies the interface on which the proxy neighbor exists.

    Prefix - Supplies the proxy neighbor prefix.
    
Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_PROXY_NEIGHBOR ProxyNeighbor;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // Find the exact matching proxy neighbor prefix.
    //
    ProxyNeighbor = IppFindProxyNeighbor(Interface, Prefix, TRUE);
    if (ProxyNeighbor == NULL) {
        return STATUS_NOT_FOUND;
    }

    RemoveEntryList(&ProxyNeighbor->Link);
    ExFreePool(ProxyNeighbor);    
    return STATUS_SUCCESS;
}

    
PIP_LOCAL_ADDRESS
IppGetProxyLocalAddress(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    Create an ephemeral proxy local address for the matching proxy neighbor
    (if any).
    
Arguments:

    Interface - Supplies the interface on which the proxy neighbor exists.

    Address - Supplies the address to create a proxy local address for.
    
Return Value:

    An ephemeral proxy LocalAddress or NULL.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/
{
    PIP_LOCAL_ADDRESS LocalTarget;
    PIP_PROXY_NEIGHBOR ProxyNeighbor;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    USHORT AddressLength = Protocol->Characteristics->AddressBytes;
    UINT8 PrefixLength = (UINT8) (AddressLength * RTL_BITS_OF(UINT8));
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // Find a proxy neighbor prefix covering this address.
    //    
    ProxyNeighbor = IppFindProxyNeighbor(Interface, Address, FALSE);
    if (ProxyNeighbor == NULL) {
        return NULL;
    }
    
    if (Protocol->Level == IPPROTO_IP) {
        if (ProxyNeighbor->PrefixLength != PrefixLength) {
            //
            // Since the prefix covers a subnet,
            // we fail to match if the suffix is either all-ones or all-zeros.
            //
            IN_ADDR SubnetBroadcastAddress;

            CreateBroadcastAddress(
                IP_PROXY_NEIGHBOR_PREFIX(ProxyNeighbor),
                ProxyNeighbor->PrefixLength,
                AddressLength,
                (BOOLEAN) Interface->UseZeroBroadcastAddress,
                (PUCHAR) &SubnetBroadcastAddress);
            if (RtlEqualMemory(
                    Address,
                    (PUCHAR) &SubnetBroadcastAddress,
                    AddressLength) ||
                RtlEqualMemory(
                    Address,
                    IP_PROXY_NEIGHBOR_PREFIX(ProxyNeighbor),
                    AddressLength)) {
                return NULL;
            }
        }
    }

    //
    // Create a local address for this proxy neighbor.  We create an anycast
    // address, if possible.  (An anycast address is not defended against DAD
    // solicitations, furthermore its neighbor advertisements have the override
    // bit off.  Of course, this only applies to IPv6.  IPv4 is kinda broken -
    // since ARP responses do not have an override bit, IPv4 anycast address
    // advertisements will conflict with IPv4 unicast address advertisements.)
    //
    LocalTarget =
        IppCreateLocalAddress(
            Protocol,
            Address,
            (Protocol->Level == IPPROTO_IP) ? NlatUnicast : NlatAnycast,
            Interface,
            ADDR_CONF_MANUAL,
            INFINITE_LIFETIME,
            INFINITE_LIFETIME,
            PrefixLength,
            NULL);
    if ((LocalTarget != NULL) && (Protocol->Level == IPPROTO_IP)) {
        ((PIP_LOCAL_UNICAST_ADDRESS) LocalTarget)->DadState = NldsPreferred;
    }

    return LocalTarget;
}


NTSTATUS
IppGetNextProxyNeighborOnInterface(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Prefix OPTIONAL,
    OUT PNL_PROXY_NEIGHBOR_KEY Key,
    OUT PNL_PROXY_NEIGHBOR_RW Rw
    )
/*++

Routine Description:

    Find the next proxy neighbor entry on the specified interface.
    
Arguments:

    Interface - Supplies the interface on which the proxy neighbor exists.

    Prefix - Supplies the previous proxy neighbor's prefix.
        A NULL argument would return the first proxy neighbor entry.

    Key - Returns the next proxy neighbor's key.

    Rw - Returns the proxy neighbor's information.
    
Return Value:

    STATUS_SUCCESS or STATUS_NOT_FOUND.

Caller IRQL: <= DISPATCH_LEVEL.
    
-*/
{
    KIRQL OldIrql;
    PLIST_ENTRY Next, Head = &Interface->ProxyNeighborSet.Head;
    USHORT AddressLength =
        Interface->Compartment->Protocol->Characteristics->AddressBytes;
    PIP_PROXY_NEIGHBOR ProxyNeighbor, Found = NULL;

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        ProxyNeighbor = (PIP_PROXY_NEIGHBOR)
            CONTAINING_RECORD(Next, IP_PROXY_NEIGHBOR, Link);

        if ((Prefix != NULL) &&
            (memcmp(IP_PROXY_NEIGHBOR_PREFIX(ProxyNeighbor),
                    Prefix,
                    AddressLength) <= 0)) {
            continue;
        }

        if ((Found != NULL) &&
            (memcmp(IP_PROXY_NEIGHBOR_PREFIX(ProxyNeighbor),
                    IP_PROXY_NEIGHBOR_PREFIX(Found),
                    AddressLength) >= 0)) {
            continue;
        }

        //
        // We have a (more) appropriate match.
        //
        Found = ProxyNeighbor;
    }

    if (Found != NULL) {
        Key->InterfaceLuid = Interface->Luid;
        RtlCopyMemory(Key->Prefix,
                      IP_PROXY_NEIGHBOR_PREFIX(Found),
                      AddressLength);
        if (Rw != NULL) {
            Rw->PrefixLength = Found->PrefixLength;
        }
    }

    RtlReleaseReadLock(&Interface->Lock, OldIrql);
    
    return (Found != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


NTSTATUS
IppGetNextProxyNeighbor(
    IN PIP_PROTOCOL Protocol,
    IN OUT PNL_PROXY_NEIGHBOR_KEY Key,
    OUT PNL_PROXY_NEIGHBOR_RW Rw
    )
/*++

Routine Description:

    Find the next proxy neighbor entry for the specified protocol.
    
Arguments:

    Protocol - Supplies the protocol to consider.

    Key - Supplies the previous proxy neighbor's key.
        Returns the next proxy neighbor's key.

    Rw - Returns the proxy neighbor's information.
        
Return Value:

    STATUS_SUCCESS or STATUS_NO_MORE_ENTRIES.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;
    PIP_INTERFACE Interface = NULL;
    NET_LUID InterfaceLuid = Key->InterfaceLuid;
    PUCHAR Prefix = Key->Prefix;
    
    //
    // Find the next proxy neighbor on the specified interface...
    //
    Interface = IppFindInterfaceByLuid(Protocol, &InterfaceLuid);
    if (Interface != NULL) {
        Status =
            IppGetNextProxyNeighborOnInterface(Interface, Prefix, Key, Rw);
        IppDereferenceInterface(Interface);
        if (NT_SUCCESS(Status)) {
            return Status;
        }
    }

    //
    // Failing which, find the first proxy neighbor on the next interface.
    //
    Interface = IppGetNextInterface(Protocol, &InterfaceLuid);
    while (Interface != NULL) {
        InterfaceLuid = Interface->Luid;
        Status =
            IppGetNextProxyNeighborOnInterface(Interface, NULL, Key, Rw);
        IppDereferenceInterface(Interface);
        if (NT_SUCCESS(Status)) {
            return Status;
        }
        Interface = IppGetNextInterface(Protocol, &InterfaceLuid);
    }
    
    return STATUS_NO_MORE_ENTRIES;
}

NTSTATUS
IppGetFirstProxyNeighbor(
    IN PIP_PROTOCOL Protocol,
    OUT PNL_PROXY_NEIGHBOR_KEY Key,
    OUT PNL_PROXY_NEIGHBOR_RW Rw
    )
/*++

Routine Description:

    Find the first proxy neighbor entry for the specified protocol.
    
Arguments:

    Protocol - Supplies the protocol to consider.

    Key - Returns the first proxy neighbor's key.

    Rw - Returns the proxy neighbor's information.
    
Return Value:

    STATUS_SUCCESS or STATUS_NO_MORE_ENTRIES.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;
    PIP_INTERFACE Interface;
    NET_LUID InterfaceLuid;

    Interface = IppGetFirstInterface(Protocol);
    while (Interface != NULL) {
        InterfaceLuid = Interface->Luid;
        Status = IppGetNextProxyNeighborOnInterface(Interface, NULL, Key, Rw);
        IppDereferenceInterface(Interface);
        if (NT_SUCCESS(Status)) {
            return Status;
        }
        Interface = IppGetNextInterface(Protocol, &InterfaceLuid);
    }
    
    return STATUS_NO_MORE_ENTRIES;
}


NTSTATUS
IppGetExactProxyNeighbor(
    IN PIP_PROTOCOL Protocol,
    IN CONST NL_PROXY_NEIGHBOR_KEY *Key,
    OUT PNL_PROXY_NEIGHBOR_RW Rw
    )
/*++

Routine Description:

    Find the exact proxy neighbor entry for the specified protocol.
    
Arguments:

    Protocol - Supplies the protocol to consider.

    Key - Supplies the proxy neighbor's key.

    Rw - Returns the proxy neighbor's information.
    
Return Value:

    STATUS_SUCCESS or STATUS_NOT_FOUND.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    KIRQL OldIrql;
    PIP_INTERFACE Interface;
    PIP_PROXY_NEIGHBOR Found = NULL;
    
    Interface = IppFindInterfaceByLuidUnderLock(Protocol, &Key->InterfaceLuid);
    if (Interface != NULL) {
        RtlAcquireReadLock(&Interface->Lock, &OldIrql);
        Found = IppFindProxyNeighbor(Interface, Key->Prefix, TRUE);
        if ((Found != NULL) && (Rw != NULL)) {
            Rw->PrefixLength = Found->PrefixLength;
        }
        RtlReleaseReadLock(&Interface->Lock, OldIrql);
        IppDereferenceInterface(Interface);
    }

    return (Found != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


NTSTATUS
NTAPI
IpGetAllProxyNeighborParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:
    
    Retreive all public parameters of a proxy neighbor entry.
    
Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNL_PROXY_NEIGHBOR_KEY Key = 
        (PNL_PROXY_NEIGHBOR_KEY) Args->KeyStructDesc.KeyStruct;
    PNL_PROXY_NEIGHBOR_RW Rw = 
        (PNL_PROXY_NEIGHBOR_RW) Args->StructDesc.RwParameterStruct;
    
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength ==
           SIZEOF_NL_PROXY_NEIGHBOR_KEY(
               Client->Protocol->Characteristics->NetworkProtocolId));

    switch (Args->Action) {
    case NsiGetExact:
        return IppGetExactProxyNeighbor(Client->Protocol, Key, Rw);

    case NsiGetFirst:
        return IppGetFirstProxyNeighbor(Client->Protocol, Key, Rw);

    case NsiGetNext:
        return IppGetNextProxyNeighbor(Client->Protocol, Key, Rw);

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }
}


NTSTATUS
NTAPI
IpSetAllProxyNeighborParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Create or destroy a proxy neighbor entry.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    USHORT AddressLength;
    
    PNL_PROXY_NEIGHBOR_KEY Key = 
        (PNL_PROXY_NEIGHBOR_KEY) Args->KeyStructDesc.KeyStruct;
    PNL_PROXY_NEIGHBOR_RW Rw = 
        (PNL_PROXY_NEIGHBOR_RW) Args->RwStructDesc.RwParameterStruct;
    PUCHAR Prefix;
    UINT8 PrefixLength;
    
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;
    AddressLength = Protocol->Characteristics->AddressBytes;
    
    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength ==
           SIZEOF_NL_PROXY_NEIGHBOR_KEY(
               Protocol->Characteristics->NetworkProtocolId));

    //
    // Transactions are not supported on ProxyNeighbors.
    //
    if (Args->Transaction != NsiTransactionNone) {
        return STATUS_INVALID_PARAMETER;
    }

    Prefix = Key->Prefix;
    if (Rw == NULL) {
        PrefixLength = (UINT8) AddressLength * RTL_BITS_OF(UINT8);
    } else {
        PrefixLength = Rw->PrefixLength;
    }
    
    //
    // Verify that we received a valid Prefix/PrefixLength.
    //
    if ((PrefixLength > AddressLength * RTL_BITS_OF(UINT8)) ||        
        !IppValidatePrefix(Prefix, PrefixLength, AddressLength) ||
        (Protocol->AddressType(Prefix) != NlatUnicast) ||
        INET_IS_ADDR_LOOPBACK(Protocol->Family, Prefix)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // All operations require a valid interface.
    //
    Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    switch (Args->Action) {
    case NsiSetCreateOnly:
        Status = IppCreateProxyNeighbor(Interface, Prefix, PrefixLength);
        break;

    case NsiSetDelete:
        Status = IppDestroyProxyNeighbor(Interface, Prefix);
        break;

    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    IppDereferenceInterface(Interface);
 
    return Status;
}
