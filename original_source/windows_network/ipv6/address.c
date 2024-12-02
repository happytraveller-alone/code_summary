/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    address.c

Abstract:

    This module implements the functions of the IPv6 Address Manager module.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "address.tmh"
#include "iBft.h"

NTSTATUS
Ipv6pStartAddressManager(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    Protocol->LocalMulticastAddressPool = FsbCreatePool(
        sizeof(IP_LOCAL_MULTICAST_ADDRESS) + sizeof(IN6_ADDR),
        0, 
        Ip6LocalMulticastAddressPoolTag,
        NULL);
    if (Protocol->LocalMulticastAddressPool == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv6 address manager: "
                   "Cannot allocate multicast address pool\n");
        Status = STATUS_BUFFER_OVERFLOW;
        goto ErrorMulticast;
    }

    Status = IppInitializeBlockType(
        &Protocol->LocalUnicastAddressBlockType,
        sizeof(IP_LOCAL_UNICAST_ADDRESS) + sizeof(IN6_ADDR),
        Ip6LocalUnicastAddressPoolTag);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv6 address manager: "
                   "Cannot allocate unicast address pool\n");
        goto ErrorUnicast;
    }

    Status = IppInitializeBlockType(
        &Protocol->LocalAnycastAddressBlockType,
        sizeof(IP_LOCAL_ANYCAST_ADDRESS) + sizeof(IN6_ADDR),
        Ip6LocalAnycastAddressPoolTag);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv6 address manager: "
                   "Cannot allocate anycast address pool\n");
        goto ErrorAnycast;
    }

    Status = IppInitializeBlockType(
        &Protocol->LocalAddressIdentifierBlockType,
        sizeof(IPV6_ADDRESS_IDENTIFIER),
        Ip6LocalAddressIdentifierPoolTag);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv6 address manager: "
                   "Cannot allocate address identifier pool\n");
        goto ErrorAddressIdentifier;
    }

    IppDefaultStartRoutine(Protocol, IMS_ADDRESS_MANAGER);

    return STATUS_SUCCESS;

ErrorAddressIdentifier:
    IppUninitializeBlockType(&Protocol->LocalAnycastAddressBlockType);
ErrorAnycast:
    IppUninitializeBlockType(&Protocol->LocalUnicastAddressBlockType);
ErrorUnicast:
    FsbDestroyPool(Protocol->LocalMulticastAddressPool);
ErrorMulticast:
    return Status;
}

VOID
Ipv6pLeaveGroupAtMultipleScopes(
    IN PIP_INTERFACE Interface,
    IN CONST IN6_ADDR *GroupAddress,
    IN SCOPE_LEVEL MaxScope
    )
/*++

Routine Description:

    Leave a multicast group at all scopes up to the specified scope.

Arguments:

    Interface - Supplies the interface on which to leave.

    GroupAddress - Supplies the address of the group to leave.

    MaxScope - Supplies the highest scope level at which to leave.

Locks:
    
    Assumes caller holds a write lock on the interface.

Caller IRQL:

    Must be called at DISPATCH since a lock is held.

--*/
{
    SCOPE_LEVEL Level;
    IN6_ADDR Address = *GroupAddress;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    for (Level = ScopeLevelInterface;
         ((Level <= MaxScope) && (Level <= ScopeLevelGlobal));
         Level++) {

        Address.s6_bytes[1] = (UCHAR)((Address.s6_bytes[1] & 0xf0) | Level);

        IppFindAndDereferenceMulticastGroup(Interface, (PUCHAR) &Address);
    }
}

NTSTATUS
Ipv6pJoinGroupAtMultipleScopes(
    IN PIP_INTERFACE Interface,
    IN CONST IN6_ADDR *GroupAddress,
    IN SCOPE_LEVEL MaxScope
    )
/*++

Routine Description:

    Join a multicast group at all scopes up to the specified scope.

    If we return success or pending, the caller is responsible for calling
    Ipv6pLeaveGroupAtMultipleScopes.

Arguments:

    Interface - Supplies the interface on which to join.

    GroupAddress - Supplies the address of the group to join.

    MaxScope - Supplies the highest scope level at which to join.

Return Value:

    STATUS_SUCCESS, STATUS_PENDING, or an appropriate failure status.

--*/
{
    SCOPE_LEVEL Level;
    IN6_ADDR Address = *GroupAddress;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_LOCAL_MULTICAST_ADDRESS LocalAddress;
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    for (Level = ScopeLevelInterface;
         ((Level <= MaxScope) && (Level <= ScopeLevelGlobal));
         Level++) {

        Address.s6_bytes[1] = (UCHAR)((Address.s6_bytes[1] & 0xf0) | Level);

        //
        // This may return STATUS_PENDING, but we'll keep our reference anyway.
        // REVIEW: This means we currently ignore the failure if it's 
        // asynchronous, but fail if it's synchronous.
        //
        Status = IppFindOrCreateLocalMulticastAddressUnderLock(
            (PUCHAR) &Address,
            Interface,
            NULL,    
            &LocalAddress);
        if (!NT_SUCCESS(Status)) {
            if (Level > ScopeLevelInterface) {
                Ipv6pLeaveGroupAtMultipleScopes(Interface,
                                                GroupAddress,
                                                Level-1);
            }
            break;
        }
    }

    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    return Status;
}


VOID
Ipv6pFindAndReleaseSolicitedNodeGroup(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    Finds the entry for the corresponding solicited-node multicast address and
    releases one reference for the entry. May result in the entry disappearing.

Arguments:

    Interface - Supplies the interface.

    Address - Supplies a unicast/anycast address.
    
Return Value:

    None.
    
Locks: 

    Called with the interface lock held. 

--*/     
{
    IN6_ADDR GroupAddress;
    PIP_LOCAL_MULTICAST_ADDRESS LocalAddress;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // Only interfaces that support Neighbor Discovery
    // use solicited-node multicast addresses.
    //    
    if (Interface->FlCharacteristics->DiscoversNeighbors) {
        //
        // Create the corresponding solicited-node multicast address.
        //
        IN6_SET_ADDR_SOLICITEDNODE(&GroupAddress, (IN6_ADDR*)Address);

        //
        // Find the entry for the solicited-node multicast address.
        //
        LocalAddress = 
            IppFindMulticastAddressOnInterfaceUnderLock(
                Interface, 
                (PUCHAR) &GroupAddress);
        if (LocalAddress != NULL) {
            IppModifyMulticastGroupUnderLock(
                LocalAddress,
                MCAST_EXCLUDE,
                0, 
                NULL,
                MCAST_INCLUDE, 
                0,
                NULL,
                NULL);
            //
            // Release the entry for the solicited-node multicast address.
            // The Find function takes a reference, so release twice.
            //
            IppDereferenceLocalMulticastAddressUnderLock(LocalAddress);
            IppDereferenceLocalMulticastAddressUnderLock(LocalAddress);
        }
    }
}


NTSTATUS
Ipv6pFindOrCreateSolicitedNodeGroup(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    If an entry for the solicited-node multicast address already exists,
    just bump the reference count. Otherwise create a new entry.

    If success or pending is returned, takes a reference on the
    entry for the caller.  The caller is responsible for calling
    Ipv6pFindAndReleaseSolicitedNodeGroup even if we later got a failure
    after returning pending.

Arguments:

    Interface - Supplies the interface.

    Address - Supplies a unicast/anycast address.
    
Return Value:

    STATUS_SUCCESS, STATUS_PENDING, or failure code.
    
Locks: 

    Called with the interface lock held. 

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    IN6_ADDR GroupAddress;
    PIP_LOCAL_MULTICAST_ADDRESS LocalAddress;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // Only interfaces that support Neighbor Discovery
    // use solicited-node multicast addresses.
    //
    if (Interface->FlCharacteristics->DiscoversNeighbors) {
        //
        // Create the corresponding solicited-node multicast address.
        //
        IN6_SET_ADDR_SOLICITEDNODE(&GroupAddress, (IN6_ADDR*)Address);

        //
        // Find or create an entry for the solicited-node multicast address.
        //
        Status = IppFindOrCreateLocalMulticastAddressUnderLock(
            (PUCHAR) &GroupAddress,
            Interface,
            NULL,
            &LocalAddress);

        //
        // Report the address.
        //
        if (NT_SUCCESS(Status)) {
            Status = 
                IppModifyMulticastGroupUnderLock(
                    LocalAddress,
                    MCAST_INCLUDE,
                    0, 
                    NULL,
                    MCAST_EXCLUDE, 
                    0,
                    NULL,
                    NULL);
        }
    }
    
    return Status;
}


VOID
Ipv6pUnAddressInterface(
    IN PIP_INTERFACE Interface
    )
{
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    IppUnAddressInterfaceUnderLock(Interface);
    
    //
    // Leave the all nodes multicast groups.
    //
    if (Interface->FlCharacteristics->Multicasts) {    
        Ipv6pLeaveGroupAtMultipleScopes(
            Interface, 
            &in6addr_allnodesonlink,
            ScopeLevelLink);
    }
    
    if (Interface->Advertise) {
        Interface->Compartment->Protocol->StopAdvertising(Interface);
        //
        // Restore the interface's advertising state.
        //
        Interface->Advertise = TRUE;
    }

    //
    // Also stop the router discovery protocol.
    //
    if (Interface->UseRouterDiscovery) {
        IppStopRouterDiscovery(Interface);
    }

    //
    // Cancel all the multicast timers. This is to ensure that the
    // multicast groups can get deleted. 
    //
    IppResetAllMulticastGroups(Interface);
}


NTSTATUS
Ipv6pAddLinkLayerSuffixAddresses(
    IN PIP_INTERFACE Interface
)
/*++

Routine Description:

    This routine generates addresses on the interface which use the link layer
    address as the suffix.  This is called when we initialize the interface and
    also when the link layer address of the interface changes and we need to
    regenerate these addresses. 

Arguments:

    Interface - Supplies the interface to generate an addresses on.

Return Value:

    Returns STATUS_SUCCESS or the appropriate failure code.  Caller is
    responsible for cleaning up if required in case of failure. 

Locks:

    Assumes caller holds a reference on Interface.
    Assumes caller holds the interface write lock.

Caller IRQL: DISPATCH.

--*/
{
    NTSTATUS Status;
    IN6_ADDR Address ={0};
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    ULONG IdentifierLength = Interface->FlCharacteristics->IdentifierLength;
 
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    //
    // Do nothing for the loopback interface.  Someone might change the DL
    // address of the loopback interface through the FL NSI provider.  In that
    // case, this function could be called for the loopback interface. 
    //
    if (IS_LOOPBACK_INTERFACE(Interface)) {
        return STATUS_SUCCESS;
    }
    
    //
    // Generate the link local address. 
    //
    ASSERT((IdentifierLength % RTL_BITS_OF(UINT8)) == 0);
    IdentifierLength = IdentifierLength / RTL_BITS_OF(UINT8);
    RtlCopyMemory(
        Address.s6_addr,
        &in6addr_linklocalprefix,
        sizeof(IN6_ADDR) - IdentifierLength);
    RtlCopyMemory(
        Address.s6_addr + sizeof(IN6_ADDR) - IdentifierLength,
        Interface->Identifier,
        IdentifierLength);

    //
    // Don't add the link local address if it conflicts with an anycast
    // address. 
    //
    if (IN6_IS_ADDR_ANYCAST((CONST IN6_ADDR*)&Address)) {
        return STATUS_SUCCESS;
    }
    
    Status =
        IppFindOrCreateLocalUnicastAddress(
            (CONST UCHAR *)&Address,
            Interface,
            ADDR_CONF_LINK,
            INFINITE_LIFETIME, 
            INFINITE_LIFETIME,
            IN6ADDR_LINKLOCALPREFIX_LENGTH,
            TRUE,
            &LocalAddress);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: [%u] Failure adding link local address %!IPV6!\n",
                   Interface->Index, (CONST UCHAR*)&Address);
        return Status;
    }

    Interface->LinkLocalAddress.Ipv6 = Address;

    IppDereferenceLocalUnicastAddress(LocalAddress);
    return STATUS_SUCCESS;
}

NTSTATUS
Ipv6pConfigureIscsiAddress(
    IN PIP_INTERFACE Interface,
    PISCSI_BOOT_NIC TcpipIscsiBootParameters
    )
/*++
Routine Description:
    This routine configures an ip address on the interface from which 
    we intend to boot if applicable. The ip address is passed to us from 
    the firmware in  TcpipIscsiBootParameters. The MAC address in this 
    struct is used to identify the interface from which we are booting. 

Arguments :
    Interface - Interface that is being addressed.
    TcpipIscsiBootParameters - Boot parameters read from the firmware.

Return Value:
    Returns the STATUS_SUCCESS or the appropriate failure code.  
--*/    
{

    IPV6_LOCAL_ADDRESS_KEY AddressKey = {0};
    
    RtlCopyMemory(&AddressKey.Address,TcpipIscsiBootParameters->IpAddress,
        sizeof(IN6_ADDR));    
    
    AddressKey.InterfaceLuid = Interface->Luid;    
    
    return 
        IppConfigureIscsiAddress(
            Interface,
            (PNL_LOCAL_ADDRESS_KEY)&AddressKey,
            TcpipIscsiBootParameters);      
}

NTSTATUS 
Ipv6pConfigureIscsiRoutes(
    IN PIP_INTERFACE Interface,
    PISCSI_BOOT_NIC TcpipIscsiBootParameters,
    ULONG NumberTargets
    )
/*++
Routine Description:
    This routine configures the routes on the interface from which 
    we intend to boot if applicable. The default gateway is passed to us from 
    the firmware in  TcpipIscsiBootParameters. The MAC address in this 
    struct is used to identify the interface from which we are booting. 

Arguments :
    Interface - Interface that is being addressed.
    TcpipIscsiBootParameters - Boot parameters read from the firmware.
    NumberTargets - Number of Targets to which host routes are to be added.

Return Value:
    Returns the STATUS_SUCCESS or the appropriate failure code.  
--*/  
{
    //
    // If the gateway is an IPV4 address then this is a misconfiguration.
    //
    if (IN6_IS_ADDR_V4MAPPED((IN6_ADDR*)TcpipIscsiBootParameters->Gateway)) {
        return STATUS_INVALID_PARAMETER;
    } 
    
    return IppConfigureIscsiTargetAndDefaultRoutes(
        Interface,
        TcpipIscsiBootParameters,
        NumberTargets,
        TcpipIscsiBootParameters->Gateway);
}

NTSTATUS
Ipv6pConfigureIscsiInterface(
    IN PIP_INTERFACE Interface
    )
/*++
Routine Description:

--*/
{
    PISCSI_BOOT_NIC TcpipIscsiBootParameters = NULL;
    UCHAR Key[IF_MAX_PHYS_ADDRESS_LENGTH];
    NTSTATUS Status = STATUS_MORE_ENTRIES;                
    ULONG NumberTargets = 0;

    __analysis_assume(
        Interface->FlCharacteristics->DlAddressLength < 
        IF_MAX_PHYS_ADDRESS_LENGTH);
    
    RtlCopyMemory(
        Key,
        Interface->FlCharacteristics->DlAddress,
        Interface->FlCharacteristics->DlAddressLength);

    Status = NetioAllocateAndGetIbftTable(
        Key,
        Interface->FlCharacteristics->DlAddressLength,
        &TcpipIscsiBootParameters,
        &NumberTargets, 
        AF_INET6);
    if (!NT_SUCCESS(Status)) {
        Status = STATUS_SUCCESS;
        goto Error;
    }

    Status = Ipv6pConfigureIscsiAddress(Interface,TcpipIscsiBootParameters);
    if (!NT_SUCCESS(Status)) {
        goto Error;
    }
    
    //
    // If there is a default gateway add that as well.
    //
    Status = 
        Ipv6pConfigureIscsiRoutes(Interface, TcpipIscsiBootParameters, NumberTargets);
    if (!NT_SUCCESS(Status)) {
        goto Error;
    }

Error:
    NetioFreeIbftTable(TcpipIscsiBootParameters);       
    return Status;    
}

NTSTATUS
Ipv6pAddressInterface(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    This routine generates a link-local unicast address on a given interface.
    It also joins relevant multicast groups and reads persistent address state.
    
Arguments:

    Interface - Supplies the interface to generate an address on.

Return Value:

    Returns the STATUS_SUCCESS or the appropriate failure code.  Caller is
    responsible for cleaning up if required in case of failure. 

Locks:

    Assumes caller holds a reference on Interface.
    Locks the global interface set for reading.
    Locks the interface for writing.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    NTSTATUS Status;
    ULONG i, Count;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    BOOLEAN IsLoopback;
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    KLOCK_QUEUE_HANDLE LockHandle;

    PIPV6_LOCAL_ADDRESS_KEY AddressKey;
    PNL_LOCAL_UNICAST_ADDRESS_RW AddressRw;
    PIPV6_ROUTE_KEY RouteKey;
    PNL_ROUTE_RW RouteRw;
    
    PASSIVE_CODE();
    
    //
    // Compose an IPv6 link-local address.
    //
    if (IS_LOOPBACK_INTERFACE(Interface)) {
        Interface->Compartment->LoopbackIndex = Interface->Index;
        IsLoopback = TRUE;
    } else {
        IsLoopback = FALSE;

        //
        // Join the appropriate all nodes groups.
        //
        if (Interface->FlCharacteristics->Multicasts) {
            Status = Ipv6pJoinGroupAtMultipleScopes(Interface,
                                                    &in6addr_allnodesonlink,
                                                    ScopeLevelLink);
            if (!NT_SUCCESS(Status)) {
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                    "IPNG: [%u] Failure joining multicast group %!IPV6!\n",
                    Interface->Index, (CONST UCHAR*)&in6addr_allnodesonlink);
                return Status;
            }
        }
    }
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    {
        if (!IsLoopback) {
            //
            // Depending on the interface link-local address configuration
            // behavior, add link-local addresses or start the link-local
            // address configuration state machine. 
            //
            Status = IppStartLinkLocalAddressConfiguration(Interface);
            if (!NT_SUCCESS(Status)) {
                RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
                return Status;
            }
        } else {
            Status =
                IppFindOrCreateLocalUnicastAddress(
                    (CONST UCHAR *) &in6addr_loopback,
                    Interface,
                    ADDR_CONF_LINK,
                    INFINITE_LIFETIME,
                    INFINITE_LIFETIME,
                    RTL_BITS_OF(IN6_ADDR),
                    TRUE,
                    &LocalAddress);
            if (!NT_SUCCESS(Status)) {
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                    "IPNG: [%u] Failure creating loopback address %!IPV6!\n",
                    Interface->Index, (CONST UCHAR*)&in6addr_loopback);
                RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
                return Status;
            }
            IppDereferenceLocalUnicastAddress(LocalAddress);
        }

        if (Interface->Advertise) {
            Status = Protocol->StartAdvertising(Interface);
            if (!NT_SUCCESS(Status)) {
                RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
                return Status;
            }                
        }
    }
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    //
    // Add the iSCSI interface address if booting from an iSCSI disk.
    //
    Status = Ipv6pConfigureIscsiInterface(Interface);
    if (!NT_SUCCESS(Status)) {
        //
        // Ignore failures so the interface can be initialized.
        //
        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
            "IPNG: [%u] iBFT configuration failed. Error %d\n",
            Interface->Index, Status);
    }
    
    //
    // Read persistent local unicast addresses.
    //
    Status =
        NsiAllocateAndGetTable(
            NsiPersistent,
            Protocol->ModuleId,
            NlLocalUnicastAddressObject,
            &AddressKey, sizeof(*AddressKey),
            &AddressRw, sizeof(*AddressRw),
            NULL, 0,
            NULL, 0,
            &Count,
            FALSE);
    if (NT_SUCCESS(Status)) {
        NM_REQUEST_SET_ALL_PARAMETERS Args = {0};

        Args.ProviderHandle = Protocol->NmClientContext;
        Args.KeyStructDesc.KeyStructLength = sizeof(*AddressKey);
        Args.RwStructDesc.RwParameterStructLength = sizeof(*AddressRw);
        Args.Action = NsiSetCreateOrSet;
        
        for (i = 0; i < Count; i++) {

            if (!RtlEqualMemory(
                    &AddressKey[i].InterfaceLuid,
                    &Interface->Luid,
                    sizeof(Interface->Luid))) {
                continue;
            }

            Args.KeyStructDesc.KeyStruct = (PUCHAR) &AddressKey[i];
            Args.RwStructDesc.RwParameterStruct = (PUCHAR) &AddressRw[i];

            Status = IppSetAllLocalAddressParameters(&Args, NlatUnicast);
            if (!NT_SUCCESS(Status)) {
                //
                // Ignore failures so the interface can be initialized.
                //
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                    "IPNG: [%u] Persistent address %!IPV6! creation failed\n",
                    Interface->Index, (CONST UCHAR *) &AddressKey[i].Address);
            }
        }

        NsiFreeTable(AddressKey, AddressRw, NULL, NULL);
    }

    //
    // Read persistent local anycast addresses.
    //
    Status =
        NsiAllocateAndGetTable(
            NsiPersistent,
            Protocol->ModuleId,
            NlLocalAnycastAddressObject,
            &AddressKey, sizeof(*AddressKey),
            NULL, 0,
            NULL, 0,
            NULL, 0,
            &Count,
            FALSE);
    if (NT_SUCCESS(Status)) {
        NM_REQUEST_SET_ALL_PARAMETERS Args = {0};

        Args.ProviderHandle = Protocol->NmClientContext;
        Args.KeyStructDesc.KeyStructLength = sizeof(*AddressKey);
        Args.Action = NsiSetCreateOrSet;
        
        for (i = 0; i < Count; i++) {

            if (!RtlEqualMemory(
                    &AddressKey[i].InterfaceLuid,
                    &Interface->Luid,
                    sizeof(Interface->Luid))) {
                continue;
            }

            Args.KeyStructDesc.KeyStruct = (PUCHAR) &AddressKey[i];

            Status = IppSetAllLocalAddressParameters(&Args, NlatAnycast);
            if (!NT_SUCCESS(Status)) {
                //
                // Ignore failures so the interface can be initialized.
                //
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                    "IPNG: [%u] Persistent address %!IPV6! creation failed\n",
                    Interface->Index, (CONST UCHAR *) &AddressKey[i].Address);
            }
        }

        NsiFreeTable(AddressKey, NULL, NULL, NULL);
    }

    //
    // Read persistent routes.
    //
    Status =
        NsiAllocateAndGetTable(
            NsiPersistent,
            Protocol->ModuleId,
            NlRouteObject,
            &RouteKey, sizeof(*RouteKey),
            &RouteRw, sizeof(*RouteRw),
            NULL, 0,
            NULL, 0,
            &Count,
            FALSE);    
    if (NT_SUCCESS(Status)) {
        for (i = 0; i < Count; i++) {
            if (!RtlEqualMemory(
                    &RouteKey[i].InterfaceLuid,
                    &Interface->Luid,
                    sizeof(IF_LUID))) {
                continue;
            }

            //
            // We care only about loopback or on-link routes now.
            // The rest are initialized during sub-interface initialization.
            //
            if (!IN6_IS_ADDR_UNSPECIFIED(&RouteKey[i].NextHopAddress)) {
                continue;
            }

            Status =
                IppUpdateUnicastRoute(
                    NsiSetCreateOrSet,
                    Interface,
                    NULL,
                    (PUCHAR) &RouteKey[i].DestinationPrefix, 
                    RouteKey[i].DestinationPrefixLength,
                    (PUCHAR) &RouteKey[i].SourcePrefix, 
                    RouteKey[i].SourcePrefixLength, 
                    NlroManual,
                    &RouteRw[i],
                    (PUCHAR) &RouteKey[i].NextHopAddress);
            if (!NT_SUCCESS(Status)) {
                //
                // Ignore failures so the interface can be initialized.
                //
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                    "IPNG: [%u] Persistent route %!IPV6!/%u creation failed\n",
                    Interface->Index,
                    (CONST UCHAR *) &RouteKey[i].DestinationPrefix,
                    RouteKey[i].DestinationPrefixLength);
            }
        }

        NsiFreeTable(RouteKey, RouteRw, NULL, NULL);
    }

    //
    // Initialize multicast route. This route will go away when the 
    // interface gets deleted.
    //
    if (Interface->FlCharacteristics->Multicasts) {
        Status =
            IppUpdateUnicastRoute(
                NsiSetCreateOrSet,
                Interface,
                NULL,
                (PUCHAR) &in6addr_multicastprefix, 
                IN6ADDR_MULTICASTPREFIX_LENGTH,
                NULL, 
                0, 
                NlroWellKnown,
                NULL,
                NULL);
        if (!NT_SUCCESS(Status)) {
            //
            // Ignore failures so the interface can be initialized.
            //
            NetioTrace(
                NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                "IPNG: [%u] Multicast route %!IPV6!/%u creation failed\n",
                Interface->Index,
                (CONST UCHAR *) &in6addr_multicastprefix,
                IN6ADDR_MULTICASTPREFIX_LENGTH);
        }
    }
    return STATUS_SUCCESS;
}


NTSTATUS
Ipv6pInitializeSubInterface(
    IN PIP_SUBINTERFACE SubInterface
    )
{
    NTSTATUS Status;
    ULONG i, Count;
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIPV6_NEIGHBOR_KEY NeighborKey;
    PNL_NEIGHBOR_RW NeighborRw;
    PIPV6_ROUTE_KEY RouteKey;
    PNL_ROUTE_RW RouteRw;

    //
    // Read persistent neighbors.
    //
    Status =
        NsiAllocateAndGetTable(
            NsiPersistent,
            Protocol->ModuleId,
            NlNeighborObject,
            &NeighborKey, sizeof(*NeighborKey),
            &NeighborRw, sizeof(*NeighborRw),
            NULL, 0,
            NULL, 0,
            &Count,
            FALSE);
    if (NT_SUCCESS(Status)) {
        for (i = 0; i < Count; i++) {
            if (!RtlEqualMemory(
                    &NeighborKey[i].InterfaceLuid, 
                    &Interface->Luid, 
                    sizeof(IF_LUID))) {
                continue;
            }

            if (!RtlEqualMemory(
                    &NeighborKey[i].SubInterfaceLuid,
                    &SubInterface->Luid,
                    sizeof(IF_LUID))) {
                continue;
            }

            Status =
                IppSetAllNeighborParametersHelper(
                    SubInterface,
                    (PUCHAR) &NeighborKey[i].Address,
                    &NeighborRw[i],
                    NsiSetCreateOrSet);
            if (!NT_SUCCESS(Status)) {
                //
                // Ignore failures so the sub-interface can be initialized.
                //
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                    "IPNG: [%u] Persistent neighbor %!IPV6! creation failed\n",
                    Interface->Index, (CONST UCHAR *) &NeighborKey[i].Address);

            }
        }

        NsiFreeTable(NeighborKey, NeighborRw, NULL, NULL);
    }

    //
    // Read persistent routes.
    //
    Status =
        NsiAllocateAndGetTable(
            NsiPersistent,
            Protocol->ModuleId,
            NlRouteObject,
            &RouteKey, sizeof(*RouteKey),
            &RouteRw, sizeof(*RouteRw),
            NULL, 0,
            NULL, 0,
            &Count,
            FALSE);    
    if (NT_SUCCESS(Status)) {
        for (i = 0; i < Count; i++) {
            if (!RtlEqualMemory(
                    &RouteKey[i].InterfaceLuid,
                    &Interface->Luid,
                    sizeof(IF_LUID))) {
                continue;
            }

            if (!RtlEqualMemory(
                    &RouteKey[i].SubInterfaceLuid,
                    &SubInterface->Luid,
                    sizeof(IF_LUID))) {
                continue;
            }

            Status =
                IppUpdateUnicastRoute(
                    NsiSetCreateOrSet,
                    Interface,
                    SubInterface,
                    (PUCHAR) &RouteKey[i].DestinationPrefix, 
                    RouteKey[i].DestinationPrefixLength,
                    (PUCHAR) &RouteKey[i].SourcePrefix, 
                    RouteKey[i].SourcePrefixLength, 
                    NlroManual,
                    &RouteRw[i],
                    (PUCHAR) &RouteKey[i].NextHopAddress);
            if (!NT_SUCCESS(Status)) {
                //
                // Ignore failures so the sub-interface can be initialized.
                //
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                    "IPNG: [%u] Persistent route %!IPV6!/%u creation failed\n",
                    Interface->Index,
                    (CONST UCHAR *) &RouteKey[i].DestinationPrefix,
                    RouteKey[i].DestinationPrefixLength);
            }
        }

        NsiFreeTable(RouteKey, RouteRw, NULL, NULL);
    }

    return STATUS_SUCCESS;
}
