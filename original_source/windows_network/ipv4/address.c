/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    address.c

Abstract:

    This module implements the functions of the IPv4 Address Manager module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "address.tmh"
#include "iBft.h"

NTSTATUS
Ipv4pStartAddressManager(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    Protocol->LocalMulticastAddressPool = FsbCreatePool(
        sizeof(IP_LOCAL_MULTICAST_ADDRESS) + sizeof(IN_ADDR),
        0, 
        Ip4LocalMulticastAddressPoolTag,
        NULL);
    if (Protocol->LocalMulticastAddressPool == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv4 address manager: "
                   "Cannot allocate multicast address pool\n");
        Status = STATUS_BUFFER_OVERFLOW;
        goto ErrorMulticast;
    }

    Status = IppInitializeBlockType(
        &Protocol->LocalUnicastAddressBlockType,
        sizeof(IP_LOCAL_UNICAST_ADDRESS) + sizeof(IN_ADDR),
        Ip4LocalUnicastAddressPoolTag);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv4 address manager: "
                   "Cannot allocate unicast address pool\n");
        goto ErrorUnicast;
    }

    Status = IppInitializeBlockType(
        &Protocol->LocalBroadcastAddressBlockType,
        sizeof(IP_LOCAL_BROADCAST_ADDRESS) + sizeof(IN_ADDR),
        Ip4LocalBroadcastAddressPoolTag);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv4 address manager: "
                   "Cannot allocate broadcast address pool\n");
        goto ErrorBroadcast;
    }

    Status = IppInitializeBlockType(
        &Protocol->LocalAddressIdentifierBlockType,
        sizeof(IPV4_ADDRESS_IDENTIFIER),
        Ip4LocalAddressIdentifierPoolTag);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error starting IPv4 address manager: "
                   "Cannot allocate address identifier pool\n");
        goto ErrorAddressIdentifier;
    }

    IppDefaultStartRoutine(Protocol, IMS_ADDRESS_MANAGER);

    return STATUS_SUCCESS;

ErrorAddressIdentifier:
    IppUninitializeBlockType(&Protocol->LocalBroadcastAddressBlockType);
ErrorBroadcast:
    IppUninitializeBlockType(&Protocol->LocalUnicastAddressBlockType);
ErrorUnicast:
    FsbDestroyPool(Protocol->LocalMulticastAddressPool);
ErrorMulticast:
    return Status;
}

VOID
Ipv4pUnAddressInterface(
    IN PIP_INTERFACE Interface
    )
{
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    IppUnAddressInterfaceUnderLock(Interface);
    
    //
    // Leave the all nodes on link multicast group.
    //
    IppFindAndDereferenceMulticastGroup(Interface, 
                                        (PUCHAR)&in4addr_allnodesonlink);

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
Ipv4pAddLinkLayerSuffixAddresses(
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
    IN_ADDR Address;
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    CONST UCHAR *Identifier = Interface->Identifier;
    ULONG IdentifierLength = Interface->FlCharacteristics->IdentifierLength;
    IN_ADDR MachineId = {0};
    ULONG MachineIdLength =0;
    ULONG SubnetMask = 0;
    ULONG PrefixLength = Ipv4Global.LinkLocalAddressPrefixLength;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    //
    // Do nothing for the loopback interface.  Someone might change the DL
    // address of the loopback interface through the FL NSI provider.
    // In that case, this function could be called for the loopback interface. 
    // 
    if (IS_LOOPBACK_INTERFACE(Interface)) {
        return STATUS_SUCCESS;
    }
    ASSERT((IdentifierLength % RTL_BITS_OF(UINT8)) == 0);
    IdentifierLength = IdentifierLength / RTL_BITS_OF(UINT8);
    Identifier += IdentifierLength;

    MachineIdLength = (sizeof(IN_ADDR) < IdentifierLength) ?
                       sizeof(IN_ADDR) : IdentifierLength;
    RtlCopyMemory(&MachineId,
                  Identifier-MachineIdLength,
                  MachineIdLength);

    Status = 
        ConvertLengthToIpv4Mask(PrefixLength,&SubnetMask);    
    
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    Address = Ipv4Global.LinkLocalAddressPrefix.Ipv4;
    Address.S_un.S_addr &= SubnetMask;
        
    MachineId.S_un.S_addr &= ~SubnetMask;
    Address.S_un.S_addr |= MachineId.S_un.S_addr;
 
    Status =
        IppFindOrCreateLocalUnicastAddress(
            (CONST UCHAR *)&Address,
            Interface,
            ADDR_CONF_LINK,
            INFINITE_LIFETIME, 
            INFINITE_LIFETIME,
            PrefixLength,
            TRUE, 
            &LocalAddress);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: [%u] Failure adding link local address %!IPV4!\n",
                   Interface->Index, (CONST UCHAR*)&Address);
        return Status;
    }

    Interface->LinkLocalAddress.Ipv4 = Address;
    
    IppDereferenceLocalUnicastAddress(LocalAddress);
    return STATUS_SUCCESS;
}

NTSTATUS
Ipv4pConfigureIscsiAddress(
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
    IPV4_LOCAL_ADDRESS_KEY AddressKey = {0};
    
    RtlCopyMemory(&AddressKey.Address,
        IN6_GET_ADDR_V4MAPPED((IN6_ADDR*)TcpipIscsiBootParameters->IpAddress),
        sizeof(IN_ADDR));
    
    AddressKey.InterfaceLuid = Interface->Luid;    
    
    return 
        IppConfigureIscsiAddress(
            Interface,
            (PNL_LOCAL_ADDRESS_KEY)&AddressKey,
            TcpipIscsiBootParameters);
}

NTSTATUS 
Ipv4pConfigureIscsiRoutes(
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
    // If the gateway is an IPV6 address then this is a misconfiguration.
    //
    if (!IN6_IS_ADDR_V4MAPPED((IN6_ADDR*)TcpipIscsiBootParameters->Gateway) &&
        (RtlCompareMemory(
            TcpipIscsiBootParameters->Gateway,
            &in6addr_any,
            sizeof(IN6_ADDR)) == 0)) {
        return STATUS_INVALID_PARAMETER;
    } 
        
    return IppConfigureIscsiTargetAndDefaultRoutes(
        Interface,
        TcpipIscsiBootParameters,
        NumberTargets,
        (PUCHAR)IN6_GET_ADDR_V4MAPPED(
            (IN6_ADDR*)TcpipIscsiBootParameters->Gateway));
}

NTSTATUS
Ipv4pConfigureIscsiInterface(
    IN PIP_INTERFACE Interface
    )
/*++
Routine Description:
    This routine configures the interface from which we intend to boot if 
    applicable. The NIC offset will tell us which firmware configuration to 
    use.

Arguments :
    Interface - Interface that is being addressed.

Return Value:
    Returns the STATUS_SUCCESS or the appropriate failure code.  
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
        AF_INET);
    if (!NT_SUCCESS(Status)) {
        Status = STATUS_SUCCESS;
        goto Error;
    }

    Status = 
        Ipv4pConfigureIscsiAddress(Interface,TcpipIscsiBootParameters);
    if (!NT_SUCCESS(Status)) {
        goto Error;
    }
    
    //
    // If there is a default gateway add that as well.
    //
    Status = 
        Ipv4pConfigureIscsiRoutes(
            Interface,
            TcpipIscsiBootParameters,
            NumberTargets);
    if (!NT_SUCCESS(Status)) {
        goto Error;
    }

Error:
    NetioFreeIbftTable(TcpipIscsiBootParameters);
    return Status;
}

NTSTATUS
Ipv4pAddressInterface(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    This routine generates a link-local unicast address on a given interface.
    It also joins the relevant multicast groups, adds the broadcast address and
    reads the persistent address state.

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

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status;
    ULONG i, Count;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    BOOLEAN IsLoopback;
    PUCHAR BroadcastAddressLiteral;
    PIP_LOCAL_UNICAST_ADDRESS LocalAddress;
    PIP_LOCAL_MULTICAST_ADDRESS GroupAddress;
    PIP_LOCAL_BROADCAST_ADDRESS BroadcastAddress;
    KLOCK_QUEUE_HANDLE LockHandle;

    PIPV4_LOCAL_ADDRESS_KEY AddressKey;
    PNL_LOCAL_UNICAST_ADDRESS_RW AddressRw;
    PIPV4_ROUTE_KEY RouteKey;
    PNL_ROUTE_RW RouteRw;    
    
    //
    // Compose an IPv4 link-local address.
    //
    if (IS_LOOPBACK_INTERFACE(Interface)) {
        Interface->Compartment->LoopbackIndex = Interface->Index;
        IsLoopback = TRUE;
    } else {
        IsLoopback = FALSE;
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
            
            //
            // Join the all nodes on link multicast group.  This may return 
            // STATUS_PENDING, but we'll keep our reference anyway.   
            // REVIEW: This means we currently ignore the failure if it's 
            // asynchronous, but fail to address the interface if it's
            // synchronous.
            //
            Status =
                IppFindOrCreateLocalMulticastAddressUnderLock(
                    (PUCHAR) &in4addr_allnodesonlink,
                    Interface,
                    NULL,
                    &GroupAddress);
            if (!NT_SUCCESS(Status)) {
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                    "IPNG: [%u] Failure joining multicast group %!IPV4!\n",
                    Interface->Index, (CONST UCHAR*)&in4addr_allnodesonlink);
                RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
                return Status;
            }
        } else {
            //
            // Add the loopback address for the loopback interface.
            //
            Status =
                IppFindOrCreateLocalUnicastAddress(
                    (CONST UCHAR *)&in4addr_loopback,
                    Interface,
                    ADDR_CONF_WELLKNOWN,
                    INFINITE_LIFETIME, 
                    INFINITE_LIFETIME,
                    IN4ADDR_LOOPBACKPREFIX_LENGTH,
                    TRUE,
                    &LocalAddress);
            if (!NT_SUCCESS(Status)) {
                NetioTrace(
                    NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                    "IPNG: [%u] Failure creating loopback address %!IPV4!\n", 
                    Interface->Index, (CONST UCHAR*)&in4addr_loopback);
                RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
                return Status;
            }
            IppDereferenceLocalUnicastAddress(LocalAddress);
        }

        //
        // Join the broadcast address. 
        //
        BroadcastAddressLiteral =
            Interface->UseZeroBroadcastAddress
            ? (PUCHAR)&in4addr_any
            : (PUCHAR)&in4addr_broadcast, 
        Status =
            IppFindOrCreateLocalBroadcastAddress(
                BroadcastAddressLiteral,
                Interface, 
                ADDR_CONF_MANUAL, 
                FALSE,
                &BroadcastAddress);
        if (!NT_SUCCESS(Status)) {
            NetioTrace(
                NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                "IPNG: [%u] Failure creating broadcast address %!IPV4!\n", 
                Interface->Index, BroadcastAddressLiteral);
            RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
            return Status;
        }
        IppDereferenceLocalBroadcastAddress(BroadcastAddress);        

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
    
    Status = Ipv4pConfigureIscsiInterface(Interface);
    if (!NT_SUCCESS(Status)) {
        //
        // Ignore failures so the interface can be initialized.
        //
        NetioTrace(
            NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
            "IPNG: [%u] iBFT configuration failed. Error:%d \n",
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
                    "IPNG: [%u] Persistent address %!IPV4! creation failed\n",
                    Interface->Index, (CONST UCHAR *) &AddressKey[i].Address);
            }
        }

        NsiFreeTable(AddressKey, AddressRw, NULL, NULL);
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
            if (!IN4_IS_ADDR_UNSPECIFIED(&RouteKey[i].NextHopAddress)) {
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
                    "IPNG: [%u] Persistent route %!IPV4!/%u creation failed\n",
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
                (PUCHAR) &in4addr_multicastprefix, 
                IN4ADDR_MULTICASTPREFIX_LENGTH,
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
                "IPNG: [%u] Multicast route %!IPV4!/%u creation failed\n",
                Interface->Index,
                (CONST UCHAR *) &in4addr_multicastprefix,
                IN4ADDR_MULTICASTPREFIX_LENGTH);
        }
    }
    return STATUS_SUCCESS;
}

            
NTSTATUS
Ipv4pInitializeSubInterface(
    IN PIP_SUBINTERFACE SubInterface
    )
{
    NTSTATUS Status;
    ULONG i, Count;
    PIP_INTERFACE Interface = SubInterface->Interface;
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    PIPV4_NEIGHBOR_KEY NeighborKey;
    PNL_NEIGHBOR_RW NeighborRw;
    PIPV4_ROUTE_KEY RouteKey;
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
                    "IPNG: [%u] Persistent neighbor %!IPV4! creation failed\n",
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
                    "IPNG: [%u] Persistent route %!IPV4!/%u creation failed\n",
                    Interface->Index,
                    (CONST UCHAR *) &RouteKey[i].DestinationPrefix,
                    RouteKey[i].DestinationPrefixLength);
            }
        }

        NsiFreeTable(RouteKey, RouteRw, NULL, NULL);
    }

    return STATUS_SUCCESS;
}
