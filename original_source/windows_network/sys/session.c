/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    session.c

Abstract:

    This module contains code for handling IP socket options.

Author:

    Amit Aggarwal (amitag) Mon Mar 24 16:41:21 2003

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "session.tmh"

HANDLE SessionStatePool;
HANDLE MulticastSessionStatePool;

__inline
VOID
IppGroupTrace(
    IN ULONG Level, 
    IN CONST UCHAR *Message, 
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *GroupAddress
    )
{
    if (IS_IPV4_PROTOCOL(Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: %s (%!IPV4!)\n", 
                   Message, 
                   GroupAddress);
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: %s (%!IPV6!)\n", 
                   Message, 
                   GroupAddress);
    }
}

__inline
VOID
IppSourceGroupTrace(
    IN ULONG Level, 
    IN CONST UCHAR *Message, 
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *GroupAddress,
    IN CONST UCHAR *SourceAddress
    )
{
    if (IS_IPV4_PROTOCOL(Protocol)) {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: %s (%!IPV4! source %!IPV4!)\n", 
                   Message, 
                   GroupAddress, 
                   SourceAddress);
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, Level, 
                   "IPNG: %s (%!IPV6! source %!IPV6!)\n", 
                   Message, 
                   GroupAddress, 
                   SourceAddress);
    }
}


NTSTATUS
IppStartSessionManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Initialize the session module.

Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    UNREFERENCED_PARAMETER(Protocol);
    ASSERT(Protocol == NULL);
    PASSIVE_CODE();

    SessionStatePool =
        FsbCreatePool(
            sizeof(IP_SESSION_STATE),
            0,
            IpSessionStatePoolTag,
            NULL);
    if (SessionStatePool == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: SessionManager - "
                   "Error creating SessionStatePool\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MulticastSessionStatePool =
        FsbCreatePool(
            sizeof(IP_SESSION_MULTICAST_STATE),
            0, 
            IpSessionStatePoolTag,
            NULL);
    if (MulticastSessionStatePool == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: SessionManager - "
                   "Error creating MulticastSessionStatePool\n");
        FsbDestroyPool(SessionStatePool);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IppInitializeSessionState(&IppSendDirectSessionState);
    IppSendDirectSessionState.MulticastHopLimit =
        IppSendDirectSessionState.UnicastHopLimit =
        255;
    
    InterlockedExchangeAdd(&IpModuleStatus, IMS_SESSION);

    return STATUS_SUCCESS;
}

VOID
IppCleanupSessionManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Called when the stack is unloading.

--*/
{
    UNREFERENCED_PARAMETER(Protocol);
    ASSERT(Protocol == NULL);
    
    FsbDestroyPool(SessionStatePool);
    FsbDestroyPool(MulticastSessionStatePool);
}

NTSTATUS
IppGetInterfaceIndexFromSocketOption(
    IN PIP_COMPARTMENT Compartment,
    IN CONST UCHAR *InterfaceAddress,
    OUT IF_INDEX *InterfaceIndex
    )
/*++

Routine Description:

    This routine converts the interface address from a V4 multicast socket
    option to an interface index. 

Arguments:

    Compartment - Supplies the compartment.

    InterfaceAddress - Supplies the interface index in the socket option.

    InterfaceIndex - Returns the interface index. 

Return Value:

    STATUS_SUCCESS or STATUS_INVALID_ADDRESS.

Caller LOCK:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    SCOPE_ID ScopeId;
    PIP_LOCAL_ADDRESS InterfaceAddressEntry;

    ASSERT(Compartment->Protocol->Level == IPPROTO_IP);

    //
    // If the most significant bit of the address is a zero, then this implies
    // that the address contains a interface index instead of an IP
    // address. In that case, just return the interface index after byte
    // swapping it. Note that the interface index is in network byte order; so
    // to check the most significant bit, we check InterfaceAddress[0].
    //
    if (InterfaceAddress[0] == 0) {
        *InterfaceIndex = RtlUlongByteSwap(*((ULONG*)InterfaceAddress));
        return STATUS_SUCCESS;
    }

    //
    // Find a local address entry with the given InterfaceAddress.
    //
    ScopeId = scopeid_unspecified;
    (VOID) IppCanonicalizeScopeId(Compartment, InterfaceAddress, &ScopeId);
    InterfaceAddressEntry = 
        IppFindAddressInScope(
            Compartment, 
            ScopeId,
            InterfaceAddress);

    if ((InterfaceAddressEntry == NULL) && 
         IppIsEphemeralAddressCandidate(
            Compartment->Protocol, 
            InterfaceAddress)) {
        *InterfaceIndex = Compartment->LoopbackIndex;
        return STATUS_SUCCESS;
    }

    if (InterfaceAddressEntry == NULL) {
        return STATUS_INVALID_ADDRESS;
    }
    
    *InterfaceIndex = InterfaceAddressEntry->Interface->Index;
    IppDereferenceLocalAddress(InterfaceAddressEntry);

    return STATUS_SUCCESS;
}

__inline
VOID
IppSetAddressInSocketStorage(
    IN OUT struct sockaddr_storage *Sockaddr,
    IN CONST UCHAR *Address,
    IN ADDRESS_FAMILY AddressFamily
    )
/*++

Routine Description:

    This routine sets the address and address family in a sockaddr_storage
    structure. 

Arguments:

    Sockaddr - Supplies the sockaddr_storage structure to modify.

    Address - Supplies the address to write in the sockaddr_storage structure.

    AddressFamily - Supplies the address family. 

Return Value:

    None.

--*/ 
{
    ASSERT((AddressFamily == AF_INET) || (AddressFamily == AF_INET6));

    RtlZeroMemory(Sockaddr, sizeof(struct sockaddr_storage));
    Sockaddr->ss_family = AddressFamily;
    if (Sockaddr->ss_family == AF_INET) {
        RtlCopyMemory(&((SOCKADDR_IN*)Sockaddr)->sin_addr, 
                      Address, 
                      sizeof(IN_ADDR));
    } else {
        RtlCopyMemory(&((SOCKADDR_IN6*)Sockaddr)->sin6_addr, 
                      Address, 
                      sizeof(IN6_ADDR));
    }
}

__inline
CONST UCHAR*
IppGetAddressFromSocketStorage(
    IN struct sockaddr_storage *Sockaddr
    )
/*++

Routine Description:

    This routine returns the address stored in a sockaddr_storage structure. 

Arguments:

    Sockaddr - Supplies the sockaddr_storage structure.

Return Value:

    Returns a pointer to the address.

--*/ 
{
    if (Sockaddr->ss_family == AF_INET) {
        return (CONST UCHAR*)(&((SOCKADDR_IN*)Sockaddr)->sin_addr);
    } else {
        return (CONST UCHAR*)(&((SOCKADDR_IN6*)Sockaddr)->sin6_addr);
    }
}


NTSTATUS
IppFillInterfaceInfo(
    IN PIP_INTERFACE Interface,
    IN OUT PUCHAR *Buffer,
    IN OUT ULONG *Length
    )
/*++

Routine Description:

    Fill Buffer with INTERFACE_INFO structs for unicast addresses on Interface.
    
Arguments:

    Interface - Supplies the interface whose unicast addresses to fill.
    
    Buffer - Supplies a pointer to the next INTERFACE_INFO structure.
        Returns an updated pointer.

    Length - Supplies the length of Buffer.
        Returns the updated length.
        
Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK: Interface (Shared).

--*/ 
{
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    PNLA_LINK Link;
    PIP_LOCAL_UNICAST_ADDRESS Address;
    INTERFACE_INFO *InterfaceInfo;     
    PSOCKADDR_IN Sockaddr;

    ASSERT_ANY_LOCK_HELD(&Interface->Lock);

    ASSERT(Interface->Compartment->Protocol->Level == IPPROTO_IP);
    
    //
    // Enumerate local unicast addresses on the interface.
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link =
            IppEnumerateNlaSetEntry(
                &Interface->LocalUnicastAddressSet,
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            return STATUS_SUCCESS;
        }

        Address = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_ADDRESS, Link);

        //
        // Only consider valid (preferred & deprecated) unicast addresses.
        //
        if (!IsLocalUnicastAddressValid(Address)) {
            continue;
        }
        
        if (*Length < sizeof(INTERFACE_INFO)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        InterfaceInfo = (INTERFACE_INFO *) *Buffer;
        
        RtlZeroMemory(InterfaceInfo, sizeof(*InterfaceInfo));

        Sockaddr = &InterfaceInfo->iiAddress.AddressIn;
        Sockaddr->sin_family = AF_INET;
        Sockaddr->sin_addr =
            *((PIN_ADDR) NL_ADDRESS(Address));
        
        Sockaddr = &InterfaceInfo->iiNetmask.AddressIn;
        Sockaddr->sin_family = AF_INET;
        Sockaddr->sin_addr.s_addr =
            RtlUlongByteSwap(~(INADDR_BROADCAST >> Address->PrefixLength));
        
        switch (Interface->FlCharacteristics->AccessType) {
        case NET_IF_ACCESS_LOOPBACK:
            InterfaceInfo->iiFlags = IFF_LOOPBACK;
            break;
        case NET_IF_ACCESS_BROADCAST:
            InterfaceInfo->iiFlags = IFF_BROADCAST;
            Sockaddr = &InterfaceInfo->iiBroadcastAddress.AddressIn;
            Sockaddr->sin_family = AF_INET;
            Sockaddr->sin_addr = in4addr_broadcast;
            break;
        case NET_IF_ACCESS_POINT_TO_POINT:
            InterfaceInfo->iiFlags = IFF_POINTTOPOINT;
            break;
        }

        if (Interface->FlCharacteristics->Multicasts) {
            InterfaceInfo->iiFlags |= IFF_MULTICAST;
        }

        if (Interface->ConnectedSubInterfaces > 0) {
            InterfaceInfo->iiFlags |= IFF_UP;
        }
        
        *Buffer += sizeof(INTERFACE_INFO);
        *Length -= sizeof(INTERFACE_INFO);
    }
}


NTSTATUS
IppGetInterfaceList(
    IN PIP_COMPARTMENT Compartment,
    IN PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG BytesTransferred
    )
/*++

Routine Description:
    
    Retrieve the address list for all interfaces from the stack.
    
Arguments:

    Compartment - Supplies the compartment.

    OutputBuffer - Returns an array of INTERFACE_INFO structures.
    
    OutputBufferLength - Supplies the length of OutputBuffer.

    BytesTransferred - Returns the number of bytes written to OutputBuffer.

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    KIRQL OldIrql;
    IN PNLI_LOCKED_SET InterfaceSet = &Compartment->InterfaceSet;
    PLIST_ENTRY Link, Head = &InterfaceSet->Set;
    PIP_INTERFACE Interface;
    PUCHAR Buffer = OutputBuffer;
    ULONG Length = OutputBufferLength;

    RtlAcquireReadLock(&InterfaceSet->Lock, &OldIrql);
    for (Link = Head->Flink; Link != Head; Link = Link->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Link, IP_INTERFACE, CompartmentLink);

        RtlAcquireReadLockAtDpcLevel(&Interface->Lock);
        Status = IppFillInterfaceInfo(Interface, &Buffer, &Length);

        ASSERT (OutputBufferLength >= Length);

        RtlReleaseReadLockFromDpcLevel(&Interface->Lock);

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }
    RtlReleaseReadLock(&InterfaceSet->Lock, OldIrql);

    if (NT_SUCCESS(Status)) {
        __analysis_assume(OutputBufferLength >= Length);
        *BytesTransferred = OutputBufferLength - Length;
    }    

    return Status;
}


NTSTATUS
NTAPI
IpNlpQuerySessionInfo(
    IN PNL_REQUEST_QUERY_SESSION_INFO Args
    )
/*++

Routine Description:

    This routine queries for network-layer-specific information associated
    with a given session at the higher layer.

Arguments:

    ProviderHandle - Supplies a pointer to our context for the client.

    NlCompartment - Supplies information identifying the compartment.

    NlSessionState - Supplies a pointer to the NL session state.  This can be
        NULL in which case the defaults are returned. 

    Level - Supplies the socket option level (IPPROTO_IP/IPPROTO_IPV6).

    OptName - Supplies the socket option code.

    OptValBuffer - Supplies a buffer to be filled in with the value requested.

    OptValBufferLength - Supplies the length of the buffer, and receives
        the number of bytes actually written.

Return Value:

    STATUS_INVALID_PARAMETER
    STATUS_BUFFER_TOO_SMALL
    STATUS_SUCCESS

Caller IRQL: Callable at PASSIVE through DISPATCH level.

Caller Lock: 

    Assumes caller holds no locks.
    The client is responsible for ensuring that no call to SetSessionInfo
    for the same session is in progress during this call.

--*/
{
    PIP_SESSION_STATE State = (PIP_SESSION_STATE)Args->NlSessionState;
    PIP_COMPARTMENT Compartment;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_PROTOCOL Protocol;
    ULONG AddressBytes;
    UINT8 ByteValue;
    KIRQL OldIrql = { 0 };
    PIP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);

    if ((Args->Level != IPPROTO_IP) &&
        (Args->Level != IPPROTO_IPV6)) {
        return STATUS_INVALID_PARAMETER;
    }

    Protocol = Client->Protocol;
    AddressBytes = Protocol->Characteristics->AddressBytes;

    Compartment = IppGetCompartment(Protocol, &Args->NlCompartment);
    if (Compartment == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Lock session state.  Technically some of the options do not
    // require serialization but this is not a hot path and it's less
    // bug prone to just lock it regardless.
    //
    if (State != NULL) {
        KeAcquireSpinLock(&State->SpinLock, &OldIrql);
    }

    switch (Args->OptName) {
    case IP_IFLIST:             // And IPV6_IFLIST.
        //
        // IFLIST is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer =
            (State != NULL) ? (State->InterfaceList != NULL) : FALSE;
        Args->OptValBufferLength = sizeof(UINT);
        break;        
        
    case IPV6_PROTECTION_LEVEL:
        //
        // Level is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer =
           (State != NULL) ? 
           State->ProtectionLevel : 
           PROTECTION_LEVEL_UNRESTRICTED;
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_HDRINCL: // and IPV6_HDRINCL
        if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP ||
            Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_UDP) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer =
            (State != NULL) ? State->HeaderInclude : FALSE;
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_TOS:
        //
        // TOS is returned in a UINT8 or UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT8)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ByteValue = (State != NULL) ? State->TypeOfService : 0;

        if (Args->OptValBufferLength < sizeof(UINT)) {
            //
            // Treat this as a UINT8. 
            //
            *(UINT8 *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT8);
        } else {
            //
            // Treat this as a UINT. 
            //
            *(UINT *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT);
        }
        break;

    case IP_TTL: // and IPV6_UNICAST_HOPS
        //
        // HopLimit is returned in a UINT8 or UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT8)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if ((State != NULL) &&
            (State->UnicastHopLimit != IP_UNSPECIFIED_HOP_LIMIT)) {
            ByteValue = (UINT8) State->UnicastHopLimit;
        } else {
            ByteValue = Compartment->DefaultHopLimit;
        }

        if (Args->OptValBufferLength < sizeof(UINT)) {
            //
            // Treat this as a UINT8. 
            //
            *(UINT8 *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT8);
        } else {
            //
            // Treat this as a UINT. 
            //
            *(UINT *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT);
        }
        break;

    case IP_OPTIONS: // and IPV6_HOPOPTS
        if (State == NULL) {
            Args->OptValBufferLength = 0;
            break;
        }
        
        if (Args->OptValBufferLength < State->HopByHopOptionsLength) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (State->HopByHopOptionsLength > 0) {
            RtlCopyMemory(Args->OptValBuffer,
                          State->HopByHopOptions,
                          State->HopByHopOptionsLength);
        }
        Args->OptValBufferLength = State->HopByHopOptionsLength;
        break;

    case IP_RTHDR:  // and IPV6_RTHDR
        if (State == NULL) {
            Args->OptValBufferLength = 0;
            break;
        }

        if (Args->OptValBufferLength < State->RoutingHeaderLength) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (State->RoutingHeaderLength > 0) {
            RtlCopyMemory(Args->OptValBuffer,
                          State->RoutingHeader,
                          State->RoutingHeaderLength);
        }
        Args->OptValBufferLength = State->RoutingHeaderLength;
        break;

    case IP_MULTICAST_IF: // and IPV6_MULTICAST_IF
        if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Interface Index is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = IFI_UNSPECIFIED;
        if ((State != NULL) && (State->MulticastInterface != NULL)) {
            *(UINT*)Args->OptValBuffer = State->MulticastInterfaceOption;
        }
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_MULTICAST_TTL: // and IPV6_MULTICAST_HOPS
        if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // HopLimit is returned in a UINT8 or UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT8)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        
        if ((State != NULL) &&
            (State->MulticastHopLimit != IP_UNSPECIFIED_HOP_LIMIT)) {
            ByteValue = (UINT8) State->MulticastHopLimit;
        } else {
            ByteValue = IP_DEFAULT_MULTICAST_HOP_LIMIT;
        }
        if (Args->OptValBufferLength < sizeof(UINT)) {
            //
            // Treat this as a UINT8. 
            //
            *(UINT8 *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT8);
        } else {
            //
            // Treat this as a UINT. 
            //
            *(UINT *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT);
        }
        break;

    case IP_MULTICAST_LOOP: // and IPV6_MULTICAST_LOOP
        if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a BOOLEAN or UINT.
        //
        if (Args->OptValBufferLength < sizeof(BOOLEAN)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (Args->OptValBufferLength < sizeof(UINT)) {
            //
            // Treat this as a BOOLEAN. 
            //
            *(BOOLEAN*)Args->OptValBuffer = 
                (State != NULL) ? State->MulticastLoopback : TRUE;
            Args->OptValBufferLength = sizeof(BOOLEAN);
        } else {
            //
            // Treat this as a UINT. 
            //
            *(UINT*)Args->OptValBuffer = 
                (State != NULL) ? State->MulticastLoopback : TRUE;
            Args->OptValBufferLength = sizeof(UINT);
        }
        
        break;

    case IP_UNICAST_IF: // and IPV6_UNICAST_IF
        //
        // Interface Index is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = IFI_UNSPECIFIED;
        if ((State != NULL) && (State->UnicastInterface != NULL)) {
            *(UINT*)Args->OptValBuffer = State->UnicastInterface->Index;
        }
        Args->OptValBufferLength = sizeof(UINT);
        break;
        
    case IP_DONTFRAGMENT:  // and IPV6_DONTFRAG
        //
        // Flag is returned in a UINT8 or UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT8)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ByteValue = 
            (State != NULL)
            ? State->DontFragment
            : Client->Npi.Dispatch->Flags.DefaultDontFragment;
        
        if (Args->OptValBufferLength < sizeof(UINT)) {
            //
            // Treat this as a UINT8. 
            //
            *(UINT8 *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT8);
        } else {
            //
            // Treat this as a UINT. 
            //
            *(UINT *)Args->OptValBuffer = ByteValue;
            Args->OptValBufferLength = sizeof(UINT);
        }
        break;

    case IP_RECEIVE_BROADCAST:
        //
        // This option is only valid for datagram sockets.
        //
        if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = 
            (State != NULL) ? State->ReceiveBroadcast : TRUE;
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_PKTINFO: // and IPV6_PKTINFO
        //
        // This option is only valid for datagram sockets.
        //
        if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = 
            (State != NULL) ? State->ReceivePacketInfo : FALSE;
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_RECVIF: // and IPV6_RECVIF
        //
        // This option is only valid for datagram sockets.
        //
        if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = 
            (State != NULL) ? State->ReceiveInterface : FALSE;
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_RECVDSTADDR: // and IPV6_RECVDSTADDR
        //
        // This option is only valid for datagram sockets.
        //
        if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = 
            (State != NULL) ? State->ReceiveDestination : FALSE;
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_HOPLIMIT: // and IPV6_HOPLIMIT
        //
        // This option is only valid for datagram sockets.
        //
        if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = 
            (State != NULL) ? State->ReceiveHopLimit : FALSE;
        Args->OptValBufferLength = sizeof(UINT);
        break;

    case IP_RECVRTHDR: // and IPV6_RECVRTHDR
        //
        // This option is only valid for datagram sockets.
        //
        if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Flag is returned in a UINT.
        //
        if (Args->OptValBufferLength < sizeof(UINT)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(UINT*)Args->OptValBuffer = 
            (State != NULL) ? State->ReceiveRoutingHeader : FALSE;
        Args->OptValBufferLength = sizeof(UINT);
        break;
    
    default:
        Status = STATUS_NOT_SUPPORTED;
        break;
    }

    if (State != NULL) {
        KeReleaseSpinLock(&State->SpinLock, OldIrql);
    }

    IppDereferenceCompartment(Compartment);
    return Status;
}

NTSTATUS
NTAPI
IpNlpInheritSessionInfo(
    IN OUT PNL_REQUEST_INHERIT_SESSION_INFO Args
    )
/*++

Routine Description:

    Copy session state to a new endpoint.  This is only used by 
    clients which are not multicast-capable.

Arguments:

    ProviderHandle - Supplies a pointer to our context for the client.
    
    OriginalSessionState - Supplies a pointer to the state to copy.

    NewSessionState - Returns a pointer to the copied state.

Return Value:

    STATUS_SUCCESS
    STATUS_INSUFFICIENT_RESOURCES
    STATUS_INVALID_PARAMETER

--*/
{
    PIP_SESSION_STATE OriginalState, State;
    KIRQL OldIrql;
    PIP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);

    Args->IpOptionPresent = FALSE;
    if (!Client->Npi.Dispatch->Flags.DisallowMulticast) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Args->OriginalSessionState == NULL) {
        Args->NewSessionState = NULL;
        return STATUS_SUCCESS;
    }

    OriginalState = (PIP_SESSION_STATE) Args->OriginalSessionState;
    ASSERT(IsListEmpty(&OriginalState->MulticastState));

    State = (PIP_SESSION_STATE) FsbAllocate(SessionStatePool);
    if (State == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeAcquireSpinLock(&OriginalState->SpinLock, &OldIrql);

    RtlCopyMemory(State, Args->OriginalSessionState, sizeof(*State));

    KeInitializeSpinLock(&State->SpinLock);
    
    IppInitializeNliSet(&State->MulticastState);

    //
    // REVIEW: Should we inherit the InterfaceList?
    //
    if (State->InterfaceList != NULL) {
        ULONG Size = SIZEOF_IP_INTERFACE_LIST(State->InterfaceList->Count);

        State->InterfaceList =
            ExAllocatePoolWithTag(NonPagedPool, Size, IpGenericPoolTag);
        if (State->InterfaceList == NULL) {
        Fail:
            KeReleaseSpinLock(&OriginalState->SpinLock, OldIrql);
            KeUninitializeSpinLock(&State->SpinLock);
            FsbFree((PVOID) State);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(State->InterfaceList,
                      OriginalState->InterfaceList,
                      Size);
    }
    if (State->HopByHopOptions != NULL) {
        State->HopByHopOptions =
            ExAllocatePoolWithTag(NonPagedPool, 
                                  State->HopByHopOptionsLength, 
                                  IpGenericPoolTag);
        if (State->HopByHopOptions == NULL) {
        FailHopByHopOptions:
            if (State->InterfaceList != NULL) {
                ExFreePool(State->InterfaceList);
            }
            goto Fail;
        }
        RtlCopyMemory(State->HopByHopOptions,
                      OriginalState->HopByHopOptions,
                      State->HopByHopOptionsLength);
        Args->IpOptionPresent = TRUE;
    }
    if (State->RoutingHeader != NULL) {
        State->RoutingHeader =
            ExAllocatePoolWithTag(NonPagedPool, 
                                  State->RoutingHeaderLength, 
                                  IpGenericPoolTag);
        if (State->RoutingHeader == NULL) {
            if (State->HopByHopOptions != NULL) {
                ExFreePool(State->HopByHopOptions);
            }
            goto FailHopByHopOptions;
        }
        RtlCopyMemory(State->RoutingHeader,
                      OriginalState->RoutingHeader,
                      State->RoutingHeaderLength);
        Args->IpOptionPresent = TRUE;
    }
        
    if (State->MulticastInterface != NULL) {
        IppReferenceInterface(State->MulticastInterface);
    }
    if (State->UnicastInterface != NULL) {
        IppReferenceInterface(State->UnicastInterface);
    }
    if (State->PromiscuousInterface != NULL) {
        (VOID) IppAddPromiscuousReference(State->PromiscuousInterface,
                                          State->PromiscuousMode,
                                          NULL,
                                          NULL);
        IppReferenceInterface(State->PromiscuousInterface);
    }
    if (State->AllMulticastInterface != NULL) {
        (VOID) IppAddAllMulticastReference(State->AllMulticastInterface,
                                           State->AllMulticastMode,
                                           NULL,
                                           NULL);
        IppReferenceInterface(State->AllMulticastInterface);
    }

    KeReleaseSpinLock(&OriginalState->SpinLock, OldIrql);

    Args->NewSessionState = State;
    return STATUS_SUCCESS;
}

VOID
IppUninitializeSessionState(
    IN PIP_SESSION_STATE State
    )
/*++

Routine Description:

    Uninitializes a session state structure.

Arguments:

    State - Supplies a pointer to the network-layer-session state to
        uninitialize.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PLIST_ENTRY Current, Next;
    PIP_SESSION_MULTICAST_STATE MulticastState;
    
    if (State->InterfaceList != NULL) {
        ExFreePool(State->InterfaceList);
    }
    if (State->MulticastInterface != NULL) {
        IppDereferenceInterface(State->MulticastInterface);
    }
    if (State->UnicastInterface != NULL) {
        IppDereferenceInterface(State->UnicastInterface);
    }
    if (State->PromiscuousInterface != NULL) {
        IppRemovePromiscuousReference(State->PromiscuousInterface,
                                      State->PromiscuousMode,
                                      NULL,
                                      NULL);
        IppDereferenceInterface(State->PromiscuousInterface);
    }
    if (State->AllMulticastInterface != NULL) {
        IppRemoveAllMulticastReference(State->AllMulticastInterface,
                                       State->AllMulticastMode,
                                       NULL,
                                       NULL);
        IppDereferenceInterface(State->AllMulticastInterface);
    }
    if (State->HopByHopOptions != NULL) {
        ExFreePool(State->HopByHopOptions);
    }
    if (State->RoutingHeader != NULL) {
        ExFreePool(State->RoutingHeader);
    }

    //
    // Leave all the multicast groups that the session is joined to.
    //
    for (Current = State->MulticastState.Flink;
         Current != &State->MulticastState;
         Current = Next) {
        Next = Current->Flink;
        MulticastState = (PIP_SESSION_MULTICAST_STATE)CONTAINING_RECORD(
            Current,
            IP_SESSION_MULTICAST_STATE,
            Link);
        IppSetMulticastSessionState(
            NULL, 
            MulticastState, 
            MCAST_INCLUDE, 
            0, 
            NULL);
    }
        
    KeUninitializeSpinLock(&State->SpinLock);
}

VOID
NTAPI
IpNlpCleanupSessionInfo(
    IN PVOID NlSessionState
    )
/*++

Routine Description:

    Cleans up all network-layer session state for an endpoint.

Arguments:

    NlSessionState - Supplies a pointer to the network-layer session
        state to free.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_SESSION_STATE State = (PIP_SESSION_STATE)NlSessionState;

    if (State == NULL) {
        return;
    }

    IppUninitializeSessionState(State);

    FsbFree(NlSessionState);
}

NTSTATUS
IppValidateMulticastOptions(
    IN PIP_PROTOCOL Protocol,
    IN CONST UCHAR *MulticastAddress, 
    IN ULONG SourceCount, 
    IN CONST UCHAR *SourceList
    )
{
    ULONG Count;
    CONST UCHAR *SourceAddress;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;

    if (Protocol->MldLevel != MldLevelAll) {
        return STATUS_NOT_SUPPORTED;
    }
    
    if (Protocol->AddressType(MulticastAddress) != NlatMulticast) {
        IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                      "Error validating multicast request: "
                      "Not a multicast address", 
                      Protocol, MulticastAddress);
        return STATUS_INVALID_ADDRESS;
    }
    for (Count = 0; Count < SourceCount; Count++) {
        SourceAddress = SourceList + (Count * AddressBytes);
        if (Protocol->AddressType(SourceAddress) != NlatUnicast) {
            IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                          "Error validating multicast request: "
                          "Not a valid source address", 
                          Protocol, SourceAddress);
            return STATUS_INVALID_ADDRESS;
        }
    }

    return STATUS_SUCCESS;
}
    
NTSTATUS
IppProcessJoinRequest(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_SESSION_STATE State,
    IN HANDLE InspectHandle,
    IN CONST IF_INDEX InterfaceIndex, 
    IN CONST UCHAR *MulticastAddress,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    This routine processes set session information options for joining a group
    (e.g. IP_ADD_MEMBERSHIP and MCAST_JOIN_GROUP). 

Arguments:

    Compartment - Supplies the compartment.

    State - Supplies the session state to modify.

    InspectHandle - Supplies a handle which is relevant to ALE.

    InterfaceIndex - Supplies the interface index on which to join the
        group.

    MulticastAddress - Supplies the multicast address to join.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_PENDING indicates that completion will be asynchronous.
    STATUS_SUCCESS indicates successful synchronous completion.
    Else a failure code is returned to indicate that the call failed.

Locks:

    Assumes caller holds the session state lock.

Caller IRQL:

    Must be called at DISPATCH level since a lock is held.

--*/ 
{
    NTSTATUS Status;
    PIP_SESSION_MULTICAST_STATE MulticastState;
    PIP_PROTOCOL Protocol = Compartment->Protocol;

    ASSERT_SPIN_LOCK_HELD(&State->SpinLock);

    Status = IppValidateMulticastOptions(
        Protocol,
        MulticastAddress,
        0,
        NULL);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MulticastState = IppFindMulticastSessionState(
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex);
    if (MulticastState != NULL) {
        //
        // There already is state for this multicast group. So, this is
        // an invalid request.
        //
        IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                      "Error processing join request : Group already exists",
                      Protocol, 
                      MulticastAddress);
        return STATUS_INVALID_PARAMETER;
    }

    IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                  "Processing join request",
                  Protocol, 
                  MulticastAddress);

    //
    // Create an entry for the multicast group.                        
    // EXCLUDE mode with a null source list is equivalent to joining the group.
    //
    return IppCreateMulticastSessionState(
        InspectHandle,
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex,
        MCAST_EXCLUDE,
        0,
        NULL,
        CompletionContext,
        CompletionRoutine);
}

NTSTATUS
IppProcessLeaveRequest(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_SESSION_STATE State,
    IN CONST IF_INDEX InterfaceIndex, 
    IN CONST UCHAR *MulticastAddress
    )
/*++

Routine Description:

    This routine processes set session information options for leaving a group
    (e.g. IP_DROP_MEMBERSHIP and MCAST_LEAVE_GROUP). 

Arguments:

    Compartment - Supplies the compartment.

    State - Supplies the session state to modify.

    InterfaceIndex - Supplies the interface index on which to leave the
        group.

    MulticastAddress - Supplies the multicast address to leave.

Return Value:

    STATUS_SUCCESS on success. Otherwise the appropriate failure code.

Caller IRQL: <= DISPATCH_LEVEL. 

--*/ 
{
    NTSTATUS Status;
    PIP_SESSION_MULTICAST_STATE MulticastState;

    Status = IppValidateMulticastOptions(
        Compartment->Protocol,
        MulticastAddress,
        0,
        NULL);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    MulticastState = IppFindMulticastSessionState(
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex);
    if (MulticastState == NULL) {
        //
        // There is no state for the multicast group. Cannot drop it.   
        //
        IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                      "Error processing leave request: No state for group", 
                      Compartment->Protocol, MulticastAddress);
        return STATUS_INVALID_ADDRESS;
    }

    IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                  "Processing leave request",
                  Compartment->Protocol, MulticastAddress);

    //
    // Dropping membership of a group is equivalent to setting the state
    // to INCLUDE with no sources in the include list.                  
    //
    return IppSetMulticastSessionState(
        NULL,
        MulticastState,
        MCAST_INCLUDE,
        0,
        NULL);
}

NTSTATUS
IppProcessAddSource(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_SESSION_STATE State,
    IN HANDLE InspectHandle,
    IN CONST IF_INDEX InterfaceIndex,
    IN CONST UCHAR *MulticastAddress,
    IN CONST UCHAR *SourceAddress,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    This routine processes set session information options for adding a source
    (e.g. IP_ADD_SOURCE_MEMBERSHIP and MCAST_JOIN_SOURCE_GROUP). 

Arguments:

    Compartment - Supplies the compartment.

    State - Supplies the session state to modify.

    InspectHandle - Supplies a handle which is relevant to ALE.

    InterfaceIndex - Supplies the interface index on which to add the
        source to the multicast address.

    MulticastAddress - Supplies the multicast address to which the source is
        added. 

    SourceAddress - Supplies the source addess to add. 

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_PENDING indicates that completion will be asynchronous.
    STATUS_SUCCESS indicates successful synchronous completion.
    Else a failure code is returned to indicate that the call failed.

Caller IRQL: <= DISPATCH_LEVEL. 

--*/ 
{
    NTSTATUS Status;
    PIP_SESSION_MULTICAST_STATE MulticastState;

    Status = IppValidateMulticastOptions(
        Compartment->Protocol,
        MulticastAddress,
        1,
        SourceAddress);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    MulticastState = IppFindMulticastSessionState(
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex);
    
    IppSourceGroupTrace(TRACE_LEVEL_INFORMATION, 
                        "Processing add source request",
                        Compartment->Protocol, 
                        MulticastAddress, 
                        SourceAddress);

    if (MulticastState != NULL) {
        if (MulticastState->Mode == MCAST_EXCLUDE) {
            //
            // This is an exclusion list.
            // Cannot add membership for a specific source.
            //
            IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                          "Error processing add source request : "
                          "Group is in exclude mode", 
                          Compartment->Protocol, MulticastAddress);
            return STATUS_INVALID_PARAMETER;
        } else {
            //
            // Simply add the source to the inclusion list.
            //
            ASSERT(MulticastState->Mode == MCAST_INCLUDE);
            return IppModifyMulticastSessionState(
                InspectHandle,
                MulticastState,
                0,
                NULL, 
                MCAST_INCLUDE,
                1,
                SourceAddress);
        }
    }
    
    //
    // Create an entry for the multicast group. 
    //
    return IppCreateMulticastSessionState(
        InspectHandle,
        State,
        Compartment, 
        MulticastAddress,
        InterfaceIndex,
        MCAST_INCLUDE,
        1,
        SourceAddress,
        CompletionContext,
        CompletionRoutine);
}

NTSTATUS
IppProcessDropSource(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_SESSION_STATE State,
    IN CONST IF_INDEX InterfaceIndex,
    IN CONST UCHAR *MulticastAddress,
    IN CONST UCHAR *SourceAddress
    )
/*++

Routine Description:

    This routine processes set session information options for dropping a
    source (e.g. IP_DROP_SOURCE_MEMBERSHIP and MCAST_LEAVE_SOURCE_GROUP). 

Arguments:

    Compartment - Supplies the compartment.

    State - Supplies the session state to modify.

    InterfaceIndex - Supplies the interface index on which to drop the
        source from the multicast address.

    MulticastAddress - Supplies the multicast address from which the source is
        dropped. 

    SourceAddress - Supplies the source addess to drop. 

Return Value:

    STATUS_SUCCESS on success. Otherwise the appropriate failure code.

Caller IRQL: <= DISPATCH_LEVEL. 

--*/ 
{        
    NTSTATUS Status;
    PIP_SESSION_MULTICAST_STATE MulticastState;

    Status = IppValidateMulticastOptions(
        Compartment->Protocol,
        MulticastAddress,
        1,
        SourceAddress);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MulticastState = IppFindMulticastSessionState(
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex);
    if ((MulticastState == NULL) || 
        (MulticastState->Mode == MCAST_EXCLUDE)) {
        //
        // Either there is no state for the group or the multicast group is
        // in exclusion mode. In either case, we cannot drop a source.
        //
        IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                      "Error processing drop request : "
                      "No state for group or group is in exclude mode", 
                      Compartment->Protocol, MulticastAddress);
        return STATUS_INVALID_PARAMETER;
    }
    
    IppSourceGroupTrace(TRACE_LEVEL_INFORMATION, 
                        "Processing drop source request",
                        Compartment->Protocol,
                        MulticastAddress, 
                        SourceAddress);

    //
    // We now have a multicast entry with mode set to INCLUDE. Just drop the
    // source from the include list. 
    //
    ASSERT(MulticastState->Mode == MCAST_INCLUDE);
    return IppModifyMulticastSessionState(
               NULL,
               MulticastState,
               1,
               SourceAddress,
               MCAST_INCLUDE,
               0,
               NULL);
}

NTSTATUS
IppProcessBlockSource(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_SESSION_STATE State,
    IN CONST IF_INDEX InterfaceIndex,
    IN CONST UCHAR *MulticastAddress,
    IN CONST UCHAR *SourceAddress
    )
/*++

Routine Description:

    This routine processes set session information options for blocking a
    source from a multicast address (e.g. IP_BLOCK_SOURCE and
    MCAST_BLOCK_SOURCE).

Arguments:

    Compartment - Supplies the compartment.

    State - Supplies the session state to modify.

    InterfaceIndex - Supplies the interface index on which to block the
        source from the multicast address.

    MulticastAddress - Supplies the multicast address on which the source is
        blocked. 

    SourceAddress - Supplies the source addess to block. 

Return Value:

    STATUS_SUCCESS on success. Otherwise the appropriate failure code.

Caller IRQL: <= DISPATCH_LEVEL. 

--*/ 
{
    NTSTATUS Status;
    PIP_SESSION_MULTICAST_STATE MulticastState;

    Status = IppValidateMulticastOptions(
        Compartment->Protocol,
        MulticastAddress,
        1,
        SourceAddress);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MulticastState = IppFindMulticastSessionState(
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex);
    if ((MulticastState == NULL) || 
        (MulticastState->Mode == MCAST_INCLUDE)) {
        //
        // This is an inclusion list. Cannot block/unblock a source.
        //
        IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                      "Error processing block request: "
                      "No state for group or group is in include mode", 
                      Compartment->Protocol, MulticastAddress);
        return STATUS_INVALID_PARAMETER;
    }
    
    IppSourceGroupTrace(TRACE_LEVEL_INFORMATION, 
                        "Processing block source request",
                        Compartment->Protocol, 
                        MulticastAddress, 
                        SourceAddress);

    ASSERT(MulticastState->Mode == MCAST_EXCLUDE);
    return IppModifyMulticastSessionState(
               NULL,
               MulticastState,
               0, 
               NULL,
               MCAST_EXCLUDE,
               1,
               SourceAddress);
}
        
NTSTATUS
IppProcessUnblockSource(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_SESSION_STATE State,
    IN CONST IF_INDEX InterfaceIndex,
    IN CONST UCHAR *MulticastAddress,
    IN CONST UCHAR *SourceAddress
    )
/*++

Routine Description:

    This routine processes set session information options for unblocking a 
    source from a multicast address (e.g. IP_UNBLOCK_SOURCE and
    MCAST_UNBLOCK_SOURCE).

Arguments:

    Compartment - Supplies the compartment.

    State - Supplies the session state to modify.

    InterfaceIndex - Supplies the interface index on which to unblock the 
        source from the multicast address.

    MulticastAddress - Supplies the multicast address on which the source is
        unblocked. 

    SourceAddress - Supplies the source addess to unblock. 

Return Value:

    STATUS_SUCCESS on success. Otherwise the appropriate failure code.

Caller IRQL: <= DISPATCH_LEVEL. 

--*/ 
{
    NTSTATUS Status;
    PIP_SESSION_MULTICAST_STATE MulticastState;

    Status = IppValidateMulticastOptions(
        Compartment->Protocol,
        MulticastAddress,
        1,
        SourceAddress);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MulticastState = IppFindMulticastSessionState(
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex);
    if ((MulticastState == NULL) || 
        (MulticastState->Mode == MCAST_INCLUDE)) {
        //
        // This is an inclusion list. Cannot unblock a source.
        //
        IppGroupTrace(TRACE_LEVEL_INFORMATION, 
                      "Error processing unblock request: "
                      "No state for group or group is in include mode", 
                      Compartment->Protocol, MulticastAddress);
        return STATUS_INVALID_PARAMETER;
    }
    
    IppSourceGroupTrace(TRACE_LEVEL_INFORMATION, 
                        "Processing unblock source request",
                        Compartment->Protocol,
                        MulticastAddress, 
                        SourceAddress);

    ASSERT(MulticastState->Mode == MCAST_EXCLUDE);
    return IppModifyMulticastSessionState(
               NULL,
               MulticastState,
               1,
               SourceAddress,
               MCAST_EXCLUDE,
               0,
               NULL);
}

NTSTATUS
IppProcessSetMulticastFilter(
    IN PIP_COMPARTMENT Compartment,
    IN PIP_SESSION_STATE State,
    IN HANDLE InspectHandle,
    IN CONST IF_INDEX InterfaceIndex,
    IN CONST UCHAR *MulticastAddress,
    IN MULTICAST_MODE_TYPE FilterMode,
    IN ULONG SourceCount,
    IN CONST UCHAR *SourceList,
    IN PVOID CompletionContext,
    IN PNL_CLIENT_SET_SESSION_INFO_COMPLETE CompletionRoutine
    )
/*++

Routine Description:

    This routine processes ioctls for setting the multicast filter
    (e.g. SIO_SET_MULTICAST_FILTER and SIOCSMSFILTER).

Arguments:

    Compartment - Supplies the compartment.

    State - Supplies the session state to modify.

    InspectHandle - Supplies a handle which is relevant to ALE.

    InterfaceIndex - Supplies the interface index on which to set the
        filter for the multicast address.

    MulticastAddress - Supplies the multicast address for which to set the
        filter. 

    FilterMode - Supplies the mode (MCAST_INCLUDE or MCAST_EXCLUDE) of
        the mulitcast filter.

    SourceCount - Supplies the number of sources in the multicast filter.

    SourceList - Supplies the list of sources in the multicast filter.

    CompletionContext - Supplies a context to supply to the completion
        routine if pended.

    CompletionRoutine - Supplies a completion routine to call if pended.

Return Value:

    STATUS_PENDING indicates that completion will be asynchronous.
    STATUS_SUCCESS indicates successful synchronous completion.
    Else a failure code is returned to indicate that the call failed.

Caller IRQL: <= DISPATCH_LEVEL. 

--*/ 
{
    NTSTATUS Status;
    PIP_SESSION_MULTICAST_STATE MulticastState;

    Status = IppValidateMulticastOptions(
            Compartment->Protocol,
            MulticastAddress, 
            SourceCount,
            SourceList);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MulticastState = IppFindMulticastSessionState(
        State,
        Compartment,
        MulticastAddress,
        InterfaceIndex);
    if (MulticastState != NULL) {
        return IppSetMulticastSessionState(
            InspectHandle,
            MulticastState,
            FilterMode,
            SourceCount,
            SourceList);
    }
    
    //
    // If required, create an entry for the multicast group.
    //
    if ((FilterMode == MCAST_INCLUDE) && (SourceCount == 0)) {
        return STATUS_SUCCESS;
    }
    return IppCreateMulticastSessionState(
        InspectHandle,
        State,
        Compartment, 
        MulticastAddress,
        InterfaceIndex,
        FilterMode,
        SourceCount,
        SourceList,
        CompletionContext,
        CompletionRoutine);
}

ULONG
IppGetAncillaryDataLength(
    IN PIP_PROTOCOL Protocol,
    IN PIP_SESSION_STATE State,
    IN PIP_REQUEST_CONTROL_DATA Control OPTIONAL
    )
/*++

Routine Description:

    Gets the amount of ancillary data available for received datagrams.

Arguments:

    Protocol - Supplies a pointer to the protocol's global data.

    State - Supplies a pointer to the session state.

    Control - Optionally supplies the packet to provide length information
        that is packet specific.

Return Value:

    Returns the ancillary data length, in bytes.
    A value of NL_ANCILLARY_DATA_LENGTH_VARIABLE indicates that the
    caller of QueryAncillaryData should use the call-twice semantics.

Locks:

    May be called at PASSIVE through DISPATCH level.
    Assumes caller synchronizes calls to SetSessionInfo.

--*/
{
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;
    ULONG Length = 0;

    if (State->ReceiveRoutingHeader) {
        if (Control == NULL) {
            return NL_ANCILLARY_DATA_LENGTH_VARIABLE;
        } else {
            Length += CMSG_SPACE(Control->ReceiveRoutingHeaderLength);
        }
    }        
    if (State->ReceivePacketInfo) {
        //
        // The PKTINFO structures contain an address and an interface index.
        //
        Length += CMSG_SPACE(AddressBytes + sizeof(IF_INDEX));
    }
    if (State->ReceiveDestination) {
        Length += CMSG_SPACE(AddressBytes);
    }
    if (State->ReceiveInterface) {
        Length += CMSG_SPACE(sizeof(IF_INDEX));
    }
    if (State->ReceiveHopLimit) {
        Length += CMSG_SPACE(sizeof(INT));
    }
    
    return Length;
}

VOID
IppInitializeSessionState(
    OUT PIP_SESSION_STATE State
    )
/*++

Routine Description:

    Initialize network-layer-specific information associated with a given
    higher-layer session. 

Arguments:

    State - Supplies a pointer to the NL session state to initialize.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    RtlZeroMemory(State, sizeof(IP_SESSION_STATE));
    State->MulticastHopLimit = State->UnicastHopLimit = 
        IP_UNSPECIFIED_HOP_LIMIT;
    State->MulticastLoopback = TRUE;
    State->ReceiveBroadcast = TRUE;
    State->ProtectionLevel = PROTECTION_LEVEL_UNRESTRICTED;
    
    IppInitializeNliSet(&State->MulticastState);

    KeInitializeSpinLock(&State->SpinLock);
}

NTSTATUS
NTAPI
IpNlpInitializeSessionInfo(
    IN PNL_REQUEST_INITIALIZE_SESSION_INFO Args
    )
/*++

Routine Description:

    This routine allocates and initializes network-layer-specific information
    associated with a given higher-layer session.

Arguments:

    ProviderHandle - Supplies a pointer to our context for the client.

    NlSessionState - Supplies a pointer to the NL session state, which
        may be updated.

Return Value:

    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_SESSION_STATE State;
    PIP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle, 
                                        IP_CLIENT_CONTEXT);

    State = (PIP_SESSION_STATE) FsbAllocate(SessionStatePool);
    if (State == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error processing SetSessionInfo request: " 
                   "Could not allocate session state\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IppInitializeSessionState(State);

    State->DontFragment = Client->Npi.Dispatch->Flags.DefaultDontFragment;
        
    Args->NlSessionState = State;
    
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IpNlpSetSessionInfo(
    IN PNL_REQUEST_SET_SESSION_INFO Args
    )
/*++

Routine Description:

    This routine updates network-layer-specific information associated
    with a given session at the higher layer.

Arguments:

    ProviderHandle - Supplies a pointer to our context for the client.

    NlCompartment - Supplies information identifying the compartment.

    NlSessionState - Supplies a pointer to the NL session state.

    Level - Supplies the socket option level (IPPROTO_IP/IPPROTO_IPV6).

    OptName - Supplies the socket option code.

    OptValBuffer - Supplies a buffer holding the socket option value to set.

    OptValBufferLength - Supplies the length of the input buffer.

    OutputBuffer - Supplies an output buffer that can be filled in.

    OutputBufferLength - Supplies the length of the output buffer, and
        receives the number of bytes actually written.

    AncillaryDataLength - Returns the number of bytes of ancillary data
        available with each received datagram.

Return Value:

    STATUS_INVALID_PARAMETER
    STATUS_INSUFFICIENT_RESOURCES
    STATUS_SUCCESS
    STATUS_PENDING

Locks:

    Locks the session state.

Caller IRQL: Callable at PASSIVE through DISPATCH level.

--*/
{
    UINT UintValue;
    UCHAR UcharValue, *SourceList;
    PIP_SESSION_STATE State = (PIP_SESSION_STATE)Args->NlSessionState;
    PIP_COMPARTMENT Compartment;
    IF_INDEX InterfaceIndex;
    PIP_INTERFACE_LIST InterfaceList;
    PIP_INTERFACE Interface;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_PROTOCOL Protocol;
    PIP_MREQ MulticastRequest;
    PIPV6_MREQ Ipv6MulticastRequest;
    PIP_MREQ_SOURCE MulticastSourceRequest;
    PIP_MSFILTER MulticastFilter, OutputMulticastFilter;
    PIP_SESSION_MULTICAST_STATE MulticastState;
    PGROUP_REQ GroupRequest;
    PGROUP_SOURCE_REQ GroupSourceRequest;
    PGROUP_FILTER GroupFilter, OutputGroupFilter;
    ULONG AddressBytes, i, Count, SourceCount, OutputBufferLength = 0;
    KIRQL OldIrql;
    PIP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle, 
                                        IP_CLIENT_CONTEXT);
    
    Protocol = Client->Protocol;
    AddressBytes = Protocol->Characteristics->AddressBytes;

    if ((Args->Level != IPPROTO_IP) &&
        (Args->Level != IPPROTO_IPV6) &&
        (Args->Level != SOL_SIO)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Error processing SetSessionInfo request: " 
                   "Illegal level %d\n", Args->Level);
        return STATUS_INVALID_PARAMETER;
    }
    //
    // Check for mismatch between the protocol level and the options level.  We
    // don't check for the case where the option is an IPv6 option while the
    // protocol is IPv4 (this can happen for V4 mapped sockets). 
    //
    if ((Args->Level == IPPROTO_IP) && (Protocol->Level != IPPROTO_IP)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Error processing SetSessionInfo request: " 
                   "Level mismatch %d expected %d\n", 
                   Args->Level, Protocol->Level);
        return STATUS_INVALID_PARAMETER;
    }

    Compartment = IppGetCompartment(Protocol, &Args->NlCompartment);
    if (Compartment == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Error processing SetSessionInfo request: " 
                   "Could not find compartment\n");
        return STATUS_INVALID_PARAMETER;
    }

    Args->OffloadStateAffected = FALSE;
    Args->PathMtuAffected = FALSE;
    
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
               "IPNG: Processing SetSessionInfo request: Name 0x%x",
               Args->OptName);

    //
    // Lock session state.  Technically some of the options do not
    // require serialization but this is not a hot path and it's less
    // bug prone to just lock it regardless.
    //
    KeAcquireSpinLock(&State->SpinLock, &OldIrql);

    if (Args->Level != SOL_SIO) {
        // 
        // Set a socket option.
        //
        switch (Args->OptName) {
        case IP_IFLIST:             // And IPV6_IFLIST.
            //
            // Determine whether the interface-list is being enabled or
            // cleared.  When enabled, an interface-list is created. 
            // When disabled, any existing interface-list is freed.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            
            if (UintValue != 0) {
                if (State->InterfaceList != NULL) {
                    Status = STATUS_SUCCESS;
                } else {
                    InterfaceList =
                        ExAllocatePoolWithTag(NonPagedPool,
                                              SIZEOF_IP_INTERFACE_LIST(0),
                                              IpGenericPoolTag);
                    if (InterfaceList == NULL) {
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                    } else {
                        InterfaceList->Count = 0;
                        State->InterfaceList = InterfaceList;
                        Status = STATUS_SUCCESS;
                    }
                }
            } else {
                if (State->InterfaceList != NULL) {
                    ExFreePool(State->InterfaceList);
                    State->InterfaceList = NULL;
                }
                Status = STATUS_SUCCESS;
            }
            break;        
    
        case IP_ADD_IFLIST:         // And IPV6_ADD_IFLIST.
            //
            // An interface-index is being added to the object's interface-list
            // so verify that an interface-list exists and, if not, fail.
            // Otherwise, verify that the index specified is valid and, if so,
            // verify that the index is not already in the interface list.
            //
            if (State->InterfaceList == NULL) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            InterfaceIndex = (IF_INDEX) *(UINT*)Args->OptValBuffer;
    
            //
            // Validate interface index.
            //        
            Interface = IppFindInterfaceByIndex(Compartment, InterfaceIndex);
            if (Interface == NULL) {
                Status = STATUS_NOT_FOUND;
                break;
            }
            IppDereferenceInterface(Interface);
    
            Count = State->InterfaceList->Count;
            for (i = 0; ; i++) {
                if (i == Count) {
                    //
                    // The index to be added is not already present.  Allocate
                    // space for an expanded interface-list, copy the old
                    // interface-list, append the new index, and replace the
                    // old interface-list.
                    // Since (Count + 1) is bounded by the number of
                    // interfaces, we don't have to worry about the size of the
                    // interface list overflowing.
                    //
                    InterfaceList =
                        ExAllocatePoolWithTag(NonPagedPool,
                                              SIZEOF_IP_INTERFACE_LIST(Count + 1),
                                              IpGenericPoolTag);
                    if (InterfaceList == NULL) {
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        break;
                    }
    
                    InterfaceList->Count = Count + 1;
                    RtlCopyMemory(InterfaceList->Index,
                                  State->InterfaceList->Index,
                                  Count * sizeof(IF_INDEX));
                    InterfaceList->Index[Count] = InterfaceIndex;
    
                    ExFreePool(State->InterfaceList);
                    State->InterfaceList = InterfaceList;
                    
                    Status = STATUS_SUCCESS;
                    break;                
                }
                
                if (State->InterfaceList->Index[i] == InterfaceIndex) {
                    Status = STATUS_SUCCESS;
                    break;
                }
            }
            break;
    
        case IP_DEL_IFLIST:         // And IPV6_DEL_IFLIST.
            //
            // An index is being removed from the object's interface-list,
            // so verify that an interface-list exists and, if not, fail.
            // Otherwise, search the list for the index and, if not found, fail.
            //
            // N.B. We do not validate the index first in this case, to allow
            // an index to be removed even after the corresponding interface
            // is no longer present.
            //
            if (State->InterfaceList == NULL) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            InterfaceIndex = (IF_INDEX) *(UINT*)Args->OptValBuffer;
    
            Count = State->InterfaceList->Count;
            for (i = 0; ; i++) {
                if (i == Count) {
                    Status = STATUS_NOT_FOUND;
                    break;
                }
                
                if (State->InterfaceList->Index[i] == InterfaceIndex) {
                    State->InterfaceList->Count = Count - 1;
                    RtlMoveMemory(State->InterfaceList->Index + i,
                                  State->InterfaceList->Index + i + 1,
                                  (Count - i - 1) * sizeof(IF_INDEX));
                    Status = STATUS_SUCCESS;
                    break;
                }
            }
            break;
    
        case IPV6_PROTECTION_LEVEL:
            //
            // Level is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            if ((UintValue != PROTECTION_LEVEL_RESTRICTED) &&
                (UintValue != PROTECTION_LEVEL_EDGERESTRICTED) &&
                (UintValue != PROTECTION_LEVEL_UNRESTRICTED) &&
                (UintValue != PROTECTION_LEVEL_DEFAULT)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (UintValue == PROTECTION_LEVEL_DEFAULT) {
                UintValue = PROTECTION_LEVEL_UNRESTRICTED;
            }
            State->ProtectionLevel = (UINT8) UintValue;
            break;        
            
        case IP_HDRINCL:            // And IPV6_HDRINCL.
            if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP ||
                Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_UDP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            //
            // Flag is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            
            if (UintValue != 0) {
                Status = IppInspectEnableHeaderInclude(Protocol->Level,
                                                       Args->InspectHandle,
                                                       NULL,
                                                       NULL);
            }
            if (NT_SUCCESS(Status)) {
                State->HeaderInclude = (UintValue != 0) ? TRUE : FALSE;
            }
            break;
    
        case IP_TOS:
            //
            // TOS is passed in a UINT8 or UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT8)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            if (Args->OptValBufferLength < sizeof(UINT)) {
                //
                // Treat this as a UINT8. 
                //
                UintValue = *(UINT8 *)Args->OptValBuffer;
            } else {
                //
                // Treat this as a UINT. 
                //
                UintValue = *(UINT *)Args->OptValBuffer;
            }
            if (UintValue >= 256) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            //
            // IP_SESSION_STATE::TypeOfService is used merely for reporting.
            // We record the value, but ignore it when generating headers.
            //
            State->TypeOfService = (UINT8)UintValue;
            break;
    
        case IP_TTL:                // And IPV6_UNICAST_HOPS.
            //
            // HopLimit is passed in a UINT8 or UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT8)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            if (Args->OptValBufferLength < sizeof(UINT)) {
                //
                // Treat this as a UINT8. 
                //
                UintValue = *(UINT8 *)Args->OptValBuffer;
            } else {
                //
                // Treat this as a UINT. 
                //
                UintValue = *(UINT *)Args->OptValBuffer;
            }
            if (UintValue >= 256) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (State->UnicastHopLimit != (SHORT) UintValue) {
                State->UnicastHopLimit = (SHORT) UintValue;
                Args->OffloadStateAffected = TRUE;
            }
            break;

        case IP_OPTIONS:            // And IPV6_HOPOPTS.
            {
                PUCHAR OldOptions, NewOptions;
                USHORT BytesToCopy, FirstHopOffset;

                if (Args->OptValBufferLength == 0) {
                    NewOptions = NULL;
                    BytesToCopy = 0;
                    FirstHopOffset = 0;
                } else {
                    //
                    // Make a local copy of the new options.
                    //
                    NewOptions = ExAllocatePoolWithTag(
                                    NonPagedPool,
                                    Args->OptValBufferLength,
                                    IpGenericPoolTag);

                    if (NewOptions == NULL) {
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        break;
                    }

                    RtlCopyMemory(NewOptions, 
                                  Args->OptValBuffer, 
                                  Args->OptValBufferLength);

                    //
                    // Validate the options buffer.  Do this on our
                    // our buffer so we're isolated from the client
                    // changing the buffer after we've validated it.
                    //
                    Status = Protocol->ValidateHopByHopOptionsForSend(
                                NewOptions,
                                Args->OptValBufferLength,
                                &FirstHopOffset,
                                &BytesToCopy);
                    if (!NT_SUCCESS(Status)) {
                        ExFreePool(NewOptions);
                        break;
                    }
                }
    
                OldOptions = State->HopByHopOptions;

                State->HopByHopOptions = NewOptions;
                State->HopByHopOptionsLength = BytesToCopy;
                State->FirstHopOffset = FirstHopOffset;
    
                if (OldOptions != NULL) {
                    ExFreePool(OldOptions);
                }
                //
                // Get the new UL MTU.
                //
                if (Args->NlPath != NULL) {
                    USHORT NlTotalHeaderSize;
                    PIP_PATH Path = IppCast(Args->NlPath, IP_PATH);  

                    Args->IpOptionLength = State->HopByHopOptionsLength + 
                            State->RoutingHeaderLength;
                    NlTotalHeaderSize = Compartment->Protocol->HeaderSize + 
                            Args->IpOptionLength;

                    Args->PathMtuAffected = TRUE;
                    Args->NewUlMtu = Path->PathMtu - NlTotalHeaderSize;
                    ASSERT(Protocol->MinimumMtu > NlTotalHeaderSize);
                    Args->NewMinimumUlMtu = 
                        Protocol->MinimumMtu - NlTotalHeaderSize;
                    
                    //
                    // We are ignoring ipsec overhead here since right now only
                    // consumer for this return value is offload.
                    //
                    Args->NewBackFillLength = NlTotalHeaderSize + 
                        Path->SourceAddress->Interface->FlCharacteristics->HeaderLength;
                }
            }

            Args->OffloadStateAffected = TRUE;
            break;

        case IP_RTHDR:  // And IPV6_RTHDR
            {
                PUCHAR OldHeader, NewHeader;
                USHORT BytesToCopy;

                if (Args->OptValBufferLength == 0) {
                    NewHeader = NULL;
                    BytesToCopy = 0;
                } else {
                    //
                    // Make a local copy of the new options.
                    //
                    NewHeader = ExAllocatePoolWithTag(
                                    NonPagedPool,
                                    Args->OptValBufferLength,
                                    IpGenericPoolTag);

                    if (NewHeader == NULL) {
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        break;
                    }

                    RtlCopyMemory(NewHeader,
                                  Args->OptValBuffer,
                                  Args->OptValBufferLength);

                    //
                    // Validate the routing header.  Do this on our
                    // our buffer so we're isolated from the client
                    // changing the buffer after we've validated it.
                    //
                    Status = Protocol->ValidateRoutingHeaderForSend(
                                NewHeader,
                                Args->OptValBufferLength,
                                &BytesToCopy);
                    if (!NT_SUCCESS(Status)) {
                        ExFreePool(NewHeader);
                        break;
                    }
                }

                OldHeader = State->RoutingHeader;

                State->RoutingHeader = NewHeader;
                State->RoutingHeaderLength = BytesToCopy;

                if (OldHeader != NULL) {
                    ExFreePool(OldHeader);
                }
                //
                // Get the new UL MTU.
                //
                if (Args->NlPath != NULL) {
                    USHORT NlTotalHeaderSize;
                    PIP_PATH Path = IppCast(Args->NlPath, IP_PATH);  

                    Args->IpOptionLength = State->HopByHopOptionsLength + 
                            State->RoutingHeaderLength;
                    NlTotalHeaderSize = Compartment->Protocol->HeaderSize + 
                            Args->IpOptionLength;

                    Args->PathMtuAffected = TRUE;
                    Args->NewUlMtu = Path->PathMtu - NlTotalHeaderSize;
                    ASSERT(Protocol->MinimumMtu > NlTotalHeaderSize);
                    Args->NewMinimumUlMtu = 
                        Protocol->MinimumMtu - NlTotalHeaderSize;
                    //
                    // We are ignoring ipsec overhead here since right now only
                    // consumer for this return value is offload.
                    //
                    Args->NewBackFillLength = NlTotalHeaderSize + 
                        Path->SourceAddress->Interface->FlCharacteristics->HeaderLength;
                }
            }
            break;
    
        case IP_MULTICAST_IF:       // And IPV6_MULTICAST_IF.
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            //
            // Interface Index is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
    
            //
            // Validate interface index.
            //
            InterfaceIndex = (IF_INDEX) *(UINT*)Args->OptValBuffer;
            if (InterfaceIndex == IFI_UNSPECIFIED) {
                Interface = NULL;
            } else {
                if (Protocol->Level == IPPROTO_IP) {
                    Status = IppGetInterfaceIndexFromSocketOption(
                        Compartment, 
                        (CONST UCHAR*) Args->OptValBuffer, 
                        &InterfaceIndex);
                    if (!NT_SUCCESS(Status)) {
                        break;
                    }
                }
    
                Interface = IppFindInterfaceByIndex(Compartment, 
                                                    InterfaceIndex);
                if (Interface == NULL) {
                    Status = STATUS_NOT_FOUND;
                    break;
                }
            }
            
            if (State->MulticastInterface != NULL) {
                IppDereferenceInterface(State->MulticastInterface);
            }
            State->MulticastInterface = Interface;
            State->MulticastInterfaceOption = *(UINT*)Args->OptValBuffer;
            break;
    
        case IP_MULTICAST_TTL:      // And IPV6_MULTICAST_HOPS.
SetMulticastTtl:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }   
            //
            // HopLimit is passed in a UINT8 or UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT8)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            if (Args->OptValBufferLength < sizeof(UINT)) {
                //
                // Treat this as a UINT8. 
                //
                UintValue = *(UINT8 *)Args->OptValBuffer;
            } else {
                //
                // Treat this as a UINT. 
                //
                UintValue = *(UINT *)Args->OptValBuffer;
            }
            if (UintValue >= 256) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            State->MulticastHopLimit = (SHORT)UintValue;
            break;
    
        case IP_MULTICAST_LOOP:     // And IPV6_MULTICAST_LOOP.
SetMulticastLoopback:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            //
            // Flag can be passed as a BOOLEAN or UINT.
            //
            if (Args->OptValBufferLength < sizeof(BOOLEAN)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            if (Args->OptValBufferLength < sizeof(UINT)) {
                //
                // Treat this as a BOOLEAN. 
                //
                State->MulticastLoopback = *(BOOLEAN*)Args->OptValBuffer;
            } else {
                //
                // Treat this as a UINT. 
                //
                UintValue = *(UINT*)Args->OptValBuffer;
                State->MulticastLoopback = (UintValue != 0) ? TRUE : FALSE;
            }

            break;
            
        case IP_UNICAST_IF:       // And IPV6_UNICAST_IF.
            //
            // Interface Index is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
    
            //
            // Validate interface index.
            //
            InterfaceIndex = (IF_INDEX) *(UINT*)Args->OptValBuffer;
            if (InterfaceIndex == IFI_UNSPECIFIED) {
                Interface = NULL;
            } else {
                if (Protocol->Level == IPPROTO_IP) {
                    Status = IppGetInterfaceIndexFromSocketOption(
                        Compartment, 
                        (CONST UCHAR*) Args->OptValBuffer, 
                        &InterfaceIndex);
                    if (!NT_SUCCESS(Status)) {
                        break;
                    }
                }
    
                Interface = IppFindInterfaceByIndex(Compartment, 
                                                    InterfaceIndex);
                if (Interface == NULL) {
                    Status = STATUS_NOT_FOUND;
                    break;
                }
            }
            
            if (State->UnicastInterface != NULL) {
                IppDereferenceInterface(State->UnicastInterface);
            }
            State->UnicastInterface = Interface;
            break;
            
        case IP_DONTFRAGMENT:  // and IPV6_DONTFRAG
            //
            // Flag is passed in a UINT8 or UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT8)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            if (Args->OptValBufferLength < sizeof(UINT)) {
                //
                // Treat this as a UINT8. 
                //
                UintValue = *(UINT8 *)Args->OptValBuffer;
            } else {
                //
                // Treat this as a UINT. 
                //
                UintValue = *(UINT *)Args->OptValBuffer;
            }

            State->DontFragment = (UintValue != 0) ? TRUE : FALSE;
            State->DontFragmentSet = TRUE;
            break;
    
        case IP_RECEIVE_BROADCAST:
            //
            // This option is only valid for datagram sockets.
            //
            if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            //
            // Flag is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            State->ReceiveBroadcast = (UintValue != 0) ? TRUE : FALSE;
            break;
    
        case IP_PKTINFO:            // And IPV6_PKTINFO.
            //
            // This option is only valid for datagram sockets.
            //
            if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            //
            // Flag is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            State->ReceivePacketInfo = (UintValue != 0) ? TRUE : FALSE;
            break;
    
        case IP_RECVIF:             // And IPV6_RECVIF.
            //
            // This option is only valid for datagram sockets.
            //
            if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            //
            // Flag is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            State->ReceiveInterface = (UintValue != 0) ? TRUE : FALSE;
            break;
    
        case IP_RECVDSTADDR:        // And IPV6_RECVDSTADDR.
            //
            // This option is only valid for datagram sockets.
            //
            if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            //
            // Flag is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            State->ReceiveDestination = (UintValue != 0) ? TRUE : FALSE;
            break;
    
        case IP_HOPLIMIT:           // And IPV6_HOPLIMIT.
            //
            // This option is only valid for datagram sockets.
            //
            if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            //
            // Flag is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            State->ReceiveHopLimit = (UintValue != 0) ? TRUE : FALSE;
            break;
            
        case IP_ADD_MEMBERSHIP:     // And IPV6_ADD_MEMBERSHIP.
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Protocol->Level == IPPROTO_IP) {
                if (Args->OptValBufferLength < sizeof(IP_MREQ)) {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                MulticastRequest = (PIP_MREQ)Args->OptValBuffer;
                Status = IppGetInterfaceIndexFromSocketOption(
                    Compartment, 
                    (CONST UCHAR*)&MulticastRequest->imr_interface,
                    &InterfaceIndex);
                if (!NT_SUCCESS(Status)) {
                    break;
                }
                Status = IppProcessJoinRequest(
                    Compartment,
                    State,
                    Args->InspectHandle,
                    InterfaceIndex, 
                    (CONST UCHAR*)&MulticastRequest->imr_multiaddr,
                    Args->Context,
                    Args->CompletionRoutine);
            } else {
                if (Args->OptValBufferLength < sizeof(IPV6_MREQ)) {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                Ipv6MulticastRequest = (PIPV6_MREQ)Args->OptValBuffer;
                Status = IppProcessJoinRequest(
                    Compartment,
                    State,
                    Args->InspectHandle,
                    (CONST IF_INDEX)Ipv6MulticastRequest->ipv6mr_interface, 
                    (CONST UCHAR*)&Ipv6MulticastRequest->ipv6mr_multiaddr,
                    Args->Context,
                    Args->CompletionRoutine);
            }
            break;
    
        case MCAST_JOIN_GROUP:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(GROUP_REQ)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            GroupRequest = (PGROUP_REQ)Args->OptValBuffer;
            Status = IppProcessJoinRequest(
                Compartment,
                State,
                Args->InspectHandle,
                (CONST IF_INDEX)GroupRequest->gr_interface, 
                IppGetAddressFromSocketStorage(&GroupRequest->gr_group),
                Args->Context,
                Args->CompletionRoutine);
            break;
    
        case IP_DROP_MEMBERSHIP:    // And IPV6_DROP_MEMBERSHIP.
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Protocol->Level == IPPROTO_IP) {
                if (Args->OptValBufferLength < sizeof(IP_MREQ)) {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                MulticastRequest = (PIP_MREQ)Args->OptValBuffer;
                Status = IppGetInterfaceIndexFromSocketOption(
                    Compartment, 
                    (CONST UCHAR *)&MulticastRequest->imr_interface,
                    &InterfaceIndex);
                if (!NT_SUCCESS(Status)) {
                    break;
                }
                Status = IppProcessLeaveRequest(
                    Compartment,
                    State,
                    InterfaceIndex, 
                    (CONST UCHAR*)&MulticastRequest->imr_multiaddr);
            } else {
                if (Args->OptValBufferLength < sizeof(IPV6_MREQ)) {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                Ipv6MulticastRequest = (PIPV6_MREQ)Args->OptValBuffer;
                Status = IppProcessLeaveRequest(
                    Compartment,
                    State,
                    (CONST IF_INDEX)Ipv6MulticastRequest->ipv6mr_interface, 
                    (CONST UCHAR*)&Ipv6MulticastRequest->ipv6mr_multiaddr);
            }
            break;
    
        case MCAST_LEAVE_GROUP:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(GROUP_REQ)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            GroupRequest = (PGROUP_REQ)Args->OptValBuffer;
            Status = IppProcessLeaveRequest(
                Compartment,
                State,
                (CONST IF_INDEX)GroupRequest->gr_interface, 
                IppGetAddressFromSocketStorage(&GroupRequest->gr_group));
            break;
    
        case IP_ADD_SOURCE_MEMBERSHIP:
            if ((Client->Npi.Dispatch->Flags.DisallowMulticast) ||
                (Args->Level != IPPROTO_IP)){
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(IP_MREQ_SOURCE)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            MulticastSourceRequest = (PIP_MREQ_SOURCE)Args->OptValBuffer;
            Status = IppGetInterfaceIndexFromSocketOption(
                Compartment, 
                (CONST UCHAR*)&MulticastSourceRequest->imr_interface,
                &InterfaceIndex);
            if (!NT_SUCCESS(Status)) {
                break;
            }
            Status = IppProcessAddSource(
                Compartment,
                State,
                Args->InspectHandle,
                InterfaceIndex,
                (CONST UCHAR*)&MulticastSourceRequest->imr_multiaddr,
                (CONST UCHAR*)&MulticastSourceRequest->imr_sourceaddr,
                Args->Context,
                Args->CompletionRoutine);
            break;        
            
        case MCAST_JOIN_SOURCE_GROUP:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(GROUP_SOURCE_REQ)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            GroupSourceRequest = (PGROUP_SOURCE_REQ)Args->OptValBuffer;
            Status = IppProcessAddSource(
                Compartment,
                State,
                Args->InspectHandle,
                (CONST IF_INDEX)GroupSourceRequest->gsr_interface, 
                IppGetAddressFromSocketStorage(&GroupSourceRequest->gsr_group),
                IppGetAddressFromSocketStorage(&GroupSourceRequest->gsr_source),
                Args->Context,
                Args->CompletionRoutine);
            break;        
            
        case IP_DROP_SOURCE_MEMBERSHIP:
            if ((Client->Npi.Dispatch->Flags.DisallowMulticast) ||
                (Args->Level != IPPROTO_IP)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(IP_MREQ_SOURCE)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            MulticastSourceRequest = (PIP_MREQ_SOURCE)Args->OptValBuffer;
            Status = IppGetInterfaceIndexFromSocketOption(
                Compartment, 
                (CONST UCHAR*)&MulticastSourceRequest->imr_interface,
                &InterfaceIndex);
            if (!NT_SUCCESS(Status)) {
                break;
            }
            Status = IppProcessDropSource(
                Compartment,
                State,
                InterfaceIndex,
                (CONST UCHAR*)&MulticastSourceRequest->imr_multiaddr,
                (CONST UCHAR*)&MulticastSourceRequest->imr_sourceaddr);
            break;        
    
        case MCAST_LEAVE_SOURCE_GROUP:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(GROUP_SOURCE_REQ)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            GroupSourceRequest = (PGROUP_SOURCE_REQ)Args->OptValBuffer;
            Status = IppProcessDropSource(
                Compartment,
                State,
                (CONST IF_INDEX)GroupSourceRequest->gsr_interface, 
                IppGetAddressFromSocketStorage(&GroupSourceRequest->gsr_group),
                IppGetAddressFromSocketStorage(
                    &GroupSourceRequest->gsr_source));
            break;                
    
        case IP_BLOCK_SOURCE:
            if ((Client->Npi.Dispatch->Flags.DisallowMulticast) ||
                (Args->Level != IPPROTO_IP)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(IP_MREQ_SOURCE)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            MulticastSourceRequest = (PIP_MREQ_SOURCE)Args->OptValBuffer;
            Status = IppGetInterfaceIndexFromSocketOption(
                Compartment, 
                (CONST UCHAR*)&MulticastSourceRequest->imr_interface,
                &InterfaceIndex);
            if (!NT_SUCCESS(Status)) {
                break;
            }
            Status = IppProcessBlockSource(
                Compartment,
                State,
                InterfaceIndex,
                (CONST UCHAR*)&MulticastSourceRequest->imr_multiaddr,
                (CONST UCHAR*)&MulticastSourceRequest->imr_sourceaddr);
            break;        
            
        case MCAST_BLOCK_SOURCE:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(GROUP_SOURCE_REQ)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            GroupSourceRequest = (PGROUP_SOURCE_REQ)Args->OptValBuffer;
            Status = IppProcessBlockSource(
                Compartment,
                State,
                (CONST IF_INDEX)GroupSourceRequest->gsr_interface, 
                IppGetAddressFromSocketStorage(&GroupSourceRequest->gsr_group),
                IppGetAddressFromSocketStorage(
                    &GroupSourceRequest->gsr_source));
            break;                
    
        case IP_UNBLOCK_SOURCE:
            if ((Client->Npi.Dispatch->Flags.DisallowMulticast) ||
                (Args->Level != IPPROTO_IP)){
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (Args->OptValBufferLength < sizeof(IP_MREQ_SOURCE)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            MulticastSourceRequest = (PIP_MREQ_SOURCE)Args->OptValBuffer;
            Status = IppGetInterfaceIndexFromSocketOption(
                Compartment, 
                (CONST UCHAR*)&MulticastSourceRequest->imr_interface,
                &InterfaceIndex);
            if (!NT_SUCCESS(Status)) {
                break;
            }
            Status = IppProcessUnblockSource(
                Compartment,
                State,
                InterfaceIndex,
                (CONST UCHAR*)&MulticastSourceRequest->imr_multiaddr,
                (CONST UCHAR*)&MulticastSourceRequest->imr_sourceaddr);
            break;        
            
        case MCAST_UNBLOCK_SOURCE:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < sizeof(GROUP_SOURCE_REQ)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            GroupSourceRequest = (PGROUP_SOURCE_REQ)Args->OptValBuffer;
            Status = IppProcessUnblockSource(
                Compartment,
                State,
                (CONST IF_INDEX)GroupSourceRequest->gsr_interface, 
                IppGetAddressFromSocketStorage(&GroupSourceRequest->gsr_group),
                IppGetAddressFromSocketStorage(
                    &GroupSourceRequest->gsr_source));
            break;                
            
        default:
            Status = STATUS_NOT_SUPPORTED;
            break;
        }
    } else {
        // 
        // Process a socket ioctl.
        //
        switch (Args->OptName) {
        case SIO_GET_MULTICAST_FILTER:
            if (Protocol->Level != IPPROTO_IP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (Args->OptValBufferLength < IP_MSFILTER_SIZE(0)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }        
            MulticastFilter = (PIP_MSFILTER) Args->OptValBuffer;

            Status = IppGetInterfaceIndexFromSocketOption(
                Compartment, 
                (CONST UCHAR*)&MulticastFilter->imsf_interface,
                &InterfaceIndex);
            if (!NT_SUCCESS(Status)) {
                break;
            }

            if (State != NULL) {
                MulticastState = IppFindMulticastSessionState(
                    State,
                    Compartment,
                    (CONST UCHAR*)&MulticastFilter->imsf_multiaddr,
                    InterfaceIndex);
            } else {
                MulticastState = NULL;
            }
            if (MulticastState == NULL) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            //
            // SourceCount is guaranteed to not cause an overflow in
            // IP_MSFILTER_SIZE. 
            //
            SourceCount = MulticastState->SourceCount;
            ASSERT(SourceCount <= MAX_MULTICAST_SOURCE_COUNT);
            OutputBufferLength = IP_MSFILTER_SIZE(SourceCount);

            if (Args->OutputBufferLength < OutputBufferLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            OutputMulticastFilter = (PIP_MSFILTER) Args->OutputBuffer;

            OutputMulticastFilter->imsf_multiaddr =
                MulticastFilter->imsf_multiaddr;
            OutputMulticastFilter->imsf_interface =
                MulticastFilter->imsf_interface;
            OutputMulticastFilter->imsf_fmode = MulticastState->Mode;
            OutputMulticastFilter->imsf_numsrc = SourceCount;
            
            IppGetMulticastSessionStateSourceList(
                MulticastState,
                (PUCHAR)&OutputMulticastFilter->imsf_slist);
            
            break;
        
        case SIOCGMSFILTER:
            if (Args->OptValBufferLength < GROUP_FILTER_SIZE(0)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }        
            GroupFilter = (PGROUP_FILTER) Args->OptValBuffer;

            if (State != NULL) {
                MulticastState =
                    IppFindMulticastSessionState(
                        State,
                        Compartment,
                        IppGetAddressFromSocketStorage(&GroupFilter->gf_group),
                        (CONST IF_INDEX)GroupFilter->gf_interface);
            } else {
                MulticastState = NULL;
            }
            if (MulticastState == NULL) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            //
            // SourceCount is guaranteed to not cause an overflow in
            // GROUP_FILTER_SIZE. 
            //
            SourceCount = MulticastState->SourceCount;
            ASSERT(SourceCount <= MAX_MULTICAST_SOURCE_COUNT);
            OutputBufferLength = GROUP_FILTER_SIZE(SourceCount);

            if (Args->OutputBufferLength < OutputBufferLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            OutputGroupFilter = (PGROUP_FILTER) Args->OutputBuffer;

            OutputGroupFilter->gf_interface = GroupFilter->gf_interface;
            OutputGroupFilter->gf_group = GroupFilter->gf_group;
            OutputGroupFilter->gf_fmode = MulticastState->Mode;
            OutputGroupFilter->gf_numsrc = SourceCount;
            
            
            //
            // REVIEW: is there any way to avoid this allocation?
            //
            SourceList =
                ExAllocatePoolWithTag(
                    NonPagedPool, 
                    SourceCount * AddressBytes, 
                    IpGenericPoolTag);
            if (SourceList == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            IppGetMulticastSessionStateSourceList(MulticastState, SourceList);
            for (Count = 0; Count < SourceCount; Count++) {
                IppSetAddressInSocketStorage(
                    &OutputGroupFilter->gf_slist[Count], 
                    SourceList + (Count * AddressBytes),
                    Protocol->Characteristics->NetworkProtocolId);
            }
            ExFreePool(SourceList);

            break;

        case SIO_GET_INTERFACE_LIST:
            if (Protocol->Level != IPPROTO_IP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            Status =
                IppGetInterfaceList(
                    Compartment,
                    Args->OutputBuffer,
                    Args->OutputBufferLength,
                    &OutputBufferLength);

            break;

        case SIO_MULTICAST_SCOPE:
            goto SetMulticastTtl;

        case SIO_MULTIPOINT_LOOPBACK:
            goto SetMulticastLoopback;

        case SIO_ADDRESS_LIST_SORT:
        {
            SOCKET_ADDRESS_LIST *InputAddressList = 
                (SOCKET_ADDRESS_LIST *) Args->OptValBuffer;
            SOCKET_ADDRESS_LIST *OutputAddressList = 
                (SOCKET_ADDRESS_LIST *) Args->OutputBuffer;

            if (Protocol->Level == IPPROTO_IP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            
            //
            // Validate buffers.  The caller is supposed to ensure that the
            // SOCKET_ADDRESS_LISTs are probed and locked or are from
            // the non-paged pool.  
            // However the SOCKET_ADDRESS_LIST::SOCKET_ADDRESS::lpSockaddr
            // members do not have this assumption. IppSortDestinationAddresses
            // later on validates lpSockaddr by probing if called in the
            // context of a user-mode thread.
            //
            if ((OutputAddressList == NULL) ||
                (InputAddressList == NULL) ||
                (Args->OptValBufferLength < SIZEOF_SOCKET_ADDRESS_LIST(0)) ||
                (Args->OptValBufferLength < 
                 SIZEOF_SOCKET_ADDRESS_LIST(
                    InputAddressList->iAddressCount)) ||
                (InputAddressList->iAddressCount < 0) ||
                (Args->OutputBufferLength < SIZEOF_SOCKET_ADDRESS_LIST(0)) ||
                (Args->OutputBufferLength < 
                 SIZEOF_SOCKET_ADDRESS_LIST(
                    InputAddressList->iAddressCount))) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            
            //
            // IppSortDestinationAddresses needs to be called at 
            // IRQL <= APC_LEVEL so release any locks and re-acquire
            // them later.  (It's possible to rewrite IpNlpSetSessionInfo
            // so that we are lock free in this instance but there's
            // little advantage to it.)
            //
            KeReleaseSpinLock(&State->SpinLock, OldIrql);            
            Status = 
                IppSortDestinationAddresses(
                    Compartment,
                    InputAddressList,
                    OutputAddressList);
            KeAcquireSpinLock(&State->SpinLock, &OldIrql);            
            if (NT_SUCCESS(Status)) {
                OutputBufferLength = 
                    SIZEOF_SOCKET_ADDRESS_LIST(
                        OutputAddressList->iAddressCount);
            }
            break;            
        }     
            
        case SIO_SET_MULTICAST_FILTER:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if ((Args->OptValBufferLength < IP_MSFILTER_SIZE(0)) ||
                (Protocol->Level != IPPROTO_IP)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            MulticastFilter = (PIP_MSFILTER) Args->OptValBuffer;
            if (MulticastFilter->imsf_numsrc > MAX_MULTICAST_SOURCE_COUNT) {
                //
                // The number of sources is large enough to cause an overflow.
                //
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (Args->OptValBufferLength < 
                IP_MSFILTER_SIZE(MulticastFilter->imsf_numsrc)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Status = IppGetInterfaceIndexFromSocketOption(
                Compartment, 
                (CONST UCHAR*)&MulticastFilter->imsf_interface,
                &InterfaceIndex);
            if (!NT_SUCCESS(Status)) {
                break;
            }
            Status = IppProcessSetMulticastFilter(
                Compartment,
                State,
                Args->InspectHandle,
                InterfaceIndex,
                (CONST UCHAR*)&MulticastFilter->imsf_multiaddr,
                MulticastFilter->imsf_fmode,
                MulticastFilter->imsf_numsrc,
                (CONST UCHAR*)&MulticastFilter->imsf_slist,
                Args->Context,
                Args->CompletionRoutine);
            break;
    
        case SIOCSMSFILTER:
            if (Client->Npi.Dispatch->Flags.DisallowMulticast) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if (Args->OptValBufferLength < GROUP_FILTER_SIZE(0)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            GroupFilter = (PGROUP_FILTER) Args->OptValBuffer;
            if (GroupFilter->gf_numsrc > MAX_MULTICAST_SOURCE_COUNT) {
                //
                // The number of sources is large enough to cause an
                // overflow. 
                //
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            
            if (Args->OptValBufferLength < 
                GROUP_FILTER_SIZE(GroupFilter->gf_numsrc)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            //
            // Allocate a source list and initialize it with the addresses
            // extracted from the sockaddr_storage array.
            //
            // REVIEW: is there any way to avoid this allocation?
            //
            if (GroupFilter->gf_numsrc > 0) {
                SourceList = ExAllocatePoolWithTag(
                    NonPagedPool, 
                    AddressBytes * GroupFilter->gf_numsrc, 
                    IpGenericPoolTag);
                if (SourceList == NULL) {
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }
            } else {
                SourceList = NULL;
            }
            
            for (Count = 0; Count < GroupFilter->gf_numsrc; Count++) {
                RtlCopyMemory(
                    SourceList + (Count * AddressBytes), 
                    IppGetAddressFromSocketStorage(
                        &GroupFilter->gf_slist[Count]),
                    AddressBytes);
            }
            
            Status = IppProcessSetMulticastFilter(
                Compartment,
                State,
                Args->InspectHandle,
                (CONST IF_INDEX)GroupFilter->gf_interface,
                IppGetAddressFromSocketStorage(&GroupFilter->gf_group),
                GroupFilter->gf_fmode,
                GroupFilter->gf_numsrc,
                SourceList,
                Args->Context,
                Args->CompletionRoutine);
            if (GroupFilter->gf_numsrc > 0) {
                ExFreePool(SourceList);
            }
            break;
    
        case SIO_RCVALL:
            //
            // Value is passed in a UCHAR or longer.
            //
            if (Args->OptValBufferLength < sizeof(UCHAR)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            //
            // Validate mode.
            //
            UcharValue = *(UCHAR*)Args->OptValBuffer;
            if (UcharValue > RCVALL_MAX) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            //
            // Get interface.
            //
            Interface = IppGetInterface(Compartment, &Args->NlInterface);
            if (Interface == NULL) {
                Status = STATUS_NOT_FOUND;
                break;
            }
            goto RcvAll;
    
        case SIO_RCVALL_IF:
            {
                RCVALL_IF Request;
    
                if (Args->OptValBufferLength < sizeof(Request)) {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
    
                //
                // Ensure structure is aligned.
                // REVIEW: Is this required.  These are BUFFERED ioctls and
                // alignment is guaranteed.
                // 
                RtlCopyMemory(&Request, Args->OptValBuffer, sizeof(Request));
    
                if (Request.Mode > RCVALL_MAX) {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
    
                UcharValue = (UCHAR) Request.Mode;
    
                Interface = IppFindInterfaceByIndex(Compartment, 
                                                    Request.Interface);
                if (Interface == NULL) {
                    Status = STATUS_NOT_FOUND;
                    break;
                }
            }
    
        RcvAll:
            if (Client->Npi.Dispatch->UpperLayerProtocolId != 
                IPPROTO_RESERVED_RAW) {
                IppDereferenceInterface(Interface);
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
    
            if ((State->PromiscuousInterface != NULL) &&
                (State->PromiscuousInterface != Interface)) {
                //
                // Changing directly from one interface to another is not 
                // supported.  One must turn off the behavior on the first one 
                // before enabling it on the new one.  This ensures that
                // the add and the remove calls below cannot both pend.
                //
                IppDereferenceInterface(Interface);
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Status = IppInspectPromiscuousRequest(
                        Protocol->Level,
                        Args->InspectHandle, 
                        (PNL_INTERFACE) Interface,
                        UcharValue,
                        NULL,
                        NULL);
            if (!NT_SUCCESS(Status)) {
                IppDereferenceInterface(Interface);                
                break;
            }
    
            //
            // Bump the new refcount first, to prevent extra calls down to 
            // a lower layer.
            //
            Status = IppAddPromiscuousReference(Interface, 
                                                UcharValue, 
                                                Args->Context,
                                                Args->CompletionRoutine);
    
            //
            // Remove old mode, if any.
            //
            if (State->PromiscuousInterface != NULL) {
                NTSTATUS RemoveStatus;
    
                RemoveStatus = IppRemovePromiscuousReference(
                                        State->PromiscuousInterface,
                                        State->PromiscuousMode,
                                        Args->Context,
                                        Args->CompletionRoutine);
                IppDereferenceInterface(State->PromiscuousInterface);
    
                if (RemoveStatus == STATUS_PENDING) {
                    Status = STATUS_PENDING;
                }
            }
    
            //
            // Save the new mode.
            //
            State->PromiscuousMode = UcharValue;
            if (UcharValue == RCVALL_OFF) {
                State->PromiscuousInterface = NULL;
                IppDereferenceInterface(Interface);
            } else {
                State->PromiscuousInterface = Interface;
            }
            break;
    
        case SIO_RCVALL_MCAST:
        case SIO_RCVALL_IGMPMCAST:
            //
            // Value is passed in a UCHAR or longer.
            //
            if (Args->OptValBufferLength < sizeof(UCHAR)) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
        
            //
            // Validate mode.
            //
            UcharValue = *(UCHAR*)Args->OptValBuffer;
            if (UcharValue > RCVALL_MAX) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
        
            //
            // Get interface.
            //
            Interface = IppGetInterface(Compartment, &Args->NlInterface);
            if (Interface == NULL) {
                Status = STATUS_NOT_FOUND;
                break;
            }
            goto RcvallMcast;
    
        case SIO_RCVALL_MCAST_IF:
            {
                RCVALL_IF Request;
    
                if (Args->OptValBufferLength < sizeof(Request)) {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
    
                //
                // Ensure structure is aligned.
                // REVIEW: Is this required.  These are BUFFERED ioctls and
                // alignment is guaranteed.
                //
                RtlCopyMemory(&Request, Args->OptValBuffer, sizeof(Request));
    
                if (Request.Mode > RCVALL_MAX) {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
    
                UcharValue = (UCHAR) Request.Mode;
    
                Interface = IppFindInterfaceByIndex(Compartment, 
                                                    Request.Interface);
                if (Interface == NULL) {
                    Status = STATUS_NOT_FOUND;
                    break;
                }
            }
        
        RcvallMcast:
            if (Client->Npi.Dispatch->UpperLayerProtocolId !=
                IPPROTO_RESERVED_RAW) {
                Status = STATUS_INVALID_PARAMETER;
                IppDereferenceInterface(Interface);
                break;
            }
    
            if ((State->AllMulticastInterface != NULL) &&
                (State->AllMulticastInterface != Interface)) {
                //
                // Changing directly from one interface to another is not
                // supported.  One must turn off the behavior on the first one
                // before enabling it on the new one.  This ensures that
                // the add and the remove calls below cannot both pend.
                //
                IppDereferenceInterface(Interface);
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Status = IppInspectAllMulticastRequest(
                        Protocol->Level,
                        Args->InspectHandle,
                        (PNL_INTERFACE) Interface,
                        UcharValue,
                        NULL,
                        NULL);
            if (!NT_SUCCESS(Status)) {
                IppDereferenceInterface(Interface);
                break;
            }
        
            //
            // Bump the new refcount first, to prevent extra calls down to
            // a lower layer.
            //
            Status = IppAddAllMulticastReference(Interface, 
                                                 UcharValue, 
                                                 Args->Context,
                                                 Args->CompletionRoutine);
    
            //
            // Remove old mode, if any.
            //
            if (State->AllMulticastInterface != NULL) {
                NTSTATUS RemoveStatus;
    
                RemoveStatus = IppRemoveAllMulticastReference(
                                        State->AllMulticastInterface,
                                        State->AllMulticastMode,
                                        Args->Context,
                                        Args->CompletionRoutine);
                IppDereferenceInterface(State->AllMulticastInterface);
    
                if (RemoveStatus == STATUS_PENDING) {
                    Status = STATUS_PENDING;
                }
            }
    
            //
            // Save the new mode.
            //
            State->AllMulticastMode = UcharValue;
            if (UcharValue == RCVALL_OFF) {
                State->AllMulticastInterface = NULL;
                IppDereferenceInterface(Interface);
            } else {
                State->AllMulticastInterface = Interface;
            }
            break;

        case IP_RECVRTHDR:        // And IPV6_RECVRTHDR.
            //
            // This option is only valid for datagram sockets.
            //
            if (Client->Npi.Dispatch->UpperLayerProtocolId == IPPROTO_TCP) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            //
            // Flag is passed in a UINT.
            //
            if (Args->OptValBufferLength < sizeof(UINT)) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            UintValue = *(UINT*)Args->OptValBuffer;
            State->ReceiveRoutingHeader = (UintValue != 0) ? TRUE : FALSE;
            break;
        default:
            Status = STATUS_NOT_SUPPORTED;
            break;
        }
    }

    State->FastPathCompatible = 
        IS_SESSION_STATE_FAST_PATH_COMPATIBLE(
                Client->Npi.Dispatch->UpperLayerProtocolId,
                State);

    KeReleaseSpinLock(&State->SpinLock, OldIrql);

    Args->AncillaryDataLength = 
        IppGetAncillaryDataLength(Protocol, State, NULL);
    Args->OutputBufferLength = OutputBufferLength;
    
    IppDereferenceCompartment(Compartment);    
    return Status;
}

VOID
IppReverseGenericAddressArray(
    IN OUT PUCHAR Array,
    IN ULONG ArrayByteSize,
    IN ULONG AddressLength
    )
/*++

Routine Description:

    Given an array of IPv4 or IPv6 addresses, reorders the addresses so that
    they appear in reverse order.

Arguments:

    Array - Supplies the array to reverse; returns the reversed array.

    ArrayByteSize - Supplies the size of the array in bytes.

    AddressLength - Supplies the size in bytes of each constiuent address of
        the array.

Return Value:

    None.

--*/
{
    UCHAR TemporaryElement[sizeof(IP_ADDRESS_STORAGE)];
    ULONG BytesLeft;
        
    ASSERT((ArrayByteSize % AddressLength) == 0);

    //
    // We divide the array into two.  The walk the two parts starting at 
    // opposite ends and swapping the corresponding elements.
    //
    // Find BytesLeft to swap, by finding the number of elements (ArrayByteSize  
    // divided by AddressLength), dividing by 2 and DROPPING the middle element,
    // and multiplying by AddressLength again.
    //
    BytesLeft = ((ArrayByteSize / AddressLength) / 2) * AddressLength;
    while (BytesLeft >= AddressLength) {
        ULONG i = ArrayByteSize - BytesLeft;
        ULONG j = BytesLeft - AddressLength;

        RtlCopyMemory(
            TemporaryElement, 
            Array + i,
            AddressLength);
        
        RtlCopyMemory(
            Array + i,
            Array + j,
            AddressLength);
        
        RtlCopyMemory(
            Array + j,
            TemporaryElement, 
            AddressLength);
        
        BytesLeft -= AddressLength;
    }
}

NTSTATUS
NTAPI
IpNlpReverseRoutingHeader(
    IN OUT PNL_REQUEST_REVERSE_ROUTING_HEADER Args
    )
/*++

Routine Description:

    Reverses a given routing header so that it can be used as a return route
    for a source routed packet.

Arguments:

    Args - Supplies the routing header to reverse; returns the reversed routing
        header.

Return Value:

    STATUS_SUCCESS on success or an NT Status error otherwise.
    
--*/
{
    if (Args->Protocol == IPPROTO_IP) {
        PIPV4_ROUTING_HEADER Ipv4RoutingHeader = Args->RoutingHeader;

        IppReverseGenericAddressArray(
            (PUCHAR) (Ipv4RoutingHeader + 1),
            Ipv4RoutingHeader->OptionLength - sizeof(IPV4_ROUTING_HEADER),
            sizeof(IN_ADDR));
        Ipv4RoutingHeader->Pointer = sizeof(IPV4_ROUTING_HEADER) + 1;
    } else if (Args->Protocol == IPPROTO_IPV6) {
        PIPV6_ROUTING_HEADER Ipv6RoutingHeader = Args->RoutingHeader;
        ULONG AddressArraySize = Ipv6RoutingHeader->Length - 
            sizeof(IPV6_ROUTING_HEADER);

        IppReverseGenericAddressArray(
            (PUCHAR) (Ipv6RoutingHeader + 1),
            AddressArraySize,
            sizeof(IN6_ADDR));
        Ipv6RoutingHeader->SegmentsLeft = 
        (UINT8) (AddressArraySize / sizeof(IN6_ADDR));
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}
