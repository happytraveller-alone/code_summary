/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    init.c

Abstract:

    This module contains the main IPv4 registration/deregistration
    functionality.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "nlmnpip.h"
#include "init.tmh"

extern CONST NPI_MODULEID NPI_MS_IPV4_MODULEID;
extern CONST NPIID NPI_NL_PNP_EVENT_ACCESS_ID;

CONST IP_INTERNAL_CLIENT_CONTEXT Ipv4InternalClientContext = {
    &Ipv4Global,
    IP_CLIENT_CONTEXT_SIGNATURE
};

//
// Network Layer Provider data.
//
CONST NL_PROVIDER_CHARACTERISTICS Ipv4NlProviderCharacteristics = {
    0,
    sizeof(NL_PROVIDER_CHARACTERISTICS),
    AF_INET,
    sizeof(IN_ADDR),
    sizeof(IPV4_HEADER) + IP_EXTRA_DATA_BACKFILL,
};

//
// Network Layer PnP event Provider routines.
//
CONST NL_PNP_EVENT_PROVIDER_CHARACTERISTICS
Ipv4NlPnpEventProviderCharacteristics = {
    0,
    sizeof(NL_PNP_EVENT_PROVIDER_CHARACTERISTICS),
    AF_INET
};

CONST NL_PNP_EVENT_PROVIDER_DISPATCH Ipv4NlPnpEventProviderDispatch = {
    0, sizeof(NL_PNP_EVENT_PROVIDER_DISPATCH),
    IpNlpPnpEventCompleteInterface
};

//
// NSI notify routines.
//
NTSTATUS
NTAPI
Ipv4AttachPnpEventClient(
    IN HANDLE  NmrBindingHandle,
    IN PVOID  ProviderContext,
    IN PNPI_REGISTRATION_INSTANCE  ClientRegistrationInstance,
    IN PVOID  ClientBindingContext,
    IN CONST VOID *ClientDispatch,
    OUT PVOID  *ProviderBindingContext,
    OUT CONST VOID*  *ProviderDispatch
    )
{
    PPNP_EVENT_CLIENT_CONTEXT Old, ClientContext;
    PIP_PROTOCOL Protocol = &Ipv4Global;

    UNREFERENCED_PARAMETER(ProviderContext);
    UNREFERENCED_PARAMETER(ClientRegistrationInstance);

    //
    // Allocate context for this binding.
    //
    ClientContext = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(*ClientContext), 'cisN');
    if (ClientContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    //
    // Remember the client's NPI in the ClientContext.
    //
    RtlZeroMemory(ClientContext, sizeof(*ClientContext));
    ClientContext->Npi.Dispatch = ClientDispatch;
    ClientContext->Npi.ProviderHandle = ClientBindingContext;
    ClientContext->Protocol = Protocol;
    ClientContext->NmrBindingHandle = NmrBindingHandle;

    //
    // Initialize the ProviderNpi required by the client.
    //
    *ProviderBindingContext = ClientContext;
    *((PNL_PNP_EVENT_PROVIDER_DISPATCH)ProviderDispatch) = 
        Ipv4NlPnpEventProviderDispatch;
    
    //
    // Ensure there is only one client (TDX), and initialize.
    //
    Old =
        InterlockedCompareExchangePointer(
            &Protocol->PnpClientContext, ClientContext, NULL);
    if (Old != NULL) {
        ExFreePool(ClientContext);
        return STATUS_UNSUCCESSFUL;
    }

    RoInitialize(&Protocol->PnpClientReferenceObject);
    
    return STATUS_SUCCESS;
}

//
// PNP notify routines.
//

NTSTATUS
NTAPI
Ipv4DetachPnpEventClient(
    IN PVOID  ProviderBindingContext
    )
{
    PPNP_EVENT_CLIENT_CONTEXT ClientContext =
        (PPNP_EVENT_CLIENT_CONTEXT) ProviderBindingContext;
    PIP_PROTOCOL Protocol = ClientContext->Protocol;
    
    
    ClientContext->PendingDetachBindingHandle = 
        ClientContext->NmrBindingHandle;
    
    //
    // Mark the client context as disabled to prevent any new requests from
    // using the client.
    //
    if (RoUnInitialize(&Protocol->PnpClientReferenceObject)) {
        Protocol->PnpClientContext = NULL;
        return STATUS_SUCCESS;
    } else {
        return STATUS_PENDING;
    }
}

VOID
NTAPI
Ipv4CleanupPnpEventClientContext(
    IN PVOID  ProviderBindingContext
    )
{
    ExFreePool(ProviderBindingContext);
}

VOID
Ipv4DeregisterPnpEventComplete(
    IN PVOID  ProviderContext
    )
{
    UNREFERENCED_PARAMETER(ProviderContext);

    IppDefaultStopRoutine(&Ipv4Global);
}

CONST NPI_PROVIDER_CHARACTERISTICS Ipv4PnpEventProviderNotify = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    (PNPI_PROVIDER_ATTACH_CLIENT_FN)Ipv4AttachPnpEventClient,
    Ipv4DetachPnpEventClient,
    Ipv4CleanupPnpEventClientContext,
    {
        0,
        sizeof(NPI_REGISTRATION_INSTANCE),
        &NPI_NL_PNP_EVENT_ACCESS_ID,
        &NPI_MS_IPV4_MODULEID,
        0,
        &Ipv4NlPnpEventProviderCharacteristics
    }
};

//
// Framing Layer Client data.
//

CONST FL_CLIENT_DISPATCH Ipv4FlClientDispatch = {
    0, sizeof(FL_CLIENT_DISPATCH),
    AF_INET,
    IpFlcAddInterface,
    IpFlcDeleteInterface,
    IpFlcUpdateInterface,
    IpFlcAddSubInterface,
    IpFlcDeleteSubInterface,
    IpFlcUpdateSubInterface,
    IpFlcPnpEvent,
    IpFlcReceivePackets,
    IpFlcReceivePreValidatedPackets,
    Ipv4FlcReceiveNeighborSolicitation,
    Ipv4FlcReceiveNeighborAdvertisement,
    IpFlcInitiateNeighborOffloadComplete,
    IpFlcTerminateNeighborOffloadComplete,
    IpFlcUpdateNeighborOffloadComplete,
    IpFlcInvalidateNeighborOffloadComplete,
    Ipv4QueryOffloadComplete,
    IpFlcQueryNeighborReachability,
    IpFlcSuspectNeighborReachability,
    IpFlcIndicateOffloadEvent
};

//
// NSI Module Provider data.
//
CONST NSI_INFORMATION_OBJECT Ipv4InformationObject[] = {
    {                           // NlBestRouteObject
        sizeof(IPV4_BEST_ROUTE_KEY),
        0,
        sizeof(IPV4_BEST_ROUTE_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv4GetAllBestRouteParameters,
        NULL
    },
    {                           // NlCompartmentForwardingObject.
        sizeof(NL_COMPARTMENT_KEY),
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        IpSetAllCompartmentForwardingParameters,
    },
    {                           // NlCompartmentObject.
        sizeof(NL_COMPARTMENT_KEY),
        sizeof(NL_COMPARTMENT_RW),
        sizeof(NL_COMPARTMENT_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllCompartmentParameters,
        IpSetAllCompartmentParameters,
    },
    {                           // NlControlProtocolObject.
        0,
        0,
        sizeof(NL_CONTROL_PROTOCOL_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllIcmpParameters,
        NULL
    },
    {                           // NlEchoRequestObject.
        sizeof(NL_ECHO_REQUEST_KEY),
        sizeof(IPV4_ECHO_REQUEST_RW),
        sizeof(NL_ECHO_REQUEST_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv4GetAllEchoRequestParameters,
        Ipv4SetAllEchoRequestParameters,
        NULL,
        IpRegisterEchoRequestChangeNotification,
        IpDeregisterEchoRequestChangeNotification,
    },
    {                           // NlEchoSequenceRequestObject.
        0,
        0,
        sizeof(NL_ECHO_SEQUENCE_REQUEST_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IppGetAllEchoSequenceRequestParameters,
        NULL,
    },
    {                           // NlGlobalObject.
        0,
        sizeof(NL_GLOBAL_RW),
        sizeof(NL_GLOBAL_ROD),
        sizeof(NL_GLOBAL_ROS),
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllGlobalParameters,
        IpSetAllGlobalParameters
    },
    {                           // NlInterfaceObject.
        sizeof(NL_INTERFACE_KEY),
        sizeof(NL_INTERFACE_RW),
        sizeof(NL_INTERFACE_ROD),
        sizeof(NL_INTERFACE_ROS),
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllInterfaceParameters,
        IpSetAllInterfaceParameters,
        NULL,
        IpRegisterInterfaceChangeNotification,
        IpDeregisterInterfaceChangeNotification,
    },
    {                           // NlLocalAnycastAddressObject.
        sizeof(IPV4_LOCAL_ADDRESS_KEY),
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllLocalAnycastAddressParameters,
        IpSetAllLocalAnycastAddressParameters,
        NULL,
        NULL, 
        NULL,
    },
    {                           // NlLocalMulticastAddressObject.
        sizeof(IPV4_LOCAL_ADDRESS_KEY),
        0,
        sizeof(NL_LOCAL_MULTICAST_ADDRESS_ROD),
        sizeof(NL_LOCAL_MULTICAST_ADDRESS_ROS),
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllLocalMulticastAddressParameters,
        NULL,
        NULL,
        NULL,
        NULL,
    },
    {                           // NlLocalUnicastAddressObject.
        sizeof(IPV4_LOCAL_ADDRESS_KEY),
        sizeof(NL_LOCAL_UNICAST_ADDRESS_RW),
        sizeof(NL_LOCAL_UNICAST_ADDRESS_ROD),
        sizeof(NL_LOCAL_UNICAST_ADDRESS_ROS),
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllLocalUnicastAddressParameters,
        IpSetAllLocalUnicastAddressParameters,
        NULL,
        IpRegisterAddressChangeNotification,
        IpDeregisterAddressChangeNotification,
    },
    {                           // NlNeighborObject.
        sizeof(IPV4_NEIGHBOR_KEY),
        sizeof(NL_NEIGHBOR_RW),
        sizeof(NL_NEIGHBOR_ROD),
        sizeof(NL_NEIGHBOR_ROS),
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllNeighborParameters,
        IpSetAllNeighborParameters
    },
    {                           // NlPathObject.
        sizeof(IPV4_PATH_KEY),
        sizeof(NL_PATH_RW),
        sizeof(IPV4_PATH_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv4GetAllPathParameters,
        Ipv4SetAllPathParameters,
        Ipv4EnumerateAllPaths,
    },
    {                           // NlPotentialRouterObject.
        0,
    },
    {                           // NlPrefixPolicyObject.
        0,
    },
    {                           // NlProxyNeighborObject.
        sizeof(IPV4_PROXY_NEIGHBOR_KEY),
        sizeof(NL_PROXY_NEIGHBOR_RW),
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllProxyNeighborParameters,
        IpSetAllProxyNeighborParameters
    },
    {                           // NlRouteObject.
        sizeof(IPV4_ROUTE_KEY),
        sizeof(NL_ROUTE_RW),
        sizeof(IPV4_ROUTE_ROD),
        sizeof(NL_ROUTE_ROS),
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllRouteParameters,
        Ipv4SetAllRouteParameters,
        NULL,
        IpRegisterRouteChangeNotification,
        IpDeregisterRouteChangeNotification,
    },
    {                           // NlSitePrefixObject.
        0,
    },
    {                           // NlSubInterfaceObject.
        sizeof(NL_SUBINTERFACE_KEY),
        sizeof(NL_SUBINTERFACE_RW),
        sizeof(NL_SUBINTERFACE_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllSubInterfaceParameters,
        IpSetAllSubInterfaceParameters
    },
    {                           // NlWakeUpPatternObject.
        sizeof(NL_WAKE_UP_PATTERN_KEY),
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        IpSetAllWakeUpPatternParameters
    },
    {                           // NlResolveNeighborObject.
        sizeof(IPV4_NEIGHBOR_KEY),
        sizeof(NL_NEIGHBOR_RW),
        sizeof(NL_NEIGHBOR_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllResolveNeighborParameters,
        NULL
    },
    {                           // NlSortAddressesObject.
        0,
    },
    {                           // NlMfeObject.
        sizeof(IPV4_MFE_KEY),
        sizeof(NL_MFE_RW),
        sizeof(NL_MFE_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv4GetAllMulticastForwardingParameters,
        Ipv4SetAllMulticastForwardingParameters,
        NULL,
    },
    {                           // NlMfeNotifyObject.
        0,
        0,
        sizeof(IPV4_MFE_NOTIFICATION_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        IpRegisterMulticastForwardingChangeNotification,
        IpDeregisterMulticastForwardingChangeNotification,
    },
    {                           // NlInterfaceHopObject.
        sizeof(NL_INTERFACE_KEY),
        0,
        sizeof(NL_INTERFACE_HOP_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllInterfaceHopParameters,
        NULL
    },
    {                           // NlDbgPacketPatternObject.
        0,
        sizeof(NLP_DBG_PACKET_PATTERN_RW),
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        IpSetAllDbgPacketPatternParameters
    }
};

CONST NM_PROVIDER_DISPATCH Ipv4NsiProviderDispatch = {
    0, sizeof(NM_PROVIDER_DISPATCH),
    sizeof(Ipv4InformationObject) / sizeof(NSI_INFORMATION_OBJECT),
    Ipv4InformationObject
};

CONST NM_PROVIDER_CHARACTERISTICS Ipv4NsiProviderCharacter = {
    sizeof(NM_PROVIDER_CHARACTERISTICS),
    0
};


//
// Framing Layer Client routines.
//
NTSTATUS
NTAPI
Ipv4AttachFlProvider(
    IN HANDLE  NmrBindingHandle,
    IN PVOID  ClientContext,
    IN PNPI_REGISTRATION_INSTANCE  ProviderRegistrationInstance
    )
{
    NTSTATUS Status;
    CONST FL_PROVIDER_CHARACTERISTICS *Character;
    PFL_PROVIDER_CONTEXT ProviderContext;
    FL_CLIENT_NPI MyNpi;
    PIP_PROTOCOL Protocol = (PIP_PROTOCOL)ClientContext;

    Character = (CONST FL_PROVIDER_CHARACTERISTICS*)
        ProviderRegistrationInstance->NpiSpecificCharacteristics;

    //
    // Refuse the binding if the framing layer is not one that we support.
    //
    if (!Character
        || (AF_INET != Character->NetworkLayerProtocolId)) {
        return STATUS_NOINTERFACE;
    }

    //
    // Allocate memory for this binding.
    //
    ProviderContext = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(*ProviderContext), 'cpLF');
    if (ProviderContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ProviderContext, sizeof(*ProviderContext));
    ProviderContext->Protocol = Protocol;
    ProviderContext->NmrBindingHandle = NmrBindingHandle;

    //
    // Our NPI that the provider will use when it calls on us will have
    // this context block as its handle.
    //
    MyNpi.ProviderHandle = ProviderContext;
    MyNpi.Dispatch = Protocol->FlClientDispatch;

    ProviderContext->NeighborPool =
        FsbCreatePool(
            sizeof(IPV4_NEIGHBOR) + DL_ADDRESS_LENGTH_MAXIMUM,
            0, 
            Ip4NeighborPoolTag,
            NULL);
    if (ProviderContext->NeighborPool == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Failure attaching FL provider for %s: "
                   "Could not allocate NeighborPool\n",
                   Protocol->TraceString);
        ExFreePool(ProviderContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Call NMR to attach to this provider.
    //
    Status = NmrClientAttachProvider(
        NmrBindingHandle, MyNpi.ProviderHandle,
        MyNpi.Dispatch, &ProviderContext->Npi.ClientHandle,
        &ProviderContext->Npi.Dispatch);

    if (NT_SUCCESS(Status)) {
        KLOCK_QUEUE_HANDLE LockHandle;

        RtlAcquireWriteLock(&Protocol->FlProviderSet.Lock, &LockHandle);
        InsertHeadList(&Protocol->FlProviderSet.Set, &ProviderContext->Link);
        Protocol->FlProviderSet.NumEntries++;
        RtlReleaseWriteLock(&Protocol->FlProviderSet.Lock, &LockHandle);

        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Attached FL provider for %s\n", 
                   Protocol->TraceString);
    } else {
        FsbDestroyPool(ProviderContext->NeighborPool);
        
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error attaching FL provider for %s (0x%x)\n", 
                   Protocol->TraceString, Status);
        ExFreePool(ProviderContext);
    }
    

    IppReferenceFlProviderContext(ProviderContext);
    return Status;
}


HANDLE Ipv4PnpEventProviderHandle;

NTSTATUS
Ipv4pStartPnpEventp(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Protocol);
    
    Status = NmrRegisterProvider(&Ipv4PnpEventProviderNotify,
                                 NULL,
                                 &Ipv4PnpEventProviderHandle);
    
    if (NT_SUCCESS(Status)) {
        IppDefaultStartRoutine(&Ipv4Global, IMS_PNP_EVENT_PROVIDER);
    }

    return Status;
}

NTSTATUS
Ipv4pStopPnpEventp(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Protocol);
    
    Status = NmrDeregisterProvider(Ipv4PnpEventProviderHandle);
    ASSERT(Status == STATUS_PENDING);

    return Status;
}

NTSTATUS
Ipv4pWaitPnpEventp(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Protocol);
    
    Status = NmrWaitForProviderDeregisterComplete(Ipv4PnpEventProviderHandle);
    ASSERT(Status == STATUS_SUCCESS);
    Ipv4DeregisterPnpEventComplete((PVOID)&Ipv4PnpEventProviderNotify);

    return Status;
}

CONST NL_MODULE Ipv4Module[] = {
    {
        IMS_COMPARTMENT_MANAGER,
        "IPv4 Compartment Manager",
        IppStartCompartmentManager,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupCompartmentManager
    },
    { 
        IMS_INTERFACE_MANAGER,
        "IPv4 Interface Manager",
        IppStartInterfaceManager, 
        IppDefaultStopRoutine, 
        NULL,
        IppCleanupInterfaceManager  
    },
    { 
        IMS_ADDRESS_MANAGER,
        "IPv4 Address Manager",
        Ipv4pStartAddressManager, 
        IppDefaultStopRoutine, 
        NULL,
        IppCleanupAddressManager, 
    },
    { 
        IMS_ROUTE_MANAGER,
        "IPv4 Route Manager",
        IppStartRouteManager,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupRouteManager
    },
    { 
        IMS_VALIDATER, 
        "IPv4 Validater",
        IppStartValidater, 
        IppDefaultStopRoutine, 
        NULL,
        IppCleanupValidater
    },
    {
        IMS_NEXT_HEADER_PROCESSOR,
        "IPv4 Next Header Processor",
        Ipv4pStartNextHeaderProcessor,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupNextHeaderProcessor
    },
    {
        IMS_ECHO_REQUEST_MANAGER,
        "IPv4 Echo Request Manager",
        IppStartEchoRequestManager,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupEchoRequestManager
    },
    { 
        IMS_NSI_PROVIDER, 
        "IPv4 NSI Provider",
        IppStartNsip, 
        IppStopNsip, 
        IppWaitNsip,
        NULL
    },
    { 
        IMS_NL_PROVIDER, 
        "IPv4 NL Provider",
        IppStartNlp, 
        IppStopNlp,
        IppWaitNlp,
        IppCleanupNlp
    },
    { 
        IMS_FL_CLIENT, 
        "IPv4 FL Client",
        IppStartFlc, 
        IppStopFlc,
        IppWaitFlc,
        IppCleanupFlc
    },
    { 
        IMS_LOOPBACK_MANAGER, 
        "IPv4 Loopback Manager",
        IppStartLoopback, 
        IppDefaultStopRoutine,
        NULL,
        IppCleanupLoopback
    },
    {
        IMS_PNP_EVENT_PROVIDER,
        "IPv4 Pnp Manager",
        Ipv4pStartPnpEventp,
        Ipv4pStopPnpEventp,
        Ipv4pWaitPnpEventp,
        NULL
    }
};

IP_PROTOCOL Ipv4Global = {
    TRUE,                       // Installed.
    0,                          // No components are disabled.
    "IPv4",
    &Ipv4NlProviderCharacteristics,
    IPPROTO_IP,
    AF_INET,
    &NPI_MS_IPV4_MODULEID,
    IPV4_MINIMUM_MTU,
    sizeof(IPV4_HEADER),
    __builtin_alignof(IPV4_HEADER),
    FIELD_OFFSET(IPV4_HEADER, TimeToLive),
    sizeof(IPV4P_ROUTE_KEY),
    sizeof(IPV4_UNICAST_ROUTE),
    sizeof(IPV4_PATH),
    sizeof(IPV4_SESSION_MULTICAST_SOURCE),
    sizeof(IPV4_LOCAL_MULTICAST_SOURCE),
    TRUE,  // DefaultDhcpEnabled.
    RouterDiscoveryDhcp, // DefaultRouterDiscoveryBehavior.
    IPV4_MINIMUM_MTU - sizeof(ICMPV4_MESSAGE) - sizeof(IPV4_HEADER),
    8,   // MinimumOnLinkPrefixLength. 
    IN4ADDR_MULTICASTPREFIX_LENGTH, // MinimumMulticastPrefixLength.

    Ip4OffloadState,
    Ip4OffloadCachedState,
    Ip4OffloadDelegatedState,
    Ipv4pValidateNetBuffer,
    Ipv4pAddressInterface,
    Ipv4pAddLinkLayerSuffixAddresses,
    Ipv4pUnAddressInterface,
    Ipv4pInitializeSubInterface,
    NULL,
    NULL,
    Ipv4pStartAdvertising,
    Ipv4pStopAdvertising,
    Ipv4AddressScope,
    Ipv4AddressType,
    Ipv4pMakeRouteKey,
    Ipv4pParseRouteKey,
    Ipv4pNotifyRouteChange,
    Ipv4pFragmentPacketHelper,
    Ipv4pIsFragment,
    Ipv4pReassemblyTimeout,
    Ipv4pValidateHopByHopOptionsForSend,
    Ipv4pFillHeaderIncludeProtocolHeader,
    Ipv4pFillProtocolHeader,
    Ipv4pUpdateProtocolHeader,
    Ipv4pSkipNetworkLayerHeaders,
    IgmppCreateMulticastDiscoveryReport,
    IgmppIsMulticastDiscoveryAllowed,
    Ipv4pPathMtuDiscoveryTimeout,
    Ipv4pSendRedirect,
    Ipv4pGetSolicitationSource,
    Ipv4pSendNeighborSolicitation,
    Ipv4pSendNeighborAdvertisement,
    Ipv4pValidateRoutingHeaderForSend,
    Ipv4pInterfaceSetTimeout,

    sizeof(IGMP_HEADER),
    sizeof(IGMPV3_REPORT_HEADER),
    sizeof(IGMPV3_REPORT_RECORD_HEADER),

    //
    // Network Layer Provider State.
    //
    
    {                           // NlProviderNotify.
        0,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        (PNPI_PROVIDER_ATTACH_CLIENT_FN) IpAttachNlClient,
        IpDetachNlClient,
        IpCleanupNlClient,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &NPI_NETWORK_LAYER_ID,
            &NPI_MS_IPV4_MODULEID,
            0,
            &Ipv4NlProviderCharacteristics
        }
    },

    NULL,                       // NlProviderHandle.

    &IpNlProviderDispatch,
    
    {0},                        // NlClientSet.
    {0},                        // ReceiveDemux.

    //
    // Framing Layer Client State. 
    //
    {                           // FlClientNotify. 
        0,
        sizeof(NPI_CLIENT_CHARACTERISTICS),
        Ipv4AttachFlProvider,
        IpDetachFlProvider,
        IpCleanupFlProviderContext,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &NPI_FRAMING_LAYER_ID,
            &NPI_MS_IPV4_MODULEID,
            0,
            NULL
        },
    }, 

    NULL,                       // FlClientHandle.

    &Ipv4FlClientDispatch,      // FlClientDispatch.

    //
    // NSI Module Provider State. 
    //
    {                           // NsiProviderNotify.
        0,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        (PNPI_PROVIDER_ATTACH_CLIENT_FN)IpAttachNsiClient,
        IpDetachNsiClient,
        IpCleanupNsiClientContext,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &NPI_NSI_MODULE_ID,
            &NPI_MS_IPV4_MODULEID,
            0,
            &Ipv4NsiProviderCharacter
        }
    }, 

    NULL,                       // NsiProviderHandle.

    &Ipv4NsiProviderDispatch, 

    //
    // Temporary address configuration.
    //
    UseTemporaryNo,
    NL_INFINITE_LIFETIME,
    NL_INFINITE_LIFETIME,
    0,
    0,
    0,
    0,

    //
    // Parameters related to dead-gateway detection. 
    //
    DEAD_ROUTE_PROBE_TIMEOUT,   // DeadRouteProbeTimeout.
    DEAD_ROUTE_TIMEOUT,         // DeadRouteTimeout.
    PATH_UNREACHABLE_TIMEOUT,   // PathUnreachableTimeout.
    DEAD_ROUTE_PROBE_TRAFFIC_PERCENT, // DeadRouteTrafficPercent.

    //
    // Link local address configuration.
    //
    LinkLocalDelayed,           // LinkLocalAddressBehavior.
    IPV4_LINK_LOCAL_CONFIGURATION_TIMEOUT,
    IN4ADDR_LINKLOCALPREFIX_INIT,  // Unchanged. Default Prefix 169.254.0.0
    IN4ADDR_LINKLOCALPREFIX_LENGTH,// Unchanged. 
                                   // Default prefix length 16

    //
    // Other configurable global parameters.
    //
    IP_DEFAULT_HOP_LIMIT,       // DefaultHopLimit.
    IP_DEFAULT_PATH_CACHE_LIMIT, // PathCacheLimit.
    SourceRoutingDontForward,   // SourceRoutingBehavior.
    MldLevelAll,                // MldLevel.
    MULTICAST_DISCOVERY_VERSION3, // MldVersion.
    (ULONG) -1,                 // DadTransmits.
    ForwardingDisabled,         // EnableForwarding.
    TRUE,                       // EnableIcmpRedirects.
    FALSE,                      // EnableAddrMaskReply.    
    FALSE,                      // DisableTaskOffload.
    TRUE,                       // EnableNonUnicastDatalinkAddresses.
    FALSE,                      // DisableMediaSense. 
    FALSE,                      // DisableMediaSenseEventLog.
    FALSE,                      // EnableMulticastForwarding.
    FALSE,                      // GroupForwardedFragments.
    TRUE,                       // RandomizeIdentifiers.
    FALSE,                      // OverrideDefaultAddressSelection
    
    Ipv4Module, 
    sizeof(Ipv4Module) / sizeof(NL_MODULE), 
    0,

};
