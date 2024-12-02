/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    init.c

Abstract:

    This module contains the main IPv6 registration/deregistration
    functionality.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "nlmnpip.h"
#include "init.tmh"

extern CONST NPI_MODULEID NPI_MS_IPV6_MODULEID;

CONST IP_INTERNAL_CLIENT_CONTEXT Ipv6InternalClientContext = {
    &Ipv6Global,
    IP_CLIENT_CONTEXT_SIGNATURE
};

//
// Network Layer Provider data. 
// 
CONST NL_PROVIDER_CHARACTERISTICS Ipv6NlProviderCharacteristics = {
    0,
    sizeof(NL_PROVIDER_CHARACTERISTICS),
    AF_INET6,
    sizeof(IN6_ADDR),
    sizeof(IPV6_HEADER) + IP_EXTRA_DATA_BACKFILL,
};
    
//
// IPv6 never indicated pnp events to TDI thus the new IPv6 does not implement
// pnp support for legacy TDI clients.
//

//
// Framing Layer Client data.
//
CONST FL_CLIENT_DISPATCH Ipv6FlClientDispatch = {
    0, sizeof(FL_CLIENT_DISPATCH),
    AF_INET6,
    IpFlcAddInterface,
    IpFlcDeleteInterface,
    IpFlcUpdateInterface,
    IpFlcAddSubInterface,
    IpFlcDeleteSubInterface,
    IpFlcUpdateSubInterface,
    IpFlcPnpEvent,
    IpFlcReceivePackets,
    IpFlcReceivePreValidatedPackets,
    NULL,
    NULL,
    IpFlcInitiateNeighborOffloadComplete,
    IpFlcTerminateNeighborOffloadComplete,
    IpFlcUpdateNeighborOffloadComplete,
    IpFlcInvalidateNeighborOffloadComplete,
    Ipv6QueryOffloadComplete,
    IpFlcQueryNeighborReachability,
    IpFlcSuspectNeighborReachability,
    IpFlcIndicateOffloadEvent
};

//
// NSI Module Provider data.
//
CONST NSI_INFORMATION_OBJECT Ipv6InformationObject[] = {
    {                           // NlBestRouteObject
        sizeof(IPV6_BEST_ROUTE_KEY),
        0,
        sizeof(IPV6_BEST_ROUTE_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv6GetAllBestRouteParameters,
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
        sizeof(IPV6_ECHO_REQUEST_RW),
        sizeof(NL_ECHO_REQUEST_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv6GetAllEchoRequestParameters,
        Ipv6SetAllEchoRequestParameters,
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
        sizeof(IPV6_LOCAL_ADDRESS_KEY),
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
        sizeof(IPV6_LOCAL_ADDRESS_KEY),
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
        sizeof(IPV6_LOCAL_ADDRESS_KEY),
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
        sizeof(IPV6_NEIGHBOR_KEY),
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
        sizeof(IPV6_PATH_KEY),
        sizeof(NL_PATH_RW),
        sizeof(IPV6_PATH_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv6GetAllPathParameters,
        Ipv6SetAllPathParameters,
        Ipv6EnumerateAllPaths,
    },
    {                           // NlPotentialRouterObject.
        sizeof(IPV6_POTENTIAL_ROUTER_KEY), 
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv6GetAllPotentialRouters,
        Ipv6SetAllPotentialRouters,
        NULL,
        NULL,
        NULL,
    },
    {                           // NlPrefixPolicyObject.
        sizeof(NL_PREFIX_POLICY_KEY),
        sizeof(NL_PREFIX_POLICY_RW),
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllPrefixPolicyParameters,
        IpSetAllPrefixPolicyParameters
    },
    {                           // NlProxyNeighborObject.
        sizeof(IPV6_PROXY_NEIGHBOR_KEY),
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
        sizeof(IPV6_ROUTE_KEY),
        sizeof(NL_ROUTE_RW),
        sizeof(IPV6_ROUTE_ROD),
        sizeof(NL_ROUTE_ROS),
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllRouteParameters,
        Ipv6SetAllRouteParameters,
        NULL,
        IpRegisterRouteChangeNotification,
        IpDeregisterRouteChangeNotification,
    },
    {                           // NlSitePrefixObject.
        sizeof(IPV6_SITEPREFIX_KEY),
        0,
        sizeof(NL_SITEPREFIX_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllSitePrefixParameters,
        NULL
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
        sizeof(IPV6_NEIGHBOR_KEY),
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
        sizeof(NL_SORT_ADDRESSES_KEY),
        0,
        sizeof(NL_SORT_ADDRESSES_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        IpGetAllSortedAddressParameters,
        NULL
    },
    {                           // NlMfeObject.
        sizeof(IPV6_MFE_KEY),
        sizeof(NL_MFE_RW),
        sizeof(NL_MFE_ROD),
        0,
        0,
        NULL,
        NULL,
        NULL,
        Ipv6GetAllMulticastForwardingParameters,
        Ipv6SetAllMulticastForwardingParameters
    },
    {                           // NlMfeNotifyObject.
        0,
        0,
        sizeof(IPV6_MFE_NOTIFICATION_ROD),
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
#if DBG
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
    },
    {                           // NlDbgInjectRawSendObject.
        sizeof(NLP_DBG_INJECT_RAW_SEND_KEY),
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        IpSetAllDbgInjectRawSendParameters
    },
    {                           // NlDbgInjectReceiveObject.
        sizeof(NLP_DBG_INJECT_RECEIVE_KEY),
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        IpSetAllDbgInjectReceiveParameters
    },
    {                           // NlDbgInjectForwardObject.
        sizeof(NLP_DBG_INJECT_FORWARD_KEY),
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        IpSetAllDbgInjectForwardParameters
    }
#endif // DBG
};

CONST NM_PROVIDER_DISPATCH Ipv6NsiProviderDispatch = {
    0, sizeof(NM_PROVIDER_DISPATCH),
    sizeof(Ipv6InformationObject) / sizeof(NSI_INFORMATION_OBJECT),
    Ipv6InformationObject
};

CONST NM_PROVIDER_CHARACTERISTICS Ipv6NsiProviderCharacter = {
    sizeof(NM_PROVIDER_CHARACTERISTICS),
    0
};

//
// Framing Layer Client routines.
//

NTSTATUS
NTAPI
Ipv6AttachFlProvider(
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
    if ((Character == NULL) ||
        (AF_INET6 != Character->NetworkLayerProtocolId)) {
        return STATUS_NOINTERFACE;
    }

    switch (Character->DataLinkLayerProtocolId) {
    case IF_TYPE_SOFTWARE_LOOPBACK:
        //
        // Always bind to the loopback framing layer.
        //
        break;
        
    case IF_TYPE_TUNNEL:
        if (Ipv6Global.DisabledComponents.Tunnel) {
            return STATUS_NOINTERFACE;
        }
        break;
        
    default:
        if (Ipv6Global.DisabledComponents.Native) {
            return STATUS_NOINTERFACE;
        }
        break;
    }
    
    //
    // Allocate context for this binding.
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
            sizeof(IPV6_NEIGHBOR) + DL_ADDRESS_LENGTH_MAXIMUM,
            0, 
            Ip6NeighborPoolTag,
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
    // Call NMR to attach to us.
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
        ExFreePool(ProviderContext);
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Error attaching FL provider for %s (0x%x)\n", 
                   Protocol->TraceString, Status);
    }

    IppReferenceFlProviderContext(ProviderContext);
        
    return Status;
}

CONST NL_MODULE Ipv6Module[] = {
    {
        IMS_PREFIX_POLICY,
        "IP Prefix Policy",
        IppStartPrefixPolicyModule,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupPrefixPolicyModule,
    },
    {
        IMS_COMPARTMENT_MANAGER,
        "IPv6 Compartment Manager",
        IppStartCompartmentManager,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupCompartmentManager
    },
    { 
        IMS_INTERFACE_MANAGER, 
        "IPv6 Interface Manager",
        IppStartInterfaceManager, 
        IppDefaultStopRoutine, 
        NULL,
        IppCleanupInterfaceManager  
    },
    { 
        IMS_ADDRESS_MANAGER, 
        "IPv6 Address Manager",
        Ipv6pStartAddressManager, 
        IppDefaultStopRoutine, 
        NULL,
        IppCleanupAddressManager, 
    },
    { 
        IMS_ROUTE_MANAGER, 
        "IPv6 Route Manager",
        IppStartRouteManager, 
        IppDefaultStopRoutine,
        NULL,
        IppCleanupRouteManager
    },
    { 
        IMS_VALIDATER, 
        "IPv6 Validater",
        IppStartValidater, 
        IppDefaultStopRoutine, 
        NULL,
        IppCleanupValidater
    },
    {
        IMS_NEXT_HEADER_PROCESSOR,
        "IPv6 Next Header Processor",
        Ipv6pStartNextHeaderProcessor,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupNextHeaderProcessor
    },
    {
        IMS_ECHO_REQUEST_MANAGER,
        "IPv6 Echo Request Manager",
        IppStartEchoRequestManager,
        IppDefaultStopRoutine,
        NULL,
        IppCleanupEchoRequestManager
    },
    { 
        IMS_NSI_PROVIDER, 
        "IPv6 NSI Provider",
        IppStartNsip, 
        IppStopNsip, 
        IppWaitNsip,
        NULL
    },
    { 
        IMS_NL_PROVIDER, 
        "IPv6 NL Provider",
        IppStartNlp, 
        IppStopNlp,
        IppWaitNlp,
        IppCleanupNlp
    },
    { 
        IMS_FL_CLIENT, 
        "IPv6 FL Client",
        IppStartFlc, 
        IppStopFlc,
        IppWaitFlc,
        IppCleanupFlc
    },
    { 
        IMS_LOOPBACK_MANAGER, 
        "IPv6 Loopback Manager",
        IppStartLoopback, 
        IppDefaultStopRoutine,
        NULL,
        IppCleanupLoopback
    }
};

IP_PROTOCOL Ipv6Global = {
    TRUE,                       // Installed.
    0,                          // No components are disabled.
    "IPv6",
    &Ipv6NlProviderCharacteristics,
    IPPROTO_IPV6,
    AF_INET6,
    &NPI_MS_IPV6_MODULEID,
    IPV6_MINIMUM_MTU,    
    sizeof(IPV6_HEADER),
    __builtin_alignof(IPV6_HEADER),
    FIELD_OFFSET(IPV6_HEADER, ip6_hlim),
    sizeof(IPV6P_ROUTE_KEY),
    sizeof(IPV6_UNICAST_ROUTE),
    sizeof(IPV6_PATH),
    sizeof(IPV6_SESSION_MULTICAST_SOURCE),
    sizeof(IPV6_LOCAL_MULTICAST_SOURCE),
    FALSE, // DefaultDhcpEnabled.
    RouterDiscoveryEnabled,  // DefaultRouterDiscoveryBehavior.
    IPV6_MINIMUM_MTU - sizeof(IPV6_HEADER) - sizeof(ICMPV6_MESSAGE), 
    10,    // MinimumOnLinkPrefixLength.
    IN6ADDR_MULTICASTPREFIX_LENGTH, // MinimumMulticastPrefixLength.
    
    Ip6OffloadState,
    Ip6OffloadCachedState,
    Ip6OffloadDelegatedState,
    Ipv6pValidateNetBuffer,
    Ipv6pAddressInterface,
    Ipv6pAddLinkLayerSuffixAddresses,
    Ipv6pUnAddressInterface,
    Ipv6pInitializeSubInterface,
    Ipv6pFindOrCreateSolicitedNodeGroup, 
    Ipv6pFindAndReleaseSolicitedNodeGroup,
    Ipv6pStartAdvertising,
    Ipv6pStopAdvertising,
    Ipv6AddressScope,
    Ipv6AddressType,
    Ipv6pMakeRouteKey,
    Ipv6pParseRouteKey,
    Ipv6pNotifyRouteChange,
    Ipv6pFragmentPacketHelper,
    Ipv6pIsFragment,
    Ipv6pReassemblyTimeout,
    Ipv6pValidateHopByHopOptionsForSend,
    Ipv6pFillHeaderIncludeProtocolHeader,
    Ipv6pFillProtocolHeader,
    Ipv6pUpdateProtocolHeader,
    Ipv6pSkipNetworkLayerHeaders,
    MldpCreateMulticastDiscoveryReport,
    MldpIsMulticastDiscoveryAllowed,
    Ipv6pPathMtuDiscoveryTimeout,
    Ipv6pSendRedirect,
    Ipv6pGetSolicitationSource,
    Ipv6pSendNeighborSolicitation,
    Ipv6pSendNeighborAdvertisement,
    Ipv6pValidateRoutingHeaderForSend,
    Ipv6pInterfaceSetTimeout,
    
    sizeof(MLD_HEADER),
    sizeof(MLDV2_REPORT_HEADER),
    sizeof(MLDV2_REPORT_RECORD_HEADER),

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
            &NPI_MS_IPV6_MODULEID,
            0,
            &Ipv6NlProviderCharacteristics
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
        Ipv6AttachFlProvider,
        IpDetachFlProvider,
        IpCleanupFlProviderContext,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &NPI_FRAMING_LAYER_ID,
            &NPI_MS_IPV6_MODULEID,
            0,
            NULL
        }
    }, 

    NULL,                       // FlClientHandle.

    &Ipv6FlClientDispatch,      // FlClientDispatch.

    //
    // NSI Module Provider State. 
    //
    {                           // NsiProviderNotify.
        0,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        IpAttachNsiClient,
        IpDetachNsiClient,
        IpCleanupNsiClientContext,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &NPI_NSI_MODULE_ID,
            &NPI_MS_IPV6_MODULEID,
            0,
            &Ipv6NsiProviderCharacter
        }
    },
    
    NULL,                       // NsiProviderHandle.

    &Ipv6NsiProviderDispatch, 

    //
    // Temporary address configuration.
    //
    UseTemporaryYes, 
    MAX_TEMPORARY_VALID_LIFETIME, 
    MAX_TEMPORARY_PREFERRED_LIFETIME, 
    MAX_TEMPORARY_DAD_ATTEMPTS, 
    TEMPORARY_REGENERATE_ADVANCE, 
    MAX_TEMPORARY_DESYNC_FACTOR, 
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
    LinkLocalAlwaysOn,          // LinkLocalAddressBehavior. 
    0,                          // LinkLocalAddressTimeout. 
    IN6ADDR_LINKLOCALPREFIX_INIT, // Ipv6 Link local address prefix
    IN6ADDR_LINKLOCALPREFIX_LENGTH, // Unused
    
    //
    // Other configurable global parameters.
    //
    IP_DEFAULT_HOP_LIMIT,       // DefaultHopLimit.
    IP_DEFAULT_PATH_CACHE_LIMIT, // PathCacheLimit.
    SourceRoutingDrop,       // SourceRoutingBehavior.
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
    
    Ipv6Module, 
    sizeof(Ipv6Module) / sizeof(NL_MODULE), 
    0,

};
