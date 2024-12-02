/*++

Copyright (c) Microsoft Corporation

Module Name:

    subr.c

Abstract:

    This module implements generic IPv4 subroutines.

--*/
#include "precomp.h"

VOID
Ipv4pInterfaceSetTimeout(
    IN PNLI_LOCKED_SET InterfaceSet,
    IN BOOLEAN RecalculateReachableTime,
    IN BOOLEAN ForceRouterAdvertisement
    )
/*++

Routine Description:

    Process timeouts pertaining to the interface set.
    Called once every timer tick from Ipv4pCompartmentSetTimeout.
    
Arguments:

    InterfaceSet - Supplies a per-compartment interface set to inspect. 

    RecalculateReachableTime - Supplies TRUE to indicate that the
        compartment's interfaces' ReachableTime should be recalculated.

    ForceRouterAdvertisement - Supplies TRUE to force the generation of
        Router Advertisements over the compartment's interfaces.

Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    PLIST_ENTRY Link;
    PIP_INTERFACE Interface;
    BOOLEAN Terminate;
    MULTICAST_DISCOVERY_VERSION Version;
    
    DISPATCH_CODE();
    
    //
    // Because new interfaces are only added at the head of the list,
    // we can unlock the list during our traversal
    // and know that the traversal will terminate properly.
    //
    RtlAcquireReadLockAtDpcLevel(&InterfaceSet->Lock);
    for (Link = InterfaceSet->Set.Flink;
         Link != &InterfaceSet->Set;
         Link = Link->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Link, IP_INTERFACE, CompartmentLink);
        IppReferenceInterface(Interface);
        RtlReleaseReadLockFromDpcLevel(&InterfaceSet->Lock);

        InterlockedExchange(&Interface->IcmpErrorCount, 0);
        
        //
        // Handle per-address timeouts.
        //
        IppAddressSetTimeout(Interface);

        //
        // Handle per-neighbor timeouts.
        // Optimize for the common case, when there are no running timers.
        // Since this check is made without holding the interface lock, there
        // is an off-chance that we will miss a timer that was just started.
        // However, that's exactly the desired behavior.
        //
        if (!TtIsTableEmpty(Interface->NeighborSet.EventTable) ||
            (Interface->NeighborSet.DropQueue != NULL) ||
            RecalculateReachableTime || 
            (IppTickCount - Interface->NeighborSet.LastEnumerationTick > 
                IPP_NEIGHBORSET_ENUM_DELAY) || 
            (Interface->NeighborSet.CacheSize > IppNeighborCacheLimit)) {
            IppNeighborSetTimeout(Interface, RecalculateReachableTime);
        }

        //
        // Handle router-discovery timeouts.
        // Again, the timer check here is an optimization,
        // because it is made without holding the interface lock.
        //
        if ((Interface->RouterDiscoveryTimer != 0) ||
            ForceRouterAdvertisement) {
            Ipv4pRouterDiscoveryTimeout(Interface, ForceRouterAdvertisement);
        }

        //
        // Handle link-local address configuration timeout. 
        //
        if (Interface->LinkLocalAddressTimer != 0) {
            IppLinkLocalAddressConfigurationTimeout(Interface);
        }
        
        //
        // Handle multicast discovery timeouts. 
        //
        for (Version = MULTICAST_DISCOVERY_VERSION2; 
             Version >= MULTICAST_DISCOVERY_VERSION1;
             Version--) {
            if ((Interface->MulticastQuerierPresent[Version] != 0) &&
                (Interface->MulticastQuerierPresent[Version] ==
                 IppTickCount)) {
                IppMulticastDiscoveryVersionTimeout(Interface, 
                                                    Version);
            }
        }
                
        if (!TtIsTableEmpty(Interface->MulticastReportTimerTable)) {
            IppMulticastDiscoveryTimeout(
                Interface, 
                Interface->MulticastReportTimerTable);
        }
        if (!TtIsTableEmpty(Interface->MulticastGeneralQueryTimerTable)) {
            IppMulticastDiscoveryTimeout(
                Interface, 
                Interface->MulticastGeneralQueryTimerTable);
        }
        if (!TtIsTableEmpty(Interface->MulticastSpecificQueryTimerTable)) {
            IppMulticastDiscoveryTimeout(
                Interface, 
                Interface->MulticastSpecificQueryTimerTable);
        }

        RtlAcquireReadLockAtDpcLevel(&InterfaceSet->Lock);

        //
        // Before releasing the interface reference (perhaps its last),
        // determine if it has been deleted (hence removed from the set).
        // If so, we terminate the traversal early (we could use a marker,
        // but the remaining interfaces will be processed at the next timeout).
        //
        Terminate = IppIsInterfaceDisabled(Interface);        
        IppDereferenceInterface(Interface);
        if (Terminate) {
            break;
        }        
    }

    RtlReleaseReadLockFromDpcLevel(&InterfaceSet->Lock);
}
