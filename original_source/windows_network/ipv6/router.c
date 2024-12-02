/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    router.c

Abstract:

    This module contains the IPv6 Router Discovery Algorithm [RFC 2461].

Author:

    Mohit Talwar (mohitt) Tue Jul 23 17:07:15 2002

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "router.tmh"

IP_SESSION_STATE Ipv6pNdSessionState = {
    NULL,                       // InterfaceList.
    NULL,                       // MulticastInterface.
    NULL,                       // UnicastInterface.
    NULL,                       // PromiscuousInterface.
    NULL,                       // AllMulticastInterface.
    255,                        // MulticastHopLimit.
    255,                        // UnicastHopLimit.
    {
        FALSE,                  // HeaderInclude.
        FALSE,                  // MulticastLoopback.
        FALSE,                  // DontFragment.
        FALSE,                  // ReceivePacketInfo.
        TRUE,                   // ReceiveHopLimit.
        FALSE,                  // ReceiveInterface.
        FALSE,                  // ReceiveDestination.
    },
    0,                          // ProtectionLevel.
    0,                          // TypeOfService.
};


VOID
Ipv6pResetAutoConfiguredParameters(
    IN PIP_INTERFACE Interface
    )
{
    DBG_UNREFERENCED_PARAMETER(Interface);
}


VOID
Ipv6pResetAutoConfiguredAddresses(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    )
/*++

Routine Description:

    Reset the lifetimes of auto configured addressess. This is different from
    Ipv6pUpdateLifetimeForAutoConfiguredAddress since it is called internally;
    so it does not have to do the extra checks to prevent setting the lifetimes
    to a very low value. Ipv6pUpdateLifetimeForAutoConfiguredAddress is called
    on receiving a router advertisement, so it has to perform all the extra
    sanity checks. 

Arguments:

    Interface - Supplies the interface for which the address lifetimes need to
        be reset. 
    
    Lifetimes - Supplies the new lifetime starting from now.

Return Value:

    None.

Caller LOCK:

    Assumes caller holds the interface lock. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    PIP_LOCAL_UNICAST_ADDRESS UnicastAddress;
    PNLA_LINK Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;

    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);

    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link =
            IppEnumerateNlaSetEntry(
                &Interface->LocalUnicastAddressSet,
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        UnicastAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);

        if (UnicastAddress->PrefixOrigin == NlpoRouterAdvertisement) {
            IppRefreshAddressLifetimes(IppTickCount, UnicastAddress);
            
            //
            // Now update the lifetimes to Lifetime if the new lifetime is less
            // than the existing lifetime.
            //
            if (Lifetime < UnicastAddress->ValidLifetime) {
                UnicastAddress->ValidLifetime = Lifetime;
            }
            if (Lifetime < UnicastAddress->PreferredLifetime) {
                UnicastAddress->PreferredLifetime = Lifetime;
            }

            //
            // Update any timeouts as a result of changing the lifetimes.
            //
            IppHandleAddressLifetimeTimeout(UnicastAddress);
        }
    }
}

VOID
Ipv6pResetAutoConfiguredRoutes(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    )
/*++

Routine Description:

    Reset the lifetimes of routes and site prefixes. 

Arguments:

    Interface - Supplies the interface on which to reset the lifetimes.
    
    Lifetime - Supplies the new value of the lifetime.

Return Value:

    None.

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;
    KIRQL OldIrql;
    ULONG Count;
    PREFIX_TREE_CONTEXT Context;
    PIPR_LINK Link;
    PUCHAR Key;
    USHORT KeyLength;
    PLIST_ENTRY Head, Next, Current;
    PIP_SITE_PREFIX_ENTRY SitePrefixEntry;
    PIP_UNICAST_ROUTE Route, NextRoute;
    BOOLEAN RouteDeleted = FALSE;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIPR_LOCKED_SET RouteSet = &Compartment->RouteSet;
     
    //
    // Lock the route set for updating the lifetimes.
    // 
    RtlAcquireScalableWriteLock(&RouteSet->Lock, &LockHandle);

    //
    // Now we scan the routing table looking for published routes.
    //
    RtlZeroMemory(&Context, sizeof(Context));
    Count = 1;
    
    do {
        Status =
            PtEnumOverTable(
                RouteSet->Tree, NULL, NULL, &Context, NULL, 0, &Count, &Link);

        if (Count == 0) {
            break;
        }

        PtGetKey(Link, &Key, &KeyLength);

        //
        // Update the lifetime of the routes and delete them if required.
        //
        Route = CONTAINING_RECORD(Link, IP_UNICAST_ROUTE, Link);
        
        //
        // Walk the chain of routes per AVL_NODE.
        //
        for (; Route != NULL; Route = NextRoute) {
            NextRoute = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
                Route->RouteLink.Flink, IP_UNICAST_ROUTE, RouteLink);
            if (PtGetData(&Route->Link) == &NextRoute->Link) {
                NextRoute = NULL;
            }
            
            if ((Route->Origin == NlroRouterAdvertisement) &&
                (Route->Interface == Interface)) {
                if (Lifetime == 0) {
                    //
                    // Delete the route. 
                    // 
                    Route->ValidLifetime = 0;
                    IppDeleteUnicastRoute(Compartment, Route);
                    RouteDeleted = TRUE;
                } else {
                    IppUpdateUnicastRouteLifetimes(RouteSet, Route);
                    if (Route->ValidLifetime > Lifetime) {
                        Route->ValidLifetime = Lifetime;
                        if (Route->ValidLifetime < Route->PreferredLifetime) {
                            Route->PreferredLifetime = Route->ValidLifetime;
                        }
                        IppRefreshUnicastRoute(Compartment, Route);
                    }
                }
            }
        }
        
    } while (Status != STATUS_NO_MORE_MATCHES);

    RtlReleaseScalableWriteLock(&RouteSet->Lock, &LockHandle);

    if (RouteDeleted) {
        //
        // A route was deleted.  Invalidate all cached paths.
        //
        IppInvalidateDestinationCache(Compartment);
    }    
    
    //
    // Acquire the site prefix set update lock. 
    //
    KeAcquireSpinLock(&Compartment->SitePrefixSet.Lock, &OldIrql);

    Head = &Compartment->SitePrefixSet.Set;
    for (Current = Head->Flink; Current != Head; Current = Next) {
        Next = Current->Flink;

        SitePrefixEntry = (PIP_SITE_PREFIX_ENTRY)
            CONTAINING_RECORD(Current, IP_SITE_PREFIX_ENTRY, Link);

        IppRefreshSitePrefixLifetime(IppTickCount, SitePrefixEntry);

        if (SitePrefixEntry->Interface == Interface) {
            if (SitePrefixEntry->ValidLifetime > Lifetime) {
                SitePrefixEntry->ValidLifetime = Lifetime;
            }
        }
        
        //
        // If we are past the valid lifetime of the site prefix, delete 
        // it. This is done for both prefixes that match and that do not
        // match because there is no explicit timeout mechanism. 
        //
        if (SitePrefixEntry->ValidLifetime == 0) {
            IppRemoveSitePrefixEntry(SitePrefixEntry);
        }
    }

    KeReleaseSpinLock(&Compartment->SitePrefixSet.Lock, OldIrql);
}

VOID
Ipv6pResetAutoConfiguredSettings(
    IN PIP_INTERFACE Interface,
    IN ULONG Lifetime
    )
/*++

Routine Description:

    Reset the lifetimes of auto configured routes, addresses and interface 
    parameters. 

Arguments:

    Interface - Supplies the interface on which to reset the lifetimes.
    
    Lifetime - Supplies the new value of the lifetime.

Return Value:

    None.

Caller LOCK:

    Exclusive lock on the Interface held. 

Caller IRQL: 

    DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    //
    // Remove auto-configured address lifetimes.
    //
    Ipv6pResetAutoConfiguredAddresses(Interface, Lifetime);
    
    //
    // Similarly, remove auto-configured route lifetimes.
    //
    Ipv6pResetAutoConfiguredRoutes(Interface, Lifetime);
    
    //
    // Remove parameters that are learned from Router Advertisements.
    //
    Ipv6pResetAutoConfiguredParameters(Interface);     
}

VOID
Ipv6pUpdateSitePrefix(
    IN PIP_INTERFACE Interface,
    IN PIN6_ADDR Prefix,
    IN UCHAR PrefixLength,
    IN ULONG ValidLifetime
    )
/*++

Routine Description:

    This routine updates the site prefix table by creating a new site prefix
    entry or modifying the lifetime of an existing site prefix. 
    
Arguments:

    Interface - Supplies the interface on which the router advertisement for
        the site prefix was received.

    Prefix - Supplies the site prefix for which to create/update the site
        prefix entry (in bits).

    PrefixLength - Supplies the length of the site prefix.

    ValidLifetime - Supplies the lifetime of the site prefix.

Return Value:

    None.

Caller LOCK:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    IN6_ADDR SitePrefix;
    BOOLEAN Create = TRUE;
    PLIST_ENTRY Head, Next, Current;
    KIRQL OriginalIrql;
    PIP_SITE_PREFIX_ENTRY SitePrefixEntry;
    PIP_COMPARTMENT Compartment = Interface->Compartment;

    //
    // Ensure that the unused prefix bits are zero.
    // This makes the prefix comparisons below safe.
    //
    CopyPrefix(
        (PUCHAR)&SitePrefix, 
        (PUCHAR)Prefix, 
        PrefixLength,
        sizeof(IN6_ADDR));

    //
    // Acquire the site prefix set update lock. 
    //
    KeAcquireSpinLock(&Compartment->SitePrefixSet.Lock, &OriginalIrql);

    //
    // Search for an existing Site Prefix Entry.
    //
    Head = &Compartment->SitePrefixSet.Set;
    for (Current = Head->Flink; Current != Head; Current = Next) {
        Next = Current->Flink;
        SitePrefixEntry = (PIP_SITE_PREFIX_ENTRY)
            CONTAINING_RECORD(Current, IP_SITE_PREFIX_ENTRY, Link);

        IppRefreshSitePrefixLifetime(IppTickCount, SitePrefixEntry);

        if ((SitePrefixEntry->Interface == Interface) &&
            (IN6_ADDR_EQUAL(&SitePrefixEntry->Prefix, &SitePrefix)) &&
            (SitePrefixEntry->PrefixLength == PrefixLength)) {
            //
            // We have an existing site prefix. Set the new valid lifetime. If
            // the new valid lifetime is 0, we will delete the entry below.
            //
            Create = FALSE;
            SitePrefixEntry->ValidLifetime = ValidLifetime;
        }

        //
        // If we are past the valid lifetime of the site prefix, delete
        // it. This is done for both prefixes that match and that do not match
        // because there is no explicit timeout mechanism. 
        //
        if (SitePrefixEntry->ValidLifetime == 0) {
            IppRemoveSitePrefixEntry(SitePrefixEntry);
        }
    }
    
    if (Create && (ValidLifetime != 0)) {
        //
        // No existing entry for this prefix and the lifetime is non-zero.  
        // Create an entry.
        //
        SitePrefixEntry =
            ExAllocatePoolWithTag(
                NonPagedPool, sizeof(IP_SITE_PREFIX_ENTRY), IpGenericPoolTag);
        if (SitePrefixEntry != NULL) {
            IppReferenceInterface(Interface);
            SitePrefixEntry->Interface = Interface;
            SitePrefixEntry->LifetimeBaseTime = IppTickCount;
            SitePrefixEntry->ValidLifetime = ValidLifetime;
            SitePrefixEntry->PrefixLength = PrefixLength;
            SitePrefixEntry->Prefix = SitePrefix;
            
            //
            // Add the new entry to the table.
            //
            InsertTailList(
                &Compartment->SitePrefixSet.Set, &SitePrefixEntry->Link);
        }
    }

    KeReleaseSpinLock(&Compartment->SitePrefixSet.Lock, OriginalIrql);
}

VOID
Ipv6pUpdateLifetimeForAutoConfiguredAddress(
    IN PIP_LOCAL_UNICAST_ADDRESS Address, 
    IN ULONG ValidLifetime, 
    IN ULONG PreferredLifetime,
    IN BOOLEAN Authenticated
    )
/*++

Routine Description:

    This routine is called to update the lifetime of a given address on
    receiving a prefix option in a router advertisement.

Arguments:

    Address - Supplies the address for which to update the lifetimes. 

    ValidLifetime - Supplies the valid lifetime for the prefix (in ticks). 

    PreferredLifetime - Supplies the preferred lifetime for the prefix (in
        ticks).

    Authenticated - Supplies a boolean indicating whether the router
        advertisement was authenticated or not.

Return Value:

    None.

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ULONG Now = IppTickCount;

    IppRefreshAddressLifetimes(Now, Address);
    
    //
    // Set the new lifetime of the address based on the lifetime in the
    // incoming router advertisement (RFC 2462 section 5.5.3). 
    //
    if ((ValidLifetime > PREFIX_LIFETIME_SAFETY) ||
        (ValidLifetime > Address->ValidLifetime) ||
        (Authenticated)) {
        Address->ValidLifetime = ValidLifetime;
    } else if (Address->ValidLifetime > PREFIX_LIFETIME_SAFETY) {
        Address->ValidLifetime = PREFIX_LIFETIME_SAFETY;
    } else {
        //
        // Leave lifetime unchanged. 
        //
    }
    
    Address->PreferredLifetime = PreferredLifetime;
    
    //
    // For temporary addresses, ensure that the lifetimes are not extended
    // indefinitely. The total lifetime (from creation) of the address should
    // never exceed MAX_TEMPORARY_VALID_LIFETIME. RFC 3041 says that a router
    // advertisement should never increase the lifetime of a temporary
    // address. However, the XP stack imposes a weaker condition: the lifetime
    // can increase but never beyond MaxTemporaryValidLifetime. We do the same
    // thing here.
    // Must be careful of overflows in these comparisons.
    // (Eg, Address->ValidLifetime might be INFINITE_LIFETIME.)
    //          N    Now (Note this is the same as Address->LifetimeBaseTime)
    //          V    Address->ValidLifetime
    //          MV   MaxTemporaryValidLifetime
    //          C    Address->CreationTime
    // We want to check
    //          N + V > C + MV
    // Transform this to
    //          N - C > MV - V
    // Then underflow of MV - V must be checked but
    // N - C is not a problem because the tick count wraps.
    //
    if (Address->AddressOrigin == ADDR_CONF_TEMPORARY) {
        ULONG TicksSinceCreation = Now - Address->CreationTime;
        ULONG MaxLifetime = Ipv6Global.MaxTemporaryValidLifetime;
        
        if ((Address->ValidLifetime > MaxLifetime) ||
            (TicksSinceCreation > (MaxLifetime - Address->ValidLifetime))) {
            //
            // This temporary address is showing its age.
            // Must curtail its valid lifetime.
            //
            if (MaxLifetime > TicksSinceCreation) {
                Address->ValidLifetime = MaxLifetime - TicksSinceCreation;
            } else {
                Address->ValidLifetime = 0;
            }
        }

        if ((Address->PreferredLifetime > MaxLifetime) ||
            (TicksSinceCreation > 
             (MaxLifetime - Address->PreferredLifetime))) {
            //
            // This temporary address is showing its age.
            // Must curtail its valid lifetime.
            //
            if (MaxLifetime > TicksSinceCreation) {
                Address->PreferredLifetime = MaxLifetime - TicksSinceCreation;
            } else {
                Address->PreferredLifetime = 0;
            }
        }
    }
    
    //
    // Maintain our invariant that the preferred lifetime is not larger than
    // the valid lifetime. 
    //
    if (Address->ValidLifetime < Address->PreferredLifetime) {
        Address->PreferredLifetime = Address->ValidLifetime;
    }
    
    //
    // Update any timeouts as a result of receiving this prefix
    // update. Lifetimes might have increased or decreased, so we need to
    // change any timeouts set for invalidating/deprecating the addresses. 
    //
    IppHandleAddressLifetimeTimeout(Address);
}

VOID
Ipv6pUpdateAutoConfiguredAddresses(
    IN PIP_INTERFACE Interface,
    IN PIN6_ADDR Prefix,
    IN UCHAR PrefixLength,
    IN ULONG ValidLifetime,
    IN ULONG PreferredLifetime,
    IN BOOLEAN Authenticated
    )
/*++

Routine Description:

    This routine is called on receiving a router advertisement with a
    prefix-information option. The caller is responsible for sanity checking
    the router advertisement as per RFC 2462. Here we assert that those checks
    are actually true. 

Arguments:

    Interface - Supplies the interface on which the router advertisement was
        received.
    
    Prefix - Supplies the prefix in the prefix-information option. 

    PrefixLength - Supplies the length of the prefix in bits. 

    ValidLifetime - Supplies the valid lifetime for the prefix (in ticks). 

    PreferredLifetime - Supplies the preferred lifetime for the prefix (in
        ticks). 

    Authenticated - Supplies a boolean indicating whether the router
        advertisement was authenticated or not.

Return Value:

    None.

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;
    BOOLEAN Create = TRUE;
    PIP_LOCAL_UNICAST_ADDRESS UnicastAddress;
    PIP_LOCAL_ANYCAST_ADDRESS AnycastAddress;
    PIP_LOCAL_TEMPORARY_ADDRESS TemporaryAddress;
    PNLA_LINK Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    ULONG IdentifierLength = Interface->FlCharacteristics->IdentifierLength;
    IN6_ADDR NewAddress;
    
    //
    // Make sure the caller sanity checked the router advertisement before
    // calling us. 
    //
    ASSERT(!IN6_IS_ADDR_LINKLOCAL(Prefix));
    ASSERT(PreferredLifetime <= ValidLifetime);
    ASSERT((PrefixLength + IdentifierLength) == RTL_BITS_OF(IN6_ADDR));

    IppInitializeAddressEnumerationContext(&Context);
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    for (;;) {
        Link =
            IppEnumerateNlaSetEntry(
                &Interface->LocalUnicastAddressSet, 
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        UnicastAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);
        
        if ((UnicastAddress->DadState != NldsInvalid) &&
            (HasPrefix(
                NL_ADDRESS(UnicastAddress),
                (CONST UCHAR *) Prefix,
                PrefixLength))) {
            //
            // Reset the lifetimes of auto-configured addresses. 
            // NB: RFC 2462 says to reset DHCP addresses too, but we think
            // that's wrong. 
            //
            if (UnicastAddress->PrefixOrigin == NlpoRouterAdvertisement) {
                Ipv6pUpdateLifetimeForAutoConfiguredAddress(
                    UnicastAddress,
                    ValidLifetime,
                    PreferredLifetime,
                    Authenticated);
            }
            
            if ((UnicastAddress->AddressOrigin == ADDR_CONF_PUBLIC) &&
                (UnicastAddress->ValidLifetime != 0)) {
                //
                // We found an existing address that matches the prefix,
                // so inhibit auto-configuration of a new address.
                //
                Create = FALSE;
            }
        }
    }
        
    if (Create && (ValidLifetime > 0)) {
        //
        // There is no existing address that matches the prefix and the valid
        // lifetime of the prefix is greater than 0. We need to auto-configure
        // a new address. 
        //

        //
        // First create a public address.  The public address is created by
        // copying the prefix and then writing the interface identifier at the
        // end of the address.
        //
        NewAddress = *Prefix;
        ASSERT((IdentifierLength % RTL_BITS_OF(UINT8)) == 0);
        IdentifierLength = IdentifierLength / RTL_BITS_OF(UINT8);
        RtlCopyMemory(
            NewAddress.s6_addr + sizeof(IN6_ADDR) - IdentifierLength,
            Interface->Identifier, 
            IdentifierLength);
        
        Status =
            IppFindOrCreateLocalUnicastAddress(
                NewAddress.s6_addr,
                Interface, 
                ADDR_CONF_PUBLIC,
                PreferredLifetime, 
                ValidLifetime,
                PrefixLength, 
                FALSE,
                &UnicastAddress);
        if (!NT_SUCCESS(Status)) {
            RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
            return;
        }
        IppDereferenceLocalUnicastAddress(UnicastAddress);
         
        //
        // Create the subnet anycast address for the prefix only if the
        // interface is advertising.
        //    
        if (Interface->Advertise) {
            IN6_ADDR SubnetAnycastAddress;
            
            CopyPrefix(
                (PUCHAR) &SubnetAnycastAddress,
                (CONST UCHAR *) Prefix,
                PrefixLength,
                sizeof(IN6_ADDR));
            Status =
                IppFindOrCreateLocalAnycastAddress(
                    (CONST UCHAR *) &SubnetAnycastAddress, 
                    Interface, 
                    ADDR_CONF_PUBLIC, 
                    FALSE,
                    &AnycastAddress);
            if (NT_SUCCESS(Status)) {
                IppDereferenceLocalAnycastAddress(AnycastAddress);
            }
        }

        //
        // Create a temporary address. 
        //
        if (!IN6_IS_ADDR_SITELOCAL(Prefix)) {
            Status =
                IppCreateLocalTemporaryAddress(
                    (PUCHAR) Prefix, 
                    Interface, 
                    UnicastAddress,
                    FALSE,
                    &TemporaryAddress);
            if (NT_SUCCESS(Status)) {
                IppDereferenceLocalTemporaryAddress(TemporaryAddress);
            }
        } 
    }

    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
}


VOID
Ipv6pUpdateMtu(
    IN PIP_SUBINTERFACE SubInterface,
    IN ULONG Mtu
    )
/*++

Routine Description:

    Update the subinterface MTU.
    
Arguments:

    SubInterface - Supplies the subinterface to update.

    Mtu - Supplies the updated MTU.
    
Return Value:

    None.
    
Caller LOCK: Interface neighbor set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    PIP_INTERFACE Interface = SubInterface->Interface;

    ASSERT_WRITE_LOCK_HELD(&Interface->NeighborSetLock);
   
    if ((Mtu >= IPV6_MINIMUM_MTU) && 
        (Mtu <= SubInterface->FlCharacteristics->Mtu)) {
        SubInterface->NlMtu = Mtu;

        IppUpdateInterfaceMtuUnderLock(Interface);
    }
}


__inline
UCHAR
Ipv6pEncodeRouteMetric(
    IN NL_ROUTE_METRIC Metric
    )
/*++

Routine Description:
    
    Encode the route preference value into the 2 bit preference field.
    
Arguments:

    Metric - Supplies the route preference value.
    
Return Value:

    2 bit preference field.    
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    if (Metric <= RouteMetricHigh) {
        return 1;               // 01.
    } else if (Metric <= RouteMetricMedium) {
        return 0;               // 00.
    } else {
        return 3;               // 11.
    }
}


__inline
NL_ROUTE_METRIC
Ipv6pExtractRouteMetric(
    __in_range(0, 3) UCHAR Preference
    )
/*++

Routine Description:
    
    Determine the route preference value from the 2 bit preference field.
    
Arguments:

    Preference - Supplies the 2 bit preference field.
    
Return Value:

    Route preference value.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    NL_ROUTE_METRIC Value[4] = {
        RouteMetricMedium,      // 00.
        RouteMetricHigh,        // 01.
        RouteMetricInvalid,     // 10.
        RouteMetricLow          // 11.
    };

    return Value[Preference];
}


VOID
Ipv6pSendRouterSolicitationOnSubInterface(
    IN PIP_SUBINTERFACE SubInterface,
    IN IN6_ADDR *NlDestination,
    IN PIP_LOCAL_UNICAST_ADDRESS Source OPTIONAL
    )
/*++

Routine Description:

    Send a Router Solicitation message.
    The solicitation is always sent to the all-routers multicast address.

Arguments:

    SubInterface - Supplies the subinterface to send the solicitation on.

    NlDestination - Supplies the destination of the solicitation.  For
        multicast enabled addresses, this is the all routers on link 
        multicast address. 

    Source - Supplies the source address to use for the Router Solicitation.
        If NULL, the solicitation is sent from the unspecified address.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;
    PIP_INTERFACE Interface = SubInterface->Interface;
    CONST FL_INTERFACE_CHARACTERISTICS *FlCharacteristics =
                Interface->FlCharacteristics;
    USHORT DlAddressLength = FlCharacteristics->DlAddressLength;
    USHORT OptionLength;
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    ND_ROUTER_SOLICIT_HEADER UNALIGNED *Solicitation;
    PND_OPTION_HDR Option;
    
    DISPATCH_CODE();
    ASSERT(Interface->UseRouterDiscovery);

    //
    // Determine the SLLA option length.
    // NB: Some interfaces do not use SLLA and TLLA options.
    // NB: We sometimes send with the unspecified (NULL) source address.
    //
    OptionLength =
        (Interface->FlCharacteristics->DiscoversNeighbors &&
        !Interface->FlCharacteristics->UseStaticMapping 
        && (Source != NULL))
        ? (sizeof(ND_OPTION_HDR) + DlAddressLength)
        : 0;
    ASSERT((OptionLength % 8) == 0);

    //
    // Allocate a packet for the Router Solicitation message.
    //
    Status =
        IppNetAllocate(
            &NetBufferList,
            &Buffer,
            Interface->FlBackfill + sizeof(IPV6_HEADER),
            sizeof(ND_ROUTER_SOLICIT_HEADER) + OptionLength);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    //
    // Fill the Router Solicitation header and the SLLA option.
    // 
    Solicitation = (ND_ROUTER_SOLICIT_HEADER UNALIGNED *) Buffer;
    Solicitation->nd_rs_type = ND_ROUTER_SOLICIT;
    Solicitation->nd_rs_code = 0;
    Solicitation->nd_rs_cksum = 0;
    Solicitation->nd_rs_reserved = 0;

    if (OptionLength != 0) {
        Option = (PND_OPTION_HDR) (Solicitation + 1);
        Option->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
        Option->nd_opt_len = (UINT8) (OptionLength / 8);
        RtlCopyMemory(
            Option + 1, 
            FlCharacteristics->DlAddress, 
            DlAddressLength);
    }

    //
    // Send the ICMPv6 Router Solicitation Message.
    //
    IppSendDirect(
        Interface, 
        SubInterface,
        NULL,
        Source,
        (PUCHAR) NlDestination,
        IPPROTO_ICMPV6,
        NULL,
        FIELD_OFFSET(ND_ROUTER_SOLICIT_HEADER, nd_rs_cksum),
        NetBufferList);

    IppUpdateIcmpOutStatistics(&Ipv6Global, ND_ROUTER_SOLICIT);
}

VOID
Ipv6pSendRouterSolicitationOnAllSubInterfaces(
    IN PIP_INTERFACE Interface,
    IN IN6_ADDR *NlDestination,
    IN PIP_LOCAL_UNICAST_ADDRESS Source OPTIONAL
    )
/*++

Routine Description:

    Send a Router Solicitation message.
    The solicitation is always sent to the all-routers multicast address.
    
Arguments:

    Interface - Supplies the interface to send the solicitation on.
    
    NlDestination - Supplies the destination of the solicitation.  For
        multicast enabled addresses, this is the all routers on link 
        multicast address. 

    Source - Supplies the source address to use for the Router Solicitation.
        If NULL, the solicitation is sent from the unspecified address.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    IF_LUID OldLuid = {0};
    PIP_SUBINTERFACE SubInterface = NULL;

    ASSERT(Interface->UseRouterDiscovery);

    for (;;) {
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 
                                                         &OldLuid, 
                                                         SubInterface);
        if (SubInterface == NULL) {
            break;
        }
        OldLuid = SubInterface->Luid;

        Ipv6pSendRouterSolicitationOnSubInterface(
            SubInterface, NlDestination, Source);
    }
}

BOOLEAN
Ipv6pAdvertiseRoute(
    IN OUT PUCHAR *Buffer,
    IN OUT PUSHORT Length,
    IN CONST IP_INTERFACE *Interface,
    IN BOOLEAN Forward,
    IN PIPR_LOCKED_SET RouteSet,
    IN PIP_UNICAST_ROUTE Route,
    IN CONST IPV6P_ROUTE_KEY *Key,
    IN USHORT KeyLength
    )
/*++

Routine Description:

    Include information from a route in an outgoing Router Advertisement.
    
Arguments:

    Buffer - Supplies the location for the next option.
        Returns the updated location.
        
    Length - Supplies the amount of space available for the next option.
        Returns the updated amount.
        
    Interface - Supplies the interface to send the advertisement over.

    Forward - Supplies TRUE if the interface is forwarding.  FALSE otherwise.
    
    RouteSet - Supplies the set to which the route belongs.
    
    Route - Supplies the route to inspect.
        Returns the route with its lifetimes updated.
    
    Key - Supplies the route's key.
    
    KeyLength - Supplies the route's key length (in bits).
    
Return Value:

    TRUE if the supplied route is a default route, FALSE otherwise.
    
Caller LOCK: Route Set (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    ND_OPTION_ROUTE_INFO UNALIGNED *RouteOption;
    ND_OPTION_PREFIX_INFO UNALIGNED *PrefixOption;
    USHORT OptionSize;
    UINT8 PrefixLength;
    CONST IN6_ADDR *Prefix = (CONST IN6_ADDR *) &(Key->DestinationPrefix);
    SCOPE_LEVEL PrefixScope = Ipv6AddressScope((PUCHAR) Prefix);

    ASSERT_SCALABLE_WRITE_LOCK_HELD(&(RouteSet->Lock));

    IppUpdateUnicastRouteLifetimes(RouteSet, Route);
    
    if (KeyLength <= RTL_BITS_OF(IN6_ADDR)) {
        PrefixLength = (UINT8) KeyLength;
    } else {
        PrefixLength = RTL_BITS_OF(IN6_ADDR);
    }

    if (IppIsOnLinkRoute(Route) && (Route->Interface == Interface)) {
        if (*Length < sizeof(*PrefixOption)) {
            return FALSE;
        }

        //
        // Generate a prefix-information option with the L (A, S?) bit(s) set.
        //        
        PrefixOption = (ND_OPTION_PREFIX_INFO UNALIGNED *) *Buffer;
        *Buffer += sizeof(*PrefixOption);
        *Length -= sizeof(*PrefixOption);

        PrefixOption->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
        PrefixOption->nd_opt_pi_len = sizeof(*PrefixOption) / 8;
        PrefixOption->nd_opt_pi_prefix_len = PrefixLength;

        PrefixOption->nd_opt_pi_flags_reserved = 0;
        PrefixOption->Flags.OnLink = TRUE;
        PrefixOption->Flags.Autonomous =
            Route->Flags.AutoconfigureAddress &&
            ((PrefixLength +
              Interface->FlCharacteristics->IdentifierLength) ==
             RTL_BITS_OF(IN6_ADDR));

        //
        // IppTicksToSeconds preserves the infinite value.
        //
        PrefixOption->nd_opt_pi_valid_time =
            ((Route->ValidLifetime == (ULONG)-1) &&
             (!Route->Flags.Immortal)) ?
                ND_RA_DEFAULT_PREFIX_ADVVALID_LIFETIME :
                RtlUlongByteSwap(IppTicksToSeconds(Route->ValidLifetime)) ;
            
            
        PrefixOption->nd_opt_pi_preferred_time =
            ((Route->PreferredLifetime == (ULONG)-1) &&
             (!Route->Flags.Immortal)) ?
                ND_RA_DEFAULT_PREFIX_ADVPREFERRED_LIFETIME : 
                RtlUlongByteSwap(IppTicksToSeconds(Route->PreferredLifetime));
            

        //
        // Is this also a site prefix?
        // NB: The SitePrefixLength field overlaps nd_opt_pi_reserved2.
        //
        PrefixOption->nd_opt_pi_reserved2 = 0;
        if (Route->SitePrefixLength != 0) {
            PrefixOption->Flags.SitePrefix = TRUE;
            PrefixOption->nd_opt_pi_site_prefix_len = Route->SitePrefixLength;
        }
                
        PrefixOption->nd_opt_pi_prefix = *Prefix;
    } else if (Forward &&
               (Route->Interface != Interface) &&
               (Interface->ZoneIndices[PrefixScope].Value ==
                Route->Interface->ZoneIndices[PrefixScope].Value)) {
        //
        // We only advertise routes if we are forwarding and if we won't
        // forward out the same interface: if such a route were published and
        // used, we'd generate a Redirect, but better to avoid in the first
        // place.  Also, we keep scoped routes within their zone.
        //
        if (PrefixLength == 0) {
            //
            // We don't explicitly advertise a default-route.
            //
            return TRUE;
        } else {
            //
            // We generate a route-information option.
            //
            if (PrefixLength <= 64) {
                OptionSize = 16;
            } else {
                OptionSize = 24; 
            }
            
            if (*Length < OptionSize) {
                return FALSE;
            }
            RouteOption = (ND_OPTION_ROUTE_INFO UNALIGNED *) *Buffer;
            *Buffer += OptionSize;
            *Length -= OptionSize;

            RouteOption->nd_opt_ri_type = ND_OPT_ROUTE_INFO;
            RouteOption->nd_opt_ri_len = OptionSize / 8;
            RouteOption->nd_opt_ri_prefix_len = PrefixLength;

            RouteOption->Flags.Preference =
                Ipv6pEncodeRouteMetric(Route->Metric);

            RouteOption->nd_opt_ri_route_lifetime =
                RtlUlongByteSwap(IppTicksToSeconds(Route->ValidLifetime));    

            CopyPrefix(
                (PUCHAR) &(RouteOption->nd_opt_ri_prefix),
                (CONST UCHAR *) Prefix,
                PrefixLength,
                OptionSize - 8);
        }
    }
    
    return FALSE;
}

VOID
Ipv6pSendRouterAdvertisementOnSubInterface(
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_LOCAL_UNICAST_ADDRESS Source,
    IN CONST IN6_ADDR *Destination
    )
/*++

Routine Description:

    Send a Router Advertisement message.

Arguments:

    SubInterface - Supplies the subinterface to send the advertisement on.

    Source - Supplies the source address to use for the Router Advertisement.

    Destination - Supplies the destination address of the Router Advertisement.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    CONST FL_INTERFACE_CHARACTERISTICS *FlCharacteristics = 
                Interface->FlCharacteristics;
    USHORT DlAddressLength = FlCharacteristics->DlAddressLength;
    ULONG Mtu;
    BOOLEAN Forward;
    USHORT SllaOptionLength, Size;
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    
    ND_ROUTER_ADVERT_HEADER UNALIGNED *Advertisement;
    PND_OPTION_HDR SllaOption;
    ND_OPTION_MTU UNALIGNED *MtuOption;
    
    IPV6_ROUTER_ADVERTISEMENT_FLAGS Flags = {0};
    ULONG RouterLifetime, DefaultRouteMetric; 
    BOOLEAN DefaultRoute;

    PIPR_LOCKED_SET RouteSet = &(Interface->Compartment->RouteSet);
    PREFIX_TREE_CONTEXT Context;
    ULONG Count;
    PIPR_LINK Link;
    PUCHAR Key;
    USHORT KeyLength;
    PIP_UNICAST_ROUTE Route, NextRoute, RouteList;
    NTSTATUS Status;
    KLOCK_QUEUE_HANDLE LockHandle;

    ASSERT(Source != NULL);
    ASSERT(Interface->UseRouterDiscovery);
    
    //
    // For consistency, capture some volatile information in locals.
    //
    Forward = (BOOLEAN) Interface->Forward;
    Mtu = SubInterface->NlMtu;

    //
    // Determine the buffer size for the advertisement.  We typically do not
    // use the entire buffer, but briefly allocating a large buffer is okay.
    //
    Size = Mtu - (USHORT) sizeof(IPV6_HEADER);

    //
    // Allocate a packet for the Router Advertisement message.
    //
    Status =
        IppNetAllocate(
            &NetBufferList,
            &Buffer,
            Interface->FlBackfill + sizeof(IPV6_HEADER),
            Size);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    //
    // Prepare the Router Advertisement header.
    //
    ASSERT(Size >= sizeof(*Advertisement));
    Advertisement = (ND_ROUTER_ADVERT_HEADER UNALIGNED *) Buffer;
    RtlZeroMemory(Advertisement, sizeof(*Advertisement));
    Advertisement->nd_ra_type = ND_ROUTER_ADVERT;

    //
    // Unless explicitly configured to advertise self as a default router,
    // we fill in the RouterLifetime and DefaultRouteMetric later.
    //
    if (Interface->AdvertiseDefaultRoute) {
        RouterLifetime = INFINITE_LIFETIME;
        DefaultRouteMetric = RouteMetricMedium;
    } else {
        RouterLifetime = 0;
        DefaultRouteMetric = (ULONG) RouteMetricInvalid;
    }
    
    //
    // Advertise "managed address config" and "other stateful config" flags.
    //
    Flags.ManagedAddressConfiguration = Interface->ManagedAddressConfiguration;
    Flags.OtherStatefulConfiguration = Interface->OtherStatefulConfiguration;

    Buffer += sizeof(*Advertisement);
    Size -= sizeof(*Advertisement);
    
    //
    // Prepare the SLLA option.
    // NB: Some interfaces do not use SLLA and TLLA options.
    //
    if (Interface->FlCharacteristics->DiscoversNeighbors &&
        !Interface->FlCharacteristics->UseStaticMapping) {
        SllaOption = (PND_OPTION_HDR) Buffer;
        SllaOptionLength = sizeof(*SllaOption) + DlAddressLength;
        ASSERT((SllaOptionLength % 8) == 0);
 
        SllaOption->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
        SllaOption->nd_opt_len = (UINT8) (SllaOptionLength / 8);
        RtlCopyMemory(
            SllaOption + 1, FlCharacteristics->DlAddress, DlAddressLength);

        Buffer += SllaOptionLength;
        Size -= SllaOptionLength;
    }

    //
    // Always include MTU option.
    //
    MtuOption = (ND_OPTION_MTU UNALIGNED *) Buffer;
    MtuOption->nd_opt_mtu_type = ND_OPT_MTU;
    MtuOption->nd_opt_mtu_len = sizeof(*MtuOption) / 8;
    MtuOption->nd_opt_mtu_reserved = 0;
    MtuOption->nd_opt_mtu_mtu = RtlUlongByteSwap(Mtu);

    Buffer += sizeof(*MtuOption);
    Size -= sizeof(*MtuOption);

    
    //
    // Lock the route set.
    // 
    RtlAcquireScalableWriteLock(&(RouteSet->Lock), &LockHandle);
    
    //
    // Now we scan the routing table looking for published routes.
    // We incrementally add Prefix Information and Route Information options,
    // and we determine RouterLifetime and DefaultRouteMetric.
    //
    RtlZeroMemory(&Context, sizeof(Context));
    Count = 1;
    
    do {
        Status =
            PtEnumOverTable(
                RouteSet->Tree, NULL, NULL, &Context, NULL, 0, &Count, &Link);

        if (Count == 0) {
            break;
        }

        PtGetKey(Link, &Key, &KeyLength);

        //
        // Advertise published routes.
        //
        Route = CONTAINING_RECORD(Link, IP_UNICAST_ROUTE, Link);
        RouteList = Route;

        do {
            NextRoute = (PIP_UNICAST_ROUTE) CONTAINING_RECORD(
                Route->RouteLink.Flink, IP_UNICAST_ROUTE, RouteLink);

            if (Route->Flags.Publish) {
                DefaultRoute =
                    Ipv6pAdvertiseRoute(
                        &Buffer,
                        &Size,
                        Interface,
                        Forward,
                        RouteSet,
                        Route,
                        (CONST IPV6P_ROUTE_KEY *) Key,
                        KeyLength);
                if (DefaultRoute) {
                    //
                    // We don't explicitly advertise zero-length prefixes.
                    // Instead we advertise a non-zero router lifetime.
                    //
                    if (Route->ValidLifetime > RouterLifetime) {
                        RouterLifetime = Route->ValidLifetime;
                    }
                
                    if (Route->Metric < DefaultRouteMetric) {
                        DefaultRouteMetric = Route->Metric;
                    }
                }
            }

            Route = NextRoute;
        } while (NextRoute != RouteList);
        
    } while ((Status != STATUS_NO_MORE_MATCHES) && (Size > 0));

    RtlReleaseScalableWriteLock(&(RouteSet->Lock), &LockHandle);

    if (RouterLifetime != 0) {
        //
        // We will be a default router. Calculate the 16-bit lifetime.
        // Note that there is no infinite value on the wire.
        //
        RouterLifetime = IppTicksToSeconds(RouterLifetime);
        if (RouterLifetime > 0xffff) {
            RouterLifetime = 0xffff;
        }
        Flags.Preference = Ipv6pEncodeRouteMetric(DefaultRouteMetric);
        
        Advertisement->nd_ra_router_lifetime =
            RtlUshortByteSwap((USHORT) RouterLifetime);
    }
    
    Advertisement->nd_ra_flags_reserved = Flags.Value;

    //
    // Before we transmit the packet (and lose ownership of the memory), make a
    // pass over the packet, processing prefix-information options ourselves.
    // This is like receiving our own Router Advertisement, except we do not
    // create routes.  The options are well-formed of course.
    //
    Size = (USHORT) (Buffer - ((PUCHAR) (MtuOption + 1)));
    Buffer = (PUCHAR) (MtuOption + 1);
    while (Size > 0) {
        PND_OPTION_HDR Option = (PND_OPTION_HDR) Buffer;

        if (Option->nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
            ND_OPTION_PREFIX_INFO UNALIGNED *PrefixOption;
            UINT8 PrefixLength, SitePrefixLength;
            ULONG ValidLifetime, PreferredLifetime;
            PIN6_ADDR Prefix;

            //
            // Because we just constructed the prefix-information options,
            // we know they are syntactically valid.
            //
            PrefixOption = (ND_OPTION_PREFIX_INFO UNALIGNED *) Buffer;

            Prefix = AlignAddr(&(PrefixOption->nd_opt_pi_prefix));
            PrefixLength = PrefixOption->nd_opt_pi_prefix_len;
            SitePrefixLength = PrefixOption->nd_opt_pi_site_prefix_len;

            ValidLifetime =
                RtlUlongByteSwap(PrefixOption->nd_opt_pi_valid_time);
            ValidLifetime = IppSecondsToTicks(ValidLifetime);
            PreferredLifetime =
                RtlUlongByteSwap(PrefixOption->nd_opt_pi_preferred_time);
            PreferredLifetime = IppSecondsToTicks(PreferredLifetime);

            if (PrefixOption->Flags.Autonomous) {
                //
                // Only "proper" prefixes are published.
                //
                ASSERT(!IN6_IS_ADDR_LINKLOCAL(Prefix));
                ASSERT(!IN6_IS_ADDR_MULTICAST(Prefix));
                ASSERT((PrefixLength +
                        FlCharacteristics->IdentifierLength) ==
                       RTL_BITS_OF(IN6_ADDR));

                //
                // Attempt autonomous address-configuration.
                //
                Ipv6pUpdateAutoConfiguredAddresses(
                    Interface,
                    Prefix,
                    PrefixLength,
                    ValidLifetime,
                    PreferredLifetime, 
                    TRUE);
            }

            if (PrefixOption->Flags.SitePrefix) {
                //
                // Again, the sanity checks should have been enforced.
                //
                ASSERT(!IN6_IS_ADDR_SITELOCAL(Prefix));
                ASSERT(SitePrefixLength <= PrefixLength);
                ASSERT(SitePrefixLength != 0);

                Ipv6pUpdateSitePrefix(
                    Interface,
                    Prefix,
                    SitePrefixLength,
                    ValidLifetime);
            }
        }

        Buffer += Option->nd_opt_len * 8;
        Size -= Option->nd_opt_len * 8;
    }
    ASSERT(Size == 0);


    //
    // We can update the LastRouterAdvertisement now that we are past all the
    // error conditions. 
    //
    Interface->LastRouterAdvertisement = IppTickCount;

    //
    // Send only what we filled in.
    //
    ASSERT(((USHORT) (Buffer - (PUCHAR) Advertisement)) < 
           NetBufferList->FirstNetBuffer->DataLength);
    NetioTruncateNetBuffer(
        NetBufferList->FirstNetBuffer,
        NetBufferList->FirstNetBuffer->DataLength - 
        (USHORT) (Buffer - (PUCHAR)Advertisement));
    
    //
    // Send the ICMPv6 Router Advertisement Message.
    //
    IppSendDirect(
        Interface, 
        SubInterface,
        NULL,
        Source,
        (PUCHAR) Destination,
        IPPROTO_ICMPV6,
        NULL,
        FIELD_OFFSET(ND_ROUTER_ADVERT_HEADER, nd_ra_cksum),
        NetBufferList);

    IppUpdateIcmpOutStatistics(&Ipv6Global, ND_ROUTER_ADVERT);
}


VOID
Ipv6pSendRouterAdvertisementOnAllSubInterfaces(
    IN PIP_INTERFACE Interface,
    IN PIP_LOCAL_UNICAST_ADDRESS Source,
    IN CONST IN6_ADDR *Destination
    )
/*++

Routine Description:

    Send a Router Advertisement message.

Arguments:

    Interface - Supplies the interface to send the advertisement on.
    
    Source - Supplies the source address to use for the Router Advertisement.

    Destination - Supplies the destination address of the Router Advertisement.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    IF_LUID OldLuid = {0};
    PIP_SUBINTERFACE SubInterface = NULL;
    NL_ADDRESS_TYPE DestinationType;

    ASSERT(Source != NULL);
    ASSERT(Interface->UseRouterDiscovery);

    DestinationType = Ipv6AddressType((CONST UCHAR *)Destination);
    
    for (;;) {
        SubInterface = IppGetNextSubInterfaceOnInterface(Interface, 
                                                         &OldLuid, 
                                                         SubInterface);
        if (SubInterface == NULL) {
            break;
        }
        OldLuid = SubInterface->Luid;

        Ipv6pSendRouterAdvertisementOnSubInterface(
            SubInterface, Source, Destination);

        //
        // TODO: WindowsOS#1974103, this needs to be cleaned up,
        // who is responsible for replicating multicast packets
        // in case of multiple subinterfaces. For now we will let 
        // IppDispatchSendPacketHelper do this, so no loop is required here.
        //

        ASSERT(DestinationType == NlatMulticast);

        if (DestinationType == NlatMulticast) {
            IppDereferenceSubInterface(SubInterface);
            break;
        }

    }
}

VOID
Ipv6pSendRedirectHelper(
    IN PIN6_ADDR Destination,
    IN PIN6_ADDR Neighbor,
    IN PIPV6_NEIGHBOR Target,
    IN PNET_BUFFER OriginalPacket
    )
/*++

Routine Description:

    Send a Redirect message to a neighbor, telling it to use a
    better first-hop neighbor in the future for the specified destination.

    Compare RedirectSend in the XP IPv6 stack.
    
Arguments:

    Destination - Supplies the destination for which to send the redirect.

    Neighbor - Supplies the neighbor to send the redirect to.

    Target - Supplies the better first-hop neighbor for the Destination.

    OriginalPacket - Supplies the packet triggering the redirect.
        This is included in the redirected header option.
        The packet offset is set to the beginning of the IPv6 header.
        Hence, the packet length is OriginalPacket->DataLength.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NTSTATUS Status;
    KIRQL OldIrql;
    PIP_INTERFACE Interface = Target->SubInterface->Interface;
    PIP_LOCAL_UNICAST_ADDRESS Source;
    UCHAR DlAddress[DL_ADDRESS_LENGTH_MAXIMUM];
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    
    ULONG Size;
    ULONG TllaOptionLength = 0;
    ULONG RedirectOptionLength, RedirectDataLength, RedirectPaddingLength;
    SIZE_T BytesCopied;
    
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    ND_REDIRECT_HEADER UNALIGNED *Redirect;
    PND_OPTION_HDR Option;

    NL_REQUEST_SEND_DATAGRAMS Args = {0};
    

    //
    // Keep prefast happy.
    //
    ASSERT(DlAddressLength <= DL_ADDRESS_LENGTH_MAXIMUM);
    __analysis_assume(DlAddressLength <= DL_ADDRESS_LENGTH_MAXIMUM);
        
    RtlAcquireReadLock(&Interface->Lock, &OldIrql);
    
    //
    // We need a valid link-local address to send a redirect.
    //
    Source = IppFindLinkLocalUnicastAddress(Interface);
    if (Source == NULL) {
        RtlReleaseReadLock(&Interface->Lock, OldIrql);
        return;
    }

    //
    // Determine the size of the required IPv6 message.
    //
    Size = sizeof(IPV6_HEADER) + sizeof(ND_REDIRECT_HEADER);
    
    //
    // Determine the TLLA option length.
    // NB: Some interfaces do not use SLLA and TLLA options.
    // NB: We sometimes do not have the target link address mapped.
    //
    if (Interface->FlCharacteristics->DiscoversNeighbors &&
        !Interface->FlCharacteristics->UseStaticMapping &&
        (Target->State != NlnsIncomplete)) {
        RtlCopyMemory(DlAddress, Target->DlAddress, DlAddressLength);

        TllaOptionLength = sizeof(ND_OPTION_HDR) + DlAddressLength;
    }
    ASSERT((TllaOptionLength % 8) == 0);
    Size += TllaOptionLength;

    RtlReleaseReadLock(&Interface->Lock, OldIrql);
    
    
    //
    // Allow space for the Redirected Header option, without exceeding the MTU.
    // Note that RFC 2461 4.6.3 explicitly specifies the IPv6 minimum MTU, not
    // the link MTU.  We can always include at least the option header and the
    // IPv6 header from the OriginalPacket.
    //
    RedirectOptionLength = 8;
    if ((Size + RedirectOptionLength + OriginalPacket->DataLength) >
        IPV6_MINIMUM_MTU) {
        //
        // Truncate OriginalPacket to make it fit.
        //
        RedirectDataLength = IPV6_MINIMUM_MTU - Size - RedirectOptionLength;
        RedirectPaddingLength = 0;
    } else {
        //
        // Include all of OriginalPacket, plus possible padding.
        //
        RedirectDataLength = OriginalPacket->DataLength;
        RedirectPaddingLength =
            ((RedirectDataLength + 7) &~ 7) - RedirectDataLength;
    }
    RedirectOptionLength += RedirectDataLength + RedirectPaddingLength;
    ASSERT((RedirectOptionLength % 8) == 0);
    Size += RedirectOptionLength;

    //
    // Allocate a packet for the Redirect message with enough backfill.
    //
    Status =
        IppAllocateIcmpError(
            &NetBufferList,
            &Buffer,
            Interface->FlCharacteristics->HeaderLength + sizeof(IPV6_HEADER),
            Size - sizeof(IPV6_HEADER));        
    if (!NT_SUCCESS(Status)) {
        IppDereferenceLocalUnicastAddress(Source);
        return;
    }
    
    //
    // Fill the Redirect header and the TLLA option.
    // 
    Redirect = (ND_REDIRECT_HEADER UNALIGNED *) Buffer;
    Redirect->nd_rd_type = ND_REDIRECT;
    Redirect->nd_rd_code = 0;
    Redirect->nd_rd_cksum = 0;
    Redirect->nd_rd_reserved = 0;
    Redirect->nd_rd_target = Target->Ipv6Address;
    Redirect->nd_rd_dst = *Destination;
    Buffer += sizeof(ND_REDIRECT_HEADER);
    
    if (TllaOptionLength != 0) {
        Option = (PND_OPTION_HDR) Buffer;
        Option->nd_opt_type = ND_OPT_TARGET_LINKADDR;
        Option->nd_opt_len = (UINT8) (TllaOptionLength / 8);
        RtlCopyMemory(Option + 1, DlAddress, DlAddressLength);    
        Buffer += TllaOptionLength;
    }

    //
    // Include a Redirected Header option (with as much of the OriginalPacket
    // as will fit, and any padding bytes zeroed out).
    //
    Option = (PND_OPTION_HDR) Buffer;
    Option->nd_opt_type = ND_OPT_REDIRECTED_HEADER;
    Option->nd_opt_len = (UINT8) (RedirectOptionLength / 8);
    RtlZeroMemory(Option + 1, 6);
    Buffer += 8;
    
    RtlCopyMdlToBuffer(
        OriginalPacket->MdlChain,
        OriginalPacket->DataOffset,
        (PUCHAR) Buffer,
        RedirectDataLength,
        &BytesCopied);
    ASSERT(BytesCopied == RedirectDataLength);
    Buffer += RedirectDataLength;

    RtlZeroMemory(Buffer, RedirectPaddingLength);
    
    //
    // Send the ICMPv6 Redirect Message.
    // Specifying a local source allows an unspecified destination scope id.
    //
    Args.NetBufferList = NetBufferList;
    Args.DestProtocol = IPPROTO_ICMPV6;
    Args.UlChecksumOffset = FIELD_OFFSET(ND_REDIRECT_HEADER, nd_rd_cksum);
    Args.RemoteAddress = (PUCHAR) Neighbor;
    Args.RemoteScopeId = scopeid_unspecified;
    Args.NlLocalAddress.LocalAddress = (CONST NL_LOCAL_ADDRESS *) Source;
    Args.NlSessionState = &Ipv6pNdSessionState;
    IppSendDatagrams(&Ipv6Global, &Args);
    IppUpdateIcmpOutStatistics(&Ipv6Global, ND_REDIRECT);

    IppDereferenceLocalUnicastAddress(Source);
}


VOID
Ipv6pSendRedirect(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PIP_NEIGHBOR Target
    )
/*++

Routine Description:

    Send a Redirect message to a neighbor, telling it to use a
    better first-hop neighbor in the future for the specified destination.
    
Arguments:

    Control - Supplies the packet triggering the redirect.    
        A clone of this packet is encapsulated in the redirect message
        and the original may be forwarded once the function returns.

    Target - Supplies the better first-hop neighbor for its destination.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    Ipv6pSendRedirectHelper(
        (PIN6_ADDR) Control->CurrentDestinationAddress,
        (PIN6_ADDR) Control->SourceAddress.Address,
        (PIPV6_NEIGHBOR) Target,
        Control->NetBufferList->FirstNetBuffer);
}


VOID
Ipv6pHandleRouterAdvertisement(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    )
/*++

Routine Description:

    Validate and Process an IPv6 Router Advertisement Message.
    
    Update Default Router list, On-Link Prefix list, and perform
    address auto-configuration.  See sections 6.1.2, 6.3.4 of RFC 2461.

Arguments:

    Icmpv6 - Supplies the parsed ICMPv6 header.
    

    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv6 Router Advertisement packet,
        with the packet offset at the start of the advertisement header.

    Interface - Supplies the interface over which the packet was received.

    RemoteAddress - Supplies the source address of the packet.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    PIP_INTERFACE Interface = Args->DestLocalAddress->Interface;
    CONST NLC_RECEIVE_DATAGRAM *ReceiveDatagram = &Args->NlcReceiveDatagram;
    CONST IN6_ADDR *RemoteAddress = (PIN6_ADDR) ReceiveDatagram->RemoteAddress;

    BOOLEAN Drop = FALSE;
    USHORT ParsedLength;
    ND_ROUTER_ADVERT_HEADER UNALIGNED AdvertisementBuffer, *Advertisement;
    IPV6_ROUTER_ADVERTISEMENT_FLAGS Flags;
    NL_ROUTE_METRIC RouteMetric;
    ULONG RouterLifetime, ReachableTime, MinLifetime;
    UCHAR Type;
    USHORT Length;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    UCHAR DlAddressBuffer[DL_ADDRESS_LENGTH_MAXIMUM], *DlAddress = NULL;
    ULONG Mtu = 0;
    
    PIP_ROUTER_DISCOVERY_TIMER Timer;
    PIPV6_POTENTIAL_ROUTER PotentialRouter;
    PIP_NEIGHBOR Neighbor;
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    KLOCK_QUEUE_HANDLE LockHandle, NeighborSetLockHandle;

    //
    // Validate the Router Advertisement.
    // By the time we get here, any IPv6 Authentication Header will have
    // already been checked, as will have the ICMPv6 checksum.  Still need
    // to check the source, IPv6 Hop Limit, and the ICMPv6 code and length.
    //

    if (((PIPV6_HEADER) Args->IP)->HopLimit != 255) {
        //
        // Packet was forwarded by a router, therefore it cannot be from a
        // legitimate neighbor.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (Icmpv6->Header.Code != 0) {
        //
        // Bogus/corrupted Router Advertisement message.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (Ipv6AddressScope((PUCHAR) RemoteAddress) != ScopeLevelLink) {
        //
        // Source address should always be link-local. Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    //
    // Get the Router Advertisement header.
    //    
    if (NetBuffer->DataLength < sizeof(ND_ROUTER_ADVERT_HEADER)) {
        //
        // Insufficient data buffer for a minimal Router Advertisement.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    Advertisement =
        NetioGetDataBuffer(
            NetBuffer,
            sizeof(ND_ROUTER_ADVERT_HEADER), 
            &AdvertisementBuffer, 
            1, 
            0);
    
    ParsedLength = sizeof(ND_ROUTER_ADVERT_HEADER);
    NetioAdvanceNetBuffer(NetBuffer, ParsedLength);

    Flags.Value = Advertisement->nd_ra_flags_reserved;
    
    RouterLifetime = RtlUshortByteSwap(Advertisement->nd_ra_router_lifetime);
    ReachableTime = RtlUlongByteSwap(Advertisement->nd_ra_reachable);
   
    //
    // Look for a source link-layer address and MTU options.
    // Also sanity-check the options before doing anything permanent.
    //
    while (Ipv6pParseTlvOption(NetBuffer, &Type, &Length)) {
        switch (Type) {
        case ND_OPT_SOURCE_LINKADDR: {
            //
            // Some interfaces do not use SLLA and TLLA options.
            // For example, see RFC 2893 section 3.8.
            //
            // Note that if there are multiple options for some bogus reason,
            // we use the last one.  We sanity-check all the options.
            //
            if (!Interface->FlCharacteristics->DiscoversNeighbors ||
                Interface->FlCharacteristics->UseStaticMapping) {
                break;
            }
            
            if (Length != (sizeof(ND_OPTION_HDR) + DlAddressLength)) {
                //
                // Invalid option format.  Drop the packet.
                //
                Drop = TRUE; 
                break;
            }

            NetioAdvanceNetBuffer(NetBuffer, sizeof(ND_OPTION_HDR));
            ParsedLength += sizeof(ND_OPTION_HDR);
            Length -= sizeof(ND_OPTION_HDR);

            DlAddress =
                NetioGetDataBuffer(NetBuffer, Length, DlAddressBuffer, 1, 0);

            break;
        }
            
        case ND_OPT_MTU: {
            ND_OPTION_MTU UNALIGNED OptionBuffer, *Option;

            //
            // Note that if there are multiple options for some bogus reason,
            // we use the last one.  We sanity-check all the options.
            //
            if (Length != sizeof(ND_OPTION_MTU)) {
                //
                // Invalid option format.  Drop the packet.
                //
                Drop = TRUE;
                break;
            }
            
            Option =
                NetioGetDataBuffer(NetBuffer, Length, &OptionBuffer, 1, 0);

            Mtu = RtlUlongByteSwap(Option->nd_opt_mtu_mtu);
            break;
        }
            
        case ND_OPT_PREFIX_INFORMATION: {
            ND_OPTION_PREFIX_INFO UNALIGNED OptionBuffer, *Option;

            //
            // Sanity-check the option.
            //
            Option =
                NetioGetDataBuffer(NetBuffer, Length, &OptionBuffer, 1, 0);

            if ((Length != sizeof(ND_OPTION_PREFIX_INFO)) ||
                (Option->nd_opt_pi_prefix_len > RTL_BITS_OF(IN6_ADDR))) {
                //
                // Invalid option format.  Drop the packet.
                //
                Drop = TRUE;
            }
            break;
        }
            
        case ND_OPT_ROUTE_INFO: {
            ND_OPTION_ROUTE_INFO UNALIGNED OptionBuffer, *Option;
            
            //
            // Sanity-check the option.
            // Depending on PrefixLength, there might be 0, 8, 16 extra bytes.
            //
            Option =
                NetioGetDataBuffer(NetBuffer, Length, &OptionBuffer, 1, 0);

            if ((Length > sizeof(ND_OPTION_ROUTE_INFO)) ||
                (Option->nd_opt_ri_prefix_len > RTL_BITS_OF(IN6_ADDR)) ||
                ((Option->nd_opt_ri_prefix_len > 64) && (Length < 24)) ||
                ((Option->nd_opt_ri_prefix_len > 0) && (Length < 16))) {
                //
                // Invalid option format.  Drop the packet.
                //
                Drop = TRUE;
            }
            break;
        }
        }

        if (Drop) {
            break;
        }

        //
        // Move forward to the next option.
        // Keep track of the parsed length, so we can use it below to back up.
        //
        NetioAdvanceNetBuffer(NetBuffer, Length);
        ParsedLength += Length;
    }
        
    //
    // We have parsed all we could, so now retreat.
    // Fail if we didn't successfully parse the entire packet.
    //
    NetioRetreatNetBuffer(NetBuffer, ParsedLength, 0);
    if (NetBuffer->DataLength != ParsedLength) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }


    RtlAcquireWriteLock(&(Interface->Lock), &LockHandle);

    //
    // Ignore the advertisement if this is an advertising interface.
    // Note that we still parse it for sanity checkin.
    //
    if ((Interface->Advertise) || (!Interface->UseRouterDiscovery)) {
        RtlReleaseWriteLock(&(Interface->Lock), &LockHandle);
        Args->NetBufferList->Status = STATUS_SUCCESS;
        return;
    }

    //
    // Find the router discovery timer for this router.  For multicast enabled
    // interfaces, this is stored in the interface itself.  For non-multicast
    // (e.g. ISATAP) interfaces, this is stored in the potential router
    // entry.  Also, if we receive a router advertisement from a router not in 
    // the potential router list, we simply ignore it. 
    //
    if (!Interface->FlCharacteristics->Multicasts) {
        PotentialRouter =
            Ipv6pFindPotentialRouterUnderLock(
                Interface, (CONST IN6_ADDR*) Args->SourceAddress.Address);
        if (PotentialRouter == NULL) {
            RtlReleaseWriteLock(&(Interface->Lock), &LockHandle);
            Args->NetBufferList->Status = STATUS_SUCCESS;
            return;
        }
        Timer = IP_GET_ROUTER_DISCOVERY_TIMER(PotentialRouter);
    } else {
        Timer = IP_GET_ROUTER_DISCOVERY_TIMER(Interface);
    }

    //
    // Create/Update the Neighbor Entry for the source of this advertisement.
    //
    RtlAcquireWriteLockAtDpcLevel(
        &Interface->NeighborSetLock, &NeighborSetLockHandle);

    Neighbor =
        IppFindOrCreateNeighborUnderLock(
            Interface, 
            Args->SourceSubInterface,
            (CONST UCHAR *) RemoteAddress,
            NlatUnicast);
    if (Neighbor != NULL) {
        Neighbor->IsRouter = TRUE;
        Control =
            IppUpdateNeighbor(
                Neighbor,
                DlAddress,
                Interface->FlModule->Npi.Dispatch->
                GetLinkLayerSourceRoute(
                    Interface->FlContext,
                    Args->NetBufferList),
                FALSE,
                TRUE,
                FALSE);
    }

    Ipv6pUpdateMtu(Args->SourceSubInterface, Mtu);
    
    RtlReleaseWriteLockFromDpcLevel(
        &Interface->NeighborSetLock, &NeighborSetLockHandle);

    //
    // Cache the parity of the "managed address config" and 
    // "other stateful config" flags.
    //
    IppUpdateInterfaceConfigurationFlags(
        Interface,
        Flags.ManagedAddressConfiguration,
        Flags.OtherStatefulConfiguration);
    
    //
    // If we had just reconnected this interface, then give all auto-configured
    // state a small "accelerated" lifetime.
    // The processing below might extend accelerated lifetimes.
    //
    if (Interface->MediaReconnected) {
        Interface->MediaReconnected = FALSE;

        //
        // Reset auto-configured address lifetimes.
        //
        Ipv6pResetAutoConfiguredAddresses(
            Interface, 2 * MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS);

        //
        // Similarly, reset auto-configured route lifetimes.
        //
        Ipv6pResetAutoConfiguredRoutes(
            Interface, 2 * MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS);

        //
        // Reset parameters that are learned from Router Advertisements.
        //
        Ipv6pResetAutoConfiguredParameters(Interface);
    }

    //
    // Stop sending Router Solicitations for this interface.
    // A host MUST stop sending Router Solicitations for an interface upon
    // receiving a valid router advertisement with a non-zero router lifetime.
    // We go a step further and, on a non-multicast interface, stop after the
    // first valid response - presumably that's all we are going to receive.
    // Note that we should always send at least one Router Solicitation,
    // even if we receive an unsolicited Router Advertisement first.
    //
    if ((RouterLifetime != 0) || !Interface->FlCharacteristics->Multicasts) {
        if (Timer->RouterDiscoveryCount < MAX_RTR_SOLICITATIONS) {
            Timer->RouterDiscoveryTimer = 0;
            Timer->RouterDiscoveryCount = 0;
        }
    }
    
    //
    // Update the BaseReachableTime and ReachableTime.
    // NB: We use a lock for coordinated updates, but other code
    // reads the ReachableTime field without a lock.
    //
    if ((ReachableTime != 0) &&
        (ReachableTime != Interface->BaseReachableTime)) {
        Interface->BaseReachableTime = ReachableTime;
        Interface->ReachableTicks = IppNeighborReachableTicks(ReachableTime);
    }

    RtlReleaseWriteLock(&(Interface->Lock), &LockHandle);

    if (Control != NULL) {
        IppFragmentPackets(&Ipv6Global, Control);
    }

    //
    // Update the hop limit for the interface.
    // NB: We rely on loads/stores of the CurrentHopLimit field being atomic.
    //
    if (Advertisement->nd_ra_curhoplimit != 0) {
        Interface->CurrentHopLimit = Advertisement->nd_ra_curhoplimit;
    }

    //
    // Update the RetransmitTicks field.
    // NB: We rely on loads/stores of this field being atomic.
    //
    if (Advertisement->nd_ra_retransmit != 0) {
        Interface->RetransmitTicks = IppMillisecondsToTicks(
            RtlUlongByteSwap(Advertisement->nd_ra_retransmit));
    }

    
    //
    // Update the Default Router List.  Being 16 bits, RouterLifetimes,
    // unlike PrefixLifetimes, can not be infinite. 
    //
    ASSERT(RouterLifetime != INFINITE_LIFETIME);
    MinLifetime = RouterLifetime = IppSecondsToTicks(RouterLifetime);

    RouteMetric = Ipv6pExtractRouteMetric(Flags.Preference);
    if (RouteMetric == RouteMetricInvalid) {
        //
        // Reserved value, treat as if it were the default [RFC 4191].
        //
        RouteMetric = RouteMetricMedium;
    }
    
    IppUpdateAutoConfiguredRoute(
        Interface,
        (CONST UCHAR *) RemoteAddress,
        Neighbor,
        (CONST UCHAR *) &in6addr_any,
        0,
        RouterLifetime,
        RouteMetric);
        
    //
    // Process any PrefixInformation and RouteInformation options.
    // These have been validated in the first pass over the options, above.
    //
    ParsedLength = sizeof(ND_ROUTER_ADVERT_HEADER);    
    NetioAdvanceNetBuffer(NetBuffer, ParsedLength);

    while (Ipv6pParseTlvOption(NetBuffer, &Type, &Length)) {
        switch (Type) {
        case ND_OPT_PREFIX_INFORMATION: {
            ND_OPTION_PREFIX_INFO UNALIGNED OptionBuffer, *Option;
            UINT8 PrefixLength;
            ULONG ValidLifetime, PreferredLifetime;
            IN6_ADDR Prefix;
            
            Option =
                NetioGetDataBuffer(NetBuffer, Length, &OptionBuffer, 1, 0);

            PrefixLength = Option->nd_opt_pi_prefix_len;
            
            ValidLifetime =
                RtlUlongByteSwap(Option->nd_opt_pi_valid_time);
            ValidLifetime = IppSecondsToTicks(ValidLifetime);
            PreferredLifetime =
                RtlUlongByteSwap(Option->nd_opt_pi_preferred_time);
            PreferredLifetime = IppSecondsToTicks(PreferredLifetime);
            if (MinLifetime > PreferredLifetime) {
                MinLifetime = PreferredLifetime;
            }

            //
            // We MUST ignore any bits in the prefix after the prefix length.
            // IppUpdateAutoConfiguredRoute & Ipv6pUpdateSitePrefix do that.
            //
            CopyPrefix(
                (PUCHAR) &Prefix,
                (CONST UCHAR *) &(Option->nd_opt_pi_prefix),
                PrefixLength,
                sizeof(IN6_ADDR));
            
            //
            // Silently ignore link-local and multicast prefixes.
            // REVIEW - Is this actually the required check?
            //
            if (IN6_IS_ADDR_LINKLOCAL(&Prefix) ||
                IN6_IS_ADDR_MULTICAST(&Prefix)) {
                break;
            }

            //
            // Generally at least one flag bit is set,
            // but we must process them independently.
            //

            if (Option->Flags.OnLink) {
                IppUpdateAutoConfiguredRoute(
                    Interface,
                    NULL,
                    NULL,
                    (CONST UCHAR *) &Prefix,
                    PrefixLength,
                    ValidLifetime,
                    RouteMetricOnLink);
            }
            
            if (Option->Flags.Route) {
                IppUpdateAutoConfiguredRoute(
                    Interface,
                    (CONST UCHAR *) RemoteAddress,
                    Neighbor,
                    (CONST UCHAR *) &Prefix,
                    PrefixLength,
                    ValidLifetime,
                    RouteMetricMedium);
            }
            
            //
            // We ignore site-local prefixes here.
            // Above check filters out link-local and multicast prefixes.
            //
            if (!IN6_IS_ADDR_SITELOCAL(&Prefix)) {
                UCHAR SitePrefixLength;

                //
                // If the S bit is clear, then we check the A bit and use the
                // interface's default site prefix length.  This lets us infer
                // site prefixes when routers do not support the S bit.
                //
                if (Option->Flags.SitePrefix) {
                    SitePrefixLength = Option->nd_opt_pi_site_prefix_len;
                } else if (Option->Flags.Autonomous) {
                    SitePrefixLength = Interface->DefaultSitePrefixLength;
                } else {
                    SitePrefixLength = 0;
                }
                
                //
                // At this point the prefix is not a multicast address, a site 
                // local prefix or a link local prefix. Ignore if the Site
                // Prefix Length is zero or the site prefix length is greater
                // than the prefix length. 
                // 
                if ((SitePrefixLength != 0) && 
                    (SitePrefixLength <= PrefixLength)) {
                    Ipv6pUpdateSitePrefix(
                        Interface,
                        &Prefix,
                        SitePrefixLength,
                        ValidLifetime);
                }
            }

            if (Option->Flags.Autonomous) {
                //
                // Attempt autonomous address-configuration.
                //
                if (PreferredLifetime > ValidLifetime) {
                    //
                    // MAY log a system management error.
                    //
                    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                               "IPNG: Error processing router advertisement: "
                               "Preferred lifetime > Valid lifetime\n");
                } else if ((PrefixLength + 
                            Interface->FlCharacteristics->IdentifierLength) !=
                           RTL_BITS_OF(IN6_ADDR)) {
                    //
                    // MUST ignore the prefix if the sum of prefix length and
                    // the length of the interface identifier is not 128 bits.
                    // MAY log a system management error.
                    //
                    NetioTrace(
                        NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                        "IPNG: Error processing router advertisement: "
                        "PrefixLength (%d) + Identifier (%d) != 128 bits\n", 
                        PrefixLength, 
                        Interface->FlCharacteristics->IdentifierLength);
                } else {
                    Ipv6pUpdateAutoConfiguredAddresses(
                        Interface,
                        &Prefix,
                        PrefixLength,
                        ValidLifetime,
                        PreferredLifetime,
                        FALSE);
                }
            }
            
            break;
        }
            
        case ND_OPT_ROUTE_INFO: {
            ND_OPTION_ROUTE_INFO UNALIGNED OptionBuffer, *Option;
            ULONG RouteLifetime;

            Option =
                NetioGetDataBuffer(NetBuffer, Length, &OptionBuffer, 1, 0);


            RouteMetric = Ipv6pExtractRouteMetric(Option->Flags.Preference);
            if (RouteMetric == RouteMetricInvalid) {
                //
                // Reserved value, ignore the option [RFC 4191].
                //
                break;
            }
            
            RouteLifetime = RtlUlongByteSwap(Option->nd_opt_ri_route_lifetime);
            RouteLifetime = IppSecondsToTicks(RouteLifetime);
            if (MinLifetime > RouteLifetime) {
                MinLifetime = RouteLifetime;
            }
            
            //
            // We MUST ignore any bits in the prefix after the prefix length.
            // IppUpdateAutoConfiguredRoute does that for us.
            //
            IppUpdateAutoConfiguredRoute(
                Interface,
                (CONST UCHAR *) RemoteAddress,
                Neighbor,
                (CONST UCHAR *) AlignAddr(&Option->nd_opt_ri_prefix),
                Option->nd_opt_ri_prefix_len,
                RouteLifetime,
                RouteMetric);

            break;
        }
        }
        

        //
        // Move forward to the next option.
        // Keep track of the parsed length, so we can use it below to retreat.
        //
        NetioAdvanceNetBuffer(NetBuffer, Length);
        ParsedLength += Length;
    }

    //
    // We should have processed the entire packet, now retreat.
    //
    NetioRetreatNetBuffer(NetBuffer, ParsedLength, 0);
    ASSERT(NetBuffer->DataLength == ParsedLength);

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    if (!Interface->Advertise &&
        !Interface->FlCharacteristics->Multicasts) {
        //
        // On non-multicast interfaces, such as the ISATAP interface, we need
        // to send periodic Router Solicitations.  We want to do so as
        // infrequently as possible and still be reasonably robust.  We'll try
        // to solicit the routers halfway through the lowest lifetime in the
        // Router Advertisement we saw.  However, if a renumbering event is
        // going on, and a lifetime is low, we don't want to send too often, so
        // we put on a minimum cap equal to what we'd use if we never got an
        // Router Advertisement.
        //
        PotentialRouter =
            Ipv6pFindPotentialRouterUnderLock(
                Interface, (CONST IN6_ADDR*) Args->SourceAddress.Address);
        
        if ((PotentialRouter != NULL) && 
            (PotentialRouter->RouterDiscoveryTimer == 0)) {
            PotentialRouter->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
            PotentialRouter->RouterDiscoveryTimer =
                (MinLifetime < (SLOW_RTR_SOLICITATION_INTERVAL * 2))
                ? SLOW_RTR_SOLICITATION_INTERVAL
                : MinLifetime / 2;
        }
    }
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    Args->NetBufferList->Status = STATUS_SUCCESS;
    if (Neighbor != NULL) {
        IppDereferenceNeighbor(Neighbor);
    }    
}


VOID
Ipv6pHandleRouterSolicitation(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    )
/*++

Routine Description:

    Validate and process an IPv6 Router Solicitation message.

Arguments:

    Icmpv6 - Supplies the parsed ICMPv6 header.


    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv6 Router Solicitation packet,
        with the packet offset at the start of the solicitation header.

    Interface - Supplies the interface over which the packet was received.
    
    RemoteAddress - Supplies the source address of the packet.
    
    LocalAddressEntry - Supplies the destination address of the packet.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    CONST IP_LOCAL_ADDRESS *LocalAddress = Args->DestLocalAddress;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    CONST IN6_ADDR *RemoteAddress = 
        (PIN6_ADDR) Args->NlcReceiveDatagram.RemoteAddress;

    USHORT ParsedLength;
    UCHAR Type;
    USHORT Length;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    UCHAR DlAddressBuffer[DL_ADDRESS_LENGTH_MAXIMUM], *DlAddress = NULL;

    PIPV6_NEIGHBOR Neighbor;
    PIP_REQUEST_CONTROL_DATA Control = NULL;
    PIP_LOCAL_UNICAST_ADDRESS Source = NULL;
    KLOCK_QUEUE_HANDLE LockHandle, NeighborSetLockHandle;

    //
    // Validate the Router Solicitation.
    // By the time we get here, any IPv6 Authentication Header will have
    // already been checked, as will have the ICMPv6 checksum.  Still need
    // to check the source, IPv6 Hop Limit, and the ICMPv6 code and length.
    //

    if (((IPV6_HEADER*)Args->IP)->HopLimit != 255) {    
        //
        // Packet was forwarded by a router, therefore it cannot be from a
        // legitimate neighbor.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (Icmpv6->Header.Code != 0) {
        //
        // Bogus/corrupted Router Solicitation message.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Skip over the Router Solicitation header, ignoring the reserved field.
    //
    ParsedLength = sizeof(ND_ROUTER_SOLICIT_HEADER);
    NetioAdvanceNetBuffer(NetBuffer, ParsedLength);

    //
    // Get the Source Link Layer Address (if present).  Some interfaces do
    // not use SLLA and TLLA options.  For example, see RFC 2893 section 3.8.
    //
    // Note that if there are multiple options for some bogus reason,
    // we use the last one.  We sanity-check all the options.
    //
    while (Ipv6pParseTlvOption(NetBuffer, &Type, &Length)) {
        if ((Type == ND_OPT_SOURCE_LINKADDR) &&
            Interface->FlCharacteristics->DiscoversNeighbors &&
            !Interface->FlCharacteristics->UseStaticMapping) {

            if (Length != (sizeof(ND_OPTION_HDR) + DlAddressLength)) {
                //
                // Invalid option format.  Drop the packet.
                //
                break;
            }

            NetioAdvanceNetBuffer(NetBuffer, sizeof(ND_OPTION_HDR));
            ParsedLength += sizeof(ND_OPTION_HDR);
            Length -= sizeof(ND_OPTION_HDR);

            DlAddress =
                NetioGetDataBuffer(NetBuffer, Length, DlAddressBuffer, 1, 0);
        }

        NetioAdvanceNetBuffer(NetBuffer, Length);
        ParsedLength += Length;
    }
    
    //
    // We have parsed all we could, so now retreat.
    // Fail if we didn't successfully parse the entire packet.
    //
    NetioRetreatNetBuffer(NetBuffer, ParsedLength, 0);
    if (NetBuffer->DataLength != ParsedLength) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Validate Source.
    //
    if (IN6_IS_ADDR_UNSPECIFIED(RemoteAddress)) {
        //
        // No Source Link Layer Address option should be present.  Multicast
        // support is required as the Router Advertisement cannot be unicast.
        //
        if ((DlAddress != NULL) ||
            !Interface->FlCharacteristics->Multicasts) {
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            return;
        }
    }    


    //
    // We've received and parsed a valid Router Solicitation.
    //
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    
    //
    // Ignore the solicitation unless this is an advertising interface.
    //
    if (!Interface->Advertise) {
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
        Args->NetBufferList->Status = STATUS_SUCCESS;
        return;
    }

    //
    // Only bother with this if Source Link Layer Address is present;
    // if it's not, IppUpdateNeighbor won't do anything.
    //
    if (!IN6_IS_ADDR_UNSPECIFIED(RemoteAddress) && (DlAddress != NULL)) {
        RtlAcquireWriteLockAtDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);
        //
        // Create/Update the Neighbor for the source of this solicitation.
        //
        Neighbor = (PIPV6_NEIGHBOR)
            IppFindOrCreateNeighborUnderLock(
                Interface, 
                Args->SourceSubInterface,
                (CONST UCHAR *) RemoteAddress,
                NlatUnicast);
        if (Neighbor != NULL) {
            //
            // Update the Neighbor for the source of this solicitation.
            //
            // REVIEW: We deviate from the specification here.  It says that if
            // you receive a Router Solicitation from a Source, then you MUST
            // set the IsRouter flag for that Source to FALSE.  However,
            // consider a node that is forwarding, but not advertising.  Such a
            // node might send a Router Solicitation but IsRouter should be
            // TRUE for that node.
            //
            Control =
                IppUpdateNeighbor(
                    (PIP_NEIGHBOR) Neighbor,
                    DlAddress,
                    Interface->FlModule->Npi.Dispatch->
                    GetLinkLayerSourceRoute(
                        Interface->FlContext,
                        Args->NetBufferList),
                    FALSE,
                    FALSE,
                    FALSE);
            IppDereferenceNeighbor((PIP_NEIGHBOR) Neighbor);
        }

        RtlReleaseWriteLockFromDpcLevel(
            &Interface->NeighborSetLock, &NeighborSetLockHandle);
    }

    if (Interface->FlCharacteristics->Multicasts) {
        //
        // Send a Router Advertisement very soon.  The randomization in
        // Ipv6pTimeout initialization provides the randomization required when
        // sending a Router Advertisement in response to a Router Solicitation.
        //
        
        //
        // If MAX_RA_DELAY_TIME is not 1, then a RandomNumber should be used
        // generate the number of ticks.
        //
        C_ASSERT(MAX_RA_DELAY_TIME == 1);
        ASSERT(Interface->RouterDiscoveryTimer != 0);


        Interface->RouterDiscoveryTimer = 1;
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    } else {
        //
        // On non-multicast interfaces, such as the ISATAP interface,
        // immediately unicast the reply.
        //
        ASSERT(!IN6_IS_ADDR_UNSPECIFIED(RemoteAddress));

        //
        // Determine the source address to use for the RA.
        //
        if ((NL_ADDRESS_TYPE(LocalAddress) == NlatUnicast) &&
            ((NL_ADDRESS_SCOPE_ID(LocalAddress)).Level == ScopeLevelLink)) {
            //
            // The Router Solicitation was received on a link-local unicast
            // address, so use that address.  It would have been validated.
            //
            Source = (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress;
        } else {
            //
            // Try the interface's link-local address.
            //
            Source = IppFindLinkLocalUnicastAddress(Interface);
        }
        
        RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

        if (Source != NULL) {
            Ipv6pSendRouterAdvertisementOnSubInterface(
                Args->SourceSubInterface, 
                Source, 
                RemoteAddress);
            if (Source != (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress) {
                IppDereferenceLocalUnicastAddress(Source);
            }
        }
    }

    Args->NetBufferList->Status = STATUS_SUCCESS;

    if (Control != NULL) {
        IppFragmentPackets(&Ipv6Global, Control);
    }
}


VOID
Ipv6pHandleRedirect(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    )
/*++

Routine Description:

    Validate and process an IPv6 Redirect message.

Arguments:

    Icmpv6 - Supplies the parsed ICMPv6 header.


    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv6 Redirect packet,
        with the packet offset at the start of the redirect header.

    Interface - Supplies the interface over which the packet was received.

    RemoteAddress - Supplies the source address of the packet.
    
    LocalAddressEntry - Supplies the destination address of the packet.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    PIP_INTERFACE Interface = Args->DestLocalAddress->Interface;
    CONST NLC_RECEIVE_DATAGRAM *ReceiveDatagram = &Args->NlcReceiveDatagram;

    USHORT ParsedLength;
    ND_REDIRECT_HEADER RedirectBuffer, *Redirect;    
    CONST IN6_ADDR *Target, *Destination;    
    UCHAR Type;
    USHORT Length;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    UCHAR DlAddressBuffer[DL_ADDRESS_LENGTH_MAXIMUM], *DlAddress = NULL;
    
    PIP_NEIGHBOR Neighbor;
    PIP_REQUEST_CONTROL_DATA Control;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // Ignore the redirect if redirects have been disabled or this is a
    // forwarding interface. 
    //
    if (!Ipv6Global.EnableIcmpRedirects || Interface->Forward) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Validate the Redirect.
    // By the time we get here, any IPv6 Authentication Header will have
    // already been checked, as will have the ICMPv6 checksum.  Still need
    // to check the IPv6 Hop Limit, and the ICMPv6 code and length.
    //

    if (((IPV6_HEADER*)Args->IP)->HopLimit != 255) {
        //
        // Packet was forwarded by a router, therefore it cannot be from a
        // legitimate neighbor.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (Icmpv6->Header.Code != 0) {
        //
        // Bogus/corrupted Redirect message.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Check that the source address is a link-local address.  We need a
    // link-local source address to identify the router that sent the redirect.
    //    
    if (Ipv6AddressScope(ReceiveDatagram->RemoteAddress) != ScopeLevelLink) {
        //
        // Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    //
    // Get the Redirect header.
    //    
    if (NetBuffer->DataLength < sizeof(ND_REDIRECT_HEADER)) {
        //
        // Insufficient data buffer for a minimal Redirect.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    Redirect =
        NetioGetDataBuffer(
            NetBuffer, 
            sizeof(ND_REDIRECT_HEADER),
            &RedirectBuffer, 
            __builtin_alignof(ND_REDIRECT_HEADER),
            0);
    
    //
    // Pick up the target and destination addresses.
    //
    Target = &(Redirect->nd_rd_target);
    Destination = &(Redirect->nd_rd_dst);
    
    //
    // Check that the destination address is not a multicast address.
    //
    if (IN6_IS_ADDR_MULTICAST(Destination)) {
        //
        // Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // Check that either the target address is link-local (redirecting to a
    // router) or the target and the destination are the same (redirecting to
    // an on-link destination).
    //
    if (!IN6_IS_ADDR_LINKLOCAL(Target) &&
        !IN6_ADDR_EQUAL(Target, Destination)) {
        //
        // Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }    

    ParsedLength = sizeof(ND_REDIRECT_HEADER);
    NetioAdvanceNetBuffer(NetBuffer, ParsedLength);

    
    //
    // Get the Target Link Layer Address (if present).  Some interfaces do
    // not use SLLA and TLLA options.  For example, see RFC 2893 section 3.8.
    //
    // Note that if there are multiple options for some bogus reason,
    // we use the last one.  We sanity-check all the options.
    //
    while (Ipv6pParseTlvOption(NetBuffer, &Type, &Length)) {
        if ((Type == ND_OPT_TARGET_LINKADDR) &&
            Interface->FlCharacteristics->DiscoversNeighbors &&
            !Interface->FlCharacteristics->UseStaticMapping) {
            if (Length != (sizeof(ND_OPTION_HDR) + DlAddressLength)) {
                //
                // Invalid option format.  Drop the packet.
                //
                break;
            }

            NetioAdvanceNetBuffer(NetBuffer, sizeof(ND_OPTION_HDR));
            ParsedLength += sizeof(ND_OPTION_HDR);
            Length -= sizeof(ND_OPTION_HDR);

            DlAddress =
                NetioGetDataBuffer(NetBuffer, Length, DlAddressBuffer, 1, 0);
        }

        NetioAdvanceNetBuffer(NetBuffer, Length);
        ParsedLength += Length;
    }


    //
    // We have parsed all we could, so now retreat.
    // Fail if we didn't successfully parse the entire packet.
    //
    NetioRetreatNetBuffer(NetBuffer, ParsedLength, 0);
    if (NetBuffer->DataLength != ParsedLength) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    //
    // We have a valid redirect message (except for checking that the source of
    // the redirect is the current first-hop neighbor for the destination -
    // IppRedirectPath does that).  If IppRedirectPath doesn't invalidate the
    // redirect, then we update the neighbor cache.
    //
    Neighbor =
        IppRedirectPath(
            Args->SourceSubInterface,
            Args->DestLocalAddress,
            (CONST UCHAR *) Destination,
            (CONST UCHAR *) ReceiveDatagram->RemoteAddress,
            (CONST UCHAR *) Target);
    if (Neighbor != NULL) {
        //
        // Update the Neighbor Cache Entry for the target.  The target is a
        // router if the target and destination addresses are not identical.
        //
        RtlAcquireWriteLock(&Interface->NeighborSetLock, &LockHandle);

        if (!IN6_ADDR_EQUAL(Target, Destination)) {
            Neighbor->IsRouter = TRUE;
        }
        
        Control =
            IppUpdateNeighbor(
                Neighbor,
                DlAddress,
                &sourceroute_unspecified,
                FALSE,
                TRUE,
                FALSE);

	 RtlReleaseWriteLock(&Interface->NeighborSetLock, &LockHandle);

        if (Control != NULL) {
            IppFragmentPackets(&Ipv6Global, Control);
        }
        
        IppDereferenceNeighbor(Neighbor);

        Args->NetBufferList->Status = STATUS_SUCCESS;
    } else {
        Args->NetBufferList->Status = STATUS_INSUFFICIENT_RESOURCES;
    }
}
    

BOOLEAN
Ipv6pRouterSolicitationTimeout(
    IN PIP_INTERFACE Interface,
    OUT IN6_ADDR *Destination,
    OUT PIP_LOCAL_UNICAST_ADDRESS *Source
    )
/*++

Routine Description:

    Process the interface's Router Solicitation timeout.
    
Arguments:

    Interface - Supplies the interface whose Router Solicitation timer fired.

    Destination - Returns the destination of the Router Solicitation.

    Source - Returns the source address to use for the Router Solicitation,
        if one should be sent.  Otherwise returns NULL.

Return Value:

    TRUE if a Router Solicitation should be sent, FALSE o/w.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    BOOLEAN SendRouterSolicitation = FALSE;
    PIP_ROUTER_DISCOVERY_TIMER Timer = NULL;
    PLIST_ENTRY Current;
    PIPV6_POTENTIAL_ROUTER PotentialRouter = NULL;
    
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));

    *Source = NULL;

    if (!Interface->FlCharacteristics->Multicasts) {
        for (Current = Interface->PotentialRouterList.Flink;
             Current != &Interface->PotentialRouterList;
             Current = Current->Flink) {
            PotentialRouter = (PIPV6_POTENTIAL_ROUTER) 
                CONTAINING_RECORD(Current, IPV6_POTENTIAL_ROUTER, Link);

            //
            // Even for non-multicast interfaces, it is possible that the
            // router discovery timer is not armed if all subinterfaces
            // on the interface have been deleted thus stopping router
            // discovery.
            //
            if (PotentialRouter->RouterDiscoveryTimer == 0) {
                ASSERT(IsListEmpty(&Interface->SubInterfaceSet));
                return FALSE;
            }
            
            if (--PotentialRouter->RouterDiscoveryTimer == 0) {
                //
                // We have found a potential router whose timer has fired.
                // Break and process this router. 
                // $$REVIEW: We process at most one potential router every
                // tick.  While this spreads out the router solicitations, it
                // can take a long time to get the router state if there are a
                // large number of potential routers. 
                //
                Timer = IP_GET_ROUTER_DISCOVERY_TIMER(PotentialRouter);
                *Destination = PotentialRouter->Address;
                break;
            }
        }
        if (Timer == NULL) {
            return FALSE;
        }
    } else {
        Timer = IP_GET_ROUTER_DISCOVERY_TIMER(Interface);
        *Destination = in6addr_allroutersonlink;
        //
        // Ensure we have a running timer.
        //
        if (Timer->RouterDiscoveryTimer == 0) {
            return FALSE;
        }
        
        //
        // Timer is running.  Decrement and check for expiration.
        //
        if (--Timer->RouterDiscoveryTimer != 0) {
            return FALSE;
        }
    }
    
    if (Timer->RouterDiscoveryCount != 0) {
        //
        // Re-arm the timer and generate a Router Solicitation.
        //
        Timer->RouterDiscoveryTimer = RTR_SOLICITATION_INTERVAL;
        Timer->RouterDiscoveryCount--;
        SendRouterSolicitation = TRUE;
    } else {
        //
        // If we are still in the reconnecting state, meaning we have not
        // received an Router Advertisement since reconnecting to the link,
        // remove stale auto-configured state.
        //
        if (Interface->MediaReconnected) {
            Interface->MediaReconnected = FALSE;
            
            //
            // Remove auto-configured address lifetimes.
            //
            Ipv6pResetAutoConfiguredAddresses(Interface, 0);
            
            //
            // Similarly, remove auto-configured route lifetimes.
            //
            Ipv6pResetAutoConfiguredRoutes(Interface, 0);
            
            //
            // Remove parameters that are learned from Router Advertisements.
            //
            Ipv6pResetAutoConfiguredParameters(Interface);
        }

        //
        // On non-multicast interfaces, such as the ISATAP interface,
        // we'll never get unsolicited Router Advertisement's.
        // Hence, we solicit periodically (but infrequently).
        //
        if (!(Interface->FlCharacteristics->Multicasts)) {
            Timer->RouterDiscoveryTimer = SLOW_RTR_SOLICITATION_INTERVAL;
            Timer->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
            SendRouterSolicitation = TRUE;
        }
    }

    if (SendRouterSolicitation) {
        *Source = IppFindLinkLocalUnicastAddress(Interface);
    }

    return SendRouterSolicitation;
}

VOID
Ipv6pRouterDiscoveryTimeout(
    IN PIP_INTERFACE Interface,
    IN BOOLEAN ForceRouterAdvertisement
    )
/*++

Routine Description:

    Process the interface's router discovery timeout.
    Called from Ipv6pInterfaceSetTimeout.
    
Arguments:

    Interface - Supplies the interface whose router discovery timer fired.

    ForceRouterAdvertisement - Supplies TRUE to indicate that a state change
        requires that a Router Advertisement be sent on the interface.
        
Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    BOOLEAN SendRouterSolicitation = FALSE, SendRouterAdvertisement = FALSE;
    PIP_LOCAL_UNICAST_ADDRESS Source = NULL;
    IN6_ADDR Destination;
    KLOCK_QUEUE_HANDLE LockHandle;

    DISPATCH_CODE();
    
    RtlAcquireWriteLockAtDpcLevel(&(Interface->Lock), &LockHandle);
    if (Interface->Advertise) {
        SendRouterAdvertisement =
            IppRouterAdvertisementTimeout(
                ForceRouterAdvertisement, 
                Interface, 
                (PIP_LOCAL_UNICAST_ADDRESS *) &Source);
    } else {
        SendRouterSolicitation =
            Ipv6pRouterSolicitationTimeout(
                Interface, 
                &Destination,
                &Source);
    }    
    RtlReleaseWriteLockFromDpcLevel(&(Interface->Lock), &LockHandle);    

    if (SendRouterAdvertisement) {
        Ipv6pSendRouterAdvertisementOnAllSubInterfaces(
            Interface, Source, &in6addr_allnodesonlink);
    } else if (SendRouterSolicitation) {
        Ipv6pSendRouterSolicitationOnAllSubInterfaces(
            Interface, &Destination, Source);
    }

    if (Source != NULL) {
        IppDereferenceLocalUnicastAddress(Source);
    }
}


NTSTATUS
Ipv6pStartAdvertising(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is not currently advertising, makes it start advertising.

    Compare InterfaceStartAdvertising in the XP IPv6 stack.
    
Arguments:

    Interface - Supplies the interface to start advertising on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    NTSTATUS Status;
    PIP_LOCAL_MULTICAST_ADDRESS GroupAddress;
    
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));
    ASSERT(Interface->UseRouterDiscovery);

    if (Interface->AdvertisingEnabled) {
        return STATUS_SUCCESS;
    }

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Starting router advertisements on interface %u\n", 
               Interface->Index);
    
    //
    // Join the all routers on link multicast group.  This may return 
    // STATUS_PENDING, but we'll keep our reference anyway.   
    // REVIEW: This means we currently ignore the failure if it's 
    // asynchronous, but fail to start advertising if it's synchronous.
    //
    Status =
        IppFindOrCreateLocalMulticastAddressUnderLock(
            (PUCHAR) &in6addr_allroutersonlink,
            Interface,
            NULL,
            &GroupAddress);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    //
    // A non-advertising interface is now advertising.
    //
    Interface->Advertise = TRUE;
    Interface->AdvertisingEnabled = TRUE;
    
    //
    // The reconnecting state is not useful for advertising interfaces
    // because the interface will not receive Router Advertisements.
    //
    Interface->MediaReconnected = FALSE;

    //
    // Remove addresses & routes that were auto-configured from Router
    // Advertisements. Advertising interfaces must be manually configured.
    // Better to remove it now than let it time-out at some random time.
    //
    Ipv6pResetAutoConfiguredAddresses(Interface, 0);
    Ipv6pResetAutoConfiguredRoutes(Interface, 0);
    Ipv6pResetAutoConfiguredParameters(Interface);

    //
    // Start sending Router Advertisements if the interface supports multicast.
    // Send the first one quickly.  We simply call IppStartRouterDiscovery
    // which looks at the advertise flag and makes the correct changes. 
    //
    // REVIEW: we should probably ensure that the group join above has 
    // completed before sending the RA.  However, we'll retransmit anyway
    // so it's not fatal even if we try to send the first one before we're
    // ready to receive a reply.
    //
    IppStartRouterDiscovery(Interface);

    return STATUS_SUCCESS;
}


VOID
Ipv6pStopAdvertising(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:

    If the interface is currently advertising, makes it stop advertising.
    
Arguments:

    Interface - Supplies the interface to stop advertising on.
    
Return Value:

    None.
    
Caller LOCK: Interface (Exclusive).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/    
{
    ASSERT_WRITE_LOCK_HELD(&(Interface->Lock));
    ASSERT(Interface->UseRouterDiscovery);

    if (!Interface->AdvertisingEnabled) {
        return;
    }

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Stopping router advertisements on interface %u\n", 
               Interface->Index);
    
    //
    // Leave the all routers on link multicast group.
    //
    IppFindAndDereferenceMulticastGroup(
        Interface, (PUCHAR) &in6addr_allroutersonlink);

    //
    // Stop sending Router Advertisements.
    //
    Interface->Advertise = FALSE;
    Interface->AdvertisingEnabled = FALSE;
    
    //
    // Remove addresses that were auto-configured from our own Router
    // Advertisements.  We will pick up new address lifetimes from other
    // router's Advertisements.  If some other router is not advertising the
    // prefixes that this router was advertising, better to remove the
    // addresses now than let them time-out at some random time.
    //
    Ipv6pResetAutoConfiguredAddresses(Interface, 0);

    //
    // There shouldn't be any auto-configured routes,
    // but Ipv6pResetAutoConfiguredRoutes also handles site prefixes.
    //
    Ipv6pResetAutoConfiguredRoutes(Interface, 0);

    //
    // Restore interface parameters.
    //
    Ipv6pResetAutoConfiguredParameters(Interface);

    //
    // Send Router Solicitations again.  Send the first one quickly.  We simply
    // call IppStartRouterDiscovery which looks at the advertise flag and makes
    // the correct changes.
    //
    IppStartRouterDiscovery(Interface);
}


PIPV6_POTENTIAL_ROUTER
Ipv6pFindPotentialRouterUnderLock(
    IN PIP_INTERFACE Interface, 
    IN CONST IN6_ADDR *RouterAddress
    )
/*++

Routine Description:

    This routine finds a potential router entry with a given address on a given
    interface. 
    
Arguments:

    Interface - Supplies the interface. 

    RouterAddress - Supplies the router address to search for.

Return Value:

    Returns the potential router entry, NULL when none is found.

Caller LOCK:

    Caller holds the interface read/write lock. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PLIST_ENTRY Next, Head = &Interface->PotentialRouterList;
    PIPV6_POTENTIAL_ROUTER PotentialRouter;

    for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
        PotentialRouter = (PIPV6_POTENTIAL_ROUTER) 
            CONTAINING_RECORD(Next, IPV6_POTENTIAL_ROUTER, Link);
        if (IN6_ADDR_EQUAL(&PotentialRouter->Address, RouterAddress)) {
            return PotentialRouter;
        }
    }
    
    return NULL;
}

NTSTATUS
Ipv6pAddPotentialRouter(
    IN PIP_INTERFACE Interface,
    IN CONST IN6_ADDR *RouterAddress
    )
/*++

Routine Description:

    This routine adds a potential router to the list of potential routers on an
    interface. 
    
Arguments:

    Interface - Supplies the interface. 

    RouterAddress - Supplies the router address.

Return Value:

    STATUS_SUCCESS when the potential router is added
    successfully. STATUS_INSUFFICIENT_RESOURCES if memory allocation
    fails. STATUS_DUPLICATE_OBJECTID if the potential router is already
    present. 

Caller LOCK:
   
    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE LockHandle;
    PIPV6_POTENTIAL_ROUTER PotentialRouter;
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);

    PotentialRouter =
        Ipv6pFindPotentialRouterUnderLock(Interface, RouterAddress);
    if (PotentialRouter != NULL) {
        Status = STATUS_DUPLICATE_OBJECTID;
        goto Done;
    }
    
    PotentialRouter =
        ExAllocatePoolWithTag(
            NonPagedPool, sizeof(*PotentialRouter), IpUnicastRoutePoolTag);
    if (PotentialRouter == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }
    
    RtlCopyMemory(&PotentialRouter->Address, RouterAddress, sizeof(IN6_ADDR));
    PotentialRouter->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
    PotentialRouter->RouterDiscoveryTimer = 1;
    InsertTailList(&Interface->PotentialRouterList, &PotentialRouter->Link);
        
Done:
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    return Status;
}


NTSTATUS
Ipv6pRemovePotentialRouter(
    IN PIP_INTERFACE Interface,
    IN CONST IN6_ADDR *RouterAddress
    )
/*++

Routine Description:

    Remove one or more potential routers from the list of potential routers
    on an interface. 
    
Arguments:

    Interface - Supplies the interface. 

    RouterAddress - Supplies the router address or NULL if all.

Return Value:

    STATUS_SUCCESS or STATUS_NOT_FOUND if the router does not exist in the
    list. 

Caller LOCK:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status = STATUS_NOT_FOUND;
    KLOCK_QUEUE_HANDLE LockHandle;
    PLIST_ENTRY Next, Head = &Interface->PotentialRouterList;
    PIPV6_POTENTIAL_ROUTER PotentialRouter;
    
    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    
    for (Next = Head->Flink; Next != Head; ) {
        PotentialRouter = (PIPV6_POTENTIAL_ROUTER) 
            CONTAINING_RECORD(Next, IPV6_POTENTIAL_ROUTER, Link);

        Next = Next->Flink;
        
        if ((RouterAddress == NULL) ||
            IN6_ADDR_EQUAL(&PotentialRouter->Address, RouterAddress)) {

            RemoveEntryList(&PotentialRouter->Link);
            ExFreePool(PotentialRouter);

            Status = STATUS_SUCCESS;
        }
    }
    
    if (!NT_SUCCESS(Status)) {
        goto Done;
    }

    //
    // We have just removed a router from the list of potential routers.  Some
    // or all of auto configured state might be stale as a result.  So, we give
    // all auto configured state a short lifetime and start router discovery on
    // all routers so that we refresh the state. 
    //
    Ipv6pResetAutoConfiguredAddresses(
        Interface,
        2 * MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS);
    
    Ipv6pResetAutoConfiguredRoutes(
        Interface,
        2 * MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS);
    
    Ipv6pResetAutoConfiguredParameters(Interface);

    IppStartRouterDiscovery(Interface);
    
Done:
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);
    return Status;
}


NTSTATUS
Ipv6pGetNextPotentialRouter(
    IN PIP_INTERFACE Interface,
    IN CONST IN6_ADDR *RouterAddress OPTIONAL,
    OUT IN6_ADDR *NextAddress
    )
/*++

Routine Description:

    Find the next entry for a potential router that is just higher than the
    specified value in the list of potential routers.

Arguments:

    Interface - Supplies a pointer to an interface.

    RouterAddress - Supplies an address value for the potential router.

    NextAddress - Returns the next address on success. 

Return Value:

    STATUS_SUCCESS
    STATUS_NO_MORE_ENTRIES

Locks:

    Locks interface for reading.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    KIRQL OldIrql;
    PLIST_ENTRY Current;
    PIPV6_POTENTIAL_ROUTER PotentialRouter, Found = NULL;

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);
    for (Current = Interface->PotentialRouterList.Flink; 
         Current != &Interface->PotentialRouterList;
         Current = Current->Flink) {
        PotentialRouter = (PIPV6_POTENTIAL_ROUTER) 
            CONTAINING_RECORD(Current, IPV6_POTENTIAL_ROUTER, Link);
        if ((RouterAddress != NULL) &&
            memcmp(
                &PotentialRouter->Address, 
                RouterAddress, 
                sizeof(IN6_ADDR)) <= 0) {
            continue;
        }
        if ((Found == NULL) ||
            (memcmp(
                &PotentialRouter->Address, 
                &Found->Address, 
                sizeof(IN6_ADDR)) < 0)) {
            //
            // We have a (more) appropriate match.
            //
            Found = PotentialRouter;
        }
    }
        
    if (Found != NULL) {
        *NextAddress = Found->Address;
    } else {
        Status = STATUS_NO_MORE_ENTRIES;
    }
    
    RtlReleaseReadLock(&Interface->Lock, OldIrql);
    
    return Status;
}

NTSTATUS
NTAPI
Ipv6GetAllPotentialRouters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a given potential router.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PIPV6_POTENTIAL_ROUTER_KEY Key = (PIPV6_POTENTIAL_ROUTER_KEY)
        Args->KeyStructDesc.KeyStruct;
    NTSTATUS Status;
    KIRQL OldIrql;
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle,
                                         NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength == 
           sizeof(IPV6_POTENTIAL_ROUTER_KEY));

    switch (Args->Action) {
    case NsiGetExact:
        Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
        if (Interface == NULL) {
            return STATUS_NOT_FOUND;
        }
        RtlAcquireReadLock(&Interface->Lock, &OldIrql);
        if (Ipv6pFindPotentialRouterUnderLock(Interface, &Key->Address)) {
            Status = STATUS_SUCCESS;
        } else {
            Status = STATUS_NOT_FOUND;
        }
        IppDereferenceInterface(Interface);
        RtlReleaseReadLock(&Interface->Lock, OldIrql);
        break;

    case NsiGetFirst:
        RtlZeroMemory(Key, Args->KeyStructDesc.KeyStructLength);
        //
        // Fall through.
        //
    case NsiGetNext:
        Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
        if (Interface != NULL) {
            Status =
                Ipv6pGetNextPotentialRouter(
                    Interface, &Key->Address, &Key->Address);
            IppDereferenceInterface(Interface);
            if (NT_SUCCESS(Status)) {
                break;
            }
        }
        
        do {
            Interface = IppGetNextInterface(Protocol, &Key->InterfaceLuid);
            if (Interface == NULL) {
                return STATUS_NO_MORE_ENTRIES;
            }

            Key->InterfaceLuid = Interface->Luid;

            Status =
                Ipv6pGetNextPotentialRouter(
                    Interface, NULL, &Key->Address);
            IppDereferenceInterface(Interface);
        } while (!NT_SUCCESS(Status));
        break;
        
    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }
    
    return Status;
}


NTSTATUS
NTAPI
Ipv6SetAllPotentialRouters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function sets all public parameters of a given route.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIPV6_POTENTIAL_ROUTER_KEY Key =
        (PIPV6_POTENTIAL_ROUTER_KEY) Args->KeyStructDesc.KeyStruct;
    ULONG KeyLength = Args->KeyStructDesc.KeyStructLength;
    PIN6_ADDR Address;
    NSI_SET_ACTION Action;
    PIP_INTERFACE Interface;
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    //
    // Handle transaction case here.
    //
    if (Args->Transaction != NsiTransactionNone) {
        return STATUS_NOT_IMPLEMENTED;
    }
    
    Protocol = Client->Protocol;
    
    if (Args->Action == NsiSetReset) {
        switch (KeyLength) {
        case RTL_SIZEOF_THROUGH_FIELD(IPV6_POTENTIAL_ROUTER_KEY,Address):
            //
            // Delete single potential router.
            //
            Address = &Key->Address;
            break;

        case RTL_SIZEOF_THROUGH_FIELD(IPV6_POTENTIAL_ROUTER_KEY,InterfaceLuid):
            //
            // Delete all potential routers on a given interface.
            //
            Address = NULL;
            break;

        default:
            return STATUS_NOT_IMPLEMENTED;
        }

        Action = NsiSetDelete;
    } else {
        //
        // Guaranteed by the NSI since we register with this requirement.
        //
        ASSERT(KeyLength == sizeof(IPV6_POTENTIAL_ROUTER_KEY));

        Address = &Key->Address;

        Action = Args->Action;
    }
    
    Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
    if (Interface == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Potential routers are not valid for interfaces that support multicast
    // or are advertising.
    //
    if ((Interface->FlCharacteristics->Multicasts) || (Interface->Advertise)) {
        IppDereferenceInterface(Interface);
        return STATUS_INVALID_PARAMETER;
    }
    
    switch (Action) {
    case NsiSetCreateOnly:
        Status = Ipv6pAddPotentialRouter(Interface, Address);
        break;
        
    case NsiSetCreateOrSet:
        Status = Ipv6pAddPotentialRouter(Interface, Address);
        if (Status == STATUS_DUPLICATE_OBJECTID) {
            Status = STATUS_SUCCESS;
        }
        break;
        
    case NsiSetDelete:
        Status = Ipv6pRemovePotentialRouter(Interface, Address);
        break;
        
    case NsiSetDefault:
        break;
        
    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    IppDereferenceInterface(Interface);
    
    return Status;
}

