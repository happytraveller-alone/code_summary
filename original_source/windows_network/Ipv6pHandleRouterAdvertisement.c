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