void Ipv6pHandleRouterAdvertisement(const ICMPV6_MESSAGE *Icmpv6, const IP_REQUEST_CONTROL_DATA *Args) {
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    PIP_INTERFACE Interface = Args->DestLocalAddress->Interface;
    const NLC_RECEIVE_DATAGRAM *ReceiveDatagram = &Args->NlcReceiveDatagram;
    const IN6_ADDR *RemoteAddress = (PIN6_ADDR) ReceiveDatagram->RemoteAddress;
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

    if (((PIPV6_HEADER) Args->IP)->HopLimit != 255) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (Icmpv6->Header.Code != 0) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (Ipv6AddressScope((PUCHAR) RemoteAddress) != ScopeLevelLink) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (NetBuffer->DataLength < sizeof(ND_ROUTER_ADVERT_HEADER)) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    Advertisement = NetioGetDataBuffer(NetBuffer, sizeof(ND_ROUTER_ADVERT_HEADER), &AdvertisementBuffer, 1, 0);

    ParsedLength = sizeof(ND_ROUTER_ADVERT_HEADER);
    NetioAdvanceNetBuffer(NetBuffer, ParsedLength);

    Flags.Value = Advertisement->nd_ra_flags_reserved;

    RouterLifetime = RtlUshortByteSwap(Advertisement->nd_ra_router_lifetime);
    ReachableTime = RtlUlongByteSwap(Advertisement->nd_ra_reachable);

    while (Ipv6pParseTlvOption(NetBuffer, &Type, &Length)) {
        switch (Type) {
        case ND_OPT_SOURCE_LINKADDR:
            if (!Interface->FlCharacteristics->DiscoversNeighbors || Interface->FlCharacteristics->UseStaticMapping) break;

            if (Length != (sizeof(ND_OPTION_HDR) + DlAddressLength)) {
                Drop = TRUE;
                break;
            }

            NetioAdvanceNetBuffer(NetBuffer, sizeof(ND_OPTION_HDR));
            ParsedLength += sizeof(ND_OPTION_HDR);
            Length -= sizeof(ND_OPTION_HDR);

            DlAddress = NetioGetDataBuffer(NetBuffer, Length, DlAddressBuffer, 1, 0);
            break;

        case ND_OPT_MTU:
            ND_OPTION_MTU UNALIGNED OptionBufferMtu, *OptionMtu;
            if (Length != sizeof(ND_OPTION_MTU)) {
                Drop = TRUE;
                break;
            }

            OptionMtu = NetioGetDataBuffer(NetBuffer, Length, &OptionBufferMtu, 1, 0);
            Mtu = RtlUlongByteSwap(OptionMtu->nd_opt_mtu_mtu);
            break;

        case ND_OPT_PREFIX_INFORMATION:
            ND_OPTION_PREFIX_INFO UNALIGNED OptionBufferPrefix, *OptionPrefix;
            OptionPrefix = NetioGetDataBuffer(NetBuffer, Length, &OptionBufferPrefix, 1, 0);
            if ((Length != sizeof(ND_OPTION_PREFIX_INFO)) || (OptionPrefix->nd_opt_pi_prefix_len > RTL_BITS_OF(IN6_ADDR))) {
                Drop = TRUE;
            }
            break;

        case ND_OPT_ROUTE_INFO:
            ND_OPTION_ROUTE_INFO UNALIGNED OptionBufferRoute, *OptionRoute;
            OptionRoute = NetioGetDataBuffer(NetBuffer, Length, &OptionBufferRoute, 1, 0);
            if ((Length > sizeof(ND_OPTION_ROUTE_INFO)) || (OptionRoute->nd_opt_ri_prefix_len > RTL_BITS_OF(IN6_ADDR)) || ((OptionRoute->nd_opt_ri_prefix_len > 64) && (Length < 24)) || ((OptionRoute->nd_opt_ri_prefix_len > 0) && (Length < 16))) {
                Drop = TRUE;
            }
            break;
        }

        if (Drop) break;

        NetioAdvanceNetBuffer(NetBuffer, Length);
        ParsedLength += Length;
    }
    NetioRetreatNetBuffer(NetBuffer, ParsedLength, 0);
    if (NetBuffer->DataLength != ParsedLength) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    RtlAcquireWriteLock(&(Interface->Lock), &LockHandle);

    if ((Interface->Advertise) || (!Interface->UseRouterDiscovery)) {
        RtlReleaseWriteLock(&(Interface->Lock), &LockHandle);
        Args->NetBufferList->Status = STATUS_SUCCESS;
        return;
    }

    if (!Interface->FlCharacteristics->Multicasts) {
        PotentialRouter = Ipv6pFindPotentialRouterUnderLock(Interface, (const IN6_ADDR*) Args->SourceAddress.Address);
        if (PotentialRouter == NULL) {
            RtlReleaseWriteLock(&(Interface->Lock), &LockHandle);
            Args->NetBufferList->Status = STATUS_SUCCESS;
            return;
        }
        Timer = IP_GET_ROUTER_DISCOVERY_TIMER(PotentialRouter);
    } else {
        Timer = IP_GET_ROUTER_DISCOVERY_TIMER(Interface);
    }

    RtlAcquireWriteLockAtDpcLevel(&Interface->NeighborSetLock, &NeighborSetLockHandle);

    Neighbor = IppFindOrCreateNeighborUnderLock(Interface, Args->SourceSubInterface, (const UCHAR *) RemoteAddress, NlatUnicast);
    if (Neighbor != NULL) {
        Neighbor->IsRouter = TRUE;
        Control = IppUpdateNeighbor(Neighbor, DlAddress, Interface->FlModule->Npi.Dispatch->GetLinkLayerSourceRoute(Interface->FlContext, Args->NetBufferList), FALSE, TRUE, FALSE);
    }

    Ipv6pUpdateMtu(Args->SourceSubInterface, Mtu);

    RtlReleaseWriteLockFromDpcLevel(&Interface->NeighborSetLock, &NeighborSetLockHandle);

    IppUpdateInterfaceConfigurationFlags(Interface, Flags.ManagedAddressConfiguration, Flags.OtherStatefulConfiguration);

    if (Interface->MediaReconnected) {
        Interface->MediaReconnected = FALSE;
        Ipv6pResetAutoConfiguredAddresses(Interface, 2 * MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS);
        Ipv6pResetAutoConfiguredRoutes(Interface, 2 * MAX_RA_DELAY_TIME + MIN_DELAY_BETWEEN_RAS);
        Ipv6pResetAutoConfiguredParameters(Interface);
    }

    if ((RouterLifetime != 0) || !Interface->FlCharacteristics->Multicasts) {
        if (Timer->RouterDiscoveryCount < MAX_RTR_SOLICITATIONS) {
            Timer->RouterDiscoveryTimer = 0;
            Timer->RouterDiscoveryCount = 0;
        }
    }

    if ((ReachableTime != 0) && (ReachableTime != Interface->BaseReachableTime)) {
        Interface->BaseReachableTime = ReachableTime;
        Interface->ReachableTicks = IppNeighborReachableTicks(ReachableTime);
    }

    RtlReleaseWriteLock(&(Interface->Lock), &LockHandle);

    if (Control != NULL) {
        IppFragmentPackets(&Ipv6Global, Control);
    }

    if (Advertisement->nd_ra_curhoplimit != 0) {
        Interface->CurrentHopLimit = Advertisement->nd_ra_curhoplimit;
    }

    if (Advertisement->nd_ra_retransmit != 0) {
        Interface->RetransmitTicks = IppMillisecondsToTicks(RtlUlongByteSwap(Advertisement->nd_ra_retransmit));
    }

    MinLifetime = RouterLifetime = IppSecondsToTicks(RouterLifetime);

    RouteMetric = Ipv6pExtractRouteMetric(Flags.Preference);
    if (RouteMetric == RouteMetricInvalid) {
        RouteMetric = RouteMetricMedium;
    }

    IppUpdateAutoConfiguredRoute(Interface, (const UCHAR *) RemoteAddress, Neighbor, (const UCHAR *) &in6addr_any, 0, RouterLifetime, RouteMetric);

    ParsedLength = sizeof(ND_ROUTER_ADVERT_HEADER);
    NetioAdvanceNetBuffer(NetBuffer, ParsedLength);

    while (Ipv6pParseTlvOption(NetBuffer, &Type, &Length)) {
        switch (Type) {
            case ND_OPT_PREFIX_INFORMATION: {
                ND_OPTION_PREFIX_INFO UNALIGNED OptionBufferPrefix, *OptionPrefix;
                UINT8 PrefixLength;
                ULONG ValidLifetime, PreferredLifetime;
                IN6_ADDR Prefix;

                OptionPrefix = NetioGetDataBuffer(NetBuffer, Length, &OptionBufferPrefix, 1, 0);

                PrefixLength = OptionPrefix->nd_opt_pi_prefix_len;

                ValidLifetime = RtlUlongByteSwap(OptionPrefix->nd_opt_pi_valid_time);
                ValidLifetime = IppSecondsToTicks(ValidLifetime);
                PreferredLifetime = RtlUlongByteSwap(OptionPrefix->nd_opt_pi_preferred_time);
                PreferredLifetime = IppSecondsToTicks(PreferredLifetime);
                if (MinLifetime > PreferredLifetime) {
                    MinLifetime = PreferredLifetime;
                }
                CopyPrefix((PUCHAR) &Prefix, (const UCHAR *) &(OptionPrefix->nd_opt_pi_prefix), PrefixLength, sizeof(IN6_ADDR));

                if (IN6_IS_ADDR_LINKLOCAL(&Prefix) || IN6_IS_ADDR_MULTICAST(&Prefix)) {
                    break;
                }

                if (OptionPrefix->Flags.OnLink) {
                    IppUpdateAutoConfiguredRoute(Interface, NULL, NULL, (const UCHAR *) &Prefix, PrefixLength, ValidLifetime, RouteMetricOnLink);
                }

                if (OptionPrefix->Flags.Route) {
                    IppUpdateAutoConfiguredRoute(Interface, (const UCHAR *) RemoteAddress, Neighbor, (const UCHAR *) &Prefix, PrefixLength, ValidLifetime, RouteMetricMedium);
                }

                if (!IN6_IS_ADDR_SITELOCAL(&Prefix)) {
                    UCHAR SitePrefixLength;

                    if (OptionPrefix->Flags.SitePrefix) {
                        SitePrefixLength = OptionPrefix->nd_opt_pi_site_prefix_len;
                    } else if (OptionPrefix->Flags.Autonomous) {
                        SitePrefixLength = Interface->DefaultSitePrefixLength;
                    } else {
                        SitePrefixLength = 0;
                    }

                    if ((SitePrefixLength != 0) && (SitePrefixLength <= PrefixLength)) {
                        Ipv6pUpdateSitePrefix(Interface, &Prefix, SitePrefixLength, ValidLifetime);
                    }
                }

                if (OptionPrefix->Flags.Autonomous) {
                    if (PreferredLifetime > ValidLifetime) {
                        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, "IPNG: Error processing router advertisement: Preferred lifetime > Valid lifetime\n");
                    } else if ((PrefixLength + Interface->FlCharacteristics->IdentifierLength) != RTL_BITS_OF(IN6_ADDR)) {
                        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, "IPNG: Error processing router advertisement: PrefixLength (%d) + Identifier (%d) != 128 bits\n", PrefixLength, Interface->FlCharacteristics->IdentifierLength);
                    } else {
                        Ipv6pUpdateAutoConfiguredAddresses(Interface, &Prefix, PrefixLength, ValidLifetime, PreferredLifetime, FALSE);
                    }
                }
                break;
            }

            case ND_OPT_ROUTE_INFO: {
                ND_OPTION_ROUTE_INFO UNALIGNED OptionBufferRoute, *OptionRoute;
                ULONG RouteLifetime;

                OptionRoute = NetioGetDataBuffer(NetBuffer, Length, &OptionBufferRoute, 1, 0);

                RouteMetric = Ipv6pExtractRouteMetric(OptionRoute->Flags.Preference);
                if (RouteMetric == RouteMetricInvalid) {
                    break;
                }

                RouteLifetime = RtlUlongByteSwap(OptionRoute->nd_opt_ri_route_lifetime);
                RouteLifetime = IppSecondsToTicks(RouteLifetime);
                if (MinLifetime > RouteLifetime) {
                    MinLifetime = RouteLifetime;
                }

                IppUpdateAutoConfiguredRoute(Interface, (const UCHAR *) RemoteAddress, Neighbor, (const UCHAR *) AlignAddr(&OptionRoute->nd_opt_ri_prefix), OptionRoute->nd_opt_ri_prefix_len, RouteLifetime, RouteMetric);
                break;
            }
        }
        NetioAdvanceNetBuffer(NetBuffer, Length);
        ParsedLength += Length;
    }

    NetioRetreatNetBuffer(NetBuffer, ParsedLength, 0);
    if (NetBuffer->DataLength != ParsedLength) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    RtlAcquireWriteLock(&Interface->Lock, &LockHandle);
    if (!Interface->Advertise && !Interface->FlCharacteristics->Multicasts) {
        PotentialRouter = Ipv6pFindPotentialRouterUnderLock(Interface, (const IN6_ADDR*) Args->SourceAddress.Address);
        if ((PotentialRouter != NULL) && (PotentialRouter->RouterDiscoveryTimer == 0)) {
            PotentialRouter->RouterDiscoveryCount = MAX_RTR_SOLICITATIONS;
            PotentialRouter->RouterDiscoveryTimer = (MinLifetime < (SLOW_RTR_SOLICITATION_INTERVAL * 2)) ? SLOW_RTR_SOLICITATION_INTERVAL : MinLifetime / 2;
        }
    }
    RtlReleaseWriteLock(&Interface->Lock, &LockHandle);

    Args->NetBufferList->Status = STATUS_SUCCESS;
    if (Neighbor != NULL) {
        IppDereferenceNeighbor(Neighbor);
    }
}