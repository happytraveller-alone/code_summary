/*++

Copyright (c) Microsoft Corporation

Module Name:

    select.c

Abstract:

    This module implements source address selection and destination 
    address ordering for use by the IPv4 and IPv6 modules.

Author:

    Dave Thaler (dthaler) 28-May-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "subr.h"
#include <stdlib.h>

BOOLEAN
IppUpdateBestSourceAddress(
    IN CONST IP_LOCAL_UNICAST_ADDRESS *SourceAddress,
    IN OUT CONST IP_LOCAL_UNICAST_ADDRESS **BestSourceAddress,
    IN OUT ULONG *BestSourceLength,
    IN OUT ULONG *BestSourceLabel,
    IN CONST UCHAR *Destination,
    IN SCOPE_LEVEL DestinationScopeLevel,
    IN ULONG DestinationLabel,
    IN ULONG AddressBytes,
    IN PIP_INTERFACE OutgoingInterface,
    IN PIP_NEXT_HOP NextHop OPTIONAL
    )
/*++

Routine Description:

    Compares SourceAddress and BestSourceAddress for their
    desirability as the source address to the supplied destination.
    If SourceAddress is more desirable, it updates BestSourceAddress
    (as well as BestSourceLength and BestSourceLabel).
  
    For both SourceAddress and BestSourceAddress, the caller must hold either a
    reference on the address or a lock on its interface.  In the former case
    the address's attributes (such as its DAD state) may not be stable.    

Arguments:

    SourceAddress - Supplies the source address to compare.

    BestSourceAddress - Supplies the best source address thus far.
        Returns the new best source address.
        
    BestSourceLength - Supplies BestSourceAddress's common prefix length.
        Returns the new best source common prefix length.
        
    BestSourceLabel - Supplies BestSourceAddress's prefix label.
        Returns the new best source prefix label.

    Destination - Supplies the destination we're sending to.

    DestinationScopeLevel - Supplies the scope level of the destination.

    DestinationLabel - Supplies the destination prefix label.

    AddressBytes - Supplies the network layer address byte count.

    OutgoingInterface - Supplies the interface we're sending from.

    NextHop - Optionaly supplies the next hop address to which the packet is
        being routed to.
    
Return Value:

    Returns TRUE to indicate that the *best possible* source has been found,
    i.e. the destination address has matched a local address.

--*/
{
    NL_PREFIX_POLICY_RW Data;    
    ULONG SourceLabel, SourceLength;
    BOOLEAN BestPossible = FALSE;
    
    IppLookupPrefixPolicy(NL_ADDRESS(SourceAddress), AddressBytes, &Data);
    SourceLabel = Data.Label;
    
    SourceLength =
        CommonPrefixLength(
            Destination,
            NL_ADDRESS(SourceAddress), 
            AddressBytes);

    //
    // Do not select a SkipAsSource address.
    //
    if (SourceAddress->SkipAsSource) {
        return FALSE;
    }

    if (*BestSourceAddress == NULL) {
        //
        // We don't have a choice yet, so take what we can get.
        //
        BestPossible = (SourceLength == 8 * AddressBytes);
        
FoundAddress:
        *BestSourceAddress = SourceAddress;
        *BestSourceLength = SourceLength;
        *BestSourceLabel = SourceLabel;
        return BestPossible;
    }    

    if (SourceLength == 8 * AddressBytes) {
        //
        // Rule 1: Prefer same address.
        // No need to keep looking.
        //
        BestPossible = TRUE;
        goto FoundAddress;
    } else if (NL_ADDRESS_SCOPE_LEVEL(*BestSourceAddress) != 
               NL_ADDRESS_SCOPE_LEVEL(SourceAddress)) {
        //  
        // Rule 2: Prefer appropriate scope.
        // If one is bigger & one smaller than the destination,
        // we should use the address that is bigger.
        // If both are bigger than the destination,
        // we should use the address with smaller scope.
        // If both are smaller than the destination,
        // we should use the address with larger scope.
        //
        if (NL_ADDRESS_SCOPE_LEVEL(*BestSourceAddress) < 
            NL_ADDRESS_SCOPE_LEVEL(SourceAddress)) {
            
            if (ScopeLevel(NL_ADDRESS_SCOPE_ID(*BestSourceAddress)) < 
                DestinationScopeLevel) {
                goto FoundAddress;
                }
        } else {
            if (DestinationScopeLevel <= 
                ScopeLevel(NL_ADDRESS_SCOPE_ID(SourceAddress))) {
                goto FoundAddress;
            }
        }
    } else if ((*BestSourceAddress)->DadState != SourceAddress->DadState) {
        //
        // Rule 3: Avoid deprecated addresses.
        //
        if ((*BestSourceAddress)->DadState < SourceAddress->DadState) {
            goto FoundAddress;
        }
    }
    //
    // Rule 4: Prefer home addresses.
    // Not yet implemented, pending mobility support.
    //
    else if (((*BestSourceAddress)->Interface == OutgoingInterface) !=
             (SourceAddress->Interface == OutgoingInterface)) {
        //
        // Rule 5: Prefer outgoing interface.
        // One source address is assigned to the
        // outgoing interface, and the other isn't.
        // Choose the one assigned to the outgoing interface.
        //
        if (SourceAddress->Interface == OutgoingInterface) {
            goto FoundAddress;
        }
    } else if ((*BestSourceLabel == DestinationLabel) != 
             (SourceLabel == DestinationLabel)) {
        //
        // Rule 6: Prefer matching label.
        // One source address has a label matching
        // the destination, and the other doesn't.
        // Choose the one with the matching label.
        //
        if (SourceLabel == DestinationLabel) {
            goto FoundAddress;
        }
    } else if (((*BestSourceAddress)->AddressOrigin == ADDR_CONF_TEMPORARY) !=
               (SourceAddress->AddressOrigin == ADDR_CONF_TEMPORARY)) {
        //  
        // Rule 7: Prefer temporary addresses.
        //
        if (SourceAddress->AddressOrigin == ADDR_CONF_TEMPORARY) {
            goto FoundAddress;
        }
    } else if ((NextHop != NULL) && 
               IS_IPV4_PROTOCOL(NextHop->Interface->Compartment->Protocol) && 
               !IN4_UNALIGNED_ADDR_EQUAL(
                    (PIN_ADDR) Destination, 
                    (PIN_ADDR) IppAddressFromNextHop(NextHop))) {
        UCHAR* NextHopNlAddress = IppAddressFromNextHop(NextHop);    
        //
        // Rule 8: If NextHop is specified, and is IPv4 and not on-link, 
        // use the address whose prefix best matches the NextHop's.  This rule
        // is an addition to the rules from RFC 3484, and is required for IPv4 
        // multinetting.
        //

        ULONG BestNextHopMatchLength, NextHopMatchLength;
        
        BestNextHopMatchLength =
            CommonPrefixLength(
                NextHopNlAddress,
                NL_ADDRESS(*BestSourceAddress), 
                AddressBytes);        

        NextHopMatchLength =
            CommonPrefixLength(
                NextHopNlAddress,
                NL_ADDRESS(SourceAddress), 
                AddressBytes);
        if (NextHopMatchLength > BestNextHopMatchLength) {
            goto FoundAddress;
        }            
    } else {
        //
        // Rule 9: Use longest matching prefix.
        //
        if (*BestSourceLength < SourceLength) {

            goto FoundAddress;
        }                
    }
    
    return BestPossible;
}


PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnInterfaceUnderLock(
    IN PIP_INTERFACE Interface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop OPTIONAL
    )
/*++

Routine Description:
    
    Given a constraining interface and a destination address,
    finds the best source address to use.
    
Arguments:

    Interface - Supplies the constraining interface.

    Destination - Supplies the destination we're sending to.

    NextHop - Optionaly supplies the next hop address to which the packet is
        being routed to.

Return Value:

    Returns a referenced pointer to the best source address, or NULL.

Caller LOCK: Interface (shared).
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    PIP_PROTOCOL Protocol = Interface->Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;    

    PVOID Link;
    IP_ADDRESS_ENUMERATION_CONTEXT Context;
    NL_PREFIX_POLICY_RW Data;
    
    SCOPE_LEVEL DestinationScopeLevel;
    ULONG DestinationLabel;    
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress, BestSourceAddress = NULL;
    ULONG BestSourceLabel = 0, BestSourceLength = 0;
            

    ASSERT_ANY_LOCK_HELD(&Interface->Lock);

    //
    // Evaluate destination characteristics.
    //
    DestinationScopeLevel = Protocol->AddressScope(Destination);

    IppLookupPrefixPolicy(Destination, AddressBytes, &Data);
    DestinationLabel = Data.Label;
    
    //
    // Enumerate addresses, keeping track of the best so far.
    //
    IppInitializeAddressEnumerationContext(&Context);
    for (;;) {
        Link =
            IppEnumerateNlaSetEntry(
                &Interface->LocalUnicastAddressSet,
                (PADAPTIVE_TABLE_ENUMERATION_CONTEXT) &Context);
        if (Link == NULL) {
            break;
        }

        SourceAddress = (PIP_LOCAL_UNICAST_ADDRESS)
            CONTAINING_RECORD(Link, IP_LOCAL_UNICAST_ADDRESS, Link);

        //
        // Only consider valid (preferred & deprecated) unicast addresses.
        //
        if (IsLocalUnicastAddressValid(SourceAddress)) {
            if (IppUpdateBestSourceAddress(
                    SourceAddress,
                    &BestSourceAddress,
                    &BestSourceLength,
                    &BestSourceLabel,
                    Destination,
                    DestinationScopeLevel,
                    DestinationLabel,
                    AddressBytes,
                    Interface,
                    NextHop)) {
                break;
            }
        }
    }
    
    if (BestSourceAddress != NULL) {
        IppReferenceLocalAddress((PIP_LOCAL_ADDRESS) BestSourceAddress);
    }

    return BestSourceAddress;
}


PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnInterfaceAtDpc(
    IN IP_INTERFACE *Interface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop OPTIONAL
    )
{
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress;

    DISPATCH_CODE();
    
    RtlAcquireReadLockAtDpcLevel(&Interface->Lock);

    SourceAddress =
        IppFindBestSourceAddressOnInterfaceUnderLock(
            Interface,
            Destination,
            NextHop);

    RtlReleaseReadLockFromDpcLevel(&Interface->Lock);

    return SourceAddress;
}


PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnInterface(
    IN IP_INTERFACE *Interface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop OPTIONAL
    )
{
    KIRQL OldIrql;
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress;

    RtlAcquireReadLock(&Interface->Lock, &OldIrql);

    SourceAddress =
        IppFindBestSourceAddressOnInterfaceUnderLock(
            Interface,
            Destination,
            NextHop);

    RtlReleaseReadLock(&Interface->Lock, OldIrql);

    return SourceAddress;
}


PIP_LOCAL_UNICAST_ADDRESS
IppFindBestSourceAddressOnHost(
    IN IP_INTERFACE *OutgoingInterface,
    IN CONST UCHAR *Destination,
    IN PIP_NEXT_HOP NextHop OPTIONAL
    )
/*++

Routine Description:
    
    Given an outgoing interface and a destination address,
    finds the best source address to use from all weak-host interfaces.
    
Arguments:

    OutgoingInterface - Supplies the interface we're sending from.

    Destination - Supplies the destination we're sending to.

    NextHop - Optionaly supplies the next hop address to which the packet is
        being routed to.
        
Return Value:

    Returns a referenced pointer to the best source address, or NULL.

Caller IRQL: DISPATCH_LEVEL.

--*/
{
    PIP_COMPARTMENT Compartment = OutgoingInterface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG AddressBytes = Protocol->Characteristics->AddressBytes;    

    PLIST_ENTRY Head, Link;
    PIP_INTERFACE Interface;
    NL_PREFIX_POLICY_RW Data;

    SCOPE_LEVEL DestinationScopeLevel;
    ULONG DestinationScopeZone, DestinationLabel;    
    PIP_LOCAL_UNICAST_ADDRESS SourceAddress, SavedSourceAddress;
    PIP_LOCAL_UNICAST_ADDRESS BestSourceAddress = NULL;
    ULONG BestSourceLength = 0, BestSourceLabel = 0;
    BOOLEAN BestPossible;

    DISPATCH_CODE();
    
    //
    // Evaluate destination characteristics.
    //
    DestinationScopeLevel = Protocol->AddressScope(Destination);
    DestinationScopeZone =
        IppGetInterfaceScopeZone(OutgoingInterface, DestinationScopeLevel);

    IppLookupPrefixPolicy(Destination, AddressBytes, &Data);
    DestinationLabel = Data.Label;

    //
    // Because new interfaces are only added at the head of the list,
    // we can unlock the list during our traversal
    // and know that the traversal will terminate properly.
    //
    RtlAcquireReadLockAtDpcLevel(&Compartment->InterfaceSet.Lock);
    Head = &Compartment->InterfaceSet.Set;
    
    for (Link = Head->Flink; Link != Head; Link = Link->Flink) {
        Interface = (PIP_INTERFACE)
            CONTAINING_RECORD(Link, IP_INTERFACE, CompartmentLink);

        if (IppGetInterfaceScopeZone(Interface, DestinationScopeLevel) !=
            DestinationScopeZone) {
            //
            // The interface does not belong to the destination scope.
            //
            continue;
        }

        
        if (Interface != OutgoingInterface) {
            if (!Interface->Forward && !Interface->WeakHostSend) {
                //
                // The interface does not allow packets to be sent out another.
                //
                continue;
            }
        }        

        SourceAddress =
            IppFindBestSourceAddressOnInterfaceAtDpc(
                Interface,
                Destination,
                NextHop);

        if (SourceAddress != NULL) {
            SavedSourceAddress = BestSourceAddress;

            BestPossible =
                IppUpdateBestSourceAddress(
                    SourceAddress,
                    &BestSourceAddress,
                    &BestSourceLength,
                    &BestSourceLabel,
                    Destination,
                    DestinationScopeLevel,
                    DestinationLabel,
                    AddressBytes,
                    OutgoingInterface,
                    NextHop);
            if (BestSourceAddress != SourceAddress) {
                //
                // Our original choice is better.
                //
                IppDereferenceLocalUnicastAddress(SourceAddress);
            } else if (SavedSourceAddress != NULL) {
                //
                // The new SourceAddress has updated our old best choice,
                // so we release the reference we held for the old one.
                //
                IppDereferenceLocalUnicastAddress(SavedSourceAddress);
            }

            if (BestPossible) {
                break;
            }
        }            
    }
    RtlReleaseReadLockFromDpcLevel(&Compartment->InterfaceSet.Lock);

    return BestSourceAddress;
}

 
SCOPE_ID
Ipv6SitePrefixMatch(
    IN PIP_COMPARTMENT Compartment, 
    IN CONST IN6_ADDR *Address
    )
/*++

Routine Description:

    This routine matches the address to the list of site prefixes. It returns
    the site id of the site prefix which matches.

Arguments:

    Compartment - Supplies the compartment.

    Address - Supplies the address to match.

Return Value:

    Returns the site id of the site prefix match. 

--*/
{
    PIP_SITE_PREFIX_ENTRY SitePrefixEntry;
    PLIST_ENTRY Head, Next, Current;
    KIRQL OriginalIrql;
    SCOPE_ID MatchingSite;

    MatchingSite.Value = 0;
    
    KeAcquireSpinLock(&Compartment->SitePrefixSet.Lock, &OriginalIrql);
    Head = &Compartment->SitePrefixSet.Set;
    for (Current = Head->Flink; Current != Head; Current = Next) {
        Next = Current->Flink;
        SitePrefixEntry = (PIP_SITE_PREFIX_ENTRY)
            CONTAINING_RECORD(Current, IP_SITE_PREFIX_ENTRY, Link);

        IppRefreshSitePrefixLifetime(IppTickCount, SitePrefixEntry);
        
        //
        // Is the site prefix still valid? If not, remove it.
        //
        if (SitePrefixEntry->ValidLifetime == 0) {
            IppRemoveSitePrefixEntry(SitePrefixEntry);
        } else {
            //
            // Does this site prefix match the destination address? 
            //
            if (HasPrefix((CONST UCHAR*)Address,
                          (CONST UCHAR*)&SitePrefixEntry->Prefix, 
                          SitePrefixEntry->PrefixLength)) {
                //
                // We have found a matching site prefix.
                // No need to look further.
                //
                MatchingSite = SitePrefixEntry->Interface->
                    ZoneIndices[ScopeLevelSite - ScopeLevelLink];
                break;
            }
        }
    }
   
    KeReleaseSpinLock(&Compartment->SitePrefixSet.Lock, OriginalIrql);

    return MatchingSite;
}


SCOPE_ID
IppDetermineSiteLocalScopeId(
    IN PIP_COMPARTMENT Compartment,
    IN ULONG AddressCount,
    IN PSOCKADDR_IN6 Addresses
    )
/*++

Routine Description:

    Examines the input array of addresses and determines the scope-id that
    can be used to qualify unqualified site-local addresses.

Arguments:

    Compartment - Supplies the compartment to use.

    Addresses - Supplies the list of addresses to process. 

    AddressCount - Supplies the number of addresses in the list of
        addresses. 

Return Value:

    Scope-id of the scope to use.

--*/    
{
    SCOPE_ID ScopeId, CurrentScopeId;
    PSOCKADDR_IN6 Address;
    ULONG Count;

    //
    // Check the global addresses against the site-prefix table, to determine
    // the appropriate site scope-id.
    //
    ScopeId = scopeid_unspecified;    
    for (Count = 0; Count < AddressCount; Count++) {
        Address = &Addresses[Count];
        
        if (IN6_IS_ADDR_GLOBAL(&Address->sin6_addr)) {
            CurrentScopeId = 
                Ipv6SitePrefixMatch(Compartment, &Address->sin6_addr);
            if (CurrentScopeId.Value != 0) {
                //
                // This global address matches a site prefix.
                //
                if (ScopeId.Value == 0) {
                    //
                    // Save the scope-id, but keep looking.
                    //
                    ScopeId = CurrentScopeId;
                } else if (ScopeId.Value != CurrentScopeId.Value) {
                    //
                    // We have found an inconsistency, so remove
                    // all unqualified site-local addresses.
                    //
                    ScopeId.Value = 0;
                    break;
                }
            }
        }
    }

    return ScopeId;    
}

SCOPE_ID
IppDetermineLinkLocalScopeId(
    IN PIP_COMPARTMENT Compartment,
    IN ULONG AddressCount,
    IN PSOCKADDR_IN6 Addresses
    )
/*++

Routine Description:

    Examines the input array of addresses and determines the scope-id that
    can be used to qualify unqualified link-local addresses.

Arguments:

    Compartment - Supplies the compartment to use.

    Addresses - Supplies the list of addresses to process. 

    AddressCount - Supplies the number of addresses in the list of
        addresses. 

Return Value:

    Scope-id of the scope to use.

--*/
{
    SCOPE_ID ScopeId, CurrentScopeId;
    PSOCKADDR_IN6 Address;
    ULONG Count;
    NTSTATUS Status;
    PIP_PATH Path;
    PIP_UNICAST_ROUTE Route;
    
    // 
    // Route global or qualified site-local address to determine its
    // outgoing interface.  Then use the interface's link-level zone-id to
    // determine the scope id.
    //
    ScopeId = scopeid_unspecified;    
    for (Count = 0; Count < AddressCount; Count++) {
        Address = &Addresses[Count];

        if (IN6_IS_ADDR_GLOBAL(&Address->sin6_addr) || 
            (IN6_IS_ADDR_SITELOCAL(&Address->sin6_addr) && 
             Address->sin6_scope_id != 0)) {
            SCOPE_ID CanonicalizedScopeId = Address->sin6_scope_struct;

            //
            // Find best route to address.
            //
            Route = NULL;
            if (IppCanonicalizeScopeId(
                    Compartment, 
                    (CONST UCHAR*) &Address->sin6_addr, 
                    &CanonicalizedScopeId)) {
                Status =
                    IppRouteToDestination(
                        Compartment, 
                        (CONST UCHAR*) &Address->sin6_addr,
                        CanonicalizedScopeId, 
                        NULL, 
                        NULL, 
                        &Path);
                if (!NT_SUCCESS(Status)) {
                    // 
                    // Do nothing; fall thru.
                    //
                } else {
                    Route = IppGetRouteFromPath(Path);
                    IppDereferencePath(Path);            
                    if ((Route != NULL) && !IppIsOnLinkRoute(Route)) {
                        IppDereferenceRoute((PIP_ROUTE) Route);
                        Route = NULL;                                                            
                    }                    
                }                    
            }                

            if (Route != NULL) {
                CurrentScopeId.Level = ScopeLevelLink;
                CurrentScopeId.Zone = 
                    IppGetInterfaceScopeZone(
                        Route->Interface,
                        ScopeLevelLink);
                IppDereferenceRoute((PIP_ROUTE) Route);

                if (ScopeId.Value == 0) {
                    //
                    // Save the scope-id, but keep looking.
                    //
                    ScopeId = CurrentScopeId;
                } else if (ScopeId.Value != CurrentScopeId.Value) {
                    //
                    // We have found an inconsistency, so remove
                    // all unqualified link-local addresses.
                    //
                    ScopeId.Value = 0;
                    break;
                }
            }                    
        }
    }

    return ScopeId;    
}

VOID
IppQualifyAddresses(
    IN PIP_COMPARTMENT Compartment,
    IN OUT ULONG *AddressCount,
    IN OUT PSOCKADDR_IN6 Addresses,
    IN OUT PNL_ADDRESS_PAIR_INDICES Key    
    )
/*++

Routine Description:

    Examines the input array of addresses and either removes unqualified link-/
    site-local addresses or qualifies them with the appropriate scope-ids.

Arguments:

    Compartment - Supplies the compartment use.

    Addresses - Supplies the list of addresses to process. 

    AddressCount - Supplies the number of addresses in the list of
        addresses. Returns the number of addresses after removing unqualified
        addresses. 

    Key - Supplies a mapping from the address number to the index of the
        address in the address list. Returns the updated mapping.  Only the
        Key[i].DestinationAddressIndex portion of the array is considered valid
        and updated.

Return Value:

    None. 

--*/
{
    ULONG LocalAddressCount = *AddressCount;
    BOOLEAN SawLinkLocal = FALSE;
    BOOLEAN SawSiteLocal = FALSE;    
    ULONG Count;
    PSOCKADDR_IN6 Address;
    SCOPE_ID LinkLocalScopeId = scopeid_unspecified;
    SCOPE_ID SiteLocalScopeId = scopeid_unspecified;    
    ULONG NewCount = 0;        
    
    //
    // First see if there are any unqualified link-local or unqualified
    // site-local addresses or global addresses in the array.
    //
    for (Count = 0; Count < LocalAddressCount; Count++) {
        Address = (PSOCKADDR_IN6) &Addresses[Count];
        if (IN6_IS_ADDR_SITELOCAL(&Address->sin6_addr)) {
            if (Address->sin6_scope_id == 0) {
                SawSiteLocal = TRUE;
            }
        } else if (IN6_IS_ADDR_LINKLOCAL(&Address->sin6_addr)) {
            if (Address->sin6_scope_id == 0) {            
                SawLinkLocal = TRUE;
            }                
        }
        if (SawSiteLocal && SawLinkLocal) {
            break;
        }            
    }

    //
    // Determine the scope ids we can fill in for link-local and site-local
    // addresses.
    //
    if (SawSiteLocal) {
        SiteLocalScopeId = 
            IppDetermineSiteLocalScopeId(
                Compartment,
                *AddressCount,
                Addresses);
    }
    if (SawLinkLocal) {
        LinkLocalScopeId = 
            IppDetermineLinkLocalScopeId(
                Compartment,
                *AddressCount,
                Addresses);
    }        

    for (Count = 0; Count < LocalAddressCount; Count++) {
        Address = &Addresses[Count];

        if (Address->sin6_scope_id == 0) {
            if (IN6_IS_ADDR_LINKLOCAL(&Address->sin6_addr)) {
                if (LinkLocalScopeId.Value == 0) {
                    //
                    // Exclude this address from the key array.
                    //
                    continue;
                } else {
                    Address->sin6_scope_id = LinkLocalScopeId.Value;                
                }                    
            } else if (IN6_IS_ADDR_SITELOCAL(&Address->sin6_addr)) {
                if (Address->sin6_scope_id == 0) {
                    if (SiteLocalScopeId.Value == 0) {
                        //
                        // Exclude this address from the key array.
                        //
                        continue;
                    } else {
                        Address->sin6_scope_id = SiteLocalScopeId.Value;                
                    }                    
                }
            }                
        }            
        
        //
        // Include this address in the key array.
        //
        ASSERT(NewCount <= Count);
        Key[NewCount++].DestinationAddressIndex = 
           Key[Count].DestinationAddressIndex;
    }
    *AddressCount = NewCount;    
}

//
// Flags that summarise information about a source-destination address pair.
//
typedef union _IP_SORT_FLAGS {
    UCHAR Value;
    struct {
        BOOLEAN DontUse : 1;
        BOOLEAN ScopeMismatch : 1;
        BOOLEAN Deprecated : 1;
        BOOLEAN LabelMismatch : 1;
    };
} IP_SORT_FLAGS, *PIP_SORT_FLAGS;

//
//  Records some information about a destination address:
//  Its precedence, whether the preferred source address
//  for the destination "matches" the destination,
//  and if it does match, the common prefix length
//  of the two addresses.  All the elements and flags of the structure
//  are guaranteed valid only iff not Flags.DontUse is FALSE.
//
typedef struct _IP_SORTADDRINFO {
    IP_SORT_FLAGS Flags;
    ULONG Metric;
    ULONG Precedence;           // -1 indicates no precedence.
    UCHAR Scope;
    UCHAR CommonPrefixLength;
} IP_SORTADDRINFO, *PIP_SORTADDRINFO;

LONG
IppCompareSortAddressInfo(
    IN PIP_SORTADDRINFO A, 
    IN PIP_SORTADDRINFO B
    )
/*++

Routine Description:

    Compares two addresses A & B and returns
    an indication of their relative desirability
    as destination addresses:
    >0 means A is preferred,
    0 means no preference,
    <0 means B is preferred.
  
    Instead of looking directly at the addresses,
    we look at some precomputed information.

Arguments:

    A - Supplies summary information on an address to be compared.
    
    B - Supplies summary information on an address to be compared.

Return Value:
    > 0 if A is preferred.
    0 if no preference.
    < 0 if B is preferred.

--*/
{
    //
    // Rule 1: Avoid unusable destinations.
    //
    if (A->Flags.DontUse) {
        if (B->Flags.DontUse) {
            return 0;   // No preference.
        } else {
            return -1;  // Prefer B.
        }
    } else {
        if (B->Flags.DontUse) {
            return 1;   // Prefer A.
        } else {
            ;           // Fall through to code below.
        }
    }

    if (A->Flags.ScopeMismatch != B->Flags.ScopeMismatch) {
        //
        // Rule 2: Prefer matching scope.
        //
        if (A->Flags.ScopeMismatch) {
            return -1;  // Prefer B.
        } else {
            return 1;   // Prefer A.
        }
    }

    if (A->Flags.Deprecated != B->Flags.Deprecated) {
        //
        // Rule 3: Avoid deprecated addresses.
        //
        if (A->Flags.Deprecated) {
            return -1;  // Prefer B.
        } else {
            return 1;   // Prefer A.
        }
    }

    //
    // Rule 4: Prefer home addresses.
    // Not yet implemented, pending mobility support.
    //

    if (A->Flags.LabelMismatch != B->Flags.LabelMismatch) {
        //
        // Rule 5: Prefer matching label.
        //
        if (A->Flags.LabelMismatch) {
            return -1;  // Prefer B.
        } else {
            return 1;   // Prefer A.
        }
    }

    if ((A->Precedence != (ULONG)-1) &&
        (B->Precedence != (ULONG)-1) &&
        (A->Precedence != B->Precedence)) {
        //
        // Rule 6: Prefer higher precedence.
        //
        if (A->Precedence > B->Precedence) {
            return 1;   // Prefer A.
        } else {
            return -1;  // Prefer B.
        }
    }

    if (A->Metric != B->Metric) {
        //
        // Rule 7: Prefer *lower* preference.
        // For example, this is used to prefer destinations reached via
        // physical (native) interfaces over virtual (tunnel) interfaces.
        //
        if (A->Metric < B->Metric) {
            return 1;   // Prefer A.
        } else {
            return -1;  // Prefer B.
        }
    }

    if (A->Scope != B->Scope) {
        //
        // Rule 8: Prefer smaller scope.
        //
        if (A->Scope < B->Scope) {
            return 1;   // Prefer A.
        } else {
            return -1;  // Prefer B.
        }
    }

    //
    // The prefixlengths will be set to zero if this check is disabled at
    // a system level by setting the reg key OverrideDefaultAddressSelection in
    // the global TCPIP parameters. See the check in 
    // IppEvaluateSortInformation.
    // 
    if (A->CommonPrefixLength != B->CommonPrefixLength) {
        //
        // Rule 9: Use longest matching prefix.
        //
        if (A->CommonPrefixLength > B->CommonPrefixLength) {
            return 1;   // Prefer A.
        } else {
            return -1;  // Prefer B.
        }
    }

    //
    // We have no preference.
    //
    return 0;
}


VOID
IppFillNextHopSortInfo(
    IN PIP_PATH Path,
    OUT PIP_SORTADDRINFO SortElement
    )
/*++

Routine Description:

    Fills summary information for sorting, taken from the next hop 
    in the the path.

Arguments:

    Path - Path containing the next hop.

    SortElement - Element to store the summary information in.

Return Value:

    None. 

--*/    
{
    PIP_NEXT_HOP NextHop;
    
    NextHop = IppGetNextHopFromPath(Path);
    if (NextHop == NULL) {
        SortElement->Flags.DontUse = TRUE;
        return;
    }
    
    //
    // REVIEW - Instead of using interface preference,
    // would it be better to cache interface+route preference in the path?
    //
    SortElement->Metric = NextHop->Interface->Metric;

    if (IppIsNextHopNeighbor(NextHop)) {
        PIP_NEIGHBOR Neighbor = (PIP_NEIGHBOR) NextHop;
        
        if ((Neighbor->IsUnreachable) ||
            (Neighbor->SubInterface->OperationalStatus != IfOperStatusUp)) {
            //
            // If the Neighbor is unreachable,
            // then we don't want to use this destination.
            // NB: No locking here, this is a heuristic check.
            //
            SortElement->Flags.DontUse = TRUE;
        }
    }
    
    IppDereferenceNextHop(NextHop);
}


//
// IppFlattenAddressList calls ProbeForRead which contains some constant
// conditions in checked builds.  These in turn cause the compiler to complain
// so disable the "conditional expression is constant" warning temporarily.
//
#pragma warning(push)
#pragma warning(disable:4127)        
NTSTATUS
IppFlattenAddressList(
    IN CONST SOCKET_ADDRESS_LIST *InputAddressList,
    OUT PSOCKADDR_IN6 FlatAddressList
    )
/*++

Routine Description:

    This routine validates and packs the list of InputAddressLists in 
    SOCKET_ADDRESS_LIST format into an array of SOCKADDR_IN6 structures.
    The main purpose of copying: if InputAddressList comes
    from user-mode we need to probe InputAddressList->Address[i].lpSockaddr
    and make a copy of it so that 1) we are safe from user mode changes,
    and 2) can do any processing at DISPATCH_LEVEL if necessary.  Flattening
    also makes it possible to access data in SOCKADDR_IN6 directly which
    is simpler than dealing with SOCKET_ADDRESS structures.
  
Arguments: 

    InputAddresses - Supplies the list of addresses to flatten. 

    FlatAddressList - Returns the list of flattened addresses.

Return Value:

    STATUS_SUCCESS or the appropriate failure code. 

Caller IRQL: <= APC_LEVEL

--*/    
{
    SOCKADDR_IN6 UNALIGNED *In6Address;
    INT i;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

    //
    // In case the PreviousMode was UserMode, we have to call
    // ProbeForRead which must be done at IRQL <= APC_LEVEL.
    // The ASSERT however will fire even if PreviousMode was
    // KernelMode to make IppFlattenAddressList semantics 
    // consistent regardless of PreviousMode.
    //
    PAGED_CODE();
    
    for (i = 0; i < InputAddressList->iAddressCount; i++) {
        if ((ULONG) InputAddressList->Address[i].iSockaddrLength != 
            sizeof(SOCKADDR_IN6)) {
            return STATUS_INVALID_PARAMETER;
        }
        In6Address = ((SOCKADDR_IN6 UNALIGNED *) 
                      InputAddressList->Address[i].lpSockaddr);
        if (PreviousMode == UserMode) {       
            __try {
                ProbeForRead(In6Address, sizeof(SOCKADDR_IN6), 1);
                FlatAddressList[i] = *In6Address;
            } __except( EXCEPTION_EXECUTE_HANDLER ) {
                return GetExceptionCode();
            }
        } else {
            FlatAddressList[i] = *In6Address;       
        }    
        
        if (FlatAddressList[i].sin6_family != AF_INET6) {
            return STATUS_INVALID_PARAMETER;
        }
     }
    
    return STATUS_SUCCESS;
}
#pragma warning(pop)

ULONG
IppCreateOrFindSourceAddressIndex(
    IN PSOCKADDR_IN6 SourceAddress,
    IN OUT PSOCKADDR_IN6 SourceAddressList,
    IN OUT ULONG *SourceAddressCount
    )
/*++

Routine Description:

    Searches for SourceAddress in the SourceAddressList.  If found it returns
    the index at which it was found; otherwise, it adds the SourceAddress to
    the list and returns the index of the the item.  SourceAddressList is
    assumed to contain space for SourceAddressCount+1 elements to accomodate
    the addition of an element.

Arguments:

    SourceAddress - Address to be found or added.

    SourceAddressList - List of addresses to be searched or added to.

    SourceAddressCount - Number of address in SourceAddressList; will be
        incremented by 1 if the SourceAddress is added to the list.

Return Value:

    Index at which SourceAddress was found or added. 

--*/
{
    ULONG i;

    for (i = 0; i < (*SourceAddressCount); i++) {
        if  (RtlEqualMemory(
                &SourceAddressList[i],
                SourceAddress,
                sizeof(*SourceAddress))) {
            return i;
        }
    }
    SourceAddressList[(*SourceAddressCount)++] = *SourceAddress;
    return (*SourceAddressCount) - 1;
}
    

VOID
IppEvaluateSortInformation(
    IN PIP_COMPARTMENT Ipv6Compartment,
    IN OUT PIP_COMPARTMENT *Ipv4Compartment, 
    IN PSOCKADDR_IN6 DestinationSocketAddress,
    IN OUT PSOCKADDR_IN6 SourceAddressList,
    IN OUT ULONG* SourceAddressCount,
    OUT PNL_ADDRESS_PAIR_INDICES AddressPairIndices,
    IN OUT PIP_SORTADDRINFO SortElement
    )
/*++

Routine Description:

    Summarizes information about the source and destination addreses into
    SortElement to be used later for sorting the pairs of addresses.  As
    part of its processing it finds the best source address for the given
    destination and stores that in SourceAddressList as well as the
    corresponding index in AddressPairIndices.

Arguments:

    Ipv6Compartment - Supplies the IPv6 comparment.
    
    Ipv4Compartment - Supplies the IPv4 compartment if known, or
        if unspecified, returns the IPv4 compartment if it was looked up.
        The IPv4 compartment will only be looked up if both the destination
        and source addresses had IPv4 embedded addresses.  The reason
        the parameter is I/O is for caching purposes so that we don't
        have to lookup the compartment more than once.
    
    DestinationSocketAddress - Supplies the destination address.
    
    SourceAddressList - Supplies the list of SourceAddress to which the best
        source address for the given DestinationSocketAddress is added if it
        doesn't already exist.
    
    SourceAddressCount - Supplies and returns the number of addresses
        in SourceAddressList.
    
    AddressPairIndices - Returns the source address index of the best 
        found source address.
    
    SortElement - Returns summarised information on the source-destination
        address pair.

Return Value:

    None. 

--*/
{
    NTSTATUS Status;
    SCOPE_ID ScopeId;
    PIP_PATH Path;
    //
    // Note that Destination and Source are aliases for the address
    // of the sin6_addr of their respective SOCKETADDR_IN6 structures.
    //
    CONST IN6_ADDR *Destination = (CONST IN6_ADDR *) 
        &DestinationSocketAddress->sin6_addr;
    SOCKADDR_IN6 SourceSocketAddress =  {AF_INET6, 0, 0,};        
    CONST IN6_ADDR *Source = (CONST IN6_ADDR *) 
        &SourceSocketAddress.sin6_addr;
    CONST UCHAR *Address;
    NL_PREFIX_POLICY_RW PrefixPolicy = {0};
    ULONG DestinationLabel;
    PIP_COMPARTMENT Compartment;
    PIP_LOCAL_UNICAST_ADDRESS LocalSourceAddress;

    SortElement->Flags.Value = 0;        

    //
    // Lookup the precedence of this destination address and
    // the desired label for source addresses used
    // with this destination.
    //
    IppLookupPrefixPolicy(
        (PUCHAR) Destination,
        sizeof(IN6_ADDR),
        &PrefixPolicy);
    SortElement->Precedence = PrefixPolicy.Precedence;
    DestinationLabel = PrefixPolicy.Label;

    //
    // If the destination is an IPv4-mapped address, find the IPv4 compartment
    // corresponding to the IPv6 comparment, and get the "Address" pointer to
    // the bytes of the destination address.
    //
    if (IN6_IS_ADDR_V4MAPPED(Destination)) {
        if (!Ipv4Global.Installed) {
            SortElement->Flags.DontUse = TRUE;
            return;
        }
        
        if (*Ipv4Compartment == NULL) {
            *Ipv4Compartment =
                 IppFindCompartmentById(
                     &Ipv4Global,
                     Ipv6Compartment->CompartmentId);
            if (*Ipv4Compartment == NULL) {
                SortElement->Flags.DontUse = TRUE;
                return;
            }
        }

        Compartment = *Ipv4Compartment;
        Address = IN6_GET_ADDR_V4MAPPED(Destination);
    } else {
        Compartment = Ipv6Compartment;
        Address = (PUCHAR) Destination;
    }

    SortElement->Scope = Compartment->Protocol->AddressScope(Address);
    
    //
    // Find the preferred source address for this destination.
    //
    ScopeId.Value = DestinationSocketAddress->sin6_scope_id;
    if (!IppCanonicalizeScopeId(Compartment, Address, &ScopeId)) {
        SortElement->Flags.DontUse = TRUE;
        return;
    }
        
    Status =
        IppRouteToDestination(
            Compartment, 
            Address,
            ScopeId, 
            NULL, 
            NULL, 
            &Path);
    if (!NT_SUCCESS(Status)) {
        SortElement->Flags.DontUse = TRUE;
        return;
    }

    //
    // Convert preferred source address to an IPv4-mapped address socket
    // address if the destination address was an IPv4-mapped address.  Update
    // "Source" and "SourceSocketAddress", where Source points to the sin6_addr
    // field of SourceSocketAddress.
    //

    //
    // LocalSourceAddress will be valid as long as we have a
    // reference on the Path.
    //
    LocalSourceAddress = Path->SourceAddress;
    if (IN6_IS_ADDR_V4MAPPED(Destination)) {
        IN6_SET_ADDR_V4MAPPED(
            &SourceSocketAddress.sin6_addr,
            (PIN_ADDR) NL_ADDRESS(LocalSourceAddress));
        SourceSocketAddress.sin6_scope_id = 
            NL_ADDRESS_SCOPE_ID(LocalSourceAddress).Value;
        IN4_UNCANONICALIZE_SCOPE_ID(
            (PIN_ADDR) IN6_GET_ADDR_V4MAPPED(&SourceSocketAddress.sin6_addr),
            (SCOPE_ID*) &SourceSocketAddress.sin6_scope_id);
    } else {
        SourceSocketAddress.sin6_addr = 
            *((PIN6_ADDR) NL_ADDRESS(LocalSourceAddress));
        SourceSocketAddress.sin6_scope_id = 
            NL_ADDRESS_SCOPE_ID(LocalSourceAddress).Value;
        IN6_UNCANONICALIZE_SCOPE_ID(
            &SourceSocketAddress.sin6_addr,
            (SCOPE_ID*) &SourceSocketAddress.sin6_scope_id);
    }

    //
    // Store the Source address, and its index.
    //
    AddressPairIndices->SourceAddressIndex = 
        IppCreateOrFindSourceAddressIndex(
            &SourceSocketAddress,
            SourceAddressList,
            SourceAddressCount
            );
    //
    // Determine the length of the prefix that Source and Destination have
    // in common. This can be overridden on a per protocol basis.
    //
    if (!Compartment->Protocol->OverrideDefaultAddressSelection) {
        SortElement->CommonPrefixLength = (UCHAR)
            CommonPrefixLength(
                (PUCHAR) Destination,
                (PUCHAR) Source,
                sizeof(IN6_ADDR));
    } else {
        SortElement->CommonPrefixLength = 0;
    }

    //
    // Lookup the label of the preferred source address and determine
    // if the source and destination labels match.
    //
    IppLookupPrefixPolicy(
        (PUCHAR) Source,
        sizeof(IN6_ADDR),
        &PrefixPolicy);

    if ((DestinationLabel != (ULONG)-1) &&
        (PrefixPolicy.Label != (ULONG)-1) &&
        (DestinationLabel != PrefixPolicy.Label)) {
        //
        // The best source address for this destination
        // does not match the destination.
        //
        SortElement->Flags.LabelMismatch = TRUE;
    }

    SortElement->Flags.ScopeMismatch =
        (NL_ADDRESS_SCOPE_LEVEL(LocalSourceAddress) != SortElement->Scope);

    if (LocalSourceAddress->DadState != NldsPreferred) {
        SortElement->Flags.Deprecated = TRUE;
    }
                
    IppFillNextHopSortInfo(Path, SortElement);

    IppDereferencePath(Path);
}
    
int  __cdecl QSortAddrCompProc(const void *key1, const void *key2)
{
    LONG Compare;
    Compare = 
        IppCompareSortAddressInfo(
            (PIP_SORTADDRINFO)((PUCHAR)key1 
            + sizeof(NL_ADDRESS_PAIR_INDICES)),
            (PIP_SORTADDRINFO)((PUCHAR)key2 
            + sizeof(NL_ADDRESS_PAIR_INDICES)));
    if ((Compare < 0) ||
        ((Compare == 0) && 
         ((*(PNL_ADDRESS_PAIR_INDICES)key2).DestinationAddressIndex 
         < (*(PNL_ADDRESS_PAIR_INDICES)key1).DestinationAddressIndex))) {
        //
        // The +1/-1 are just fitted to mimic with minimal code changes 
        // the output sorting order that was there without qsort. Whenever 
        // the bubble sort was doing a swap, qsort will do swap too because 
        // +1 means Key1 > Key2, and qsort sorts in the ascending order.
        //
        return +1;
    }
    return -1;
}

    
NTSTATUS
IppCreateSortedAddressPairs(
    IN PIP_COMPARTMENT Ipv6Compartment,
    IN OUT PSOCKADDR_IN6* SourceAddressList,
    IN OUT ULONG *SourceAddressCount,
    IN const PSOCKADDR_IN6 DestinationAddressList,
    IN ULONG DestinationAddressCount,
    OUT PNL_ADDRESS_PAIR_INDICES* SortedAddressPairIndices,
    OUT ULONG *SortedAddressPairCount
    )
/*++

Routine Description:

    Given a list of destinations addresses, finds the preferred source address
    for each destination, and sorts the pairs based on suitability for
    communication.
    
Arguments:

    Ipv6Compartment - Supplies the IPv6 comparment.
    
    SourceAddressList - Supplies or returns the list of preferred source
        addresses.  Reserved for future use; *SourceAddressList must be NULL.
        Currently the funtion determines the SourceAddressList by determining
        the best source address for a given destination.
        If the list must be freed using ExFreePool.

    SourceAddressCount - Supplies or returns the count of preferred source
        addresses.  Reserved for future use; must be 0.
    
    DestinationAddressList - Supplies the list of destination addresses.
    
    DestinationAddressCount - Supplies the number of destination addresses.
    
    SortedAddressPairIndices - Returns the sorted pairs of (source,destination)
        indices corresponding to the Source and Destinatin address lists.
        The list must be freed using ExFreePool.

    SortedAddressPairCount - Number of sorted address pairs returned.


Return Value:

    STATUS_SUCCESS on success or some NTSTATUS error code otherwise.

--*/
{
    PIP_SORTADDRINFO SortInfomation;
    PNL_ADDRESS_PAIR_INDICES AddressPairIndices;
    PUCHAR QSortArray, QSortEl;
    ULONG QSortElSize;
    ULONG AddressCount;
    ULONG i;    
    PIP_COMPARTMENT Ipv4Compartment = NULL;
    PSOCKADDR_IN6 CreatedSourceAddressList;
    ULONG CreatedSourceAddressCount;
    NTSTATUS Status;

    if (*SourceAddressList != NULL || *SourceAddressCount != 0) {
        return STATUS_NOT_IMPLEMENTED;
    }

    *SortedAddressPairIndices = NULL;    
    *SortedAddressPairCount = 0;

    if (DestinationAddressCount == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Since there will be atmost one source address associated with each 
    // destination address, we allocate as many source addresses as
    // destination addresses (for the extreme case).
    //
    CreatedSourceAddressList = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            sizeof(SOCKADDR_IN6) * DestinationAddressCount, 
            IpAddressSortPoolTag);
    if (CreatedSourceAddressList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    CreatedSourceAddressCount = 0;


    //
    // Similar allocate the worst-case address pair table size.
    //
    AddressPairIndices = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            sizeof(NL_ADDRESS_PAIR_INDICES) * DestinationAddressCount, 
            IpAddressSortPoolTag);
    if (AddressPairIndices == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;        
        goto FreeCreatedSourceAddressList;
    }

    //
    // Set the initial DestinationAddressIndex to correspond to the
    // the indices of the DestinationAddressList.
    //
    for (i = 0; i < DestinationAddressCount; i++) {
        AddressPairIndices[i].DestinationAddressIndex = i;
        //
        // Assert: AddressPairIndices[i].SourceAddressIndex will be initalized
        // later.
        //
    }

    //
    // Determine the scope-id of site-local and link-local addresses. 
    // 
    AddressCount = DestinationAddressCount;    
    IppQualifyAddresses(
        Ipv6Compartment, 
        &AddressCount, 
        DestinationAddressList, 
        AddressPairIndices);    
    
    if (AddressCount == 0) {
        Status = STATUS_SUCCESS;
        goto FreeAddressPairIndices;
    }

    //
    // Calculate summary information about each source-destination address
    // pair.  This will be the basis for our sort.
    //
    SortInfomation = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            sizeof(*SortInfomation) * AddressCount,
            IpAddressSortPoolTag);
    if (SortInfomation == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;        
        goto FreeAddressPairIndices;
    }

    //
    // For each destination address, find the preferred source address
    // and summarise that information into SortInformation.
    //
    for (i = 0; i < AddressCount; i++) {
        IppEvaluateSortInformation(
            Ipv6Compartment,
            &Ipv4Compartment,
            &DestinationAddressList[i],            
            CreatedSourceAddressList,
            &CreatedSourceAddressCount,
            &AddressPairIndices[i],
            &SortInfomation[i]);
    }
    if (Ipv4Compartment != NULL) {
        IppDereferenceCompartment(Ipv4Compartment);
    }

    //
    // If there were no potential source addresses found, then there
    // are no address pairs to return.
    //
    if (CreatedSourceAddressCount == 0) {
        Status = STATUS_SUCCESS;
        goto FreeSortInformation;
    }

     QSortElSize = sizeof(NL_ADDRESS_PAIR_INDICES) + sizeof(*SortInfomation);
     QSortArray = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            QSortElSize * AddressCount, 
            IpAddressSortPoolTag);

    if (QSortArray == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;        
        goto FreeSortInformation;
    }

    //
    // copy the data to QSort array
    //
    QSortEl = QSortArray;
    for (i=0; i < AddressCount; i++) {
        *(NL_ADDRESS_PAIR_INDICES *)(QSortEl) = 
            AddressPairIndices[i];
        *(PIP_SORTADDRINFO)(QSortEl + sizeof(NL_ADDRESS_PAIR_INDICES)) = 
            SortInfomation[i];
        QSortEl += QSortElSize;
    }
   
    qsort(QSortArray, AddressCount, QSortElSize, QSortAddrCompProc);	

    //
    // copy the necessary data back from QSort array
    //
    QSortEl = QSortArray;
    for (i=0; i < AddressCount; i++) {
        AddressPairIndices[i] = *(NL_ADDRESS_PAIR_INDICES *)(QSortEl);
        QSortEl += QSortElSize;
    }

    ExFreePool(QSortArray);
    ExFreePool(SortInfomation);

    *SortedAddressPairCount = AddressCount;
    *SortedAddressPairIndices = AddressPairIndices;
    *SourceAddressList = CreatedSourceAddressList;
    *SourceAddressCount = CreatedSourceAddressCount;
    
    return STATUS_SUCCESS;    

FreeSortInformation:
    ExFreePool(SortInfomation);            
    
FreeAddressPairIndices:
    ExFreePool(AddressPairIndices);    
    
FreeCreatedSourceAddressList:
    ExFreePool(CreatedSourceAddressList);        

    return Status;    
}

NTSTATUS
IppSortDestinationAddresses(
    IN PIP_COMPARTMENT Ipv6Compartment,
    IN CONST SOCKET_ADDRESS_LIST *InputAddressList,
    OUT SOCKET_ADDRESS_LIST *OutputAddressList
    )
/*++

Routine Description:

    Sorts the input array of addresses, from most preferred destination to
    least preferred. IppSortDestinationAddresses calls IppFlattenAddressList
    which requires to be called at IRQL <= APC_LEVEL in some instances.
  
Arguments: 

    Ipv6Compartment - Supplies the IPv6 compartment. 

    InputAddressList - Supplies the list of addresses to sort. 

    OutputAddressList - Returns the list of sorted addresses. Note that this can
        contain be fewer addresses than InputAddresses since some of the
        addresses might be removed. 

Return Value:

    STATUS_SUCCESS or the appropriate failure code. 

Caller IRQL: <= APC_LEVEL   

--*/
{
    NTSTATUS Status;
    PSOCKET_ADDRESS ScratchAddresseses;
    PNL_ADDRESS_PAIR_INDICES AddressPairIndices;
    ULONG AddressCount;
    PSOCKADDR_IN6 InputFlatAddressList;
    ULONG i;
    PSOCKADDR_IN6 SourceAddressList = NULL;
    ULONG SourceAddressCount = 0;
    ULONG AllocationSize;

    if (InputAddressList->iAddressCount == 0) {
        OutputAddressList->iAddressCount = 0;        
        return STATUS_SUCCESS;
    }        

    AddressCount = InputAddressList->iAddressCount;
 
    InputFlatAddressList = 
        ExAllocatePoolWithTag(
            NonPagedPool, 
            AddressCount * sizeof(SOCKADDR_IN6), 
            IpAddressSortPoolTag);
    if (InputFlatAddressList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = 
        IppFlattenAddressList(
            InputAddressList,
            InputFlatAddressList);
    if (!NT_SUCCESS(Status)) {
        ExFreePool(InputFlatAddressList);        
        return Status;
    }
        
    //
    // The input and output buffers may fully or partially overlap so allocate 
    // memory to not overwrite addresses in the input buffer. 
    //
    ScratchAddresseses = NULL;
    ASSERT(InputAddressList->iAddressCount >= 0);
    Status = RtlULongMult(
                (ULONG) InputAddressList->iAddressCount,
                sizeof(SOCKET_ADDRESS),
                &AllocationSize);
    if (NT_SUCCESS(Status)) {
        ScratchAddresseses = 
            ExAllocatePoolWithTag(
                NonPagedPool, 
                AllocationSize,
                IpAddressSortPoolTag);
    }        
    if (ScratchAddresseses == NULL) {
        ExFreePool(InputFlatAddressList);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(
        ScratchAddresseses, 
        InputAddressList->Address, 
        AllocationSize);

    Status = 
        IppCreateSortedAddressPairs(
            Ipv6Compartment,
            &SourceAddressList,
            &SourceAddressCount,
            InputFlatAddressList,
            AddressCount,
            &AddressPairIndices,
            &AddressCount);
    if (!NT_SUCCESS(Status)) {
        ExFreePool(InputFlatAddressList);        
        return Status;
    }

    //
    // Don't need SourceAddressList.
    //
    if (SourceAddressList != NULL) {
        ExFreePool(SourceAddressList);
    }            
    
    //
    // Now write the sorted addresses into the output buffer. 
    // 
    for (i = 0; i < AddressCount; i++) {
        OutputAddressList->Address[i] = 
            ScratchAddresseses[AddressPairIndices[i].DestinationAddressIndex];
    }
    
    OutputAddressList->iAddressCount = AddressCount;
   
    ExFreePool(ScratchAddresseses);

    ExFreePool(InputFlatAddressList);

    ASSERT((AddressPairIndices != NULL) || (AddressCount == 0));
    if (AddressPairIndices != NULL) {
        ExFreePool(AddressPairIndices);
    }

    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
IpGetAllSortedAddressParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:
    Given a list of source and destination addresses, returns a list of
    pairs of address in sorted order.  The list is sorted by which address
    pair is best suited for communication between two peers.

    The list of source addresses is optional, in which case the function
    automatically uses all the host machine's local addresses.

Arguments:

    SourceAddressList - Supplies list of potential source addresses.
        If NULL this list is automatically usess all local addresses.
    
    SourceAddressCount - Supplies the number of addresses in the 
        SourceAddressList.

    DestinationAddressList - Supplies list of potential destination addresses.
        IPv4 addresses can be specified in IPv4-mapped format.

    DestinationAddressCount -  Supplies the number of addresses in the 
        DestinationAddressList.

    AddressSortOptions - Supplies options to change the default sort options.
        Must be set to 0 if unused.

    SortedAddressPairList - Returns a sorted list of pairs of addresses
        in prefered order of communication.  The list must be freed with a
        single call to IphFreeMemory.

    SortedAddressPairCount - Returns the number of address pairs in
        SortedAddressPairList.

Return Value:

    ERROR_SUCCESS on success.  NTSTATUS error code on error.

--*/ 
{
    NTSTATUS Status;
    PIP_COMPARTMENT Ipv6Compartment;
    PNL_SORT_ADDRESSES_KEY Key = (PNL_SORT_ADDRESSES_KEY)
        Args->KeyStructDesc.KeyStruct;
    PNL_SORT_ADDRESSES_ROD UNALIGNED Rod = (PNL_SORT_ADDRESSES_ROD) 
        Args->StructDesc.RoDynamicParameterStruct;
    PNL_ADDRESS_PAIR_INDICES SortedAddressPairIndices;
    PSOCKADDR_IN6 SourceAddressList;
    ULONG SourceAddressCount;
    ULONG SortedAddressPairCount;

    ASSERT(Key->DestinationAddressCount <= NL_MAX_SORT_ADDRESSES);
        
    if (!Ipv6Global.Installed) {
        return STATUS_NOT_SUPPORTED; 
   }
    
    if (Args->Action != NsiGetExact || Rod == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Ipv6Compartment = IppFindCompartmentById(&Ipv6Global, Key->CompartmentId);
    if (Ipv6Compartment == NULL) {
        return STATUS_NOT_FOUND;
    }

    SourceAddressList = NULL;
    SourceAddressCount = 0;
    Status = 
        IppCreateSortedAddressPairs(
            Ipv6Compartment,
            &SourceAddressList,
            &SourceAddressCount,
            Key->DestinationAddressList,
            Key->DestinationAddressCount,
            &SortedAddressPairIndices,
            &SortedAddressPairCount
            );
    if (NT_SUCCESS(Status)) {
        if (SourceAddressList != NULL) {
            RtlCopyMemory(
                &Rod->SourceAddressList,
                SourceAddressList,
                sizeof(*SourceAddressList) * SourceAddressCount);
            Rod->SourceAddressCount = SourceAddressCount;
            
            ASSERT(SortedAddressPairIndices != NULL);            
            RtlCopyMemory(
                &Rod->SortedAddressPairIndices,
                SortedAddressPairIndices,
                sizeof(*SortedAddressPairIndices) * 
                SortedAddressPairCount);
            Rod->SortedAddressPairCount = SortedAddressPairCount;

            ExFreePool(SourceAddressList);
            ExFreePool(SortedAddressPairIndices);
        }
    }
    
    return Status;
}
