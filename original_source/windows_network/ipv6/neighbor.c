/*++

Copyright (c) 2001-2002  Microsoft Corporation

Module Name:

    neighbor.c

Abstract:

    This module contains the IPv6 Neighbor Discovery Algorithm [RFC 2461].

Author:

    Mohit Talwar (mohitt) Mon Oct 15 09:53:07 2001

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "neighbor.tmh"

BOOLEAN
Ipv6pParseTlvOption(
    IN PNET_BUFFER NetBuffer,
    OUT PUCHAR Type,
    OUT PUSHORT Length
    )
/*++

Routine Description:

    Parse an IPv6 Neighbor Discovery Type-Length-Value option.
    
Arguments:

    NetBuffer - Supplies an IPv6 Neighbor Discovery packet,
        with the packet offset at the start of the TLV option.

    Type - Returns the type of the encoded value.
    
    Length - Returns the length of the entire option.
    
Return Value:

    TRUE on success, FALSE on failure.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ND_OPTION_HDR Buffer, *Option;

    if (NetBuffer->DataLength < sizeof(ND_OPTION_HDR)) {
        //
        // Insufficient data buffer for a valid TLV option.
        //
        return FALSE;
    }    

    Option =
        NetioGetDataBuffer(NetBuffer, sizeof(ND_OPTION_HDR), &Buffer, 1, 0);

    *Length = ((USHORT) Option->nd_opt_len) * 8;
    if ((*Length == 0) || (*Length > NetBuffer->DataLength)) {
        //
        // Invalid option length.
        //
        return FALSE;
    }

    *Type = Option->nd_opt_type;
    return TRUE;
}


PUCHAR
Ipv6pNetAllocate(
    OUT PNET_BUFFER_LIST *NetBufferList,
    IN ULONG Size,
    IN ULONG Offset
    )
/*++

Routine Description:

    Allocate a NetBufferList (including NetBuffer, MDL, and Buffer) to describe
    a packet of the specified Size.  Set the NetBuffer's DataOffset to the
    specified value and return the resulting pointer within the Buffer.

Arguments:

    NetBufferList - Returns the allocated NetBufferList.
        This includes a NetBuffer, an MDL, and a Buffer.
        
    Size - Supplies the required size of the allocated Buffer.

    Offset - Supplies the required offset within the allocated Buffer.
    
Return Value:

    Returns a pointer within the Buffer at the specified offset.
    Returns NULL upon failure.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;
    PUCHAR Buffer;
    
    *NetBufferList = NetioAllocateAndReferenceNetBufferAndNetBufferList(
        NetioCompleteNetBufferAndNetBufferListChain,
        NULL, 
        NULL, 
        0, 
        0,
        FALSE);
    if (*NetBufferList == NULL) {
        return NULL;
    }

    Status = NetioRetreatNetBufferList(*NetBufferList, Size - Offset, Offset);
    if (!NT_SUCCESS(Status)) {
        NetioDereferenceNetBufferList(*NetBufferList, FALSE);
        *NetBufferList = NULL;
        return NULL;
    }
    
    Buffer =
        NetioGetDataBuffer(
            (*NetBufferList)->FirstNetBuffer, 
            Size - Offset, 
            NULL, 
            1, 
            0);
    ASSERT(Buffer != NULL);
    return Buffer;
}


VOID
Ipv6pSendNeighborAdvertisement(
    IN PIP_SUBINTERFACE SubInterface,
    IN CONST UCHAR *SolicitationSourceDlAddress OPTIONAL,
    IN CONST SOURCEROUTE_HEADER *SolicitationSourceDlRoute OPTIONAL,
    IN CONST UCHAR *SolicitationSourceAddress,
    IN PIP_LOCAL_ADDRESS LocalTarget
    )
/*++

Routine Description:
    
    Construct and send a neighbor advertisement for a local target.

Arguments:

    SubInterface - Supplies the subinterface over which the neighbor 
        advertisement should be sent. 

    SolicitationSourceDlAddress - Supplies the data link address to which the 
        advertisement is to be sent. Unused.

    SolicitationSourceDlRoute - Unused for Ipv6.
    
    SolicitationSourceAddress - Supplies the source address of the 
        corresponding neighbor solicitation.

    LocalTarget - Supplies the local target address.

Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    PIP_INTERFACE Interface = SubInterface->Interface;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    USHORT Backfill = (Interface->FlBackfill + sizeof(IPV6_HEADER));
    NL_ADDRESS_TYPE AddressType = NL_ADDRESS_TYPE(LocalTarget);
    USHORT OptionLength, Size;
    PNET_BUFFER_LIST NetBufferList;
    PIP_LOCAL_UNICAST_ADDRESS Source;
    IPV6_NEIGHBOR_ADVERTISEMENT_FLAGS Flags = { 0, };
    PUCHAR Buffer;
    ND_NEIGHBOR_ADVERT_HEADER UNALIGNED *Advertisement;
    PND_OPTION_HDR Option;

    DISPATCH_CODE();

    UNREFERENCED_PARAMETER(SolicitationSourceDlRoute);
    UNREFERENCED_PARAMETER(SolicitationSourceDlAddress);
    
    //
    // Determine the TLLA option length.
    // NB: Some interfaces do not use SLLA and TLLA options.
    //
    OptionLength = (Interface->FlCharacteristics->DiscoversNeighbors &&
        !Interface->FlCharacteristics->UseStaticMapping)
        ? (sizeof(ND_OPTION_HDR) + DlAddressLength)
        : 0;
    ASSERT((OptionLength % 8) == 0);

    //
    // Determine the size of the required data buffer.
    //
    Size = Backfill + sizeof(ND_NEIGHBOR_ADVERT_HEADER) + OptionLength;

    //
    // Determine the source address of the advertisement.
    //
    if (AddressType == NlatUnicast) {
        //
        // Take our source address from the target address.
        //
        Source = (PIP_LOCAL_UNICAST_ADDRESS) LocalTarget;
    } else {
        ASSERT(AddressType == NlatAnycast);

        //
        // Find the best source address for the destination address.
        //
        Source =
            IppFindBestSourceAddressOnInterface(
                Interface,
                (CONST UCHAR *) SolicitationSourceAddress,
                NULL);
        if (Source == NULL) {
            return;
        }
    }


    //
    // Determine the destination address of the advertisement (and the
    // advertisement type) by examining the source of the solicitation.
    //
    if (IN6_IS_ADDR_UNSPECIFIED((CONST IN6_ADDR *)SolicitationSourceAddress)) {
        //
        // Solicitation came from an unspecified address (presumably a node
        // undergoing initialization), so we need to multicast our response.
        // We also don't set the solicited flag since we can't specify the
        // specific node our advertisement is directed at.
        //
        SolicitationSourceAddress = (CONST UCHAR *)&in6addr_allnodesonlink;
        ASSERT(Flags.Solicited == FALSE);
    } else {
        //
        // We know who sent the solicitation, so we can respond by
        // unicasting our solicited advertisement back to the soliciter.
        //
        Flags.Solicited = TRUE;
    }

    Flags.Router = (Interface->Forward == TRUE);

    //
    // We set the override flag except if...
    // - The target address is an anycast address or
    // - The TLLA option is not included.
    //
    Flags.Override = (AddressType != NlatAnycast) && (OptionLength != 0);

    //
    // Allocate a packet for the neighbor advertisement message.
    //
    Buffer = Ipv6pNetAllocate(&NetBufferList, Size, Backfill);
    if (Buffer == NULL) {
        goto Bail;
    }

    //
    // Fill the Neighbor Advertisement header and the TLLA option.
    //
    Advertisement = (ND_NEIGHBOR_ADVERT_HEADER UNALIGNED *) Buffer;
    Advertisement->nd_na_type = ND_NEIGHBOR_ADVERT;
    Advertisement->nd_na_code = 0;
    Advertisement->nd_na_cksum = 0;
    Advertisement->nd_na_flags_reserved = Flags.Value;
    Advertisement->nd_na_target = *((PIN6_ADDR) NL_ADDRESS(LocalTarget));

    if (OptionLength != 0) {
        Option = (PND_OPTION_HDR) (Advertisement + 1);
        Option->nd_opt_type = ND_OPT_TARGET_LINKADDR;
        Option->nd_opt_len = (UINT8) (OptionLength / 8);
        RtlCopyMemory(
            Option + 1, 
            Interface->FlCharacteristics->DlAddress, 
            DlAddressLength);
    }
    
    //
    // Send the ICMPv6 Neighbor Advertisement Message.
    // REVIEW: Optimize for the case when we Create/Update a neighbor?
    //
    IppSendDirect(
        Interface,
        SubInterface,
        NULL,
        Source,
        (CONST UCHAR *) SolicitationSourceAddress,
        IPPROTO_ICMPV6,
        NULL,
        FIELD_OFFSET(ND_NEIGHBOR_ADVERT_HEADER, nd_na_cksum),
        NetBufferList);

    IppUpdateIcmpOutStatistics(&Ipv6Global, ND_NEIGHBOR_ADVERT);

Bail:
    ASSERT((AddressType == NlatUnicast) == (Source == (PVOID) LocalTarget));
    if (AddressType == NlatAnycast) {
        IppDereferenceLocalUnicastAddress(Source);
    }
}

VOID
Ipv6pHandleNeighborSolicitation(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    )
/*++

Routine Description:

    Validate and process an IPv6 Neighbor Solicitation message.
    
Arguments:

    Icmpv6 - Supplies the parsed ICMPv6 header.


    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv6 Neighbor Solicitation packet,
        with the packet offset at the start of the solicitation header.

    Interface - Supplies the interface over which the packet was received.
    
    RemoteScopeId - Supplies the scope identifier of RemoteAddress.
    
    RemoteAddress - Supplies the source address of the packet.
    
    LocalAddress - Supplies the destination address of the packet.
    
Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    PIP_INTERFACE Interface = Args->DestLocalAddress->Interface;
    CONST NLC_RECEIVE_DATAGRAM *ReceiveDatagram = &Args->NlcReceiveDatagram;
    CONST IN6_ADDR *SourceAddress = (PIN6_ADDR) ReceiveDatagram->RemoteAddress;
    CONST IN6_ADDR *DestinationAddress =
        (PIN6_ADDR) NL_ADDRESS(Args->DestLocalAddress);
    
    USHORT ParsedLength;
    ND_NEIGHBOR_SOLICIT_HEADER SolicitationBuffer, *Solicitation;
    UCHAR Type;
    USHORT Length;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    UCHAR DlAddressBuffer[DL_ADDRESS_LENGTH_MAXIMUM], *DlAddress = NULL;
    BOOLEAN IsSourceUnspecified;
    PIP_LOCAL_ADDRESS LocalTarget;
    PIPV6_ANYCAST_ADVERTISEMENT Data;

    DISPATCH_CODE();
    
    //
    // Validate the neighbor solicitation.
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
        // Bogus/corrupted neighbor solicitation message.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }


    //
    // Get the neighbor solicitation.
    //    
    if (NetBuffer->DataLength < sizeof(ND_NEIGHBOR_SOLICIT_HEADER)) {
        //
        // Insufficient data buffer for a neighbor solicitation.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    Solicitation =
        NetioGetDataBuffer(
            NetBuffer,
            sizeof(ND_NEIGHBOR_SOLICIT_HEADER),
            &SolicitationBuffer, 
            1, 
            0);

    if (IN6_IS_ADDR_MULTICAST(&(Solicitation->nd_ns_target))) {
        //
        // A packet containing a multicast target address is quickly dropped.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    ParsedLength = sizeof(ND_NEIGHBOR_SOLICIT_HEADER);
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
    // Validate Source & Destination.
    //
    IsSourceUnspecified = IN6_IS_ADDR_UNSPECIFIED(SourceAddress);
    if (IsSourceUnspecified) {
        if (!IN6_IS_ADDR_SOLICITEDNODE(DestinationAddress)) {
            //
            // Destination address must be a solicited node multicast address.
            //
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            return;
        }

        if (DlAddress != NULL) {
            //
            // No Source Link Layer Address option should be present.
            //
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            return;
        }
    }

    LocalTarget =
        IppHandleNeighborSolicitation(
            Args->SourceSubInterface,
            DlAddress,
            Interface->FlModule->Npi.Dispatch->
            GetLinkLayerSourceRoute(
                Interface->FlContext,
                Args->NetBufferList),
            (PUCHAR) SourceAddress,
            (PUCHAR) &Solicitation->nd_ns_target);
    if (LocalTarget == NULL) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (NL_ADDRESS_TYPE(LocalTarget) == NlatUnicast) {
        //
        // Send a neighbor advertisement for the target back to the source. 
        //
        Ipv6pSendNeighborAdvertisement(
            Args->SourceSubInterface, 
            NULL,
            NULL,
            (CONST UCHAR *) SourceAddress, 
            LocalTarget);
    } else {
        //
        // Anycast address.
        // Delay the neighbor advertisement by a random amount.
        //
        Data =
            ExAllocatePoolWithTag(
                NonPagedPool, sizeof(*Data), Ip6LocalAnycastAddressPoolTag);
        if (Data != NULL) {
            Data->SubInterface = Args->SourceSubInterface;
            IppReferenceSubInterface(Args->SourceSubInterface);
            Data->AnycastAddress = (PIP_LOCAL_ANYCAST_ADDRESS) LocalTarget;
            IppReferenceLocalAddress(LocalTarget);
            Data->SourceAddress = *SourceAddress;
            TtStartTimer(
                Interface->AnycastAdvertisementTimerTable, 
                &Data->Timer,
                RandomNumber(1, IppTimerTicks(MAX_ANYCAST_DELAY_TIME)));
        } else {
            Ipv6pSendNeighborAdvertisement(
                Args->SourceSubInterface, 
                NULL,
                NULL,
                (CONST UCHAR *) SourceAddress, 
                LocalTarget);
        }
    }
    
    IppDereferenceLocalAddress(LocalTarget);
    
    Args->NetBufferList->Status = STATUS_SUCCESS;
}


VOID
Ipv6pHandleAnycastAdvertisementTimeout(
    IN PIP_INTERFACE Interface
    )
/*++

Routine Description:
    
    This routine processes timeouts for sending anycast advertisements.  The
    routine sends any anycast advertisements that need to be sent. 

Arguments:

    Interface - Supplies the interface on which the anycast timer has fired.  

Return Value:

    None.

Caller LOCK:

    None. 

Caller IRQL: = DISPATCH_LEVEL.

--*/ 
{
    ULONG FiredCount;
    LIST_ENTRY FiredList;
    PIPV6_ANYCAST_ADVERTISEMENT Data;
    PIP_SUBINTERFACE SubInterface;
    PIP_LOCAL_ADDRESS LocalTarget;
    KLOCK_QUEUE_HANDLE LockHandle;

    DISPATCH_CODE();
    
    //
    // Get the list of advertisements that need to be sent out under lock. 
    //
    RtlAcquireWriteLockAtDpcLevel(&Interface->Lock, &LockHandle);

    FiredCount = 
        TtFireTimer(
            Interface->AnycastAdvertisementTimerTable,
            &FiredList);    

    RtlReleaseWriteLockFromDpcLevel(&Interface->Lock, &LockHandle);

    //
    // For each advertisement, if the anycast address is still valid, send out
    // a neighbor advertisement. 
    //
    while (!IsListEmpty(&FiredList)) {
        Data = (PIPV6_ANYCAST_ADVERTISEMENT) CONTAINING_RECORD(
            RemoveHeadList(&FiredList), 
            IPV6_ANYCAST_ADVERTISEMENT, 
            Timer.Link);
        
        SubInterface = Data->SubInterface;
        LocalTarget = (PIP_LOCAL_ADDRESS) Data->AnycastAddress;
        //
        // $$REVIEW: An alternate implementation would be to delete all the
        // pending advertisements when the anycast address gets deleted. 
        //
        if (!LocalTarget->Deleted) {
            Ipv6pSendNeighborAdvertisement(
                SubInterface,
                NULL,
                NULL,
                (CONST UCHAR*) &Data->SourceAddress, 
                LocalTarget);
        }
        IppDereferenceLocalAddress(LocalTarget);
        IppDereferenceSubInterface(SubInterface);
        ExFreePool(Data);
    }
}


VOID
Ipv6pHandleNeighborAdvertisement(
    IN CONST ICMPV6_MESSAGE *Icmpv6,
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    )
/*++

Routine Description:

    Validate and Process an IPv6 Neighbor Advertisement Message.
    
Arguments:

    Icmpv6 - Supplies the parsed ICMPv6 header.
    

    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies an IPv6 Neighbor Advertisement packet,
        with the packet offset at the start of the advertisement header.

    Interface - Supplies the interface over which the packet was received.
    
    LocalAddress - Supplies the destination address of the packet.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PNET_BUFFER NetBuffer = Args->NetBufferList->FirstNetBuffer;
    PIP_INTERFACE Interface = Args->SourceSubInterface->Interface;
    CONST IN6_ADDR *DestinationAddress = (CONST IN6_ADDR *) 
        NL_ADDRESS(Args->DestLocalAddress);
    
    USHORT ParsedLength;
    ND_NEIGHBOR_ADVERT_HEADER UNALIGNED AdvertisementBuffer, *Advertisement;
    UCHAR Type;
    USHORT Length;
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    UCHAR DlAddressBuffer[DL_ADDRESS_LENGTH_MAXIMUM], *DlAddress = NULL;
    IPV6_NEIGHBOR_ADVERTISEMENT_FLAGS Flags;
    
    //
    // Validate the neighbor advertisement.
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
        // Bogus/corrupted neighbor advertisement message.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }


    //
    // Get the neighbor advertisement.
    //
    if (NetBuffer->DataLength < sizeof(ND_NEIGHBOR_ADVERT_HEADER)) {
        //
        // Insufficient data buffer for a neighbor advertisement.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    Advertisement =
        NetioGetDataBuffer(
            NetBuffer,
            sizeof(ND_NEIGHBOR_ADVERT_HEADER), 
            &AdvertisementBuffer, 
            1, 
            0);

    ParsedLength = sizeof(ND_NEIGHBOR_ADVERT_HEADER);
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
    // Get the neighbor advertisement flags.
    //
    Flags.Value = Icmpv6->icmp6_pptr;

    
    //
    // Validate Destination.
    // The Solicited flag must be zero if the destination address is multicast.
    //
    if (IN6_IS_ADDR_MULTICAST(DestinationAddress) && Flags.Solicited) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }


    //
    // We've received and parsed a valid neighbor advertisement.
    //
    IppHandleNeighborAdvertisement(
        Args->SourceSubInterface,
        DlAddress,
        Interface->FlModule->Npi.Dispatch->
        GetLinkLayerSourceRoute(
            Interface->FlContext,
            Args->NetBufferList),
        (PUCHAR) &Advertisement->nd_na_target,
        Flags);

    Args->NetBufferList->Status = STATUS_SUCCESS;
}


VOID
Ipv6pSendNeighborSolicitation(
    IN BOOLEAN DispatchLevel,
    IN PIP_INTERFACE Interface,
    IN PIP_SUBINTERFACE SubInterface,
    IN PIP_NEIGHBOR Neighbor OPTIONAL,
    IN PIP_LOCAL_UNICAST_ADDRESS SourceAddress OPTIONAL,
    IN CONST UCHAR *DestinationAddress OPTIONAL,
    IN CONST UCHAR *TargetAddress
    )
/*++

Routine Description:
    
    Low-level version of IppSendNeighborSolicitation -
    uses explicit source/destination/target addresses.

    Compare NeighborSolicitSend0 in the XP IPv6 stack.

Arguments:

    DispatchLevel - Supplies TRUE if IRQL is known to be at DISPATCH level.
    
    Interface - Supplies the interface over which to send a solicitation.

    SubInterface - Supplies the sub-interface over which to send the solicit.
    
    Neighbor - Supplies the neighbor to which to send the solicitation.

    SourceAddress - Supplies the source address for the solicitation.
        If NULL, solicitation is sent with the unspecified address. 

    DestinationAddress - Supplies the destination address for the solicitation.
        If NULL, solicitation is sent to target's solicited-node address.

    TargetAddress - Supplies the target address for the solicitation.

Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    IN6_ADDR Destination;    
    USHORT DlAddressLength = Interface->FlCharacteristics->DlAddressLength;
    USHORT Backfill = (Interface->FlBackfill + sizeof(IPV6_HEADER));
    USHORT OptionLength, Size;
    PNET_BUFFER_LIST NetBufferList;
    PUCHAR Buffer;
    ND_NEIGHBOR_SOLICIT_HEADER UNALIGNED *Solicitation;
    PND_OPTION_HDR Option;

    if (DispatchLevel) {
        DISPATCH_CODE();
    }

    if (DestinationAddress == NULL) {
        //
        // We do not have a link-layer address cached.
        // Multicast the solicitation to target's solicited-node address.
        //
        IN6_SET_ADDR_SOLICITEDNODE(&Destination, (PIN6_ADDR) TargetAddress);
        DestinationAddress = (CONST UCHAR *) &Destination;
    }
    
    //
    // Determine the SLLA option length.
    // NB: Some interfaces do not use SLLA and TLLA options.
    // NB: We sometimes send with the unspecified source address.
    //
    OptionLength =
        (Interface->FlCharacteristics->DiscoversNeighbors &&
        !Interface->FlCharacteristics->UseStaticMapping
         && (SourceAddress != NULL))
        ? (sizeof(ND_OPTION_HDR) + DlAddressLength)
        : 0;
    ASSERT((OptionLength % 8) == 0);

    //
    // Determine the size of the required data buffer.
    //
    Size = Backfill +  sizeof(ND_NEIGHBOR_SOLICIT_HEADER) + OptionLength;

    //
    // Allocate a packet for the neighbor solicitation message.
    //
    Buffer = Ipv6pNetAllocate(&NetBufferList, Size, Backfill);
    if (Buffer == NULL) {
        return;
    }
    
    //
    // Retreat and fill the Neighbor Solicitation header and the SLLA option.
    //
    Solicitation = (ND_NEIGHBOR_SOLICIT_HEADER UNALIGNED *) Buffer;
    Solicitation->nd_ns_type = ND_NEIGHBOR_SOLICIT;
    Solicitation->nd_ns_code = 0;
    Solicitation->nd_ns_cksum = 0;
    Solicitation->nd_ns_reserved = 0;
    Solicitation->nd_ns_target = *((PIN6_ADDR) TargetAddress);

    if (OptionLength != 0) {
        Option = (PND_OPTION_HDR) (Solicitation + 1);
        Option->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
        Option->nd_opt_len = (UINT8) (OptionLength / 8);
        RtlCopyMemory(
            Option + 1, 
            Interface->FlCharacteristics->DlAddress, 
            DlAddressLength);
    }

    IppSendDirect(
        Interface,
        SubInterface,
        Neighbor,
        SourceAddress,
        DestinationAddress,
        IPPROTO_ICMPV6,
        NULL,
        FIELD_OFFSET(ND_NEIGHBOR_SOLICIT_HEADER, nd_ns_cksum),
        NetBufferList);

    IppUpdateIcmpOutStatistics(&Ipv6Global, ND_NEIGHBOR_SOLICIT);
}
