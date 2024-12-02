/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module 

    mld.c

Abstract:

    This module contains the IPv6 specific components of the multicast listener
    discovery protocol.

Author:

    Amit Aggarwal (amitag) Mon Jan 27 10:56:26 2003 

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "mld.tmh"

//
// Session state for adding the router alert option to outgoing MLD packets.
//
extern IP_SESSION_STATE MldSessionState;
 
#define DEFAULT_MLD_ROBUSTNESS DEFAULT_MULTICAST_DISCOVERY_ROBUSTNESS
#define MAX_MLD_ROBUSTNESS 7

#define DEFAULT_MLD_QUERY_RESPONSE_TIME IppMilliseconds(10 * SECONDS)

C_ASSERT(sizeof(MLDV2_QUERY_HEADER) >= sizeof(MLD_HEADER));

VOID
Ipv6pHandleMldQuery(
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    )
/*+++

Routine Description:

    This routine is the receive handler for MLD queries. It validates the
    query and calls the common query handler with all the parameters. 

Arguments:

    The following fields in 'Args' are relevant...
    
    NetBufferList - Supplies a MLD query packet.

    Interface - Supplies the interface over which the packet was received.

    IP, RemoteAddress, RouterAlert - Supplies parsed header information.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

---*/
{
    PNET_BUFFER NetBuffer;
    MLDV2_QUERY_HEADER Buffer, *Mldv2Header;
    MLD_HEADER *MldHeader;
    PUCHAR SourceList = NULL, SourceListBuffer = NULL;
    ULONG SourceCount, QuerySize;
    PUCHAR MulticastAddress;
    ULONG MaxResponseTime;
    PIP_INTERFACE Interface;
    MULTICAST_DISCOVERY_VERSION Version;
    
    //
    // Validate the MLD Query.
    // By the time we get here, any IPv6 Authentication Header will have
    // already been checked, as will have the ICMPv6 checksum.  Still need
    // to check the Hop Limit, Source, and the ICMPv6 code and length.
    //

    if (!Args->RouterAlert) {
        //
        // MLD queries must be sent with a RouterAlert option.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (((PIPV6_HEADER) Args->IP)->HopLimit != 1) {
        //
        // Per [RFC-3810], MLD queries with HopLimit != 1 dropped.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    if (Ipv6AddressScope(Args->NlcReceiveDatagram.RemoteAddress)
        != ScopeLevelLink) {
        //
        // Source address should always be link-local.  Drop the packet.
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }    

    //
    // Each NET_BUFFER_LIST must contain exactly one NET_BUFFER.
    //
    NetBuffer = Args->NetBufferList->FirstNetBuffer;
    ASSERT((NetBuffer != NULL) && (NetBuffer->Next == NULL));

    //
    // Any packet whose size is not equal to sizeof(MLD_HEADER) and less
    // than sizeof(MLDV2_QUERY_HEADER) is rejected.
    //
    if ((NetBuffer->DataLength != sizeof(MLD_HEADER)) &&
        (NetBuffer->DataLength < sizeof(MLDV2_QUERY_HEADER))) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                   "IPNG: Dropping MLD packet with bad header length (%u)\n", 
                   NetBuffer->DataLength);
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }

    Interface = Args->DestLocalAddress->Interface;
    
    if (NetBuffer->DataLength == sizeof(MLD_HEADER)) {
        //
        // MLDv1 query.
        //
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Received MLDv1 query\n");
        MldHeader = (PMLD_HEADER)
            NetioGetDataBuffer(
                NetBuffer,
                sizeof(MLD_HEADER),
                &Buffer, 
                __builtin_alignof(MLD_HEADER),
                0);
        ASSERT(MldHeader->mld_type == ICMP6_MEMBERSHIP_QUERY);
        
        Version = MULTICAST_DISCOVERY_VERSION2;
        SourceCount = 0;
        SourceList = NULL;
        MulticastAddress = (PUCHAR)&MldHeader->MulticastAddress;
        MaxResponseTime = RtlUshortByteSwap(MldHeader->MaxRespTime);
    } else {
        //
        // MLDv2 query.
        //
        ASSERT(NetBuffer->DataLength >= sizeof(MLDV2_QUERY_HEADER));
        
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
                   "IPNG: Received MLDv2 query\n");
        Mldv2Header = (PMLDV2_QUERY_HEADER)
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(MLDV2_QUERY_HEADER),
                &Buffer, 
                __builtin_alignof(MLDV2_QUERY_HEADER),
                0);
        ASSERT(Mldv2Header->mld_type == ICMP6_MEMBERSHIP_QUERY);

        SourceCount = RtlUshortByteSwap(Mldv2Header->SourceCount);
        //
        // There is no danger of overflow because SourceCount in
        // IGMPV3_QUERY_HEADER is a 16 bit while we are doing ULONG
        // computation here. 
        //
        QuerySize =
            sizeof(MLDV2_QUERY_HEADER) + (SourceCount * sizeof(IN6_ADDR));
        
        if (NetBuffer->DataLength < QuerySize) {
            //
            // Reject anything that does not have enough space for all the
            // source addresses. 
            //
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            return;
        } 
        
        Version = MULTICAST_DISCOVERY_VERSION3;
        
        //
        // Get various parameters from the query message.
        // 
        if (Mldv2Header->MaxRespCodeType == MLD_MAX_RESP_CODE_TYPE_NORMAL) {
            MaxResponseTime = RtlUshortByteSwap(Mldv2Header->MaxRespCode);
        } else {
            MaxResponseTime =
                ((((Mldv2Header->MaxRespCodeMantissaHi << 8) + 
                   (Mldv2Header->MaxRespCodeMantissaLo)) | 0x1000) <<
                 (Mldv2Header->MaxRespCodeExponent + 3));
        }
        
        //
        // Set the robustness variable in the interface. 
        // 
        Interface->RobustnessVariable = 
            Mldv2Header->QuerierRobustnessVariable;
        if ((Interface->RobustnessVariable > MAX_MLD_ROBUSTNESS) || 
            (Interface->RobustnessVariable == 0)) {
            Interface->RobustnessVariable = DEFAULT_MLD_ROBUSTNESS;
        }
        
        //
        // Get the multicast address and source address list from the
        // query message. 
        //
        MulticastAddress = (PUCHAR)&Mldv2Header->MulticastAddress;
        if (SourceCount > 0) {
            SourceList =
                NetioGetDataBuffer(NetBuffer, QuerySize, NULL, 1, 0);
            if (SourceList == NULL) {
                //
                // The sources were not in contiguous memory. 
                //
                SourceListBuffer =
                    ExAllocatePoolWithTag(
                        NonPagedPool, QuerySize, Ip6BufferPoolTag);
                if (SourceListBuffer == NULL) {
                    Args->NetBufferList->Status =
                        STATUS_INSUFFICIENT_RESOURCES;
                    return;
                }
                SourceList =
                    NetioGetDataBuffer(
                        NetBuffer, QuerySize, SourceListBuffer, 1, 0);
            }
            
            ASSERT(SourceList != NULL);
            SourceList += sizeof(MLDV2_QUERY_HEADER);
        }
    } 
    
    if (RtlEqualMemory(MulticastAddress, &in6addr_any, sizeof(IN6_ADDR))) {
        MulticastAddress = NULL;
    }
    
    Args->NetBufferList->Status =
        IppProcessMulticastDiscoveryQuery(
            Interface, 
            Version,
            MulticastAddress,
            SourceCount,
            SourceList,
            MaxResponseTime);
    if (SourceListBuffer != NULL) {
        ExFreePool(SourceListBuffer);
        SourceListBuffer = NULL;
    }
}

VOID
Ipv6pHandleMldReport(
    IN CONST IP_REQUEST_CONTROL_DATA *Args
    )
/*+++

Routine Description:

    This routine is the receive handler for MLD reports. It validates the
    query and calls the common report handler with all the parameters. 

Arguments:

    The following fields in 'Args' are relevant...
    
    NetBuffer - Supplies a MLD query packet

    Interface - Supplies the interface over which the packet was received.
    
Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

---*/
{
    PNET_BUFFER NetBuffer;
    MLDV2_QUERY_HEADER Buffer;
    MLD_HEADER *MldHeader;
    PIP_INTERFACE Interface;
    
    //
    // Each NET_BUFFER_LIST must contain exactly one NET_BUFFER.
    //
    NetBuffer = Args->NetBufferList->FirstNetBuffer;
    ASSERT((NetBuffer != NULL) && (NetBuffer->Next == NULL));
    
    //
    // Any packet whose size is less than sizeof(MLD_HEADER) is rejected. 
    //
    if (NetBuffer->DataLength < sizeof(MLD_HEADER)) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    Interface = Args->DestLocalAddress->Interface;
    
    //
    // Reject packets that got looped back. Otherwise, an
    // MLD report sent by us would be processed by us again as if it
    // came from a remote host. 
    //
    if (Args->IsOriginLocal) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    MldHeader = (PMLD_HEADER)
        NetioGetDataBuffer(
            NetBuffer,
            sizeof(MLD_HEADER),
            &Buffer, 
            __builtin_alignof(MLD_HEADER),
            0);
            
    if (MldHeader->mld_type != ICMP6_MEMBERSHIP_REPORT) {
        //
        // Accept only reports from MLDv1. MLDv2 reports are not
        // useful because MLDv2 does not have suppression. 
        //
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    if (!RtlEqualMemory(
            &MldHeader->MulticastAddress, 
            NL_ADDRESS(Args->DestLocalAddress), 
            sizeof(IN6_ADDR))) {
        Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
        return;
    }
    
    Args->NetBufferList->Status =
        IppProcessMulticastDiscoveryReport(
            Interface, 
            MULTICAST_DISCOVERY_VERSION2,
            (PUCHAR) &MldHeader->MulticastAddress);
}

NTSTATUS
MldpCreateMulticastDiscoveryReport(
    IN PIP_INTERFACE Interface,
    IN ULONG ReportSize, 
    IN PIP_MULTICAST_RECORD_ENTRY Records, 
    IN OUT PNL_REQUEST_SEND_DATAGRAMS SendArgs
    )
/*++

Routine Description:
    
    This routine creates an MLD report from the given parameters. It creates
    the net buffer list of the right size, fills in the headers and sets the
    various protocol specific fields on the SendArgs. 

Arguments:

    Interface - Supplies the local interface on which to send the report. 

    ReportSize - Supplies the size of the report. 

    Records - Supplies a list of records to be added in the report. Each record
        contains the multicast address, type and list of sources. 

    SendArgs - Supplies a send argument structure that is filled by the routine
        with the net buffer list and other protocol specific data. 

Return Value:

    STATUS_SUCCESS on success.
    STATUS_NOT_FOUND if no suitable source address is found.
    STATUS_INSUFFICIENT_RESOURCES if memory allocation fails.

Caller LOCK:
 
    The interface lock should be held by the caller. 
 
Caller IRQL: 
 
    Called at DISPATCH_LEVEL.
 
--*/ 
{
    NTSTATUS Status;
    PUCHAR ReportData;
    PNET_BUFFER NetBuffer;
    PNET_BUFFER_LIST NetBufferList;
    MLDV2_REPORT_HEADER UNALIGNED *V2ReportHeader;
    MLD_HEADER UNALIGNED *V1ReportHeader;
    MLDV2_REPORT_RECORD_HEADER UNALIGNED *ReportRecordHeader;
    MULTICAST_DISCOVERY_VERSION Version;
    PIP_MULTICAST_RECORD_ENTRY CurrentRecord;
    ULONG RecordCount = 0, BytesWritten = 0;
    UCHAR *Destination;
    
    ASSERT_WRITE_LOCK_HELD(&Interface->Lock);
    
    //
    // Sanity checks. For version 3 multicast reports, there can be multiple
    // records. For older versions, there can be just one record with the types
    // JOIN_GROUP or LEAVE_GROUP.
    //
    Version = Interface->MulticastDiscoveryVersion;
    ASSERT(Records != NULL);
    if (Version != MULTICAST_DISCOVERY_VERSION3) {
        ASSERT(SendArgs->NetBufferList == NULL);
        ASSERT(Version == MULTICAST_DISCOVERY_VERSION2);
        ASSERT(Records->Next == NULL);
        ASSERT((Records->Type == JOIN_GROUP) || 
               (Records->Type == LEAVE_GROUP));
    } else {
        for (CurrentRecord = Records; 
             CurrentRecord != NULL; 
             CurrentRecord = CurrentRecord->Next) {
            ASSERT((CurrentRecord->Type != JOIN_GROUP) &&
                   (CurrentRecord->Type != LEAVE_GROUP));
        }
    }
    
    //
    // Decide on the destination address based on the type of the message. 
    // MLDv1 reports go to the multicast address of the join. Leave
    // messages go to all routers on link address. All MLDv2 report messages
    // go to all MLDv2 routers on link.  
    //
    if (Records->Type == JOIN_GROUP) {
        Destination = MULTICAST_RECORD_ENTRY_GROUP(Records);
    } else if (Records->Type == LEAVE_GROUP) {
        Destination = (UCHAR*)&in6addr_allroutersonlink;
    } else {
        Destination = (UCHAR*)&in6addr_allmldv2routersonlink;
    }

    //
    // Create the packet. 
    // 
    NetBuffer = NetioAllocateNetBuffer(NULL, 0, 0, FALSE);
    if (NetBuffer == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error creating MLD report: "
                   "Cannot allocate memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ASSERT(NetBuffer->Next == NULL);

    Status = NetioRetreatNetBuffer(
        NetBuffer, 
        ReportSize,
        sizeof(IPV6_HEADER) + Interface->FlCharacteristics->HeaderLength);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error creating MLD report: "
                   "Cannot allocate memory\n");
        NetioFreeNetBuffer(NetBuffer, FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    //
    // For multicast discovery version 3, the same net buffer list might be
    // used for multiple reports. So the net buffer list might already be set
    // in the args. 
    //
    NetBufferList = SendArgs->NetBufferList;
    if (NetBufferList == NULL) {
        NetBufferList = NetioAllocateAndReferenceNetBufferList(
            NetioCompleteNetBufferListChain, 
            NULL, 
            FALSE);
        if (NetBufferList == NULL) {
            NetioRestoreNetBuffer(NetBuffer);
            NetioFreeNetBuffer(NetBuffer, FALSE);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ASSERT(NetBufferList->FirstNetBuffer == NULL);
        SendArgs->NetBufferList = NetBufferList;
    }

    NetBuffer->Next = NetBufferList->FirstNetBuffer;
    NetBufferList->FirstNetBuffer = NetBuffer;
    ReportData = NetioGetDataBufferSafe(NetBuffer, ReportSize);

    if (Version == MULTICAST_DISCOVERY_VERSION3) {
        V2ReportHeader = (PMLDV2_REPORT_HEADER) ReportData;
        RtlZeroMemory(V2ReportHeader, sizeof(MLDV2_REPORT_HEADER));
        V2ReportHeader->mld_type = ICMP6_V2_MEMBERSHIP_REPORT;
        BytesWritten += sizeof(MLDV2_REPORT_HEADER);
        
        for (CurrentRecord = Records;
             CurrentRecord != NULL;
             CurrentRecord = CurrentRecord->Next) {
            ASSERT((CurrentRecord->Type != JOIN_GROUP) &&
                   (CurrentRecord->Type != LEAVE_GROUP));
            RecordCount++;
            
            ReportRecordHeader = (PMLDV2_REPORT_RECORD_HEADER)
                (ReportData + BytesWritten);
            RtlZeroMemory(ReportRecordHeader, 
                          sizeof(MLDV2_REPORT_RECORD_HEADER));
            ReportRecordHeader->Type = CurrentRecord->Type;
            ReportRecordHeader->SourceCount = 
                RtlUshortByteSwap(CurrentRecord->SourceCount);
            RtlCopyMemory(&ReportRecordHeader->MulticastAddress,
                          MULTICAST_RECORD_ENTRY_GROUP(CurrentRecord),
                          sizeof(IN6_ADDR));
            BytesWritten += sizeof(MLDV2_REPORT_RECORD_HEADER);
             
            RtlCopyMemory(ReportData + BytesWritten, 
                          MULTICAST_RECORD_ENTRY_SOURCE(CurrentRecord,
                                                        0,
                                                        sizeof(IN6_ADDR)), 
                          CurrentRecord->SourceCount * sizeof(IN6_ADDR));
            BytesWritten += CurrentRecord->SourceCount * sizeof(IN6_ADDR);
            ASSERT(BytesWritten <= ReportSize);
        }
        V2ReportHeader->RecordCount = RtlUshortByteSwap(RecordCount);
        SendArgs->UlChecksumOffset = FIELD_OFFSET(MLDV2_REPORT_HEADER, 
                                                  mld_checksum);
    } else {
        V1ReportHeader = (PMLD_HEADER)ReportData;
        RtlZeroMemory(V1ReportHeader, sizeof(MLD_HEADER));
        if (Records->Type == JOIN_GROUP) {
            Destination = (UCHAR*)&V1ReportHeader->MulticastAddress;
            V1ReportHeader->mld_type = ICMP6_MEMBERSHIP_REPORT;
        } else {
            V1ReportHeader->mld_type = ICMP6_MEMBERSHIP_REDUCTION;
        }
        RtlCopyMemory(&V1ReportHeader->MulticastAddress,
                      MULTICAST_RECORD_ENTRY_GROUP(Records),
                      sizeof(IN6_ADDR));
        BytesWritten += sizeof(MLD_HEADER);
        ASSERT(BytesWritten <= ReportSize);
        
        SendArgs->UlChecksumOffset = FIELD_OFFSET(MLD_HEADER, mld_checksum);
    }
    
    SendArgs->DestProtocol = IPPROTO_ICMPV6;
    SendArgs->NlCompartment.Id = Interface->Compartment->CompartmentId;
    SendArgs->NlInterface.Index = Interface->Index;
    SendArgs->UlChecksumOptions = 0;
    SendArgs->RemoteAddress = Destination;
    SendArgs->RemoteScopeId = scopeid_unspecified;
    SendArgs->NlSessionState = &MldSessionState;
    
    return STATUS_SUCCESS;
}

BOOLEAN
MldpIsMulticastDiscoveryAllowed(
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    This routine determines if multicast discovery is allowed for a given
    multicast address. Multicast discovery is allowed for all addresses except
    all nodes on link mulitcast address and interface local multicast
    addresses.  
    
Arguments:

    Address - Supplies the address to check.

Return Value:

    TRUE if multicast discovery is allowed, FALSE otherwise.

--*/ 
{
    return ((!RtlEqualMemory(Address, 
                             &in6addr_allnodesonlink, 
                             sizeof(IN6_ADDR))) &&
            (!IN6_IS_ADDR_MC_NODELOCAL((CONST IN6_ADDR *)Address)));
}
