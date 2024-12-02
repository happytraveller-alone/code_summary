/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module 

    igmp.c

Abstract:

    This module contains the IPv4 specific components of the multicast listener
    discovery protocol.

Author:

    Amit Aggarwal (amitag) Mon Dec 16 19:00:40 2002

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "igmp.tmh"

#define DEFAULT_IGMP_ROBUSTNESS DEFAULT_MULTICAST_DISCOVERY_ROBUSTNESS
#define MAX_IGMP_ROBUSTNESS 7

#define DEFAULT_IGMP_QUERY_RESPONSE_TIME IppMilliseconds(10 * SECONDS)

IP_RECEIVE_DEMUX IgmpDemux = { IgmpReceiveDatagrams };

C_ASSERT(FIELD_OFFSET(IGMP_HEADER, VersionType) == 
         FIELD_OFFSET(IGMPV3_REPORT_HEADER, Type));
C_ASSERT(FIELD_OFFSET(IGMPV3_REPORT_HEADER, Type) ==
         FIELD_OFFSET(IGMPV3_QUERY_HEADER, Type));
C_ASSERT(sizeof(IGMPV3_REPORT_HEADER) >= sizeof(IGMP_HEADER));
C_ASSERT(sizeof(IGMPV3_QUERY_HEADER) >= sizeof(IGMP_HEADER));

//
// Session state for adding the router alert option to outgoing IGMP packets.
//
extern IP_SESSION_STATE IgmpSessionState;

VOID
NTAPI
IgmpReceiveDatagrams(
    IN PIP_REQUEST_CONTROL_DATA Args
    )
/*++

Routine Description:
    
    This routine is the receive data handler for the IGMP protocol. 

Arguments:

    Args - Supplies the packet received. 

Return Value:

    None.

Caller LOCK:
Caller IRQL: = DISPATCH_LEVEL.

--*/    
{
    PNET_BUFFER NetBuffer;
    IGMPV3_QUERY_HEADER Buffer, *Igmpv3QueryHeader;
    PIGMP_HEADER IgmpHeader;
    PUCHAR SourceList = NULL, SourceListBuffer = NULL;
    ULONG SourceCount, QuerySize;
    PUCHAR MulticastAddress;
    UINT16 Checksum;
    ULONG MaxResponseTime;
    PIP_INTERFACE Interface;
    MULTICAST_DISCOVERY_VERSION Version;
    IP_FILTER_ACTION Action;
    
    for (; Args != NULL; Args = Args->Next) {
        //
        // Each NET_BUFFER_LIST must contain exactly one NET_BUFFER.
        //
        NetBuffer = Args->NetBufferList->FirstNetBuffer;
        ASSERT((NetBuffer != NULL) && (NetBuffer->Next == NULL));

        //
        // Any packet whose size is less than sizeof(IGMP_HEADER) is rejected. 
        //
        if (NetBuffer->DataLength < sizeof(IGMP_HEADER)) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Dropping IGMP packet : "
                       "Bad header length (%u)\n",
                       NetBuffer->DataLength);
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            continue;
        }
    
        //
        // Verify checksum.
        //
        Checksum = IppChecksumBuffer(NetBuffer, NetBuffer->DataLength);
        if (Checksum != 0xffff) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Dropping IGMP packet with bad checksum\n");
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            continue;
        }

        Interface = Args->DestLocalAddress->Interface;
        IgmpHeader = (IGMP_HEADER*) NetioGetDataBuffer(
            NetBuffer,
            sizeof(IGMP_HEADER),
            &Buffer,
            __builtin_alignof(IGMP_HEADER),
            0);

        //
        // Call the WFP inspection point. 
        //
        Action = IppInspectLocalDatagramsIn(
            IPPROTO_IP,
            (PNL_LOCAL_ADDRESS)Args->DestLocalAddress,
            Args->NlcReceiveDatagram.RemoteAddress,
            (PNL_INTERFACE) Args->SourcePointer->Interface,            
            (Args->IsOriginLocal ? IFI_UNSPECIFIED :
             Args->SourceSubInterface->Index),
            Args->NlcReceiveDatagram.Loopback,
            IPPROTO_IGMP,
            (PTRANSPORT_DATA) &IgmpHeader->VersionType,
            Args->NlcReceiveDatagram.NetworkLayerHeadersSize,
            0,
            IgmpDemux.LocalEndpoint,
            &Args->NlcReceiveDatagram,
            Args->NetBufferList);
        if (Action >= IpFilterDrop) {
            if ((Action == IpFilterDrop) || (Action == IpFilterDropAndSendIcmp)) {
                Ipv4Global.
                    PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                    InFilterDrops++;

                NetioTrace(NETIO_TRACE_RECEIVE, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Inspection point dropped IGMP packet: "
                           "Source %!IPV4! destination %!IPV4!\n", 
                           Args->NlcReceiveDatagram.RemoteAddress,
                           NL_ADDRESS(Args->DestLocalAddress));
                
                Args->NetBufferList->Status = STATUS_FWP_DROP_NOICMP;
                if (Action == IpFilterDropAndSendIcmp) {
                    //
                    // If this is administratively dropped 
                    // send an ICMP error.
                    //
                    Args->NetBufferList->Status = STATUS_ACCESS_DENIED;
                }
            } else {
                ASSERT(Action == IpFilterAbsorb);
            }
            continue;
        }

        if ((IgmpHeader->VersionType == IGMP_VERSION1_REPORT_TYPE) ||
            (IgmpHeader->VersionType == IGMP_VERSION2_REPORT_TYPE)) {
            //
            // Reject reports whose destination address is different from the
            // multicast address in the IGMP header. 
            //
            if (!RtlEqualMemory(&IgmpHeader->MulticastAddress, 
                                NL_ADDRESS(Args->DestLocalAddress), 
                                sizeof(IN_ADDR))) {
                Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
                continue;
            }
            
            //
            // Reject reports that got looped back. Otherwise,
            // an IGMPv1/v2 report sent by us would be processed by us again as
            // if it came from a remote host. 
            //
            if (Args->IsOriginLocal) {
                Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
                continue;
            }
                        
            Args->NetBufferList->Status = IppProcessMulticastDiscoveryReport(
                Interface, 
                (IgmpHeader->VersionType == IGMP_VERSION1_REPORT_TYPE) ?
                MULTICAST_DISCOVERY_VERSION1 : MULTICAST_DISCOVERY_VERSION2,
                (PUCHAR)&IgmpHeader->MulticastAddress);
            continue;
        } else if (IgmpHeader->VersionType != IGMP_QUERY_TYPE) {
            //
            // Don't process IGMP_LEAVE_GROUP_TYPE or IGMP_VERSION3_REPORT_TYPE
            // messages (or any other bad values). We should not receive these
            // messages in any case because they are sent to just the routers
            // (all-routers in case of IGMP_LEAVE_GROUP_TYPE and
            // all-IGMPv3-routers in case of
            // IGMP_VERSION3_REPORT_TYPE). Further, we don't handle IGMPv3
            // reports because reports are relevant only to the IGMPv1 and
            // IGMPv2 protocols. Even if the interface is in IGMPv1/2
            // compatibility mode, it doesn't make sense to process IGMPv3
            // reports because the querier is not going to look at them 
            // either.  
            //
            Args->NetBufferList->Status = STATUS_ARBITRATION_UNHANDLED;
            continue;
        }
        
        //
        // IGMP query.
        //
        ASSERT(IgmpHeader->VersionType == IGMP_QUERY_TYPE);

        //
        // Any packet whose size is not equal to sizeof(IGMP_HEADER) and less
        // than sizeof(IGMPV3_QUERY_HEADER) is rejected.
        //
        if ((NetBuffer->DataLength != sizeof(IGMP_HEADER)) &&
            (NetBuffer->DataLength < sizeof(IGMPV3_QUERY_HEADER))) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Dropping IGMP packet with "
                       "bad header length (%u)\n", 
                       NetBuffer->DataLength);
            Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
            continue;
        }

        if (NetBuffer->DataLength == sizeof(IGMP_HEADER)) {
            //
            // IGMPv1 or IGMPv2 query.
            //
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
                       "IPNG: Received IGMPv1/v2 query\n");
            SourceCount = 0;
            SourceList = NULL;
            MulticastAddress = (PUCHAR)&IgmpHeader->MulticastAddress;
            
            if (IgmpHeader->MaxRespTime == 0) {
                //
                // IGMPv1 query.
                //
                Version = MULTICAST_DISCOVERY_VERSION1;
                MaxResponseTime = DEFAULT_IGMP_QUERY_RESPONSE_TIME;
            } else {
                //
                // IGMPv2 query.
                //
                Version = MULTICAST_DISCOVERY_VERSION2;
                MaxResponseTime = IgmpHeader->MaxRespTime * 100;
            }
            //
            // Fall through. The code below is going to handle the query. 
            //
        } else {
            //
            // IGMPv3 query.
            //
            ASSERT(NetBuffer->DataLength >= sizeof(IGMPV3_QUERY_HEADER));
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_VERBOSE, 
                       "IPNG: Received IGMPv3 query\n");

            if (!Args->RouterAlert) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                           "IPNG: Received IGMP query without router alert option\n");
                Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
                continue;
            }

            Igmpv3QueryHeader = NetioGetDataBuffer(
                NetBuffer, 
                sizeof(IGMPV3_QUERY_HEADER),
                &Buffer, 
                __builtin_alignof(IGMPV3_QUERY_HEADER),
                0);
            
            SourceCount = RtlUshortByteSwap(Igmpv3QueryHeader->SourceCount);
            //
            // There is no danger of overflow because SourceCount in
            // IGMPV3_QUERY_HEADER is a 16 bit while we are doing ULONG
            // computation here. 
            //
            QuerySize = sizeof(IGMPV3_QUERY_HEADER) + 
                (sizeof(IN_ADDR) * SourceCount);

            if (NetBuffer->DataLength < QuerySize) {
                //
                // Reject anything that does not have enough space to contain
                // all the source addresses.
                //
                Args->NetBufferList->Status = STATUS_DATA_NOT_ACCEPTED;
                continue;
            } 
                
            Version = MULTICAST_DISCOVERY_VERSION3;
            
            //
            // Get various parameters from the query message.
            // 
            if (Igmpv3QueryHeader->MaxRespCodeType == 
                IGMP_MAX_RESP_CODE_TYPE_NORMAL) {
                MaxResponseTime = Igmpv3QueryHeader->MaxRespCode * 100;
            } else {
                MaxResponseTime =
                    (((Igmpv3QueryHeader->MaxRespCodeMantissa | 0x10) <<
                      (Igmpv3QueryHeader->MaxRespCodeExponent + 3))) * 100;
            }
            
            //
            // Set the robustness variable in the interface. 
            // 
            Interface->RobustnessVariable = 
                Igmpv3QueryHeader->QuerierRobustnessVariable;
            if ((Interface->RobustnessVariable > MAX_IGMP_ROBUSTNESS) || 
                (Interface->RobustnessVariable == 0)) {
                Interface->RobustnessVariable = DEFAULT_IGMP_ROBUSTNESS;
            }
            
            //
            // Get the multicast address and source address list from the
            // query message. 
            //
            MulticastAddress = (PUCHAR)&Igmpv3QueryHeader->MulticastAddress;
            if (SourceCount > 0) {
                SourceList = NetioGetDataBuffer(NetBuffer, 
                                                QuerySize,
                                                NULL,
                                                1,
                                                0);
                if (SourceList == NULL) {
                    //
                    // The sources were not in contiguous memory. 
                    //
                    SourceListBuffer = ExAllocatePoolWithTag(
                        NonPagedPool, 
                        QuerySize,
                        Ip4BufferPoolTag);
                    if (SourceListBuffer == NULL) {
                        Args->NetBufferList->Status = 
                            STATUS_INSUFFICIENT_RESOURCES;
                        continue;
                    }
                    SourceList = NetioGetDataBuffer(
                        NetBuffer, 
                        QuerySize,
                        SourceListBuffer, 
                        1, 
                        0);
                }
            
                ASSERT(SourceList != NULL);
                SourceList += sizeof(IGMPV3_QUERY_HEADER);
            }
        }
            
        if (RtlEqualMemory(MulticastAddress, 
                           &in4addr_any, 
                           sizeof(IN_ADDR))) {
            MulticastAddress = NULL;
        }
        
        Args->NetBufferList->Status = IppProcessMulticastDiscoveryQuery(
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
}

NTSTATUS
IgmppCreateMulticastDiscoveryReport(
    IN PIP_INTERFACE Interface,
    IN ULONG ReportSize, 
    IN PIP_MULTICAST_RECORD_ENTRY Records, 
    IN OUT PNL_REQUEST_SEND_DATAGRAMS SendArgs
    )
/*++

Routine Description:
    
    This routine creates an IGMP report from the given parameters. It creates
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
    IGMPV3_REPORT_HEADER UNALIGNED *ReportHeader;
    IGMPV3_REPORT_RECORD_HEADER UNALIGNED *ReportRecordHeader;
    IGMP_HEADER UNALIGNED *IgmpHeader;
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
        ASSERT((Version == MULTICAST_DISCOVERY_VERSION1) ||
               (Version == MULTICAST_DISCOVERY_VERSION2));
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
    // IGMPv1 and IGMPv2 reports go to the multicast address of the join. Leave
    // messages go to all routers on link address. All IGMPv3 report messages
    // go to all IGMPv3 routers on link.  
    //
    if (Records->Type == JOIN_GROUP) {
        Destination = MULTICAST_RECORD_ENTRY_GROUP(Records);
    } else if (Records->Type == LEAVE_GROUP) {
        Destination = (UCHAR*)&in4addr_allroutersonlink;
    } else {
        Destination = (UCHAR*)&in4addr_alligmpv3routersonlink;
    }
    
    //
    // Create the packet. 
    // 
    NetBuffer = NetioAllocateNetBuffer(NULL, 0, 0, FALSE);
    if (NetBuffer == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error creating IGMP report: "
                   "Cannot allocate memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ASSERT(NetBuffer->Next == NULL);

    Status = NetioRetreatNetBuffer(
        NetBuffer, 
        ReportSize, 
        sizeof(IPV4_HEADER) + Interface->FlBackfill);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error creating IGMP report: "
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
        
        //
        // REVIEW: Because we are adding the new net buffer list to the
        // beginning of the list instead of the end, this reverses the order in
        // which we send the reports to the router.  Reports created first are
        // sent last.  This matters only when we are sending multiple reports
        // for the same multicast group -- e.g. ALLOW and BLOCK sources or when
        // a report is split into multiple packets. 
        //
        SendArgs->NetBufferList = NetBufferList;
    }
     
    NetBuffer->Next = NetBufferList->FirstNetBuffer;
    NetBufferList->FirstNetBuffer = NetBuffer;
    ReportData = NetioGetDataBufferSafe(NetBuffer, ReportSize);

    if (Version == MULTICAST_DISCOVERY_VERSION3) {
        ReportHeader = (IGMPV3_REPORT_HEADER UNALIGNED *) ReportData;
        RtlZeroMemory(ReportHeader, sizeof(IGMPV3_REPORT_HEADER));
        ReportHeader->Type = IGMP_VERSION3_REPORT_TYPE;
        BytesWritten += sizeof(IGMPV3_REPORT_HEADER);
        
        for (CurrentRecord = Records; 
             CurrentRecord != NULL;
             CurrentRecord = CurrentRecord->Next) {
            ASSERT((CurrentRecord->Type != JOIN_GROUP) &&
                   (CurrentRecord->Type != LEAVE_GROUP));
            RecordCount++;

            ReportRecordHeader = (IGMPV3_REPORT_RECORD_HEADER UNALIGNED *)
                (ReportData + BytesWritten);
            RtlZeroMemory(ReportRecordHeader, 
                          sizeof(IGMPV3_REPORT_RECORD_HEADER));
            ReportRecordHeader->Type = CurrentRecord->Type;
            ReportRecordHeader->SourceCount =
                RtlUshortByteSwap(CurrentRecord->SourceCount);
            RtlCopyMemory(&ReportRecordHeader->MulticastAddress,
                          MULTICAST_RECORD_ENTRY_GROUP(CurrentRecord),
                          sizeof(IN_ADDR));
            BytesWritten += sizeof(IGMPV3_REPORT_RECORD_HEADER);

            RtlCopyMemory(ReportData + BytesWritten, 
                          MULTICAST_RECORD_ENTRY_SOURCE(CurrentRecord, 
                                                        0,
                                                        sizeof(IN_ADDR)),
                          CurrentRecord->SourceCount * sizeof(IN_ADDR));
            BytesWritten += CurrentRecord->SourceCount * sizeof(IN_ADDR);
            ASSERT(BytesWritten <= ReportSize);
        }

        ReportHeader->RecordCount = RtlUshortByteSwap(RecordCount);
        
        ReportHeader->Checksum = IppChecksumBuffer(
            NetBuffer, NetBuffer->DataLength);
    } else {
        IgmpHeader = (IGMP_HEADER UNALIGNED *)ReportData;
        RtlZeroMemory(IgmpHeader, sizeof(IGMP_HEADER));
        if (Version == MULTICAST_DISCOVERY_VERSION2) {
            if (Records->Type == JOIN_GROUP) {
                Destination = (UCHAR*)&IgmpHeader->MulticastAddress;
                IgmpHeader->VersionType = IGMP_VERSION2_REPORT_TYPE;
            } else {
                IgmpHeader->VersionType = IGMP_LEAVE_GROUP_TYPE;
            }
        } else {
            ASSERT(Records->Type == JOIN_GROUP);
            IgmpHeader->VersionType = IGMP_VERSION1_REPORT_TYPE;
        }
        RtlCopyMemory(&IgmpHeader->MulticastAddress,
                      MULTICAST_RECORD_ENTRY_GROUP(Records),
                      sizeof(IN_ADDR));
        BytesWritten += sizeof(IGMP_HEADER);
        ASSERT(BytesWritten <= ReportSize);
        
        IgmpHeader->Checksum = IppChecksumBuffer(
            NetBuffer, NetBuffer->DataLength);
    }
    
    SendArgs->DestProtocol = IPPROTO_IGMP;
    SendArgs->NlCompartment.Id = Interface->Compartment->CompartmentId;
    SendArgs->NlInterface.Index = Interface->Index;
    SendArgs->RemoteAddress = Destination;
    SendArgs->RemoteScopeId = scopeid_unspecified;
    //
    // The lower layer only computes pseudo-header checksums and IGMP
    // does not use pseudo-header checksums, we compute the checksum here
    // instead of offloading it to the lower layer. So, the ChecksumOffset is
    // set to NL_CHECKSUM_OFFSET_NONE. 
    // REVIEW: We can add a way of computing a vanilla non-pseudo header
    // checksum by using a special value for UlChecksumOffset.
    //
    SendArgs->UlChecksumOffset = NL_CHECKSUM_OFFSET_NONE;
    SendArgs->NlSessionState = &IgmpSessionState;
    
    return STATUS_SUCCESS;
}

BOOLEAN
IgmppIsMulticastDiscoveryAllowed(
    IN CONST UCHAR *Address
    )
/*++

Routine Description:

    This routine determines if multicast discovery is allowed for a given
    multicast address. Multicast discovery is allowed for all addresses except
    the all nodes on link mulitcast address. 
    
Arguments:

    Address - Supplies the address to check.

Return Value:

    TRUE if multicast discovery is allowed, FALSE otherwise.

--*/ 
{
    return (!RtlEqualMemory(Address, 
                            &in4addr_allnodesonlink, 
                            sizeof(IN_ADDR)));
}
    
