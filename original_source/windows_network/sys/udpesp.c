/*++

Copyright (c) 2004  Microsoft Corporation

Module Name:

    udpesp.c

Abstract:

    This module implements functions relating to ESP-over-UDP header 
    processing. This is currently in draft-ietf-ipsec-udp-encaps-09.txt

Author:

    Raymond Sinnappan (RaymondS)   27-September-2004

Environment:

    Kernel mode only

--*/

#include "precomp.h"

IP_INTERNAL_RECEIVE_DATAGRAMS IppReceiveUdpEspList;
IP_INTERNAL_RECEIVE_CONTROL_MESSAGE IppReceiveUdpEspControl;
IP_INTERNAL_ADD_HEADER IppAddUdpEspHeader;

IP_RECEIVE_DEMUX IpUdpEspDemux = {
    IppReceiveUdpEspList, 
    IppReceiveUdpEspControl, 
    NULL,
    NULL,
    IppAddUdpEspHeader,
    TRUE 
};

NETIO_INLINE
NTSTATUS
IppDecomposeUdpPacket(
    IN PNET_BUFFER NetBuffer,
    IN PUCHAR UdpBuffer,        
    IN ULONG UdpPayloadSegmentSizeRequested,
    OUT UDP_HDR UNALIGNED * *UdpHeader,
    OUT PUCHAR* UdpPayloadSegment, 
    OUT PULONG UdpPayloadSegmentSizeReturned
    )
/*++

Routine Description:

    Given a packet, parses it to obtain the UDP header and optionally
    a portion of the payload.

Arguments:

    NetBuffer - Supplies the packet beginning at the UDP header.

    UdpBuffer - Supplies a fallback buffer in case the UDP header
        and payload is not contiguous and hence requires a copy into
        this buffer.  UdpBuffer must have enough space for sizeof(UDP_HDR)
        + UdpPayloadSegmentSizeRequested.

    UdpPayloadSegmentSizeRequested - Supplies the number of initial bytes of 
        the payload required.

    UdpHeader - Returns a pointer to the UDP header; this could be within
        an MDL in NetBuffer if the header was contiguous; otherwise it'd
        point to UdpBuffer.

    UdpPayload - Returns a pointer to the UDP payload; this could be within
        an MDL in NetBuffer if the payload was contiguous; otherwise it'd
        point within UdpBuffer.

    UdpPayloadSegmentSizeReturned - Returns the actual size of the
        payload copied over.  It will be less than or equal to 
        UdpPayloadSegmentSizeRequested.

Return Value:

    Returns 
        STATUS_INVALID_BUFFER_SIZE - if NetBuffer has less data than the
            UDP header size + min(size of payload specified in header, 
            UdpPayloadSegmentSizeRequested). This error is also returned if
            the header length in the UDP header is greater than the data length
            of the NetBuffer supplied.
        STATUS_SUCCESS - on success.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/    
{
    NTSTATUS Status = STATUS_SUCCESS;
    UDP_HDR UNALIGNED *UdpHeaderLocal = NULL;
    PUCHAR UdpPayloadSegmentLocal = NULL; 
    ULONG UdpPayloadSegmentSizeLocal = 0;
    ULONG UdpPayloadSize = 0;
    USHORT LengthInUdpHeader;

    //
    // Get UDP header.
    //

    if (NetBuffer->DataLength < sizeof(UDP_HDR)) {
        Status = STATUS_INVALID_BUFFER_SIZE;
        goto Exit;
    }
    UdpHeaderLocal = (UDP_HDR UNALIGNED *) 
        NetioGetDataBuffer(
            NetBuffer,
            sizeof(UDP_HDR),
            &UdpBuffer,
            1,
            0);

    // 
    // Obtain up to UdpPayloadSegmentSizeRequested bytes from payload.
    //

    LengthInUdpHeader = RtlUshortByteSwap(UdpHeaderLocal->uh_ulen);
    if ((LengthInUdpHeader >= sizeof(UDP_HDR)) &&
        (LengthInUdpHeader <= NetBuffer->DataLength)) {
        UdpPayloadSize = LengthInUdpHeader - sizeof(UDP_HDR);
    } else {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }        
    
    NetioAdvanceNetBuffer(
        NetBuffer,
        sizeof(UDP_HDR));
 
    UdpPayloadSegmentSizeLocal = 
        min(UdpPayloadSize, UdpPayloadSegmentSizeRequested);
    
    UdpPayloadSegmentLocal = UdpBuffer + sizeof(UDP_HDR);
    UdpPayloadSegmentLocal = 
        NetioGetDataBuffer(
            NetBuffer,
            UdpPayloadSegmentSizeLocal,
            UdpPayloadSegmentLocal,
            1,
            0);

    Status = NetioRetreatNetBuffer(
                 NetBuffer,
                 sizeof(UDP_HDR),
                 0);
    ASSERT(NT_SUCCESS(Status));

Exit:
    if (NT_SUCCESS(Status)) {
        *UdpHeader = UdpHeaderLocal;
        *UdpPayloadSegment = UdpPayloadSegmentLocal;
        *UdpPayloadSegmentSizeReturned = UdpPayloadSegmentSizeLocal;
    }

    return Status;
}

BOOLEAN
IppIsUdpEspPacket(
    IN PNET_BUFFER NetBuffer
    )
/*++

Routine Description:

    Given a UDP packet, examines the payload to determine if it's a normal UDP
    or an ESP-over-UDP.

Arguments:

    NetBuffer - Supplies the packet beginning at the UDP header.

Return Value:

    Returns TRUE if it is an ESP-over-UDP packet; FALSE otherwise.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/    
{
    NTSTATUS Status = STATUS_SUCCESS;
    UDP_HDR UNALIGNED * UdpHeader;
    UCHAR UdpBuffer[MAX_IPSEC_UDP_PAYLOAD_REQUIRED + 
        sizeof(UDP_HDR)];
    PUCHAR UdpPayloadSegment;
    ULONG UdpPayloadSegmentLength;

    UdpHeader = (UDP_HDR UNALIGNED *)
        NetioGetDataBuffer(
            NetBuffer,
            sizeof(UDP_HDR),
            NULL,
            1,
            0);

    if ((UdpHeader != NULL) &&
        !IpSecIsInboundUdpPacketIpSecNatT(
            UdpHeader->uh_sport,
            UdpHeader->uh_dport)) {
        return FALSE;
    }

    //
    // Obtain the UDP header and part of the payload.
    //

    Status =
       IppDecomposeUdpPacket(
          NetBuffer,
          UdpBuffer,
          MAX_IPSEC_UDP_PAYLOAD_REQUIRED,
          &UdpHeader,
          &UdpPayloadSegment,
          &UdpPayloadSegmentLength);

    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }
        
    return
       IpSecIsInboundUdpPacketEsp(
           UdpHeader->uh_sport,
           UdpHeader->uh_dport,
           UdpPayloadSegment,
           UdpPayloadSegmentLength);
}

NETIO_INLINE
VOID
NTAPI
IppReceiveUdpEsp(
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Processes an ESP-over-UDP header like an extension header.  It
    also differentiates between a real ESP-over-UDP packet, and
    normal NAT-T keep alive packets.  
  
Arguments:

    Control - Supplies an IP packet.

Return Values:

    Sets the Status value in the NetBufferLIst in Control to:
    - STATUS_MORE_ENTRIES if the header was processed successfully.
    - STATUS_SUCCESS if the packet was a keep-alive packet so that the
      caller will finish processing (equivalent to dropping the packet).
  
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    UDP_HDR UNALIGNED * UdpHeader;
    UCHAR UdpBuffer[MAX_IPSEC_UDP_PAYLOAD_REQUIRED + 
        sizeof(UDP_HDR)];
    PUCHAR UdpPayloadSegment;
    ULONG UdpPayloadSegmentLength;
    
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    PIP_PROTOCOL Protocol = Control->Compartment->Protocol;
    PIP_GLOBAL_STATISTICS GlobalStatistics = 
        &(Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()]);

    //
    // Obtain the UDP header and part of the payload.
    //

    Status = 
        IppDecomposeUdpPacket(
            NetBuffer,
            (PUCHAR) &UdpBuffer,
            MAX_IPSEC_UDP_PAYLOAD_REQUIRED,
            &UdpHeader,
            &UdpPayloadSegment,
            &UdpPayloadSegmentLength);
    
    //
    // This is the second time we are decomposing, and if we succeeded
    // before, we must succeed again.
    //
    ASSERT(NT_SUCCESS(Status));

    if (!IpSecIsInboundUdpEspPacketKeepAlive(
            UdpPayloadSegment,
            UdpPayloadSegmentLength)) {        
        // 
        //  This is an ESP-over-UDP packet so advance past the UDP header
        //  and continue with the remaining header processing.
        //
        Control->IpSecHeadersPresent = TRUE;
        ASSERT(NetBuffer->DataLength >= sizeof(UDP_HDR));
        NetioAdvanceNetBuffer(
            NetBuffer,
            sizeof(UDP_HDR));

        Control->NlcReceiveDatagram.NextHeaderValue = IPPROTO_ESP;
        Control->NlcReceiveDatagram.NetworkLayerHeadersSize += sizeof(UDP_HDR);
        ASSERT(NetBufferList->Status == STATUS_MORE_ENTRIES);
    } else {
        //
        // This is just a keep alive packet so we return success and drop.
        //
        NetBufferList->Status = STATUS_SUCCESS;
        Control->NlcReceiveDatagram.NextHeaderValue = IPPROTO_NONE;
    }

    GlobalStatistics->InIpsecEspOverUdpPackets++;
}

VOID
NTAPI
IppReceiveUdpEspList(
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Processes a packet with an ESP-over-UDP header.  Unlike other functions
    of the form IppReceive*List (E.g. IppReceiveEspList) this function
    does not traverse the list of Control structures and process all
    packets meant for it.  Instead it lets the main calling loop do that.
    This is because additional checks are required to determine if a packet
    is an ESP-over-UDP and due to their complexity it's best to isolate
    them to a few points in code rather than repeating the checks everywhere.
  
Arguments:

    Control - Supplies an IP packet.

Return Value:

    None.

--*/
    
{
    IppReceiveUdpEsp(Control);
}

VOID
IppReceiveUdpEspControl(
    IN PIP_REQUEST_CONTROL_DATA ControlMessage
    )
/*++

Routine Description:

    Handle an ICMP error message in response to an ESP-over-UDP we sent.

Arguments:

    ControlMessage - Supplies information about the message received.

Return Value:

    The Status in the NetBufferList is set to STATUS_SUCCESS 
    to drop the message.

--*/
{
    UNREFERENCED_PARAMETER(ControlMessage);

    ControlMessage->NetBufferList->Status = STATUS_PROTOCOL_UNREACHABLE;
}

NTSTATUS
IppAddUdpEspHeader(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN PNET_BUFFER NetBuffer,
    IN UINT8 NextHeader,
    IN PIP_PACKETIZE_DATA Data
    )
/*++

Routine Description:

    Add a UDP header to an outgoing packet for the purposes
    of ESP-over-UDP.

Arguments:

    Control - Supplies the packet metadata.

    Buffer - Supplies a NetBuffer which already contains space for the 
        UDP header.

    NextHeader - Supplies the NextHeader that follows the UDP header.
        This parameter is unused and will always be IPPROTO_ESP.

    Data - Supplies metadata about the packetization operation.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    UDP_HDR UdpHeader;
    SIZE_T BytesCopied;
    PIP_PROTOCOL Protocol = Control->Compartment->Protocol;
    PIP_GLOBAL_STATISTICS GlobalStatistics = 
        &(Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()]);

    UNREFERENCED_PARAMETER(NextHeader);
    UNREFERENCED_PARAMETER(Data);

    //
    // We don't support adding Authentication of ESP-over-UDP.
    //
    ASSERT(!Data->AhHeaderPresent);

    ASSERT(NextHeader == IPPROTO_ESP);

    IpSecGetSendUdpEspEncapsulationPorts(
        Control->NetBufferList,
        &UdpHeader.uh_sport,
        &UdpHeader.uh_dport);

    UdpHeader.uh_ulen = RtlUshortByteSwap(NetBuffer->DataLength);
    
    //
    // Checksum must be 0 according to draft-ietf-ipsec-udp-encaps-09.txt.
    //
    UdpHeader.uh_sum = 0;

    RtlCopyBufferToMdl(
        &UdpHeader,
        NetBuffer->MdlChain,
        NetBuffer->DataOffset,
        sizeof(UDP_HDR),
        &BytesCopied);

    ASSERT(BytesCopied == sizeof(UDP_HDR));

    GlobalStatistics->OutIpsecEspOverUdpPackets++;

    return STATUS_SUCCESS;
}



