/*++

Copyright (c) Microsoft Corporation

Module Name:

    common.c

Abstract:

    This is a dummy module containing stubs for common IPsec funcions.
    The IPsec team owns the actual module.

--*/

#include "precomp.h"

#if DBG
#define TEST_IPSEC_HEADERS
#endif

NTSTATUS
IpSecEntry(
    IN PDRIVER_OBJECT DriverObject,
    OUT PDEVICE_OBJECT* DeviceObject,
    OUT PDRIVER_DISPATCH* DevControlDispatchFn
    )
{
   UNREFERENCED_PARAMETER(DriverObject);
   UNREFERENCED_PARAMETER(DeviceObject);
   UNREFERENCED_PARAMETER(DevControlDispatchFn);


   return STATUS_SUCCESS;
}

VOID
IpSecUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{
   UNREFERENCED_PARAMETER(DriverObject);
}

ULONG
IpSecGetOverheadEstimate(
    VOID
    )
{
   return 0;
}

NTSTATUS
IpSecGetSessionInformation(
    __in PVOID PacketHandle,
    __in PVOID RequestContext,
    __in BOOLEAN IsLoopback,
    __in BOOLEAN IsOptionsPresent,                          
    __in IF_LUID* OutgoingIf,                  
    __in UINT32 PathMtu,
    __out PIPSEC_SESSION_INFORMATION IpSecSessionInformation,
    __deref_out_range(0, MAX_IPSEC_HEADERS) PULONG HeaderCount,
    __out_ecount(MAX_IPSEC_HEADERS) PIP_EXTENSION_HEADER_INFORMATION Header
    )
{
   static ULONG Count = 0;

   DBG_UNREFERENCED_PARAMETER(OutgoingIf);
   DBG_UNREFERENCED_PARAMETER(PathMtu);
   DBG_UNREFERENCED_PARAMETER(IsOptionsPresent);
#ifndef TEST_IPSEC_HEADERS
   DBG_UNREFERENCED_PARAMETER(PacketHandle);
   DBG_UNREFERENCED_PARAMETER(RequestContext);
   DBG_UNREFERENCED_PARAMETER(IsLoopback);
   DBG_UNREFERENCED_PARAMETER(Header);

   *HeaderCount = 0;

   RtlZeroMemory(IpSecSessionInformation, sizeof(*IpSecSessionInformation));
#else

   Count++;
   if (Count & 1)
   {
      NTSTATUS Status;
        
      Status = IpGetSessionInformationPend(&RequestContext);
      if (!NT_SUCCESS(Status))
      {
         return Status;
      }

      IpGetSessionInformationComplete(RequestContext,
                                      STATUS_SUCCESS);

      return STATUS_PENDING;
   }

   DBG_UNREFERENCED_PARAMETER(PacketHandle);
   DBG_UNREFERENCED_PARAMETER(IsLoopback);

   Header[0].NextHeader = IPPROTO_ESP;
   Header[0].HeaderLength = sizeof(ESP_HEADER);

#if !defined(TEST_ESP_OVER_UDP)
    //
    // AH Header with 4-bytes of authentication data.
    //
    Header[1].NextHeader = IPPROTO_AH;
    Header[1].HeaderLength = sizeof(AUTHENTICATION_HEADER) + 4;
#else
    Header[1].NextHeader = IPPROTO_UDP;
    Header[1].HeaderLength = sizeof(UDP_HDR);
#endif

   *HeaderCount = 2;

   IpSecSessionInformation->AhAuthenticationDataLength =
       DUMMY_AUTHENTICATION_DATA_SIZE;

   IpSecSessionInformation->EspProcessingType.Authentication =
       TRUE;
   IpSecSessionInformation->EspProcessingType.Confidentiality =
       TRUE;
   IpSecSessionInformation->EspAuthenticationDataLength =
       DUMMY_AUTHENTICATION_DATA_SIZE;
   IpSecSessionInformation->EspBlockSize =
       4;
   IpSecSessionInformation->EspMaxTrailerSize =
       3 + sizeof(ESP_TRAILER) + DUMMY_AUTHENTICATION_DATA_SIZE;
#endif

   return STATUS_SUCCESS;
}

VOID
IpSecDropInboundPacket(
    IN PVOID PacketHandle
    )
{
   DBG_UNREFERENCED_PARAMETER(PacketHandle);
}

VOID
IpSecGetPacketInformation(
    IN PVOID PacketHandle,
    IN ULONG PayloadLength,
    OUT PUINT8 EspPadLength
    )
{
   DBG_UNREFERENCED_PARAMETER(PacketHandle);

   //
   // ESP trailer has an alignment of requirement 4n+2.
   //
   *EspPadLength = (2 - PayloadLength) & 3;
}

VOID
IpSecCleanupSessionInformation(
    IN PVOID PacketHandle
    )
{
   IpSecSetSecurityContext(PacketHandle, NULL);
}

NTSTATUS 
IpSecTranslateInboundSecureUdpEspPacket(
    IN IPPROTO UpperLayerProtocol,
    IN VOID* Packet
    )
/*++

Routine Description:
    This routine is called by the network layer to perform any in-place
    transport protocol-specific translation to enable IPSec NAT-T to work.  
    For example, for UDP it translates the destination port (see the IPsec-NL
    interaction specification for more details).  This routine will only
    be called for IPv4 packets.

Arguments:

    UpperLayerProtocol - Supplies the upper-layer protocol to which the packet
        is about to be delivered.

    Packet - Supplies the packet as a pointer to a NetBufferList. There will be
        a single NetBuffer within the NetBufferList and it's DataOffset will
        be at the end of the ESP header.

Return Value:

    Returns STATUS_SUCCESS on success or some NTSTATUS error otherwise.
    
--*/    
{
   DBG_UNREFERENCED_PARAMETER(UpperLayerProtocol);
   DBG_UNREFERENCED_PARAMETER(Packet);

   return STATUS_SUCCESS;
}

NTSTATUS 
IpSecNLFramedPacketIndication(
    IN NET_BUFFER_LIST * netBufferList, 
    IN IPPROTO protocol, 
    IN VOID * requestContext, 
    IN UINT32 protocolLevel,
    IN IF_LUID* outgoingIf,
    IN UINT32 pathMtu, 
    IN UINT32 extensionHeaderLength, 
    IN UINT32 ipHeaderLength, 
    IN BOOLEAN dontFragment,
    IN ULONG headerCount,
    IN PIP_EXTENSION_HEADER_INFORMATION headers
    )
{
   DBG_UNREFERENCED_PARAMETER(netBufferList);
   DBG_UNREFERENCED_PARAMETER(protocol);
   DBG_UNREFERENCED_PARAMETER(requestContext);
   DBG_UNREFERENCED_PARAMETER(protocolLevel);
   DBG_UNREFERENCED_PARAMETER(outgoingIf);
   DBG_UNREFERENCED_PARAMETER(pathMtu);
   DBG_UNREFERENCED_PARAMETER(extensionHeaderLength);
   DBG_UNREFERENCED_PARAMETER(ipHeaderLength);
   DBG_UNREFERENCED_PARAMETER(dontFragment);
   DBG_UNREFERENCED_PARAMETER(headerCount);
   DBG_UNREFERENCED_PARAMETER(headers);
   return STATUS_SUCCESS;
}

VOID
IPsecCreateReassemblyContext(
   OUT VOID** reassemblyContext
)
{
   DBG_UNREFERENCED_PARAMETER(reassemblyContext);
}

NTSTATUS
IPsecVerifyFragment(
   IN OUT VOID** reassemblyContext,
   IN VOID* fragPacket,
   IN IPPROTO ipProtocol,
   IN CONST UCHAR* sourceAddress,
   IN CONST UCHAR* destAddress
)
{
   DBG_UNREFERENCED_PARAMETER(reassemblyContext);
   DBG_UNREFERENCED_PARAMETER(fragPacket);
   DBG_UNREFERENCED_PARAMETER(ipProtocol);
   DBG_UNREFERENCED_PARAMETER(sourceAddress);
   DBG_UNREFERENCED_PARAMETER(destAddress);
   return STATUS_SUCCESS;
}

VOID
IPsecSetSecurityCtxtOnReassembledPkt(
   IN OUT VOID** reassemblyContext,
   IN OUT VOID* reassembledPacket
)
{
   DBG_UNREFERENCED_PARAMETER(reassemblyContext);
   DBG_UNREFERENCED_PARAMETER(reassembledPacket);
}

VOID
IPsecDestroyReassemblyContext(
   IN OUT VOID** reassemblyContext
)
{
   DBG_UNREFERENCED_PARAMETER(reassemblyContext);
}

VOID 
IpSecCleanupInboundPacketStateGuarded(
   IN VOID* packetHandle
)
{
   DBG_UNREFERENCED_PARAMETER(packetHandle);
}

IP_FILTER_ACTION
IPsecProcessOutboundFragList(
   IN IPPROTO ipProtocol,
   IN VOID* originalNbl,
   IN VOID* fragmentedNbl
)
{
   DBG_UNREFERENCED_PARAMETER(ipProtocol);
   DBG_UNREFERENCED_PARAMETER(originalNbl);
   DBG_UNREFERENCED_PARAMETER(fragmentedNbl);   
   return IpFilterAllow;
}

VOID
IPsecMapTransProtoForInboundPkt(
   IN VOID* packet,
   IN OUT IPPROTO* transProtocol
)
{
   DBG_UNREFERENCED_PARAMETER(packet);
   DBG_UNREFERENCED_PARAMETER(transProtocol);
}

VOID
IPsecRestoreTransProtoForInboundPkt(
   IN VOID* packet,
   IN OUT IPPROTO* transProtocol
)
{
   DBG_UNREFERENCED_PARAMETER(packet);
   DBG_UNREFERENCED_PARAMETER(transProtocol);
}
