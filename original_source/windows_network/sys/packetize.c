/*++

Copyright (c) 2001-2005  Microsoft Corporation

Module Name:

    packetize.c

Abstract:

    This module implements the protocol-independent functions of the
    Packetizer module.

    NTRAID#931009-2005/01/20-RaymondS:
    Call IppInspectDiscard() upon failure of local sends?

Author:

    Dave Thaler (dthaler) 27-Sep-2001

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "nlmnpip.h"

#pragma warning(disable:4204)   // non-constant aggregate initializer

#define MAX_IPSEC_HEADERS_SIZE 80 // big enough for AH and ESP

VOID
IppPacketizeDatagrams(
    IN PIP_REQUEST_CONTROL_DATA Control
    );

NETIO_INLINE
VOID
IppCleanupSendState(
    IN PIP_REQUEST_CONTROL_DATA Control,
    IN BOOLEAN CleanupIpSec
    )
/*++

Routine Description:
    
    Clean up state used only during packetization.

Arguments:

    Control - Supplies the control structure.

    CleanupIpSec - Supplies TRUE to also cleanup IPSec security context.

Return Value:

    None.
    
--*/    
{
    if (CleanupIpSec &&
        (IpSecGetSecurityContext(Control->NetBufferList) != NULL)) {
        IpSecCleanupSessionInformation(Control->NetBufferList);
    }

    if (Control->HeaderIncludeHeader != NULL) {
        ExFreePool(Control->HeaderIncludeHeader);
        Control->HeaderIncludeHeader = NULL;
    }
    
    if (Control->HopByHopOptions != NULL) {
        ExFreePool(Control->HopByHopOptions);
        Control->HopByHopOptions = NULL;
    }

    if (Control->RoutingHeader != NULL) {
        ExFreePool(Control->RoutingHeader);
        Control->RoutingHeader = NULL;
    }
}

NTSTATUS
IppCopySendState(
    IN PIP_REQUEST_CONTROL_DATA Src,
    OUT PIP_REQUEST_CONTROL_DATA Dst
    )
/*++

Routine Description:
    
    Copy state used only during packetization.

Arguments:

    Src - Old packet to copy from.

    Dst - New packet to copy to.

Return Value:

    NTSTATUS
    
--*/    
{
   Dst->HeaderIncludeHeader = NULL;
   Dst->HopByHopOptions = NULL;
   Dst->RoutingHeader = NULL;

   if (Src->HeaderIncludeHeader != NULL) {
      Dst->HeaderIncludeHeader =
        ExAllocatePoolWithTagPriority(
            NonPagedPool,
            Src->HeaderIncludeHeaderLength,
            IpGenericPoolTag,
            LowPoolPriority);
      if (Dst->HeaderIncludeHeader == NULL) {
         return STATUS_INSUFFICIENT_RESOURCES;
      }
      Dst->HeaderIncludeHeaderLength = Src->HeaderIncludeHeaderLength;
      RtlCopyMemory(
         Dst->HeaderIncludeHeader,
         Src->HeaderIncludeHeader,
         Src->HeaderIncludeHeaderLength);
   }

   if (Src->HopByHopOptions != NULL) {
      Dst->HopByHopOptions =
        ExAllocatePoolWithTagPriority(
            NonPagedPool,
            Src->HopByHopOptionsLength,
            IpGenericPoolTag,
            LowPoolPriority);
      if (Dst->HopByHopOptions == NULL) {
         return STATUS_INSUFFICIENT_RESOURCES;
      }
      Dst->HopByHopOptionsLength = Src->HopByHopOptionsLength;
      RtlCopyMemory(
         Dst->HopByHopOptions,
         Src->HopByHopOptions,
         Src->HopByHopOptionsLength);
   }

   if (Src->RoutingHeader != NULL) {
      Dst->RoutingHeader =
        ExAllocatePoolWithTagPriority(
            NonPagedPool,
            Src->RoutingHeaderLength,
            IpGenericPoolTag,
            LowPoolPriority);
      if (Dst->RoutingHeader == NULL) {
         return STATUS_INSUFFICIENT_RESOURCES;
      }
      Dst->RoutingHeaderLength = Src->RoutingHeaderLength;
      RtlCopyMemory(
         Dst->RoutingHeader,
         Src->RoutingHeader,
         Src->RoutingHeaderLength);
   }

   return STATUS_SUCCESS;
}

NTSTATUS
IpGetSessionInformationPend(
    IN OUT PVOID *RequestContext
    )
/*++

Routine Description:
    
    Invoked by IPSec when a packet needs to be pended for IPSec processing.
    We allocate required resources, deep copy the NetBufferList and reference
    any objects we need to.  
    
Arguments:

    RequestContext - Supplies a context for the send request.
        Returns an updated context.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/ 
{
    PIP_REQUEST_CONTROL_DATA Control =
        (PIP_REQUEST_CONTROL_DATA) *RequestContext;        

    PIP_REQUEST_CONTROL_DATA PendedControl = IppStrongPendPacket(Control);

    if (PendedControl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    *RequestContext = PendedControl;
    return STATUS_SUCCESS;
}

NTSTATUS
IpGetSessionInformationCopy(
    IN OUT PVOID *RequestContext
    )
/*++

Routine Description:
    
    Invoked by IPSec when a packet needs to be copied for subsequent IPSec 
    processing. We allocate required resources, deep copy the NetBufferList and 
    reference any objects we need to.  
    
Arguments:

    RequestContext - Supplies a context for the send request.
        Returns an updated context.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/ 
{
    PIP_REQUEST_CONTROL_DATA Control =
        (PIP_REQUEST_CONTROL_DATA) *RequestContext;        

    PIP_REQUEST_CONTROL_DATA PendedControl = IppStrongCopyPacket(Control);

    if (PendedControl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    *RequestContext = PendedControl;
    return STATUS_SUCCESS;
}

VOID
IpGetSessionInformationComplete(
    IN PVOID RequestContext,
    IN NTSTATUS Status
    )
/*++

Routine Description:
    
    Invoked by IPSec when a pended packet's IPSec processing completes.
    
Arguments:

    RequestContext - Supplies the context for the send request.

    Status - Supplies the status of IPSec processing.
    
Return Value:

    None.
    
Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_REQUEST_CONTROL_DATA Control = 
        (PIP_REQUEST_CONTROL_DATA) RequestContext;
    
    if (!NT_SUCCESS(Status)) {
        if (Control->NetBufferList != NULL) {
            Control->NetBufferList->Status = Status;
        }
        IppCompleteAndFreePacketList(Control, FALSE);
        return;
    }
    
    IppPacketizeDatagrams(Control);
}


VOID* 
IpGetPacketFromRequestContext(
   IN PVOID RequestContext
   )
{
   PIP_REQUEST_CONTROL_DATA Control = 
      (PIP_REQUEST_CONTROL_DATA) RequestContext;
   return Control->NetBufferList;
}   


VOID
IppRemoveTrailer(
    IN PNET_BUFFER NetBuffer
    )
/*++

Routine Description:

    Remove the extra MDL for an ESP trailer at the end of a packet.

--*/
{
    PMDL *NextPointer, Trailer;

    ASSERT(NetBuffer->MdlChain != NULL);
    
    //
    // Find the pointer to the trailing MDL.  The chain might only have 1 MDL.
    //
    for (NextPointer = &NetBuffer->MdlChain;
         (*NextPointer)->Next != NULL;
         NextPointer = &(*NextPointer)->Next);

    Trailer = *NextPointer;

    NetBuffer->DataLength -= MmGetMdlByteCount(Trailer);    

    NetioFreeMdl(Trailer);

    *NextPointer = NULL; 

}

VOID
IppFreeCloneNetBufferListWithTrailer(
    IN PNET_BUFFER_LIST NetBufferListChain,
    IN ULONG Count,
    IN BOOLEAN DispatchLevel
    )
/*++

Routine Description:

    Free a chain of cloned net buffer lists which have trailers appended.

--*/
{
    PNET_BUFFER_LIST NetBufferList;
    PNET_BUFFER NetBuffer, Marker;
    
    UNREFERENCED_PARAMETER(Count);

    while ((NetBufferList = NetBufferListChain) != NULL) {
        //
        // Move to the next NetBufferList before freeing the current.
        //
        NetBufferListChain = NetBufferList->Next;
        
        //
        // Remove and free all the trailers.
        //
        Marker = (PNET_BUFFER)
            NetioQueryNetBufferListCompletionContext(NetBufferList);

        for (NetBuffer = NetBufferList->FirstNetBuffer;
             NetBuffer != Marker;
             NetBuffer = NetBuffer->Next) {
            NetioRestoreNetBuffer(NetBuffer);
            IppRemoveTrailer(NetBuffer);
        }

        for (NetBuffer = Marker;
             NetBuffer != NULL;
             NetBuffer = NetBuffer->Next) {
            NetioRestoreNetBuffer(NetBuffer);
        }

        //
        // Now it's a normal clone that we can free.
        //
        NetioFreeCloneNetBufferList(NetBufferList, DispatchLevel);
    }
}

NETIO_INLINE
NTSTATUS
IppFillFirstHeaderIncludeHeader(
    PUCHAR IpHeader,
    IN PNET_BUFFER NetBuffer,
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    OUT PUCHAR *FirstIpHeader,
    IN ULONG HeaderLength,
    IN UINT8 NextHeader
    )
/*++

Routine Description:
    
    Add the IP header.  The IP header should already be contiguous and aligned.
    
    Called for the 1st NetBuffer in a NetBufferList for header-include sends.

Arguments:

    IpHeader - Supplies a contiguous buffer to write to.    

    NetBuffer - Supplies the NetBuffer to which to add the IP header.
        
    Protocol - Supplies the protocol.

    Control - Supplies the control structure.
    
    FirstIpHeader - Returns the filled in IP header to be used subsequently.
    
    HeaderLength - Supplies the length of the IP header (perhaps with options).

    NextHeader - Supplies the next header value.
    
Return Value:

    STATUS_SUCCESS or failure code.

--*/    
{

    ASSERT(Control->HeaderInclude);

    ASSERT(Control->HeaderIncludeHeaderLength == HeaderLength);
    RtlCopyMemory(IpHeader, Control->HeaderIncludeHeader, HeaderLength);    
        
    Protocol->FillHeaderIncludeProtocolHeader(
        Control,
        IpHeader,
        NetBuffer,
        HeaderLength,
        NextHeader);

    *FirstIpHeader = IpHeader;
    
    return STATUS_SUCCESS;
}

NETIO_INLINE
VOID
IppInitializeOnStackControlForLocalSend(
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN NL_CLIENT_DISPATCH_FLAGS ClientFlags,
    IN PNET_BUFFER_LIST NetBufferList
    )
/*++
Routine Description:
    
    Initialize the Control structure for use with local sends.

Arguments:

    Control - Supplies the control structure.
    ClientFlags - Supplies TL client's send defaults.
    NetBufferList - Supplies a list of packets (NB).
    
Return Value:

    None.

--*/    
{
    //
    // Initialize the Control structure.
    //
    ASSERT(!Control->IsAllocated);    
    Control->IsOriginLocal = TRUE;
    Control->OnSendPath = TRUE;

    //
    // Set up the defaults.
    //
    Control->HopLimit = IP_UNSPECIFIED_HOP_LIMIT;
    Control->TypeOfService = (UINT8) IP_UNSPECIFIED_TYPE_OF_SERVICE;
    ASSERT(Control->HeaderIncludeHeader == NULL);
    ASSERT(Control->RoutingHeader == NULL);
    ASSERT(Control->HopByHopOptions == NULL);
    ASSERT(Control->CurrentDestinationAddress == NULL);

    Control->Flags.DontFragment =
        ClientFlags.DefaultDontFragment;
    Control->EnforceHeaderIncludeChecks =
        ClientFlags.EnforceHeaderIncludeChecks;    
    
    Control->NetBufferList = NetBufferList;
}

NETIO_INLINE
NTSTATUS    
IppGetContiguousIpHeader(
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN PNET_BUFFER *NetBuffer,
    IN ULONG HeaderLength,
    IN ULONG Backfill,
    OUT PUCHAR *IpHeader,
    OUT PUCHAR *FirstIpHeader
    )    
/*++
Routine Description:
    
    This function retrieves a contiguous IP header from the Net Buffer.
    If the IP header is not contiguous it clones the Net Buffer List and 
    returns the contiguous IP header from the clone.

Arguments:

    Protocol - Supplies the backfill required for framing layer headers.   

    Control - Supplies the control structure.

    NetBuffer - Supplies the NetBuffer to which to add the IP header.
    
    HeaderLength - Supplies the length of the IP header (perhaps with options).        
            
    Backfill - Supplies the backfill required for framing layer headers.

    IpHeader - Returns the buffer that can be used to fill IP header.

    FirstIpHeader - Returns the filled in IP header to be used subsequently.
    
Return Value:

    STATUS_SUCCESS or failure code.

--*/        
{
    NTSTATUS Status;
    PNET_BUFFER_LIST Clone;
    PNET_BUFFER LocalNetBuffer = NULL;
    PNET_BUFFER CloneNetBuffer = NULL;

    //
    // Retreat by the IP header length and interface backfill.
    // NDIS expects a contiguous MAC header.
    //
    Status = NetioRetreatNetBuffer(*NetBuffer, HeaderLength + Backfill, 0);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    *IpHeader = 
        NetioGetDataBufferIfSafe(
            *NetBuffer, 
            HeaderLength + Backfill,
            Protocol->HeaderAlignment,
            0);
    
    if (*IpHeader == NULL) {
        PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;

        //
        // Advance the NetBuffer so we are again just past the IP header + MAC header.
        //
        NetioAdvanceNetBuffer(*NetBuffer, HeaderLength + Backfill);
        
        //
        // Clone the NetBufferList.
        //
        Clone = 
            NetioAllocateAndReferenceCloneNetBufferList(NetBufferList, FALSE);
        if (Clone == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        IppCopyNetBufferListInfo(Clone, NetBufferList);
        Control->NetBufferList = Clone;

        //
        // Get to the Net Buffer that is not contiguous. The ones before that 
        // are contiguous
        //
        CloneNetBuffer = Clone->FirstNetBuffer;
        for (LocalNetBuffer = NetBufferList->FirstNetBuffer; 
            LocalNetBuffer != NULL;
            LocalNetBuffer = LocalNetBuffer->Next,
            CloneNetBuffer = CloneNetBuffer->Next) {
            if(*NetBuffer == LocalNetBuffer) {
                *NetBuffer = CloneNetBuffer;
                break;
            }
        }

        ASSERT(LocalNetBuffer != NULL);
        
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
        
        //
        // The IP header + MAC header is now guaranteed to be contiguous 
        // and aligned.
        Status = NetioRetreatNetBuffer(*NetBuffer, HeaderLength, Backfill);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        *IpHeader = NetioGetDataBufferSafe(*NetBuffer, HeaderLength); 

        //
        // Copy the 1st IP header since we cloned.
        //
        *FirstIpHeader = 
            NetioGetDataBufferSafe(Clone->FirstNetBuffer, HeaderLength);
    } else {
        //
        // Advance past the framing header backfill.
        //
        NetioAdvanceNetBuffer(*NetBuffer, Backfill);
        *IpHeader = NetioGetDataBufferSafe(*NetBuffer, HeaderLength); 
    }        
    return Status;
}


NETIO_INLINE
NTSTATUS
IppFillFirstHeader(
    IN ULONG Backfill,
    IN PNET_BUFFER *NetBuffer,
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    OUT PUCHAR *FirstIpHeader,
    IN ULONG HeaderLength,
    IN UINT8 NextHeader
    )
/*++

Routine Description:
    
    Add the IP header.  Ensure that the IP header is contiguous and aligned.
    If not, clone the NetBufferList and release the reference on the original.
    
    Called for the first NetBuffer in a NetBufferList on the send path.

Arguments:

    Backfill - Supplies the backfill required for framing layer headers.    

    NetBuffer - Supplies the NetBuffer to which to add the IP header.
        
    Protocol - Supplies the protocol.

    Control - Supplies the control structure.
    
    FirstIpHeader - Returns the filled in IP header to be used subsequently.
    
    HeaderLength - Supplies the length of the IP header (perhaps with options).

    NextHeader - Supplies the next header value.
    
Return Value:

    STATUS_SUCCESS or failure code.

--*/    
{
    NTSTATUS Status;
    PUCHAR IpHeader;

    //
    // Check if the IP header is contiguous and properly aligned. 
    //
    Status = 
        IppGetContiguousIpHeader(
            Protocol,
            Control,
            NetBuffer, 
            HeaderLength,
            Backfill, 
            &IpHeader,
            FirstIpHeader);    
    if (!NT_SUCCESS(Status)) {
        return Status;
    } 
    
    if (Control->HeaderInclude) {
        return
            IppFillFirstHeaderIncludeHeader(
                IpHeader,
                *NetBuffer,
                Protocol,
                Control,
                FirstIpHeader,
                HeaderLength,
                NextHeader);
    }    
    
    Status =
        Protocol->FillProtocolHeader(
            Control,
            IpHeader, 
            *NetBuffer, 
            HeaderLength, 
            NextHeader);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }    
    return STATUS_SUCCESS;
}


NETIO_INLINE
NTSTATUS
IppFillNextHeader(
    IN ULONG Backfill,
    IN PNET_BUFFER *NetBuffer,
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN PUCHAR *FirstIpHeader,
    IN ULONG HeaderLength
    )
/*++

Routine Description:
    
    Add the IP header.  The IP header should already be contiguous and aligned.

    Called for all (except 1st) NetBuffers in a NetBufferList on the send path.

Arguments:

    Backfill - Supplies the backfill required for framing layer headers.
    
    NetBuffer- Supplies the NetBuffer to which to add the IP header.

    Protocol - Supplies the protocol.

    Control - Supplies the control structure.
    
    FirstIpHeader - Supplies the first filled in IP header.
    
    HeaderLength - Supplies the length of the IP header (perhaps with options).

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    NTSTATUS Status;
    PUCHAR IpHeader = NULL;

    //
    // Check if the IP header is contiguous and properly aligned. 
    //
    Status = 
        IppGetContiguousIpHeader(
            Protocol,
            Control,
            NetBuffer, 
            HeaderLength,
            Backfill, 
            &IpHeader,
            FirstIpHeader);    

    if (!NT_SUCCESS(Status)) {
        return Status;
    } 
    
    RtlCopyMemory(IpHeader, *FirstIpHeader, HeaderLength);
    
    Protocol->UpdateProtocolHeader(Control, IpHeader, *NetBuffer);
    return STATUS_SUCCESS;
}


__inline
VOID
IppTruncateTrailer(
    IN PNET_BUFFER_LIST NetBufferList,
    IN PNET_BUFFER NetBuffer,
    IN OUT PIP_PACKETIZE_DATA PacketizeData
    )
/*++

Routine Description:

    Truncate the ESP trailer.
    
Arguments:

    NetBuffer - Supplies the NetBuffer.

    NetBufferList - Supplies the NetBufferList.

    PacketizeData - Supplies the packetize data.
    
Return Value:

    None.
    
--*/ 
{
    ULONG TrailerLength;

    //
    // Get the actual amount of padding needed given the payload size.
    //
    IpSecGetPacketInformation(
        NetBufferList,
        NetBuffer->DataLength - PacketizeData->EspMaxTrailerSize,
        &PacketizeData->EspPadLength);

    TrailerLength = 
        (PacketizeData->EspPadLength +
         sizeof(ESP_TRAILER) +
         PacketizeData->EspAuthenticationDataLength);

    //
    // Throw away any spare trailer space now.
    //
    ASSERT(PacketizeData->EspMaxTrailerSize >= TrailerLength);
    if (PacketizeData->EspMaxTrailerSize > TrailerLength) {
        NetioTruncateNetBuffer(
            NetBuffer,
            PacketizeData->EspMaxTrailerSize - TrailerLength);
    }
    
#if DBG
    {
        //
        // Ensure that the Authentication Data will be 4-byte aligned [RFC2406].
        //
        ULONG PayloadLength =
            NetBuffer->DataLength - PacketizeData->EspAuthenticationDataLength;
        ASSERT((PayloadLength % 4) == 0);
    }
#endif // DBG
}

NTSTATUS
IppComputeHeaderLengthAndFillExtensionHeaders(
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN OUT IP_EXTENSION_HEADER_INFORMATION ExtensionHeader [],
    OUT PULONG IpHeaderLength,
    OUT PULONG ExtensionHeaderCount,
    OUT PULONG ExtensionHeaderLength
    )
/*++

Routine Description:

    Compute IPv4/IPv6 header length and the total extension header length.
    For header include sends, any extension headers are considered part of
    the IPv4/IPv6 header.  Otherwise, use control information to determine
    what extension headers need to be inserted (e.g. routing header).

Arguments:

    Protocol - Supplies the protocol.

    Control - Supplies the control structure.

    ExtensionHeader - Array to fill ext. headers into.

    IpHeaderLength - Length of IPv4/IPv6 header including extension headers.

    ExtensionHeaderCount - # of ext.headers.

    ExtensionHeaderLength - Length of total ext. headers.
    
Return Value:

    STATUS_SUCCESS or failure code.
    
--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;

    PIP_EXTENSION_HEADER_INFORMATION Header;
    PNET_BUFFER NetBuffer;

    //
    // Compute IPv4/IPv6 header length and the total extension header length.
    // For header include sends, any extension headers are considered part of
    // the IPv4/IPv6 header.  Otherwise, use control information to determine
    // what extension headers need to be inserted (e.g. routing header).
    //
    if (Control->HeaderInclude) {
        (*IpHeaderLength) = Control->HeaderIncludeHeaderLength;
    } else {
        (*IpHeaderLength) = Protocol->HeaderSize;
        
        //
        // TODO: Destination options.
        //

        if (IS_IPV4_PROTOCOL(Protocol)) {
            //
            // IPv4: Update IpHeaderLength since IPv4 header includes options.
            //
            (*IpHeaderLength) += 
                ALIGN_UP(
                    Control->HopByHopOptionsLength + 
                    Control->RoutingHeaderLength,
                    UINT32);
        } else {
            USHORT HopByHopOptionsLength;
            BOOLEAN Jumbogram, JumbogramCheck;
            ULONG Mtu;
            PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO SendOffload;

            SendOffload = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)
                &NET_BUFFER_LIST_INFO(
                    Control->NetBufferList,
                    TcpLargeSendNetBufferListInfo);

            //
            // Routing Header:
            //
            if (Control->RoutingHeader != NULL) {
                Header = &ExtensionHeader[(*ExtensionHeaderCount)++];
                Header->NextHeader = IPPROTO_ROUTING;
                Header->HeaderLength = Control->RoutingHeaderLength;
                (*ExtensionHeaderLength) += Control->RoutingHeaderLength;
            }

            // 
            // Hop-by-hop options:
            //
            NetBuffer = Control->NetBufferList->FirstNetBuffer;

            if ((SendOffload->Value == 0) &&
                ((NetBuffer->DataLength + (*ExtensionHeaderLength)) >
                MAX_IPV6_PAYLOAD)) {
                Mtu = IppGetMtuFromNextHop(Control->NextHop);                
                if (Mtu > MAX_IPV6_PAYLOAD) {
                    Jumbogram = TRUE;
                } else {
                    //
                    // Jubograms must not be combined with Fragment headers
                    // (RFC2675 sec. 3)
                    //
                    Status = STATUS_DATA_NOT_ACCEPTED;
                    goto Bail;
                }
            } else {
                Jumbogram = FALSE;
            }                    
                    
            
            //
            // IPv6: HopByHop options header is required if specified in the
            // control structure (ancillary data or session state) or if the
            // payload length of the packets is greater than MAX_IPV6_PAYLOAD.
            //
            if ((Control->HopByHopOptions != NULL) || Jumbogram) {
                //
                // We don't support both user and system specified options.
                //
                if ((Control->HopByHopOptions != NULL) && Jumbogram) {
                    Status = STATUS_DATA_NOT_ACCEPTED;
                    goto Bail;
                }
                
                if (SendOffload->Value == 0) {
                    //
                    // We do not support a mix of jumbograms and normal NetBuffers.
                    //
                    while ((NetBuffer = NetBuffer->Next) != NULL) {

                        JumbogramCheck = 
                            ((NetBuffer->DataLength + (*ExtensionHeaderLength)) >
                             MAX_IPV6_PAYLOAD);
                        
                        if (JumbogramCheck != Jumbogram) {
                            Status = STATUS_DATA_NOT_ACCEPTED;
                            goto Bail;
                        }
                    }
                }
                
                if (Control->HopByHopOptions != NULL) {
                    HopByHopOptionsLength = Control->HopByHopOptionsLength;
                } else {
                    HopByHopOptionsLength = 
                        sizeof(IPV6_EXTENSION_HEADER) +
                        sizeof(IPV6_OPTION_JUMBOGRAM);                    
                }

                if (Jumbogram) {
                    Control->JumbogramHopByHopOptionsLength += 
                        HopByHopOptionsLength; 
                }

                Header = &ExtensionHeader[(*ExtensionHeaderCount)++];
                Header->NextHeader = IPPROTO_HOPOPTS;
                Header->HeaderLength = HopByHopOptionsLength;
                (*ExtensionHeaderLength) += HopByHopOptionsLength;
            }
        }
    }

    //
    // We need to store this information so that it can be passed on to WFP.
    //
    Control->IpHeaderAndExtensionHeadersLength = 
        (*ExtensionHeaderLength) + (*IpHeaderLength);

Bail:
    return Status;
}

VOID
IppPacketizeDatagrams(
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Compose network layer headers for each NetBuffer in the NetBufferList.

    Consumes the Control structure and its NetBufferList.

Arguments:

    Control - Supplies the control structure.

Return Value:

    None.
    
Caller IRQL:

    Callable at PASSIVE through DISPATCH.

--*/
{   
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_INTERFACE Interface = Control->NextHop->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    ULONG PacketCount = IppGetPacketCount(Control->NetBufferList);
    BOOLEAN IpSecRequired =
        (IpSecGetSecurityContext(Control->NetBufferList) != NULL);
    PNET_BUFFER NetBuffer;
    ULONG Backfill, IpHeaderLength;
    PUCHAR FirstIpHeader = NULL;

    //
    // The ExtensionHeader array needs to be big enough to hold the following:
    // 1. IPv6 Hop-by-Hop Options header 
    // 2. Routing Header
    // 3. MAX_IPSEC_HEADERS (for IPsec)
    // 4. Destination Options header
    // The elements in the array are placed in the reverse order.
    // ExtensionHeaders[0] is the innermost header, and
    // ExtensionHeaders[ExtensionHeaderCount - 1] is the outermost header.
    //
    ULONG i, ExtensionHeaderLength = 0, ExtensionHeaderCount = 0, IpSecExtensionHeaderLength =0;
    IP_EXTENSION_HEADER_INFORMATION ExtensionHeader[MAX_IPSEC_HEADERS + 3];
    PIP_EXTENSION_HEADER_INFORMATION Header;
    IP_PACKETIZE_DATA PacketizeDataBuffer;
    PIP_PACKETIZE_DATA PacketizeData = &PacketizeDataBuffer;    

    //
    // Call IpSecGetSessionInformation to get IPSec related information.
    // Note: IPSec can pend the request.
    //
    if (IpSecRequired) {
        Control->Flags.UseIpSec = TRUE;

        RtlZeroMemory(PacketizeData, sizeof(*PacketizeData));

        Status =
            IpSecGetSessionInformation(
                Control->NetBufferList,
                Control,
                IppIsNextHopLocalAddress(Control->NextHop),
                ((Control->RoutingHeader != NULL) ||
                (Control->HopByHopOptions != NULL)  ||
                (Control->HeaderIncludeHeaderLength > sizeof(IPV4_HEADER))),
                &Control->NextHop->Interface->Luid,
                (Control->Path == NULL) 
                ?IppGetMtuFromNextHop(Control->NextHop) 
                :Control->Path->PathMtu,
                (PIPSEC_SESSION_INFORMATION) PacketizeData,
                &ExtensionHeaderCount,
                ExtensionHeader);

        if (Status == STATUS_PENDING) {
            //
            // Control and NetBufferList were both copied & pended.
            // The completion routine will invoke IppPacketizeDatagrams again.
            //
            return;
        }

        ASSERT(ExtensionHeaderCount <= MAX_IPSEC_HEADERS);
        
        if (!NT_SUCCESS(Status)) {
            Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                OutIpsecErrors++;
            goto Bail;
        }

        //
        // Compute the length of the IPSec extension headers.
        // This is useful later on for allocating the right amount of backfill.
        //
        for (i = 0; i < ExtensionHeaderCount; i++) {
            ExtensionHeaderLength += ExtensionHeader[i].HeaderLength;
            IpSecExtensionHeaderLength += ExtensionHeader[i].HeaderLength;
        }
    }

    //
    // Adjust OutRequests once IPSec has had the opportunity to pend packets.
    // This ensures that each packet gets counted exactly once.
    //
    Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        OutRequests += PacketCount;

    Status = IppComputeHeaderLengthAndFillExtensionHeaders(
                Protocol,
                Control,
                ExtensionHeader,
                &IpHeaderLength,
                &ExtensionHeaderCount,
                &ExtensionHeaderLength
                );
    if (!NT_SUCCESS(Status)) {
        goto Bail;
    }

    //
    // We now know the exact amount of backfill required.
    //
    Backfill = Control->IpHeaderAndExtensionHeadersLength 
        + Interface->FlBackfill;
    //
    // Prepare the NetBufferList for IPSec processing. 
    //
    if (IpSecRequired) {
        PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;

        ASSERT(PacketizeData->EspBlockSize <= MAX_IPSEC_BLOCK_SIZE);

        Status = IpSecNLFramedPacketIndication(
                     NetBufferList,
                     Control->DestinationProtocol,
                     Control,
                     Protocol->Level,
                     &Control->NextHop->Interface->Luid,
                     (Control->Path == NULL) 
                     ?IppGetMtuFromNextHop(Control->NextHop) :Control->Path->PathMtu,
                     ExtensionHeaderLength - IpSecExtensionHeaderLength,
                     IpHeaderLength,
                     Control->Flags.DontFragment,
                     ExtensionHeaderCount,
                     ExtensionHeader
                     );
        
        if (!NT_SUCCESS(Status)) {
            Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
                OutIpsecErrors++;
            goto Bail;
        }
        
        if (PacketizeData->EspMaxTrailerSize > 0) {
            PNET_BUFFER_LIST NewNetBufferList;
            PNET_BUFFER NewNetBuffer;

            //
            // We'll need to append an ESP trailer.
            //
            if (PacketizeData->EspProcessingType.Confidentiality) {
                //
                // We need a writable payload area.  Create a brand new
                // packet with space for EspMaxTrailerSize more bytes.
                //
                NewNetBufferList =
                    NetioAllocateAndReferenceVacantNetBufferList(
                        NetBufferList,
                        Backfill,
                        PacketizeData->EspMaxTrailerSize,
                        TRUE,
                        TRUE, //Copy data from original to new.
                        FALSE);
                if (NewNetBufferList == NULL) {
                    Status = STATUS_DATA_NOT_ACCEPTED;
                    goto Bail;
                }

                // REVIEW: Rather than copying all the data, we could
                // conceivably keep both buffers and walk them in
                // parallel, passing an input buffer and an output
                // buffer to IPsec.  Since that would be a lot of extra
                // complexity, for now we just copy the whole thing.
                //
                IppCopyNetBufferListInfo(NewNetBufferList, NetBufferList);
                NetioDereferenceNetBufferList(NetBufferList, FALSE);
                Control->NetBufferList = NewNetBufferList;                        
            } else {
                //
                // We can share the payload with the original buffer.
                //
                BOOLEAN CloneForEsp = FALSE;
                //
                // This optimization for ESP auth works only when a path 
                // entry has been created. If there is no path skip the optimization.
                //
                if (Control->Path == NULL) {
                    CloneForEsp = TRUE;
                } else {
                    Control->Path->Flags.EspAuthenticationOnly = TRUE;                
                    for (NetBuffer = NetBufferList->FirstNetBuffer; 
                        NetBuffer != NULL; 
                        NetBuffer = NetBuffer->Next) {

                        PNETIO_NET_BUFFER_CONTEXT Context = (PNETIO_NET_BUFFER_CONTEXT)
                            NET_BUFFER_PROTOCOL_RESERVED(NetBuffer);
                
                        if (!Context->EspTrailerSpaceAllocated ||
                            Context->TruncatedLength < PacketizeData->EspMaxTrailerSize) {
                            //
                            // Restore all NetBuffers to their original state.                        
                            //                                                                                                 
                            PNET_BUFFER Iterator;
                            ASSERT(!Context->EspTrailerSpaceAllocated);
                            for (Iterator = NetBufferList->FirstNetBuffer;
                                Iterator != NetBuffer;
                                Iterator = Iterator->Next) {
                                NetBuffer->DataLength -= PacketizeData->EspMaxTrailerSize;    
                                Context->TruncatedLength += PacketizeData->EspMaxTrailerSize;
                            }               
                            CloneForEsp = TRUE;                            
                            break;                            
                        } else {
                            NetBuffer->DataLength += PacketizeData->EspMaxTrailerSize;
                            Context->TruncatedLength -= PacketizeData->EspMaxTrailerSize;
                        }                    
                    }
                }
                
                if (CloneForEsp) {
                    NewNetBufferList =
                        NetioAllocateAndReferenceCloneNetBufferListEx(
                            NetBufferList,
                            IppFreeCloneNetBufferListWithTrailer,
                            NULL,
                            FALSE);
                    if (NewNetBufferList == NULL) {
                        Status = STATUS_DATA_NOT_ACCEPTED;
                        goto Bail;
                    }
                    
                    for (NewNetBuffer = NewNetBufferList->FirstNetBuffer; 
                         NewNetBuffer != NULL; 
                         NewNetBuffer = NewNetBuffer->Next) {
                        PMDL NewMdl;
                        ULONG ByteCount = PacketizeData->EspMaxTrailerSize;
                        
                        //
                        // Allocate another MDL for the trailer with space
                        // for EspMaxTrailerSize more bytes.
                        //
                        NewMdl = NetioAllocateMdl(&ByteCount);
                        if (NewMdl == NULL) {
                            //
                            // Remember the first NetBuffer with no trailer.
                            //
                            NetioUpdateNetBufferListContext(
                                NewNetBufferList,
                                IppFreeCloneNetBufferListWithTrailer,
                                NewNetBuffer);

                            NetioDereferenceNetBufferList(NewNetBufferList, FALSE);

                            Status = STATUS_DATA_NOT_ACCEPTED;
                            goto Bail;
                        }

                        //
                        // We don't need more trailer space than what we asked for.
                        //
                        NewMdl->ByteCount = PacketizeData->EspMaxTrailerSize;
                        
                        //
                        // Chain the new MDL after the last existing MDL.
                        //
                        NetioExpandNetBuffer(
                            NewNetBuffer,
                            NewMdl,
                            PacketizeData->EspMaxTrailerSize); 
                    }
                    IppCopyNetBufferListInfo(NewNetBufferList, NetBufferList);
                    NetioDereferenceNetBufferList(NetBufferList, FALSE);
                    Control->NetBufferList = NewNetBufferList;                        
                }
            }                
        }
    }

    //
    // Insert network-layer headers.
    //
    for (NetBuffer = Control->NetBufferList->FirstNetBuffer; 
         NetBuffer != NULL; 
         NetBuffer = NetBuffer->Next) {

        ULONG NextBackfill = Backfill;
        UINT8 NextHeader = (UINT8) Control->DestinationProtocol;
        
        if (IpSecRequired && (PacketizeData->EspMaxTrailerSize > 0)) {
            IppTruncateTrailer(
                Control->NetBufferList,
                NetBuffer,
                PacketizeData);
        }

        //
        // Insert all extension headers first.
        //
        for (i = 0; i < ExtensionHeaderCount; i++) {
            PIP_INTERNAL_ADD_HEADER AddHeader;
            
            Header = &ExtensionHeader[i];
            
            NextBackfill -= Header->HeaderLength;
            
            Status =
                NetioRetreatNetBuffer(
                    NetBuffer,
                    Header->HeaderLength,
                    NextBackfill);
            if (!NT_SUCCESS(Status)) {
                goto Bail;
            }

            if (Header->NextHeader == IPPROTO_UDP) {
                //
                // IPSec requested UDP as an extension header for ESP-over-UDP.
                //
                ASSERT(IpSecRequired && (NextHeader == IPPROTO_ESP));
                AddHeader = IpUdpEspDemux.InternalAddHeader;
            } else {
                AddHeader = Protocol->ReceiveDemux[Header->NextHeader].
                    InternalAddHeader;
            }    

            Status = AddHeader(Control, NetBuffer, NextHeader, PacketizeData);
            if (!NT_SUCCESS(Status)) {
                goto Bail;
            }
            
            NextHeader = Header->NextHeader;
        }

        //
        // And then insert the IP header.
        //
        ASSERT(NextBackfill == (IpHeaderLength + Interface->FlBackfill));

        if (FirstIpHeader == NULL) {
            //
            // While filling the first header, we might end up making a clone.
            //
            Status =
                IppFillFirstHeader(
                    Interface->FlBackfill,
                    &NetBuffer,
                    Protocol,
                    Control,
                    &FirstIpHeader,
                    IpHeaderLength,
                    NextHeader);
        } else {
            Status =
                IppFillNextHeader(
                    Interface->FlBackfill,
                    &NetBuffer,
                    Protocol,
                    Control,
                    &FirstIpHeader,
                    IpHeaderLength);
        }
        
        if (!NT_SUCCESS(Status)) {
            goto Bail;
        }
        
        if (IpSecRequired) {
            if (PacketizeData->AhHeaderPresent) {
                //
                // Fill AuthenticationData now that the packet is fully formed.
                //
                Status =
                    IppAuthenticatePacket(
                        Protocol, Control, NetBuffer, PacketizeData);
                if (!NT_SUCCESS(Status)) {
                    goto Bail;
                }
            }
        }
    }

    ASSERT(NT_SUCCESS(Control->NetBufferList->Status));
    IppCleanupSendState(Control, IppIsNextHopLocalAddress(Control->NextHop));
    IppDispatchSendPacketHelper(Protocol, Control);
    return;

Bail:
    Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        OutDiscards += PacketCount;

    ASSERT(!NT_SUCCESS(Status));
    Control->NetBufferList->Status = Status;
    IppCleanupSendState(Control, TRUE);
    IppCompleteAndFreePacketList(Control, FALSE);
}


UINT16
IppChecksumDatagram(
    IN PNET_BUFFER NetBuffer,
    IN ULONG DataLength,
    IN CONST UCHAR *Source OPTIONAL,
    IN CONST UCHAR *Destination OPTIONAL,
    IN ULONG AddressLength,
    IN ULONG NextHeader,
    IN ULONG PartialPseudoHeaderChecksum OPTIONAL
    )
/*++

Routine Description:

    Calculates the checksum of packet data.
    Also calculates and adds-in the pseudo-header checksum.
    Because of the pseudo-header layout of IPv4 and IPv6,
    the same algorithm works for both.  

    Following are valid use of this function:

    1. Pseudo-header checksum only:
    No NetBuffer.
    Supply PartialPseudoHeaderChecksum or (Source, Destination, NextHeader).
    e.g. Filling in PseudoHeaderChecksum when TCP checksum is offloaded.

    2. NetBuffer checksum only:
    Supply NetBuffer.
    No PartialPseudoHeaderChecksum or (Source, Destination, NextHeader).
    e.g. ICMPv4.
    
    3. Pseudo-header and NetBuffer checksum:
    Supply NetBuffer.
    Supply PartialPseudoHeaderChecksum or (Source, Destination, NextHeader).
    e.g. ICMPv6.

Arguments:

    NetBuffer - Supplies the packet to checksum.
        The offset should be at the start of the upper-layer header.

    DataLength - Supplies the length of the packet data to checksum.

    Source - Supplies the source IP address for the pseudo-header.

    Destination - Supplies the destination IP address for the pseudo-header.

    AddressLength - Supplies the length of an IP address.

    NextHeader - Supplies the upper-layer protocol id for the pseudo-header.

    PartialPseudoHeaderChecksum - Supplies the cached pseudo-header checksum.
    
Return Value:

    On success, returns the 16-bit 1's complement checksum.  On failure,
    returns 0 (e.g. data buffer could not be mapped into kernel address space).

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG Checksum, SwappedLength, MdlOffset, Offset;
    PMDL Mdl;
   
    //
    // Determine the pseudo-header checksum.
    //
    
    if (PartialPseudoHeaderChecksum != 0) {
        //
        // 1. Partial pseudo-header checksum specified.
        // Simply add the checksum of the length.
        //
        Checksum = PartialPseudoHeaderChecksum;
        SwappedLength = RtlUlongByteSwap(DataLength);
        Checksum += (SwappedLength >> 16) + (SwappedLength & 0xffff);
    } else if (Source != NULL && NextHeader != IPPROTO_ICMP) {
        //
        // 2. Source and destination addresses specified.
        // Checksum (Source, Destination, NextHeader, and Length).
        //
        ASSERT(Destination != NULL);
        Checksum =
            IppChecksum(Source, AddressLength) +
            IppChecksum(Destination, AddressLength);
        Checksum += (NextHeader << 8);

        SwappedLength = RtlUlongByteSwap(DataLength);
        Checksum += (SwappedLength >> 16) + (SwappedLength & 0xffff);
    } else {
        //
        // 3. Neither partial pseudo-header checksum nor addreses specified.
        // Caller does not require a psuedo-header checksum.
        //
        Checksum = 0;
    }


    //
    // Determine the data checksum.
    //
    
    if (NetBuffer == NULL) {
        //
        // Caller does not require data checksum.
        // Wrap the carries to reduce Checksum to 16 bits.
        // (Twice is sufficient because it can only overflow once.)
        //
        Checksum = (Checksum >> 16) + (Checksum & 0xffff);
        Checksum += (Checksum >> 16);

        return (UINT16)Checksum;
    }    

    //
    // The first MDL must be checksummed from an offset.
    //
    Mdl = NetBuffer->CurrentMdl;
    MdlOffset = NetBuffer->CurrentMdlOffset;

    Offset = 0;
        
    ASSERT(DataLength <= NetBuffer->DataLength);
    while (DataLength != 0) {
        PUCHAR Buffer;
        ULONG BufferLength;
        UINT16 BufferChecksum;
        
        Buffer = MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority);
        if (Buffer == NULL) {
            return 0;
        }

        BufferLength = MmGetMdlByteCount(Mdl);
        ASSERT(BufferLength >= MdlOffset);
        
        Buffer += MdlOffset;
        BufferLength -= MdlOffset;
        
        //
        // BufferLength might be bigger than we need,
        // if there is "extra" data in the packet.
        //
        if (BufferLength > DataLength) {
            BufferLength = DataLength;
        }
            
        BufferChecksum = IppChecksum(Buffer, BufferLength);
        if ((Offset & 1) == 0) {
            Checksum += BufferChecksum;
        } else {
            //
            // We're at an odd offset into the logical buffer,
            // so we need to swap the bytes that IppChecksum returns.
            //
            Checksum += (BufferChecksum >> 8) + ((BufferChecksum & 0xff) << 8);
        }

        Offset += BufferLength;
            
        DataLength -= BufferLength;
        
        Mdl = Mdl->Next;

        MdlOffset = 0;
    }
    
    //
    // Wrap in the carries to reduce Checksum to 16 bits.
    // (Twice is sufficient because it can only overflow once.)
    //
    Checksum = (Checksum >> 16) + (Checksum & 0xffff);
    Checksum += (Checksum >> 16);

    //
    // Take ones-complement and replace 0 with 0xffff.
    //
    if (Checksum != 0xffff) {
        Checksum = (UINT16) ~Checksum;
    }

    return (UINT16) Checksum;
}


ULONG
IpNlpChecksumDatagram(
    IN PNL_REQUEST_CHECKSUM_DATAGRAM Args
    )
{   
    PIP_PROTOCOL Protocol;
    PIP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, IP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;
    
    return
        IppChecksumDatagram(
            Args->NetBuffer,
            Args->DataLength,
            Args->SourceAddress, 
            Args->DestinationAddress,
            Protocol->Characteristics->AddressBytes,
            Args->NextHeaderValue, 
            Args->PseudoHeaderChecksum);
}

NETIO_INLINE
VOID
IppFillChecksumAtOffset(
    IN UINT16 Checksum,
    IN USHORT UlChecksumOffset,
    IN OUT PNET_BUFFER NetBuffer
    )
/*++

Routine Description:

    Fill in the upper protocol checksum given an offset into the packet.

Arguments:

    Checksum - Supplies the checksum value.

    UlChecksumOffset - Supplies offset into the TL header to fill checksum to.

    NetBuffer - Supplies the packet for which to fill the checksum.

Return Value:

    None.
    
--*/ 
{
    PUCHAR Buffer;    

    //
    // In the common case, the transport header is in contiguous memory.
    // If so write the checksum at its offset, else use RtlCopyBufferToMdl.
    //
    Buffer =
        NetioGetDataBufferIfSafe(
            NetBuffer, 
            UlChecksumOffset + sizeof(UINT16),
            sizeof(UINT16),
            0);
    if (Buffer != NULL) {
        *((UINT16 UNALIGNED*)(Buffer + UlChecksumOffset)) = Checksum;
    } else {
        SIZE_T BytesCopied;    
        
        RtlCopyBufferToMdl(
            &Checksum, 
            NetBuffer->CurrentMdl, 
            NetBuffer->CurrentMdlOffset + UlChecksumOffset, 
            sizeof(UINT16),
            &BytesCopied);

        ASSERT(BytesCopied == sizeof(UINT16));
    }
}

VOID
IppChecksumNetBufferList(
    IN PIP_PROTOCOL Protocol,
    IN ULONG PseudoHeaderChecksum,
    IN USHORT UlChecksumOffset,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    BOOLEAN ChecksumOffloaded
    )
/*++

Routine Description:

    Fill in the upper protocol checksums (partial or full) for all NBs 
    chained under an NBL.

Arguments:

    Protocol - Supplies the protocol.

    PseudoHeaderChecksum - Partial checksum of source and destination address.

    UlChecksumOffset - Offset into transport header where checksum should be 
                       filled.
    Control - Supplies the control structure.

    ChecksumOffloaded - Fill out pseudo-checksum (source/dest/length) if
                        TRUE; fill out full-checksum (source/dest/length/data)
                        if FALSE.

Return Value:

    None.

--*/ 
{
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    PNET_BUFFER NetBuffer; 
    UINT16 Checksum;

    for (NetBuffer = NetBufferList->FirstNetBuffer; 
         NetBuffer != NULL; 
         NetBuffer = NetBuffer->Next) {
        //
        // If ChecksumOffloaded, we need only compute the pseudo header
        // checksum.  The NIC will compute checksum over the data buffer.
        // Hence we supply a NULL NetBuffer.
        //
            
        Checksum =
            IppChecksumDatagram(
                ChecksumOffloaded ? NULL : NetBuffer,
                NetBuffer->DataLength,
                NL_ADDRESS(Control->SourceLocalAddress),
                Control->FinalDestinationAddress.Buffer,
                Protocol->Characteristics->AddressBytes,
                Control->DestinationProtocol,
                PseudoHeaderChecksum);
        
        IppFillChecksumAtOffset(
            Checksum,
            UlChecksumOffset,
            NetBuffer);
    }
}

VOID
IppPreparePacketChecksum(
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_SEND_DATAGRAMS Args,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Process upper-layer checksum.
    
Arguments:

    Protocol - Supplies the protocol.

    Args - Supplies the send request.  Following fields are relevant...
    
        ChecksumOffset - Supplies the NetBuffer offset to place the checksum.
            NL_CHECKSUM_OFFSET_NONE if checksum is necessary.

        PseudoHeaderChecksum - Supplies the pseudo-header checksum.

    Control - Supplies the control structure.
    
Return Value:

    None.
    
--*/ 
{
    BOOLEAN ChecksumOffloaded = FALSE;
    PIP_INTERFACE Interface = Control->NextHop->Interface;
    PNET_BUFFER_LIST NetBufferList = Control->NetBufferList;
    PNET_BUFFER NetBuffer; 
      
    if (Args->UlChecksumOffset == NL_CHECKSUM_OFFSET_NONE) {
        return;
    } 

    //
    // IPSec trumps checksum offload.
    //
    if (IpSecGetSecurityContext(NetBufferList) == NULL) {
        NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo;

        ChecksumInfo.Value = (ULONG) (ULONG_PTR)
            NET_BUFFER_LIST_INFO(NetBufferList,TcpIpChecksumNetBufferListInfo);

        //
        // Determine if the outgoing interface can support checksum offload.
        //
        if (Args->DestProtocol == IPPROTO_TCP) {
            //
            // Offload the checksum if the TCP header does not contain options
            // or the interface supports TCP options, and fragmentation is
            // dissallowed (for performance, unlike for UDP, we don't try to 
            // find out if the packet would indeed be fragmented.
            //
            if (Interface->TransmitOffload.TlStreamChecksumSupported &&
                (!Control->Flags.TcpOptions || 
                 Interface->TransmitOffload.TlStreamOptionsSupported) &&
                Control->Flags.DontFragment) {

                ChecksumInfo.Transmit.NdisPacketTcpChecksum = TRUE;
                if (IS_IPV4_PROTOCOL(Protocol)) { 
                    ChecksumInfo.Transmit.NdisPacketChecksumV4 = TRUE;
                } else {
                    ChecksumInfo.Transmit.NdisPacketChecksumV6 = TRUE;
                } 

                ChecksumOffloaded = TRUE;
            }
        } else if (Args->DestProtocol == IPPROTO_UDP) {
            if (Interface->TransmitOffload.TlDatagramChecksumSupported) {
                ULONG UlMtu = 0;
                
                //
                // Calculate the available packet size since we have to disable
                // UDP checksum offload for packets that will be fragmented.
                //
                if (Control->Path == NULL) {
                    UlMtu = IppGetMtuFromNextHop(Control->NextHop);
                } else {
                    UlMtu = Control->Path->PathMtu;
                }                
                if (Control->HeaderInclude) {
                    UlMtu -= Control->HeaderIncludeHeaderLength;
                } else {
                    //
                    // Notice we don't check and add the Jumbogram header
                    // size as it won't be added if the packet is fragmented.
                    //
                    UlMtu -= 
                        (IS_IPV4_PROTOCOL(Protocol)
                         ? ALIGN_UP(
                              Protocol->HeaderSize + 
                              Control->RoutingHeaderLength +
                              Control->HopByHopOptionsLength, UINT32) 
                         : (Protocol->HeaderSize + 
                            Control->RoutingHeaderLength +
                            Control->HopByHopOptionsLength)); 
                }                    

                //
                // Make sure that none of the packets will get fragmented.  If
                // at least one will, then disable offload.
                //
                ChecksumOffloaded = TRUE;                
                for (NetBuffer = NetBufferList->FirstNetBuffer; 
                     NetBuffer != NULL; 
                     NetBuffer = NetBuffer->Next) {                
                    if (NetBuffer->DataLength > UlMtu) {
                        ChecksumOffloaded = FALSE;
                        break;
                    }                
                }                    

                if (ChecksumOffloaded) {
                    ChecksumInfo.Transmit.NdisPacketUdpChecksum = TRUE;
                    if (IS_IPV4_PROTOCOL(Protocol)) { 
                        ChecksumInfo.Transmit.NdisPacketChecksumV4 = TRUE;
                    } else {
                        ChecksumInfo.Transmit.NdisPacketChecksumV6 = TRUE;
                    }
                }                    
            }
        }

        NET_BUFFER_LIST_INFO(NetBufferList, TcpIpChecksumNetBufferListInfo) =
            (PVOID) (ULONG_PTR) ChecksumInfo.Value;                    
    }

    IppChecksumNetBufferList(
        Protocol,
        Args->PseudoHeaderChecksum,
        Args->UlChecksumOffset,
        Control,
        ChecksumOffloaded
        );
}

VOID
IppProcessDefaults(
    IN PIP_PROTOCOL Protocol,
    IN USHORT UlChecksumOptions,
    IN USHORT DestProtocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Process compartment defaults.
    The parsed information is used to fill the Control structure.
    
Arguments:

    Protocol - Supplies the protocol.

    UlChecksumOptions - Supplies upper layer option information.

    Control - Supplies the control structure.
    
Return Value:

    None.
    
--*/ 
{
    UNREFERENCED_PARAMETER(Protocol);
    
    //
    // Pull out the upper layer option information.
    //
    if (UlChecksumOptions && (DestProtocol == IPPROTO_TCP)) {
        Control->Flags.TcpOptions = TRUE;
    }

    //
    // If the path has the ForceFragment flag set,
    // then the don't fragment bit should be overwritten to FALSE.
    //
    if ((Control->Path != NULL) && Control->Path->Flags.ForceFragment) {
        Control->Flags.DontFragment =  FALSE;
        Control->Flags.DontFragmentSet = TRUE;
    }
                                 
    //
    // Interface followed by compartment defaults.
    //
    if (Control->HopLimit == IP_UNSPECIFIED_HOP_LIMIT) {
        //
        // The default multicast hop limit is always 1 per RFC 3493.
        //
        if (Control->CurrentDestinationType == NlatMulticast) {
            Control->HopLimit = IP_DEFAULT_MULTICAST_HOP_LIMIT;
        } else {
            Control->HopLimit =
                (Control->NextHop->Interface->CurrentHopLimit != 0)
                ? Control->NextHop->Interface->CurrentHopLimit
                : Control->Compartment->DefaultHopLimit;
        }            
    }

    if (Control->TypeOfService == (UINT8) IP_UNSPECIFIED_TYPE_OF_SERVICE) {
        //
        // The default ToS value is 0.
        //
        Control->TypeOfService = 0;
    }
}


NTSTATUS
IppProcessSessionState(
    IN PIP_PROTOCOL Protocol,
    IN PVOID NlSessionState,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Process session state.
    The parsed information is used to fill the Control structure.
    
Arguments:

    Protocol - Supplies the protocol.

    NlSessionState - Supplies the NL session state.

    Control - Supplies the control structure.
    
Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_SESSION_STATE State = (PIP_SESSION_STATE)NlSessionState;
    PUCHAR DataCopy;
    KIRQL OldIrql;
    IP_SESSION_FLAGS Flags;
   
    UNREFERENCED_PARAMETER(Protocol);
    
    ASSERT(NlSessionState != NULL);

    //
    // HeaderInclude data takes precedence.
    //
    if (Control->HeaderInclude) {
        return STATUS_SUCCESS;
    }    

    if (Control->HopLimit == IP_UNSPECIFIED_HOP_LIMIT) {
        if (Protocol->AddressType(Control->FinalDestinationAddress.Buffer)
            == NlatMulticast) {
            Control->HopLimit = State->MulticastHopLimit;
        } else {
            Control->HopLimit = State->UnicastHopLimit;
        }
    }

    //
    // Copy over session flags, preserving DontFragment flag if already set.
    //
    Flags.Flags = State->Flags;
    if (Control->Flags.DontFragmentSet) {
        Flags.DontFragment = Control->Flags.DontFragment;
        Flags.DontFragmentSet = TRUE;
    }        
    Control->Flags.Flags = Flags.Flags;

    if ((State->HopByHopOptionsLength == 0) &&
        (State->RoutingHeaderLength == 0)) {
        return STATUS_SUCCESS;
    }    
    
    KeAcquireSpinLock(&State->SpinLock, &OldIrql);

    if ((Control->HopByHopOptions == NULL) &&
        (State->HopByHopOptionsLength > 0)) {

        ASSERT(State->HopByHopOptions != NULL);
        
        DataCopy = 
            ExAllocatePoolWithTagPriority(
                NonPagedPool,
                State->HopByHopOptionsLength,
                IpGenericPoolTag,
                LowPoolPriority);
        if (DataCopy == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Bail;
        }

        RtlCopyMemory(
            DataCopy,
            State->HopByHopOptions,
            State->HopByHopOptionsLength);

        Control->HopByHopOptions = DataCopy;
        Control->HopByHopOptionsLength = State->HopByHopOptionsLength;

        if (State->FirstHopOffset != 0) {
            Control->CurrentDestinationAddress =
                ((PUCHAR) Control->HopByHopOptions) + State->FirstHopOffset;
        }
    }
    
    if ((Control->RoutingHeader == NULL) &&
        (State->RoutingHeaderLength > 0)) {
            
        ASSERT(State->RoutingHeader != NULL);
        
        DataCopy =
            ExAllocatePoolWithTagPriority(
                NonPagedPool,
                State->RoutingHeaderLength,
                IpGenericPoolTag,
                LowPoolPriority);
        if (DataCopy == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Bail;
        }

        RtlCopyMemory(
            DataCopy,
            State->RoutingHeader,
            State->RoutingHeaderLength);
        
        Control->RoutingHeader = DataCopy;
        Control->RoutingHeaderLength = State->RoutingHeaderLength;

        Control->CurrentDestinationAddress =
            (PUCHAR) (((PIPV6_ROUTING_HEADER) Control->RoutingHeader) + 1);
    }
Bail:
    KeReleaseSpinLock(&State->SpinLock, OldIrql);
    return Status;
}


NTSTATUS
IppProcessAncillaryData(
    IN PIP_PROTOCOL Protocol,
    IN PUCHAR Buffer,
    IN SIZE_T BufferLength,
    IN BOOLEAN EnforceAncillaryDataChecks,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Process the ancillary data - everything except IP_PKTINFO option.
    IP_PKTINFO will be parsed after this call when the NL client joins a path.
    The parsed information is used to fill the Control structure.
    
Arguments:

    Protocol - Supplies the protocol.

    Buffer - Supplies the buffer containing ancillary data.

    BufferLength - Supplies the buffer length.

    EnforceAncillaryDataChecks - Supplies TRUE to perform ancillary data check.

    Control - Supplies the control structure.  Following fields are relevant:

        HopLimit - Returns the hop limit from the ancillary data.  Remains
            unmodified if the ancillary data does not contain the IP_HOPLIMIT
            option.

        TypeOfService - Returns the type of service from the ancillary data.
            Remains unmodified if the ancillary data does not contain the
            IP_TOS option.

        HopByHopOptions - Returns the hop-by-hop options from the ancillary
            data.  Remains unmodified if the ancillary data does not contain
            the IP_OPTIONS option.

        HopByHopOptionsLength - Returns the hop-by-hop options length from the
            ancillary data.  Remains unmodified if the ancillary data does not
            contain the IP_OPTIONS option.

        RoutingHeader - Returns the routing header from the ancillary
            data. Remains unmodified if the ancillary data
            does not contain any IP_RTHDR or IP_OPTIONS::IP_OPT_SSRR or
            IP_OPTIONS::IP_OPT_LSRR options.

        RoutingHeaderLength - Returns the routing header length from the
            ancillary data.  Remains unmodified if the ancillary data does not
            contain the IP_RTHDR option.

        CurrentDestinationAddress - Returns the current destination address
            from the ancillary data.  Remains unmodified if the ancillary data
            does not contain any IP_RTHDR or IP_OPTIONS::IP_OPT_SSRR or
            IP_OPTIONS::IP_OPT_LSRR options.
        
Return Value:
    
    STATUS_SUCCESS - Success.

    STATUS_INVALID_PARAMETER - Malformed ancillary data.

    STATUS_INSUFFICIENT_RESOURCES - Allocation of routing header or hop-by-hop
        options fails.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCMSGHDR Object;
    PUCHAR Data, DataCopy;
    SIZE_T DataLength;
    USHORT BytesToCopy, FirstHopOffset;

    ASSERT(BufferLength > 0);

    //
    // HeaderInclude data takes precedence.
    //
    if (Control->HeaderInclude) {
        return STATUS_SUCCESS;
    }
    
    while (BufferLength >= CMSG_SPACE(0)) {
        Object = (PCMSGHDR) Buffer;
        if (Object->cmsg_len < CMSG_SPACE(0)) {
            Status = STATUS_INVALID_PARAMETER;
            goto Bail;
        }
        
        Data = WSA_CMSG_DATA(Object);
        DataLength = Object->cmsg_len - CMSG_SPACE(0);

        if (BufferLength < CMSG_SPACE(DataLength)) {
            Status = STATUS_INVALID_PARAMETER;
            goto Bail;
        }
    
        Buffer += CMSG_SPACE(DataLength);
        BufferLength -= CMSG_SPACE(DataLength);
    
        if (Object->cmsg_level != Protocol->Level) {
            Status = STATUS_INVALID_PARAMETER;
            goto Bail;
        }
    
        switch (Object->cmsg_type) {
        case IP_DONTFRAGMENT:  // And IPV6_DONTFRAG.
            if (Control->Flags.DontFragmentSet) {
                break;
            }
            
            if (DataLength < sizeof(INT)) {
                Status = STATUS_INVALID_PARAMETER;
                goto Bail;
            }

            Control->Flags.DontFragment = (BOOLEAN) (*((PINT) Data) != 0);        
            Control->Flags.DontFragmentSet = TRUE;
            
            break;
            
        case IP_HOPLIMIT:
            if (Control->HopLimit != IP_UNSPECIFIED_HOP_LIMIT) {
                break;
            }                
                
            if (DataLength < sizeof(INT)) {
                Status = STATUS_INVALID_PARAMETER;
                goto Bail;
            }
            
            Control->HopLimit = *((PINT) Data);
            if ((Control->HopLimit < 0) || (Control->HopLimit > 255)) {
                Status = STATUS_INVALID_PARAMETER;
                goto Bail;
            }
            break;
            
        case IP_TOS:
            if (Control->TypeOfService !=
                (UINT8) IP_UNSPECIFIED_TYPE_OF_SERVICE) {
                break;
            }                

            if (DataLength < sizeof(INT)) {
                Status = STATUS_INVALID_PARAMETER;
                goto Bail;
            }            

            if (!EnforceAncillaryDataChecks) {
                //
                // Process the option.
                //
                Control->TypeOfService = *((PINT) Data);
                if ((Control->TypeOfService < 0) || 
                    (Control->TypeOfService > 255)) {
                    Status = STATUS_INVALID_PARAMETER;
                    goto Bail;
                }
            }
            
            break;

        case IP_OPTIONS:
            if (Control->HopByHopOptions != NULL) {
                break;
            }                
            
            if (DataLength == 0) {
                break;
            }
            
            //
            // Validate the options buffer.
            //
            Status =
                Protocol->ValidateHopByHopOptionsForSend(
                    Data,
                    (ULONG) DataLength,
                    &FirstHopOffset,
                    &BytesToCopy);
            if (!NT_SUCCESS(Status)) {
                goto Bail;
            }

            //
            // The ancillary data is only valid for the lifetime of the 
            // downcall, but we need it around until IppPacketizeDatagrams,
            // which may be after IPsec negotiation completes.
            // Hence, we'll allocate a copy here.
            //
            DataCopy =
                ExAllocatePoolWithTagPriority(
                    NonPagedPool,
                    BytesToCopy,
                    IpGenericPoolTag,
                    LowPoolPriority);
            if (DataCopy == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Bail;
            }
            RtlCopyMemory(DataCopy, Data, BytesToCopy);
            
            ASSERT(Control->HopByHopOptions == NULL);            
            Control->HopByHopOptions = DataCopy;
            Control->HopByHopOptionsLength = (USHORT) BytesToCopy;

            if (FirstHopOffset != 0) {
                Control->CurrentDestinationAddress =
                    ((PUCHAR) Control->HopByHopOptions) + FirstHopOffset;
            }
            
            break;

        case IP_RTHDR:          // And IPV6_RTHDR
            if (Control->RoutingHeader != NULL) {
                break;
            }                
            
            if (DataLength == 0) {
                break;
            }
            
            //
            // Validate the routing header buffer.
            //
            Status =
                Protocol->ValidateRoutingHeaderForSend(
                    Data,
                    (ULONG) DataLength,
                    &BytesToCopy);
            if (!NT_SUCCESS(Status)) {
                goto Bail;
            }
            
            //
            // The ancillary data is only valid for the lifetime of the
            // downcall, but we need it around until IppPacketizeDatagrams,
            // which may be after IPsec negotiation completes.  Hence,
            // we'll allocate a copy here.
            //
            DataCopy =
                ExAllocatePoolWithTagPriority(
                    NonPagedPool,
                    BytesToCopy,
                    IpGenericPoolTag,
                    LowPoolPriority);
            if (DataCopy == NULL) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Bail;
            }
            RtlCopyMemory(DataCopy, Data, BytesToCopy);
            
            ASSERT(Control->RoutingHeader == NULL);            
            Control->RoutingHeader = DataCopy;
            Control->RoutingHeaderLength = (USHORT) BytesToCopy;

            if (IS_IPV4_PROTOCOL(Protocol)) {
                //
                // RFC791/IPv4 doesn't prohibit empty LSRR/SSRR headers,
                // so we accept them, but we should pick the address from
                // LSRR/SSRR only if there is at least one available.
                //
                if (Control->RoutingHeaderLength > 
                      sizeof(IPV4_ROUTING_HEADER)) {
                   Control->CurrentDestinationAddress = (PUCHAR) 
                       (((PIPV4_ROUTING_HEADER) Control->RoutingHeader) + 1);
                }
            } else {
                Control->CurrentDestinationAddress = (PUCHAR) 
                    (((PIPV6_ROUTING_HEADER) Control->RoutingHeader) + 1);
            }
            
            break;
            
        case IP_PKTINFO:
            //
            // This will be parsed when caller invokes JoinPath. 
            //
            continue;
            
        default:
            Status = STATUS_INVALID_PARAMETER;
            goto Bail;
        }
    }
    
Bail:
    return Status;
}

NETIO_INLINE
NTSTATUS 
IppAllocateAndCopyHeaderIncludeHeader(
    IN ULONG HeaderIncludeHeaderLength,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Allocate and store the header-include header of a packet into the 
    control structure.

Arguments:

    HeaderIncludeHeaderLength - Length of the IP header.

    Control - Supplies the control structure.


Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    PNET_BUFFER NetBuffer = NET_BUFFER_LIST_FIRST_NB(Control->NetBufferList);
    PUCHAR Buffer;
    SIZE_T BytesCopied;

    Buffer =
        ExAllocatePoolWithTagPriority(
            NonPagedPool,
            HeaderIncludeHeaderLength,
            IpGenericPoolTag,
            LowPoolPriority);
    if (Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMdlToBuffer(
        NetBuffer->MdlChain,
        NetBuffer->DataOffset,
        Buffer,
        HeaderIncludeHeaderLength,
        &BytesCopied);

    ASSERT(BytesCopied == HeaderIncludeHeaderLength);        

    Control->HeaderInclude = TRUE;
    Control->HeaderIncludeHeader = Buffer;
    Control->HeaderIncludeHeaderLength = HeaderIncludeHeaderLength;

    return STATUS_SUCCESS;
}


NTSTATUS
IppFindOrSpoofLocalAddressForRawSend(
    IN PIP_PROTOCOL Protocol,
    IN PIP_COMPARTMENT Compartment,
    IN PNL_LOCAL_ADDRESS_ARG Arg,
    IN CONST UCHAR *RemoteAddress,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

   Look up the IP_LOCAL_ADDRESS object matching the Arg->Address (local
   address in network order). If not found, perform a route lookup based on 
   remote address and spoof the local address on the resulting interface.

Arguments:

    Protocol - Supplies the protocol.

    Compartment - Supplies the routing compartment.

    Arg - Structure encapsulating the source address.
        ScopeId - Supplies remote Scope Id.
        Address - Supplies the source address in network order.

    RemoteAddress - Supplies the destination address in network order.

    Control - Supplies the control structure.

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_LOCAL_ADDRESS LocalAddress;
    PIP_NEXT_HOP NextHop;

    //
    // Get the caller supplied local address.
    //
    LocalAddress = IppFindLocalAddress(Compartment, Arg);
    if (LocalAddress == NULL) {
        KIRQL OldIrql;
        IP_PATH_FLAGS Constrained;
        SCOPE_ID RemoteScopeId = Arg->ScopeId;

        if (!IppCanonicalizeScopeId(
                Compartment, 
                RemoteAddress,
                &RemoteScopeId)) {
            Status = STATUS_INVALID_ADDRESS_COMPONENT;
            goto Bail;
        }
        
        //
        // We need to spoof. Create an address on the outgoing interface.
        //
        OldIrql = KeRaiseIrqlToDpcLevel();

        IppFindNextHopAtDpc(
            Compartment,
            RemoteAddress,
            NULL,
            NULL,
            RemoteScopeId,
            &NextHop,
            &Constrained,
            NULL);

        KeLowerIrql(OldIrql);        
        
        if (NextHop == NULL) {
            Status = STATUS_DATA_NOT_ACCEPTED;
            goto Bail;
        }

        Control->NextHop = NextHop;
        Control->IsNextHopReferenced = TRUE;

        //
        // Only allow broadcast packets with a spoofed address.
        // This is required for dplay proxy scenarios.
        // TODO: Use ALE to verify that endpoint was created by LocalSystem.
        //
        if (Control->EnforceHeaderIncludeChecks &&
            (!IppIsNextHopLocalAddress(Control->NextHop) ||
             (Control->NextHopLocalAddress->Type != NlatBroadcast))) {
            Status = STATUS_DATA_NOT_ACCEPTED;
            goto Bail;
        }
        
        LocalAddress =
            IppCreateLocalAddress(
                Protocol,
                Arg->Address,
                NlatUnicast,
                NextHop->Interface,
                ADDR_CONF_MANUAL,
                INFINITE_LIFETIME,
                INFINITE_LIFETIME,
                8 * Protocol->Characteristics->AddressBytes,
                NULL);
    }
        
    if (LocalAddress == NULL) {
        Status = STATUS_DATA_NOT_ACCEPTED;
        goto Bail;
    }

    Control->SourceLocalAddress =  (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress;
    Control->IsSourceReferenced = TRUE;

Bail:

    return Status;
}

NTSTATUS
IppProcessHeaderIncludeHeader(
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_SEND_DATAGRAMS Args,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Process the raw data in the HeaderInclude header.
    The parsed information is used to fill the Control structure.
    
Arguments:

    Protocol - Supplies the protocol.

    Args - Supplies the send request.

    Control - Supplies the control structure.

        SourceLocalAddress - Returns the source from the header-include data.
    
        NextHop - Optionally returns the next-hop from the header-include data.

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PNET_BUFFER_LIST NetBufferList;
    PIP_COMPARTMENT Compartment = NULL;
    
    //
    // TODO: Ensure that only one packet is being sent for header includes.
    //

    //
    // SkipNetworkLayerHeaders has already been called once and would
    // have performed any internal header validation.  However, we need 
    // to be at the start of the transport header for the rest of the function.
    // Control->HeaderIncludeHeaderLength specifies the offset to the 
    // transport header.
    //
    NetioAdvanceNetBufferList(
        Control->NetBufferList,
        Control->HeaderIncludeHeaderLength);
        
    //
    // Get the caller supplied compartment.
    //
    Compartment = IppGetCompartment(Protocol, &Args->NlCompartment);
    if (Compartment == NULL) {
        return STATUS_DATA_NOT_ACCEPTED;
    }

    Status = IppFindOrSpoofLocalAddressForRawSend(
                Protocol,
                Compartment,
                &Args->NlLocalAddress,
                Args->RemoteAddress,
                Control);
    if (!NT_SUCCESS(Status)) {
        goto Bail;
    }

    Args->NextHop = Control->NextHop;
    Args->NlLocalAddress.LocalAddress = (PNL_LOCAL_ADDRESS)(Control->SourceLocalAddress);

    if (Control->EnforceHeaderIncludeChecks) {
        if ((Args->DestProtocol == IPPROTO_TCP) ||
            (Args->DestProtocol == IPPROTO_IPV4) ||
            (Args->DestProtocol == IPPROTO_IPV6)) {
            Status = STATUS_DATA_NOT_ACCEPTED;
            goto Bail;
        }

        //
        // Clone packet from the beginning of the transport layer header.
        // 1. We don't want to modify the user's buffers when updating
        // checksum and identifier in the IPv4 header.
        // 2. The user might modify IP header after the validation checks but
        // before we actually send it out.
        //

        NetBufferList =
            NetioAllocateAndReferenceCloneNetBufferList(
                Control->NetBufferList,
                FALSE);
        if (NetBufferList == NULL) {
            Status = STATUS_DATA_NOT_ACCEPTED;
            goto Bail;
        }
        
        IppCopyNetBufferListInfo(NetBufferList, Control->NetBufferList);
        NetioDereferenceNetBufferList(Control->NetBufferList, FALSE);
        Control->NetBufferList = NetBufferList;        
    }

Bail:
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);
    }

    return Status;
}

NTSTATUS
IppProcessRawData(
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_SEND_DATAGRAMS Args,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Process raw data (perhaps including a HeaderInclude header).
    The parsed information is used to fill the Control structure.
    
Arguments:

    Protocol - Supplies the protocol.

    Args - Supplies the send request.

    Control - Supplies the control structure.

        HeaderIncludeHeader - Returns a copy of the header-include header.
        
        HeaderIncludeHeader - Returns the header-include header length.
        
        FinalDestinationAddress - Returns the final destinatination address
            from the raw header-include data.
        
        CurrentDestinationAddress - Returns the current destination address
            from the raw header-include data.  Same as final destination
            address, unless header-include data contains any IPV6_RTHDR or
            IP_OPTIONS::IP_OPT_SSRR or IP_OPTIONS::IP_OPT_LSRR options.

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    PNET_BUFFER NetBuffer = Control->NetBufferList->FirstNetBuffer;
    PIP_SESSION_STATE State = (PIP_SESSION_STATE) Args->NlSessionState;    
    IP_ADDRESS_STORAGE SourceAddress;
    IP_ADDRESS_STORAGE CurrentDestinationAddress, FinalDestinationAddress;
    UINT8 DestinationProtocol = (UINT8) Args->DestProtocol;
    ULONG SkippedLength = 0;
    TCP_HDR TcpBuffer, *Tcp;
    UDP_HDR UdpBuffer, *Udp;
    ICMP_MESSAGE IcmpBuffer, *Icmp;

    //
    // TODO: Ensure that only one packet is being sent for "raw" datagrams
    //

    if ((State != NULL) && State->HeaderInclude) {
        //
        // Skip past the network layer headers to the beginning of the
        // transport layer header.  Ignore the values in the Args structure.
        //
        Status = Protocol->
            SkipNetworkLayerHeaders(
                NetBuffer, 
                (PUCHAR) &SourceAddress, 
                (PUCHAR) &CurrentDestinationAddress, 
                (PUCHAR) &FinalDestinationAddress, 
                &DestinationProtocol,
                &SkippedLength);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    //
    // We are now at the beginning of the transport layer header. 
    //
    switch (DestinationProtocol) {
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        if (NetBuffer->DataLength < sizeof(IcmpBuffer)) {
            return STATUS_DATA_NOT_ACCEPTED;
        }
        
        Icmp =
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(IcmpBuffer),
                &IcmpBuffer, 
                __builtin_alignof(ICMP_MESSAGE), 
                0);
        if (Icmp == NULL) {
            return STATUS_DATA_NOT_ACCEPTED;
        }

        //
        // Identify ICMP error messages.
        // This will ensure we do not to generate an ICMP error in response.
        //
        Control->IcmpError = (DestinationProtocol == IPPROTO_ICMP)
            ? ICMP4_ISTYPEERROR(Icmp->Header.Type)
            : ICMP6_ISTYPEERROR(Icmp->Header.Type);
        
        Control->TransportData.IcmpData = *Icmp;
        Control->TransportHeaderLength = (ULONG) sizeof(ICMP_MESSAGE);
        break;        

    case IPPROTO_UDP:
        if (NetBuffer->DataLength < sizeof(UdpBuffer)) {
            return STATUS_DATA_NOT_ACCEPTED;
        }
        
        Udp =
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(UdpBuffer),
                &UdpBuffer, 
                __builtin_alignof(UDP_HDR), 
                0);
        if (Udp == NULL) {
            return STATUS_DATA_NOT_ACCEPTED;
        }

        Control->TransportData.PortData.SourcePort = Udp->uh_sport;
        Control->TransportData.PortData.DestinationPort = Udp->uh_dport;
        Control->TransportHeaderLength = (ULONG) sizeof(UDP_HDR);
        break;

    case IPPROTO_TCP:
        if (NetBuffer->DataLength < sizeof(TcpBuffer)) {
            return STATUS_DATA_NOT_ACCEPTED;
        }
        
        Tcp =
            NetioGetDataBuffer(
                NetBuffer, 
                sizeof(TcpBuffer),
                &TcpBuffer, 
                __builtin_alignof(TCP_HDR), 
                0);
        if (Tcp == NULL) {
            return STATUS_DATA_NOT_ACCEPTED;
        }

        Control->TransportData.PortData.SourcePort = Tcp->th_sport;
        Control->TransportData.PortData.DestinationPort = Tcp->th_dport;
        Control->TransportHeaderLength = Tcp->th_len << 2;

        if (NetBuffer->DataLength < Control->TransportHeaderLength) {
            return STATUS_DATA_NOT_ACCEPTED;
        }

        break;
    }

    if (SkippedLength != 0) {
        (VOID) NetioRetreatNetBuffer(NetBuffer, SkippedLength, 0);

        Status = IppAllocateAndCopyHeaderIncludeHeader(
                    SkippedLength, 
                    Control);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        RtlCopyMemory(
            Control->FinalDestinationAddress.Buffer,
            &FinalDestinationAddress,
            Protocol->Characteristics->AddressBytes);

        //
        // Reset caller supplied routing information.
        //
        Args->RemoteAddress = Control->FinalDestinationAddress.Buffer;
        
        Args->Path = NULL;
        
        Args->NlLocalAddress.LocalAddress = NULL;
        if (IS_IPV4_PROTOCOL(Protocol)) { 
            PIPV4_HEADER Ipv4 = (PIPV4_HEADER) Control->HeaderIncludeHeader;
            Ipv4->HeaderChecksum = 0;
            Args->NlLocalAddress.Address =
                (PUCHAR) &Ipv4->SourceAddress;
            Control->CurrentDestinationAddress =
                (PUCHAR) &Ipv4->DestinationAddress;
            Control->Flags.DontFragment = (BOOLEAN) (Ipv4->DontFragment != 0); 
            Control->Flags.DontFragmentSet = TRUE;
        } else {
            PIPV6_HEADER Ipv6 = (PIPV6_HEADER) Control->HeaderIncludeHeader;
            Args->NlLocalAddress.Address =
                (PUCHAR) &Ipv6->SourceAddress;
            Control->CurrentDestinationAddress =
                (PUCHAR) &Ipv6->DestinationAddress;
        }

        Args->NextHop = NULL;

        Args->DestProtocol = DestinationProtocol;

        Status = IppProcessHeaderIncludeHeader(Protocol, Args, Control);
    }
    
    return Status;
}

NL_CLIENT_DISPATCH_FLAGS
IppInspectLookupNlClientFlags(
   IN IPPROTO IpProtocol,   // IPPROTO_IP or IPPROTO_IPV6
   IN IPPROTO UpperLayerProtocol,
   IN BOOLEAN IsRawSend
   )
{
    NL_CLIENT_DISPATCH_FLAGS ClientFlags;
    PIP_PROTOCOL Protocol;
    IN IPPROTO UpperLayerProtocolId;

    RtlZeroMemory(&ClientFlags, sizeof(NL_CLIENT_DISPATCH_FLAGS));

    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;

    UpperLayerProtocolId = IsRawSend ? IPPROTO_RESERVED_RAW : UpperLayerProtocol;

    if (UpperLayerProtocolId < IPPROTO_RESERVED_MAX)
    {
        PIP_CLIENT_CONTEXT NlClient
            = Protocol->ReceiveDemux[UpperLayerProtocolId].NlClient;

        if (NlClient != NULL)
        {
           ClientFlags = NlClient->Npi.Dispatch->Flags;
        }
    }

    return ClientFlags;
}

VOID
IppSendDatagramsCommon(
    IN BOOLEAN DispatchLevel, 
    IN NL_CLIENT_DISPATCH_FLAGS ClientFlags,
    IN PIP_PROTOCOL Protocol,
    IN HANDLE LocalEndpoint,
    IN PNL_REQUEST_SEND_DATAGRAMS Args
    )    
/*++

Routine Description:

    Get the appropriate parameters for sending the packet based on
    defaults, session state, ancillary data, and raw data.

    HopLimit - The hop limit to send with.  Order of preference...
           1. ancillary data, 2. session state, 3. default for compartment.

    TypeOfService - TOS value to send with.  Order of preference...
           1. QoS 2. ancillary data, 3. default = 0.

    HopByHopOptions - Hop-by-hop options to send with.  Order of preference...
           1. ancillary data, 2. session state, 3. default = none.

    RoutingHeader - Routing header to send with.  Order of preference being
           1. ancillary data, 2. session state, 3. default = none.

    Of course, the raw header-include header (if present) takes precedence.
    
Arguments:

    DispatchLevel - Supplies TRUE if IRQL is known to be at DISPATCH level.
    
    ClientFlags - Supplies the client's send defaults.

    Protocol - Supplies the protocol.

    LocalEndpoint - Supplies the local endpoint for firewall inspection.

    Args - Supplies the send request.  The following fields are relevant:

        NetBufferList - NetBufferList to send.

        AncillaryData - Ancillary data for the send request. 
        
        AncillaryDataLength - Ancillary data length for the send request. 

        NlSessionState - Session state associated with the send request. 

        DestProtocol - Transport layer protocol.

        TransportData - Transport layer protocol information.
        
        CancelKey - Send cancellation context.

Return Value:

    None.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    IP_FILTER_ACTION Action;
    PNET_BUFFER_LIST NetBufferList;
    IP_REQUEST_CONTROL_DATA Control = {0};

    UNREFERENCED_PARAMETER(DispatchLevel);

    //
    // We currently support a single NetBufferList in a send request.
    // Of course, the NetBufferList may contain multiple NetBuffers (packets).
    //
    NetBufferList = Args->NetBufferList;
    ASSERT((NetBufferList != NULL) && 
           (NetBufferList->Next == NULL) && 
           (NetBufferList->FirstNetBuffer != NULL));
    ASSERT(NetBufferList->Status == STATUS_SUCCESS);

    ASSERT(Args->Next == NULL);
    ASSERT(Args->DestProtocol < IPPROTO_MAX);    

    IppInitializeOnStackControlForLocalSend(&Control, ClientFlags, NetBufferList);

    Control.FlSendPackets.CancelId = Args->CancelKey;

    //
    // A. Raw data takes precedence.
    //
    if (Args->TransportData == NULL) {
        Status = IppProcessRawData(Protocol, Args, &Control);
        if (!NT_SUCCESS(Status)) {
            goto Error;
        }
    } else {
        //
        // A header-include send must not contain transport data.
        //
        ASSERT((Args->NlSessionState == NULL) ||
               !((PIP_SESSION_STATE) Args->NlSessionState)->HeaderInclude);
        Control.TransportData = 
            *((PTRANSPORT_DATA) Args->TransportData);
        Control.TransportHeaderLength = Args->TransportHeaderLength;

    }    

    //
    // Set the Final destination address.
    //
    ASSERT((Args->RemoteAddress != NULL) || (Args->Path != NULL));
    RtlCopyMemory(
        Control.FinalDestinationAddress.Buffer,
        (Args->RemoteAddress != NULL)
        ? Args->RemoteAddress
        : Args->Path->DestinationAddress,
        Protocol->Characteristics->AddressBytes);
    
    //
    // B. Ancillary data comes next.
    // Packet offsets are now at the start of the transport layer header.
    //
    if (Args->AncillaryDataLength != 0) {
        Status = 
            IppProcessAncillaryData(
                Protocol,
                Args->AncillaryData,
                Args->AncillaryDataLength,
                TRUE,
                &Control);
        if (!NT_SUCCESS(Status)) {
            goto Error;
        }
    }

    //
    // C. Followed by session state.
    //
    if (Args->NlSessionState != NULL) {
        Status = IppProcessSessionState(Protocol, Args->NlSessionState, &Control);
        if (!NT_SUCCESS(Status)) {
            goto Error;
        }
    }

    //
    // D. Network layer client ancillary data comes next.
    //
    if (Args->NlClientAncillaryDataLength != 0) {
        Status = 
            IppProcessAncillaryData(
                Protocol,
                Args->NlClientAncillaryData,
                Args->NlClientAncillaryDataLength,
                FALSE,
                &Control);
        if (!NT_SUCCESS(Status)) {
            goto Error;
        }
    }

    //
    // Set Current destination address and destination protocol.
    //
    if (Control.CurrentDestinationAddress == NULL) {
        Control.CurrentDestinationAddress =
            Control.FinalDestinationAddress.Buffer;
    }
    
    Control.DestinationProtocol = Args->DestProtocol;    
    
    //
    // Set the SourceAddress and NextHop
    // 1. (Path != NULL)
    //  - SourceAddress is obtained from the path.
    //  - NextHop is either non-null or also obtained from the path.
    // 2. else if (NextHop != NULL)
    //  - SourceAddress must also be non-null.
    // 3. else perform a route lookup (with the SourceAddress constraint)
    //  - SourceAddress and NextHop are obtained from the path.
    //
    Control.Path = IppCast(Args->Path, IP_PATH);
    if (Control.Path != NULL) {
        //
        // The client has supplied a path that is guaranteed to exist for the
        // duration of this call (i.e. caller has a reference).  Hence it is
        // unnecessary to take a reference until we need to pend the packet.
        //
        ASSERT(!Control.IsPathReferenced);

        ASSERT(!Control.IsSourceReferenced);            
        Control.SourceLocalAddress = Control.Path->SourceAddress;

        ASSERT(!Control.IsNextHopReferenced);            
        if (Args->NextHop != NULL) {
            //
            // The client has also supplied a NextHop.
            //
            Control.NextHop = (PIP_NEXT_HOP) Args->NextHop;
        } else {
            if (!IS_PATH_VALID(
                    Control.Path,
                    Control.Path->SourceAddress->Interface->Compartment)) {
                IppValidatePath(Control.Path);
            }

            Control.NextHop = IppGetNextHopFromPath(Control.Path);
            if (Control.NextHop == NULL) {
                Status = STATUS_NOT_FOUND;
                goto ErrorRouting;
            }            
            Control.IsNextHopReferenced = TRUE;
        }
    } else if (Args->NextHop != NULL) {
        ASSERT(Args->NlLocalAddress.LocalAddress != NULL);
        
        //
        // The client has supplied both the SourceAddress and the NextHop.
        //
        Control.SourceLocalAddress =
            (PIP_LOCAL_UNICAST_ADDRESS) Args->NlLocalAddress.LocalAddress;

        Control.NextHop = (PIP_NEXT_HOP) Args->NextHop;
    } else if ((Control.DestinationProtocol == IPPROTO_TCP) && 
               (Args->AncillaryDataLength == 0) && 
               (Args->NlLocalAddress.LocalAddress != NULL)) {
        // 
        // Under SYN Attack, TCP will send datagrams for half-open connections 
        // without a Path. Hence do not create additional Path cache state.
        // Not doing so bloats the NPP usage.
        //
        // TODO: Ideally, the path cache should be redone to automatically 
        // reuse unreferenced entries when the cache starts bloating up. And 
        // then this check should be removed. 
        // 
        SCOPE_ID RemoteScopeId = Args->RemoteScopeId;
        PIP_LOCAL_UNICAST_ADDRESS SourceAddress;
        PIP_LOCAL_ADDRESS LocalAddress = 
            (PIP_LOCAL_ADDRESS) Args->NlLocalAddress.LocalAddress;

        //
        // Even though some assumptions can be made if this code path is taken, 
        // doing full validation.
        //
        if (!IppCanonicalizeScopeId(
                LocalAddress->Interface->Compartment,
                Control.CurrentDestinationAddress,
                &RemoteScopeId)) {
            Status = STATUS_INVALID_ADDRESS_COMPONENT;
            goto ErrorRouting;
        }

        Status = 
            IppValidateRouteLookup(
                LocalAddress->Interface->Compartment,
                Control.CurrentDestinationAddress,
                &RemoteScopeId,
                LocalAddress->Interface,
                LocalAddress);
        if (!NT_SUCCESS(Status)) {
            goto ErrorRouting;
        }
        
        Control.Path = 
            IppFindPath(
                LocalAddress->Interface->Compartment,
                NULL,
                Control.CurrentDestinationAddress, 
                RemoteScopeId, 
                LocalAddress->Interface,
                (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress);
        if (Control.Path != NULL) {
            Control.IsPathReferenced = TRUE;
            Control.NextHop = IppGetNextHopFromPath(Control.Path);
            if (Control.NextHop == NULL) {
                Status = STATUS_NOT_FOUND;
                goto ErrorRouting;
            }
            Control.IsNextHopReferenced = TRUE;           
            Control.SourceLocalAddress =
                (PIP_LOCAL_UNICAST_ADDRESS) Control.Path->SourceAddress;
        } else {
            Status = 
                IppFindNextHopAndSource(
                    LocalAddress->Interface->Compartment, 
                    LocalAddress->Interface,
                    Control.CurrentDestinationAddress, 
                    RemoteScopeId, 
                    (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress, 
                    &Control.NextHop,
                    &SourceAddress,
                    NULL,
                    NULL);
            if (!NT_SUCCESS(Status)) {
                goto ErrorRouting;
            }        
            Control.IsNextHopReferenced = TRUE;
            Control.IsSourceReferenced = TRUE;
            Control.SourceLocalAddress = SourceAddress;
        }
    } else {
        NL_REQUEST_JOIN_PATH JoinPathArgs = {0};

        //
        // Perform a route lookup for the current destination
        // IppJoinPath considers client supplied constraints (e.g. Interface).
        //        
        JoinPathArgs.NlCompartment = Args->NlCompartment;
        JoinPathArgs.NlSessionState = Args->NlSessionState;
        JoinPathArgs.AncillaryDataLength = Args->AncillaryDataLength;
        JoinPathArgs.AncillaryData = Args->AncillaryData;
        JoinPathArgs.NlInterface = Args->NlInterface;
        JoinPathArgs.RemoteScopeId = Args->RemoteScopeId;
        JoinPathArgs.RemoteAddress = Control.CurrentDestinationAddress;
        JoinPathArgs.NlLocalAddress = Args->NlLocalAddress;
        Status = IppJoinPath(Protocol, &JoinPathArgs);
        if (!NT_SUCCESS(Status)) {
            goto ErrorRouting;
        }
        
        ASSERT(JoinPathArgs.Path != NULL);
        Control.Path = (PIP_PATH) JoinPathArgs.Path;
        Control.IsPathReferenced = TRUE;

        ASSERT((Args->NlLocalAddress.LocalAddress == NULL) ||
               (Args->NlLocalAddress.LocalAddress ==
                (PNL_LOCAL_ADDRESS) Control.Path->SourceAddress));
        
        Control.SourceLocalAddress =
            (PIP_LOCAL_UNICAST_ADDRESS) Control.Path->SourceAddress;
        
        Control.NextHop = IppGetNextHopFromPath(Control.Path);
        if (Control.NextHop == NULL) {
            Status = STATUS_NOT_FOUND;
            goto ErrorRouting;
        }
        Control.IsNextHopReferenced = TRUE;        
    }

    //
    // For LSO, if IP option is present, we need to make sure IP option is 
    // supported by NIC.
    //
    if ((Control.RoutingHeaderLength != 0) ||
        (Control.HopByHopOptionsLength != 0)) {
        PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO NblInfo;
        NblInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)(
            &NET_BUFFER_LIST_INFO(
                Args->NetBufferList,
                TcpLargeSendNetBufferListInfo));
        if ((NblInfo->Value != 0) && 
            (NblInfo->Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE)) {
            PIP_INTERFACE Interface = Control.NextHop->Interface;
            if (Interface->Lso.IPv4.IpOptions != NDIS_OFFLOAD_SUPPORTED) {
                Status = STATUS_NOT_SUPPORTED;
                goto Error;
            }
        }
    }

    Control.Compartment =
        Control.SourceLocalAddress->Interface->Compartment;

    Control.CurrentDestinationType = NlppNextHopAddressType(Control.NextHop);
    
    //
    // E. And then any compartment defaults.
    //
    IppProcessDefaults(Protocol, Args->UlChecksumOptions, Args->DestProtocol, &Control);

    //
    // Transport layer inspection call callout.  Sets IPSec security context.
    //
   
    Action =
        IppInspectLocalDatagramsOut(
            Protocol->Level,
            (PNL_LOCAL_ADDRESS) Control.SourceLocalAddress,
            Control.FinalDestinationAddress.Buffer,
            Control.CurrentDestinationType,
            (PNL_INTERFACE) Control.NextHop->Interface,
            IppGetNextHopSubInterfaceIndex(Control.NextHop),
            IppIsNextHopLocalAddress(Control.NextHop),
            Control.DestinationProtocol,
            LocalEndpoint,
            &Control.TransportData,
            Control.TransportHeaderLength,
            Control.NetBufferList,
            (PIP_PATH_PRIVATE) Control.Path,
            Args->RemoteScopeId,
            Args->AncillaryData,
            Args->AncillaryDataLength,
            Control.HeaderIncludeHeader,
            Control.HeaderIncludeHeaderLength);

    if (Action >= IpFilterDrop) {
        if ((Action == IpFilterDrop) || (Action == IpFilterDropAndSendIcmp)) {
            Status = STATUS_DATA_NOT_ACCEPTED;
        } else {
            ASSERT(Action == IpFilterAbsorb);
        }        
        goto Error;
    }

    //
    // E. Classification is performed during inspection, updating ToS value.
    //
    if (NET_BUFFER_LIST_INFO(
            Control.NetBufferList,
            ClassificationHandleNetBufferListInfo) != NULL) {
        Control.TypeOfService =
            NetioQueryNetBufferListTrafficClass(
                Control.NetBufferList,
                Control.NextHop->Interface->\
                    FlCharacteristics->PhysicalMediumType);
    }
    
    //
    // Upper layer checksum calculation.
    //
    IppPreparePacketChecksum(Protocol, Args, &Control);

    //
    // We are now ready to send the packet.
    //
    IppPacketizeDatagrams(&Control); 

    return;
    
ErrorRouting:
    Protocol->PerProcessorStatistics[KeGetCurrentProcessorNumber()].
        OutNoRoutes += IppGetPacketCount(NetBufferList);
Error:
    NetBufferList->Status = Status;
    IppCleanupSendState(&Control, TRUE);
    IppCompleteAndFreePacketList(&Control, FALSE);
}

VOID IppInspectInjectTlSend(
        IN IPPROTO IpProtocol,
        IN NL_CLIENT_DISPATCH_FLAGS ClientFlags,
        IN PNET_BUFFER_LIST NetBufferList,
        IN PVOID AncillaryData,
        IN ULONG AncillaryDataLength,
        IN PVOID SessionState,
        IN CONST NL_LOCAL_ADDRESS* NlLocalAddress,
        IN CONST UCHAR* RemoteAddress,
        IN SCOPE_ID RemoteScopeId,
        IN IPPROTO UpperLayerProtocol,
        IN HANDLE InspectHandle,
        IN COMPARTMENT_ID CompartmentId,
        IN BOOLEAN IsRawSend
        )
{
    PIP_PROTOCOL Protocol;
    NL_REQUEST_SEND_DATAGRAMS SendDatagramsRequest = {0};
    PIP_COMPARTMENT Compartment;

    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;

    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        NetBufferList->Status = STATUS_NOT_FOUND;
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
        return;
    }

    //
    // Issue a request to send a list of datagrams to the given remote address.
    //

    NBL_SET_PROT_RSVD_FLAG(NetBufferList, NBL_NAT_RESERVED);
    
    SendDatagramsRequest.NetBufferList = NetBufferList;
    SendDatagramsRequest.AncillaryData = AncillaryData;
    SendDatagramsRequest.AncillaryDataLength = AncillaryDataLength;
    SendDatagramsRequest.NlSessionState = SessionState;
    SendDatagramsRequest.DestProtocol = UpperLayerProtocol;
    SendDatagramsRequest.InspectHandle = InspectHandle;
    SendDatagramsRequest.NlCompartment.Compartment = (CONST NL_COMPARTMENT*)Compartment;;
    SendDatagramsRequest.NlLocalAddress.LocalAddress = NlLocalAddress;
    SendDatagramsRequest.RemoteAddress = RemoteAddress;
    SendDatagramsRequest.RemoteScopeId = RemoteScopeId;
    
    if (!IsRawSend) {
       if (UpperLayerProtocol == IPPROTO_TCP) {
          SendDatagramsRequest.UlChecksumOffset = FIELD_OFFSET(TCP_HDR, th_sum);
       }
       else if (UpperLayerProtocol == IPPROTO_UDP) {
          SendDatagramsRequest.UlChecksumOffset = FIELD_OFFSET(UDP_HDR, uh_sum);
       }
       else if ((UpperLayerProtocol == IPPROTO_ICMP) || 
                (UpperLayerProtocol == IPPROTO_ICMPV6)) {
         SendDatagramsRequest.UlChecksumOffset = FIELD_OFFSET(ICMP_HEADER, Checksum);
       }
       else {
         SendDatagramsRequest.UlChecksumOffset = NL_CHECKSUM_OFFSET_NONE;
       }
    } else {
         SendDatagramsRequest.UlChecksumOffset = NL_CHECKSUM_OFFSET_NONE;
    }
    
    IppSendDatagramsCommon(
        FALSE, 
        ClientFlags,
        Protocol,
        InspectHandle,
        &SendDatagramsRequest
        );

    IppDereferenceCompartment(Compartment);
}

NTSTATUS
IppInspectSkipNetworkLayerHeaders(
    IN IPPROTO IpProtocol,
    IN OUT PNET_BUFFER NetBuffer,
    OUT PUCHAR SourceAddress OPTIONAL, 
    OUT PUCHAR DestinationAddress OPTIONAL,   
    OUT UINT8 *TransportLayerProtocol OPTIONAL, 
    OUT ULONG *SkippedLength OPTIONAL
    )
/*++

Routine Description:
    
    Advance the input net buffer past network layer headers (including
    extension headers).
    
Arguments:

    Protocol - Supplies address family (IPPROTO_IP or IPPROTO_IPV6).
    
    NetBuffer - Supplies the packet to skip headers on.

    TransportLayerProtocol - Supplies the address to receive the transport
                             layer protocol.

    SkippedLength - Supplies the address to receive the length skipped.

Return Value:

    STATUS_SUCCESS or failure code.
    
--*/ 
{
    NTSTATUS Status;
    PIP_PROTOCOL Protocol;
    UINT8 TransportLayerProtocolLocal; 
    ULONG SkippedLengthLocal;

    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;

    Status =  Protocol->SkipNetworkLayerHeaders(
                            NetBuffer,
                            SourceAddress,
                            DestinationAddress,
                            NULL,
                            &TransportLayerProtocolLocal,
                            &SkippedLengthLocal
                            );
    if (NT_SUCCESS(Status)) {

        if (TransportLayerProtocol) {
            *TransportLayerProtocol = TransportLayerProtocolLocal;
        }
        if (SkippedLength) {
            *SkippedLength = SkippedLengthLocal;
        }
    }

    return Status;
}

VOID
IppSendDatagrams(
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_SEND_DATAGRAMS Args
    )
/*++

Routine Description:
    
    Construct and send IP packets.  Called by internal clients.
    
Arguments:

    Protocol - Supplies the protocol.
    
    Args - Supplies a send request.

Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NL_CLIENT_DISPATCH_FLAGS Flags = {0};
    PIP_RECEIVE_DEMUX Demux = &Protocol->ReceiveDemux[Args->DestProtocol];
    
    ASSERT(Demux->LocalEndpoint != NULL);
    
    IppSendDatagramsCommon(
        FALSE,
        Flags,
        Protocol,
        Demux->LocalEndpoint,
        Args);
}


VOID
IpNlpSendDatagrams(
    IN HANDLE ProviderHandle, 
    IN PNL_REQUEST_SEND_DATAGRAMS Args
    )
/*++

Routine Description:
    
    Construct and send IP packets.  Called by external network layer clients.
    
Arguments:

    ProviderHandle - Supplies the context allocated for the client.

    Args - Supplies a send request.
    
Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_RECEIVE_DEMUX Demux;
    PIP_CLIENT_CONTEXT Client = IppCast(ProviderHandle, IP_CLIENT_CONTEXT);
    
    Demux = 
        &(Client->Protocol->ReceiveDemux
          [Client->Npi.Dispatch->UpperLayerProtocolId]);
    //
    // Clear NBL_WFP_RESERVED flag (which indicates that IPSec was performed).
    // The IPSec team is concerned that an attacker could directly register
    // with the NL (using NMR) and invoke IpNlpSendDatagrams.
    //
    NBL_CLEAR_PROTOCOL_RSVD_FLAG(Args->NetBufferList, NBL_WFP_RESERVED);
    
    IppSendDatagramsCommon(
        FALSE,
        Client->Npi.Dispatch->Flags,
        Client->Protocol,
        (Client->Npi.Dispatch->Flags.CreateLocalEndpoint ?
         Demux->LocalEndpoint : Args->InspectHandle),
        Args);
}


NTSTATUS
NTAPI
IpNlpCancelSendDatagrams(
    IN PNL_REQUEST_CANCEL_SEND_DATAGRAMS Args
    )
{
    DBG_UNREFERENCED_PARAMETER(Args);

    return STATUS_NOT_IMPLEMENTED;
}

VOID
IppInspectInjectRawSend(
    IN IPPROTO IpProtocol,
    IN COMPARTMENT_ID CompartmentId,
    IN HANDLE InspectHandle,
    IN PVOID SessionState OPTIONAL,
    IN PNET_BUFFER_LIST NetBufferList
    )
/*++

Routine Description:

    This routine injects a raw IP send on behalf of the inspection module.

Arguments:

    IpProtocol - Identifies the IP protocol number for the injected packet.

    CompartmentId - Identifies the compartment from which the packet should
        be transmitted.

    InspectHandle - Supplies an inspect handle with which the packet should be
        associated.

    NetBufferList - Supplies the packet to be injected.

Return Value:

    None.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    NL_REQUEST_SEND_DATAGRAMS Args = {0};
    PIP_COMPARTMENT Compartment;
    NL_CLIENT_DISPATCH_FLAGS Flags = {0};
    PIP_PROTOCOL Protocol;
    IP_SESSION_STATE LocalSessionState;
    BOOLEAN UseLocalSessionState = TRUE;

    //
    // If caller passes in a session-state that's suitable for use
    // for raw send, then use it. In this case caller will cleanup
    // the session state.
    //
    if ((SessionState != NULL) &&
        ((IP_SESSION_STATE*)SessionState)->HeaderInclude == TRUE) {
        UseLocalSessionState = FALSE;
    }

    //
    // We'll resolve the caller's target IP protocol and compartment,
    // and use them to construct a send-datagrams request.
    //
    ASSERT(NetBufferList->Next == NULL);

    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;
    Compartment = IppFindCompartmentById(Protocol, CompartmentId);
    if (Compartment == NULL) {
        NetBufferList->Status = STATUS_NOT_FOUND;
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
        return;
    }

    if (UseLocalSessionState) {
        IppInitializeSessionState(&LocalSessionState);
        LocalSessionState.HeaderInclude = TRUE;
    }

    NBL_SET_PROT_RSVD_FLAG(NetBufferList, NBL_NAT_RESERVED);

    Args.NetBufferList = NetBufferList;
    Args.NlCompartment.Compartment = (CONST NL_COMPARTMENT*)Compartment;
    if (UseLocalSessionState) {
        Args.NlSessionState = &LocalSessionState;
    } else {
        Args.NlSessionState = SessionState;
    }
    Args.UlChecksumOffset = NL_CHECKSUM_OFFSET_NONE;

    IppSendDatagramsCommon(
        FALSE, Flags, Protocol, InspectHandle, &Args);

    if (UseLocalSessionState) {
        IppUninitializeSessionState(&LocalSessionState);
    }
    IppDereferenceCompartment(Compartment);
}

NTSTATUS
NTAPI
IpSetAllDbgInjectRawSendParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Injects a raw IP header-include packet.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    HANDLE InspectHandle;
    IPV6_HEADER UNALIGNED* Ipv6Header;
    PNET_BUFFER_LIST NetBufferList;
    NTSTATUS Status;
    
    PNLP_DBG_INJECT_RAW_SEND_KEY Key =
        (PNLP_DBG_INJECT_RAW_SEND_KEY) Args->KeyStructDesc.KeyStruct;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);

    ASSERT(Client->Protocol == &Ipv6Global);
    
    //
    // Guaranteed by the NSI since we register with this requirement.
    //
    ASSERT(Key != NULL);
    ASSERT(Args->KeyStructDesc.KeyStructLength ==
           sizeof(*Key));

    if (Args->Transaction != NsiTransactionNone) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Args->Action != NsiSetDefault &&
        Args->Action != NsiSetCreateOnly &&
        Args->Action != NsiSetCreateOrSet) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Key->PayloadLength > MAX_IPV6_PAYLOAD) {
        return STATUS_INVALID_PARAMETER;
    }

    InspectHandle = NULL;
    NetBufferList = NULL;
    Status = 
        WfpAleEndpointCreationHandler(
            NULL,
            AF_INET6,
            SOCK_DGRAM,
            Key->NextHeaderValue,
            PsGetCurrentProcess(),
            NULL,
            NULL,
            NULL,
            &InspectHandle);        
    if (!NT_SUCCESS(Status)) {
        goto CleanupAndReturn;
    }

    //
    // Construct a NetBufferList for the injected packet.
    //
    Status =
        IppNetAllocate(
            &NetBufferList,
            (PUCHAR*)&Ipv6Header,
            0,
            sizeof(*Ipv6Header) + Key->PayloadLength);
    if (!NT_SUCCESS(Status)) {
        goto CleanupAndReturn;
    }

    //
    // Initialize an IP header in the space allocated.
    //
    Ipv6Header->VersionClassFlow = IPV6_VERSION;
    Ipv6Header->PayloadLength = RtlUshortByteSwap(Key->PayloadLength);
    Ipv6Header->NextHeader = Key->NextHeaderValue;
    Ipv6Header->HopLimit = Client->Protocol->DefaultHopLimit;
    Ipv6Header->SourceAddress = Key->SourceAddress;
    Ipv6Header->DestinationAddress = Key->DestinationAddress;

    RtlZeroMemory(Ipv6Header + 1, Key->PayloadLength);

    //
    // Inject the packet.
    //
    IppInspectInjectRawSend(
        IPPROTO_IPV6,
        DEFAULT_COMPARTMENT_ID,
        InspectHandle,
        NULL,
        NetBufferList);
    NetBufferList = NULL;

CleanupAndReturn:
    if (NetBufferList != NULL) {
        NetioDereferenceNetBufferList(NetBufferList, FALSE);
    }

    if (InspectHandle != NULL) {
        WfpAleEndpointTeardownHandler(InspectHandle);
    }

    return Status;
}

VOID
IppSlowSendDatagram(
    IN HANDLE ProviderHandle,
    IN PNL_FAST_SEND_DATAGRAM Datagram
    )
{
/*++

Routine Description:

    Called by IpNlpFastSendDatagram for datagrams that must be sent 
    on the slow path due some fast path validation failure.

Arguments:

    ProviderHandle - Provides an NL provider handle that will be cast 
        to IP_CLIENT_CONTEXT.
    
    Datagram - Provides an NL_FAST_SEND_DATAGRAM structure with relevant 
        fields set by the transport layer.

Return Value:

    None.

--*/
    
    NL_REQUEST_SEND_DATAGRAMS SendDatagramRequest = {0};

    RtlCopyMemory(
        &SendDatagramRequest, 
        Datagram, 
        sizeof(NL_FAST_SEND_DATAGRAM));

    IpNlpSendDatagrams(ProviderHandle, &SendDatagramRequest);    
}
    
VOID
IpNlpFastSendDatagram(
    IN HANDLE ProviderHandle,
    IN BOOLEAN DispatchLevel,
    IN PNL_FAST_SEND_DATAGRAM SendDatagram
    )
/*++

Routine Description:

    Called by transport layer to transmit a single NetBufferList 
    using the fast path. 
    
    In order for the send operation to proceed using the send fast 
    a number of conditions must be satisfied or the datagram will 
    fall to the slow path:

    1.) The outbound IP packet and transport WFP layers must be empty.
        At this point, it is best to fall off the fast path as we do not
        have a low cost method of determining which filter would be 
        satisfied on a per datagram basis. We also do not want IPSEC 
        traffic to take this path.
    2.) The network interface must support IP and TCP or UDP checksum offload 
        for IPV4 and only TCP or UDP checksum offload for IPV6. 
    3.) The datagram must be destined to a neighbor.
    4.) The neighbor has already been resolved and is ready for use.
    5.) The path MTU discovery timeout has not fired.
    6.) ECN codepoint has not been negotiated for this traffic.
    7.) If the NL session state structure is not NULL, session state
        options that have been set must be fast path compatible.

    When all of the conditions have been statisfied, the routine retreats
    NetBuffer to the start of the available backfill provided by the 
    transport layer. The IPV4 or IPV6 fields are then set before the 
    datagram is passed to the FL fast send path.
    
Arguments:

    ProviderHandle - Provides an NL provider handle that will be 
        cast to IP_CLIENT_CONTEXT.

    DispatchLevel - Supplies TRUE if IRQL is known to be at DISPATCH level.

    Datagram - Provides an NL_FAST_SEND_DATAGRAM structure with relevant 
        fields set by the transport layer.

Return Value:

    None.

--*/
{
    PNET_BUFFER_LIST NetBufferList;
    PNET_BUFFER NetBuffer;
    PIP_PROTOCOL Protocol;
    PIP_NEIGHBOR NextHopNeighbor;
    PIP_PATH Path;
    PIP_INTERFACE Interface;
    PIP_SESSION_STATE SessionState;
    PIP_SUBINTERFACE SubInterface;
    PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO LargeSendInfo;
    PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ChecksumInfo;
    PNETIO_NET_BUFFER_CONTEXT Context;
    PIPV4_HEADER Ipv4Header;
    PIPV6_HEADER Ipv6Header;
    FL_FAST_SEND_PACKETS FlSendPackets;
    ADDRESS_FAMILY Family;
    PUCHAR HeaderBuffer;
    USHORT Index;
    ULONG IpHeaderSize, TransportHdrSize, BackFill, PayloadLength, OutOctets;
    ULONG FragmentCount, FragmentId, Mss, Processor;
    UINT8 IpHopLimit;
    BOOLEAN Gso;

    //
    // Get address family informtion and make sure WFP filters
    // are not present in the outbound layers.
    //

    Protocol =
        ((PIP_CLIENT_CONTEXT) ProviderHandle)->Protocol;
    Family = Protocol->Family;
    Index = ADDRESS_FAMILY_INDEX(Family);

    if (!KfdIsLayerEmpty(
            AddressFamilyInformation[Index].WfpOutboundIpPacketLayerId) ||
        !KfdIsLayerEmpty(
            AddressFamilyInformation[Index].WfpOutboundTransportLayerId)) {
        IppSlowSendDatagram(ProviderHandle, SendDatagram);
        return;
    }
    
    NextHopNeighbor = (PIP_NEIGHBOR) SendDatagram->NextHop;
    Interface = NextHopNeighbor->Interface;

    //
    // Verify checksum offload capabilities.
    //
    if (SendDatagram->DestProtocol == IPPROTO_TCP) {
        if (!Interface->TransmitOffload.FastPathCompatible) {
            IppSlowSendDatagram(ProviderHandle, SendDatagram);
            return;
        }
    } else {
        ASSERT(SendDatagram->DestProtocol == IPPROTO_UDP);
        if (!Interface->TlDatagramFastPathCompatible) {
            IppSlowSendDatagram(ProviderHandle, SendDatagram);
            return;
        }
    }

    //
    // Verify NextHop availability.
    //
    if (!IppIsNextHopNeighbor((PIP_NEXT_HOP) NextHopNeighbor) ||
        (NextHopNeighbor->AddressType != NlatUnicast) ||
        IppDoesNeighborNeedResolution(NextHopNeighbor, Interface)) {
        IppSlowSendDatagram(ProviderHandle, SendDatagram);
        return;
    }

    SubInterface = NextHopNeighbor->SubInterface;
    Path = (PIP_PATH) SendDatagram->Path;

    NetBufferList = SendDatagram->NetBufferList;
    ASSERT((NetBufferList != NULL) &&
        (NetBufferList->Next == NULL) &&
        (NetBufferList->Scratch == NULL) &&
        (NetBufferList->FirstNetBuffer != NULL) &&
        (NetBufferList->FirstNetBuffer->Next == NULL));
    ASSERT(NetBufferList->Status == STATUS_SUCCESS);

    NetBuffer = NetBufferList->FirstNetBuffer;
    IpHeaderSize = AddressFamilyInformation[Index].HeaderSize;

    //
    // Check if UDP payload size will result in fragmentation.
    //

    //
    // Check if the MTU has changed recently or if the UDP payload
    // size is larger that the path MTU. These most likely will result in
    // fragmentation being required. If so, fall to the slow path.
    //

    if (HAS_PATH_MTU_TIMEOUT_FIRED(Protocol, Interface, SubInterface) ||
        ((SendDatagram->DestProtocol == IPPROTO_UDP) &&
            (NetBuffer->DataLength > (Path->PathMtu - IpHeaderSize)))) {
        IppSlowSendDatagram(ProviderHandle, SendDatagram);
        return;
    }

    Context = (PNETIO_NET_BUFFER_CONTEXT)
        NET_BUFFER_PROTOCOL_RESERVED(NetBuffer);

    //
    // Check that ECN codepoint has not been negotiated for this
    // traffic.
    //
    
    if (Context->EcnField != NlEcnCodepointNotEct) {
        IppSlowSendDatagram(ProviderHandle, SendDatagram);
        return;
    }

    IpHopLimit = 
        (Interface->CurrentHopLimit != 0) ? 
            Interface->CurrentHopLimit : 
            Interface->Compartment->DefaultHopLimit;

    //
    // Check NL session state if not NULL and set the
    // unicast hop limit if necessary.
    //

    if (SendDatagram->NlSessionState != NULL) {

        SessionState = (PIP_SESSION_STATE) 
            SendDatagram->NlSessionState;

        if (SessionState->FastPathCompatible == FALSE) {
            IppSlowSendDatagram(ProviderHandle, SendDatagram);
            return;
        }

        //
        // Update the hop limit value if needed.
        //

        if (SessionState->UnicastHopLimit != IP_UNSPECIFIED_HOP_LIMIT) {
            IpHopLimit = (UINT8) SessionState->UnicastHopLimit;
        }
    }

    //
    // We are now cleared to send this packet. Lets get the information
    // required to proceed with the send operation.
    // 
    
    PayloadLength = NetBuffer->DataLength;
    ASSERT(Interface->FlBackfill >= sizeof(ETHERNET_HEADER));
    BackFill = IpHeaderSize + sizeof(ETHERNET_HEADER);

    //
    // Retreat the buffer and make sure it is contiguous.
    // 
    
    (VOID) NetioRetreatNetBuffer(NetBuffer, BackFill, 0);
    ASSERT(NetioGetContiguousDataBufferSize(NetBuffer) >= BackFill);

    //
    // Get the header buffer. It should alway be aligned.
    //
    
    TransportHdrSize = 
        ((SendDatagram->DestProtocol == IPPROTO_TCP) ?
            sizeof(TCP_HDR) : 
            sizeof(UDP_HDR));

    HeaderBuffer = 
        NetioGetDataBufferSafe(NetBuffer, (BackFill + TransportHdrSize));
    ASSERT(((ULONG_PTR)(HeaderBuffer) & 
        (__builtin_alignof(ETHERNET_HEADER) - 1)) == 0);

    LargeSendInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)
        &NET_BUFFER_LIST_INFO(NetBufferList, TcpLargeSendNetBufferListInfo);
    ChecksumInfo = (PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO)
         &NET_BUFFER_LIST_INFO(NetBufferList, TcpIpChecksumNetBufferListInfo);

    //
    // Get the number of MSS segments and compute full pseudoheader
    // checksum if needed. The Gso (LSOv2) flag is needed to 
    // differentiate between LSO or GSO operations. 
    //
    // We also need to determine the number fragments in datagram for 
    // the IPV4 identification field and the statistics calculation
    // later.
    // 

    Gso = FALSE;

    if (LargeSendInfo->Value != 0) {

        Mss = LargeSendInfo->LsoV2Transmit.MSS;
        FragmentCount = (Context->OriginalDataLength + (Mss - 1)) / Mss;
        ASSERT(FragmentCount < 0x4000);

        if (LargeSendInfo->Transmit.Type ==
                NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE) {
            LargeSendInfo->LsoV2Transmit.TcpHeaderOffset = BackFill;
            //
            // Update the packet type. This is supposed to simplify 
            // the hardware design. Otherwise they need to dig into the 
            // MAC header to figure this out.
            //
            LargeSendInfo->LsoV2Transmit.IPVersion = 
                (IS_IPV4_PROTOCOL(Protocol)) ?
                    NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4 :
                    NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6;
                
            Gso = TRUE;
        }
        if (LargeSendInfo->Transmit.Type == 
                NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE) {
            LargeSendInfo->LsoV1Transmit.TcpHeaderOffset = BackFill;
        }        

    } else {
        UINT16 Checksum = 
            IppChecksumDatagram(
                NULL,
                PayloadLength,
                NL_ADDRESS(Path->SourceAddress),
                Path->DestinationAddress,
                AddressFamilyInformation[Index].AddressBytes,
                SendDatagram->DestProtocol,
                SendDatagram->PseudoHeaderChecksum);

        if (SendDatagram->DestProtocol == IPPROTO_TCP) {
            PTCP_HDR TcpHeader = (PTCP_HDR) (HeaderBuffer + BackFill);
            TcpHeader->th_sum = Checksum;
        
            //
            // TCP checksum flags (set for non-large send traffic).
            // 
        
            ChecksumInfo->Transmit.TcpChecksum = TRUE;

            //
            // Update the Tcp Header offset for the checksum offload.
            //

            ChecksumInfo->Transmit.TcpHeaderOffset = BackFill;
        } else {
            PUDP_HDR UdpHeader = (PUDP_HDR) (HeaderBuffer + BackFill);
            ASSERT(SendDatagram->DestProtocol == IPPROTO_UDP);

            UdpHeader->uh_sum = Checksum;

            //
            // UDP checksum flag.
            //

            ChecksumInfo->Transmit.UdpChecksum = TRUE;
        }
        
        if (IS_IPV4_PROTOCOL(Protocol)) {
            ChecksumInfo->Transmit.IsIPv4 = TRUE;
            ChecksumInfo->Transmit.IpHeaderChecksum = TRUE;
        } else {
            ChecksumInfo->Transmit.IsIPv6 = TRUE;
        }
            
        FragmentCount = 1;
    }

    //
    // Fill IP header fields here.
    //
    
    if (IS_IPV4_PROTOCOL(Protocol)) {

        //
        // IPV4 Header Fields.
        //

        Ipv4Header = (PIPV4_HEADER) (((PETHERNET_HEADER) HeaderBuffer) + 1);
 
        //
        // Set TotalLength field to zero for GSO enabled sends only.
        //
        
        Ipv4Header->TotalLength = 
            ((!Gso) ? RtlUshortByteSwap((PayloadLength + IpHeaderSize)) : 0);
        
        Ipv4Header->VersionAndHeaderLength = IPV4_DEFAULT_VERHLEN;
        Ipv4Header->TypeOfService = 0;
        Ipv4Header->TimeToLive = IpHopLimit;
        Ipv4Header->FlagsAndOffset = 0;
        Ipv4Header->DontFragment = !Path->Flags.ForceFragment;
        Ipv4Header->HeaderChecksum = 0;
        Ipv4Header->EcnField = 0;
        Ipv4Header->Protocol = (UINT8) SendDatagram->DestProtocol;
        Ipv4Header->SourceAddress = 
            *((PIN_ADDR) NL_ADDRESS(Path->SourceAddress));
        Ipv4Header->DestinationAddress = 
            *((PIN_ADDR) Path->DestinationAddress);

        do {
            FragmentId = 
                InterlockedExchangeAdd(&Interface->FragmentId, FragmentCount);
            FragmentId &= 0x7FFF;
        } while ((LargeSendInfo->Value != 0) && 
                ((LargeSendInfo->Transmit.Type ==
                    NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE)||
                (LargeSendInfo->Transmit.Type ==
                    NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE)) &&
                ((FragmentId + FragmentCount) > 0x7FFF));
            
        Ipv4Header->Identification = RtlUshortByteSwap(FragmentId);
    } else {
        ASSERT(Family == AF_INET6);

        //
        // IPV6 Header Fields.
        //
        
        Ipv6Header = (PIPV6_HEADER) (((PETHERNET_HEADER) HeaderBuffer) + 1);

        //
        // Set PayloadLength field to zero for GSO enabled sends only.
        //
                
        Ipv6Header->PayloadLength = 
            ((!Gso) ? RtlUshortByteSwap(PayloadLength) : 0);
        
        Ipv6Header->VersionClassFlow = IPV6_VERSION;
        Ipv6Header->NextHeader = (UINT8) SendDatagram->DestProtocol;
        Ipv6Header->HopLimit = IpHopLimit;
        Ipv6Header->SourceAddress = 
            *((PIN6_ADDR) NL_ADDRESS(Path->SourceAddress));
        Ipv6Header->DestinationAddress = 
            *((PIN6_ADDR) Path->DestinationAddress);
    }

    //
    // Store start of header buffer in the NetBufferList scratch field 
    // for use by FlFastSendPacket().
    //

    NetBufferList->Scratch = HeaderBuffer;
    ASSERT(NetBufferList->Status == STATUS_SUCCESS);

    IppVerifyDataLength(NetBuffer);
    OutOctets =
        (((IpHeaderSize + TransportHdrSize) * FragmentCount) +
            Context->OriginalDataLength);    
    
    //
    // Set the FL fast send structure fields. 
    //

    FlSendPackets.NetBufferList = NetBufferList;
    FlSendPackets.DlDestination = 
        IP_NEIGHBOR_DL_ADDRESS(
            NextHopNeighbor, 
            AddressFamilyInformation[Index].AddressBytes);

    //
    // Call the FL fast send routine.
    //

    Interface->FlModule->Npi.Dispatch->FastSendPackets(
        SubInterface->FlContext,
        DispatchLevel,
        &FlSendPackets);

    //
    // Update global network statistics.
    // 

    Processor = KeGetCurrentProcessorNumber();

    SubInterface->PerProcessorStatistics[Processor]->OutTransmits +=
        FragmentCount;
    SubInterface->PerProcessorStatistics[Processor]->OutOctets += OutOctets;

    Protocol->PerProcessorStatistics[Processor].OutRequests++;
    Protocol->PerProcessorStatistics[Processor].OutTransmits += FragmentCount;
    Protocol->PerProcessorStatistics[Processor].OutOctets += OutOctets;
}

NETIO_INLINE
VOID
IppClearChecksumNetBufferList(
    IN USHORT UlChecksumOffset,
    IN OUT PNET_BUFFER_LIST NetBufferList
    )
/*++

Routine Description:
    
    Clear transport checksum to 0.

Arguments:

    UlChecksumOffset - Supplies the offset into the TL header.

    NetBufferList - Supplies the list of packets for which to clean checksums. 

Return Value:

    None.

--*/    
{
    PNET_BUFFER NetBuffer; 
    UINT16 Checksum = 0;

    for (NetBuffer = NetBufferList->FirstNetBuffer; 
         NetBuffer != NULL; 
         NetBuffer = NetBuffer->Next) {

         IppFillChecksumAtOffset(
            Checksum,
            UlChecksumOffset,
            NetBuffer);
    }
}

NETIO_INLINE
VOID
IppRebuildUpperLayerProtocolChecksum(
    IN UINT8 NextHeader,
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:
    
    Clear and recompute transport (full) checksum for TCP, UDP, 
    and ICMP/v6.

Arguments:

    NextHeader - Supplies the transport protocol.

    Protocol - Supplies the protocol. 

    Control - Supplies the control structure.

Return Value:

    None.

--*/    
{
    USHORT UlChecksumOffset = NL_CHECKSUM_OFFSET_NONE;
    ULONG PseudoHeaderChecksum;

    if (NextHeader == IPPROTO_TCP) {
        UlChecksumOffset = FIELD_OFFSET(TCP_HDR, th_sum);
    }
    else if (NextHeader == IPPROTO_UDP) {
        UlChecksumOffset = FIELD_OFFSET(UDP_HDR, uh_sum);
    }
    else if ((NextHeader == IPPROTO_ICMP) || 
             (NextHeader == IPPROTO_ICMPV6)) {
        UlChecksumOffset = FIELD_OFFSET(ICMP_HEADER, Checksum);
    }

    if (UlChecksumOffset == NL_CHECKSUM_OFFSET_NONE) {
        return;
    }

    //
    // TODO: consider accepting partial checksum via a new param 
    //       and construct pseudo checksums here. 

    //
    // First set the existing transport header checksum to 0 
    // because it is likely not valid anymore (due to source/dest 
    // address change).
    //
    IppClearChecksumNetBufferList(
        UlChecksumOffset,
        Control->NetBufferList);

    //
    // Second calculate the Pseudo Header Checksum based one 
    // the new source/dest and next protocol.
    //
    PseudoHeaderChecksum =
        IppChecksumDatagram(
            NULL,
            0,
            NL_ADDRESS(Control->SourceLocalAddress),
            Control->FinalDestinationAddress.Buffer,
            Protocol->Characteristics->AddressBytes,
            Control->DestinationProtocol,
            0);

    //
    // Third given the Pseudo Header Checksum (same for all NBs), 
    // calculate full checksums for each packet (i.e. NB) under 
    // the NBL.
    //
    IppChecksumNetBufferList(
        Protocol, 
        PseudoHeaderChecksum, 
        UlChecksumOffset, 
        Control, 
        FALSE);
}

NETIO_INLINE
NTSTATUS
IppBuildFirstHeader(
    IN ULONG Backfill,
    IN PNET_BUFFER NetBuffer,
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    OUT PUCHAR *FirstIpHeader,
    IN ULONG HeaderLength,
    IN UINT8 NextHeader
    )
/*++

Routine Description:
    
    This function is a variant of IppFillNextHeader. The only differences 
    are that it uses Ndis Net Buffer api to manipulate the packet and that 
    it fails should the ip header is not contiguous or aligned.

Arguments:

    See function comment for IppFillNextHeader.

Return Value:

    STATUS_SUCCESS or failure code.

--*/    
{
    NTSTATUS Status = STATUS_SUCCESS;
    PUCHAR IpHeader;

    Status = NdisRetreatNetBufferDataStart(
                NetBuffer, 
                HeaderLength, 
                Backfill, 
                NULL);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (Control->HeaderInclude) {

        //
        // We assume IP header is contiguous & 2/4 bytes aligned for 
        // header rebuild. 
        //

        IpHeader = NetioGetDataBufferSafe(NetBuffer, HeaderLength);
        ASSERT(IpHeader != NULL);
        
        ASSERT(Control->HeaderIncludeHeaderLength == HeaderLength);
        RtlCopyMemory(IpHeader, Control->HeaderIncludeHeader, HeaderLength);    
            
        Protocol->FillHeaderIncludeProtocolHeader(
            Control,
            IpHeader,
            NetBuffer,
            HeaderLength,
            NextHeader);
    } else {   

        //
        // Check if the IP header is contiguous and properly aligned. 
        //

        IpHeader = 
            NetioGetDataBufferIfSafe(
                NetBuffer, 
                HeaderLength,
                Protocol->HeaderAlignment,
                0);
        if (IpHeader == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status =
            Protocol->FillProtocolHeader(
                Control,
                IpHeader, 
                NetBuffer, 
                HeaderLength, 
                NextHeader);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    *FirstIpHeader = IpHeader;

    return STATUS_SUCCESS;
}

NETIO_INLINE
NTSTATUS
IppBuildNextHeader(
    IN ULONG Backfill,
    IN PNET_BUFFER NetBuffer,
    IN PIP_PROTOCOL Protocol,
    IN OUT PIP_REQUEST_CONTROL_DATA Control,
    IN PUCHAR FirstIpHeader,
    IN ULONG HeaderLength
    )
/*++

Routine Description:
    
    This function is a variant of IppFillNextHeader. The only difference is
    that it uses Ndis Net Buffer api to manipulate the packet.

    Arguments:

    See function comment for IppFillNextHeader.

Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
    NTSTATUS Status;
    PUCHAR IpHeader;

    Status = NdisRetreatNetBufferDataStart(
                NetBuffer, 
                HeaderLength, 
                Backfill, 
                NULL);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    IpHeader = 
        NetioGetDataBufferIfSafe(
            NetBuffer, 
            HeaderLength,
            Protocol->HeaderAlignment,
            0);
    if (IpHeader == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyMemory(IpHeader, FirstIpHeader, HeaderLength);
    
    Protocol->UpdateProtocolHeader(Control, IpHeader, NetBuffer);

    return STATUS_SUCCESS;
}

NTSTATUS
IppPacketizeDatagramsForHeaderBuild(
    IN PIP_REQUEST_CONTROL_DATA Control
    )
/*++

Routine Description:

    Compose network layer headers for each NetBuffer in the NetBufferList.
    This function does NOT compose Ipsec headers, nor does it send composed 
    packets.

Arguments:

    Control - Supplies the control structure.

Return Value:

    STATUS_SUCCESS or failure code.
    
Caller IRQL:

    Callable at PASSIVE through DISPATCH.

--*/
{   
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_INTERFACE Interface = Control->NextHop->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    PIP_PROTOCOL Protocol = Compartment->Protocol;
    PNET_BUFFER NetBuffer; 
    ULONG IpHeaderLength;
    PUCHAR FirstIpHeader = NULL;
    ULONG IpHeaderBackfill;
    //
    // The ExtensionHeader array needs to be big enough to hold the following:
    // 1. IPv6 Hop-by-Hop Options header 
    // 2. Routing Header
    // 3. Destination Options header
    // The elements in the array are placed in the reverse order.
    // ExtensionHeaders[0] is the innermost header, and
    // ExtensionHeaders[ExtensionHeaderCount - 1] is the outermost header.
    //
    ULONG i, ExtensionHeaderLength = 0, ExtensionHeaderCount = 0;
    IP_EXTENSION_HEADER_INFORMATION ExtensionHeader[3];
    PIP_EXTENSION_HEADER_INFORMATION Header;

    Status = IppComputeHeaderLengthAndFillExtensionHeaders(
                Protocol,
                Control,
                ExtensionHeader,
                &IpHeaderLength,
                &ExtensionHeaderCount,
                &ExtensionHeaderLength
                );
    if (!NT_SUCCESS(Status)) {
        goto Bail;
    }
    
    for (NetBuffer = Control->NetBufferList->FirstNetBuffer; 
         NetBuffer != NULL; 
         NetBuffer = NetBuffer->Next) {

        ULONG NextBackfill = Control->IpHeaderAndExtensionHeadersLength + 
                             Interface->FlBackfill;
        UINT8 NextHeader = (UINT8) Control->DestinationProtocol;
        
        //
        // Insert all extension headers first.
        //
        for (i = 0; i < ExtensionHeaderCount; i++) {
            PIP_INTERNAL_ADD_HEADER AddHeader;
            
            Header = &ExtensionHeader[i];
            
            NextBackfill -= Header->HeaderLength;
            
            Status =
                NdisRetreatNetBufferDataStart(
                    NetBuffer,
                    Header->HeaderLength,
                    NextBackfill,
                    NULL);
            if (!NT_SUCCESS(Status)) {
                goto Bail;
            }

            AddHeader = Protocol->ReceiveDemux[Header->NextHeader].
                InternalAddHeader;

            Status = AddHeader(Control, NetBuffer, NextHeader, NULL);
            if (!NT_SUCCESS(Status)) {
                goto Bail;
            }
            
            NextHeader = Header->NextHeader;
        }

        //
        // And then insert the IP header.
        //
        ASSERT(NextBackfill == (IpHeaderLength + Interface->FlBackfill));

        //
        // It is possible that the packet we construct for Wfp will 
        // need to be Ipsec protected when it is injected back to the 
        // Stack via a raw send. Here we make room to hold the largest
        // possible AH and/or ESP headers (MAX_IPSEC_HEADERS_SIZE); 
        // otherwise the future raw send could result in non-contiguous 
        // ip header -- IP header must be contiguous on the send path.
        //
        // If the packet already contains IP header, then it is up to
        // the caller to provide above guarantees.
        // 
        IpHeaderBackfill = (Control->HeaderInclude ? Interface->FlBackfill :
                                             (Interface->FlBackfill + 
                                              MAX_IPSEC_HEADERS_SIZE));

        if (FirstIpHeader == NULL) {
            Status =
                IppBuildFirstHeader(
                    IpHeaderBackfill,
                    NetBuffer,
                    Protocol,
                    Control,
                    &FirstIpHeader,
                    IpHeaderLength,
                    NextHeader);
        } else {
            Status =
                IppBuildNextHeader(
                    IpHeaderBackfill,
                    NetBuffer,
                    Protocol,
                    Control,
                    FirstIpHeader,
                    IpHeaderLength);
        }
        
        if (!NT_SUCCESS(Status)) {
            goto Bail;
        }

        if (IS_IPV4_PROTOCOL(Protocol))
        {
           IppInspectFillIpv4PacketChecksum(NetBuffer);
        }
    }

Bail:
    
    return Status;
}

NETIO_INLINE
ULONG
IppGetBasicHeaderLength(
    IN PNET_BUFFER NetBuffer,
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Return the header size encoded in the header for IPv6 and return the
    the fixed header size of IPv6.

Arguments:

    NetBuffer - Supplies the packet to parse header size out.

    Protocol - Supplies the protocol.

Return Value:

     > 0 - Header size encoded. 
    == 0 - Error.

--*/
{
    ULONG HeaderSize = 0;

    if (IS_IPV4_PROTOCOL(Protocol))
    {
        IPV4_HEADER *Ipv4Header, Ipv4HeaderBuffer;
        if (NET_BUFFER_DATA_LENGTH(NetBuffer) >= sizeof(Ipv4HeaderBuffer))
        {
            Ipv4Header = NetioGetDataBuffer(
                            NetBuffer, 
                            sizeof(Ipv4HeaderBuffer), 
                            &Ipv4HeaderBuffer, 
                            __builtin_alignof(IPV4_HEADER), 
                            0);
            if (Ipv4Header != NULL)
            {
                HeaderSize = (Ipv4Header->HeaderLength << 2);
            }
        }
    }
    else
    {
        HeaderSize = Protocol->HeaderSize;
    }

    return HeaderSize;
}

NTSTATUS
IppInspectBuildHeaders(
    IN OUT PNET_BUFFER_LIST NetBufferList,
    IN ULONG HeaderIncludeHeaderLength,
    IN IPPROTO IpProtocol,
    IN const UCHAR* SourceAddress,
    IN const UCHAR* RemoteAddress,
    IN UINT8 TransportProtocol,
    IN NL_CLIENT_DISPATCH_FLAGS ClientFlags,
    IN PVOID SessionState OPTIONAL,
    IN PVOID AncillaryData OPTIONAL,
    IN ULONG AncillaryDataLength
    )
/*++

Routine Description:

    Build or re-build network layer headers for each NetBuffer in the 
    NetBufferList given 3-tuple (source/dest/proto), address family,
    session state, as well as socket ancillary data. 

    Headers are built as if it were to be sent over the interface per the
    result of a route lookup (based on destination) but with LSO and checksum
    offload disabled. 

    N.B. The input NBL is not a netio NBL (there is no netio context) and
    hence this function and subroutines should not use Netio retreat or 
    advance function to manipulate the NBL, instead Ndis version of the 
    retreat/advance function should be used instead.

Arguments:

    NetBufferList - NetBufferList to build headers.
    
    HeaderIncludeHeaderLength - Length of existing ntework layer headers.

    IpProtocol - IPPROTO_IP or IPPROTO_IPV6

    SourceAddress - Source address in network order.

    RemoteAddress - Destination address in network order.

    TransportProtocol - Transport layer protocol.

    ClientFlags - Supplies the client's send defaults.

    SessionState - Session state containing socket options. 

    AncillaryData/AncillaryDataLength - Ancillary data containing socket options. 

Return Value:

    STATUS_SUCCESS or failure code.
    
Caller IRQL:

    Callable at PASSIVE through DISPATCH.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_PROTOCOL Protocol;
    PIP_SESSION_STATE State = (PIP_SESSION_STATE)SessionState;
    IP_REQUEST_CONTROL_DATA Control = {0};
    PIP_COMPARTMENT Compartment = NULL;
    PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO NblInfo;
    NL_LOCAL_ADDRESS_ARG LocalAddressArg = {0};
     
    //
    // Disable LSO processing.
    // TODO: consider adding a flag to preserve LSO.
    //
    NblInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)(
            &NET_BUFFER_LIST_INFO(
                NetBufferList,
                TcpLargeSendNetBufferListInfo));
    NblInfo->Value = 0;

    Protocol = (IpProtocol == IPPROTO_IP) ? &Ipv4Global : &Ipv6Global;

    //
    // Relax header include checks for header build.
    //
    ClientFlags.EnforceHeaderIncludeChecks = 0;

    IppInitializeOnStackControlForLocalSend(
        &Control, 
        ClientFlags, 
        NetBufferList);

    //
    // Parse the IP header if HeaderIncludeHeaderLength is not given 
    // for raw sends.
    //
    if (HeaderIncludeHeaderLength == 0) {
        if ((State != NULL) && State->HeaderInclude) {
            UINT8 DestinationProtocol;

            ASSERT(NET_BUFFER_LIST_FIRST_NB(NetBufferList)->Next == NULL);
            
            Status = Protocol->
               SkipNetworkLayerHeaders(
                   NET_BUFFER_LIST_FIRST_NB(NetBufferList), 
                   NULL, 
                   NULL, 
                   NULL, 
                   &DestinationProtocol,
                   &HeaderIncludeHeaderLength);
            if (!NT_SUCCESS(Status)) {
                goto Error;
            }

            if ((HeaderIncludeHeaderLength == 0) || 
                (DestinationProtocol != TransportProtocol)) {
                Status = STATUS_INVALID_PARAMETER;
                goto Error;
            }

            //
            // Restore the advancement done by SkipNetworkLayerHeaders.
            //
            NetioRetreatNetBuffer(
                NET_BUFFER_LIST_FIRST_NB(NetBufferList), 
                HeaderIncludeHeaderLength, 
                0);
        }
    }

    if (HeaderIncludeHeaderLength > 0) {

        //
        // When rebuilding IP headers, we will preserve IPv4 options but all
        // IPv6 extension headers will be discarded.
        //
        ULONG BasicHeaderLength = IppGetBasicHeaderLength(
                                    NET_BUFFER_LIST_FIRST_NB(NetBufferList),
                                    Protocol);
        if ((BasicHeaderLength == 0) ||
            (BasicHeaderLength > HeaderIncludeHeaderLength))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto Error;
        }

        ASSERT(NET_BUFFER_LIST_FIRST_NB(NetBufferList)->Next == NULL);

        Status = IppAllocateAndCopyHeaderIncludeHeader(
                    BasicHeaderLength, 
                    &Control);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        if (IS_IPV4_PROTOCOL(Protocol))
        {
            PIPV4_HEADER Ipv4Header = 
                (PIPV4_HEADER)(Control.HeaderIncludeHeader);

            Ipv4Header->SourceAddress = *((PIN_ADDR) SourceAddress);
            Ipv4Header->DestinationAddress = 
                *((IN_ADDR UNALIGNED *)RemoteAddress);
            Ipv4Header->Protocol = TransportProtocol;
        }
        else
        {
            PIPV6_HEADER Ipv6Header = 
                (PIPV6_HEADER)(Control.HeaderIncludeHeader);
                
            Ipv6Header->SourceAddress = *((PIN6_ADDR) SourceAddress);
            Ipv6Header->DestinationAddress = *((PIN6_ADDR) RemoteAddress);
            Ipv6Header->NextHeader = TransportProtocol;
        }

        //
        // Rest of the code assumes NB offset starts with transport header.
        //
        NetioAdvanceNetBuffer(
            NET_BUFFER_LIST_FIRST_NB(NetBufferList), 
            HeaderIncludeHeaderLength);
    }

    RtlCopyMemory(
        Control.FinalDestinationAddress.Buffer,
        RemoteAddress,
        Protocol->Characteristics->AddressBytes);

    Control.CurrentDestinationAddress = RemoteAddress;

    Compartment = IppFindCompartmentById(Protocol, UNSPECIFIED_COMPARTMENT_ID);
    LocalAddressArg.Address = SourceAddress;

    Status = IppFindOrSpoofLocalAddressForRawSend(
                Protocol,
                Compartment,
                &LocalAddressArg,
                RemoteAddress,
                &Control);
    if (!NT_SUCCESS(Status)) {
        goto Error;
    }

    if (AncillaryDataLength != 0) {

        ASSERT(AncillaryData != NULL);

        Status = 
            IppProcessAncillaryData(
                Protocol,
                AncillaryData,
                AncillaryDataLength,
                TRUE,
                &Control);
        if (!NT_SUCCESS(Status)) {
            goto Error;
        }
    }

    if (SessionState != NULL) {
        Status = IppProcessSessionState(Protocol, SessionState, &Control);
        if (!NT_SUCCESS(Status)) {
            goto Error;
        }
    }

    Control.DestinationProtocol = TransportProtocol;

    if (Control.NextHop == NULL)
    {
        //
        // Join path is needed in case the local address is present in the
        // local machine. Otherwise the "spoof" operation above would have
        // given us the next-hop (which would give us all information to
        // construct the packet header).
        //
        NL_REQUEST_JOIN_PATH JoinPathArgs = {0};

        JoinPathArgs.NlCompartment.Compartment = 
            (CONST NL_COMPARTMENT*)Compartment;
        JoinPathArgs.NlSessionState = SessionState;
        JoinPathArgs.AncillaryDataLength = AncillaryDataLength;
        JoinPathArgs.AncillaryData = AncillaryData;
        JoinPathArgs.RemoteAddress = RemoteAddress;
        JoinPathArgs.NlLocalAddress.Address = SourceAddress;
        Status = IppJoinPath(Protocol, &JoinPathArgs);
        if (!NT_SUCCESS(Status)) {
            goto Error;
        }
        
        ASSERT(JoinPathArgs.Path != NULL);
        Control.Path = (PIP_PATH) JoinPathArgs.Path;
        Control.IsPathReferenced = TRUE;

        ASSERT(Control.SourceLocalAddress ==
                (PIP_LOCAL_UNICAST_ADDRESS) Control.Path->SourceAddress);

        Control.NextHop = IppGetNextHopFromPath(Control.Path);
        if (Control.NextHop == NULL) {
            Status = STATUS_NOT_FOUND;
            goto Error;
        }
        Control.IsNextHopReferenced = TRUE;        
    }

    Control.Compartment = 
        Control.SourceLocalAddress->Interface->Compartment;
    Control.CurrentDestinationType = NlppNextHopAddressType(Control.NextHop);

    IppProcessDefaults(Protocol, 0, TransportProtocol, &Control);

    IppRebuildUpperLayerProtocolChecksum(
        TransportProtocol, 
        Protocol, 
        &Control);

    Status = IppPacketizeDatagramsForHeaderBuild(&Control);

Error:
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);
    }

    IppCleanupSendState(&Control, FALSE);

    //
    // Be sure Control->NetBufferList is not deref'ed. 
    //
    Control.NetBufferList = NULL;

    ASSERT(Control.IsAllocated == FALSE);
    
    IppCompleteAndFreePacketList(&Control, FALSE);

    return Status;
}
