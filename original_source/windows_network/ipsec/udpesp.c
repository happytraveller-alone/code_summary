/*++

Copyright (c) Microsoft Corporation

Module Name:

    udpesp.c

Abstract:

    This is a dummy module containing stubs for functions relating to
    ESP-over-UDP packets.  The IPsec team owns the actual module.

Author:

    Raymond Sinnappan (RaymondS) 28-Sep-2004

Environment:

    Kernel mode and user mode.

--*/

#include "precomp.h"

VOID
IpSecGetSendUdpEspEncapsulationPorts(
   IN PVOID PacketHandle,
   OUT UINT16* SourcePort,
   OUT UINT16* DestinationPort
   )
/*++

Routine Description: 

   Returns the ports to use when creating the UDP header of
   an ESP-over-UDP packet.

Arguments:

   PacketHandle - Ignored.
   
   SourcePort - Returns UDP source port.
   
   DestinationPort - Returns UDP destination port.

Return Value:

    None.

--*/
{
   UNREFERENCED_PARAMETER(PacketHandle);
   
   *SourcePort = IPSEC_ISAKMP_NATT_PORT;
   *DestinationPort = IPSEC_ISAKMP_NATT_PORT;
}
