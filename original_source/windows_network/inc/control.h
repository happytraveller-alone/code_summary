/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    control.h

Abstract:

    This module contains declarations for the network layer module's
    control (ICMP) message handling.

Author:

    Mohit Talwar (mohitt) Tue Mar 25 14:46:50 2003

Environment:

    Kernel mode only.

--*/

#ifndef _CONTROL_
#define _CONTROL_

#pragma once

//
// Minimum interval between ICMP error message generation for a destination.
// In timer ticks (500 ms).
//
#define ICMP_MIN_ERROR_INTERVAL 1

//
// Maximum number of ICMP error messages outstanding at any one time.
//
#define ICMP_MAX_ERROR_COUNT 1000

//
// Maximum number of ICMP error messages generated from an interface per tick.
//
#define ICMP_MAX_INTERFACE_ERROR_COUNT 100

BOOLEAN
IppRateLimitIcmp(
    IN PIP_PATH Path
    );

NTSTATUS
IppAllocateIcmpError(
    OUT PNET_BUFFER_LIST *NetBufferList,
    OUT PUCHAR *FlatBuffer,
    IN ULONG Offset,
    IN ULONG Length
    );

VOID
IppSendControl(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PNL_REQUEST_GENERATE_CONTROL_MESSAGE FirstArgs
    );

VOID
IppSendError(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA FirstArgs,
    IN UINT8 Type,
    IN UINT8 Code,
    IN ULONG ErrorParameter,
    IN BOOLEAN MulticastOverride
    );

VOID
IppSendErrorList(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA FirstArgs,
    IN UINT8 Type,
    IN UINT8 Code,
    IN ULONG ErrorParameter,
    IN BOOLEAN MulticastOverride
    );

VOID
IppSendErrorListForDiscardReason(
    IN BOOLEAN DispatchLevel,
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA ControlList,
    IN IP_DISCARD_REASON DiscardReason,
    IN ULONG ErrorParameter
    );

__inline
VOID
IppUpdateIcmpOutStatistics(
    IN PIP_PROTOCOL Protocol,
    IN UINT8 Type
    )
/*++

Routine Description:

   Updates the outbound ICMP statistics for the given protocol.
   
Arguments:

    Protocol - Supplies the protocol for which the ICMP statistics must be
        updated.

Return Value:

    None.

--*/
{
    Protocol->IcmpStatistics.OutMessages++;
    Protocol->IcmpStatistics.OutTypeCount[Type]++;
}

NL_PROVIDER_GENERATE_CONTROL_MESSAGE IpNlpGenerateIcmpMessage;

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllIcmpParameters;

#endif // _CONTROL_
