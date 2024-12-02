/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    ctrlv4.h

Abstract:

    This module contains the private (internal) definitions and structures
    for IPv4 ICMP handling.

Author:

    Stephanie Song (weiyings) 16-May-2003

Environment:

    kernel mode only

--*/

#ifndef _CTRLV4_
#define _CTRLV4_


typedef struct _IPV4_ECHO_REQUEST_CONTEXT {
    IP_ECHO_REQUEST_CONTEXT;

    IPV4_ECHO_REQUEST_ROD Rod;
    IPV4_ECHO_REQUEST_RW Rw;
} IPV4_ECHO_REQUEST_CONTEXT, *PIPV4_ECHO_REQUEST_CONTEXT;

VOID
Ipv4SendEchoRequestComplete(
    PNET_BUFFER_LIST NetBufferList,
    ULONG Count,
    BOOLEAN DispatchLevel
    );

#endif
