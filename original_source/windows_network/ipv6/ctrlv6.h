/*++

Copyright (c) 2001  Microsoft Corporation

Module Name:

    ctrlv6.h

Abstract:

    This module contains the private (internal) definitions and structures
    for IPv6 ICMP handling.

Author:

    Stephanie Song (weiyings) 16-May-2003

Environment:

    kernel mode only

--*/

#ifndef _CTRLV6_
#define _CTRLV6_

typedef struct _IPV6_ECHO_REQUEST_CONTEXT {
    IP_ECHO_REQUEST_CONTEXT;
    
    IPV6_ECHO_REQUEST_ROD Rod;
    IPV6_ECHO_REQUEST_RW Rw;
} IPV6_ECHO_REQUEST_CONTEXT, *PIPV6_ECHO_REQUEST_CONTEXT;

VOID
Ipv6SendEchoRequestComplete(
    PNET_BUFFER_LIST NetBufferList,
    ULONG Count,
    BOOLEAN DispatchLevel
    );


#endif
