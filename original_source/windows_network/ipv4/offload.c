/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    offload.c

Abstract:

    This module contains the main IPv4 offload support routines

Author:

    Weiying Song 12-July-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"

//TODO: Implement the functions properly

VOID
NTAPI
Ipv4QueryOffloadComplete (
    IN PNDIS_PROTOCOL_OFFLOAD_BLOCK_LIST OffloadBlockList
    )
/*++

Routine Description:



Arguments:

    OffloadBlockList - Supplies the list that was passed in when the
        framing layer client requested a query and contains information
        on what states to query. On successful return, each element
        in this list contains the queried information.
                
Return Value:

    None.
    
Caller IRQL: PASSIVE_LEVEL.

--*/
{
    PASSIVE_CODE();

    DBG_UNREFERENCED_PARAMETER(OffloadBlockList);
    return;
}
