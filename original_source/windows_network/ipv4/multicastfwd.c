/*++

Copyright (c) 2002-2005  Microsoft Corporation

Module Name:

    multicastfwd.c

Abstract:

    This module contains the functions of IPv4 multicast forwarding module.
    
Environment:

    Kernel mode only.

--*/

#include "precomp.h"

NTSTATUS
NTAPI
Ipv4GetAllMulticastForwardingParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a given Mfe.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PIP_PROTOCOL Protocol = &Ipv4Global;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(IPV4_MFE_KEY));

    return IppGetAllMulticastForwardingParameters(Protocol, Args);
}

  
NTSTATUS
NTAPI
Ipv4SetAllMulticastForwardingParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function is used to set/create an Mfe. 

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PIPV4_MFE_KEY Key = (PIPV4_MFE_KEY)Args->KeyStructDesc.KeyStruct;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_PROTOCOL Protocol = &Ipv4Global;
    PNL_MFE_RW MfeRw = (PNL_MFE_RW)Args->RwStructDesc.RwParameterStruct;
    
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(IPV4_MFE_KEY));

    Status = 
        IppSetAllMulticastForwardingParameters(
            Args->Action,
            Args->Transaction,
            Protocol,
            Key->CompartmentId,
            (CONST UCHAR*) &Key->Group, 
            (CONST UCHAR*) &Key->SourcePrefix, 
            Key->SourcePrefixLength, 
            MfeRw, 
            &Args->ProviderTransactionContext);

    return Status;

}


