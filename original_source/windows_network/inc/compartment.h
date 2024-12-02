/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    compartment.h

Abstract:

    This module contains declarations for the network layer module's
    compartment management.

Author:

    Mohit Talwar (mohitt) Tue Nov 19 09:44:52 2002

Environment:

    Kernel mode only.

--*/

#ifndef _COMPARTMENT_
#define _COMPARTMENT_

#pragma once

//
// TODO: Change this to a locked extensible hash table.
//
typedef LIST_ENTRY NLC_SET, *PNLC_SET;
typedef LIST_ENTRY NLC_LINK, *PNLC_LINK;


//
// IP_COMPARTMENT
//
// Define
//
// The following objects hold references for a compartment:
// 1. The global compartment set.
// 2. Interfaces.
//

typedef struct _IP_COMPARTMENT {
    //
    // Read-only fields visible to clients.
    //
    NL_COMPARTMENT;

    LONG RoutingEpoch;
    LONG FlushEpoch;

    ULONG Signature;
    
    //
    // Index of the loopback interface. 
    //
    IF_INDEX LoopbackIndex;

    LONG ReferenceCount;
    
    NLC_LINK Link;
    union {
        struct {
            UCHAR WeakHostSend : 1;
            UCHAR WeakHostReceive : 1;
            UCHAR MulticastForwarding : 1;
        };
        UCHAR Flags;
    };

    //
    // Used to make notifications at PASSIVE level.
    //
    NETIO_WORK_QUEUE WorkQueue; 

    UCHAR DefaultHopLimit;
    NL_COMPARTMENT_FORWARDING Forwarding;
    LONG ForwardingReferenceCount;
    LONG RecalculationTimer;
    LONG ForceRouterAdvertisement;
    NLI_LOCKED_SET InterfaceSet;
    IPR_LOCKED_SET RouteSet;
    IP_SITE_PREFIX_SET SitePrefixSet;
    IP_ADDRESS_IDENTIFIER_SET AddressIdentifierSet;
    PIP_MFE_LOCKED_SET MfeSet;
    PIP_PROTOCOL Protocol;
    IPP_PATH_SET PathSet;

    //
    // Loopback 127.x.x.x address set.
    //
    IP_LOOPBACK_ADDRESS_LOCKED_SET EphemeralLoopbackAddressSet;

} IP_COMPARTMENT, *PIP_COMPARTMENT;

C_ASSERT(FIELD_OFFSET(NL_COMPARTMENT, CompartmentId) ==
         FIELD_OFFSET(IP_COMPARTMENT, CompartmentId));


//
// Compartment Management Routines.
//

NTSTATUS
IppStartCompartmentManager(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopCompartmentManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupCompartmentManager(
    IN PIP_PROTOCOL Protocol
    );

#define IppCleanupCompartment(Compartment)

#if COMPARTMENT_REFHIST
extern PREFERENCE_HISTORY IppCompartmentReferenceHistory;
DEFINE_REFERENCE_HISTORY_ROUTINES(
    PIP_COMPARTMENT, Compartment, Ipp, IppCompartmentReferenceHistory)
#define IppDereferenceCompartment(Compartment) \
    _IppDereferenceCompartment((Compartment), __LINE__, __FILE__)
#define IppReferenceCompartment(Compartment) \
    _IppReferenceCompartment((Compartment), __LINE__, __FILE__)
#else  // COMPARTMENT_REFHIST
DEFINE_REFERENCE_ROUTINES(PIP_COMPARTMENT, Compartment, Ipp)
#endif // COMPARTMENT_REFHIST

__inline
BOOLEAN
IppIsCompartmentDisabled(
    IN PLOCKED_LIST CompartmentSet,
    IN PIP_COMPARTMENT Compartment
    )
/*++

Routine Description:

    Check if the compartment is disabled.
    TODO: Can this routine be removed?

Arguments:

    CompartmentSet - Supplies the set to which the compartment belongs.
    
    Compartment - Supplies the compartment in question.
    
Return Value:

    TRUE if the compartment is disabled, FALSE if not.
    
Caller LOCK: Compartment Set Lock (Shared).
Caller IRQL: DISPATCH_LEVEL (Since a lock is held).

--*/ 
{
    ASSERT_ANY_LOCK_HELD(&CompartmentSet->Lock);
    
    UNREFERENCED_PARAMETER(CompartmentSet);
    UNREFERENCED_PARAMETER(Compartment);
    
    //
    // We don't disable a compartment until all pending operations are done.
    //
    return FALSE;
}

PIP_COMPARTMENT
IppFindCompartmentById(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID Id
    );

PIP_COMPARTMENT
IppGetCompartment(
    IN PIP_PROTOCOL Protocol,
    IN CONST NL_COMPARTMENT_ARG *Args
    );

PIP_COMPARTMENT
IppFindCompartmentByIdUnderLock(
    IN PLOCKED_LIST CompartmentSet,
    IN COMPARTMENT_ID Id
    );

PIP_COMPARTMENT
IppGetFirstCompartment(
    IN PIP_PROTOCOL Protocol
    );

PIP_COMPARTMENT
IppGetNextCompartment(
    IN PIP_PROTOCOL Protocol, 
    IN COMPARTMENT_ID CompartmentId
    );

PIP_COMPARTMENT
IppCreateCompartment(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID CompartmentId
    );

PIP_COMPARTMENT
IppFindOrCreateCompartmentById(
    IN PIP_PROTOCOL Protocol,
    IN COMPARTMENT_ID Id
    );

VOID
IppCompartmentNotificationWorker(
    IN PSINGLE_LIST_ENTRY WorkQueueHead
    );

VOID
IppUpdateAllProtocolCompartments(
    IN PIP_PROTOCOL Protocol,
    IN ULONG DefaultHopLimit,
    IN NL_COMPARTMENT_FORWARDING Forwarding,
    IN BOOLEAN WeakHostSend,
    IN BOOLEAN WeakHostReceive,
    IN BOOLEAN MulticastForwarding,
    IN BOOLEAN RandomizeIdentifiers
    );

//
// Network Layer Provider Handlers.
//

NL_PROVIDER_REFERENCE_COMPARTMENT IpNlpReferenceCompartment;
NL_PROVIDER_DEREFERENCE_COMPARTMENT IpNlpDereferenceCompartment;


//
// Network Layer Management Provider Handlers.
//

NM_PROVIDER_GET_ALL_PARAMETERS IpGetAllCompartmentParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllCompartmentParameters;
NM_PROVIDER_SET_ALL_PARAMETERS IpSetAllCompartmentForwardingParameters;

#endif // _COMPARTMENT_
