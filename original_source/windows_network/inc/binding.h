/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    binding.h
    
Abstract:

    This module contains declarations for the network layer module's
    NMR binding management.

Author:

    Mohit Talwar (mohitt) Tue Nov 19 10:11:28 2002

Environment:

    Kernel mode only.

--*/

#ifndef _BINDING_
#define _BINDING_

#pragma once

//
// Network Layer Provider Structures and Routines.
//


//
// IP_INTERNAL_CLIENT_CONTEXT
//
// Define the structure of an internal network layer client.
//

typedef struct _IP_INTERNAL_CLIENT_CONTEXT {
    struct _IP_PROTOCOL *Protocol;
    ULONG Signature;
} IP_INTERNAL_CLIENT_CONTEXT, *PIP_INTERNAL_CLIENT_CONTEXT;


//
// IP_CLIENT_CONTEXT
//
// Define the structure of an external network layer client.
//

typedef struct _IP_CLIENT_CONTEXT {
    struct _IP_PROTOCOL *Protocol;
    ULONG Signature;

    LIST_ENTRY Link;            // Linkage within IP_PROTOCOL::NlClientSet.

    NL_CLIENT_NPI Npi;          // Client's network layer interface.

    HANDLE PendingDetachBindingHandle;
    HANDLE NmrBindingHandle;
    PIO_WORKITEM WorkItem;
} IP_CLIENT_CONTEXT, *PIP_CLIENT_CONTEXT;

NTSTATUS
IppStartNlp(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopNlp(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppWaitNlp(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupNlp(
    IN PIP_PROTOCOL Protocol
    );

VOID
NTAPI
IpDeregisterNlProviderComplete(
    IN PVOID ProviderContext
    );

NTSTATUS
NTAPI
IpAttachNlClient(
    IN HANDLE  NmrBindingHandle,
    IN PVOID  ProviderContext,
    IN PNPI_REGISTRATION_INSTANCE  ClientRegistrationInstance,
    IN PVOID  ClientBindingContext,
    IN CONST VOID *ClientDispatch,
    OUT PVOID  *ProviderBindingContext,
    OUT PVOID  *ProviderDispatch
    );

NTSTATUS
NTAPI
IpDetachNlClient(
    IN PVOID  ProviderBindingContext
    );

VOID
FASTCALL
IppDetachNlClientComplete(
    IN PIP_CLIENT_CONTEXT NlClient
    );

VOID
NTAPI
IpCleanupNlClient(
    IN PVOID  ProviderBindingContext
    );

BOOLEAN
IppReferenceNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    );

VOID
IppReferenceValidNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    );

VOID
IppDereferenceNlClient(
    IN PIP_CLIENT_CONTEXT NlClient
    );

//
// Amount of default backfill space to request, in addition to the space for
// the network-layer header.  For now, we use the ethernet header size (aligned
// up to a 4 byte boundary).
//
#define IP_EXTRA_DATA_BACKFILL (ALIGN_UP(sizeof(ETHERNET_HEADER), ULONG))

//
// Used for each attached framing layer provider.
//
typedef struct _FL_PROVIDER_CONTEXT {
    // Linkage on a global FlProviderAttachedList or on an
    // FlProviderDetachingList.  (Never on both at the same time.)
    LIST_ENTRY Link;

    // The provider's side of the framing layer interface.
    FL_PROVIDER_NPI Npi;

    // The number of reasons we cannot yet indicate detach complete.
    // When this reaches zero, we will indicate NmrDetachClientComplete.
    LONG ReferenceCount;

    LOGICAL Detaching;
    HANDLE NmrBindingHandle;
    HANDLE PendingDetachBindingHandle;

    //
    // TODO: Allocate interfaces from a FL_PROVIDER_CONTEXT block pool.
    // NDIS_HANDLE InterfacePool;  // Pool for allocating interfaces.
    //
    NDIS_HANDLE NeighborPool;   // Pool for allocating neighbors.

    struct _IP_PROTOCOL *Protocol;

} FL_PROVIDER_CONTEXT, *PFL_PROVIDER_CONTEXT;

//
// Used for the NSI
//
typedef struct _NMP_NOTIFICATION_CONTEXT {
    REFERENCE_OBJECT ReferenceObject;
    KEVENT DeregisterCompleteEvent;
} NMP_NOTIFICATION_CONTEXT, *PNMP_NOTIFICATION_CONTEXT;

typedef struct _NMP_CLIENT_CONTEXT {
    // The client's side of the network layer interface.
    NM_CLIENT_NPI Npi;

    HANDLE PendingDetachBindingHandle;
    HANDLE NmrBindingHandle;

    struct _IP_PROTOCOL *Protocol;
    ULONG Signature;

    NMP_NOTIFICATION_CONTEXT InterfaceNotificationContext;
    NMP_NOTIFICATION_CONTEXT AddressNotificationContext;
    NMP_NOTIFICATION_CONTEXT RouteNotificationContext;
    NMP_NOTIFICATION_CONTEXT EchoRequestNotificationContext;
    NMP_NOTIFICATION_CONTEXT MulticastForwardingNotificationContext;
} NMP_CLIENT_CONTEXT, *PNMP_CLIENT_CONTEXT;

typedef struct _PNP_EVENT_CLIENT_CONTEXT {
    NL_PNP_EVENT_CLIENT_NPI Npi;
    HANDLE PendingDetachBindingHandle;
    HANDLE NmrBindingHandle;
    struct _IP_PROTOCOL *Protocol;
} PNP_EVENT_CLIENT_CONTEXT, *PPNP_EVENT_CLIENT_CONTEXT;

    
typedef struct _NA_PROVIDER_CONTEXT {
    NA_PROVIDER_NPI Npi;
    HANDLE PendingDetachBindingHandle;
    struct _IP_PROTOCOL *Protocol;
} NA_PROVIDER_CONTEXT, *PNA_PROVIDER_CONTEXT;

__inline
BOOLEAN
IppReferenceFlProviderContext(
    IN PFL_PROVIDER_CONTEXT FlProvider
    )
{
    if (!FlProvider->Detaching) {
        InterlockedIncrement(&FlProvider->ReferenceCount);
        return TRUE;
    }
    return FALSE;
}

VOID
FASTCALL
IppDereferenceFlProviderContext(
    IN PLOCKED_LIST FlProviderSet,
    IN PFL_PROVIDER_CONTEXT ProviderContext
    );

NTSTATUS
NTAPI
IpDetachFlProvider(
    IN PVOID  ClientBindingContext
    );

VOID
NTAPI
IpCleanupFlProviderContext(
    IN PVOID  ClientBindingContext
    );

NTSTATUS
NTAPI
IpDetachNsiClient(
    IN PVOID  ClientBindingContext
    );

VOID
NTAPI
IpCleanupNsiClientContext(
    IN PVOID  ClientBindingContext
    );

#endif // _BINDING_
