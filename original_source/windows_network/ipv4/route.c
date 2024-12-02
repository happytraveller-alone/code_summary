/*++

Copyright (c) 2001-2002  Microsoft Corporation

Module Name:

    route.c

Abstract:

    This module implements the functions of the IPv4 Route Manager module.

Author:

    Dave Thaler (dthaler) 16-Nov-2001

Environment:

    kernel mode only

--*/

#include "precomp.h"

//
// A table containing MTU "plateaus" as recommended by RFC 1191.
//
ULONG Ipv4pMtuTable[] = {
    65535,
    32000,
    17914,
    8166,
    4352,
    2002,
    1492,
    1006,
    IPV4_MINIMUM_VALID_MTU
};


VOID
Ipv4pMakeRouteKey(
    IN CONST UCHAR *DestinationPrefix,
    IN UINT8 DestinationPrefixLength,
    IN CONST UCHAR *SourcePrefix OPTIONAL,
    IN UINT8 SourcePrefixLength,
    OUT PUCHAR KeyBuffer,
    OUT PUSHORT KeyLength
    )
/*++

Routine Description:

    This routine creates a route key from information like the destination
    prefix, source prefix and destination scope id.  The source prefix length
    can be greater than zero only if the destination prefix length is equal to
    the size of the IP address.

Arguments:

    DestinationPrefix - Supplies the destination prefix or address.

    DestinationPrefixLength - Supplies the destination prefix length.

    SourcePrefix - Optionally supplies the source prefix.

    SourcePrefixLength - Supplies the source prefix length.

    KeyBuffer - Returns the route key. 

    KeyLength - Returns the length of the route key. 

Return Value: 
 
    None.

--*/
{
    PIPV4P_ROUTE_KEY Key = (PIPV4P_ROUTE_KEY)KeyBuffer;

    ASSERT((SourcePrefixLength == 0) || 
           (DestinationPrefixLength == RTL_BITS_OF(IN_ADDR)));

    CopyPrefix(
        (PUCHAR) &Key->DestinationPrefix, 
        DestinationPrefix, 
        DestinationPrefixLength, 
        sizeof(IN_ADDR));

    if (SourcePrefix == NULL) {
        RtlZeroMemory(&Key->SourcePrefix, sizeof(IN_ADDR));
    } else {
        CopyPrefix(
            (PUCHAR) &Key->SourcePrefix,
            SourcePrefix,
            SourcePrefixLength, 
            sizeof(IN_ADDR));
    }
    
    *KeyLength = DestinationPrefixLength + SourcePrefixLength;
}


VOID
Ipv4pParseRouteKey(
    IN CONST UCHAR *KeyBuffer,
    IN USHORT KeyLength,
    OUT PUCHAR *DestinationPrefix OPTIONAL,
    OUT UINT8 *DestinationPrefixLength OPTIONAL,
    OUT PUCHAR *SourcePrefix OPTIONAL,
    OUT UINT8 *SourcePrefixLength OPTIONAL
    )
/*++

    This routine parses a route key and extracts information like the
    destination prefix, destination prefix length from it. 

Arguments:

    KeyBuffer - Supplies the key. 

    KeyLength - Supplies the length of the key. 

    DestinationPrefix - Returns the destination prefix.

    DestinationPrefixLength - Returns the destination prefix length.

    SourcePrefix - Returns the source prefix.

    SourcePrefixLength - Returns the source prefix length.

Returns Value:
   
    None.

--*/
{
    PIPV4P_ROUTE_KEY Key = (PIPV4P_ROUTE_KEY)KeyBuffer;
    UINT8 SourceLength, DestinationLength;

    if (DestinationPrefix != NULL) {
        *DestinationPrefix = (PUCHAR) &Key->DestinationPrefix;
    }
    if (SourcePrefix != NULL) {
        *SourcePrefix = (PUCHAR) &Key->SourcePrefix;
    }

    if (KeyLength > RTL_BITS_OF(IN_ADDR)) {
        DestinationLength = RTL_BITS_OF(IN_ADDR);
        SourceLength = (UINT8) (KeyLength - RTL_BITS_OF(IN_ADDR));
    } else {
        DestinationLength = (UINT8) KeyLength;        
        SourceLength = 0;
    }

    if (SourcePrefixLength != NULL) {
        *SourcePrefixLength = SourceLength;
    }
    if (DestinationPrefixLength != NULL) {
        *DestinationPrefixLength = DestinationLength;
    }
}

VOID
Ipv4pNotifyRouteChange(
    IN PIP_UNICAST_ROUTE Route,
    IN NSI_NOTIFICATION NotificationType,
    OUT PIP_ROUTE_NOTIFY_CONTEXT RouteContext
    )
/*++

Routine Description:

    Called from IppNotifyRouteChange to handle the specifics of notifying
    clients about a route change/addition/deletion. A work item is allocated to
    defer the work. The only thing that is done is the construction of the
    route key and this is done here because deletion of a route causes the
    AVL_NODE to be freed - along with information we need. Note this code must
    be called before the deletion of a route actually occurs or information
    will be lost.

Arguments:

    Route - Supplies the route that has changed.

    NotificationType - Type of notification (add/delete/parameter change).
    
    RouteContext - Returns the context to supply to WorkItem.

Locks:

    A reference count on the route was taken, to be released when notification
    to the client is complete.

Caller IRQL:

    Any IRQL - all work is postponed to a work item.

--*/
{
    PIPV4_ROUTE_KEY RouteKey;
    PIPV4_UNICAST_ROUTE Ipv4Route = (PIPV4_UNICAST_ROUTE) Route;
    PIPV4P_ROUTE_KEY InternalRouteKey;
    USHORT InternalKeyMaskLen;

    UNREFERENCED_PARAMETER(NotificationType);
    
    ASSERT_SCALABLE_WRITE_LOCK_HELD(
        &Route->Interface->Compartment->RouteSet.Lock); 
    ASSERT(RouteContext != NULL);
 
    if (!Route->Flags.InRouteSet) {
        return; 
    } 
        
    RouteContext->UnicastRoute = Route;
    RouteKey = (PIPV4_ROUTE_KEY) (&RouteContext->Ipv4Key);
    RtlZeroMemory(RouteKey, sizeof(*RouteKey));

    //
    // Call trie function to obtain a key, which will be converted into the key
    // structure understandable to the NSI client.
    //
    PtGetKey(
        &Ipv4Route->Link,
        (PUCHAR*)&InternalRouteKey,
        &InternalKeyMaskLen);
    
    ASSERT(InternalKeyMaskLen <= RTL_BITS_OF(IPV4P_ROUTE_KEY));

    RouteKey->CompartmentId = Ipv4Route->Interface->Compartment->CompartmentId;
    RouteKey->DestinationPrefix = InternalRouteKey->DestinationPrefix;
    RouteKey->SourcePrefix = InternalRouteKey->SourcePrefix;
    if (InternalKeyMaskLen <= RTL_BITS_OF(IN_ADDR)) {
        RouteKey->DestinationPrefixLength = (UINT8)InternalKeyMaskLen;
        RouteKey->SourcePrefixLength = 0;
    } else {
        InternalKeyMaskLen -= RTL_BITS_OF(IN_ADDR);
        RouteKey->DestinationPrefixLength = RTL_BITS_OF(IN_ADDR);
        RouteKey->SourcePrefixLength = (UINT8)InternalKeyMaskLen;
    }

    RouteKey->NextHopAddress = *((PIN_ADDR) IppGetFirstHopAddress(Route));

    RouteKey->InterfaceLuid = Route->Interface->Luid;

    if (Route->Flags.Loopback) {
        //
        // First hop is a local address. Set sub interface LUID to 0
        //
        RouteKey->SubInterfaceLuid.Value = 0;
    } else if (Route->CurrentNextHop != NULL) {
        //
        // First hop is in the neighbor entry.  Set sub interface luid
        // to the sub interface this neighbor entry points to.
        //
        RouteKey->SubInterfaceLuid = 
            ((PIPV4_NEIGHBOR)Route->CurrentNextHop)->SubInterface->Luid;
    } else {
        //
        // No neighbor entry. Set it to 0.
        //
        RouteKey->SubInterfaceLuid.Value = 0;
    }   
}

BOOLEAN
Ipv4pValidateRouteKey(
    IN CONST IPV4_ROUTE_KEY *Key
    )
{
    //
    // Validate key fields.
    //
    if (!IppValidatePrefix(
            (CONST UCHAR *) &Key->DestinationPrefix,
            Key->DestinationPrefixLength,
            sizeof(IN_ADDR))) {
        return FALSE;
    }
    
    if (!IppValidatePrefix(
            (CONST UCHAR *) &Key->SourcePrefix,
            Key->SourcePrefixLength,
            sizeof(IN_ADDR))) {
        return FALSE;
    }

    if ((Key->SourcePrefixLength > 0) &&
        (Key->DestinationPrefixLength != RTL_BITS_OF(IN_ADDR))) {
        return FALSE;
    }

    return TRUE;
}


NTSTATUS
NTAPI
Ipv4SetAllRouteParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function sets all public parameters of a given route.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{   
    PIPV4_ROUTE_KEY Key = (PIPV4_ROUTE_KEY)Args->KeyStructDesc.KeyStruct;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_SUBINTERFACE SubInterface = NULL;
    PIP_INTERFACE Interface = NULL;
    PIP_PROTOCOL Protocol = &Ipv4Global;
    KLOCK_QUEUE_HANDLE InterfaceLockHandle, RouteSetLockHandle;
    PNL_ROUTE_RW RouteRw = (PNL_ROUTE_RW)Args->RwStructDesc.RwParameterStruct;
    IF_LUID ZeroLuid = {0};
    PIP_NEXT_HOP NextHop = NULL;    
    
    if (Args->Action == NsiSetReset) {
        return STATUS_NOT_IMPLEMENTED;
    }

    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(IPV4_ROUTE_KEY));

    if ((Args->Transaction == NsiTransactionNone) ||
        (Args->Transaction == NsiTransactionValidate)) {
        if (!Ipv4pValidateRouteKey(Key)) {
            return STATUS_INVALID_PARAMETER;
        }

        //
        // W2K3/XP supports adding IPv4 routes with a next-hop but no 
        // interface specified.  In which case we have to determine the 
        // best interface the next hop would lie over.
        // RaymondS-Issue: Do something similar for IPv6 as well
        // when Net Shell supports adding such routes.
        //
        if (!RtlEqualMemory(
                &Key->InterfaceLuid, 
                &ZeroLuid, 
                sizeof(IF_LUID))) {
            //
            // If Interface specified.
            //
            SubInterface = 
                IppFindSubInterfaceByLuid(
                    Protocol, 
                    &Key->InterfaceLuid,
                    &Key->SubInterfaceLuid);
            if (SubInterface == NULL) {
                return STATUS_NOT_FOUND;
            }
            Interface = SubInterface->Interface;
            if ((Key->CompartmentId != 0) &&
                (Key->CompartmentId != 
                 Interface->Compartment->CompartmentId)) {
                IppDereferenceSubInterface(SubInterface);
                return STATUS_INVALID_PARAMETER;
            }
        } else {
            IP_PATH_FLAGS ConstrainFlags;
            PIP_COMPARTMENT Compartment;
            SCOPE_ID ScopeId = scopeid_unspecified;
            PIP_LOCAL_UNICAST_ADDRESS SourceAddress;
            
            //
            // Determine the compartment.
            //
            Compartment = 
                IppFindCompartmentById(&Ipv4Global, Key->CompartmentId);
            if (Compartment == NULL) {
                return STATUS_NOT_FOUND;
            }        

            //
            // Find the best interface the next hop would be
            // accessible from.
            //
            Status = 
                IppFindNextHopAndSource(
                    Compartment,
                    NULL,
                    (PUCHAR) &Key->NextHopAddress,
                    ScopeId,
                    NULL,
                    &NextHop,
                    &SourceAddress, 
                    NULL,
                    &ConstrainFlags);
            IppDereferenceCompartment(Compartment);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }
            IppDereferenceLocalUnicastAddress(SourceAddress);                        
            Interface = NextHop->Interface;
        }
    }

    ASSERT(Interface != NULL);
    RtlAcquireWriteLock(&Interface->Lock, &InterfaceLockHandle);
    RtlAcquireScalableWriteLockAtDpcLevel(
        &Interface->Compartment->RouteSet.Lock,
        &RouteSetLockHandle);
    
    //
    // Handle the transaction case here.
    //
    switch (Args->Transaction) {
    case NsiTransactionNone:
        Status = 
            IppValidateSetAllRouteParameters(
                Args->Action, 
                Interface,
                SubInterface, 
                (CONST UCHAR*) &Key->DestinationPrefix, 
                Key->DestinationPrefixLength, 
                (CONST UCHAR*) &Key->SourcePrefix, 
                Key->SourcePrefixLength, 
                NlroManual, 
                RouteRw, 
                (CONST UCHAR*) &Key->NextHopAddress, 
                NULL, 
                &Args->ProviderTransactionContext);
        if (NT_SUCCESS(Status)) {
            IppCommitSetAllRouteParameters(
                Args->Action, 
                Interface->Compartment, 
                Args->ProviderTransactionContext, 
                (CONST UCHAR*) &Key->DestinationPrefix, 
                Key->DestinationPrefixLength, 
                RouteRw);
        }
        break;
        
    case NsiTransactionValidate:
        Status = 
            IppValidateSetAllRouteParameters(
                Args->Action, 
                Interface,
                SubInterface, 
                (CONST UCHAR*) &Key->DestinationPrefix, 
                Key->DestinationPrefixLength, 
                (CONST UCHAR*) &Key->SourcePrefix, 
                Key->SourcePrefixLength, 
                NlroManual, 
                RouteRw, 
                (CONST UCHAR*) &Key->NextHopAddress, 
                NULL, 
                &Args->ProviderTransactionContext);
        break;

    case NsiTransactionCommit:
        IppCommitSetAllRouteParameters(
            Args->Action, 
            Interface->Compartment, 
            Args->ProviderTransactionContext, 
            (CONST UCHAR*) &Key->DestinationPrefix, 
            Key->DestinationPrefixLength, 
            RouteRw);
        break;

    case NsiTransactionCancel:
        IppCancelSetAllRouteParameters(
            Args->Action, 
            Interface->Compartment, 
            Args->ProviderTransactionContext, 
            (CONST UCHAR*) &Key->DestinationPrefix, 
            Key->DestinationPrefixLength);
        break;

    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }
    
    RtlReleaseScalableWriteLockFromDpcLevel(
        &Interface->Compartment->RouteSet.Lock,
        &RouteSetLockHandle);
    RtlReleaseWriteLock(&Interface->Lock, &InterfaceLockHandle);

    if (SubInterface != NULL) {
        IppDereferenceSubInterface(SubInterface);
    }

    if (NextHop != NULL) {
        IppDereferenceNextHop(NextHop);
    }
    
    return Status;
}

NTSTATUS
NTAPI
Ipv4GetAllPathParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public parameters of a given path.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    PIPV4_PATH_KEY Key = (PIPV4_PATH_KEY)Args->KeyStructDesc.KeyStruct;
    PIP_PATH Path = NULL;
    PIP_COMPARTMENT Compartment = NULL;
    PIP_INTERFACE Interface = NULL;
    PIP_PROTOCOL Protocol = &Ipv4Global;
    PIP_LOCAL_ADDRESS Source = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(*Key));

    switch (Args->Action) {
    case NsiGetExact:

        //
        // Look up the interface object.
        //
        
        Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
        if (Interface == NULL) {
            Status = STATUS_NOT_FOUND;
            break;
        }

        //
        // Use the interface object to look up the source address object.
        //

        Source = IppFindAddressOnInterface(Interface, (PUCHAR) &Key->Source);
        if (Source == NULL) {
            Status = STATUS_NOT_FOUND;
            break;
        }
        if (Source->Type != NlatUnicast) {
            Status = STATUS_NOT_FOUND;
            break;
        }

        //
        // Look up the compartment object.
        //

        Compartment = IppFindCompartmentById(Protocol, Key->CompartmentId);
        if (Compartment == NULL) {
            Status = STATUS_NOT_FOUND;
            break;
        }

        //
        // Use all of the previous objects to look up the path object.
        //
        
        Path =
            IppFindPath(
                Compartment,
                NULL,
                (PUCHAR) &Key->Destination,
                IppGetScopeId(Interface, (PUCHAR)&Key->Destination),
                Interface,
                (PIP_LOCAL_UNICAST_ADDRESS) Source);
        if (Path == NULL) {
           Status = STATUS_NOT_FOUND;
        }
        
        break;

    case NsiGetFirst:
    case NsiGetNext:
        return STATUS_NOT_IMPLEMENTED;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Dereference any objects that we referenced while trying to look up
    // the path and return any error we may have encountered.
    //
    
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);    
    }
    if (Source != NULL) {
        IppDereferenceLocalAddress(Source);
    }
    if (Interface != NULL) {
        IppDereferenceInterface(Interface);
    }
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
   
    //
    // We were able to locate the requested path.  Now fill the caller-supplied
    // buffer with ROD and RW parameters.
    //
    
    if (Args->StructDesc.RoDynamicParameterStruct) {
        IppFillPathRod(
            Protocol->Characteristics->AddressBytes,
            Path,
            (PNL_PATH_ROD) Args->StructDesc.RoDynamicParameterStruct);
    }

    if (Args->StructDesc.RwParameterStruct) {
        IppFillPathRw(Path, (PNL_PATH_RW) Args->StructDesc.RwParameterStruct);
    }

    Args->StructDesc.RoStaticParameterStructLength = 0;

    IppDereferencePath(Path);

    return Status;
}

NTSTATUS
NTAPI
Ipv4SetAllPathParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function sets all public parameters of a given path.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    CONST UCHAR *Destination = NULL;
    PIP_LOCAL_ADDRESS Source = NULL;
    PIP_PROTOCOL Protocol = &Ipv4Global;
    PIP_COMPARTMENT Compartment = NULL;
    PIP_INTERFACE Interface = NULL;
    PIPV4_PATH_KEY Key = (PIPV4_PATH_KEY) Args->KeyStructDesc.KeyStruct;
    PNL_PATH_RW Rw = (PNL_PATH_RW) Args->RwStructDesc.RwParameterStruct;    
    PIP_PATH Path = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    

    switch (Args->Action) {
    case NsiSetReset:

        //
        // Flush the destination cache.  Compare IoctlFlushRouteCache in the
        // XP IPv6 stack, and FlushArpTable in the XP IPv4 stack.
        //

        if (Args->KeyStructDesc.KeyStructLength <
            FIELD_OFFSET(IPV4_PATH_KEY, InterfaceLuid)) {
            //
            // Flushing paths in all compartments is not yet implemented.
            //
            return STATUS_NOT_IMPLEMENTED;
        } else {
            COMPARTMENT_ID CompartmentId = Key->CompartmentId;

            if (CompartmentId == UNSPECIFIED_COMPARTMENT_ID) {
                CompartmentId = NdisGetCurrentThreadCompartmentId();
            }

            Compartment = IppFindCompartmentById(Protocol, Key->CompartmentId);
            if (Compartment == NULL) {
                //
                // There's nothing to reset.
                //
                return STATUS_SUCCESS;
            }
        }

        //
        // If an interface is specified, find it.
        //
        if (Args->KeyStructDesc.KeyStructLength >= 
            FIELD_OFFSET(IPV4_PATH_KEY, Destination)) {
            Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);

            if (Interface == NULL) {
                //
                // There's nothing to reset.
                //
                break;
            }
        }

        if (Args->KeyStructDesc.KeyStructLength >=
             FIELD_OFFSET(IPV4_PATH_KEY, Source)) {
            Destination = (PUCHAR) &Key->Destination;
        }

        if (Args->KeyStructDesc.KeyStructLength >= sizeof(IPV4_PATH_KEY)) {
            Source = 
                IppFindAddressOnInterface(Interface, (PUCHAR) &Key->Source);
            if (Source == NULL) {
                //
                // There's nothing to reset.
                //
                break;
            }
        }

        IppFlushPaths(Compartment, Interface, Destination, Source);

        break;

    case NsiSetCreateOrSet:
        
        if ((Args->KeyStructDesc.KeyStructLength != sizeof(IPV4_PATH_KEY)) ||
            (Args->RwStructDesc.RwParameterStructLength !=
                sizeof(NL_PATH_RW))) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Look up the interface object.
        //
        
        Interface = IppFindInterfaceByLuid(Protocol, &Key->InterfaceLuid);
        if (Interface == NULL) {
            Status = STATUS_NOT_FOUND;
            break;
        }

        //
        // Use the interface object to look up the source address object.
        //

        Source = 
            IppFindAddressOnInterface(Interface, (PUCHAR) &Key->Source);
        if (Source == NULL) {
            Status = STATUS_NOT_FOUND;
            break;
        }
        if (Source->Type != NlatUnicast) {
            Status = STATUS_NOT_FOUND;
            break;
        }

        //
        // Look up the compartment object.
        //

        Compartment = IppFindCompartmentById(Protocol, Key->CompartmentId);
        if (Compartment == NULL) {
            Status = STATUS_NOT_FOUND;
            break;
        }

        //
        // Use all of the previous objects to look up or create the path object.
        //

        Status =
            IppFindOrCreatePath(
                Compartment,
                (PUCHAR) &Key->Destination,
                IppGetScopeId(Interface, (PUCHAR)&Key->Destination),
                Interface,
                (PIP_LOCAL_UNICAST_ADDRESS) Source,
                &Path);

        if (!NT_SUCCESS(Status)) {
            break;
        }

        //
        // Now that we finally have the path object, enable or disable bandwidth
        // estimation as appropriate.
        //
        
        Status =
            IppAddOrRemoveBandwidthListeners(
                Path,
                &Path->Bandwidth,
                Rw->EstimateBandwidthOut,
                Rw->EstimateBandwidthIn);
        break;

    case NsiSetDelete:                
    case NsiSetDefault:
    case NsiSetCreateOnly:
    case NsiSetDeleteWithReference:
    case NsiSetCreateOrSetWithReference:        
        return STATUS_NOT_IMPLEMENTED;
        break;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
        
    }

    if (Path != NULL) {
        IppDereferencePath(Path);
    }
    if (Compartment != NULL) {
        IppDereferenceCompartment(Compartment);    
    }
    if (Interface != NULL) {
        IppDereferenceInterface(Interface);
    }
    if (Source != NULL) {
        IppDereferenceLocalAddress(Source);
    }

    return Status;
}

NTSTATUS
NTAPI
Ipv4EnumerateAllPaths(
    IN OUT PNM_REQUEST_ENUMERATE_OBJECTS_ALL_PARAMETERS EnumerateRequest
    )
/*++

Routine Description:

    Enumerates all IPv4 path entries.

Arguments:

    EnumerateObjectsAllParametersRequest - Supplies the address of an
        NA_REQUEST_ENUMERATE_OBJECTS_ALL_PARAMETERS structure.

Return Value:

    STATUS_SUCCESS if successful.
    STATUS_MORE_ENTRIES if successful, but more entries exist than fit.
    STATUS_INVALID_PARAMETER if the parameter request is invalid.
    STATUS_NOT_IMPLEMENTED if the action is not NsiGetFirst.

--*/
{
    ULONG EntryLimit;
    ULONG Index = 0;
    PIPV4_PATH_KEY KeyArray, Key;
    PIPV4_PATH_ROD RodArray;
    NTSTATUS Status = STATUS_SUCCESS;
    PIP_INTERFACE Interface;
    PIP_PATH Path;
    PIP_COMPARTMENT Compartment;
    COMPARTMENT_ID CompartmentId = 0;
    PIP_PROTOCOL Protocol = &Ipv4Global;
    KLOCK_QUEUE_HANDLE LockHandle;
    PIPP_PATH_SET PathSet;
    PRTL_HASH_TABLE_ENTRY Current;
    RTL_HASH_TABLE_ENUMERATOR Enumerator;

    switch (EnumerateRequest->Action) {
    case NsiGetFirst:
        break;

    case NsiGetExact:
    case NsiGetNext:
        return STATUS_NOT_IMPLEMENTED;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    KeyArray = (PIPV4_PATH_KEY) EnumerateRequest->KeyStructDesc.KeyStruct;
    RodArray = (PIPV4_PATH_ROD) 
        EnumerateRequest->StructDesc.RoDynamicParameterStruct;
    EntryLimit = EnumerateRequest->EntryCount;

    do {
        Compartment = IppGetNextCompartment(Protocol, CompartmentId);
        if (Compartment == NULL) {
            break;
        }
        CompartmentId = Compartment->CompartmentId;

        if (EntryLimit == 0) {
            //
            // Just count paths.
            // No lock is held, but we're reading a 32-bit value which is
            // atomic.
            //
            Index += RtlTotalEntriesHashTable(&Compartment->PathSet.Table);
            IppDereferenceCompartment(Compartment);
            continue;
        }

        //
        // Enumerate all paths in this compartment.
        //
        RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

        PathSet = &Compartment->PathSet;
        RtlInitEnumerationHashTable(&PathSet->Table, &Enumerator);

        for (Current = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator);
             Current != NULL;
             Current = RtlEnumerateEntryHashTable(&PathSet->Table, &Enumerator)
            ) {

            Path = IppGetPathFromPathLink(Current);

            if (Index == EntryLimit) {
                Status = STATUS_MORE_ENTRIES;
                break;
            }
            
            if (!IS_PATH_VALID(Path, Compartment)) {
                continue;
            }

            Key = &KeyArray[Index];
            Interface = Path->SourceAddress->Interface;
            Key->CompartmentId = Interface->Compartment->CompartmentId;
            Key->InterfaceLuid = Interface->Luid;
            Key->Destination = *(PIN_ADDR) Path->DestinationAddress;
            Key->Source = *(PIN_ADDR) NL_ADDRESS(Path->SourceAddress);
            
            if (RodArray != NULL) {
                IppFillPathRodUnderLock(
                    sizeof(IN_ADDR), 
                    Path, 
                    (PNL_PATH_ROD) &RodArray[Index]);
            }
            
            Index++;
        }

        RtlEndEnumerationHashTable(&PathSet->Table, &Enumerator);

        RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

        IppDereferenceCompartment(Compartment);
    } while (Index <= EntryLimit);

    EnumerateRequest->EntryCount = Index;

    return Status;
}

NTSTATUS
NTAPI
Ipv4GetAllBestRouteParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function looks up the best route for a given destination.

Arguments:

    Args - Supplies a pointer to a structure describing the operation to
        be performed.

Return Value:

    Status of the operation.

--*/
{
    NTSTATUS Status;
    PIPV4_BEST_ROUTE_KEY Key;
    PIP_PROTOCOL Protocol = &Ipv4Global;
    
    //
    // Guaranteed by the NSI since we register with this requirement.
    //    
    ASSERT(Args->KeyStructDesc.KeyStructLength == sizeof(IPV4_BEST_ROUTE_KEY));
    Key = (PIPV4_BEST_ROUTE_KEY)Args->KeyStructDesc.KeyStruct;

    switch (Args->Action) {
    case NsiGetExact:
        if (Args->StructDesc.RoDynamicParameterStruct != NULL) {
            ASSERT(Args->StructDesc.RoDynamicParameterStructLength >= 
                   sizeof(IPV4_BEST_ROUTE_ROD));
            Args->StructDesc.RoDynamicParameterStructLength = 
                sizeof(IPV4_BEST_ROUTE_ROD);
        }
        
        Status =
            IppGetAllBestRouteParameters(
                Protocol, 
                Key->CompartmentId, 
                (PUCHAR) &Key->SourceAddress, 
                Key->SourceScopeId, 
                Key->SourceInterfaceLuid.Value 
                    == NET_IFLUID_UNSPECIFIED 
                    ? NULL 
                    : &Key->SourceInterfaceLuid,                
                (PUCHAR) &Key->DestinationAddress, 
                Key->DestinationScopeId, 
                Args->StructDesc.RoDynamicParameterStruct);

        break;
        
    case NsiGetFirst:
    case NsiGetNext:
        return STATUS_NOT_IMPLEMENTED;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    Args->StructDesc.RoStaticParameterStructLength = 0;

    return Status;
}


NTSTATUS
Ipv4pUpdatePathMtu(
    IN PIP_LOCAL_ADDRESS LocalAddress, 
    IN PICMPV4_MESSAGE Icmpv4,
    IN PIPV4_HEADER Ipv4Header
    )
/*++

Routine Description:

    This routine is called on receiving an ICMP destination unreachable message
    with code FRAG_NEEDED. The routine estimates the new MTU of the path based
    on the ICMP message and updates the MTU. 
    
Arguments:

    LocalAddress - Supplies the local address on which the ICMP error was
        received.  

    Icmpv4 - Supplies the ICMP header of the ICMP error message. 

    Ipv4Header - Supplies the IPv4 header of the packet that caused the ICMP
        error to be generated. 

Return Value:

    STATUS_SUCCESS or failure code.

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    BOOLEAN Updated = FALSE, ForceFragment = FALSE, FlagsChanged = FALSE;
    PIP_INTERFACE Interface = LocalAddress->Interface;
    PIP_COMPARTMENT Compartment = Interface->Compartment;
    ULONG NewMtu, CurrentMtu, HeaderLength, OriginalLength, CurrentIndex;
    UCHAR *Destination = (UCHAR*)&Ipv4Header->DestinationAddress;
    PIP_PATH Path;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // Verify the destination IP address of the ICMP error matches the source 
    // of the enclosed packet.
    //
    if (!RtlEqualMemory(LocalAddress->Identifier->Address,
                        &Ipv4Header->SourceAddress,
                        sizeof(IN_ADDR))) {
        return STATUS_DATA_NOT_ACCEPTED;
    }
    
    //
    // Find the correct path but be careful not to create one if it doesn't
    // exist (we call IppFindPath instead of IppRouteToDestination here).  The
    // source of the path is the destination address of the ICMP error and the
    // destination of the path is the destination in the IP header that caused
    // the ICMP error to be generated. 
    //
    Path = IppFindPath(
        Compartment, 
        NULL,
        Destination, 
        IppGetScopeId(Interface, Destination),
        Interface, 
        (PIP_LOCAL_UNICAST_ADDRESS) LocalAddress);

    if (Path == NULL) {
        return STATUS_NOT_FOUND;
    }

    CurrentMtu = Path->PathMtu;
    NewMtu = RtlUshortByteSwap(Icmpv4->icmp4_data16[1]);
    HeaderLength = Ip4HeaderLengthInBytes(Ipv4Header);
    OriginalLength = RtlUshortByteSwap(Ipv4Header->TotalLength);

    if (NewMtu == 0) {
        //
        // The ICMP message is from an old router which does not set the
        // next-hop MTU field. Estimate the MTU of the path based on the total
        // length of the packet that caused the ICMP error. Handle BSD 4.2
        // based routers as outlined in RFC 1191. 
        //
        if (OriginalLength >= CurrentMtu) {
            //
            // BSD 4.2 routers add the header length to the total length of the
            // original packet (RFC 1191). Subtract the header length here to
            // get a true estimate of the original packet length. 
            //
            OriginalLength -= HeaderLength;
        }

        if (OriginalLength > CurrentMtu) {
            NewMtu = CurrentMtu;
        } else {
            //
            // Find the plateau corresponding to the length of the original
            // packet, or leave at 0 if no plateau lower than OriginalLength
            // could be found (i.e. OriginalLength <= IPV4_MINIMUM_VALID_MTU).
            //
            for (CurrentIndex = 0; 
                 CurrentIndex < RTL_NUMBER_OF(Ipv4pMtuTable);
                 CurrentIndex++) {
                if (Ipv4pMtuTable[CurrentIndex] < OriginalLength) {
                    NewMtu = Ipv4pMtuTable[CurrentIndex];                    
                    break;
                }
            }
        }
    } else if (NewMtu < IPV4_MINIMUM_LEGAL_MTU ||  
               NewMtu >= OriginalLength) {
        //
        // Discard the PMTU update if one of the following holds:
        //     1. The new MTU proposed (RFC 1191) is lesser than 68 bytes. A 
        //        router should always be able to forward a datagram of 68 
        //        octets, RFC 791.
        //     2. The new MTU proposed is greater than the total length as
        //        described by the attached IP Header.
        //
        goto Done;
    }
    
    if (NewMtu < IPV4_MINIMUM_VALID_MTU) {
        //
        // If the indicated MTU in the ICMP error is less than
        // IPV4_MINIMUM_VALID_MTU, we still use an MTU of
        // IPV4_MINIMUM_VALID_MTU but we clear the don't fragment bit in every
        // packet.
        //
        ForceFragment = TRUE;
        if (Path->Flags.ForceFragment == FALSE) {
            FlagsChanged = TRUE;
        }
        NewMtu = IPV4_MINIMUM_VALID_MTU;
    }

    if (CurrentMtu <= NewMtu && !FlagsChanged) {
        goto Done;
    }

    //
    // At this point we have an estimate of the new MTU as well as what our
    // previous MTU was. The new MTU estimate is lower than the current MTU; so
    // acquire the lock and try to update the MTU. Also, before changing the
    // MTU, make sure someone already hasn't set it to a lower value. The first
    // check was done without the lock held and so between the time the first
    // check was made and the MTU is updated, another thread could have set it
    // to a lower value.
    // We update the PathEpoch if either the MTU or the flags have changed.
    //
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
    if (Path->PathMtu > NewMtu || FlagsChanged) {
        Updated = TRUE;
        Path->Flags.ForceFragment = ForceFragment;
        IppUpdatePathMtu(Path, NewMtu);
    }
    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);

    //
    // If the MTU was updated, inform the network layer clients. 
    //
    if (Updated) {
        IppUpdatePathNotification(Compartment, Path);
    }

Done:
    IppDereferencePath(Path);
    return STATUS_SUCCESS;
}

VOID
Ipv4pPathMtuDiscoveryTimeout(
    IN PIP_PATH Path,
    IN PIP_INTERFACE Interface, 
    IN PIP_SUBINTERFACE SubInterface
    )
/*++

Routine Description:

    This routine is called to process a path MTU discovery timeout.  It first
    checks whether a timeout has fired and if so increases the path MTU.  This
    is called from two places: 
    (1) On every send, the condition for the timeout is checked and if the
    timeout has fired, then this routine is called.  This routine is not on the 
    performance critical data since the caller checks the condition for the
    timeout firing before calling this routine. 
    (2) This is also called every time a NL client queries a path. 
    
Arguments:

    Path - Supplies the path for which to increase the MTU if the timeout has
        fired. 

    Interface - Supplies the interface on which the path exists. 

    SubInterface - Supplies the sub-interface of the outgoing interface.

Return Value:

    None.

Caller LOCK:

    None. 

Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ULONG CurrentIndex, NewMtu;
    PIP_COMPARTMENT Compartment;
    BOOLEAN Updated = FALSE;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // We lazily check to see if it's time to probe for an increased Path
    // MTU as this is perceived to be cheaper than routinely running through
    // all our Paths looking for one whose PMTU timer has expired. Also, the
    // check is done without the bucket lock so that on the fast path, we don't
    // acquire any locks. In order to prevent multiple timeouts from firing at
    // the same time, we check the condition again after acquiring the lock
    // (see below).
    //
    if (!Ipv4pPathMtuTimeoutFired(Path, Interface, SubInterface)) {
        return;
    }
    
    //
    // It's been at least 10 minutes since we last lowered our PMTU or
    // 2 minutes since we last increased it. Bump up the path MTU to the 
    // next plateau. 
    // First acquire the bucket lock for this. Once the lock has been
    // acquired, recheck the above condition since another thread might
    // have executed the same routine in the meantime and already updated
    // the path MTU.
    //
    Compartment = Interface->Compartment;
    RtlAcquireScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
    if (Ipv4pPathMtuTimeoutFired(Path, Interface, SubInterface)) {
        //
        // The timeout is still valid. Compute the next higher plateau and
        // update the path MTU.
        //
        for (CurrentIndex = sizeof(Ipv4pMtuTable) / sizeof(ULONG) - 1; 
             CurrentIndex != 0; 
             CurrentIndex--) {
            if (Ipv4pMtuTable[CurrentIndex] > Path->PathMtu) {
                break;
            }
        }
        
        //
        // The new MTU can be more than the link MTU. In that case set it
        // to the link MTU. 
        //
        NewMtu = Ipv4pMtuTable[CurrentIndex];
        if (NewMtu > SubInterface->NlMtu) {
            NewMtu = SubInterface->NlMtu;
        }
        
        ASSERT(NewMtu > Path->PathMtu);
        Updated = TRUE;

        //
        // The MTU has increased past the minimum MTU. No need to force
        // fragmentation any longer. 
        //
        Path->Flags.ForceFragment = FALSE;
        IppUpdatePathMtu(Path, NewMtu);
    }
    RtlReleaseScalableWriteLock(&Compartment->PathSet.Lock, &LockHandle);
    
    //
    // If the path MTU was updated, notify the network layer clients. 
    //
    if (Updated) {
        IppUpdatePathNotification(Compartment, Path);
    }
}
