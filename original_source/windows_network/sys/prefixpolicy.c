/*++

Copyright (c) 2003-2004  Microsoft Corporation

Module Name:

    prefixpolicy.c

Abstract:

    This module contains generic prefix policy management functions.

Author:

    Mohit Talwar (mohitt) Tue Feb 03 16:31:42 2004

Environment:

    Kernel mode only.

--*/

#include "precomp.h"
#include "prefixpolicy.tmh"


//
// IP_PREFIX_POLICY
//
// Define a structure to represent prefix policies.
// IPv4 and IPv6 policies are stored in a common IPv6 address format.
//

typedef struct _IP_PREFIX_POLICY {
    NL_PREFIX_POLICY_KEY Key;
    NL_PREFIX_POLICY_RW Data;
} IP_PREFIX_POLICY, *PIP_PREFIX_POLICY;


//
// IP_PREFIX_POLICY_TABLE
//
// Define a structure to represent a table of prefix policies.
//

typedef struct _IP_PREFIX_POLICY_TABLE {
    RTL_MRSW_LOCK Lock;
    ULONG Count;
    __field_ecount_opt(Count)
    IP_PREFIX_POLICY *Policies;
} IP_PREFIX_POLICY_TABLE, *PIP_PREFIX_POLICY_TABLE;

IP_PREFIX_POLICY_TABLE PrefixPolicyTable;


//
// Default prefix policies, when there are none configured by the user.
//

CONST IP_PREFIX_POLICY DefaultPrefixPoliciesPreferIpv6[] = {
    { {IN6ADDR_LOOPBACK_INIT, 128}, {50, 0} },      // ::1/128 (loopback)
    { {IN6ADDR_ANY_INIT, 0}, {40, 1} },             // ::/0
    { {IN6ADDR_6TO4PREFIX_INIT, 16}, {30, 2} },     // 2002::/16 (6to4)
    { {IN6ADDR_ANY_INIT, 96}, {20, 3} },            // ::/96 (v4-compatible)
    { {IN6ADDR_V4MAPPEDPREFIX_INIT, 96}, {10, 4} }, // ::ffff:0.0.0.0/96
    { {IN6ADDR_TEREDOPREFIX_INIT, 32}, {5, 5} },    // 3ffe:831f::/32 (Teredo)
};

CONST IP_PREFIX_POLICY DefaultPrefixPoliciesPreferIpv4[] = {
    { {IN6ADDR_V4MAPPEDPREFIX_INIT, 96}, {50, 0} }, // ::ffff:0.0.0.0/96
    { {IN6ADDR_LOOPBACK_INIT, 128}, {40, 1} },      // ::1/128 (loopback)
    { {IN6ADDR_ANY_INIT, 0}, {30, 2} },             // ::/0
    { {IN6ADDR_6TO4PREFIX_INIT, 16}, {20, 3} },     // 2002::/16 (6to4)
    { {IN6ADDR_ANY_INIT, 96}, {10, 4} },            // ::/96 (v4-compatible)
    { {IN6ADDR_TEREDOPREFIX_INIT, 32}, {5, 5} },    // 3ffe:831f::/32 (Teredo)
};

PIP_PREFIX_POLICY DefaultPrefixPolicies;
ULONG DefaultPrefixPoliciesCount;

__inline
VOID
IppConfigureDefaultPrefixPolicies(
    VOID
    )
{
    PrefixPolicyTable.Count = DefaultPrefixPoliciesCount;
    PrefixPolicyTable.Policies = DefaultPrefixPolicies;
}


__inline
VOID
IppUnconfigureDefaultPrefixPolicies(
    VOID
    )
{
    ASSERT(PrefixPolicyTable.Policies == DefaultPrefixPolicies);
    
    PrefixPolicyTable.Count = 0;
    PrefixPolicyTable.Policies = NULL;
}


//
// The default prefix policy, when nothing in the table matches.
// (Normally there will be a ::/0 policy.)
//

CONST IP_PREFIX_POLICY NullPrefixPolicy = {{{ 0 }, 0}, {(ULONG)-1, (ULONG)-1}};


__inline
ULONG
IppPolicyIndex(
    IN PIP_PREFIX_POLICY Policy
    )
{
    ULONG PolicyOffset = 
        (ULONG)(((PUCHAR) Policy) - ((PUCHAR) PrefixPolicyTable.Policies));

    ASSERT_ANY_LOCK_HELD(&PrefixPolicyTable.Lock);
    
    return (PolicyOffset / sizeof(*Policy));
}


PIP_PREFIX_POLICY
IppGetExactPrefixPolicy(
    IN PNL_PREFIX_POLICY_KEY Key
    )
{
    ULONG i;
    PIP_PREFIX_POLICY Policy;
    
    ASSERT_ANY_LOCK_HELD(&PrefixPolicyTable.Lock);
    
    for (i = 0; i < PrefixPolicyTable.Count; i++) {
        Policy = &PrefixPolicyTable.Policies[i];
        
        if ((Policy->Key.PrefixLength == Key->PrefixLength) &&
            IN6_ADDR_EQUAL(&Policy->Key.Prefix, &Key->Prefix)) {
            return Policy;
        }
    }
    return NULL;
}


PIP_PREFIX_POLICY
IppGetFirstPrefixPolicy(
    VOID
    )
{
    ASSERT_ANY_LOCK_HELD(&PrefixPolicyTable.Lock);

    if (PrefixPolicyTable.Count == 0) {
        //
        // There are no policies in the table.
        //
        return NULL;
    }

    return &PrefixPolicyTable.Policies[0];
}


PIP_PREFIX_POLICY
IppGetNextPrefixPolicy(
    IN PNL_PREFIX_POLICY_KEY Key
    )
{
    ULONG i;
    PIP_PREFIX_POLICY Policy;
    
    ASSERT_ANY_LOCK_HELD(&PrefixPolicyTable.Lock);

    Policy = IppGetExactPrefixPolicy(Key);
    if (Policy == NULL) {
        //
        // There is no existing policy matching the key.
        // Define an ordering amongst policies so enumeration always works?
        //
        return NULL;
    }
    
    i = IppPolicyIndex(Policy) + 1;
    if (i == PrefixPolicyTable.Count) {
        //
        // The key matched the last policy in the table.
        //
        return NULL;
    }

    return &PrefixPolicyTable.Policies[i];
}


NTSTATUS
IppAddPrefixPolicy(
    IN PNL_PREFIX_POLICY_KEY Key,
    IN PNL_PREFIX_POLICY_RW Data
    )
{
    ULONG Count;
    PIP_PREFIX_POLICY OldPolicies, NewPolicies;

    ASSERT_WRITE_LOCK_HELD(&PrefixPolicyTable.Lock);
    
    ASSERT(PrefixPolicyTable.Policies != DefaultPrefixPolicies);
    
    Count = PrefixPolicyTable.Count;
    OldPolicies = PrefixPolicyTable.Policies;
    
    //
    // Allocate space for an expanded list of prefix policies
    // (taking care to check for overflow first).
    //
    if (Count > ((ULONG_MAX / sizeof(IP_PREFIX_POLICY)) - 1)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    NewPolicies =
        ExAllocatePoolWithTag(
            NonPagedPool,
            (Count + 1) * sizeof(IP_PREFIX_POLICY),
            IpPrefixPolicyPoolTag);
    if (NewPolicies == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING, 
                   "IPNG: Failure allocating policies.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy old prefix policies.
    //
    if (OldPolicies != NULL) {
        RtlCopyMemory(
            NewPolicies,
            OldPolicies,
            Count * sizeof(IP_PREFIX_POLICY));
        ExFreePool(OldPolicies);
    }

    //
    // Append the new policy.
    //
    NewPolicies[Count].Key = *Key;
    NewPolicies[Count].Data = *Data;

    //
    // Update the old table.
    //
    PrefixPolicyTable.Count = Count + 1;
    PrefixPolicyTable.Policies = NewPolicies;

    return STATUS_SUCCESS;
}


NTSTATUS
IppDeletePrefixPolicy(
    IN PIP_PREFIX_POLICY Policy
    )
{
    ULONG Count = PrefixPolicyTable.Count, i = IppPolicyIndex(Policy);

    ASSERT_WRITE_LOCK_HELD(&PrefixPolicyTable.Lock);
    
    ASSERT(PrefixPolicyTable.Policies != DefaultPrefixPolicies);
    
    PrefixPolicyTable.Count = Count - 1;
    RtlMoveMemory(
        PrefixPolicyTable.Policies + i,
        PrefixPolicyTable.Policies + i + 1,
        (Count - i - 1) * sizeof(IP_PREFIX_POLICY));

    return STATUS_SUCCESS;
}


NTSTATUS
IppSetPrefixPolicy(
    IN PIP_PREFIX_POLICY Policy,
    IN PNL_PREFIX_POLICY_RW Data
    )
{
    ASSERT_WRITE_LOCK_HELD(&PrefixPolicyTable.Lock);
    
    ASSERT(PrefixPolicyTable.Policies != DefaultPrefixPolicies);
    
    Policy->Data = *Data;

    return STATUS_SUCCESS;
}


NTSTATUS
IppSwitchToUserConfiguredPrefixPolicies(
    IN PNL_PREFIX_POLICY_KEY Key,
    IN PNL_PREFIX_POLICY_RW Data,
    IN NSI_SET_ACTION Action
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    
    ASSERT_WRITE_LOCK_HELD(&PrefixPolicyTable.Lock);
    
    ASSERT(PrefixPolicyTable.Policies == DefaultPrefixPolicies);
    
    IppUnconfigureDefaultPrefixPolicies();
        
    if (Action != NsiSetDelete) {
        Status = IppAddPrefixPolicy(Key, Data);
        if (!NT_SUCCESS(Status)) {
            IppConfigureDefaultPrefixPolicies();
        }
    }

    return Status;
}


NTSTATUS
IppSetAllPrefixPolicyParametersHelper(
    IN PNL_PREFIX_POLICY_KEY Key,
    IN PNL_PREFIX_POLICY_RW Data,
    IN NSI_SET_ACTION Action
    )
{
    NTSTATUS Status;
    PIP_PREFIX_POLICY Policy;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // Validate parameters.
    //
    if (Key->PrefixLength > RTL_BITS_OF(IN6_ADDR)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Action != NsiSetDelete) {
        if ((Data == NULL) ||
            (Data->Precedence == (ULONG)-1) ||
            (Data->Label == (ULONG)-1)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    
    //
    // Ensure that the unused prefix bits are zero.
    // This makes the prefix comparisons below safe.
    //
    CopyPrefix(
        (PUCHAR) &Key->Prefix,
        (PUCHAR) &Key->Prefix,
        Key->PrefixLength, 
        sizeof(IN6_ADDR));

    RtlAcquireWriteLock(&PrefixPolicyTable.Lock, &LockHandle);

    //
    // Default policies cannot be modified, switch to user-configured policies.
    //
    if (PrefixPolicyTable.Policies == DefaultPrefixPolicies) {
        Status = IppSwitchToUserConfiguredPrefixPolicies(Key, Data, Action);
        RtlReleaseWriteLock(&PrefixPolicyTable.Lock, &LockHandle);
        return Status;
    }
        
    Policy = IppGetExactPrefixPolicy(Key);

    switch (Action) {
    case NsiSetCreateOnly:
        if (Policy == NULL) {
            Status = IppAddPrefixPolicy(Key, Data);
        } else {
            Status = STATUS_DUPLICATE_OBJECTID;
        }
        break;        
        
    case NsiSetCreateOrSet:
        if (Policy == NULL) {
            Status = IppAddPrefixPolicy(Key, Data);
        } else {
            Status = IppSetPrefixPolicy(Policy, Data);
        }
        break;
            
    case NsiSetDefault:
        if (Policy == NULL) {
            Status = STATUS_NOT_FOUND;
        } else {
            Status = IppSetPrefixPolicy(Policy, Data);
        }   
        break;

    case NsiSetDelete:
        if (Policy == NULL) {
            Status = STATUS_NOT_FOUND;
        } else {
            Status = IppDeletePrefixPolicy(Policy);
        }
        break;

    default:
        ASSERT(FALSE);
        Status = STATUS_SUCCESS;
        break;
    }

    RtlReleaseWriteLock(&PrefixPolicyTable.Lock, &LockHandle);

    return Status;
}


VOID
IppResetPrefixPolicy(
    VOID
    )
/*++

Routine Description:
    
    Revert to default prefix policies after deleting those configured by user.
    
Arguments:

    None.
    
Return Value:

    None.
    
--*/ 
{
    IP_PREFIX_POLICY *Policies = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // Free the prefix policies.
    //
    RtlAcquireWriteLock(&PrefixPolicyTable.Lock, &LockHandle);
    if (PrefixPolicyTable.Policies != DefaultPrefixPolicies) {
        Policies = PrefixPolicyTable.Policies;
        IppConfigureDefaultPrefixPolicies();
    }
    RtlReleaseWriteLock(&PrefixPolicyTable.Lock, &LockHandle);

    if (Policies != NULL) {
        ExFreePool(Policies);
    }
}


NTSTATUS
IppStartPrefixPolicyModule(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Initializes the prefix policy module.

Arguments:

    Protocol - Unused.
    
Return Value:

    None.
    
Caller IRQL: PASSIVE_LEVEL.

--*/ 
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i, Count = 0;
    PNL_PREFIX_POLICY_KEY Key;
    PNL_PREFIX_POLICY_RW Rw;

    PASSIVE_CODE();

    //
    // The prefix policy table is initialized once.
    //
    ASSERT(IS_IPV6_PROTOCOL(Protocol));

    if (Ipv6Global.DisabledComponents.PreferIpv4) {
        DefaultPrefixPoliciesCount =
            RTL_NUMBER_OF(DefaultPrefixPoliciesPreferIpv4);
        DefaultPrefixPolicies =
            (PIP_PREFIX_POLICY) DefaultPrefixPoliciesPreferIpv4;
    } else {
        DefaultPrefixPoliciesCount =
            RTL_NUMBER_OF(DefaultPrefixPoliciesPreferIpv6);
        DefaultPrefixPolicies =
            (PIP_PREFIX_POLICY) DefaultPrefixPoliciesPreferIpv6;
    }
    
    RtlInitializeMrswLock(&PrefixPolicyTable.Lock);

    //
    // Configure persistent policies.
    //
    NsiAllocateAndGetTable(
        NsiPersistent,
        Protocol->ModuleId,
        NlPrefixPolicyObject,
        &Key, sizeof(*Key),
        &Rw, sizeof(*Rw),
        NULL, 0,
        NULL, 0,
        &Count,
        FALSE);
    if (Count == 0) {
        Status = STATUS_NOT_FOUND;
        goto Bail;
    }
    
    for (i = 0; i < Count; i++) {
        Status =
            IppSetAllPrefixPolicyParametersHelper(
                &Key[i],
                &Rw[i],
                NsiSetCreateOrSet);
        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    NsiFreeTable(Key, Rw, NULL, NULL);
    
Bail:
    if (!NT_SUCCESS(Status)) {
        IppResetPrefixPolicy();
    }

    IppDefaultStartRoutine(Protocol, IMS_PREFIX_POLICY);

    return STATUS_SUCCESS;
}


VOID
IppCleanupPrefixPolicyModule(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Uninitialize the prefix policy module.

Arguments:

    Protocol - Unused.
    
Return Value:

    None.
    
Caller IRQL: PASSIVE_LEVEL.

--*/ 
{
    PASSIVE_CODE();

    //
    // The prefix policy table is uninitialized once.
    //
    ASSERT(IS_IPV6_PROTOCOL(Protocol));
    
    UNREFERENCED_PARAMETER(Protocol);
    
    IppResetPrefixPolicy();

    RtlUninitializeMrswLock(&PrefixPolicyTable.Lock);
}


VOID
IppLookupPrefixPolicy(
    IN CONST UCHAR *Address,
    IN ULONG AddressBytes,
    OUT PNL_PREFIX_POLICY_RW Data
    )
{
    ULONG i;
    KIRQL OldIrql;
    IN6_ADDR Ipv6Address;
    CONST IP_PREFIX_POLICY *Policy, *BestPolicy = NULL;

    if (AddressBytes != sizeof(IN6_ADDR)) {
        IN_ADDR Ipv4Address = *((IN_ADDR UNALIGNED *) Address);
        IN6_SET_ADDR_V4MAPPED(&Ipv6Address, &Ipv4Address);
        Address = (PUCHAR) &Ipv6Address;
    }
    
    RtlAcquireReadLock(&PrefixPolicyTable.Lock, &OldIrql);

    for (i = 0; i < PrefixPolicyTable.Count; i++) {
        Policy = &PrefixPolicyTable.Policies[i];

        if (HasPrefix(Address, 
                      (CONST UCHAR *) Policy->Key.Prefix.s6_bytes,
                      Policy->Key.PrefixLength)) {

            if ((BestPolicy == NULL) ||
                (BestPolicy->Key.PrefixLength < Policy->Key.PrefixLength)) {
                //
                // So far this is our best match.
                //
                BestPolicy = Policy;
            }
        }
    }

    if (BestPolicy == NULL) {
        //
        // There were no matches, so return default values.
        //
        BestPolicy = &NullPrefixPolicy;
    }

    //
    // Return information from the best matching policy.
    //
    *Data = BestPolicy->Data;

    RtlReleaseReadLock(&PrefixPolicyTable.Lock, OldIrql);
}


NTSTATUS
NTAPI
IpGetAllPrefixPolicyParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Retreive all public parameters of a prefix policy.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    KIRQL OldIrql;
    NTSTATUS Status;
    PIP_PREFIX_POLICY Policy;
    PNL_PREFIX_POLICY_KEY Key = (PNL_PREFIX_POLICY_KEY)
        Args->KeyStructDesc.KeyStruct;
    PNL_PREFIX_POLICY_RW Data = (PNL_PREFIX_POLICY_RW)
        Args->StructDesc.RwParameterStruct;

    RtlAcquireReadLock(&PrefixPolicyTable.Lock, &OldIrql);
    
    switch (Args->Action) {
    case NsiGetExact:
        Policy = IppGetExactPrefixPolicy(Key);
        break;

    case NsiGetFirst:
        Policy = IppGetFirstPrefixPolicy();
        break;

    case NsiGetNext:
        Policy = IppGetNextPrefixPolicy(Key);
        break;

    default:
        ASSERT(FALSE);
        Policy = NULL;
        break;
    }

    if (Policy == NULL) {
        Status = (Args->Action == NsiGetExact)
            ? STATUS_NOT_FOUND
            : STATUS_NO_MORE_ENTRIES;
    } else {
        if (Args->Action != NsiGetExact) {
            *Key = Policy->Key;
        }

        if (Data != NULL) {
            *Data = Policy->Data;
        }

        Status = STATUS_SUCCESS;
    }

    RtlReleaseReadLock(&PrefixPolicyTable.Lock, OldIrql);    
    
    return Status;
}



NTSTATUS
NTAPI
IpSetAllPrefixPolicyParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    Updates public parameters of a prefix policy.

Arguments:

    Args - Supplies information about the operation to perform.

Return Value:

    STATUS_SUCCESS or a failure code.

Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    PNL_PREFIX_POLICY_KEY Key = (PNL_PREFIX_POLICY_KEY)
        Args->KeyStructDesc.KeyStruct;
    PNL_PREFIX_POLICY_RW Data = (PNL_PREFIX_POLICY_RW)
        Args->RwStructDesc.RwParameterStruct;

    if (Args->Action == NsiSetReset) {
        if (Key != NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        IppResetPrefixPolicy();

        return STATUS_SUCCESS;
    }

    return IppSetAllPrefixPolicyParametersHelper(Key, Data, Args->Action);
}
