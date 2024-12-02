/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    subr.c

Abstract:

    This module provides protocol-independent helper subroutines
    for use by the IPv4 and IPv6 modules.

    REVIEW: should some of these functions be moved to indef.h?

Author:

    Dave Thaler (dthaler) 22-May-2002

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "subr.tmh"
#include "subr.h"

UINT32 g_37HashSeed;
volatile LONG IppRandomValue;
ULONG IppTickCount = 0;
KDPC IppTimeoutDpc;
KTIMER IppTimer;

NTSTATUS
IppRegQueryDwordValue(
    IN CONST WCHAR *KeyName,
    IN CONST WCHAR *ValueName,
    PULONG ValueData
    )
/*++

Routine Description:
    
    Read a REG_DWORD value from the registry.
    
Arguments:

    KeyName - Supplies the name of the parent key of the value to read.

    ValueName - Supplies the name of the value to read.

    ValueData - Returns the read data.
    
Return Value:

    STATUS_SUCCESS or failure code.

--*/ 
{
#define WORK_BUFFER_SIZE  512

    NTSTATUS Status;
    HANDLE KeyHandle;
    UNICODE_STRING UnicodeName;
    OBJECT_ATTRIBUTES ObjectAttributes = {0};
    UCHAR InformationBuffer[WORK_BUFFER_SIZE] = {0};
    PKEY_VALUE_FULL_INFORMATION Information =
        (PKEY_VALUE_FULL_INFORMATION) InformationBuffer;
    ULONG ResultLength;
    
    PAGED_CODE();

    RtlInitUnicodeString(&UnicodeName, KeyName);

    InitializeObjectAttributes(
        &ObjectAttributes,
        &UnicodeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlInitUnicodeString(&UnicodeName, ValueName);

    Status =
        ZwQueryValueKey(
            KeyHandle,
            &UnicodeName,
            KeyValueFullInformation,
            Information,
            WORK_BUFFER_SIZE,
            &ResultLength);
    if (NT_SUCCESS(Status)) {
        if (Information->Type != REG_DWORD) {
            Status = STATUS_INVALID_PARAMETER_MIX;
        } else {
            *ValueData =
                *((ULONG UNALIGNED *)
                  ((PCHAR) Information + Information->DataOffset));
        }
    }

    ZwClose(KeyHandle);
    
    return Status;
}


DL_ADDRESS_TYPE
IppDatalinkAddressType(
    IN CONST UCHAR *Address,
    IN CONST IP_INTERFACE *Interface
    )
/*++

Routine Description:

    Determine the type of the datalink layer address.

Arguments:

    Address - Supplies the datalink address.

    Interface - Supplies the interface for which to determine the address type.
    
Return Value:

    Address type: broadcast, multicast, or unicast.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    CONST FL_INTERFACE_CHARACTERISTICS *Character =
        Interface->FlCharacteristics;

    switch (Character->InterfaceType) {
    case IF_TYPE_ETHERNET_CSMACD:       // Ethernet.
    case IF_TYPE_IEEE80211:             // Wireless.
        //
        // Ethernet like interfaces.
        //
        ASSERT(Character->DlAddressLength == sizeof(DL_EUI48));
        return EthernetAddressType(Address);

    case IF_TYPE_ISO88025_TOKENRING:    // Token Ring.
        //
        // Token-Ring like interfaces.
        //
        ASSERT(Character->DlAddressLength == sizeof(DL_EUI48));
        return TokenRingAddressType(Address);
        
    default:
        return DlUnicast;
    }    
}


BOOLEAN
IppGetSystemRandomBits(
    OUT PUCHAR Buffer,
    IN ULONG Length
    )
/*++

Routine Description:
    
    Ask the KSecDD driver for a block of 'random' bits.

    This routine requests a block of random bits from the KSecDD driver.
    Doing so is not cheap - we only use this routine to provide seed values
    for our other random number generators.

Arguments:

    Buffer - Returns a buffer filled with random data.

    Length - Supplies the length of Buffer in bytes.
    
Return Value:

    TRUE if successful, FALSE otherwise.

Caller IRQL: PASSIVE_LEVEL.

--*/ 
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    KEVENT Event;
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;

    PASSIVE_CODE();
    
    RtlInitUnicodeString(&DeviceName, DD_KSEC_DEVICE_NAME_U);

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    //
    // Get the file and device objects for KDSECDD,
    // acquire a reference to the device-object,
    // release the unneeded reference to the file-object,
    // and build the I/O control request to issue to KSecDD.
    //
    Status =
        IoGetDeviceObjectPointer(
            &DeviceName, FILE_ALL_ACCESS, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                   "IPNG: IoGetDeviceObjectPointer(KSecDD)=%08x\n", Status);
        return FALSE;
    }
    
    ObReferenceObject(DeviceObject);

    ObDereferenceObject(FileObject);

    Irp =
        IoBuildDeviceIoControlRequest(
            IOCTL_KSEC_RNG,
            DeviceObject,
            NULL,
            0,
            Buffer,
            Length,
            FALSE,
            &Event,
            &IoStatusBlock);
    if (Irp == NULL) {
        ObDereferenceObject(DeviceObject);
        return FALSE;
    }

    //
    // Issue the I/O control request, wait for it to complete if necessary,
    // and release the reference to KSecDD's device-object.
    //
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }
    ObDereferenceObject(DeviceObject);

    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                   "IPNG: IoCallDriver IOCTL_KSEC_RNG failed %#x\n", Status);
        return FALSE;
    }

    return TRUE;
}


VOID
IppSeedRandom(
    VOID
    )
/*++

Routine Description:
    
    Seed our random number generator.
    
Arguments:

    None.
    
Return Value:

    None.
    
Caller IRQL: PASSIVE_LEVEL.

--*/
{
    UCHAR Seed[16];
    LONG OldValue;
    MD5_CTX Context;
    union {
        LONG NewValue;
        UCHAR Buffer[MD5DIGESTLEN];
    } Hash;

    PASSIVE_CODE();
    
    //
    // Perform initial seed of our psuedo-random number generator using
    // 'random' bits from the KSecDD driver.  KSecDD reportedly seeds itself
    // with various system-unique values, which is exactly what we want
    // (in order to avoid synchronicity issues between machines).
    // NOTE: sizeof(Seed) is arbitrarily chosen to be 16.
    //
    (VOID) IppGetSystemRandomBits(Seed, sizeof(Seed));

    do {
        OldValue = IppRandomValue;
        MD5Init(&Context);
        MD5Update(&Context, Seed, sizeof(Seed));
        MD5Update(&Context, (PUCHAR) &OldValue, sizeof(OldValue));
        MD5Final(&Context);
        RtlCopyMemory(Hash.Buffer, Context.digest, MD5DIGESTLEN);
    } while (InterlockedCompareExchange(
                 &IppRandomValue,
                 Hash.NewValue,
                 OldValue) != OldValue);
}


ULONG
IppRandom(
    VOID
    )
/*++

Routine Description:

    Generate a pseudo random value between 0 and 2^32 - 1.

    This routine is a quick and dirty psuedo random number generator.  It has
    the advantages of being fast and consuming very little memory (for either
    code or data).  The random numbers it produces are not of the best quality,
    however.  A much better generator could be had if we were willing to use an
    extra 256 bytes of memory for data.

    This routine uses the linear congruential method (see Knuth, Vol II), with
    specific values for the multiplier and constant taken from Numerical
    Recipes in C Second Edition by Press, et. al.
     
Arguments:

    None.
    
Return Value:

    A random unsigned long.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    LONG NewValue, OldValue;

    //
    // The algorithm is R = (aR + c) mod m, where R is the random number,
    // a is a magic multiplier, c is a constant, and the modulus m is the
    // maximum number of elements in the period.  We chose our m to be 2^32
    // in order to get the mod operation for free.
    //
    do {
        OldValue = IppRandomValue;
        NewValue = (1664525 * OldValue) + 1013904223;
    } while (InterlockedCompareExchange(
                 &IppRandomValue, NewValue, OldValue) != OldValue);

    return (ULONG) NewValue;
}


ULONG
RandomNumber(
    IN ULONG Min,
    IN ULONG Max
    )
/*++

Routine Description:
    
    Return a number randomly selected from a range.
    
Arguments:

    Min, Max - Supplies the range.
    
Return Value:

    Random number between Min and Max.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/    
{
    ULONG Number;

    //
    // NOTE: The high bits of Random() are much more random than the low bits.
    //

    //
    // Calculate spread.
    //
    Number = Max - Min;

    //
    // Randomize spread.
    //
    Number = (ULONG)(((ULONGLONG) IppRandom() * Number) >> 32);

    Number += Min;

    return Number;
}


BOOLEAN
HasPrefix(
    IN CONST UCHAR *Address,
    IN CONST UCHAR *Prefix,
    IN ULONG PrefixLength
    )
/*++

Routine Description:

    Tests whether an address has the given prefix.

Arguments:

    Address - Supplies the address to test.

    Prefix - Supplies the prefix to test against.

    PrefixLength - Supplies the prefix length in bits.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    //
    // Check that initial integral bytes match.
    //
    while (PrefixLength > 8) {
        if (*Address++ != *Prefix++) {
            return FALSE;
        }
        PrefixLength -= 8;
    }

    //
    // Check any remaining bits.
    // Note that if PrefixLength is zero now, we should not
    // dereference AddressBytes/PrefixBytes.
    //
    if ((PrefixLength > 0) &&
        ((*Address >> (8 - PrefixLength)) !=
         (*Prefix >> (8 - PrefixLength)))) {
        return FALSE;
    }

    return TRUE;
}

VOID
CopyPrefix(
    __out_ecount(AddressBytes) UCHAR *Address, 
    __in CONST UCHAR *Prefix,
    __in_range(0, AddressBytes * 8) ULONG PrefixLength, 
    __in ULONG AddressBytes
    )
/*++

Routine Description:

    Copy an address prefix, zeroing the remaining bits
    in the destination address.

Arguments:

    Address - Supplies the address buffer to fill in.

    Prefix - Supplies the initial prefix.

    PrefixLength - Supplies the initial prefix length in bits.

    AddressBytes - Supplies the complete length of the address in bytes.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG PLBytes, PLRemainderBits, Loop;

    PLBytes = PrefixLength / 8;
    PLRemainderBits = PrefixLength % 8;
    for (Loop = 0; Loop < AddressBytes; Loop++) {
        if (Loop < PLBytes) {
            Address[Loop] = Prefix[Loop];
        } else {
            Address[Loop] = 0;
        }
    }
    if (PLRemainderBits != 0) {
        //
        // Keep prefast happy.
        //
        ASSERT(PLBytes < AddressBytes);
        __analysis_assume(PLBytes < AddressBytes);
        Address[PLBytes] =
            (UCHAR)(Prefix[PLBytes] & (0xff << (8 - PLRemainderBits)));
    }
}

BOOLEAN
IppValidatePrefix(
    IN CONST UCHAR *Prefix,
    IN ULONG PrefixLength,
    IN ULONG AddressBytes
    )
/*++

Routine Description:

    Verifies that all bits past the prefix length are zero.

Arguments:

    Prefix - Supplies the initial prefix.

    PrefixLength - Supplies the initial prefix length in bits.

    AddressBytes - Supplies the complete length of the address in bytes.

Return Value:

    TRUE if remaining bits are zero, FALSE if not.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG PlBytes, PlRemainderBits, Loop;

    PlBytes = PrefixLength / 8;
    PlRemainderBits = PrefixLength % 8;
    for (Loop = 0; Loop < AddressBytes; Loop++) {
        if (Loop < PlBytes) {
            continue;
        } else if ((Loop == PlBytes) && (PlRemainderBits > 0)) {
            ASSERT(PlBytes < AddressBytes);
            if (Prefix[PlBytes] !=
                (UCHAR)(Prefix[PlBytes] & (0xff << (8 - PlRemainderBits)))) {
                return FALSE;
            }
        } else {
            if (Prefix[Loop] != 0) {
                return FALSE;
            }
        }
    }
    return TRUE;
}

VOID
CreateBroadcastAddress(
    __in CONST UCHAR *Prefix,
    __in_range(0, AddressBytes * 8) ULONG PrefixLength, 
    __in ULONG AddressBytes,
    __in BOOLEAN UseZeroBroadcastAddress, 
    __out_ecount(AddressBytes) UCHAR *BroadcastAddress
    )
/*++

Routine Description:

    Create an IPv4 broadcast address from a given prefix and prefix length by
    copying the prefix and setting the remaining bits to 1.

Arguments:

    Prefix - Supplies the initial prefix.

    PrefixLength - Supplies the initial prefix length in bits.

    AddressBytes - Supplies the length of the address in bytes. 

    UseZeroBroadcastAddress - Supplies a boolean indicating whether the
         broadcast address has all zeroes or not. 

    BroadcastAddress - Returns the broadcast address.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG PLBytes, PLRemainderBits, Loop;

    PLBytes = PrefixLength / 8;
    PLRemainderBits = PrefixLength % 8;
    for (Loop = 0; Loop < AddressBytes; Loop++) {
        if (Loop < PLBytes) {
            BroadcastAddress[Loop] = Prefix[Loop];
        } else {
            BroadcastAddress[Loop] = UseZeroBroadcastAddress ? 0 : 0xff;
        }
    }
    if (PLRemainderBits != 0) {
        //
        // Keep prefast happy.
        //
        ASSERT(PLBytes < AddressBytes);
        __analysis_assume(PLBytes < AddressBytes);
        if (UseZeroBroadcastAddress) {
            BroadcastAddress[PLBytes] =
                (UCHAR)(Prefix[PLBytes] & (0xff << (8 - PLRemainderBits)));
        } else {
            BroadcastAddress[PLBytes] =
                (UCHAR)(Prefix[PLBytes] | (~(0xff << (8 - PLRemainderBits))));
        }
    }
}


ULONG
CommonPrefixLength(
    IN CONST UCHAR *Address1, 
    IN CONST UCHAR *Address2,
    IN ULONG Size
    )
/*++

Routine Description:

    Calculate the length of the longest prefix common
    to the two addresses.

Arguments:

    Address1 - Supplies the first address to compare.

    Address2 - Supplies the second address to compare.

Return Value:

    Returns the number of bits in the prefix in common.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    ULONG i, j;

    //
    // Find first non-matching byte.
    //
    for (i = 0; ; i++) {
        if (i == Size) {
            return 8 * i;
        }

        if (Address1[i] != Address2[i]) {
            break;
        }
    }

    //
    // Find first non-matching bit (there must be one).
    //
    for (j = 0; ; j++) {
        ULONG Mask = 1 << (7 - j);

        if ((Address1[i] & Mask) != (Address2[i] & Mask)) {
            break;
        }
    }

    return 8 * i + j;
}

VOID
IppCompartmentSetTimeout(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Process timeouts pertaining to the compartment set.
    Called once every timer tick from IppProtocolTimeout.
    
Arguments:

    Protocol - Supplies the protocol whose compartment set is to be inspected.

Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/ 
{
    PLIST_ENTRY Link;
    PIP_COMPARTMENT Compartment;    
    BOOLEAN RecalculateReachableTime, ForceRouterAdvertisement, Terminate;
    PLOCKED_LIST CompartmentSet = &Protocol->CompartmentSet;

    DISPATCH_CODE();

    //
    // Because new compartments are only added at the head of the list,
    // we can unlock the list during our traversal
    // and know that the traversal will terminate properly.
    //
    RtlAcquireReadLockAtDpcLevel(&CompartmentSet->Lock);
    for (Link = CompartmentSet->Set.Flink;
         Link != &CompartmentSet->Set;
         Link = Link->Flink) {
        Compartment = (PIP_COMPARTMENT)
            CONTAINING_RECORD(Link, IP_COMPARTMENT, Link);
        IppReferenceCompartment(Compartment);
        RtlReleaseReadLockFromDpcLevel(&CompartmentSet->Lock);
       
        IppPathSetTimeout(Compartment);
 
        //
        // Recalculate ReachableTime every few hours.
        //
        RecalculateReachableTime =
            (InterlockedDecrement(&Compartment->RecalculationTimer) == 0);
        if (RecalculateReachableTime) {
            //
            // Restart timer.
            // Assumes writes are synchronized with interlocked operations.
            //
            Compartment->RecalculationTimer = RECALC_REACHABLE_INTERVAL;
        }

        //
        // Grab the value of ForceRouterAdvertisement.
        //
        ForceRouterAdvertisement =
            (InterlockedExchange(
                &Compartment->ForceRouterAdvertisement, FALSE) == TRUE);

        //
        // Handle per-interface timeouts.
        //
        Protocol->InterfaceSetTimeout(
            &Compartment->InterfaceSet,
            RecalculateReachableTime,
            ForceRouterAdvertisement);

        //
        // Handle per-route timeouts.
        //
        IppRouteSetTimeout(Compartment);

        //
        // Handle multicast forwarding entry timeouts.
        //
        IppMfeSetTimeOut(Compartment);  

        //
        // Handle ephemeral loopback address cleanup.
        //
        IppEphemeralLoopbackAddressSetTimeout(Compartment);

        RtlAcquireReadLockAtDpcLevel(&CompartmentSet->Lock);

        //
        // Before releasing the compartment reference (perhaps its last),
        // determine if it has been deleted (hence removed from the set).
        // If so, this traversal must terminate early.
        //
        Terminate = IppIsCompartmentDisabled(CompartmentSet, Compartment);
        IppDereferenceCompartment(Compartment);
        if (Terminate) {
            break;
        }        
    }
    RtlReleaseReadLockFromDpcLevel(&CompartmentSet->Lock);
}

NETIO_INLINE
ULONG 
IppComputeCurrentTickCount(
    VOID
    )
/*++

Routine Description:
    
    Get the current tick count from system time.
    
Arguments:

    None.
    
Return Value:

    Tick count in 0.5s intervals.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/
{
    ULONGLONG CurrentMillis = (ULONGLONG)X100NSTOMS(KeQueryInterruptTime());

    return (ULONG)(CurrentMillis / IPP_MS_PER_TICK);
}

VOID
IppTimeout(
    IN PKDPC Dpc,
    IN PVOID Context,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    )
/*++

Routine Description:

    Perform various housekeeping duties periodically for all protocols.

Arguments:

    Dpc - Supplies the DPC object describing this routine.

    Context - Supplies the argument we asked to be called with. Should be NULL.

    SystemArgument1, SystemArgument2 - Unused.
    
Return Value:

    None.
    
Caller IRQL: DISPATCH_LEVEL.

--*/    
{
    ULONG CurrentTicks;
    
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    DISPATCH_CODE();
    ASSERT(Context == NULL);

    CurrentTicks = (ULONG)IppComputeCurrentTickCount();
    
    //
    // Update to current tick count.
    //
    InterlockedExchange((PLONG) &IppTickCount, CurrentTicks);

    if (Ipv4Global.Installed) {
        IppProtocolTimeout(&Ipv4Global);
    }
    
    if (Ipv6Global.Installed) {
        IppProtocolTimeout(&Ipv6Global);
    }
}


VOID
IppProtocolTimeout(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:

    Neighbor discovery, fragment reassembly, ICMP ping, etc. all have
    time-dependent parts.  Check for timer expiration here.


Arguments:

    Protocol - Supplies the protocol whose timeout to process.

Return Value:

    None.

Caller IRQL: DISPATCH_LEVEL

--*/

{
    DISPATCH_CODE();

    ASSERT(Protocol != NULL);

    //
    // Handle per-compartment timeouts.
    //
    IppCompartmentSetTimeout(Protocol);

    //
    // If we might have active reassembly records,
    // call out to handle timeout processing for them.
    //
    if (!TtIsTableEmpty(Protocol->ReassemblySet.TimerTable)) {
        IppReassemblyTimeout(Protocol);
    }

    //
    // Handle echo request timeouts.
    //
    IppEchoRequestSetTimeout(Protocol);
  
}


ULONG
IppSecondsToTicks(
    IN ULONG Seconds
    )
/*++

Routine Description:
    
    Convert seconds to timer ticks.

Arguments:

    Seconds - Supplies seconds.  A value of INFINITE_LIFETIME means infinity.
    
Return Value:

    Seconds.  A value of INFINITE_LIFETIME indicates infinity.
    
--*/    
{
    ULONG Ticks;

    Ticks = Seconds * IPP_TICKS_SECOND;
    if ((Ticks / IPP_TICKS_SECOND) != Seconds) {
        Ticks = INFINITE_LIFETIME; // Overflow.
    }
    
    return Ticks;
}


ULONG
IppTicksToSeconds(
    IN ULONG Ticks
    )
/*++

Routine Description:
    
    Convert timer ticks to seconds.

Arguments:

    Ticks - Supplies timer ticks.  A value of INFINITE_LIFETIME means infinity.
    
Return Value:

    Seconds.  A value of INFINITE_LIFETIME indicates infinity.
    
--*/    
{
    ULONG Seconds;

    if (Ticks == INFINITE_LIFETIME) {
        Seconds = INFINITE_LIFETIME;
    } else {
        Seconds = Ticks / IPP_TICKS_SECOND;
    }

    return Seconds;
}


ULONG
IppMillisecondsToTicks(
    IN ULONG Millis
    )
/*++

Routine Description:

    Convert milliseconds to timer ticks.

Arguments:

    Millis - Supplies milliseconds.

Return Value:

    Timer ticks.

--*/
{
    ULONG Ticks;

    //
    // Use 64-bit arithmetic to guard against intermediate overlow.
    //
    Ticks = (ULONG) (((ULONGLONG) Millis * IPP_TICKS_SECOND) / 1000);

    //
    // If the number of millis is non-zero, then have at least one tick.
    // Caveat: Hence we rounds up, but only if Millis < IPP_TIMEOUT.
    //
    if ((Ticks == 0) && (Millis != 0)) {
        Ticks = 1;
    }

    return Ticks;
}


NTSTATUS
IppStartTimerManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:
    
    Start the periodic timer.
    
Arguments:

    Protocol - Supplies the network layer protocol's state.
    
Return Value:

    STATUS_SUCCESS.
    
Caller IRQL: PASSIVE_LEVEL.

--*/ 
{
    LARGE_INTEGER Time;
    ULONG InitialWakeUp;

    PASSIVE_CODE();

    ASSERT(Protocol == NULL);

    UNREFERENCED_PARAMETER(Protocol);
    
    //
    // Prepare our periodic timer and its associated DPC object.
    //
    // When the timer expires, the timeout deferred procedure call (DPC) is
    // queued.  Everything we need to do at some specific frequency is driven
    // off of this routine.
    //
    KeInitializeDpc(&IppTimeoutDpc, IppTimeout, NULL);
    KeInitializeTimerEx(&IppTimer, SynchronizationTimer);
    
    //
    // Start the timer with an initial relative expiration time and also a
    // recurring period.  The initial expiration time is negative (to indicate
    // a relative time), and in 100ns units, so we first have to do some
    // conversions.  The initial expiration time is randomized to help prevent
    // synchronization between different machines.
    //
    InitialWakeUp = RandomNumber(0, IPP_TIMEOUT * 10000);
    Time.QuadPart = - (LONGLONG) InitialWakeUp;
    KeSetTimerEx(&IppTimer, Time, IPP_TIMEOUT, &IppTimeoutDpc);

    return STATUS_SUCCESS;
}

VOID
IppCleanupTimerManager(
    IN PIP_PROTOCOL Protocol
    )
/*++

Routine Description:
    
    Stop the periodic timer.
    
Arguments:

    Protocol - Supplies the network layer protocol's state.
    
Return Value:

    None.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    ASSERT(Protocol == NULL);
    UNREFERENCED_PARAMETER(Protocol);

    //
    // Stop the periodic timer.
    //
    KeCancelTimer(&IppTimer);

    //
    // Ensure that the associated DPC has completed.
    //
    KeFlushQueuedDpcs();
}

UINT32
IppGetMillisecondsFromMidnight(
    VOID
    )
/*++

Routine Description:

    Returns the time in milliseconds since midnight.

Arguments:

    None.

Return Value:

    Time in milliseconds since midnight.

--*/
{
    LARGE_INTEGER NtTime;
    TIME_FIELDS TimeFields;

    KeQuerySystemTime(&NtTime);

    RtlTimeToTimeFields(&NtTime, &TimeFields);

    return 
        IppMilliseconds(
            (TimeFields.Hour * HOURS + TimeFields.Minute * MINUTES + 
             TimeFields.Second * SECONDS) + TimeFields.Milliseconds);
}


VOID
IppCopyNetBufferListInfo(
    IN PNET_BUFFER_LIST Destination,
    IN PNET_BUFFER_LIST Source
    )
{
    PVOID SecurityContext;

    //
    // Copy the IPsec context to the new NetBufferList.
    //
    SecurityContext = IpSecGetSecurityContext(Source);
    IpSecSetSecurityContext(Destination, SecurityContext);
    IpSecSetSecurityContext(Source, NULL);

    //
    // Copy the checksum context into the new NetBufferList.
    //
    NET_BUFFER_LIST_INFO(Destination, TcpIpChecksumNetBufferListInfo) =
        NET_BUFFER_LIST_INFO(Source, TcpIpChecksumNetBufferListInfo);

    //
    // Copy the IPsec context into the new NetBufferList.
    //
    NET_BUFFER_LIST_INFO(Destination, IPsecOffloadV1NetBufferListInfo) =
        NET_BUFFER_LIST_INFO(Source, IPsecOffloadV1NetBufferListInfo);

#if (NDIS_SUPPORT_NDIS61)
    //
    // Copy the IPsec V2 context into the new NetBufferList.
    //
    NET_BUFFER_LIST_INFO(Destination, IPsecOffloadV2NetBufferListInfo) =
        NET_BUFFER_LIST_INFO(Source, IPsecOffloadV2NetBufferListInfo);
   NET_BUFFER_LIST_INFO(Destination, IPsecOffloadV2HeaderNetBufferListInfo) =
        NET_BUFFER_LIST_INFO(Source, IPsecOffloadV2HeaderNetBufferListInfo);
   NET_BUFFER_LIST_INFO(Destination, IPsecOffloadV2TunnelNetBufferListInfo) =
        NET_BUFFER_LIST_INFO(Source, IPsecOffloadV2TunnelNetBufferListInfo);
#endif

    //
    // Copy the protocol reserved flags.
    //
    NBL_SET_PROTOCOL_RSVD_FLAG(Destination, Source->Flags);
}


PIP_REQUEST_CONTROL_DATA
IppCopyPacket(
    IN PIP_PROTOCOL Protocol,
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    Creates a copy of a given packet. It allocates space for the new packet,
    copies all the fields and adds references where needed.

Arguments:

    Protocol - Supplies the network layer protocol's state.

    Packet - Supplies the packet to be copied.

Return Value:

    Returns the copy or NULL in case of failure. 

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_REQUEST_CONTROL_DATA Copy;
    
    Copy = (PIP_REQUEST_CONTROL_DATA) FsbAllocate(Protocol->ControlPool);
    if (Copy == NULL) {
        return NULL;
    }
    
    RtlCopyMemory(Copy, Packet, sizeof(*Packet));

    if (Packet->CurrentDestinationAddress == 
          Packet->FinalDestinationAddress.Buffer) {
       Copy->CurrentDestinationAddress =
          Copy->FinalDestinationAddress.Buffer;
    }

    Copy->Next = NULL;
    Copy->IsAllocated = TRUE;
    
    if (Copy->IsOriginLocal) {
        if (Copy->Path != NULL) {
            IppReferencePath(Copy->Path);
            Copy->IsPathReferenced = TRUE;
            Copy->IsSourceReferenced = FALSE;
            ASSERT((Copy->SourceLocalAddress == NULL) ||
                   (Copy->SourceLocalAddress == Copy->Path->SourceAddress));
        } else if (Copy->SourceLocalAddress != NULL) {
            IppReferenceLocalUnicastAddress(Copy->SourceLocalAddress);
            Copy->IsSourceReferenced = TRUE;
            ASSERT(!Copy->IsPathReferenced);
        }  else {
            ASSERT(!Copy->IsPathReferenced);
            ASSERT(!Copy->IsSourceReferenced);
            ASSERT(Copy->Compartment == NULL);
        }
    } else {
        //
        // We don't reference the path bucket in the copy since it is not used
        // anywhere in the data path.  We add an explicit reference to the
        // destination below which should suffice. 
        //
        Copy->Path = NULL;
        Copy->IsPathReferenced = FALSE;

        ASSERT(Copy->SourceSubInterface != NULL);
        IppReferenceSubInterface(Copy->SourceSubInterface);
        Copy->IsSourceReferenced = TRUE;
    }

    if (Copy->NextHop != NULL) {
        IppReferenceNextHop(Copy->NextHop);
        Copy->IsNextHopReferenced = TRUE;
    }

    return Copy;
}


VOID
IppParseHeaderIntoPacket(
    PIP_PROTOCOL Protocol,
    PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    Parses header fields in a packet, setting packet pointers appropriately.
    The given packet must have a valid, contiguous header.

Arguments:

    Protocol - Supplies the network layer protocol's state.

    Packet - Supplies the packet to be parsed.

Return Value:

    None.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PNET_BUFFER NetBuffer;

    NetBuffer = Packet->NetBufferList->FirstNetBuffer;
    if (IS_IPV4_PROTOCOL(Protocol)) {
        PIPV4_HEADER Header;
        
        Header = NetioGetDataBufferSafe(NetBuffer, sizeof(IPV4_HEADER));
        ASSERT(Header != NULL);

        Packet->IP = (PUCHAR) Header;
        Packet->CurrentDestinationAddress = 
            (PUCHAR) &Header->DestinationAddress;
        Packet->SourceAddress.Address = (PUCHAR) &Header->SourceAddress;
    } else {
        PIPV6_HEADER Header;

        Header = NetioGetDataBufferSafe(NetBuffer, sizeof(IPV6_HEADER));
        ASSERT(Header != NULL);
        
        Packet->IP = (PUCHAR) Header;
        Packet->CurrentDestinationAddress = 
            (PUCHAR) &Header->DestinationAddress;
        Packet->SourceAddress.Address = (PUCHAR) &Header->SourceAddress;
    }
}


NETIO_INLINE
VOID
IppFreePacket(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
{    
    if (Packet->IsNextHopReferenced) {
        IppDereferenceNextHop(Packet->NextHop);
    }

    if (Packet->IsPathReferenced) {
        IppDereferencePath(Packet->Path);
    }

    if (Packet->IsOriginLocal) {
        if (Packet->IsSourceReferenced) {
            IppDereferenceLocalUnicastAddress(Packet->SourceLocalAddress);
        }
    } else {
        if (Packet->IsSourceReferenced) {
            IppDereferenceSubInterface(Packet->SourceSubInterface);
        }
    }

    if (Packet->IsAllocated) {
        FsbFree((PUCHAR)Packet);
    }
}
    
PIP_REQUEST_CONTROL_DATA
IppPendPacket(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    This routine creates a packet that is suitable for pending.  In case the
    input packet has not been allocated, this routine allocates a new packet
    and copies the contents and references over.  If the input packet does not
    have a reference on the path/source address, a reference is added.
    In case of allocation failure, the routine returns NULL, and the caller
    must clean-up the original packet.  In case of success the caller only has
    to free the returned packet, not the packet supplied.  

Arguments:

    Packet - Supplies the packet. 

Return Value:

    Returns the packet to pend or NULL on allocation failure.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    PIP_REQUEST_CONTROL_DATA Copy;
    
    if (!Packet->IsAllocated) {
        //
        // The input packet was not allocated.
        // Allocate a new packet and copy the contents over. 
        //
        Copy = (PIP_REQUEST_CONTROL_DATA)
            FsbAllocate(Packet->Compartment->Protocol->ControlPool);
        if (Copy == NULL) {
            //
            // Allocation failure.
            //
            return NULL;
        }
    
        RtlCopyMemory(Copy, Packet, sizeof(*Packet));

        if (Packet->CurrentDestinationAddress ==
            Packet->FinalDestinationAddress.Buffer) {
            Copy->CurrentDestinationAddress =
                Copy->FinalDestinationAddress.Buffer;
        }
        
        Packet = Copy;
        Packet->IsAllocated = TRUE;
        Packet->Next = NULL;
    }

    
    //
    // We have a packet that is allocated.  All the references in the old
    // packet have been transferred to the new.  Add any new references that
    // are needed.  Note that the original packet does not need to be
    // cleaned up since all the reference have been transferred. Also, it was
    // not allocated, so it does not need to be freed. 
    //
    if (Packet->IsOriginLocal) {
        if (Packet->Path != NULL) {
            if (!Packet->IsPathReferenced) {
                IppReferencePath(Packet->Path);
                Packet->IsPathReferenced = TRUE;
            }
            ASSERT((Packet->SourceLocalAddress == NULL) ||
                   (Packet->SourceLocalAddress == Packet->Path->SourceAddress));
        } else if ((Packet->SourceLocalAddress != NULL) &&
                   (!Packet->IsSourceReferenced)) {
            IppReferenceLocalUnicastAddress(Packet->SourceLocalAddress);
            Packet->IsSourceReferenced = TRUE;
        }
    } else {
        ASSERT(Packet->Path == NULL);

        if ((Packet->SourceSubInterface != NULL) &&
            (!Packet->IsSourceReferenced)) {
            IppReferenceSubInterface(Packet->SourceSubInterface);
            Packet->IsSourceReferenced = TRUE;
        }
    }

    if ((Packet->NextHop != NULL) &&
        (!Packet->IsNextHopReferenced)) {
        IppReferenceNextHop(Packet->NextHop);
        Packet->IsNextHopReferenced = TRUE;
    }

    return Packet;
}

PIP_REQUEST_CONTROL_DATA
IppStrongPendPacket(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    This routine creates a packet that is suitable for pending.  It has the
    same behavior as IppPendPacket, but in addition does a deep copy of
    Packet->NetBufferList.

Arguments:

    Packet - Supplies the packet.

Return Value:

    Returns the packet to pend or NULL on allocation failure.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
   PNET_BUFFER_LIST NewNetBufferList, NetBufferList;
   PIP_REQUEST_CONTROL_DATA NewPacket;

   NetBufferList = Packet->NetBufferList;
   ASSERT(NetBufferList->Status == STATUS_SUCCESS);

   //
   // We should be called on the send side, where NL supports a single 
   // NetBufferList per send from the NL client.
   //
   ASSERT(NetBufferList->Next == NULL);

   NewNetBufferList = 
     NetioAllocateAndReferenceVacantNetBufferList(
         NetBufferList,
         0,
         0,
         FALSE,
         TRUE, //Copy data from original to new.
         FALSE);
   if (NewNetBufferList == NULL) {
      return NULL;
   }

   //
   // Create a pended control structure.
   //
   NewPacket = IppPendPacket(Packet);
   if (NewPacket == NULL) {
      //
      // Call failed, so cleanup the NBL copy.
      //
      NetioDereferenceNetBufferList(NewNetBufferList, FALSE);
      return NULL;
   }

   // Copy the NBL context info
   IppCopyNetBufferListInfo(NewNetBufferList, NetBufferList);    

   //
   // Replace the NetBufferList in the NewPacket with the copy & deref the old
   // NetBufferList, as it is not needed anymore.
   //
   NewPacket->NetBufferList = NewNetBufferList;
   NetioDereferenceNetBufferList(NetBufferList, FALSE);

   return NewPacket;
}

PIP_REQUEST_CONTROL_DATA
IppStrongCopyPacket(
    IN PIP_REQUEST_CONTROL_DATA Packet
    )
/*++

Routine Description:

    This routine creates deep copy of a packet.  It has the same behavior as 
    IppCopyPacket, but in addition does a deep copy of Packet->NetBufferList.

Arguments:

    Packet - Supplies the packet.

Return Value:

    Returns the packet copy or NULL on allocation failure.

Caller LOCK:
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
   PNET_BUFFER_LIST NewNetBufferList, NetBufferList;
   PIP_REQUEST_CONTROL_DATA NewPacket;
   NTSTATUS Status;

   NetBufferList = Packet->NetBufferList;
   ASSERT(NetBufferList->Status == STATUS_SUCCESS);

   //
   // We should be called on the send side, where NL supports a single 
   // NetBufferList per send from the NL client.
   //
   ASSERT(NetBufferList->Next == NULL);

   NewNetBufferList = 
     NetioAllocateAndReferenceVacantNetBufferList(
         NetBufferList,
         0,
         0,
         FALSE,
         TRUE, //Copy data from original to new.
         FALSE);
   if (NewNetBufferList == NULL) {
      return NULL;
   }

   //
   // Create a copy of control structure.
   //
   NewPacket = IppCopyPacket(Packet->Compartment->Protocol, Packet);
   if (NewPacket == NULL) {
      //
      // Call failed, so cleanup the NBL copy.
      //
      NetioDereferenceNetBufferList(NewNetBufferList, FALSE);
      return NULL;
   }

   //
   // Copy the send specific pointers
   //
   Status = IppCopySendState(Packet, NewPacket);
   if(!NT_SUCCESS(Status)){
      //
      // Call failed, so cleanup the NBL copy & Packet control copy.
      //
      NetioDereferenceNetBufferList(NewNetBufferList, FALSE);
      IppCleanupSendState(NewPacket, FALSE);
      IppFreePacket(NewPacket);
      return NULL;
   }

   // Copy the NBL context info
   IppCopyNetBufferListInfo(NewNetBufferList, NetBufferList);

   //
   // Replace the NetBufferList in the NewPacket with the copy.
   //
   NewPacket->NetBufferList = NewNetBufferList;

   return NewPacket;
}
    
VOID
IppFreePacketList(
    IN PIP_REQUEST_CONTROL_DATA PacketList
    )
/*++

Routine Description:

    Takes a list of packet data structures and frees each one.

Arguments:

    PacketList - Supplies a list of packet data structures.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_REQUEST_CONTROL_DATA Packet;
    
    for (Packet = PacketList; Packet != NULL; Packet = PacketList) {
        PacketList = Packet->Next;
        
        IppFreePacket(Packet);
    }
}

VOID
IppCompleteAndFreePacketList(
    IN PIP_REQUEST_CONTROL_DATA PacketList,
    IN BOOLEAN DispatchLevel
    )
/*++

Routine Description:

    Takes a list of packet data structures and frees each one and also
    completes the net buffer list in each of them.

Arguments:

    PacketList - Supplies a list of packet data structures.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_REQUEST_CONTROL_DATA Packet;
    PNET_BUFFER_LIST NetBufferList, Batch, *TailNextPointer;

    Batch = NULL;
    TailNextPointer = &Batch;
    
    for (Packet = PacketList; Packet != NULL; Packet = PacketList) {
        PacketList = Packet->Next;

        NetBufferList = Packet->NetBufferList;
        if (NetBufferList != NULL) {
            ASSERT(NetBufferList->Next == NULL);
            *TailNextPointer = NetBufferList;
            TailNextPointer = &NetBufferList->Next;
        }

        IppFreePacket(Packet);
    }

    if (Batch != NULL) {
        NetioDereferenceNetBufferListChain(Batch, DispatchLevel);
    }
}

VOID
IppClearInboundSecurityContext(
    IN PIP_REQUEST_CONTROL_DATA PacketList
    )
/*++

Routine Description:

    Takes a list of packet data structures on receive and frees security 
    context on each of them.

Arguments:

    PacketList - Supplies a list of packet data structures.

Caller IRQL:

    May be called at PASSIVE through DISPATCH level.

--*/
{
    PIP_REQUEST_CONTROL_DATA Packet;
    
    for (Packet = PacketList; Packet != NULL; Packet = PacketList) {
        PacketList = Packet->Next;
        
        if (Packet->NetBufferList) {
            IpSecCleanupInboundPacketStateGuarded(Packet->NetBufferList);
        }  
    }
}

NTSTATUS
IppNetAllocate(
    OUT PNET_BUFFER_LIST *NetBufferList,
    OUT PUCHAR *FlatBuffer,
    IN ULONG Offset,
    IN ULONG Length
    )
/*++

Routine Description:

    Allocate a NetBufferList (including NetBuffer, MDL, and Buffer) to describe
    a packet of the specified Offset + Length.  Set the NetBuffer's DataOffset
    to the specified value and return the resulting pointer within the Buffer.

Arguments:

    NetBufferList - Returns the allocated NetBufferList.
        This includes a NetBuffer, an MDL, and a Buffer.

    FlatBuffer - Returns a pointer within the Buffer at the specified offset.
        This is NULL upon failure or if Length is 0.
        Use the return value to distinguish between the two cases.
        
    Offset - Supplies the required offset within the allocated Buffer.
    
    Length - Supplies the length of the allocated buffer, starting from Offset.

Return Value:

    Returns STATUS_SUCCESS on success or some NTSTATUS error code otherwise.
    
Caller IRQL: <= DISPATCH_LEVEL.

--*/ 
{
    NTSTATUS Status;

    *FlatBuffer = NULL;
    
    *NetBufferList =
        NetioAllocateAndReferenceNetBufferAndNetBufferList(
            NetioCompleteNetBufferAndNetBufferListChain,
            NULL, 
            NULL, 
            0, 
            0,
            FALSE);
    if (*NetBufferList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = NetioRetreatNetBufferList(*NetBufferList, Length, Offset);
    if (!NT_SUCCESS(Status)) {
        NetioDereferenceNetBufferList(*NetBufferList, FALSE);
        *NetBufferList = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    *FlatBuffer =
        NetioGetDataBuffer(
            (*NetBufferList)->FirstNetBuffer, 
            Length, 
            NULL, 
            1, 
            0);
    ASSERT((*FlatBuffer != NULL) || (Length == 0));
    
    return STATUS_SUCCESS;
}


#define IPP_MAX_AVERAGE_HASH_CHAIN_LENGTH   3
#define IPP_MAX_EMPTY_BUCKET_PERCENTAGE     25

VOID
IppRestructureHashTableUnderLock(
    PRTL_HASH_TABLE HashTable
    )
/*++

Routine Description:

    Restructures dynamic-hash-table periodically when called from a timeout 
    routine.

    The restructuring aims to achieve two conflicting goals:
    1. The average number of entries in a non-empty bucket should
       not exceed a threshold. This threshold is defined above
       (IPP_MAX_AVERAGE_HASH_CHAIN_LENGTH).

    2. No more than a certain percentage of the total buckets 
       in the hash-table should be empty. This percentage is
       defined above (IPP_MAX_EMPTY_BUCKET_PERCENTAGE).

    As the hash-table expands, the average chain length in the
    table reduces, but the number of empty buckets will tend 
    to increase.

    As long as the hash-function is reasonably good (it distributes
    entropy more or less uniformly among all the 32-bits of the
    Key), both these goals can be met.

Arguments:

    HashTable - Pointer to the PathSet table in the compartment.

Return Value:

    None.

Caller LOCK: Lock for the hash table (Exclusive).
Caller IRQL: DISPATCH_LEVEL (since a lock is held).

--*/
{
    ULONG EmptyBuckets, NonEmptyBuckets, NumEntries, TableSize;

    DISPATCH_CODE();

    NumEntries = RtlTotalEntriesHashTable(HashTable);
    TableSize = RtlTotalBucketsHashTable(HashTable);
    NonEmptyBuckets = RtlNonEmptyBucketsHashTable(HashTable);
    EmptyBuckets = RtlEmptyBucketsHashTable(HashTable);

    if (NumEntries > 
        (IPP_MAX_AVERAGE_HASH_CHAIN_LENGTH * NonEmptyBuckets)) {

        do {
            if (RtlExpandHashTable(HashTable) == FALSE) {
                break;
            }

            NonEmptyBuckets = RtlNonEmptyBucketsHashTable(HashTable);
            EmptyBuckets = RtlEmptyBucketsHashTable(HashTable);
            NumEntries = RtlTotalEntriesHashTable(HashTable);
            TableSize = RtlTotalBucketsHashTable(HashTable);
        } while (NumEntries > 
                 IPP_MAX_AVERAGE_HASH_CHAIN_LENGTH * NonEmptyBuckets);

    } else 
    if (EmptyBuckets >
        (IPP_MAX_EMPTY_BUCKET_PERCENTAGE * TableSize / 100)) {

        do {
            if (RtlContractHashTable(HashTable) == FALSE) {
                break;
            }

            NonEmptyBuckets = RtlNonEmptyBucketsHashTable(HashTable);
            EmptyBuckets = RtlEmptyBucketsHashTable(HashTable);
            NumEntries = RtlTotalEntriesHashTable(HashTable);
            TableSize = RtlTotalBucketsHashTable(HashTable);
        } while (EmptyBuckets >
                 (IPP_MAX_EMPTY_BUCKET_PERCENTAGE * TableSize / 100));
    }
}

ULONG
IppDefaultMemoryLimit(
    VOID
    )
/*++

Routine Description:
    
    Computes the default memory limit for buffers, based on the amount of physical memory in
    the system. The maximum size is limited to 1/128th of the physical memory.
    
Arguments:

    None.
    
Return Value:

    Memory limit, in bytes, for buffers.
    
--*/
{
    SYSTEM_BASIC_INFORMATION Info;
    NTSTATUS Status;

    Status = ZwQuerySystemInformation(SystemBasicInformation,
                                      &Info,
                                      sizeof(Info),
                                      NULL);
    if (!NT_SUCCESS(Status)) {
        //
        // If this failed, then we're probably really resource constrained,
        // so use only 256K.
        //
        return (256 * 1024);
    }

    //
    // By default, limit the buffers to a maximum size equal
    // to 1/128th of the physical memory.  On a machine with only 128M of
    // memory, this is 1M of memory maximum.    
    // For reassemble buffers this is enough to reassemble
    // 16 64K packets, or 128 8K packets, for example. (In contrast,
    // the XP IPv4 stack currently allows reassembling a fixed maximum of
    // 100 packets, regardless of packet size or available memory.)
    //
    return (ULONG)(Info.NumberOfPhysicalPages * (Info.PageSize / 128));
}

BOOLEAN
IppInitSharedHashContext(
    VOID
    )
{
    g_37HashSeed = (UINT32)RandomNumber(1, ULONG_MAX);
    return TRUE;
}

VOID
IppCleanupSharedHashContext(
    VOID
    )
{
    return;
}


