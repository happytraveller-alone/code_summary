/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    init.c

Abstract:

    This module contains the initialization code for ipng.sys.

Author:

    Dave Thaler (dthaler) 3-Oct-2000

Environment:

    kernel mode only

--*/

#include "precomp.h"
#include "init.tmh"

BOOLEAN IppIsServerSKU = FALSE;
LONG IpngpReferenceCount;
KEVENT IpngpAllowUnloadEvent;
PDEVICE_OBJECT IppDeviceObject;
KTIMER IppNotificationTimer;

CONST NL_PROVIDER_DISPATCH IpNlProviderDispatch = {
    0, sizeof(NL_PROVIDER_DISPATCH),

    IpNlpChecksumDatagram,
    IpNlpSendDatagrams,
    IpNlpFastSendDatagram,
    IpNlpCancelSendDatagrams,
    IpNlpGenerateIcmpMessage,

    IpNlpQueryAncillaryData,
    IpNlpFilterDatagramBySessionInformation,
    IpNlpFilterIndicationBySessionInformation,

    IpNlpJoinPath,
    IpNlpLeavePath,
    IpNlpQueryPathInfomation,
    IpNlpSetPathInfo,
    IpNlpInitiatePathOffload,
    IpNlpTerminatePathOffload,
    IpNlpUpdatePathOffload,
    IpNlpSuspectNeighborReachability,
    IpNlpSuspectPathReachability, 
    IpNlpConfirmForwardReachability, 

    IpNlpReferenceNextHop, 
    IpNlpDereferenceNextHop,

    IpNlpReferenceLocalAddress,
    IpNlpDereferenceLocalAddress,
    IpNlpValidateLocalAddress,

    IpNlpQueryInterface,
    NULL,
    IpNlpQueryInterfaceProperty,
    IpNlpSetInterfaceProperty,
    IpNlpReferenceInterface,
    IpNlpDereferenceInterface,
    
    IpNlpReferenceCompartment,
    IpNlpDereferenceCompartment,
    
    IpNlpInitializeSessionInfo,
    IpNlpQuerySessionInfo,
    IpNlpSetSessionInfo,
    IpNlpCleanupSessionInfo,
    IpNlpInheritSessionInfo,
    NULL,
    IpNlpGetNextHopFromPath,
};

typedef struct _DEVICE_OBJECT_DISPATCH_ENTRY {
   PDEVICE_OBJECT DeviceObject;
   PDRIVER_DISPATCH DeviceControlDispatchFunction;
} DEVICE_OBJECT_DISPATCH_ENTRY;

#define MAX_DISPATCH_ENTRIES 4

#define NETIO_DISPATCH_IPSEC 0
#define NETIO_DISPATCH_KFD 1
#define NETIO_DISPATCH_ALE 2
#define NETIO_DISPATCH_EQOS 3

DEVICE_OBJECT_DISPATCH_ENTRY IoctlDispatchTable[MAX_DISPATCH_ENTRIES];


//
// Internal Next Header Processor functions
//
VOID
IppInsertNlClientReceiveContext(
    IN PIP_CLIENT_CONTEXT NlClient
    );

VOID
IppRemoveNlClientReceiveContext(
    IN PIP_CLIENT_CONTEXT NlClient
    );


VOID
FASTCALL
IpngpReferenceDriver(
    VOID
    )
{
    InterlockedIncrement(&IpngpReferenceCount);
}

VOID
FASTCALL
IpngpDereferenceDriver(
    VOID
    )
{
    LONG Value;

    Value = InterlockedDecrement(&IpngpReferenceCount);
    if (0 == Value) {
        KeSetEvent(&IpngpAllowUnloadEvent, 0, FALSE);
    }
}

__inline
VOID
IpngpInitializeAllowUnloadEvent(
    VOID
    )
{
    KeInitializeEvent(&IpngpAllowUnloadEvent, NotificationEvent, FALSE);
}

__inline
NTSTATUS
IpngpWaitForAllowUnloadEvent(
    VOID
    )
{
    NTSTATUS Status;

    Status =
        KeWaitForSingleObject(
            &IpngpAllowUnloadEvent,
            UserRequest,
            KernelMode,
            FALSE,
            NULL);

    KeUninitializeEvent(&IpngpAllowUnloadEvent);

    return Status;
}

NTSTATUS
NlStartup(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT DeviceObject,
    IN PUNICODE_STRING RegistryPath
    );

VOID
NlCleanup(
    IN PDRIVER_OBJECT DriverObject
    );

NTSTATUS
IppStartModules(
    IN CONST NL_MODULE *Modules,
    IN ULONG ModuleCount,
    OUT ULONG *ModuleStatus,
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopModules(
    IN CONST NL_MODULE *Modules, 
    IN ULONG ModuleCount, 
    IN ULONG ModuleStatus, 
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupModules(
    IN CONST NL_MODULE *Modules, 
    IN ULONG ModuleCount, 
    IN ULONG ModuleStatus, 
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStartProtocolManager(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppStopProtocolManager(
    IN PIP_PROTOCOL Protocol
    );

NTSTATUS
IppWaitProtocolManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupProtocolManager(
    IN PIP_PROTOCOL Protocol
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, NlStartup)
#pragma alloc_text(INIT, IppStartModules)
#pragma alloc_text(PAGE, NlCleanup)
#pragma alloc_text(PAGE, IppStopModules)
#pragma alloc_text(PAGE, IppCleanupModules)
#endif

CONST NL_MODULE IpModule[] = {
    {
        IMS_SESSION, 
        "IP Session", 
        IppStartSessionManager, 
        NULL, 
        NULL,
        IppCleanupSessionManager
    }, 
    {
        IMS_CONTROL_POOL, 
        "IP Control Data Pool", 
        IppStartControlPoolManager, 
        NULL, 
        NULL,
        IppCleanupControlPoolManager
    },
    {
        IMS_PROTOCOLS,
        "IP Protocol Manager",
        IppStartProtocolManager,
        IppStopProtocolManager,
        IppWaitProtocolManager,
        IppCleanupProtocolManager
    },
    {
        IMS_TIMER,
        "IP Timer",
        IppStartTimerManager,
        NULL,
        NULL,
        IppCleanupTimerManager
    }
};

ULONG IpModuleStatus = 0;

NTSTATUS
IppStartModules(
    IN CONST NL_MODULE *Modules, 
    IN ULONG ModuleCount, 
    OUT ULONG *ModuleStatus, 
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;
    ULONG i;

    *ModuleStatus = 0;

    //
    // Initialize each sub-module.
    //
    for (i = 0; i < ModuleCount; i++) {
        Status = Modules[i].StartFcn(Protocol);
        if (!NT_SUCCESS(Status)) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                       "IPNG: Error starting %s module (0x%x)\n", 
                       Modules[i].ModuleString, Status);
            return Status;
        } else {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                       "IPNG: Started %s module\n", 
                       Modules[i].ModuleString);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IppStopModules(
    IN CONST NL_MODULE *Modules, 
    IN ULONG ModuleCount, 
    IN ULONG ModuleStatus, 
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG PendingCount = 0;
    LONG i;

    for (i = ModuleCount - 1; i >= 0; i--) {
        if (ModuleStatus & Modules[i].Bit) {
            if (Modules[i].StopFcn == NULL) {
                Status = STATUS_PENDING;
            } else {
                Status = Modules[i].StopFcn(Protocol);
                ASSERT(NT_SUCCESS(Status) || (Status == STATUS_PENDING));
            }
            if (Status == STATUS_PENDING) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                           "IPNG: Stopping %s module is pending\n", 
                           Modules[i].ModuleString);
                PendingCount++;
            } else if (NT_SUCCESS(Status)) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                           "IPNG: Stopped %s module\n", 
                           Modules[i].ModuleString);
            } else {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                           "IPNG: Error stopping %s module (0x%x)\n", 
                           Modules[i].ModuleString, Status);
            }
        } 
    }
    
    return (PendingCount > 0)? STATUS_PENDING : STATUS_SUCCESS;
}

NTSTATUS
IppWaitModules(
    IN CONST NL_MODULE *Modules, 
    IN ULONG ModuleCount, 
    IN ULONG ModuleStatus, 
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    LONG i;
    ULONG PendingCount = 0;

    for (i = ModuleCount - 1; i >= 0; i--) {
        if (ModuleStatus & Modules[i].Bit) {
            if (Modules[i].WaitFcn != NULL) {
                NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                           "IPNG: Wait %s module\n", 
                           Modules[i].ModuleString);
                Status = Modules[i].WaitFcn(Protocol);
                ASSERT(Status == STATUS_SUCCESS);
            }
        }
    }
    
    return (PendingCount > 0)? STATUS_PENDING : STATUS_SUCCESS;
}

VOID
IppCleanupModules(
    IN CONST NL_MODULE *Modules, 
    IN ULONG ModuleCount, 
    IN ULONG ModuleStatus, 
    IN PIP_PROTOCOL Protocol
    )
{
    LONG i;

    for (i = ModuleCount - 1; i >= 0; i--) {
        if (ModuleStatus & Modules[i].Bit) {
            NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
                       "IPNG: Cleaning up %s module\n", 
                       Modules[i].ModuleString);
            if (Modules[i].CleanupFcn != NULL) {
                Modules[i].CleanupFcn(Protocol);
            }
        }
    }
}

NTSTATUS
IppStartProtocolManager(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;
    BOOLEAN Installed = (BOOLEAN) -1;
    RTL_OSVERSIONINFOEXW OsVersionInfoExW;
    
    UNREFERENCED_PARAMETER(Protocol);
    ASSERT(Protocol == NULL);

    RtlZeroMemory(&OsVersionInfoExW, sizeof(OsVersionInfoExW));
    OsVersionInfoExW.dwOSVersionInfoSize = sizeof(OsVersionInfoExW);
    Status = RtlGetVersion((PRTL_OSVERSIONINFOW) &OsVersionInfoExW);

    //
    // REVIEW: Trace a failure.
    //
    if (NT_SUCCESS(Status) &&
        OsVersionInfoExW.wProductType != VER_NT_WORKSTATION) {
        IppIsServerSKU = TRUE;
    }

    IppDefaultMemoryLimitOfBuffers = IppDefaultMemoryLimit();
        
    //
    // IPv4 may be (un)installed by setting NL_GLOBAL_RW::Installed.
    // We perturb the default value only when NSI returns success.
    //
    (VOID)
        NsiGetParameter(
            NsiPersistent,
            Ipv4Global.ModuleId,
            NlGlobalObject,
            NULL, 0,
            NsiStructRw,
            &Installed,
            RTL_FIELD_SIZE(NL_GLOBAL_RW, Installed),
            FIELD_OFFSET(NL_GLOBAL_RW, Installed));
    if (Installed != (BOOLEAN) -1) {
        Ipv4Global.Installed = !!Installed;
    }
    
    if (Ipv4Global.Installed) {
        Status = 
            IppStartModules(
                Ipv4Global.Modules, 
                Ipv4Global.ModuleCount,
                &Ipv4Global.ModuleStatus, 
                &Ipv4Global);

        if (!NT_SUCCESS(Status)) {
            goto Bail;
        }
        IppInitializeProtocolSettings(&Ipv4Global);
    } else {
        PIO_ERROR_LOG_PACKET ErrorLogEntry;
        
        //
        // Log an error.
        //
        ErrorLogEntry =
            IoAllocateErrorLogEntry(
                IppDeviceObject,
                sizeof(IO_ERROR_LOG_PACKET));
        if (ErrorLogEntry != NULL) {
            ErrorLogEntry->ErrorCode = EVENT_TCPIP_IPV4_UNINSTALLED;
            IoWriteErrorLogEntry(ErrorLogEntry);
        }
    }

    //
    // No IPv4 components can be disabled at the moment.
    //
    ASSERT(Ipv4Global.DisabledComponents.Flags == 0);
    
    //
    // IPv6 must always be installed.  Hence we ignore NL_GLOBAL_RW::Installed.
    //
    ASSERT(Ipv6Global.Installed);

    //
    // Certain IPv6 components may be disabled by setting this registry key.
    //
    IppRegQueryDwordValue(
        TCPIP6_PARAMETERS_KEY_KERNEL,
        DISABLED_COMPONENTS_VALUE_NAME,
        &Ipv6Global.DisabledComponents.Flags);
    
    Status = 
        IppStartModules(
            Ipv6Global.Modules, 
            Ipv6Global.ModuleCount,
            &Ipv6Global.ModuleStatus, 
            &Ipv6Global);

    if (!NT_SUCCESS(Status)) {
        goto Bail;
    }

    IppInitializeProtocolSettings(&Ipv6Global);

    InterlockedExchangeAdd(&IpModuleStatus, IMS_PROTOCOLS);

Bail:
    if (!NT_SUCCESS(Status)) {
        IppStopProtocolManager(NULL);
        IppWaitProtocolManager(NULL);
        IppCleanupProtocolManager(NULL);
    }

    return Status;
}

NTSTATUS
IppStopProtocolManager(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Ipv4Status, Ipv6Status;

    UNREFERENCED_PARAMETER(Protocol);
    ASSERT(Protocol == NULL);

    //
    // Stop can be invoked even if a module wasn't started.
    //
    Ipv4Status = 
        IppStopModules(
            Ipv4Global.Modules, 
            Ipv4Global.ModuleCount,
            Ipv4Global.ModuleStatus, 
            &Ipv4Global);

    Ipv6Status = 
        IppStopModules(
            Ipv6Global.Modules, 
            Ipv6Global.ModuleCount,
            Ipv6Global.ModuleStatus, 
            &Ipv6Global);
    
    if (Ipv4Status == STATUS_PENDING) {
        return STATUS_PENDING;
    }
    ASSERT(Ipv4Status == STATUS_SUCCESS);

    if (Ipv6Status == STATUS_PENDING) {
        return STATUS_PENDING;
    }
    ASSERT(Ipv6Status == STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

NTSTATUS
IppWaitProtocolManager(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Ipv4Status, Ipv6Status;

    UNREFERENCED_PARAMETER(Protocol);
    ASSERT(Protocol == NULL);

    Ipv4Status = 
        IppWaitModules(
            Ipv4Global.Modules, 
            Ipv4Global.ModuleCount,
            Ipv4Global.ModuleStatus, 
            &Ipv4Global);

    Ipv6Status = 
        IppWaitModules(
            Ipv6Global.Modules, 
            Ipv6Global.ModuleCount,
            Ipv6Global.ModuleStatus, 
            &Ipv6Global);


    ASSERT(Ipv4Status == STATUS_SUCCESS);


    ASSERT(Ipv6Status == STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

VOID
IppCleanupProtocolManager(
    IN PIP_PROTOCOL Protocol
    )
{
    UNREFERENCED_PARAMETER(Protocol);
    ASSERT(Protocol == NULL);

    //
    // Cleanup can be invoked even if a module wasn't started.
    //
    IppCleanupModules(
        Ipv4Global.Modules, 
        Ipv4Global.ModuleCount,
        Ipv4Global.ModuleStatus, 
        &Ipv4Global);

    IppCleanupModules(
        Ipv6Global.Modules, 
        Ipv6Global.ModuleCount,
        Ipv6Global.ModuleStatus, 
        &Ipv6Global);
}

VOID NlCompleteIrp(
    IN NTSTATUS Status,
    IN DWORD NumBytes,
    IN OUT PIRP Irp
    )
{
#ifndef USER_MODE
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = NumBytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
#else
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(NumBytes);
    UNREFERENCED_PARAMETER(Irp);
#endif
}


NTSTATUS
NlDispatchDeviceControl(
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp
   )
{
    int i;

    for (i=0; i < MAX_DISPATCH_ENTRIES; i++) {
        if (DeviceObject == IoctlDispatchTable[i].DeviceObject) {
            return IoctlDispatchTable[i].
                DeviceControlDispatchFunction(DeviceObject, Irp);
        }
    }
    ASSERT(0);

    NlCompleteIrp(STATUS_UNSUCCESSFUL, 0, Irp);
    return STATUS_UNSUCCESSFUL;

}

NTSTATUS
NlDispatchInternalDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
   )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NlCompleteIrp(STATUS_SUCCESS, 0, Irp);
    return (STATUS_SUCCESS);
}

NTSTATUS
NlDispatchCreate(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
   )
{
    UNREFERENCED_PARAMETER(DeviceObject);   

    NlCompleteIrp(STATUS_SUCCESS, 0, Irp);
    return (STATUS_SUCCESS);
}

NTSTATUS
NlDispatchClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
   )
{
    UNREFERENCED_PARAMETER(DeviceObject);   

    NlCompleteIrp(STATUS_SUCCESS, 0, Irp);
    return (STATUS_SUCCESS);
}

NTSTATUS
NlDispatchCleanup(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
   )
{
    UNREFERENCED_PARAMETER(DeviceObject);   

    NlCompleteIrp(STATUS_SUCCESS, 0, Irp);
    return (STATUS_SUCCESS);
}




NTSTATUS
NlStartup(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT DeviceObject,
    IN PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
        
    UNREFERENCED_PARAMETER(RegistryPath);

    IpngpReferenceDriver();

#if COMPARTMENT_REFHIST
    IppCompartmentReferenceHistory = RhAllocateHistory(NonPagedPool, 1024);
#endif
#if INTERFACE_REFHIST
    IppInterfaceReferenceHistory = RhAllocateHistory(NonPagedPool, 10240);
    IppSubInterfaceReferenceHistory = RhAllocateHistory(NonPagedPool, 1024);
#endif
#if PATH_REFHIST
    IppPathReferenceHistory = RhAllocateHistory(NonPagedPool, 10240);
#endif
#if NEIGHBOR_REFHIST
    IppNeighborReferenceHistory = RhAllocateHistory(NonPagedPool, 1024);
#endif
#if ADDRESS_REFHIST
    IppAddressReferenceHistory = RhAllocateHistory(NonPagedPool, 1024);
#endif
#if ECHO_REFHIST
    IppEchoRequestReferenceHistory = RhAllocateHistory(NonPagedPool, 100);
#endif  
#if MFE_REFHIST
    IppMfeReferenceHistory = RhAllocateHistory(NonPagedPool, 1024);
#endif

    IppDeviceObject = DeviceObject;

#ifndef USER_MODE
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NlDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NlDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = NlDispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
        NlDispatchInternalDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        NlDispatchDeviceControl;
#endif

    
    //
    // Start all modules in this driver
    //
    Status =
        IpSecEntry(
            DriverObject,
            &IoctlDispatchTable[NETIO_DISPATCH_IPSEC].
            DeviceObject,
            &IoctlDispatchTable[NETIO_DISPATCH_IPSEC].
            DeviceControlDispatchFunction);
    if (!NT_SUCCESS(Status)) {
       NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                  "IPNG: Error loading driver : "
                  "IPSEC initialization failed (0x%x)\n", 
                  Status);
       return Status;
    }
    
    Status =
        KfdDriverEntry(
            DriverObject,
            &IoctlDispatchTable[NETIO_DISPATCH_KFD].
            DeviceObject,
            &IoctlDispatchTable[NETIO_DISPATCH_KFD].
            DeviceControlDispatchFunction);
    if (!NT_SUCCESS(Status)) {
      NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                 "IPNG: Error loading driver : "
                 "Kfd initialization failed (0x%x)\n", 
                 Status);
       return Status;
    }   

    Status =
        WfpAleInitializeIo(
            DriverObject,
            &IoctlDispatchTable[NETIO_DISPATCH_ALE].
            DeviceObject,
            &IoctlDispatchTable[NETIO_DISPATCH_ALE].
            DeviceControlDispatchFunction);
    if (!NT_SUCCESS(Status)) {
      NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                 "IPNG: Error loading driver : "
                 "ALE initialization failed (0x%x)\n", 
                 Status);
       return Status;
    }   

#ifndef USER_MODE

    //
    // Initialize EQoS device IO. Note that there is no 
    // EQoS "simulation" in user mode.
    //
    
    Status =         
        EQoSInitializeDeviceIO(
            DriverObject,
            &IoctlDispatchTable[NETIO_DISPATCH_EQOS].\
            DeviceObject,
            &IoctlDispatchTable[NETIO_DISPATCH_EQOS].\
            DeviceControlDispatchFunction
            );
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                   "IPNG: Error loading driver : "
                   "EQoS initialization failed (0x%x)\n", 
                   Status);
        goto Error;
    }   

    Status = 
        TcpChimneyInit();
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
                 "IPNG: Error loading driver : "
                 "TCP Chimney initialization failed (0x%x)\n", 
                 Status);
        goto Error;
    }   
#endif 

    //
    // Initialize our random number generator.
    //
    IppSeedRandom();

    if(!IppInitSharedHashContext()) {
        goto Error;
    }

    Status =
        IppStartModules(
            IpModule, 
            RTL_NUMBER_OF(IpModule), 
            &IpModuleStatus, 
            NULL);

    if (!NT_SUCCESS(Status)) {
        goto Error;
    }


    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: Driver loaded successfully\n");

    return STATUS_SUCCESS;

Error:
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_ERROR,
               "IPNG: Error loading driver (0x%x)\n", Status);

    NlCleanup(DriverObject);
    return Status;
}

VOID
NlCleanup(
    IN PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS Status;

    IpngpInitializeAllowUnloadEvent();
    IpngpDereferenceDriver();

    //
    // Unload all modules in this driver
    //
    Status = 
        IppStopModules(
            IpModule, 
            RTL_NUMBER_OF(IpModule), 
            IpModuleStatus, 
            NULL);

    //
    // Wait for stop to complete.
    //
    Status = IppWaitModules(
        IpModule,
        RTL_NUMBER_OF(IpModule),
        IpModuleStatus,
        NULL);
    Status = IpngpWaitForAllowUnloadEvent();

    IppCleanupModules(IpModule, 
                      RTL_NUMBER_OF(IpModule), 
                      IpModuleStatus, 
                      NULL);

#if COMPARTMENT_REFHIST
    if (IppCompartmentReferenceHistory != NULL) {
        RhFreeHistory(IppCompartmentReferenceHistory);
    }
#endif
#if INTERFACE_REFHIST
    if (IppInterfaceReferenceHistory != NULL) {
        RhFreeHistory(IppInterfaceReferenceHistory);
    }
    if (IppSubInterfaceReferenceHistory != NULL) {
        RhFreeHistory(IppSubInterfaceReferenceHistory);
    }
#endif
#if PATH_REFHIST
    if (IppPathReferenceHistory != NULL) {
        RhFreeHistory(IppPathReferenceHistory);
    }
#endif
#if NEIGHBOR_REFHIST
    if (IppNeighborReferenceHistory != NULL) {
        RhFreeHistory(IppNeighborReferenceHistory);
    }
#endif
#if ADDRESS_REFHIST
    if (IppAddressReferenceHistory != NULL) {
        RhFreeHistory(IppAddressReferenceHistory);
    }
#endif
#if ECHO_REFHIST
    if (IppEchoRequestReferenceHistory != NULL) {
        RhFreeHistory(IppEchoRequestReferenceHistory);
    }
#endif
#if MFE_REFHIST
    if (IppMfeReferenceHistory != NULL) {
        RhFreeHistory(IppMfeReferenceHistory);
    }
#endif

#ifndef USER_MODE
    EQoSShutdownDeviceIO(IoctlDispatchTable[NETIO_DISPATCH_EQOS].DeviceObject);
    TcpChimneyShutdown();
#endif 

    WfpAleShutdownIo(IoctlDispatchTable[NETIO_DISPATCH_ALE].DeviceObject);

    IppCleanupSharedHashContext();

    IpSecUnload(DriverObject);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION, 
               "IPNG: Driver unloaded successfully\n");

}

NTSTATUS
IppStartLoopback(
    IN PIP_PROTOCOL Protocol
    )
{
    //
    // Initialize the loopback queue and lock. Packets 
    // destined for an address on the same machine are 
    // queued up so that the send and recv calls to the 
    // client do not happen in the same call stack.
    // 
    Protocol->LoopbackWorkItem = IoAllocateWorkItem(IppDeviceObject);
    if (Protocol->LoopbackWorkItem == NULL) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error allocating loopback work item for %s\n",
                   Protocol->TraceString);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IppInitializeGenericList(&Protocol->LoopbackQueue);
    KeInitializeSpinLock(&Protocol->LoopbackQueueLock);
    Protocol->IsLoopbackTransmitScheduled = FALSE;

    IppDefaultStartRoutine(Protocol, IMS_LOOPBACK_MANAGER);
    
    return STATUS_SUCCESS;
}

VOID
IppCleanupLoopback(
    IN PIP_PROTOCOL Protocol
    )
{ 
    KeUninitializeSpinLock(&Protocol->LoopbackQueueLock);
    IoFreeWorkItem(Protocol->LoopbackWorkItem);
}

//
// Framing layer client related routines. 
//
VOID
IpDeregisterFlClientComplete(
    IN PVOID  ClientContext
    )
{
    PIP_PROTOCOL Protocol = (PIP_PROTOCOL)ClientContext;

    IppDefaultStopRoutine(Protocol);
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: %s FL Client deregistration complete\n",
               Protocol->TraceString);
}

VOID
IppDetachFlProviderComplete(
    IN PLOCKED_LIST FlProviderSet,
    IN PFL_PROVIDER_CONTEXT FlProvider
    )
/*++

Routine Description:

    This function completes FL provider detach processing, once all
    operations using the FL provider have finished.

Arguments:

    FlProviderSet - Supplies a pointer to the set from which to remove
        an FL provider.

    FlProvider - Supplies a pointer to information about the FL provider
        from which to detach.

Return Value:

    None:

Called by:

    IppDereferenceFlProviderContext()

Locks:

    Assumes caller holds no locks.
    Locks provider set for writing.

--*/
{
    KLOCK_QUEUE_HANDLE LockHandle;

    RtlAcquireWriteLock(&FlProviderSet->Lock, &LockHandle);
    {
        RemoveEntryList(&FlProvider->Link);
        FlProviderSet->NumEntries--;
    }
    RtlReleaseWriteLock(&FlProviderSet->Lock, &LockHandle);

    NmrClientDetachProviderComplete(FlProvider->PendingDetachBindingHandle);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: %s FL Provider detach complete\n", 
               FlProvider->Protocol->TraceString);
}

VOID
FASTCALL
IppDereferenceFlProviderContext(
    IN PLOCKED_LIST FlProviderSet,
    IN PFL_PROVIDER_CONTEXT ProviderContext
    )

/*++

Routine Description:

    This function dereferences a FL provider, potentially completing
    detachment.

Arguments:

    FlProviderSet - Supplies a pointer to the set containing the FL provider.

    ProviderContext - Supplies a pointer to the FL provider context.

Return Value:

    None.

Called by:

    IpDetachFlProvider, IppFreeInterface.

Caller locks:

    Assumes caller holds no locks (due to Complete call).

--*/

{
    LONG Value;

    ASSERT(ProviderContext->ReferenceCount > 0);
    Value = InterlockedDecrement(&ProviderContext->ReferenceCount);
    if (0 == Value) {
        IppDetachFlProviderComplete(FlProviderSet, ProviderContext);
    }
}

VOID
IpDisableFlProviderContext(
    IN PFL_PROVIDER_CONTEXT FlProvider,
    IN HANDLE BindingHandle
    )
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PIP_PROTOCOL Protocol = FlProvider->Protocol;

    FlProvider->Detaching = TRUE;
    FlProvider->PendingDetachBindingHandle = BindingHandle;

    RtlAcquireWriteLock(&Protocol->FlProviderSet.Lock, &LockHandle);
    {
        RemoveEntryList(&FlProvider->Link);
        InsertHeadList(&Protocol->FlProviderDetachingList, &FlProvider->Link);
    }
    RtlReleaseWriteLock(&Protocol->FlProviderSet.Lock, &LockHandle);
}

NTSTATUS
NTAPI
IpDetachFlProvider(
    IN PVOID  ClientBindingContext
    )
{
    PFL_PROVIDER_CONTEXT ProviderContext =
        (PFL_PROVIDER_CONTEXT) ClientBindingContext;
    PIP_PROTOCOL Protocol = ProviderContext->Protocol;

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: %s FL Provider detach started\n", 
               Protocol->TraceString);

    //
    // Mark the provider context as disabled to prevent any new requests from
    // using the provider.
    //
    IpDisableFlProviderContext(
        ProviderContext, ProviderContext->NmrBindingHandle);
    IppDereferenceFlProviderContext(&Protocol->FlProviderSet, ProviderContext);

    return STATUS_PENDING;
}

VOID
NTAPI
IpCleanupFlProviderContext(
    IN PVOID  ClientBindingContext
    )
{
    PFL_PROVIDER_CONTEXT ProviderContext =
        (PFL_PROVIDER_CONTEXT) ClientBindingContext;
    
    FsbDestroyPool(ProviderContext->NeighborPool);
    ExFreePool(ProviderContext);
}

NTSTATUS
IppStartFlc(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    IppInitializeLockedList(&Protocol->FlProviderSet);
    InitializeListHead(&Protocol->FlProviderDetachingList);

    Status =
        NmrRegisterClient(
            &Protocol->FlClientNotify,
            Protocol,
            &Protocol->FlClientHandle);

    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error registering as an %s FL client (0x%x)\n",
                   Protocol->TraceString, Status);
        IppUninitializeLockedList(&Protocol->FlProviderSet);
        return Status;
    }

    IppDefaultStartRoutine(Protocol, IMS_FL_CLIENT);
    return Status;
}

NTSTATUS
IppStopFlc(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    Status = NmrDeregisterClient(Protocol->FlClientHandle);
    ASSERT(Status == STATUS_PENDING);

    return Status;
}

NTSTATUS
IppWaitFlc(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;

    Status = NmrWaitForClientDeregisterComplete(Protocol->FlClientHandle);
    ASSERT(Status == STATUS_SUCCESS);
    IpDeregisterFlClientComplete(&Protocol->FlClientNotify);

    return Status;
}

VOID
IppCleanupFlc(
    IN PIP_PROTOCOL Protocol
    )
{
    UninitializeListHead(&Protocol->FlProviderDetachingList);
    IppUninitializeLockedList(&Protocol->FlProviderSet);
}

//
// NSI provider related routines.
//
NTSTATUS
NTAPI
IpAttachNsiClient(
    IN HANDLE  NmrBindingHandle,
    IN PVOID  ProviderContext,
    IN PNPI_REGISTRATION_INSTANCE  ClientRegistrationInstance,
    IN PVOID  ClientBindingContext,
    IN CONST VOID *ClientDispatch,
    OUT PVOID  *ProviderBindingContext,
    OUT CONST VOID*  *ProviderDispatch
    )
{
    PNMP_CLIENT_CONTEXT BindingContext;
    PNMP_CLIENT_CONTEXT Old;
    PIP_PROTOCOL Protocol = 
        CONTAINING_RECORD(ProviderContext, IP_PROTOCOL, NsiProviderNotify);

    UNREFERENCED_PARAMETER(ClientRegistrationInstance);
    //
    // Allocate context for this binding.
    //
    BindingContext = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(*BindingContext), 'cmLN');
    if (BindingContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    //
    // Remember the client's NPI in our context block.
    //
    RtlZeroMemory(BindingContext, sizeof(*BindingContext));
    BindingContext->Npi.Dispatch = ClientDispatch;
    BindingContext->Npi.ProviderHandle = ClientBindingContext;
    BindingContext->Protocol = Protocol;
    BindingContext->Signature = NMP_CLIENT_CONTEXT_SIGNATURE;
    BindingContext->NmrBindingHandle = NmrBindingHandle;
    //
    // Our NPI that the client will use when it calls on us will have
    // this context block as its handle.
    //
    *ProviderBindingContext = BindingContext;
    *ProviderDispatch = Protocol->NsiProviderDispatch;

    RoInitializeAsInvalid(&BindingContext->InterfaceNotificationContext.
        ReferenceObject);
    RoInitializeAsInvalid(&BindingContext->AddressNotificationContext.
        ReferenceObject);
    RoInitializeAsInvalid(&BindingContext->RouteNotificationContext.
        ReferenceObject);
    RoInitializeAsInvalid(&BindingContext->EchoRequestNotificationContext.
        ReferenceObject);
    RoInitializeAsInvalid(&BindingContext->
        MulticastForwardingNotificationContext.ReferenceObject);
    
    Old = InterlockedCompareExchangePointer(
        &Protocol->NmClientContext, 
        BindingContext, 
        NULL);
    if (Old != NULL) {
        ExFreePool(BindingContext);
        return STATUS_UNSUCCESSFUL;
    }
    
    RoInitialize(&Protocol->NmClientReferenceObject);

    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: Attached NSI Client for %s\n",
               Protocol->TraceString);

    return STATUS_SUCCESS;
}

VOID
IpDeregisterNsiProviderComplete(
    IN PVOID  ProviderContext
    )
{
    PIP_PROTOCOL Protocol = 
        CONTAINING_RECORD(ProviderContext, IP_PROTOCOL, NsiProviderNotify);
    
    IppDefaultStopRoutine(Protocol);
    NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
               "IPNG: %s NSI Provider deregistration complete\n",
               Protocol->TraceString);
}

NTSTATUS
NTAPI
IpDetachNsiClient(
    IN PVOID  ProviderBindingContext
    )
{
    PNMP_CLIENT_CONTEXT ClientContext = 
        (PNMP_CLIENT_CONTEXT)ProviderBindingContext;
    PIP_PROTOCOL Protocol = ClientContext->Protocol;


    ClientContext->PendingDetachBindingHandle = 
        ClientContext->NmrBindingHandle;

    //
    // Mark the client context as disabled to prevent any new requests from
    // using the client.
    //
    if (RoUnInitialize(&Protocol->NmClientReferenceObject)) {
        Protocol->NmClientContext = NULL;
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                   "IPNG: %s NSI Client detach complete\n", 
                   Protocol->TraceString);
        return STATUS_SUCCESS;
    } else {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_INFORMATION,
                   "IPNG: %s NSI Client detach started\n", 
                   Protocol->TraceString);
        return STATUS_PENDING;
    }
}

VOID
NTAPI
IpCleanupNsiClientContext(
    IN PVOID  ProviderBindingContext
    )
{
    ExFreePool(ProviderBindingContext);
}


NTSTATUS
IppStartNsip(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;
    
    Status = NmrRegisterProvider(&Protocol->NsiProviderNotify,
                                 &Protocol->NsiProviderNotify,
                                 &Protocol->NsiProviderHandle);
    if (!NT_SUCCESS(Status)) {
        NetioTrace(NETIO_TRACE_NETWORK, TRACE_LEVEL_WARNING,
                   "IPNG: Error registering as an %s NSI Provider (0x%x)\n",
                   Protocol->TraceString, Status);
        return Status;
    }
    
    IppDefaultStartRoutine(Protocol, IMS_NSI_PROVIDER);
    return Status;
}

NTSTATUS
IppStopNsip(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;
    
    Status = NmrDeregisterProvider(Protocol->NsiProviderHandle);
    ASSERT(Status == STATUS_PENDING);

    return Status;
}

NTSTATUS
IppWaitNsip(
    IN PIP_PROTOCOL Protocol
    )
{
    NTSTATUS Status;
    
    Status = NmrWaitForProviderDeregisterComplete(Protocol->NsiProviderHandle);
    ASSERT(Status == STATUS_SUCCESS);
    IpDeregisterNsiProviderComplete(&Protocol->NsiProviderNotify);

    return Status;
}

NTSTATUS
NTAPI
IpGetAllGlobalParameters(
    IN OUT PNM_REQUEST_GET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function gets all public global parameters.

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

--*/
{
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client = IppCast(Args->ProviderHandle,
                                         NMP_CLIENT_CONTEXT);

    Protocol = Client->Protocol;

    //
    // The NSI guarantees that the KeyStructLength matches what
    // we registered with it.
    //
    ASSERT(Args->KeyStructDesc.KeyStructLength == 0);

    switch (Args->Action) {
    case NsiGetExact:
    case NsiGetFirst:
        break;

    case NsiGetNext:
        return STATUS_NO_MORE_ENTRIES;

    default:
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    if (Args->StructDesc.RwParameterStruct != NULL) {
        NL_GLOBAL_RW Data = {0};

        ASSERT(Args->StructDesc.RwParameterStructLength == sizeof(Data));
        
        Data.UseTemporaryAddresses =
            Protocol->UseTemporaryAddresses;
        Data.MaxTemporaryDesynchronizationTime = 
            IppTicksToSeconds(Protocol->MaxTemporaryDesyncFactor);
        Data.MaxTemporaryValidLifetime = 
            IppTicksToSeconds(Protocol->MaxTemporaryValidLifetime);
        Data.MaxTemporaryPreferredLifetime = 
            IppTicksToSeconds(Protocol->MaxTemporaryPreferredLifetime) + 
            IppTicksToSeconds(Protocol->TemporaryDesyncFactor);

        Data.MaxTemporaryDadAttempts =
            Protocol->MaxTemporaryDadAttempts;
        Data.TemporaryRegenerateTime = 
            IppTicksToSeconds(Protocol->TemporaryRegenerateAdvance);
        Data.DefaultHopLimit =
            Protocol->DefaultHopLimit;
        Data.NeighborCacheLimit =
            IppNeighborCacheLimit;
        Data.ReassemblyLimit =
            Protocol->ReassemblySet.Limit;
        Data.PathCacheLimit =
            Protocol->PathCacheLimit;

        //
        // TODO: fill these in when they exist.
        //
        // Data.RouteTableLimit = 0;

        Data.DeadRouteProbeTimeout = 
            IppTicksToSeconds(Protocol->DeadRouteProbeTimeout);
        Data.DeadRouteTimeout = 
            IppTicksToSeconds(Protocol->DeadRouteTimeout);
        Data.PathUnreachableTimeout = 
            IppTicksToSeconds(Protocol->PathUnreachableTimeout);
        Data.DeadRouteProbeTrafficPercent = 
            Protocol->DeadRouteProbeTrafficPercent;
        Data.LinkLocalAddressBehavior =
            Protocol->LinkLocalAddressBehavior;
        Data.SourceRoutingBehavior =
            Protocol->SourceRoutingBehavior;
        Data.MldLevel =
            Protocol->MldLevel;
        switch (Protocol->MaximumMldVersion) {
        case MULTICAST_DISCOVERY_VERSION1: 
            Data.MldVersion = MldVersion1;
            break;
        case MULTICAST_DISCOVERY_VERSION2:
            Data.MldVersion = MldVersion2;
            break;
        case MULTICAST_DISCOVERY_VERSION3:
            Data.MldVersion = MldVersion3;
            break;
        default:
            ASSERT(FALSE);
            break;
        }
        Data.DadTransmits =
            Protocol->DadTransmits;
        Data.EnableForwarding =
            (Protocol->EnableForwarding == ForwardingEnabled);
        Data.EnableIcmpRedirects =
            Protocol->EnableIcmpRedirects;
        Data.EnableAddrMaskReply=
            Protocol->EnableAddrMaskReply;        
        Data.DisableTaskOffload =
            Protocol->DisableTaskOffload;
        Data.EnableNonUnicastDatalinkAddresses =
            Protocol->EnableNonUnicastDatalinkAddresses;
        Data.DisableMediaSense =
            Protocol->DisableMediaSense;
        Data.DisableMediaSenseEventLog =
            Protocol->DisableMediaSenseEventLog;
        Data.EnableMulticastForwarding = Protocol->EnableMulticastForwarding;
        Data.GroupForwardedFragments = Protocol->GroupForwardedFragments;
        Data.RandomizeIdentifiers = Protocol->RandomizeIdentifiers;
        
        RtlCopyMemory(
            Args->StructDesc.RwParameterStruct,
            &Data,
            Args->StructDesc.RwParameterStructLength);
    }
    
    if (Args->StructDesc.RoDynamicParameterStruct != NULL) {
        NL_GLOBAL_ROD Data = {0};
        PIP_GLOBAL_STATISTICS Stats;
        LONG CurrentProcessorIndex = -1;
        ASSERT(Args->StructDesc.RoDynamicParameterStructLength == sizeof(Data));

        //
        // We only support querying offload statistics at passive.
        //
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_PARAMETER;
        }
        
        Data.CompartmentCount = Protocol->CompartmentSet.NumEntries;
        Data.NlClientCount = Protocol->NlClientSet.NumEntries;
        Data.FlProviderCount = Protocol->FlProviderSet.NumEntries;
        Data.InterfaceCount = Protocol->GlobalInterfaceSet.NumEntries;

        Data.TemporaryDesynchronizationTime = 
            IppTicksToSeconds(Protocol->TemporaryDesyncFactor);

        //
        // Total up per-processor stats.
        //

        while (NetioGetNextActiveProcessor(&CurrentProcessorIndex)) {            
            Stats = &Protocol->PerProcessorStatistics[CurrentProcessorIndex];
            Data.InReceives += Stats->InReceives;
            Data.InOctets += Stats->InOctets;
            Data.InForwardedDatagrams += Stats->InForwardedDatagrams;
            Data.InDelivers += Stats->InDelivers;
            Data.OutRequests += Stats->OutRequests;
            Data.OutForwardedDatagrams += Stats->OutForwardedDatagrams;
            Data.OutTransmits += Stats->OutTransmits;
            Data.OutOctets += Stats->OutOctets;
            Data.InMulticastPackets += Stats->InMulticastPackets;
            Data.InMulticastOctets += Stats->InMulticastOctets;
            Data.OutMulticastPackets += Stats->OutMulticastPackets;
            Data.OutMulticastOctets += Stats->OutMulticastOctets;
            Data.InBroadcastPackets += Stats->InBroadcastPackets;
            Data.OutBroadcastPackets += Stats->OutBroadcastPackets;

            Data.InHeaderErrors += Stats->InHeaderErrors;
            Data.InAddressErrors += Stats->InAddressErrors;
            Data.InUnknownProtocols += Stats->InUnknownProtocols;
            Data.InTruncatedPackets += Stats->InTruncatedPackets;
            Data.ReassemblyRequireds += Stats->ReassemblyRequireds;
            Data.ReassemblyOks += Stats->ReassemblyOks;
            Data.ReassemblyFailures += Stats->ReassemblyFailures;
            Data.InDiscards += Stats->InDiscards + Stats->InFilterDrops;
            Data.OutNoRoutes += Stats->OutNoRoutes;
            Data.OutDiscards += Stats->OutDiscards + Stats->OutFilterDrops;
            Data.FragmentOks += Stats->FragmentOks;
            Data.FragmentFailures += Stats->FragmentFailures;
            Data.FragmentsCreated += Stats->FragmentsCreated;
            Data.RoutingDiscards += Stats->RoutingDiscards;
            
            Data.OutIpsecEspOverUdpPackets += Stats->OutIpsecEspOverUdpPackets;
            Data.InIpsecEspOverUdpPackets += Stats->InIpsecEspOverUdpPackets;
        }
        Data.FragmentationRequireds = 
            Data.FragmentOks + Data.FragmentFailures;
    
        IppAddGlobalOffloadStatistics(Protocol, &Data);

        RtlCopyMemory(
            Args->StructDesc.RoDynamicParameterStruct,
            &Data,
            Args->StructDesc.RoDynamicParameterStructLength);
    }
        
    if (Args->StructDesc.RoStaticParameterStruct != NULL) {
        NL_GLOBAL_ROS Data = {0};

        ASSERT(Args->StructDesc.RoStaticParameterStructLength == sizeof(Data));
        
        Data.ReassemblyTimeout = IppTicksToSeconds(DEFAULT_REASSEMBLY_TIMEOUT);

        RtlCopyMemory(
            Args->StructDesc.RoStaticParameterStruct,
            &Data,
            Args->StructDesc.RoStaticParameterStructLength);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IppValidateGlobalRwParameters(
    IN PIP_PROTOCOL Protocol,
    IN PNL_GLOBAL_RW GlobalRw
    )
/*++

Routine Description:

    This function will validate global RW parameters.

Arguments:

    Protocol - Supplies a pointer to the global protocol block.

    GlobalRw - Supplies a pointer to Global Rw structure.

Return Value:

    Status of the validation.
    
--*/
{
    ULONG MaxTemporaryDesyncFactor, MaxTemporaryValidLifetime, 
        MaxTemporaryPreferredLifetime, TemporaryRegenerateAdvance;
    
    ASSERT(GlobalRw != NULL);
    ASSERT(sizeof(NL_GLOBAL_RW) == sizeof(*GlobalRw));

    if (GlobalRw->UseTemporaryAddresses != (ULONG) -1) {
        //
        // Temporary addresses can not be turned on for IPv4. 
        //
        if (IS_IPV4_PROTOCOL(Protocol) &&
            (GlobalRw->UseTemporaryAddresses != UseTemporaryNo)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
                                           
    //
    // We maintain the following invariant: 
    // TemporaryRegenerateAdvance + MaxTemporaryDesynchronizationTime <
    // MaxTemporaryPreferredLifetime <= 
    // MaxTemporaryValidLifetime. 
    // Note the strict inequality -- this is to make sure that we do not
    // generate an unlimited number of temporary addresses. 
    // First estimate the values of all the parameters so that we can check
    // the above condition.
    //
    if (GlobalRw->MaxTemporaryDesynchronizationTime != (ULONG) -1) {
        MaxTemporaryDesyncFactor = 
            IppSecondsToTicks(GlobalRw->MaxTemporaryDesynchronizationTime);
    } else {
        MaxTemporaryDesyncFactor = Protocol->MaxTemporaryDesyncFactor;
    }

    if (GlobalRw->MaxTemporaryValidLifetime != (ULONG) -1) {
        MaxTemporaryValidLifetime = 
            IppSecondsToTicks(GlobalRw->MaxTemporaryValidLifetime);
    } else {
        MaxTemporaryValidLifetime = Protocol->MaxTemporaryValidLifetime;
    }

    if (GlobalRw->MaxTemporaryPreferredLifetime != (ULONG) -1) {
        MaxTemporaryPreferredLifetime = 
            IppSecondsToTicks(GlobalRw->MaxTemporaryPreferredLifetime);
    } else {
        MaxTemporaryPreferredLifetime = 
            Protocol->MaxTemporaryPreferredLifetime;
    }

    if (GlobalRw->TemporaryRegenerateTime != (ULONG) -1) {
        TemporaryRegenerateAdvance =
            IppSecondsToTicks(GlobalRw->TemporaryRegenerateTime);
    } else {
        TemporaryRegenerateAdvance = Protocol->TemporaryRegenerateAdvance;
    }

    if (!(MaxTemporaryPreferredLifetime <= MaxTemporaryValidLifetime) ||
        !(TemporaryRegenerateAdvance + MaxTemporaryDesyncFactor < 
          MaxTemporaryPreferredLifetime)) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((GlobalRw->DefaultHopLimit != (ULONG) -1) && 
        (GlobalRw->DefaultHopLimit > 255)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // A protocol can only be (un)installed during a reboot.
    // Hence this property can not be modified in the active state.
    //
    if (GlobalRw->Installed != (BOOLEAN) -1) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if ((GlobalRw->DeadRouteProbeTrafficPercent != (ULONG) -1) &&
        (GlobalRw->DeadRouteProbeTrafficPercent > 100)) {
        return STATUS_INVALID_PARAMETER;
    }
        
    switch(GlobalRw->LinkLocalAddressBehavior) {
    case LinkLocalUnchanged:
    case LinkLocalAlwaysOn:
        break;
    case LinkLocalAlwaysOff:
    case LinkLocalDelayed:
        if (IS_IPV4_PROTOCOL(Protocol)) {
            break;
        }
        //
        // For IPv6, link local address configuration must always be enabled.
        // Fall through and return an error.
        //
    default:
        return STATUS_INVALID_PARAMETER;
    }

    if ((GlobalRw->SourceRoutingBehavior != SourceRoutingUnchanged) &&
        ((GlobalRw->SourceRoutingBehavior < SourceRoutingForward) ||
         (GlobalRw->SourceRoutingBehavior > SourceRoutingDrop))) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((GlobalRw->MldLevel != MldLevelUnchanged) &&
        ((GlobalRw->MldLevel < MldLevelNone) ||
         (GlobalRw->MldLevel > MldLevelAll))) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if ((GlobalRw->MldVersion != MldVersionUnchanged) &&
        ((GlobalRw->MldVersion < MldVersion1) ||
         (GlobalRw->MldVersion > MldVersion3) ||
         ((GlobalRw->MldVersion == MldVersion1) &&
          IS_IPV6_PROTOCOL(Protocol)))) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((GlobalRw->DadTransmits != (ULONG) -1) && 
        (GlobalRw->DadTransmits > 3)) {
        return STATUS_INVALID_PARAMETER;
    }    
    
    if (IS_IPV4_PROTOCOL(Protocol)) {

        if (GlobalRw->LinkLocalAddressPrefix.Ipv4.S_un.S_addr != (ULONG)-1) {            
            if (Ipv4AddressType((UCHAR *)&GlobalRw->LinkLocalAddressPrefix.Ipv4)                
                != NlatUnicast) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        if (GlobalRw->LinkLocalAddressPrefixLength != (ULONG)-1) {
            if (GlobalRw->LinkLocalAddressPrefixLength > RTL_BITS_OF(UINT32)) {
                return STATUS_INVALID_PARAMETER;
            }            
        }
    }
    return STATUS_SUCCESS;
}

VOID
IppUpdateGlobalRwParameters(
    IN OUT PIP_PROTOCOL Protocol,
    IN PNL_GLOBAL_RW GlobalRw
    )
/*++

Routine Description:

    This function will update the protocol with global settings.

Arguments:

    Protocol - Supplies a pointer to the global protocol block.

    GlobalRw - Supplies a pointer to Global Rw structure.
    
Return Value:

    None.
    
--*/
{
    ASSERT(Protocol != NULL);
    ASSERT(GlobalRw != NULL);

    if (GlobalRw->UseTemporaryAddresses != (ULONG) -1)  {
        Protocol->UseTemporaryAddresses = GlobalRw->UseTemporaryAddresses;
    }

    if (GlobalRw->MaxTemporaryDesynchronizationTime != (ULONG) -1) {
        Protocol->MaxTemporaryDesyncFactor = 
            IppSecondsToTicks(GlobalRw->MaxTemporaryDesynchronizationTime);
        Protocol->TemporaryDesyncFactor = 
            RandomNumber(0, Protocol->MaxTemporaryDesyncFactor);
    }

    if (GlobalRw->MaxTemporaryValidLifetime != (ULONG) -1) {
        Protocol->MaxTemporaryValidLifetime = 
            IppSecondsToTicks(GlobalRw->MaxTemporaryValidLifetime);
    }

    if (GlobalRw->MaxTemporaryPreferredLifetime != (ULONG) -1) {
        Protocol->MaxTemporaryPreferredLifetime = 
            IppSecondsToTicks(GlobalRw->MaxTemporaryPreferredLifetime) - 
            Protocol->TemporaryDesyncFactor;
    }

    if (GlobalRw->MaxTemporaryDadAttempts != (ULONG) -1) {
        Protocol->MaxTemporaryDadAttempts = GlobalRw->MaxTemporaryDadAttempts;
    }

    if (GlobalRw->TemporaryRegenerateTime != (ULONG) -1) {
        Protocol->TemporaryRegenerateAdvance =
            IppSecondsToTicks(GlobalRw->TemporaryRegenerateTime);
    }

    ASSERT(Protocol->MaxTemporaryPreferredLifetime <= 
           Protocol->MaxTemporaryValidLifetime);
    ASSERT(Protocol->TemporaryRegenerateAdvance < 
           Protocol->MaxTemporaryPreferredLifetime);
    
    if (GlobalRw->DefaultHopLimit != (ULONG) -1) {
        Protocol->DefaultHopLimit = (UINT8) GlobalRw->DefaultHopLimit;
    }

    if (GlobalRw->NeighborCacheLimit != (ULONG) -1) {
        IppNeighborCacheLimit = GlobalRw->NeighborCacheLimit;
    }

    if (GlobalRw->ReassemblyLimit != (ULONG) -1) {
        Protocol->ReassemblySet.Limit = GlobalRw->ReassemblyLimit;
    }

    if (GlobalRw->DeadRouteProbeTimeout != (ULONG) -1) {
        Protocol->DeadRouteProbeTimeout = 
            IppSecondsToTicks(GlobalRw->DeadRouteProbeTimeout);
    }

    if (GlobalRw->DeadRouteTimeout != (ULONG) -1) {
        Protocol->DeadRouteTimeout =
            IppSecondsToTicks(GlobalRw->DeadRouteTimeout);
    }

    if (GlobalRw->PathUnreachableTimeout != (ULONG) -1) {
        Protocol->PathUnreachableTimeout = 
            IppSecondsToTicks(GlobalRw->PathUnreachableTimeout);
    }

    if (GlobalRw->DeadRouteProbeTrafficPercent != (ULONG) -1) {
        Protocol->DeadRouteProbeTrafficPercent = 
            GlobalRw->DeadRouteProbeTrafficPercent;
    }

    if (GlobalRw->LinkLocalAddressBehavior != LinkLocalUnchanged) {
        Protocol->LinkLocalAddressBehavior =
            GlobalRw->LinkLocalAddressBehavior;
    }

    if (IS_IPV4_PROTOCOL(Protocol)) {
        
        if (GlobalRw->LinkLocalAddressPrefix.Ipv4.S_un.S_addr != (ULONG)-1) {            
            Protocol->LinkLocalAddressPrefix =
                GlobalRw->LinkLocalAddressPrefix;
        }
        if (GlobalRw->LinkLocalAddressPrefixLength != (ULONG)-1) {
            Protocol->LinkLocalAddressPrefixLength =
                GlobalRw->LinkLocalAddressPrefixLength;          
        }        
    }
    
    if (GlobalRw->SourceRoutingBehavior != SourceRoutingUnchanged) {
        Protocol->SourceRoutingBehavior = GlobalRw->SourceRoutingBehavior;
    }

    if (GlobalRw->MldLevel != MldLevelUnchanged) {
        Protocol->MldLevel = GlobalRw->MldLevel;
    }
    
    switch (GlobalRw->MldVersion) {
    case MldVersion1:
        Protocol->MaximumMldVersion = MULTICAST_DISCOVERY_VERSION1;
        break;
    case MldVersion2:
        Protocol->MaximumMldVersion = MULTICAST_DISCOVERY_VERSION2;
        break;
    case MldVersion3:
        Protocol->MaximumMldVersion = MULTICAST_DISCOVERY_VERSION3;
        break;
    default:
        break;
    }
    
    if (GlobalRw->DadTransmits != (ULONG) -1) {
        Protocol->DadTransmits = GlobalRw->DadTransmits;
    }
    
    if (GlobalRw->EnableForwarding != (BOOLEAN) -1) {
        if (GlobalRw->EnableForwarding) {
            Protocol->EnableForwarding = ForwardingEnabled;
        } else {
            Protocol->EnableForwarding = ForwardingDisabled;
        }
    }
    
    if (GlobalRw->EnableIcmpRedirects != (BOOLEAN) -1) {
        Protocol->EnableIcmpRedirects = GlobalRw->EnableIcmpRedirects;
    }

    if (GlobalRw->EnableAddrMaskReply!= (BOOLEAN) -1) {
        Protocol->EnableAddrMaskReply = GlobalRw->EnableAddrMaskReply;
    }    

    if (GlobalRw->DisableTaskOffload != (BOOLEAN) -1) {
        Protocol->DisableTaskOffload = GlobalRw->DisableTaskOffload;
    }

    if (GlobalRw->EnableNonUnicastDatalinkAddresses != (BOOLEAN) -1) {
        Protocol->EnableNonUnicastDatalinkAddresses =
            GlobalRw->EnableNonUnicastDatalinkAddresses;
    }
    
    if (GlobalRw->DisableMediaSense != (BOOLEAN) -1) {
        IppSetDhcpOperationalStatus(Protocol, GlobalRw->DisableMediaSense);
    }
    
    if (GlobalRw->DisableMediaSenseEventLog != (BOOLEAN) -1) {
        Protocol->DisableMediaSenseEventLog =
            GlobalRw->DisableMediaSenseEventLog;
    }
    
    if (GlobalRw->PathCacheLimit != (ULONG) -1) {
        Protocol->PathCacheLimit = GlobalRw->PathCacheLimit;
    }

    if (GlobalRw->EnableMulticastForwarding != (BOOLEAN) -1) {
        Protocol->EnableMulticastForwarding =
            !!GlobalRw->EnableMulticastForwarding;
    }

    if (GlobalRw->GroupForwardedFragments != (BOOLEAN) -1) {
        Protocol->GroupForwardedFragments =
            !!GlobalRw->GroupForwardedFragments;
    }

    if (GlobalRw->RandomizeIdentifiers != (BOOLEAN) -1) {
        Protocol->RandomizeIdentifiers =
            !!GlobalRw->RandomizeIdentifiers;
    }
    
    if (GlobalRw->OverrideDefaultAddressSelection != (BOOLEAN)-1) {
        Protocol->OverrideDefaultAddressSelection = 
            !!GlobalRw->OverrideDefaultAddressSelection;
    }
    //
    // Update compartments if required.
    //
    if ((GlobalRw->DefaultHopLimit != (ULONG) -1) || 
        (GlobalRw->EnableForwarding != (BOOLEAN) -1) ||
        (GlobalRw->EnableMulticastForwarding != (BOOLEAN) -1) ||
        (GlobalRw->RandomizeIdentifiers != (BOOLEAN)(-1))) {
        IppUpdateAllProtocolCompartments(
            Protocol,
            GlobalRw->DefaultHopLimit,
            (GlobalRw->EnableForwarding == (BOOLEAN) -1) 
            ? ForwardingUnchanged
            : Protocol->EnableForwarding,
            (BOOLEAN) -1,
            (BOOLEAN) -1,
            GlobalRw->EnableMulticastForwarding,
            GlobalRw->RandomizeIdentifiers);
    }
    //
    // TODO: save these when they exist.
    // Data->RouteTableLimit
    //
}

VOID
IppInitializeProtocolSettings(
    IN PIP_PROTOCOL Protocol
    )
/*++

Description:

    This routine initializes protocol with any SKU specific settings and 
    persistent global settings. If unable to read persistent settings, use the 
    defaults.

Arguments:

    Protocol - Supplies a pointer to the global protocol block.
    
Caller IRQL:

    Must be called at PASSIVE level.

--*/
{
    RTL_OSVERSIONINFOEXW OsVersionInfoExW;
    NTSTATUS Status;
    NL_GLOBAL_RW Rw;

    //
    // Ipv6 temporary addresses are disabled by default on server SKU.
    //
    if (IS_IPV6_PROTOCOL(Protocol)) {

        RtlZeroMemory(&OsVersionInfoExW, sizeof(OsVersionInfoExW));
        OsVersionInfoExW.dwOSVersionInfoSize = sizeof(OsVersionInfoExW);
        Status = RtlGetVersion((PRTL_OSVERSIONINFOW) &OsVersionInfoExW);

        if (NT_SUCCESS(Status) &&
            OsVersionInfoExW.wProductType != VER_NT_WORKSTATION) {
            Protocol->UseTemporaryAddresses = UseTemporaryNo;
        }
    }

    //
    // Read persistent configuration.
    //
    NlInitializeGlobalRw(&Rw);
    
    Status =
        NsiGetAllParameters(
            NsiPersistent,
            Protocol->ModuleId,
            NlGlobalObject,
            NULL, 0,
            &Rw, sizeof(Rw),
            NULL, 0,
            NULL, 0);

    if (NT_SUCCESS(Status)) {
        Status = IppValidateGlobalRwParameters(Protocol, &Rw);
        if (NT_SUCCESS(Status)) {
            IppUpdateGlobalRwParameters(Protocol, &Rw);
        }
    }
}    

NTSTATUS
IppValidateSetAllGlobalParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will validate a set all global parameters request.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    Status of the validation.
    
--*/
{
    NTSTATUS Status;
    PIP_PROTOCOL Protocol;
    PNMP_CLIENT_CONTEXT Client =
        IppCast(Args->ProviderHandle, NMP_CLIENT_CONTEXT);


    Protocol = Client->Protocol;

    Args->ProviderTransactionContext = NULL;
    
    switch (Args->Action) {
        case NsiSetCreateOrSet:
        case NsiSetDefault:
            break;

        case NsiSetDelete:
            return STATUS_NOT_IMPLEMENTED;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate parameter structure.
    //
    if (Args->RwStructDesc.RwParameterStruct != NULL) {
        PNL_GLOBAL_RW Data = 
            (PNL_GLOBAL_RW) Args->RwStructDesc.RwParameterStruct;

        ASSERT(Args->RwStructDesc.RwParameterStructLength == sizeof(*Data));

        Status = IppValidateGlobalRwParameters(Protocol, Data);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }
    Args->ProviderTransactionContext = Protocol;

    return STATUS_SUCCESS;
}

VOID
IppCancelSetAllGlobalParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will cancel a validated set all parameters request.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    None.
    
--*/
{
    Args->ProviderTransactionContext = NULL;
}

VOID
IppCommitSetAllGlobalParameters(
    PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function will commit a set all request validated before.

Arguments:

    Args - Pointer to the parameter structure.

Return Value:

    None.
    
--*/
{
    PIP_PROTOCOL Protocol = Args->ProviderTransactionContext;
    PNL_GLOBAL_RW Data = (PNL_GLOBAL_RW)Args->RwStructDesc.RwParameterStruct;

    ASSERT(Protocol != NULL);
    ASSERT(Data != NULL);

    IppUpdateGlobalRwParameters(Protocol, Data);
    
    Args->ProviderTransactionContext = NULL;
}

NTSTATUS
NTAPI
IpSetAllGlobalParameters(
    IN OUT PNM_REQUEST_SET_ALL_PARAMETERS Args
    )
/*++

Routine Description:

    This function sets all global public read-write parameters.

Arguments:

    Args - Supplies a pointer to information about the operation to perform.

Return Value:

    The status of the operation.

Caller IRQL:

    NSI always calls this at PASSIVE level.

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    switch (Args->Transaction) {
        case NsiTransactionNone:
            Status = IppValidateSetAllGlobalParameters(Args);
            if (NT_SUCCESS(Status)) {
                IppCommitSetAllGlobalParameters(Args);
            }
            break;
        case NsiTransactionCancel:
            IppCancelSetAllGlobalParameters(Args);
            break;
        case NsiTransactionCommit:
            IppCommitSetAllGlobalParameters(Args);
            break;
        case NsiTransactionValidate:
            Status = IppValidateSetAllGlobalParameters(Args);
            break;
        default:
            Status = STATUS_INVALID_PARAMETER;
    }
    return Status;
}

NTSTATUS
NlProcessorAddRemoveHandler(
    IN ULONG ProcessorIndex,
    IN BOOLEAN ProcessorAdded
    )
/*++

Routine Description:

    NL Handler for processor additions.

Arguments:
    ProcessorIndex - Index of the processor that is being modified.

    ProcessorAdded - Added or removed. Remove is not supported today.
        But we can get called to remove due to an add failure.
        
Return Value:
    NTSTATUS. On the remove path this should return success.
--*/                   
{
    NTSTATUS Status;
    ASSERT(ProcessorIndex < KeQueryMaximumProcessorCount());
    
    Status = 
        IppInterfaceListProcessorAddRemoveHandler(        
            &Ipv4Global, ProcessorIndex, ProcessorAdded);
    if (!NT_SUCCESS(Status)) {
        // 
        // Processor Cleanup cannot fail.
        //
        ASSERT(ProcessorAdded);
        //
        // We can rely on the Processor add failure
        // being called after we return from here. 
        // The clean up will happen then.
        //
        return Status;
    }

    Status = 
        IppInterfaceListProcessorAddRemoveHandler(        
            &Ipv6Global, ProcessorIndex, ProcessorAdded);
    if (!NT_SUCCESS(Status)) {
        // 
        // Processor Cleanup cannot fail.
        //
        ASSERT(ProcessorAdded);
        return Status;
    }

    Status = 
        IppAddRemoveReceivePerProcessorContexts(
            ProcessorIndex, ProcessorAdded);
    if (!NT_SUCCESS(Status)) {
        // 
        // Processor Cleanup cannot fail.
        //
        ASSERT(ProcessorAdded);
        return Status;
    }

    return Status;    
}
