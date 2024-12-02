/*++

Copyright (c) 2000-2001  Microsoft Corporation

Module Name:

    dllmain.c

Abstract:

    This module contains the initialization code for ipngdll.dll.

Author:

    Dave Thaler (dthaler) 1-Dec-2000

Environment:

    user mode only

--*/

#include "precomp.h"

DRIVER_OBJECT    g_Driver;

HANDLE NotificationRpcHandle = NULL;
    
NTSTATUS
NlStartup(
    IN PDRIVER_OBJECT DriverObject, 
    IN PDEVICE_OBJECT DeviceObject, 
    IN PUNICODE_STRING RegistryPath
    );

BOOL
NetStartIpng(
    VOID
    )
/*++
Description:
    Invoke the IPNG driver entry routine.  This must NOT be called from
    DllMain, since one must not wait on synchronization objects from within
    DllMain.
--*/
{
    NTSTATUS nts;

    nts = NlStartup(&g_Driver, NULL, NULL);

    return NT_SUCCESS(nts);

}

VOID
NetStopIpng(
    VOID
    )
/*++
Description:
    Invoke the IPNG driver unload routine.  This must NOT be called from
    DllMain, since one must not wait on synchronization objects from within
    DllMain.
--*/
{
    NlCleanup(&g_Driver);
}

BOOL
WINAPI
DllMain(
    HINSTANCE   hModule,
    DWORD       dwReason,
    LPVOID      lpvReserved
    )
{
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (dwReason) {

        //
        // Startup Initialization of Dll
        //
        case DLL_PROCESS_ATTACH:
        {
            // disable per-thread initialization
            DisableThreadLibraryCalls(hModule);

            break;
        }

        //
        // Cleanup of Dll
        //
        case DLL_PROCESS_DETACH:
        {
            break;
        }

        default:
            break;

    }
    return TRUE;
}
