/*++

Copyright (c) 2002-2003  Microsoft Corporation

Module Name:

    timeout.h

Abstract:

    This module contains declarations for the network layer module's
    timeout management.

Author:

    Mohit Talwar (mohitt) Mon Nov 18 18:39:45 2002

Environment:

    Kernel mode only.

--*/

#ifndef _A_
#define _A_

#pragma once

#define SECONDS                     1
#define MINUTES                     (60 * SECONDS)
#define HOURS                       (60 * MINUTES)
#define DAYS                        (24 * HOURS)

//
// Periodic Timer.
//
// We have a periodic timer (Protocol::Timer) that causes our timeout routine
// to be called IPP_TICKS_SECOND times per second.  Most of the timers and
// timeouts in this implementation are driven off this routine.
//
// There is a trade-off here between timer granularity/resolution and overhead.
// The resolution should be subsecond because RETRANS_TIMER is only one second.
//

#define IPP_TICKS_SECOND            2 // Two ticks per second.
#define IPP_MS_PER_TICK             500 // 500ms per tick.

#define IppTimerTicks(Seconds)      ((Seconds) * IPP_TICKS_SECOND)
#define IppMilliseconds(Seconds)    ((Seconds) * 1000)

#define IPP_TIMEOUT (IppMilliseconds(1 * SECONDS) / IPP_TICKS_SECOND)


//
// Timeout Management Routines.
//
    
NTSTATUS
IppStartTimerManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppCleanupTimerManager(
    IN PIP_PROTOCOL Protocol
    );

VOID
IppProtocolTimeout(
    IN PIP_PROTOCOL Protocol
    );

ULONG
IppSecondsToTicks(
    IN ULONG Seconds
    );

ULONG
IppTicksToSeconds(
    IN ULONG Ticks
    );
    
ULONG
IppMillisecondsToTicks(
    IN ULONG Millis
    );

__inline
ULONG
IppTicksToMilliseconds(
    IN ULONG Ticks
    )
{
    return Ticks * IPP_TIMEOUT;
}

#endif // _A_
