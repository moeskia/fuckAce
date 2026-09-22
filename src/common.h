#ifndef COMMON_H
#define COMMON_H

#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

/* ------------------------------------------------------------------ */
/* forward-compatibility shims for older headers                       */
/* ------------------------------------------------------------------ */

#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
typedef struct _PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} PROCESS_POWER_THROTTLING_STATE;
#endif

#ifndef MEMORY_PRIORITY_VERY_LOW
#define MEMORY_PRIORITY_VERY_LOW 1
#endif

#ifndef JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
#define JOB_OBJECT_CPU_RATE_CONTROL_ENABLE 0x1
#define JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED 0x2
#define JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP 0x4
#endif

/* PROCESS_INFORMATION_CLASS values, kept as explicit casts so the code
   does not depend on the SDK enum being present. */
#define PIC_MEMORY_PRIORITY  ((PROCESS_INFORMATION_CLASS)0)
#define PIC_POWER_THROTTLING ((PROCESS_INFORMATION_CLASS)4)

/* NtSetInformationProcess(ProcessIoPriority); PROCESSINFOCLASS 0x21 */
#define NT_PROCESS_IO_PRIORITY 0x21
#define IO_PRIORITY_VERY_LOW 0
#define NT_SUCCESS(status) ((LONG)(status) >= 0)

/* Layout-compatible with JOBOBJECT_CPU_RATE_CONTROL_INFORMATION. */
typedef struct _ACE_CPU_RATE {
    DWORD ControlFlags;
    DWORD CpuRate;
} ACE_CPU_RATE;

/* our own code: the API reported success but the state did not stick */
#define ERROR_NOT_VERIFIED 0x20000001

/* priority, affinity, ecoqos, cpu cap, io, memory, threads */
#define STEP_COUNT 7
#define MAX_TARGETS 256
#define MAX_TARGET_NAMES 32
#define RETRY_SECONDS 5
#define EXIT_SECONDS 10
#define DEFAULT_CPU_CAP 3

enum {
    STEP_PRI = 0,
    STEP_AFF,
    STEP_ECO,
    STEP_CAP,
    STEP_IO,
    STEP_MEM,
    STEP_THR
};

extern const char *const kStepHead[STEP_COUNT];
extern const char *const kStepShort[STEP_COUNT];

typedef struct _TARGET {
    DWORD pid;
    wchar_t name[32];
} TARGET;

typedef struct _PROCESS_RESULT {
    BOOL opened;
    BOOL stale;                         /* pid was recycled: not a target */
    DWORD openErr;
    BOOL attempted[STEP_COUNT];
    BOOL ok[STEP_COUNT];
    DWORD err[STEP_COUNT];
    int attemptCount;
    int okCount;
    int thrSet;
    int thrTotal;
} PROCESS_RESULT;

#endif /* COMMON_H */
