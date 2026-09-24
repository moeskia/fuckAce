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
#include <errno.h>
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

/* The SDK calls it SE_INCREASE_BASE_PRIORITY_NAME, MinGW
   SE_INC_BASE_PRIORITY_NAME. */
#ifndef SE_INCREASE_BASE_PRIORITY_NAME
#ifdef SE_INC_BASE_PRIORITY_NAME
#define SE_INCREASE_BASE_PRIORITY_NAME SE_INC_BASE_PRIORITY_NAME
#else
#define SE_INCREASE_BASE_PRIORITY_NAME L"SeIncreaseBasePriorityPrivilege"
#endif
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
/* NtSetInformationThread(ThreadIoPriority); THREADINFOCLASS 0x16.
   Setting needs THREAD_SET_INFORMATION, the read-back needs
   THREAD_QUERY_LIMITED_INFORMATION, and the set is documented to require
   SeIncreaseBasePriorityPrivilege. */
#define NT_THREAD_IO_PRIORITY 0x16
#define IO_PRIORITY_VERY_LOW 0
#define NT_SUCCESS(status) ((LONG)(status) >= 0)

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

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

/* buffer size for a target image name, terminator included */
#define TARGET_NAME_MAX 32

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
    wchar_t name[TARGET_NAME_MAX];
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
    int ioThrSet;                       /* threads whose I/O priority stuck */
    int ioThrTotal;                     /* threads the I/O priority was tried on */
    BOOL ioThreadsFailed;               /* IO failed on the per-thread part */
} PROCESS_RESULT;

#endif /* COMMON_H */
