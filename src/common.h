#ifndef COMMON_H
#define COMMON_H

#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

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

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

#define ERROR_NOT_VERIFIED 0x20000001
#define ERROR_JOB_CONFLICT 0x20000002
#define ERROR_NOT_VERIFIABLE 0x20000003

#define STEP_COUNT 7
#define MAX_TARGETS 256
#define MAX_TARGET_NAMES 32
#define RETRY_SECONDS 5
#define EXIT_SECONDS 10
#define DEFAULT_CPU_CAP 3
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

enum {
    RESULT_FAILED = 0,
    RESULT_PARTIAL,
    RESULT_FULL
};

enum {
    CAP_SKIP_NONE = 0,
    CAP_SKIP_RIGHTS,
    CAP_SKIP_JOB,
    CAP_SKIP_UNVERIFIED
};

extern const char *const kStepHead[STEP_COUNT];
extern const char *const kStepShort[STEP_COUNT];

typedef struct _TARGET {
    DWORD pid;
    wchar_t name[TARGET_NAME_MAX];
} TARGET;

typedef struct _PROCESS_RESULT {
    BOOL opened;
    BOOL stale;
    DWORD openErr;
    BOOL attempted[STEP_COUNT];
    DWORD err[STEP_COUNT];
    int thrSet;
    int thrTotal;
    int ioThrSet;
    int ioThrTotal;
    BOOL ioThreadFailed;
    BOOL capSkipped;
    DWORD capSkipErr;
    int capSkipReason;
} PROCESS_RESULT;

#define RESULT_OK(result, step) ((result)->attempted[step] && (result)->err[step] == ERROR_SUCCESS)
#define RESULT_ACCEPTED(result, step) \
    ((result)->attempted[step] && \
     ((result)->err[step] == ERROR_SUCCESS || (result)->err[step] == ERROR_NOT_VERIFIABLE))


static inline int ResultState(const PROCESS_RESULT *result) {
    int attempted = 0;
    int succeeded = 0;
    int step;

    for (step = 0; step < STEP_COUNT; step++) {
        attempted += result->attempted[step] != FALSE;
        succeeded += RESULT_ACCEPTED(result, step);
    }
    if (attempted > 0 && attempted == succeeded) {
        return RESULT_FULL;
    }
    return succeeded > 0 ? RESULT_PARTIAL : RESULT_FAILED;
}

static inline int SummaryExitCode(int found, int full, int partial) {
    if (found <= 0) {
        return 1;
    }
    if (found == full) {
        return 0;
    }
    return full > 0 || partial > 0 ? 2 : 3;
}

#endif
