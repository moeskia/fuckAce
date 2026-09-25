#include "system/limiter.h"
#include "app/config.h"
#include "elevation/elevate.h"

static DWORD NtError(NTSTATUS status) {
    return (DWORD)RtlNtStatusToDosError(status);
}

/* 生产路径用 ElevateHasRights()（生效档位）判定；本函数只按“进程令牌里的
   Administrators 组是否启用”判定，仅供测试与诊断参考。 */
BOOL LimiterIsRunAsAdmin(void) {
    /* 必须查进程令牌而不是当前线程：提权成功后线程可能正模拟
       TrustedInstaller/SYSTEM，那些令牌里的 Administrators 是 deny-only。 */
    HANDLE token = NULL;
    BOOL isAdmin = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return FALSE;
    }
    isAdmin = ElevateTokenHasAdminGroup(token);
    CloseHandle(token);
    return isAdmin;
}

static BOOL EnablePrivilege(LPCWSTR name, DWORD *outError) {
    return ElevateEnablePrivilege(name, outError);
}

BOOL LimiterEnableDebugPrivilege(DWORD *outError) {
    return EnablePrivilege(SE_DEBUG_NAME, outError);
}

DWORD LimiterGetCpuCount(DWORD group) {
    DWORD count = GetActiveProcessorCount((WORD)group);
    SYSTEM_INFO info;

    if (count == 0) {
        GetSystemInfo(&info);
        count = info.dwNumberOfProcessors;
    }
    return count > 0 ? count : 1;
}

DWORD_PTR LimiterGetLastCpuAffinityMask(DWORD cpuCount) {
    DWORD bits = (DWORD)(sizeof(DWORD_PTR) * 8);

    if (cpuCount < 1) {
        cpuCount = 1;
    }
    if (cpuCount > bits) {
        cpuCount = bits;
    }
    return ((DWORD_PTR)1) << (cpuCount - 1);
}

int LimiterScanTargets(TARGET *targets, int cap, DWORD *outError, BOOL *outTruncated) {
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    int count = 0;
    DWORD error;

    *outError = ERROR_SUCCESS;
    *outTruncated = FALSE;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        *outError = GetLastError();
        return -1;
    }
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        error = GetLastError();
        CloseHandle(snapshot);
        if (error == ERROR_NO_MORE_FILES) {
            return 0;
        }
        *outError = error;
        return -1;
    }
    do {
        if (!ConfigIsTargetProcess(entry.szExeFile)) {
            continue;
        }
        if (count < cap) {
            targets[count].pid = entry.th32ProcessID;
            wcsncpy(targets[count].name, entry.szExeFile, TARGET_NAME_MAX - 1);
            targets[count].name[TARGET_NAME_MAX - 1] = 0;
            count++;
        } else {
            *outTruncated = TRUE;
        }
    } while (Process32NextW(snapshot, &entry));
    error = GetLastError();
    CloseHandle(snapshot);
    if (error != ERROR_NO_MORE_FILES) {
        *outError = error;
        return -1;
    }
    return count;
}

static BOOL SetEfficiencyMode(HANDLE process, DWORD *outError) {
    PROCESS_POWER_THROTTLING_STATE state = {
        PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED
    };
    PROCESS_POWER_THROTTLING_STATE check;
    DWORD queryError;

    *outError = ERROR_SUCCESS;
    if (!SetProcessInformation(process, ProcessPowerThrottling, &state, sizeof(state))) {
        *outError = GetLastError();
        return FALSE;
    }
    memset(&check, 0, sizeof(check));
    check.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    if (!GetProcessInformation(process, ProcessPowerThrottling, &check, sizeof(check))) {
        queryError = GetLastError();
        if (queryError == ERROR_INVALID_PARAMETER ||
            queryError == ERROR_NOT_SUPPORTED ||
            queryError == ERROR_INVALID_FUNCTION) {
            *outError = ERROR_NOT_VERIFIABLE;
            return TRUE;
        }
        *outError = queryError;
        return FALSE;
    }
    if (!(check.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED)) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }
    return TRUE;
}

static BOOL SetVeryLowIoPriority(HANDLE handle, BOOL thread, DWORD *outError) {
    ULONG value = 0;
    ULONG check = 0;
    NTSTATUS status;

    *outError = ERROR_SUCCESS;
    status = thread
        ? NtSetInformationThread(handle, ThreadIoPriority, &value, sizeof(value))
        : NtSetInformationProcess(handle, ProcessIoPriority, &value, sizeof(value));
    if (!NT_SUCCESS(status)) {
        *outError = NtError(status);
        return FALSE;
    }
    status = thread
        ? NtQueryInformationThread(handle, ThreadIoPriority, &check, sizeof(check), NULL)
        : NtQueryInformationProcess(handle, ProcessIoPriority, &check, sizeof(check), NULL);
    if (!NT_SUCCESS(status)) {
        *outError = NtError(status);
        return FALSE;
    }
    if (check != value) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }
    return TRUE;
}

static BOOL SetVeryLowMemoryPriority(HANDLE process, DWORD *outError) {
    MEMORY_PRIORITY_INFORMATION value;
    MEMORY_PRIORITY_INFORMATION check;

    *outError = ERROR_SUCCESS;
    value.MemoryPriority = MEMORY_PRIORITY_VERY_LOW;
    if (!SetProcessInformation(process, ProcessMemoryPriority, &value, sizeof(value))) {
        *outError = GetLastError();
        return FALSE;
    }
    if (!GetProcessInformation(process, ProcessMemoryPriority, &check, sizeof(check)) ||
        check.MemoryPriority != MEMORY_PRIORITY_VERY_LOW) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }
    return TRUE;
}

static DWORD CpuRateFromPercent(DWORD percent, DWORD cpuCount) {
    unsigned long long rate;

    if (cpuCount < 1) {
        cpuCount = 1;
    }
    if (percent < 1) {
        percent = 1;
    }
    if (percent > 100) {
        percent = 100;
    }
    rate = ((unsigned long long)percent * 100ULL) / cpuCount;
    if (rate < 1) {
        rate = 1;
    }
    if (rate > 10000) {
        rate = 10000;
    }
    return (DWORD)rate;
}

static void BuildJobName(DWORD pid, const FILETIME *created, wchar_t *name, size_t size) {
    swprintf(
        name, size, L"Local\\fuckAce_%lu_%08lX%08lX",
        (unsigned long)pid,
        (unsigned long)created->dwHighDateTime,
        (unsigned long)created->dwLowDateTime);
}

static BOOL ApplyCpuCap(
    HANDLE process,
    DWORD percent,
    BOOL allowNest,
    DWORD *outError,
    BOOL *skipped,
    int *outSkipReason
) {
    FILETIME created, exited, kernel, user;
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION info;
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION check;
    HANDLE job;
    BOOL inAnyJob = FALSE;
    BOOL inOurJob = FALSE;
    DWORD returned = 0;
    wchar_t name[96];

    *outError = ERROR_SUCCESS;
    *skipped = FALSE;
    *outSkipReason = CAP_SKIP_NONE;
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        *outError = GetLastError();
        return FALSE;
    }
    BuildJobName(GetProcessId(process), &created, name, sizeof(name) / sizeof(name[0]));
    job = CreateJobObjectW(NULL, name);
    if (!job) {
        *outError = GetLastError();
        return FALSE;
    }
    if (!IsProcessInJob(process, NULL, &inAnyJob)) {
        *outError = ERROR_NOT_VERIFIED;
        *skipped = TRUE;
        *outSkipReason = CAP_SKIP_UNVERIFIED;
        CloseHandle(job);
        return FALSE;
    }
    if (!IsProcessInJob(process, job, &inOurJob)) {
        *outError = ERROR_NOT_VERIFIED;
        *skipped = TRUE;
        *outSkipReason = CAP_SKIP_UNVERIFIED;
        CloseHandle(job);
        return FALSE;
    }
    if (inAnyJob && !inOurJob && !allowNest) {
        /* Nested rate control compounds across runs, so nesting is opt-in. */
        *outError = ERROR_JOB_CONFLICT;
        *skipped = TRUE;
        *outSkipReason = CAP_SKIP_JOB;
        CloseHandle(job);
        return FALSE;
    }
    memset(&info, 0, sizeof(info));
    info.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    info.CpuRate = CpuRateFromPercent(percent, LimiterGetCpuCount(ALL_PROCESSOR_GROUPS));
    if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation, &info, sizeof(info))) {
        *outError = GetLastError();
        CloseHandle(job);
        return FALSE;
    }
    if (!inOurJob) {
        /* Windows 8+ allows nesting: the process may already be in an external
           job, so associate it with our job as a child of the existing one. */
        if (!AssignProcessToJobObject(job, process)) {
            *outError = GetLastError();
            if (*outError == ERROR_SUCCESS) {
                *outError = ERROR_NOT_VERIFIED;
            }
            *skipped = TRUE;
            *outSkipReason = CAP_SKIP_JOB;
            CloseHandle(job);
            return FALSE;
        }
        if (!IsProcessInJob(process, job, &inOurJob) || !inOurJob) {
            *outError = ERROR_NOT_VERIFIED;
            *skipped = TRUE;
            *outSkipReason = CAP_SKIP_UNVERIFIED;
            CloseHandle(job);
            return FALSE;
        }
    }
    if (!QueryInformationJobObject(
            job, JobObjectCpuRateControlInformation, &check, sizeof(check), &returned) ||
        returned < sizeof(check) ||
        (check.ControlFlags & (JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP)) !=
            (JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) ||
        check.CpuRate != info.CpuRate) {
        *outError = ERROR_NOT_VERIFIED;
        CloseHandle(job);
        return FALSE;
    }
    CloseHandle(job);
    return TRUE;
}

static void EnsureThreadIoPrivilege(void) {
    static BOOL tried = FALSE;
    DWORD ignored;

    if (!tried) {
        tried = TRUE;
        EnablePrivilege(SE_INCREASE_BASE_PRIORITY_NAME, &ignored);
    }
}

static void KeepError(PROCESS_RESULT *result, int step, DWORD error) {
    if (error != ERROR_SUCCESS && result->err[step] == ERROR_SUCCESS) {
        result->err[step] = error;
    }
}

static void MarkThreadFailure(PROCESS_RESULT *result, DWORD error, BOOL counted) {
    if (counted) {
        result->thrTotal++;
        result->ioThrTotal++;
    }
    KeepError(result, STEP_THR, error);
    if (result->err[STEP_IO] == ERROR_SUCCESS) {
        result->err[STEP_IO] = error;
        result->ioThreadFailed = TRUE;
    }
}

static void RunThreadPass(
    const TARGET *targets,
    const BOOL *valid,
    PROCESS_RESULT *results,
    int count
) {
    HANDLE snapshot;
    THREADENTRY32 entry;
    DWORD error;
    int i;

    EnsureThreadIoPrivilege();
    for (i = 0; i < count; i++) {
        if (valid[i]) {
            results[i].attempted[STEP_THR] = TRUE;
        }
    }
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        for (i = 0; i < count; i++) {
            if (valid[i]) {
                MarkThreadFailure(&results[i], error, FALSE);
            }
        }
        return;
    }
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry)) {
        error = GetLastError();
        CloseHandle(snapshot);
        if (error != ERROR_NO_MORE_FILES) {
            for (i = 0; i < count; i++) {
                if (valid[i]) {
                    MarkThreadFailure(&results[i], error, FALSE);
                }
            }
        }
        return;
    }
    do {
        HANDLE thread;
        DWORD actualPid;
        int index = -1;

        for (i = 0; i < count; i++) {
            if (valid[i] && targets[i].pid == entry.th32OwnerProcessID) {
                index = i;
                break;
            }
        }
        if (index < 0) {
            continue;
        }
        thread = OpenThread(
            THREAD_SET_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
            FALSE,
            entry.th32ThreadID);
        if (!thread) {
            error = GetLastError();
            if (error == ERROR_INVALID_PARAMETER) {
                continue;
            }
            MarkThreadFailure(&results[index], error, TRUE);
            continue;
        }
        actualPid = GetProcessIdOfThread(thread);
        if (actualPid == 0) {
            error = GetLastError();
            CloseHandle(thread);
            if (error == ERROR_INVALID_PARAMETER) {
                continue;
            }
            MarkThreadFailure(&results[index], error, TRUE);
            continue;
        }
        if (actualPid != targets[index].pid) {
            CloseHandle(thread);
            continue;
        }
        results[index].thrTotal++;
        results[index].ioThrTotal++;
        if (!SetThreadPriority(thread, THREAD_PRIORITY_IDLE)) {
            KeepError(&results[index], STEP_THR, GetLastError());
        } else if (GetThreadPriority(thread) != THREAD_PRIORITY_IDLE) {
            KeepError(&results[index], STEP_THR, ERROR_NOT_VERIFIED);
        } else {
            results[index].thrSet++;
        }
        {
            DWORD ioError = ERROR_SUCCESS;
            if (SetVeryLowIoPriority(thread, TRUE, &ioError)) {
                results[index].ioThrSet++;
            } else {
                results[index].ioThreadFailed = TRUE;
                KeepError(&results[index], STEP_IO, ioError);
            }
        }
        CloseHandle(thread);
    } while (Thread32Next(snapshot, &entry));
    error = GetLastError();
    CloseHandle(snapshot);
    if (error != ERROR_NO_MORE_FILES) {
        for (i = 0; i < count; i++) {
            if (valid[i]) {
                MarkThreadFailure(&results[i], error, FALSE);
            }
        }
    }
}

static HANDLE OpenTargetProcess(DWORD pid, DWORD *outRights, DWORD *outError) {
    static const DWORD fullRights =
        PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE |
        PROCESS_QUERY_LIMITED_INFORMATION;
    static const DWORD basicRights =
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
    HANDLE process;
    DWORD firstError;

    *outRights = 0;
    *outError = ERROR_SUCCESS;
    process = OpenProcess(fullRights, FALSE, pid);
    if (process) {
        *outRights = fullRights;
        return process;
    }
    firstError = GetLastError();
    process = OpenProcess(basicRights, FALSE, pid);
    if (process) {
        *outRights = basicRights;
        return process;
    }
    *outError = firstError;
    return NULL;
}

static int VerifyTargetName(HANDLE process, const wchar_t *expected, DWORD *outError) {
    wchar_t path[MAX_PATH];
    DWORD length = MAX_PATH;
    const wchar_t *base;

    *outError = ERROR_SUCCESS;
    if (!QueryFullProcessImageNameW(process, 0, path, &length)) {
        *outError = GetLastError();
        return -1;
    }
    base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    if (_wcsicmp(base, expected) != 0) {
        *outError = ERROR_INVALID_NAME;
        return 0;
    }
    return 1;
}

void LimiterApplyBatch(
    const TARGET *targets,
    int count,
    DWORD_PTR affinityMask,
    DWORD cpuCapPercent,
    BOOL allowNest,
    PROCESS_RESULT *results
) {
    HANDLE processes[MAX_TARGETS];
    DWORD rights[MAX_TARGETS];
    BOOL valid[MAX_TARGETS];
    int i;

    if (count > MAX_TARGETS) {
        count = MAX_TARGETS;
    }
    if (count <= 0) {
        return;
    }
    memset(results, 0, sizeof(PROCESS_RESULT) * (size_t)count);
    memset(processes, 0, sizeof(processes));
    memset(valid, 0, sizeof(valid));
    for (i = 0; i < count; i++) {
        int identity;
        DWORD error = ERROR_SUCCESS;

        processes[i] = OpenTargetProcess(targets[i].pid, &rights[i], &error);
        if (!processes[i]) {
            results[i].openErr = error;
            continue;
        }
        results[i].opened = TRUE;
        identity = VerifyTargetName(processes[i], targets[i].name, &error);
        if (identity == 0) {
            results[i].stale = TRUE;
            CloseHandle(processes[i]);
            processes[i] = NULL;
            continue;
        }
        if (identity < 0) {
            results[i].opened = FALSE;
            results[i].openErr = error;
            CloseHandle(processes[i]);
            processes[i] = NULL;
            continue;
        }
        valid[i] = TRUE;
        results[i].attempted[STEP_PRI] = TRUE;
        if (!SetPriorityClass(processes[i], IDLE_PRIORITY_CLASS)) {
            results[i].err[STEP_PRI] = GetLastError();
        } else if (GetPriorityClass(processes[i]) != IDLE_PRIORITY_CLASS) {
            results[i].err[STEP_PRI] = ERROR_NOT_VERIFIED;
        }

        results[i].attempted[STEP_AFF] = TRUE;
        if (!SetProcessAffinityMask(processes[i], affinityMask)) {
            results[i].err[STEP_AFF] = GetLastError();
        } else {
            DWORD_PTR processMask = 0;
            DWORD_PTR systemMask = 0;
            if (!GetProcessAffinityMask(processes[i], &processMask, &systemMask) ||
                processMask != affinityMask) {
                results[i].err[STEP_AFF] = ERROR_NOT_VERIFIED;
            }
        }

        results[i].attempted[STEP_ECO] = TRUE;
        SetEfficiencyMode(processes[i], &results[i].err[STEP_ECO]);

        if (cpuCapPercent > 0) {
            if ((rights[i] & (PROCESS_SET_QUOTA | PROCESS_TERMINATE)) !=
                (PROCESS_SET_QUOTA | PROCESS_TERMINATE)) {
                results[i].capSkipped = TRUE;
                results[i].capSkipErr = ERROR_ACCESS_DENIED;
                results[i].capSkipReason = CAP_SKIP_RIGHTS;
            } else {
                BOOL skipped = FALSE;
                int reason = CAP_SKIP_NONE;
                results[i].attempted[STEP_CAP] = TRUE;
                if (!ApplyCpuCap(
                        processes[i], cpuCapPercent, allowNest,
                        &results[i].err[STEP_CAP], &skipped, &reason)) {
                    if (skipped) {
                        results[i].attempted[STEP_CAP] = FALSE;
                        results[i].capSkipped = TRUE;
                        results[i].capSkipErr = results[i].err[STEP_CAP];
                        results[i].capSkipReason = reason;
                        results[i].err[STEP_CAP] = ERROR_SUCCESS;
                    }
                }
            }
        }

        results[i].attempted[STEP_IO] = TRUE;
        SetVeryLowIoPriority(processes[i], FALSE, &results[i].err[STEP_IO]);

        results[i].attempted[STEP_MEM] = TRUE;
        SetVeryLowMemoryPriority(processes[i], &results[i].err[STEP_MEM]);
    }
    RunThreadPass(targets, valid, results, count);
    for (i = 0; i < count; i++) {
        if (processes[i]) {
            CloseHandle(processes[i]);
        }
    }
}
