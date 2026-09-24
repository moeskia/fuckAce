#include "limiter.h"
#include "config.h"

/* ------------------------------------------------------------------ */
/* Dynamic NTDLL function resolution                                  */
/* ------------------------------------------------------------------ */

typedef LONG (NTAPI *PFN_NtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *PFN_NtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG (NTAPI *PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static PFN_NtSetInformationProcess LoadNtSetInformationProcess(void) {
    static PFN_NtSetInformationProcess fn = NULL;
    static BOOL tried = FALSE;
    HMODULE ntdll;

    if (!tried) {
        tried = TRUE;
        ntdll = GetModuleHandleW(L"ntdll.dll");

        if (ntdll) {
            fn = (PFN_NtSetInformationProcess)(void *)GetProcAddress(
                ntdll, "NtSetInformationProcess");
        }
    }

    return fn;
}

static PFN_NtQueryInformationProcess LoadNtQueryInformationProcess(void) {
    static PFN_NtQueryInformationProcess fn = NULL;
    static BOOL tried = FALSE;
    HMODULE ntdll;

    if (!tried) {
        tried = TRUE;
        ntdll = GetModuleHandleW(L"ntdll.dll");

        if (ntdll) {
            fn = (PFN_NtQueryInformationProcess)(void *)GetProcAddress(
                ntdll, "NtQueryInformationProcess");
        }
    }

    return fn;
}

static PFN_NtSetInformationThread LoadNtSetInformationThread(void) {
    static PFN_NtSetInformationThread fn = NULL;
    static BOOL tried = FALSE;
    HMODULE ntdll;

    if (!tried) {
        tried = TRUE;
        ntdll = GetModuleHandleW(L"ntdll.dll");

        if (ntdll) {
            fn = (PFN_NtSetInformationThread)(void *)GetProcAddress(
                ntdll, "NtSetInformationThread");
        }
    }

    return fn;
}

static PFN_NtQueryInformationThread LoadNtQueryInformationThread(void) {
    static PFN_NtQueryInformationThread fn = NULL;
    static BOOL tried = FALSE;
    HMODULE ntdll;

    if (!tried) {
        tried = TRUE;
        ntdll = GetModuleHandleW(L"ntdll.dll");

        if (ntdll) {
            fn = (PFN_NtQueryInformationThread)(void *)GetProcAddress(
                ntdll, "NtQueryInformationThread");
        }
    }

    return fn;
}

/* ------------------------------------------------------------------ */
/* Privileges & System Info                                           */
/* ------------------------------------------------------------------ */

BOOL LimiterIsRunAsAdmin(void) {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin;
}

static BOOL EnablePrivilege(LPCWSTR name, DWORD *outError) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL ok;

    *outError = ERROR_SUCCESS;

    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hToken)) {
        *outError = GetLastError();
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        *outError = GetLastError();
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);

    ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    *outError = GetLastError();
    CloseHandle(hToken);

    return ok && *outError == ERROR_SUCCESS;
}

BOOL LimiterEnableDebugPrivilege(DWORD *outError) {
    return EnablePrivilege(SE_DEBUG_NAME, outError);
}

/* Logical CPUs of the whole machine. A job's CpuRate is a share of the
   machine, so the rate conversion needs this count, not the group count. */
DWORD LimiterGetLogicalCpuCount(void) {
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);

    if (count == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        count = si.dwNumberOfProcessors;
    }

    return count > 0 ? count : 1;
}

/* Logical CPUs of processor group 0: the group every affinity mask we can
   build with SetProcessAffinityMask applies to. */
DWORD LimiterGetGroupCpuCount(void) {
    DWORD count = GetActiveProcessorCount(0);

    if (count == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        count = si.dwNumberOfProcessors;
    }

    return count > 0 ? count : 1;
}

DWORD_PTR LimiterGetLastCpuAffinityMask(DWORD cpuCount) {
    DWORD bitCount = (DWORD)(sizeof(DWORD_PTR) * 8);

    if (cpuCount < 1) {
        cpuCount = 1;
    }

    if (cpuCount > bitCount) {
        cpuCount = bitCount;
    }

    return ((DWORD_PTR)1) << (cpuCount - 1);
}

/* ------------------------------------------------------------------ */
/* Process Discovery                                                  */
/* ------------------------------------------------------------------ */

int LimiterScanTargets(TARGET *targets, int cap, DWORD *outError, BOOL *outTruncated) {
    HANDLE snapshot;
    PROCESSENTRY32W pe;
    int n = 0;

    *outError = 0;
    *outTruncated = FALSE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        *outError = GetLastError();
        return -1;
    }

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snapshot, &pe)) {
        *outError = GetLastError();
        CloseHandle(snapshot);
        return -1;
    }

    do {
        if (!ConfigIsTargetProcess(pe.szExeFile)) {
            continue;
        }
        if (n < cap) {
            targets[n].pid = pe.th32ProcessID;
            wcsncpy(targets[n].name, pe.szExeFile, TARGET_NAME_MAX - 1);
            targets[n].name[TARGET_NAME_MAX - 1] = 0;
            n++;
        } else {
            *outTruncated = TRUE;
        }
    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);
    return n;
}

/* ------------------------------------------------------------------ */
/* Process Tweaks: EcoQoS, I/O, Memory, CPU Cap, Threads              */
/* ------------------------------------------------------------------ */

static BOOL EnableEfficiencyMode(HANDLE hProcess, DWORD *outError) {
    PROCESS_POWER_THROTTLING_STATE state = {
        PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED
    };
    PROCESS_POWER_THROTTLING_STATE check;

    *outError = ERROR_SUCCESS;

    if (!SetProcessInformation(
            hProcess,
            PIC_POWER_THROTTLING,
            &state,
            sizeof(state))) {
        *outError = GetLastError();
        return FALSE;
    }

    /* A read-back that fails is not a pass: we could not confirm anything. */
    if (!GetProcessInformation(
            hProcess,
            PIC_POWER_THROTTLING,
            &check,
            sizeof(check))) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    if (!(check.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED)) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    return TRUE;
}

/* I/O priority has no Win32 API; it is set and read back through
   NtSetInformationProcess / NtQueryInformationProcess with
   ProcessIoPriority (PROCESSINFOCLASS 0x21). */
static BOOL SetVeryLowIoPriority(HANDLE hProcess, DWORD *outError) {
    PFN_NtSetInformationProcess setFn = LoadNtSetInformationProcess();
    PFN_NtQueryInformationProcess queryFn = LoadNtQueryInformationProcess();
    ULONG hint = IO_PRIORITY_VERY_LOW;
    ULONG check = 0;
    LONG status;

    *outError = ERROR_SUCCESS;

    if (!setFn) {
        *outError = ERROR_NOT_SUPPORTED;
        return FALSE;
    }

    status = setFn(hProcess, NT_PROCESS_IO_PRIORITY, &hint, sizeof(hint));

    if (!NT_SUCCESS(status)) {
        *outError = (DWORD)status;
        return FALSE;
    }

    if (!queryFn) {
        *outError = ERROR_NOT_SUPPORTED;
        return FALSE;
    }

    status = queryFn(hProcess, NT_PROCESS_IO_PRIORITY, &check, sizeof(check), NULL);

    if (!NT_SUCCESS(status)) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    if (check != IO_PRIORITY_VERY_LOW) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    return TRUE;
}

static BOOL SetVeryLowMemoryPriority(HANDLE hProcess, DWORD *outError) {
    MEMORY_PRIORITY_INFORMATION mp;
    MEMORY_PRIORITY_INFORMATION check;

    *outError = ERROR_SUCCESS;
    mp.MemoryPriority = MEMORY_PRIORITY_VERY_LOW;

    if (!SetProcessInformation(
            hProcess,
            PIC_MEMORY_PRIORITY,
            &mp,
            sizeof(mp))) {
        *outError = GetLastError();
        return FALSE;
    }

    if (!GetProcessInformation(
            hProcess,
            PIC_MEMORY_PRIORITY,
            &check,
            sizeof(check))) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    if (check.MemoryPriority != MEMORY_PRIORITY_VERY_LOW) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    return TRUE;
}

/* A job's CpuRate is a share of the whole machine, not of one logical CPU,
   so a per-CPU percentage has to be scaled by the processor count. */
static DWORD CpuRateFromPercent(DWORD percent, DWORD cpuCount) {
    unsigned long long rate;

    if (cpuCount < 1) {
        cpuCount = 1;
    }
    if (percent < 1) {
        percent = 1;
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

/* Hard CPU ceiling. A process cannot leave a job it did not create, so
   unlike the other knobs this one cannot be undone by the target.
   Needs PROCESS_SET_QUOTA | PROCESS_TERMINATE on the handle. */
static BOOL ApplyCpuCap(HANDLE hProcess, DWORD percent, DWORD *outError) {
    HANDLE job;
    ACE_CPU_RATE info;
    ACE_CPU_RATE check;
    DWORD returned = 0;

    *outError = ERROR_SUCCESS;

    if (percent < 1) {
        percent = 1;
    }
    if (percent > 100) {
        percent = 100;
    }

    job = CreateJobObjectW(NULL, NULL);

    if (!job) {
        *outError = GetLastError();
        return FALSE;
    }

    info.ControlFlags =
        JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    info.CpuRate = CpuRateFromPercent(percent, LimiterGetLogicalCpuCount());

    if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation, &info, sizeof(info))) {
        *outError = GetLastError();
        CloseHandle(job);
        return FALSE;
    }

    if (!AssignProcessToJobObject(job, hProcess)) {
        *outError = GetLastError();
        CloseHandle(job);
        return FALSE;
    }

    if (!QueryInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            &check,
            sizeof(check),
            &returned)) {
        *outError = ERROR_NOT_VERIFIED;
        CloseHandle(job);
        return FALSE;
    }

    if (returned < sizeof(check) ||
        !(check.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE) ||
        !(check.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP)) {
        *outError = ERROR_NOT_VERIFIED;
        CloseHandle(job);
        return FALSE;
    }

    /* Documented: the job survives while its processes run, so dropping
       our handle keeps the cap in force without holding the process. */
    CloseHandle(job);
    return TRUE;
}

/* NtSetInformationThread(ThreadIoPriority) is documented to need
   SeIncreaseBasePriorityPrivilege. Best effort: if it cannot be enabled the
   per-thread set/read-back still reports the real failure. */
static void EnsureThreadIoPrivilege(void) {
    static BOOL tried = FALSE;
    DWORD ignored;

    if (!tried) {
        tried = TRUE;
        EnablePrivilege(SE_INCREASE_BASE_PRIORITY_NAME, &ignored);
    }
}

/* Per-thread I/O priority has no Win32 API either: set and read back through
   NtSetInformationThread / NtQueryInformationThread with ThreadIoPriority
   (THREADINFOCLASS 0x16). */
static BOOL SetVeryLowThreadIoPriority(HANDLE hThread, DWORD *outError) {
    PFN_NtSetInformationThread setFn = LoadNtSetInformationThread();
    PFN_NtQueryInformationThread queryFn = LoadNtQueryInformationThread();
    ULONG hint = IO_PRIORITY_VERY_LOW;
    ULONG check = 0;
    LONG status;

    *outError = ERROR_SUCCESS;

    if (!setFn) {
        *outError = ERROR_NOT_SUPPORTED;
        return FALSE;
    }

    status = setFn(hThread, NT_THREAD_IO_PRIORITY, &hint, sizeof(hint));

    if (!NT_SUCCESS(status)) {
        *outError = (DWORD)status;
        return FALSE;
    }

    if (!queryFn) {
        *outError = ERROR_NOT_SUPPORTED;
        return FALSE;
    }

    status = queryFn(hThread, NT_THREAD_IO_PRIORITY, &check, sizeof(check), NULL);

    if (!NT_SUCCESS(status)) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    if (check != IO_PRIORITY_VERY_LOW) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    return TRUE;
}

typedef struct _THREAD_PASS {
    BOOL enumerated;                    /* thread list was obtained */
    DWORD enumErr;
    int prioSet;                        /* threads lowered to IDLE */
    int prioTotal;
    DWORD prioErr;
    int ioSet;                          /* threads lowered to VeryLow I/O */
    int ioTotal;                        /* only threads we could open */
    DWORD ioErr;
} THREAD_PASS;

/* SetPriorityClass only shifts the base priority of threads that are at
   their normal value, so pin every thread explicitly and read each one
   back. A thread's I/O priority is likewise a per-thread property, so the
   process-wide default set earlier does not retroactively cover threads
   that already exist — walk them here. Threads that exit mid-walk are
   skipped, not counted as failures. Threads we cannot open are counted
   against THR (as before) but not against IO, because they still inherit
   the process-level I/O default. */
static void RunThreadPass(DWORD pid, THREAD_PASS *out) {
    HANDLE snapshot;
    THREADENTRY32 te;
    DWORD firstPrioErr = ERROR_SUCCESS;
    DWORD firstIoErr = ERROR_SUCCESS;
    BOOL prioFailed = FALSE;
    BOOL ioFailed = FALSE;

    memset(out, 0, sizeof(*out));

    EnsureThreadIoPrivilege();

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        out->enumErr = GetLastError();
        return;
    }

    memset(&te, 0, sizeof(te));
    te.dwSize = sizeof(te);

    if (!Thread32First(snapshot, &te)) {
        DWORD err = GetLastError();
        CloseHandle(snapshot);

        if (err == ERROR_NO_MORE_FILES) {
            out->enumerated = TRUE;
            return;
        }

        out->enumErr = err;
        return;
    }

    out->enumerated = TRUE;

    do {
        HANDLE hThread;
        DWORD err;

        if (te.th32OwnerProcessID != pid) {
            continue;
        }

        hThread = OpenThread(
            THREAD_SET_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
            FALSE, te.th32ThreadID);

        if (!hThread) {
            /* A query right may be denied where set is allowed; keep the
               thread priority part working even then. */
            hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);
        }

        if (!hThread) {
            err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER) {
                continue;   /* thread exited between snapshot and open */
            }
            out->prioTotal++;
            prioFailed = TRUE;
            if (firstPrioErr == ERROR_SUCCESS) {
                firstPrioErr = err;
            }
            continue;
        }

        out->prioTotal++;
        out->ioTotal++;

        if (!SetThreadPriority(hThread, THREAD_PRIORITY_IDLE)) {
            prioFailed = TRUE;
            if (firstPrioErr == ERROR_SUCCESS) {
                firstPrioErr = GetLastError();
            }
        } else if (GetThreadPriority(hThread) != THREAD_PRIORITY_IDLE) {
            prioFailed = TRUE;
            if (firstPrioErr == ERROR_SUCCESS) {
                firstPrioErr = ERROR_NOT_VERIFIED;
            }
        } else {
            out->prioSet++;
        }

        {
            DWORD ioErr = ERROR_SUCCESS;

            if (SetVeryLowThreadIoPriority(hThread, &ioErr)) {
                out->ioSet++;
            } else {
                ioFailed = TRUE;
                if (firstIoErr == ERROR_SUCCESS) {
                    firstIoErr = ioErr;
                }
            }
        }

        CloseHandle(hThread);
    } while (Thread32Next(snapshot, &te));

    CloseHandle(snapshot);

    if (prioFailed) {
        out->prioErr = firstPrioErr;
    }
    if (ioFailed) {
        out->ioErr = firstIoErr;
    }
}

static HANDLE OpenTargetProcess(DWORD pid, DWORD *outRights, DWORD *outError) {
    static const DWORD kFullRights =
        PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE |
        PROCESS_QUERY_LIMITED_INFORMATION;
    static const DWORD kBasicRights =
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
    DWORD firstErr = ERROR_SUCCESS;
    HANDLE hProcess;

    *outRights = 0;
    *outError = ERROR_SUCCESS;

    hProcess = OpenProcess(kFullRights, FALSE, pid);
    if (hProcess) {
        *outRights = kFullRights;
        return hProcess;
    }
    firstErr = GetLastError();

    hProcess = OpenProcess(kBasicRights, FALSE, pid);
    if (hProcess) {
        *outRights = kBasicRights;
        return hProcess;
    }

    hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hProcess) {
        *outRights = PROCESS_SET_INFORMATION;
        return hProcess;
    }

    *outError = firstErr;
    return NULL;
}

/* Guards against a pid that was recycled between scan and open. If the
   name cannot be read we assume the handle is still the right process. */
static BOOL VerifyTargetName(HANDLE hProcess, const wchar_t *expected) {
    wchar_t path[MAX_PATH];
    DWORD len = MAX_PATH;
    const wchar_t *base;

    if (!QueryFullProcessImageNameW(hProcess, 0, path, &len)) {
        return TRUE;
    }

    base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;

    return _wcsicmp(base, expected) == 0;
}

PROCESS_RESULT LimiterApplySettings(
    DWORD pid,
    const wchar_t *expectedName,
    DWORD_PTR affinityMask,
    DWORD cpuCapPercent
) {
    PROCESS_RESULT r;
    HANDLE hProcess;
    DWORD rights = 0;
    DWORD openErr = 0;
    BOOL haveJobRights;
    BOOL procIoOk;
    int i;

    memset(&r, 0, sizeof(r));

    hProcess = OpenTargetProcess(pid, &rights, &openErr);

    if (!hProcess) {
        r.openErr = openErr;
        return r;
    }

    r.opened = TRUE;

    if (!VerifyTargetName(hProcess, expectedName)) {
        r.stale = TRUE;
        CloseHandle(hProcess);
        return r;
    }

    haveJobRights = (rights & PROCESS_SET_QUOTA) && (rights & PROCESS_TERMINATE);

    r.attempted[STEP_PRI] = TRUE;
    if (SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS)) {
        if (GetPriorityClass(hProcess) == IDLE_PRIORITY_CLASS) {
            r.ok[STEP_PRI] = TRUE;
        } else {
            r.err[STEP_PRI] = ERROR_NOT_VERIFIED;
        }
    } else {
        r.err[STEP_PRI] = GetLastError();
    }

    r.attempted[STEP_AFF] = TRUE;
    if (SetProcessAffinityMask(hProcess, affinityMask)) {
        DWORD_PTR procMask = 0;
        DWORD_PTR sysMask = 0;

        if (GetProcessAffinityMask(hProcess, &procMask, &sysMask) &&
            procMask != affinityMask) {
            r.err[STEP_AFF] = ERROR_NOT_VERIFIED;
        } else {
            r.ok[STEP_AFF] = TRUE;
        }
    } else {
        r.err[STEP_AFF] = GetLastError();
    }

    r.attempted[STEP_ECO] = TRUE;
    if (!EnableEfficiencyMode(hProcess, &r.err[STEP_ECO])) {
        r.ok[STEP_ECO] = FALSE;
    } else {
        r.ok[STEP_ECO] = TRUE;
    }

    if (cpuCapPercent > 0 && haveJobRights) {
        r.attempted[STEP_CAP] = TRUE;
        if (ApplyCpuCap(hProcess, cpuCapPercent, &r.err[STEP_CAP])) {
            r.ok[STEP_CAP] = TRUE;
        }
    }

    r.attempted[STEP_IO] = TRUE;
    procIoOk = SetVeryLowIoPriority(hProcess, &r.err[STEP_IO]);
    if (procIoOk) {
        r.ok[STEP_IO] = TRUE;
    }

    r.attempted[STEP_MEM] = TRUE;
    if (SetVeryLowMemoryPriority(hProcess, &r.err[STEP_MEM])) {
        r.ok[STEP_MEM] = TRUE;
    }

    CloseHandle(hProcess);

    {
        THREAD_PASS tp;

        RunThreadPass(pid, &tp);

        r.attempted[STEP_THR] = TRUE;
        r.thrSet = tp.prioSet;
        r.thrTotal = tp.prioTotal;

        if (tp.enumerated && tp.prioErr == ERROR_SUCCESS) {
            r.ok[STEP_THR] = TRUE;
        } else {
            r.err[STEP_THR] = tp.enumerated ? tp.prioErr : tp.enumErr;
        }

        /* The IO step is process-wide plus per-thread; it only counts as
           applied when the process-level set stuck and every thread we could
           reach also took the setting. If the thread list itself could not
           be obtained, fall back to the process-level verdict. */
        r.ioThrSet = tp.ioSet;
        r.ioThrTotal = tp.ioTotal;

        if (procIoOk && tp.enumerated && tp.ioErr != ERROR_SUCCESS) {
            r.ok[STEP_IO] = FALSE;
            r.err[STEP_IO] = tp.ioErr;
            r.ioThreadsFailed = TRUE;
        }
    }

    for (i = 0; i < STEP_COUNT; i++) {
        if (r.attempted[i]) {
            r.attemptCount++;
            if (r.ok[i]) {
                r.okCount++;
            }
        }
    }

    return r;
}
