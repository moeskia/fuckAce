#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include <stdarg.h>

#ifndef ProcessPowerThrottling
#define ProcessPowerThrottling 4
#endif

#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#endif

#ifndef PROCESS_POWER_THROTTLING_EXECUTION_SPEED
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
#endif

#define COLOR_DEFAULT 7
#define COLOR_GREEN   10
#define COLOR_RED     12
#define COLOR_YELLOW  14

typedef struct _PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} PROCESS_POWER_THROTTLING_STATE;

typedef BOOL (WINAPI *PFN_SetProcessInformation)(
    HANDLE hProcess,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    LPVOID ProcessInformation,
    DWORD ProcessInformationSize
);

typedef struct _PROCESS_RESULT {
    BOOL opened;
    BOOL priority_ok;
    BOOL affinity_ok;
    BOOL efficiency_ok;
} PROCESS_RESULT;

static void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

static void PrintOk(const char *fmt, ...) {
    va_list args;

    SetColor(COLOR_GREEN);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    SetColor(COLOR_DEFAULT);
}

static void PrintFail(const char *fmt, ...) {
    va_list args;

    SetColor(COLOR_RED);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    SetColor(COLOR_DEFAULT);
}

static void PrintWarn(const char *fmt, ...) {
    va_list args;

    SetColor(COLOR_YELLOW);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    SetColor(COLOR_DEFAULT);
}

static void PauseBeforeExit(void) {
    printf("\nPress Enter to exit...");
    fflush(stdout);
    getchar();
}

static BOOL IsRunAsAdmin(void) {
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
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

static BOOL RelaunchAsAdmin(void) {
    wchar_t exePath[MAX_PATH];

    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        return FALSE;
    }

    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));

    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;

    return ShellExecuteExW(&sei);
}

static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    ZeroMemory(&tp, sizeof(tp));

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);

    if (!AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(tp),
            NULL,
            NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    DWORD err = GetLastError();

    CloseHandle(hToken);

    return err == ERROR_SUCCESS;
}

static BOOL EnableEfficiencyMode(HANDLE hProcess, DWORD *outError) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    if (!hKernel32) {
        if (outError) {
            *outError = GetLastError();
        }
        return FALSE;
    }

    PFN_SetProcessInformation pSetProcessInformation =
        (PFN_SetProcessInformation)GetProcAddress(
            hKernel32,
            "SetProcessInformation"
        );

    if (!pSetProcessInformation) {
        if (outError) {
            *outError = GetLastError();
        }
        return FALSE;
    }

    PROCESS_POWER_THROTTLING_STATE state;
    ZeroMemory(&state, sizeof(state));

    state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    state.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;

    SetLastError(ERROR_SUCCESS);

    BOOL ok = pSetProcessInformation(
        hProcess,
        (PROCESS_INFORMATION_CLASS)ProcessPowerThrottling,
        &state,
        sizeof(state)
    );

    if (!ok && outError) {
        *outError = GetLastError();
    }

    return ok;
}

static DWORD GetLogicalCpuCount(void) {
    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(si));

    GetSystemInfo(&si);

    return si.dwNumberOfProcessors > 0 ? si.dwNumberOfProcessors : 1;
}

static DWORD_PTR GetLastCpuAffinityMask(DWORD cpuCount) {
    DWORD bitCount = (DWORD)(sizeof(DWORD_PTR) * 8);

    if (cpuCount == 0) {
        return 1;
    }

    if (cpuCount >= bitCount) {
        return ((DWORD_PTR)1) << (bitCount - 1);
    }

    return ((DWORD_PTR)1) << (cpuCount - 1);
}

static BOOL IsTargetProcess(const wchar_t *name) {
    return
        _wcsicmp(name, L"SGuard64.exe") == 0 ||
        _wcsicmp(name, L"SGuardSvc64.exe") == 0;
}

static void PrintErrorHint(DWORD err) {
    if (err == ERROR_ACCESS_DENIED) {
        PrintFail("  Hint: ERROR_ACCESS_DENIED. The process may be protected.\n");
    } else if (err == ERROR_INVALID_PARAMETER) {
        PrintFail("  Hint: ERROR_INVALID_PARAMETER. This operation may not be supported.\n");
    } else if (err == ERROR_NOT_SUPPORTED) {
        PrintFail("  Hint: ERROR_NOT_SUPPORTED. Efficiency Mode may not be supported.\n");
    }
}

static PROCESS_RESULT ConfigureProcess(
    DWORD pid,
    const wchar_t *processName,
    DWORD_PTR affinityMask
) {
    PROCESS_RESULT result;
    ZeroMemory(&result, sizeof(result));

    wprintf(L"\nProcess: %ls  PID=%lu\n", processName, pid);

    HANDLE hProcess = OpenProcess(
        PROCESS_SET_INFORMATION |
        PROCESS_QUERY_INFORMATION |
        PROCESS_SET_LIMITED_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );

    if (!hProcess) {
        DWORD err = GetLastError();
        PrintFail("  [FAIL] OpenProcess failed. Error=%lu\n", err);
        PrintErrorHint(err);
        return result;
    }

    result.opened = TRUE;

    SetLastError(ERROR_SUCCESS);
    if (SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS)) {
        result.priority_ok = TRUE;
        PrintOk("  [OK] Priority set to IDLE_PRIORITY_CLASS.\n");
    } else {
        DWORD err = GetLastError();
        PrintFail("  [FAIL] SetPriorityClass failed. Error=%lu\n", err);
        PrintErrorHint(err);
    }

    SetLastError(ERROR_SUCCESS);
    if (SetProcessAffinityMask(hProcess, affinityMask)) {
        result.affinity_ok = TRUE;
        PrintOk("  [OK] CPU affinity set to last logical CPU.\n");
    } else {
        DWORD err = GetLastError();
        PrintFail("  [FAIL] SetProcessAffinityMask failed. Error=%lu\n", err);
        PrintErrorHint(err);
    }

    DWORD efficiencyErr = ERROR_SUCCESS;
    if (EnableEfficiencyMode(hProcess, &efficiencyErr)) {
        result.efficiency_ok = TRUE;
        PrintOk("  [OK] Efficiency Mode enabled.\n");
    } else {
        PrintFail("  [FAIL] Enable Efficiency Mode failed. Error=%lu\n", efficiencyErr);
        PrintErrorHint(efficiencyErr);
    }

    CloseHandle(hProcess);

    return result;
}

int wmain(void) {
    SetConsoleOutputCP(CP_UTF8);

    if (!IsRunAsAdmin()) {
        printf("Not running as administrator. Requesting elevation...\n");

        if (RelaunchAsAdmin()) {
            return 0;
        }

        PrintFail("FAILED: Could not request elevation. Error=%lu\n", GetLastError());
        PauseBeforeExit();
        return 1;
    }

    printf("SGuard priority / affinity / efficiency tool\n");
    printf("-------------------------------------------\n");

    PrintOk("[OK] Running as Administrator.\n");

    SetLastError(ERROR_SUCCESS);
    if (EnableDebugPrivilege()) {
        PrintOk("[OK] SeDebugPrivilege enabled.\n");
    } else {
        PrintWarn("[WARN] SeDebugPrivilege not enabled. Error=%lu\n", GetLastError());
        PrintWarn("       Continue anyway. Protected processes may still fail.\n");
    }

    DWORD cpuCount = GetLogicalCpuCount();
    DWORD targetCpu = cpuCount - 1;
    DWORD_PTR affinityMask = GetLastCpuAffinityMask(cpuCount);

    printf("\nCPU Count      = %lu\n", cpuCount);
    printf("Target CPU     = CPU %lu\n", targetCpu);
    printf("Affinity Mask  = 0x%p\n", (void *)affinityMask);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintFail("\n[FAIL] CreateToolhelp32Snapshot failed. Error=%lu\n", GetLastError());
        PauseBeforeExit();
        return 1;
    }

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snapshot, &pe)) {
        PrintFail("\n[FAIL] Process32FirstW failed. Error=%lu\n", GetLastError());
        CloseHandle(snapshot);
        PauseBeforeExit();
        return 1;
    }

    int foundCount = 0;
    int fullSuccessCount = 0;
    int partialSuccessCount = 0;
    int failedCount = 0;

    do {
        if (!IsTargetProcess(pe.szExeFile)) {
            continue;
        }

        foundCount++;

        PROCESS_RESULT r = ConfigureProcess(
            pe.th32ProcessID,
            pe.szExeFile,
            affinityMask
        );

        if (r.opened && r.priority_ok && r.affinity_ok && r.efficiency_ok) {
            fullSuccessCount++;
        } else if (r.opened && (r.priority_ok || r.affinity_ok || r.efficiency_ok)) {
            partialSuccessCount++;
        } else {
            failedCount++;
        }

    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);

    printf("\n-------------------------------------------\n");
    printf("Summary\n");
    printf("-------------------------------------------\n");
    printf("Found processes       = %d\n", foundCount);
    printf("Fully successful      = %d\n", fullSuccessCount);
    printf("Partially successful  = %d\n", partialSuccessCount);
    printf("Failed                = %d\n", failedCount);

    if (foundCount == 0) {
        PrintFail("\nFINAL RESULT: FAILED - no target process found.\n");
    } else if (fullSuccessCount == foundCount) {
        PrintOk("\nFINAL RESULT: SUCCESS - all target processes were fully configured.\n");
    } else if (fullSuccessCount > 0 || partialSuccessCount > 0) {
        PrintWarn("\nFINAL RESULT: PARTIAL SUCCESS - some settings failed.\n");
    } else {
        PrintFail("\nFINAL RESULT: FAILED - target processes were found, but no setting was applied.\n");
        PrintFail("Reason: access denied, protected process, or unsupported operation.\n");
    }

    PauseBeforeExit();

    return 0;
}