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
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
typedef struct _PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} PROCESS_POWER_THROTTLING_STATE;
#endif

#define COLOR_DEFAULT 7
#define COLOR_GREEN   10
#define COLOR_RED     12
#define COLOR_YELLOW  14

#define STEP_COUNT 3

typedef struct _PROCESS_RESULT {
    BOOL opened;
    int okCount;
} PROCESS_RESULT;

static HANDLE g_console;

static void PrintColorV(WORD color, const char *fmt, va_list args) {
    SetConsoleTextAttribute(g_console, color);
    vprintf(fmt, args);
    SetConsoleTextAttribute(g_console, COLOR_DEFAULT);
}

static void PrintOk(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    PrintColorV(COLOR_GREEN, fmt, args);
    va_end(args);
}

static void PrintFail(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    PrintColorV(COLOR_RED, fmt, args);
    va_end(args);
}

static void PrintWarn(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    PrintColorV(COLOR_YELLOW, fmt, args);
    va_end(args);
}

static void PrintHint(DWORD err) {
    const char *hint = NULL;

    switch (err) {
    case ERROR_ACCESS_DENIED:
        hint = "access denied, process may be protected";
        break;
    case ERROR_INVALID_PARAMETER:
        hint = "invalid parameter, operation may be unsupported";
        break;
    case ERROR_NOT_SUPPORTED:
        hint = "operation not supported on this system";
        break;
    }

    if (hint) {
        PrintFail("            hint: %s\n", hint);
    }
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
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin;
}

static BOOL RelaunchAsAdmin(void) {
    wchar_t exePath[MAX_PATH];

    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        return FALSE;
    }

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;

    return ShellExecuteExW(&sei);
}

static BOOL EnableDebugPrivilege(DWORD *outError) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    *outError = ERROR_SUCCESS;

    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hToken)) {
        *outError = GetLastError();
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        *outError = GetLastError();
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);

    BOOL ok = AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(tp),
        NULL,
        NULL);

    *outError = GetLastError();
    CloseHandle(hToken);

    return ok && *outError == ERROR_SUCCESS;
}

static BOOL EnableEfficiencyMode(HANDLE hProcess, DWORD *outError) {
    PROCESS_POWER_THROTTLING_STATE state = {
        PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED
    };

    if (SetProcessInformation(
            hProcess,
            (PROCESS_INFORMATION_CLASS)ProcessPowerThrottling,
            &state,
            sizeof(state))) {
        return TRUE;
    }

    *outError = GetLastError();
    return FALSE;
}

static DWORD GetLogicalCpuCount(void) {
    SYSTEM_INFO si;

    GetSystemInfo(&si);

    return si.dwNumberOfProcessors > 0 ? si.dwNumberOfProcessors : 1;
}

static DWORD_PTR GetLastCpuAffinityMask(DWORD cpuCount) {
    DWORD bitCount = (DWORD)(sizeof(DWORD_PTR) * 8);

    if (cpuCount < 1) {
        cpuCount = 1;
    }

    if (cpuCount > bitCount) {
        cpuCount = bitCount;
    }

    return ((DWORD_PTR)1) << (cpuCount - 1);
}

static BOOL IsTargetProcess(const wchar_t *name) {
    return
        _wcsicmp(name, L"SGuard64.exe") == 0 ||
        _wcsicmp(name, L"SGuardSvc64.exe") == 0;
}

static PROCESS_RESULT ConfigureProcess(
    int index,
    DWORD pid,
    const wchar_t *processName,
    DWORD targetCpu,
    DWORD_PTR affinityMask
) {
    PROCESS_RESULT result = {0};

    printf("\n #%-2d %ls  (PID %lu)\n", index, processName, pid);

    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);

    if (!hProcess) {
        DWORD err = GetLastError();
        PrintFail("      [-] %-11s failed (Error=%lu)\n", "open", err);
        PrintHint(err);
        return result;
    }

    result.opened = TRUE;

    if (SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS)) {
        result.okCount++;
        PrintOk("      [+] %-11s %s\n", "priority", "IDLE");
    } else {
        DWORD err = GetLastError();
        PrintFail("      [-] %-11s failed (Error=%lu)\n", "priority", err);
        PrintHint(err);
    }

    if (SetProcessAffinityMask(hProcess, affinityMask)) {
        result.okCount++;
        PrintOk("      [+] %-11s CPU %lu\n", "affinity", targetCpu);
    } else {
        DWORD err = GetLastError();
        PrintFail("      [-] %-11s failed (Error=%lu)\n", "affinity", err);
        PrintHint(err);
    }

    DWORD ecoErr = ERROR_SUCCESS;

    if (EnableEfficiencyMode(hProcess, &ecoErr)) {
        result.okCount++;
        PrintOk("      [+] %-11s %s\n", "efficiency", "EcoQoS");
    } else {
        PrintFail("      [-] %-11s failed (Error=%lu)\n", "efficiency", ecoErr);
        PrintHint(ecoErr);
    }

    CloseHandle(hProcess);

    return result;
}

int wmain(void) {
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);

    if (!IsRunAsAdmin()) {
        printf("Requesting administrator privileges...\n");

        if (RelaunchAsAdmin()) {
            return 0;
        }

        DWORD err = GetLastError();

        if (err == ERROR_CANCELLED) {
            PrintFail("FAILED: elevation cancelled by user\n");
        } else {
            PrintFail("FAILED: could not request elevation (Error=%lu)\n", err);
        }

        PauseBeforeExit();
        return 1;
    }

    printf("================================================\n");
    printf(" fuckAce - SGuard priority/affinity/efficiency\n");
    printf("================================================\n\n");

    PrintOk(" [+] administrator privileges\n");

    DWORD dbgErr = ERROR_SUCCESS;

    if (EnableDebugPrivilege(&dbgErr)) {
        PrintOk(" [+] SeDebugPrivilege enabled\n");
    } else {
        PrintWarn(" [!] SeDebugPrivilege not enabled (Error=%lu)\n", dbgErr);
    }

    DWORD cpuCount = GetLogicalCpuCount();
    DWORD_PTR affinityMask = GetLastCpuAffinityMask(cpuCount);

    printf("\n logical CPUs : %lu\n", cpuCount);
    printf(" target CPU   : %lu\n", cpuCount - 1);
    printf(" affinity     : 0x%llX\n", (unsigned long long)affinityMask);
    printf(" targets      : SGuard64.exe, SGuardSvc64.exe\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintFail("\n[FAIL] CreateToolhelp32Snapshot failed (Error=%lu)\n", GetLastError());
        PauseBeforeExit();
        return 1;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snapshot, &pe)) {
        PrintFail("\n[FAIL] Process32FirstW failed (Error=%lu)\n", GetLastError());
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
            foundCount,
            pe.th32ProcessID,
            pe.szExeFile,
            cpuCount - 1,
            affinityMask
        );

        if (r.opened && r.okCount == STEP_COUNT) {
            fullSuccessCount++;
        } else if (r.opened && r.okCount > 0) {
            partialSuccessCount++;
        } else {
            failedCount++;
        }

    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);

    printf("\n------------------------------------------------\n");
    printf(" Summary\n");
    printf("------------------------------------------------\n");
    printf(" found        : %d\n", foundCount);
    printf(" fully ok     : %d\n", fullSuccessCount);
    printf(" partial      : %d\n", partialSuccessCount);
    printf(" failed       : %d\n", failedCount);

    int exitCode;

    if (foundCount == 0) {
        PrintFail("\n RESULT: FAILED - no target process found\n");
        exitCode = 1;
    } else if (fullSuccessCount == foundCount) {
        PrintOk("\n RESULT: SUCCESS - all %d processes fully configured\n", foundCount);
        exitCode = 0;
    } else if (fullSuccessCount > 0 || partialSuccessCount > 0) {
        PrintWarn("\n RESULT: PARTIAL - %d of %d processes fully configured\n", fullSuccessCount, foundCount);
        exitCode = 2;
    } else {
        PrintFail("\n RESULT: FAILED - found %d processes but no setting applied\n", foundCount);
        PrintFail("        access denied, protected process, or unsupported operation\n");
        exitCode = 3;
    }

    PauseBeforeExit();

    return exitCode;
}
