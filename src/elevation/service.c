#include "elevation/elevate.h"
#include "app/config.h"
#include "system/titoken.h"
#include "elevation/elevate_internal.h"

#include <winsvc.h>

static BOOL StartTrustedInstallerService(
    DWORD *outPid,
    DWORD *outError,
    wchar_t *stage,
    size_t stageSize,
    BOOL *outStarted
) {
    SC_HANDLE manager;
    SC_HANDLE service;
    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0;
    int attempt;
    BOOL ok = FALSE;

    if (outStarted) {
        *outStarted = FALSE;
    }
    *outError = ERROR_SUCCESS;
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) {
        *outError = GetLastError();
        wcsncpy(stage, L"open SCM failed", stageSize - 1);
        stage[stageSize - 1] = 0;
        return FALSE;
    }
    service = OpenServiceW(
        manager,
        ELEVATE_TI_SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE);
    if (!service) {
        *outError = GetLastError();
        wcsncpy(stage, L"open TrustedInstaller service failed", stageSize - 1);
        stage[stageSize - 1] = 0;
        CloseServiceHandle(manager);
        return FALSE;
    }
    if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&status,
            sizeof(status),
            &needed)) {
        *outError = GetLastError();
        wcsncpy(stage, L"query service status failed", stageSize - 1);
        stage[stageSize - 1] = 0;
        goto done;
    }
    if (status.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(service, 0, NULL)) {
            DWORD startError = GetLastError();
            if (startError != ERROR_SERVICE_ALREADY_RUNNING) {
                *outError = startError;
                wcsncpy(stage, L"StartService failed", stageSize - 1);
                stage[stageSize - 1] = 0;
                goto done;
            }
        } else if (outStarted) {
            *outStarted = TRUE;
        }
    }
    for (attempt = 0; attempt < ELEVATE_SERVICE_WAIT_MS / 100; attempt++) {
        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&status,
                sizeof(status),
                &needed)) {
            *outError = GetLastError();
            wcsncpy(stage, L"query service status failed", stageSize - 1);
            stage[stageSize - 1] = 0;
            goto done;
        }
        if (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0) {
            *outPid = status.dwProcessId;
            ok = TRUE;
            goto done;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            *outError = ERROR_SERVICE_NOT_ACTIVE;
            wcsncpy(stage, L"service stopped again immediately", stageSize - 1);
            stage[stageSize - 1] = 0;
            goto done;
        }
        Sleep(100);
    }
    *outError = ERROR_TIMEOUT;
    wcsncpy(stage, L"service never reached RUNNING", stageSize - 1);
    stage[stageSize - 1] = 0;
done:
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return ok;
}

void ElevateReleaseService(void) {
    SC_HANDLE manager;
    SC_HANDLE service;
    SERVICE_STATUS status;
    int attempt;

    if (!g_elevate.tiers[ELEVATE_TIER_TI].startedService || g_elevate.keepService) {
        return;
    }
    g_elevate.tiers[ELEVATE_TIER_TI].startedService = FALSE;
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) {
        return;
    }
    service = OpenServiceW(manager, ELEVATE_TI_SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service) {
        if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
            for (attempt = 0; attempt < 50; attempt++) {
                if (!QueryServiceStatus(service, &status) ||
                    status.dwCurrentState == SERVICE_STOPPED) {
                    break;
                }
                Sleep(100);
            }
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
}

BOOL ElevateDuplicateTrustedInstallerToken(DWORD pid, HANDLE *outToken, DWORD *outError) {
    HANDLE token = NULL;

    if (!ElevateDuplicateTokenFromPid(pid, &token, outError)) {
        return FALSE;
    }
    if (!TiTokenGroupEnabled(token, TITOKEN_TI_SID_STRING)) {
        CloseHandle(token);
        *outError = ERROR_INVALID_ACCOUNT_NAME;
        return FALSE;
    }
    *outToken = token;
    return TRUE;
}

static BOOL FindTrustedInstallerToken(HANDLE *outToken, DWORD *outPid, DWORD *outError) {
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    DWORD lastError = ERROR_NOT_FOUND;
    BOOL named = FALSE;
    BOOL found = FALSE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        *outError = GetLastError();
        return FALSE;
    }
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            HANDLE token = NULL;
            DWORD error = ERROR_SUCCESS;

            if (_wcsicmp(entry.szExeFile, ELEVATE_TI_PROCESS_NAME) != 0) {
                continue;
            }
            named = TRUE;
            if (ElevateDuplicateTrustedInstallerToken(entry.th32ProcessID, &token, &error)) {
                *outPid = entry.th32ProcessID;
                *outToken = token;
                found = TRUE;
                break;
            }
            lastError = error;
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (!found) {
        *outError = named ? lastError : ERROR_NOT_FOUND;
    }
    return found;
}

BOOL ElevateAcquireTrustedInstallerTokenFromProcess(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    DWORD pid = 0;
    DWORD error = ERROR_SUCCESS;
    wchar_t stage[96];
    BOOL started = FALSE;
    BOOL startOk;

    if (FindTrustedInstallerToken(outToken, &pid, &error)) {
        result->pid = pid;
        wcsncpy(result->source, ELEVATE_TI_PROCESS_NAME, sizeof(result->source) / sizeof(wchar_t) - 1);
        wcscpy(result->note, L"verified existing process");
        return TRUE;
    }
    wcscpy(stage, L"no verified TrustedInstaller.exe running");
    startOk = StartTrustedInstallerService(&pid, &error, stage, sizeof(stage) / sizeof(stage[0]), &started);
    result->startedService = started;
    if (startOk) {
        if (ElevateDuplicateTrustedInstallerToken(pid, outToken, &error)) {
            result->pid = pid;
            wcsncpy(result->source, ELEVATE_TI_PROCESS_NAME, sizeof(result->source) / sizeof(wchar_t) - 1);
            wcscpy(result->note, L"service started");
            return TRUE;
        }
        if (error == ERROR_ACCESS_DENIED) {
            wcscpy(stage, L"PPL token not granted to Administrators");
        } else if (error == ERROR_INVALID_ACCOUNT_NAME) {
            wcscpy(stage, L"service token carries no TI sid");
        } else {
            wcscpy(stage, L"open TrustedInstaller token failed");
        }
    }
    result->error = error != ERROR_SUCCESS ? error : ERROR_NOT_FOUND;
    wcsncpy(result->note, stage, sizeof(result->note) / sizeof(wchar_t) - 1);
    result->note[sizeof(result->note) / sizeof(wchar_t) - 1] = 0;
    return FALSE;
}

/* ------------------------------------------------------------ 服务供体 */

static SERVICE_STATUS_HANDLE g_donorStatus = NULL;
static HANDLE g_donorStop = NULL;

static DWORD WINAPI DonorControlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context) {
    SERVICE_STATUS status;

    (void)eventType;
    (void)eventData;
    (void)context;
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_donorStatus) {
            memset(&status, 0, sizeof(status));
            status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
            status.dwCurrentState = SERVICE_STOP_PENDING;
            status.dwWin32ExitCode = NO_ERROR;
            status.dwWaitHint = 3000;
            SetServiceStatus(g_donorStatus, &status);
        }
        if (g_donorStop) {
            SetEvent(g_donorStop);
        }
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/* 只做一件事：以 LocalSystem 的身份把自己挂成 SERVICE_RUNNING，然后等父进程来取令牌。
   报上 RUNNING 之后 SCM 里就能查到 pid，父进程据此 OpenProcessToken/复制，
   来源是我们自己的二进制，不存在 PPL 拦路的问题。 */
static void WINAPI DonorServiceMain(DWORD argc, LPWSTR *argv) {
    SERVICE_STATUS status;

    (void)argc;
    g_donorStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    /* lpServiceArgVectors[0] 就是服务名，注册控制处理器必须用它。 */
    g_donorStatus = RegisterServiceCtrlHandlerExW(argv[0], DonorControlHandler, NULL);
    if (!g_donorStatus) {
        return;
    }
    memset(&status, 0, sizeof(status));
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(g_donorStatus, &status);

    /* 兜底寿命：父进程若中途没了，也不把供体进程永远留在系统里。 */
    if (g_donorStop) {
        WaitForSingleObject(g_donorStop, ELEVATE_DONOR_LIFETIME_MS);
    }
    memset(&status, 0, sizeof(status));
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(g_donorStatus, &status);
}

BOOL ElevateDonorRequested(int argc, wchar_t **argv) {
    int i;

    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], ELEVATE_DONOR_FLAG) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

int ElevateDonorMain(void) {
    SERVICE_TABLE_ENTRYW table[2];
    wchar_t serviceName[64];

    wcscpy(serviceName, ELEVATE_DONOR_SERVICE_NAME);
    table[0].lpServiceName = serviceName;
    table[0].lpServiceProc = DonorServiceMain;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    if (!StartServiceCtrlDispatcherW(table)) {
        /* 不是被 SCM 拉起来的（用户手敲了 --syndonor），直接退。 */
        return 1;
    }
    return 0;
}

static BOOL DonorServiceIsOurs(SC_HANDLE service) {
    LPQUERY_SERVICE_CONFIGW config;
    wchar_t executable[MAX_PATH * 2];
    wchar_t expected[MAX_PATH * 2 + 64];
    DWORD needed = 0;
    BOOL ours = FALSE;

    if (!ElevateSelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
        return FALSE;
    }
    if (QueryServiceConfigW(service, NULL, 0, &needed) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        needed == 0) {
        return FALSE;
    }
    config = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(LPTR, needed);
    if (!config) {
        return FALSE;
    }
    if (QueryServiceConfigW(service, config, needed, &needed)) {
        swprintf(
            expected,
            sizeof(expected) / sizeof(expected[0]),
            L"\"%ls\" %ls",
            executable,
            ELEVATE_DONOR_FLAG);
        ours = _wcsicmp(config->lpBinaryPathName, expected) == 0;
    }
    LocalFree(config);
    return ours;
}

static void RemoveDonorService(SC_HANDLE manager) {
    SC_HANDLE service;
    SERVICE_STATUS status;
    int attempt;

    service = OpenServiceW(
        manager,
        ELEVATE_DONOR_SERVICE_NAME,
        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | DELETE);
    if (!service) {
        return;
    }
    if (!DonorServiceIsOurs(service)) {
        CloseServiceHandle(service);
        return;
    }
    if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        for (attempt = 0; attempt < 30; attempt++) {
            SERVICE_STATUS_PROCESS info;
            DWORD needed = 0;
            if (!QueryServiceStatusEx(
                    service,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&info,
                    sizeof(info),
                    &needed) ||
                info.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
            Sleep(100);
        }
    }
    DeleteService(service);
    CloseServiceHandle(service);
}

static BOOL WaitForDonor(SC_HANDLE service, DWORD *outPid, DWORD *outError) {
    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0;
    int attempt;

    *outPid = 0;
    for (attempt = 0; attempt < ELEVATE_DONOR_WAIT_MS / 100; attempt++) {
        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&status,
                sizeof(status),
                &needed)) {
            *outError = GetLastError();
            return FALSE;
        }
        if (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0) {
            *outPid = status.dwProcessId;
            return TRUE;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            *outError = ERROR_SERVICE_NOT_ACTIVE;
            return FALSE;
        }
        Sleep(100);
    }
    *outError = ERROR_TIMEOUT;
    return FALSE;
}

/* 稳定拿到 SYSTEM：临时服务 → 查 pid → 复制令牌 → 停服务并注销。 */
static BOOL ElevateAcquireSystemTokenViaService(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    wchar_t executable[MAX_PATH * 2];
    wchar_t binPath[MAX_PATH * 2 + 64];
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    HANDLE token = NULL;
    DWORD error = ERROR_SUCCESS;
    DWORD pid = 0;
    BOOL ok = FALSE;
    int attempt;

    if (!g_config.elevateServiceDonor) {
        result->error = ERROR_NOT_SUPPORTED;
        wcscpy(result->note, L"service donor disabled");
        return FALSE;
    }
    if (!ElevateSelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
        result->error = ERROR_INSUFFICIENT_BUFFER;
        wcscpy(result->note, L"own executable path too long");
        return FALSE;
    }
    swprintf(
        binPath,
        sizeof(binPath) / sizeof(binPath[0]),
        L"\"%ls\" %ls",
        executable,
        ELEVATE_DONOR_FLAG);
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!manager) {
        result->error = GetLastError();
        wcscpy(result->note, L"open SCM failed");
        return FALSE;
    }
    for (attempt = 0; attempt < 3; attempt++) {
        service = CreateServiceW(
            manager,
            ELEVATE_DONOR_SERVICE_NAME,
            ELEVATE_DONOR_SERVICE_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            binPath,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL);
        if (service) {
            break;
        }
        error = GetLastError();
        if (error != ERROR_SERVICE_EXISTS && error != ERROR_SERVICE_MARKED_FOR_DELETE) {
            result->error = error;
            wcscpy(result->note, L"CreateService failed");
            CloseServiceHandle(manager);
            return FALSE;
        }
        RemoveDonorService(manager);
        Sleep(200);
    }
    if (!service) {
        result->error = error != ERROR_SUCCESS ? error : ERROR_SERVICE_EXISTS;
        wcscpy(result->note, L"service still marked for delete");
        CloseServiceHandle(manager);
        return FALSE;
    }
    if (!StartServiceW(service, 0, NULL)) {
        result->error = GetLastError();
        wcscpy(result->note, L"StartService failed");
        goto done;
    }
    if (!WaitForDonor(service, &pid, &error)) {
        result->error = error;
        wcscpy(result->note, L"donor never reached RUNNING");
        goto done;
    }
    if (!ElevateDuplicateTokenFromPid(pid, &token, &error)) {
        result->error = error;
        wcscpy(result->note, L"open donor token failed");
        goto done;
    }
    if (!ElevateTokenSidEquals(token, ELEVATE_SYSTEM_SID_STRING)) {
        result->error = ERROR_INVALID_ACCOUNT_NAME;
        wcscpy(result->note, L"donor token was not SYSTEM");
        goto done;
    }
    result->pid = pid;
    wcscpy(result->source, ELEVATE_DONOR_SERVICE_NAME);
    wcscpy(result->note, L"temporary LocalSystem service");
    *outToken = token;
    token = NULL;
    ok = TRUE;
done:
    if (token) {
        CloseHandle(token);
    }
    RemoveDonorService(manager);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return ok;
}

static const wchar_t *const kSystemCandidates[] = {
    L"winlogon.exe",
    L"services.exe",
    L"wininit.exe",
    L"spoolsv.exe",
    L"svchost.exe",
    L"WmiPrvSE.exe",
    L"SearchIndexer.exe",
    L"lsass.exe",
    L"csrss.exe"
};

/* 一轮提权里 SYSTEM 令牌会被要两次：一次是 TI 档借它当伪造底座，一次是
   SYSTEM 档自己落地。自建供体服务不便宜（建服务、起进程、复制令牌、再停掉），
   所以第一次拿到就留一份，后面直接复用。句柄只在本进程里，ElevateRun 开头清掉。 */
static HANDLE g_systemBase = NULL;
static ELEVATE_TIER_RESULT g_systemBaseInfo;

HANDLE ElevateSystemBaseToken(void) {
    return g_systemBase;
}

void ElevateReleaseSystemBase(void) {
    if (g_systemBase) {
        CloseHandle(g_systemBase);
        g_systemBase = NULL;
    }
    memset(&g_systemBaseInfo, 0, sizeof(g_systemBaseInfo));
}

static BOOL DuplicatePrimaryToken(HANDLE source, HANDLE *outToken, DWORD *outError) {
    HANDLE token = NULL;

    *outToken = NULL;
    *outError = ERROR_SUCCESS;
    if (!DuplicateTokenEx(
            source,
            TOKEN_ALL_ACCESS,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &token)) {
        *outError = GetLastError();
        return FALSE;
    }
    *outToken = token;
    return TRUE;
}

/* 带缓存的取用入口：缓存里没有才真的去建供体服务 / 扫进程。 */
static BOOL ElevateAcquireSystemTokenUncached(ELEVATE_TIER_RESULT *result, HANDLE *outToken);

BOOL ElevateAcquireSystemToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    HANDLE token = NULL;
    DWORD error = ERROR_SUCCESS;

    if (g_systemBase) {
        if (!DuplicatePrimaryToken(g_systemBase, &token, &error)) {
            result->error = error;
            wcscpy(result->note, L"cached SYSTEM token unusable");
            return FALSE;
        }
        *result = g_systemBaseInfo;
        *outToken = token;
        return TRUE;
    }
    if (!ElevateAcquireSystemTokenUncached(result, outToken)) {
        return FALSE;
    }
    g_systemBaseInfo = *result;
    if (!DuplicatePrimaryToken(*outToken, &g_systemBase, &error)) {
        /* 缓存不上不算失败：令牌本身是好的，下一档再去拿一次就行。 */
        memset(&g_systemBaseInfo, 0, sizeof(g_systemBaseInfo));
    }
    return TRUE;
}

static BOOL ElevateAcquireSystemTokenUncached(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    DWORD pid = 0;
    DWORD error = ERROR_SUCCESS;
    DWORD serviceError;
    wchar_t serviceNote[96];
    size_t i;

    /* 首选自建供体：令牌来源确定，不受 PPL、不受目标机器上跑了什么影响。 */
    if (ElevateAcquireSystemTokenViaService(result, outToken)) {
        return TRUE;
    }
    serviceError = result->error;
    wcsncpy(serviceNote, result->note, sizeof(serviceNote) / sizeof(wchar_t) - 1);
    serviceNote[sizeof(serviceNote) / sizeof(wchar_t) - 1] = 0;
    result->error = ERROR_SUCCESS;
    result->pid = 0;
    result->source[0] = 0;
    result->note[0] = 0;

    for (i = 0; i < sizeof(kSystemCandidates) / sizeof(kSystemCandidates[0]); i++) {
        HANDLE token = NULL;

        if (!ElevateFindProcessNamed(kSystemCandidates[i], &pid)) {
            continue;
        }
        if (!ElevateDuplicateTokenFromPid(pid, &token, &error)) {
            continue;
        }
        /* 同名进程可能不是 SYSTEM（例如用户会话里的 svchost），必须核对 SID。 */
        if (ElevateTokenSidEquals(token, ELEVATE_SYSTEM_SID_STRING)) {
            result->pid = pid;
            wcsncpy(result->source, kSystemCandidates[i], sizeof(result->source) / sizeof(wchar_t) - 1);
            wcscpy(result->note, L"SID verified");
            *outToken = token;
            return TRUE;
        }
        CloseHandle(token);
        error = ERROR_INVALID_ACCOUNT_NAME;
    }
    {
        wchar_t name[64];
        HANDLE token = NULL;
        DWORD debugError = ERROR_SUCCESS;

        /* 全量扫描代价较高，只有拿到 SeDebugPrivilege 时才值得做。 */
        if (!ElevateEnablePrivilege(SE_DEBUG_NAME, &debugError)) {
            /* 刚失败的是这一步，报它自己的错误；上面循环留下的 error 只是历史。 */
            result->error = debugError != ERROR_SUCCESS ? debugError
                                                        : (error != ERROR_SUCCESS ? error : ERROR_NOT_FOUND);
            wcscpy(result->note, L"SeDebugPrivilege unavailable for SID scan");
            return FALSE;
        }
        if (!ElevateFindProcessBySid(ELEVATE_SYSTEM_SID_STRING, &pid, name, sizeof(name) / sizeof(name[0]))) {
            error = ERROR_NOT_FOUND;
        } else if (ElevateDuplicateTokenFromPid(pid, &token, &error)) {
            result->pid = pid;
            wcsncpy(result->source, name, sizeof(result->source) / sizeof(wchar_t) - 1);
            wcscpy(result->note, L"scanned by SID");
            *outToken = token;
            return TRUE;
        }
    }
    result->error = error != ERROR_SUCCESS ? error : ERROR_NOT_FOUND;
    /* 两条路都断了：把稳定路径失败的原因一并留在 note 里，便于定位。 */
    swprintf(
        result->note,
        sizeof(result->note) / sizeof(result->note[0]),
        L"service donor: %ls (err %lu)",
        serviceNote[0] ? serviceNote : L"failed",
        (unsigned long)serviceError);
    return FALSE;
}
