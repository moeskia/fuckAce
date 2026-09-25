#include "elevation/elevate.h"
#include "app/config.h"
#include "system/titoken.h"
#include "elevation/elevate_internal.h"

#include <winsvc.h>

/* ------------------------------------------- TrustedInstaller 注册表维护 */

/* 备份值只存在 HKLM\SOFTWARE\fuckAce 里，不用文件：低权限用户写不了 HKLM，
   否则一个“恢复 ImagePath”的动作就变成了“让低权限用户指定 TI 的镜像路径”。 */
static BOOL TiReadBackup(wchar_t *backup, size_t capacity, DWORD *outType, DWORD *outError) {
    HKEY key;
    DWORD type = 0;
    DWORD bytes;
    LONG status;
    BOOL ok = FALSE;

    if (outType) {
        *outType = 0;
    }
    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    if (!backup || capacity < 2) {
        if (outError) {
            *outError = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }
    backup[0] = 0;
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ELEVATE_TI_BACKUP_KEY, 0, KEY_QUERY_VALUE, &key);
    if (status != ERROR_SUCCESS) {
        if (outError) {
            *outError = (DWORD)status;
        }
        return FALSE;
    }
    bytes = (DWORD)(capacity * sizeof(wchar_t));
    status = RegQueryValueExW(key, ELEVATE_TI_BACKUP_VALUE, NULL, &type, (LPBYTE)backup, &bytes);
    if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        backup[capacity - 1] = 0;
        if (bytes < sizeof(wchar_t)) {
            backup[0] = 0;
        }
        if (outType) {
            *outType = type;
        }
        ok = TRUE;
    } else if (outError) {
        *outError = status == ERROR_SUCCESS ? ERROR_INVALID_DATATYPE : (DWORD)status;
    }
    RegCloseKey(key);
    if (!ok) {
        backup[0] = 0;
    }
    return ok;
}

static BOOL TiWriteBackup(const wchar_t *imagePath, DWORD type, DWORD *outError) {
    HKEY key;
    DWORD disposition = 0;
    LONG status;
    BOOL ok = FALSE;

    *outError = ERROR_SUCCESS;
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        ELEVATE_TI_BACKUP_KEY,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        NULL,
        &key,
        &disposition);
    if (status != ERROR_SUCCESS) {
        *outError = (DWORD)status;
        return FALSE;
    }
    status = RegSetValueExW(
        key,
        ELEVATE_TI_BACKUP_VALUE,
        0,
        type,
        (const BYTE *)imagePath,
        (DWORD)((wcslen(imagePath) + 1) * sizeof(wchar_t)));
    if (status != ERROR_SUCCESS) {
        *outError = (DWORD)status;
    } else {
        ok = TRUE;
    }
    RegCloseKey(key);
    return ok;
}

static void TiDropBackup(void) {
    HKEY key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ELEVATE_TI_BACKUP_KEY, 0, KEY_SET_VALUE, &key) !=
        ERROR_SUCCESS) {
        return;
    }
    RegDeleteValueW(key, ELEVATE_TI_BACKUP_VALUE);
    RegDeleteValueW(key, ELEVATE_TI_BACKUP_PID_VALUE);
    RegCloseKey(key);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, ELEVATE_TI_BACKUP_KEY);
}

BOOL ElevateTiKeyStale(void) {
    wchar_t backup[MAX_PATH * 2];

    return TiReadBackup(backup, sizeof(backup) / sizeof(backup[0]), NULL, NULL);
}

static BOOL TiReadImagePath(wchar_t *value, size_t capacity, DWORD *outType, DWORD *outError) {
    HKEY key;
    DWORD type = 0;
    DWORD bytes;
    LONG status;
    BOOL ok = FALSE;

    if (outType) {
        *outType = 0;
    }
    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    if (!value || capacity < 2) {
        if (outError) {
            *outError = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }
    value[0] = 0;
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ELEVATE_TI_KEY_PATH, 0, KEY_QUERY_VALUE, &key);
    if (status != ERROR_SUCCESS) {
        if (outError) {
            *outError = (DWORD)status;
        }
        return FALSE;
    }
    bytes = (DWORD)(capacity * sizeof(wchar_t));
    status = RegQueryValueExW(key, ELEVATE_TI_IMAGE_VALUE, NULL, &type, (LPBYTE)value, &bytes);
    if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        value[capacity - 1] = 0;
        if (bytes < sizeof(wchar_t)) {
            value[0] = 0;
        }
        if (outType) {
            *outType = type;
        }
        ok = TRUE;
    } else if (outError) {
        *outError = status == ERROR_SUCCESS ? ERROR_INVALID_DATATYPE : (DWORD)status;
    }
    RegCloseKey(key);
    return ok;
}

static BOOL TiWriteImagePath(const wchar_t *value, DWORD type, DWORD *outError) {
    HKEY key;
    LONG status;

    *outError = ERROR_SUCCESS;
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ELEVATE_TI_KEY_PATH, 0, KEY_SET_VALUE, &key);
    if (status != ERROR_SUCCESS) {
        *outError = (DWORD)status;
        return FALSE;
    }
    status = RegSetValueExW(
        key,
        ELEVATE_TI_IMAGE_VALUE,
        0,
        type,
        (const BYTE *)value,
        (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        *outError = (DWORD)status;
        return FALSE;
    }
    return TRUE;
}

static BOOL TiImagePathLooksOurs(const wchar_t *value) {
    return value && wcsstr(value, ELEVATE_DONOR_FLAG) != NULL;
}

BOOL ElevateTiRestoreKey(DWORD *outError) {
    wchar_t backup[MAX_PATH * 2];
    wchar_t current[MAX_PATH * 2];
    DWORD backupType = 0;
    DWORD currentType = 0;
    DWORD error = ERROR_SUCCESS;

    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    if (!TiReadBackup(backup, sizeof(backup) / sizeof(backup[0]), &backupType, &error)) {
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return TRUE;
        }
        if (outError) {
            *outError = error;
        }
        return FALSE;
    }
    if (!TiReadImagePath(current, sizeof(current) / sizeof(current[0]), &currentType, &error)) {
        if (outError) {
            *outError = error;
        }
        return FALSE;
    }
    if (_wcsicmp(current, backup) == 0) {
        if (currentType != backupType && !TiWriteImagePath(backup, backupType, &error)) {
            if (outError) {
                *outError = error;
            }
            return FALSE;
        }
        TiDropBackup();
        return TRUE;
    }
    if (!TiImagePathLooksOurs(current)) {
        TiDropBackup();
        return TRUE;
    }
    if (!TiWriteImagePath(backup, backupType, &error)) {
        if (outError) {
            *outError = error;
        }
        return FALSE;
    }
    TiDropBackup();
    return TRUE;
}

/* 兜底守护进程：万一本进程在“键被改过、还没还原”的那几百毫秒里被干掉，
   这个以 SYSTEM 身份跑起来的小进程会替我们把键修回去。
   它只等父进程退出（最多 30 秒），然后做一次幂等还原就退出。 */
static void TiSpawnGuardian(HANDLE systemToken) {
    wchar_t executable[MAX_PATH * 2];
    wchar_t commandLine[MAX_PATH * 4];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    HANDLE token = systemToken;
    BOOL owned = FALSE;
    DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB;

    if (!ElevateSelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
        return;
    }
    if (!token && !OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES,
            &token)) {
        return;
    }
    ElevateEnableAllTokenPrivileges(token);
    if (!systemToken) {
        owned = TRUE;
    }
    ElevateNote(
        commandLine,
        sizeof(commandLine) / sizeof(commandLine[0]),
        L"\"%ls\" %ls%lu",
        executable,
        ELEVATE_TI_REPAIR_FLAG,
        (unsigned long)GetCurrentProcessId());
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    if (!CreateProcessAsUserW(
            token,
            NULL,
            commandLine,
            NULL,
            NULL,
            FALSE,
            flags,
            NULL,
            NULL,
            &startup,
            &process)) {
        if (!CreateProcessAsUserW(
                token,
                NULL,
                commandLine,
                NULL,
                NULL,
                FALSE,
                flags & ~((DWORD)CREATE_BREAKAWAY_FROM_JOB),
                NULL,
                NULL,
                &startup,
                &process) &&
            !CreateProcessWithTokenW(
                token,
                0,
                NULL,
                commandLine,
                flags & ~((DWORD)CREATE_BREAKAWAY_FROM_JOB),
                NULL,
                NULL,
                &startup,
                &process)) {
            /* 守护进程起不来也继续：正常路径照样会立刻还原，只是少一层兜底。 */
            if (owned) {
                CloseHandle(token);
            }
            return;
        }
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (owned) {
        CloseHandle(token);
    }
}

BOOL ElevateTiRepairRequested(int argc, wchar_t **argv, DWORD *outParentPid) {
    size_t length = wcslen(ELEVATE_TI_REPAIR_FLAG);
    int i;

    if (outParentPid) {
        *outParentPid = 0;
    }
    for (i = 1; i < argc; i++) {
        const wchar_t *cursor;
        DWORD pid = 0;

        if (wcsncmp(argv[i], ELEVATE_TI_REPAIR_FLAG, length) != 0) {
            continue;
        }
        cursor = argv[i] + length;
        if (!*cursor) {
            return FALSE; /* 空值不当内部模式，交给参数解析去报错 */
        }
        while (*cursor) {
            DWORD digit;

            if (*cursor < L'0' || *cursor > L'9') {
                return FALSE;
            }
            digit = (DWORD)(*cursor - L'0');
            if (pid > (MAXDWORD - digit) / 10) {
                return FALSE;
            }
            pid = pid * 10 + digit;
            cursor++;
        }
        if (outParentPid) {
            *outParentPid = pid;
        }
        return TRUE;
    }
    return FALSE;
}

int ElevateTiRepairMain(DWORD parentPid) {
    HANDLE parent = NULL;
    DWORD error = ERROR_SUCCESS;

    if (parentPid) {
        parent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
    }
    if (parent) {
        WaitForSingleObject(parent, ELEVATE_TI_GUARDIAN_WAIT_MS);
        CloseHandle(parent);
    } else {
        Sleep(ELEVATE_TI_GUARDIAN_WAIT_MS);
    }
    ElevateTiRestoreKey(&error);
    return error == ERROR_SUCCESS ? 0 : 1;
}

/* ------------------------------------------------ TrustedInstaller 令牌获取 */

/* 把一次尝试的结果并回调用方持有的结构体。
   tried 是调用方（ElevateRun）在进 TI 这一档之前就打上的，中间临时用了几个局部
   结果结构体来拼诊断信息，回写时不能把 tried 一起冲掉，否则界面上会显示成
   “not attempted”，而且失败详情也一起丢了。 */
static void ElevateTierResultCopy(ELEVATE_TIER_RESULT *destination, const ELEVATE_TIER_RESULT *source) {
    BOOL tried = destination->tried;
    BOOL startedService = destination->startedService;

    *destination = *source;
    destination->tried = tried;
    destination->startedService = startedService || source->startedService;
}

/* 办法二（默认）：站在 SYSTEM 上造一个组里带 TI 服务 SID 的令牌。
   不写注册表、不起服务、不留任何持久状态，是现代 Windows 上真正稳的那条路。
   调用方保证当前线程已经是 SYSTEM，因为 SeCreateTokenPrivilege 只有 LocalSystem 有。 */
static BOOL ElevateAcquireTrustedInstallerTokenForged(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    HANDLE forged;
    DWORD error = ERROR_SUCCESS;

    if (!g_config.tiForge) {
        result->error = ERROR_NOT_SUPPORTED;
        wcscpy(result->note, L"forge disabled (--no-ti-forge)");
        return FALSE;
    }
    /* Windows 11 客户端的 LocalSystem 令牌里根本没有 SeCreateTokenPrivilege
       （实测 28 个特权，没有它）。先问一句，比让 NtCreateToken 回一个看不懂的
       STATUS_PRIVILEGE_NOT_HELD 强，也让用户明白该换哪条路。 */
    if (!TiEffectiveTokenHasPrivilege(L"SeCreateTokenPrivilege")) {
        result->error = ERROR_PRIVILEGE_NOT_HELD;
        wcscpy(result->note, L"no SeCreateTokenPrivilege in the SYSTEM token");
        return FALSE;
    }
    forged = TiTokenForge(g_elevate.process.sessionId, &error);
    if (!forged) {
        result->error = error != ERROR_SUCCESS ? error : ERROR_NOT_VERIFIED;
        wcscpy(result->note, L"NtCreateToken rejected");
        return FALSE;
    }
    /* 造出来就核对：SID 没进去，这个令牌只是个普通 SYSTEM，不能算 TI。 */
    if (!TiTokenGroupEnabled(forged, TITOKEN_TI_SID_STRING)) {
        result->error = ERROR_NOT_VERIFIED;
        wcscpy(result->note, L"forged token carries no TI sid");
        CloseHandle(forged);
        return FALSE;
    }
    result->pid = GetCurrentProcessId();
    wcscpy(result->source, L"forged");
    wcscpy(result->note, L"NtCreateToken | SYSTEM base");
    *outToken = forged;
    return TRUE;
}

/* 办法三（--ti-hijack，默认开启）：临时把 TrustedInstaller 服务的 ImagePath 换成自己。
   SCM 会用真实的 TI 服务身份（ServiceSidType=1 会补上 NT SERVICE\TrustedInstaller）
   把本程序拉起来，复制完令牌立刻把键还原。

   这是唯一一条会改系统持久状态的路径，所以顺序被钉死：
   先确认能停掉原服务 → 先备份 → 先起守护进程 → 才动键 → 服务 RUNNING 后立刻还原。
   暴露窗口只有 StartService 到服务 RUNNING 之间的几百毫秒。 */
static BOOL ElevateAcquireTrustedInstallerTokenViaHijack(
    ELEVATE_TIER_RESULT *result,
    HANDLE *outToken,
    int serviceWasRunning
) {
    wchar_t executable[MAX_PATH * 2];
    wchar_t binPath[MAX_PATH * 2 + 64];
    wchar_t original[MAX_PATH * 2];
    DWORD originalType = 0;
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS_PROCESS info;
    SERVICE_STATUS status;
    DWORD needed = 0;
    DWORD pid = 0;
    DWORD error = ERROR_SUCCESS;
    DWORD restoreError = ERROR_SUCCESS;
    HANDLE token = NULL;
    BOOL donorStarted = FALSE;
    BOOL ok = FALSE;
    int attempt;

    if (g_config.tiHijack == TI_HIJACK_OFF) {
        result->error = ERROR_NOT_SUPPORTED;
        wcscpy(result->note, L"hijack off (--no-ti-hijack)");
        return FALSE;
    }
    if (g_config.elevateKeepService) {
        /* --keep-ti 要的是"别停我拉起来的 TI 服务"，而劫持必须先把服务停掉；
           更关键的是劫持完绝不能把供体留在系统里（那就是一个 TI 身份的后门）。
           两者语义冲突，这里直接跳过劫持，让链条往 SYSTEM 回退。 */
        result->error = ERROR_INVALID_FLAGS;
        wcscpy(result->note, L"hijack skipped (--keep-ti)");
        return FALSE;
    }
    if (!ElevateSelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
        result->error = ERROR_INSUFFICIENT_BUFFER;
        wcscpy(result->note, L"own executable path too long");
        return FALSE;
    }
    if (!TiReadImagePath(original, sizeof(original) / sizeof(original[0]), &originalType, &error)) {
        result->error = error != ERROR_SUCCESS ? error : ERROR_ACCESS_DENIED;
        wcscpy(result->note, L"cannot read TrustedInstaller ImagePath");
        return FALSE;
    }
    ElevateNote(binPath, sizeof(binPath) / sizeof(binPath[0]), L"\"%ls\" %ls", executable, ELEVATE_DONOR_FLAG);

    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) {
        result->error = GetLastError();
        wcscpy(result->note, L"open SCM failed");
        return FALSE;
    }
    /* SERVICE_STOP 不能跟 START 一起要：TI 的服务描述符不保证给管理员停的权限，
       多要一个权利会让 OpenService 整个失败。真需要停的时候单独再开一个句柄。 */
    service = OpenServiceW(
        manager,
        ELEVATE_TI_SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE);
    if (!service) {
        result->error = GetLastError();
        wcscpy(result->note, L"open TrustedInstaller service failed");
        goto done;
    }
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&info, sizeof(info), &needed)) {
        result->error = GetLastError();
        wcscpy(result->note, L"query service status failed");
        goto done;
    }
    if (info.dwCurrentState != SERVICE_STOPPED) {
        SC_HANDLE stopper;
        BOOL stopped = FALSE;

        /* 这里看的必须是**我们动手之前**的状态。方法一为了拿令牌会自己把 TI 拉起来，
           如果拿"现在的状态"当判据，默认配置就会把自己刚启动的服务误判成
           "系统正在维护"，于是永远跳过劫持、永远落不到 TI。 */
        if (g_config.tiHijack != TI_HIJACK_FORCE && serviceWasRunning != 0) {
            result->error = ERROR_SERVICE_ALREADY_RUNNING;
            wcscpy(result->note, L"TI was already running; hijack skipped (--ti-hijack forces it)");
            goto done;
        }
        stopper = OpenServiceW(
            manager,
            ELEVATE_TI_SERVICE_NAME,
            SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!stopper) {
            result->error = GetLastError();
            wcscpy(result->note, L"TI is running and cannot be stopped");
            goto done;
        }
        ControlService(stopper, SERVICE_CONTROL_STOP, &status);
        for (attempt = 0; attempt < ELEVATE_TI_STOP_WAIT_MS / 100; attempt++) {
            memset(&status, 0, sizeof(status));

            if (!QueryServiceStatus(stopper, &status)) {
                result->error = GetLastError();
                CloseServiceHandle(stopper);
                wcscpy(result->note, L"query TI stop status failed");
                goto done;
            }
            if (status.dwCurrentState == SERVICE_STOPPED) {
                stopped = TRUE;
                break;
            }
            Sleep(100);
        }
        if (!stopped) {
            CloseServiceHandle(stopper);
            result->error = ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            wcscpy(result->note, L"TI refuses to stop (busy with servicing)");
            goto done;
        }
        CloseServiceHandle(stopper);
    }

    if (!TiWriteBackup(original, originalType, &error)) {
        result->error = error;
        wcscpy(result->note, L"cannot save the ImagePath backup");
        goto done;
    }
    TiSpawnGuardian(ElevateSystemBaseToken());

    if (!TiWriteImagePath(binPath, REG_EXPAND_SZ, &error)) {
        result->error = error;
        wcscpy(result->note, L"cannot rewrite TrustedInstaller ImagePath");
        goto done;
    }
    if (!StartServiceW(service, 0, NULL)) {
        error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            result->error = error;
            wcscpy(result->note, L"StartService failed");
            goto done;
        }
    } else {
        donorStarted = TRUE;
    }
    for (attempt = 0; attempt < ELEVATE_SERVICE_WAIT_MS / 100; attempt++) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&info, sizeof(info), &needed)) {
            result->error = GetLastError();
            wcscpy(result->note, L"query donor status failed");
            goto done;
        }
        if (info.dwCurrentState == SERVICE_RUNNING && info.dwProcessId != 0) {
            pid = info.dwProcessId;
            break;
        }
        if (info.dwCurrentState == SERVICE_STOPPED) {
            break;
        }
        Sleep(100);
    }
    /* 关键一步：镜像已经在内存里了，键可以立刻还原，不用等服务退出。 */
    if (!ElevateTiRestoreKey(&restoreError)) {
        result->error = restoreError != ERROR_SUCCESS ? restoreError : ERROR_ACCESS_DENIED;
        wcscpy(result->note, L"ImagePath restore failed");
        goto done;
    }
    if (!pid) {
        result->error = ERROR_SERVICE_NOT_ACTIVE;
        wcscpy(result->note, L"donor never reached RUNNING");
        goto done;
    }
    if (!ElevateDuplicateTrustedInstallerToken(pid, &token, &error)) {
        result->error = error;
        wcscpy(result->note, error == ERROR_INVALID_ACCOUNT_NAME
                                  ? L"donor token carries no TI sid"
                                  : L"open donor token failed");
        goto done;
    }
    result->pid = pid;
    wcscpy(result->source, L"TI service image swap");
    wcscpy(result->note, L"ImagePath restored");
    *outToken = token;
    token = NULL;
    ok = TRUE;

done:
    if (token) {
        CloseHandle(token);
    }
    if (!ok) {
        ElevateTiRestoreKey(&restoreError);
    }
    if (donorStarted) {
        SC_HANDLE stopper = OpenServiceW(
            manager,
            ELEVATE_TI_SERVICE_NAME,
            SERVICE_STOP | SERVICE_QUERY_STATUS);

        if (stopper) {
            ControlService(stopper, SERVICE_CONTROL_STOP, &status);
            CloseServiceHandle(stopper);
        }
    }
    if (service) {
        CloseServiceHandle(service);
    }
    if (manager) {
        CloseServiceHandle(manager);
    }
    return ok;
}

/* 只读查询：TI 服务当前在不在跑。安全闸门要的是"我们动手之前"的状态。 */
static int TiServiceRunning(void) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service;
    SERVICE_STATUS status;

    if (!manager) {
        return -1;
    }
    service = OpenServiceW(manager, ELEVATE_TI_SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(manager);
        return -1;
    }
    memset(&status, 0, sizeof(status));
    if (!QueryServiceStatus(service, &status)) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return -1;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return status.dwCurrentState == SERVICE_STOPPED ? 0 : 1;
}

/* 这两种办法都必须站在 SYSTEM 上。 */
static BOOL ElevateAcquireTrustedInstallerTokenElevated(
    ELEVATE_TIER_RESULT *result,
    HANDLE *outToken,
    int serviceWasRunning
) {
    ELEVATE_TIER_RESULT forge;
    ELEVATE_TIER_RESULT hijack;

    memset(&forge, 0, sizeof(forge));
    if (ElevateAcquireTrustedInstallerTokenForged(&forge, outToken)) {
        ElevateTierResultCopy(result, &forge);
        return TRUE;
    }
    memset(&hijack, 0, sizeof(hijack));
    if (ElevateAcquireTrustedInstallerTokenViaHijack(&hijack, outToken, serviceWasRunning)) {
        ElevateTierResultCopy(result, &hijack);
        return TRUE;
    }
    ElevateTierResultCopy(result, &forge);
    ElevateNote(
        result->note,
        sizeof(result->note) / sizeof(result->note[0]),
        L"forge: %ls | hijack: %ls",
        forge.note[0] ? forge.note : L"failed",
        hijack.note[0] ? hijack.note : L"failed");
    return FALSE;
}

/* 三种办法按“副作用从小到大”排：
   1) 直接复制现成 TI 进程的令牌（零副作用，PPL 机器上必失败）
   2) SYSTEM 上 NtCreateToken 造一个（零持久状态）
   3) 换 TI 服务的 ImagePath（默认允许，--no-ti-hijack 关闭）
   借 SYSTEM 这件事只在这里发生一次，两条需要 SYSTEM 的办法共用同一个底座。 */
BOOL ElevateAcquireTrustedInstallerToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    ELEVATE_TIER_RESULT direct;
    ELEVATE_TIER_RESULT elevated;
    ELEVATE_TIER_RESULT sysInfo;
    HANDLE base = NULL;
    HANDLE impersonation = NULL;
    DWORD error = ERROR_SUCCESS;
    BOOL borrowed = FALSE;
    /* 必须在任何方法动手之前取样：方法一会把 TI 服务拉起来。 */
    int serviceWasRunning = TiServiceRunning();
    BOOL ok;

    memset(&direct, 0, sizeof(direct));
    if (ElevateAcquireTrustedInstallerTokenFromProcess(&direct, outToken)) {
        ElevateTierResultCopy(result, &direct);
        return TRUE;
    }
    memset(&elevated, 0, sizeof(elevated));
    /* 方法一要是启动过服务，收摊的责任得一路带到最终结果里去，否则那个由我们
       拉起来的 TrustedInstaller 就永远留在系统里跑着了。 */
    elevated.startedService = direct.startedService;
    if (ElevateIsImpersonating()) {
        elevated.error = ERROR_BUSY;
        wcscpy(elevated.note, L"already impersonating another identity");
        ok = FALSE;
    } else {
        if (g_elevate.process.tier != ELEVATE_TIER_SYSTEM) {
            memset(&sysInfo, 0, sizeof(sysInfo));
            sysInfo.tried = TRUE;
            if (!ElevateAcquireSystemToken(&sysInfo, &base)) {
                ElevateTierResultCopy(result, &direct);
                /* 首要原因还是 TI 这一档自己为什么没成；借不到 SYSTEM 底座的细节在 note 里。 */
                result->error = direct.error != ERROR_SUCCESS
                                    ? direct.error
                                    : (sysInfo.error != ERROR_SUCCESS ? sysInfo.error : ERROR_ACCESS_DENIED);
                ElevateNote(
                    result->note,
                    sizeof(result->note) / sizeof(result->note[0]),
                    L"dup: %ls | no SYSTEM base: %ls",
                    direct.note[0] ? direct.note : L"failed",
                    sysInfo.note[0] ? sysInfo.note : L"failed");
                return FALSE;
            }
            if (!ElevateImpersonateWithToken(base, &impersonation, &error)) {
                CloseHandle(base);
                ElevateTierResultCopy(result, &direct);
                result->error = error;
                ElevateNote(
                    result->note,
                    sizeof(result->note) / sizeof(result->note[0]),
                    L"cannot impersonate the SYSTEM base (err %lu)",
                    (unsigned long)error);
                return FALSE;
            }
            borrowed = TRUE;
        }
        ok = ElevateAcquireTrustedInstallerTokenElevated(&elevated, outToken, serviceWasRunning);
        if (borrowed) {
            RevertToSelf();
            CloseHandle(impersonation);
        }
        if (base) {
            CloseHandle(base);
        }
    }
    if (ok) {
        ElevateTierResultCopy(result, &elevated);
        return TRUE;
    }
    ElevateTierResultCopy(result, &elevated);
    result->error = result->error != ERROR_SUCCESS ? result->error : ERROR_NOT_FOUND;
    if (!result->note[0] && direct.note[0]) {
        wcsncpy(result->note, direct.note, sizeof(result->note) / sizeof(result->note[0]) - 1);
        result->note[sizeof(result->note) / sizeof(result->note[0]) - 1] = 0;
    }
    return FALSE;
}
