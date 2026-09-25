#include "elevate.h"
#include "config.h"
#include "ui.h"

#include <sddl.h>
#include <winsvc.h>
#include <shellapi.h>

ELEVATE_STATUS g_elevate;

static HANDLE g_impersonation = NULL;

/* GetModuleFileNameW 返回 >= size 表示路径被截断，那种路径拿去注册服务/拉起子进程
   只会得到莫名其妙的失败，不如当场判掉。 */
static BOOL SelfExecutablePath(wchar_t *buffer, size_t size) {
    DWORD length = GetModuleFileNameW(NULL, buffer, (DWORD)size);

    if (length == 0 || length >= (DWORD)size) {
        buffer[0] = 0;
        return FALSE;
    }
    return TRUE;
}

/* ---------------------------------------------------------------- 身份查询 */

static BOOL SidStringFromToken(HANDLE token, wchar_t *buffer, size_t size, DWORD *outError) {
    DWORD needed = 0;
    TOKEN_USER *user;
    LPWSTR text = NULL;
    BOOL ok = FALSE;

    *outError = ERROR_SUCCESS;
    if (size == 0) {
        return FALSE;
    }
    buffer[0] = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (needed == 0) {
        *outError = GetLastError();
        return FALSE;
    }
    user = (TOKEN_USER *)LocalAlloc(LPTR, needed);
    if (!user) {
        *outError = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    if (GetTokenInformation(token, TokenUser, user, needed, &needed) &&
        ConvertSidToStringSidW(user->User.Sid, &text)) {
        wcsncpy(buffer, text, size - 1);
        buffer[size - 1] = 0;
        LocalFree(text);
        ok = TRUE;
    } else {
        *outError = GetLastError();
    }
    LocalFree(user);
    return ok;
}

static void AccountFromToken(HANDLE token, wchar_t *buffer, size_t size, DWORD *outError) {
    DWORD needed = 0;
    TOKEN_USER *user;
    wchar_t name[128];
    wchar_t domain[128];
    DWORD nameLength = (DWORD)(sizeof(name) / sizeof(name[0]));
    DWORD domainLength = (DWORD)(sizeof(domain) / sizeof(domain[0]));
    SID_NAME_USE use;

    buffer[0] = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (needed == 0) {
        return;
    }
    user = (TOKEN_USER *)LocalAlloc(LPTR, needed);
    if (!user) {
        return;
    }
    if (!GetTokenInformation(token, TokenUser, user, needed, &needed)) {
        LocalFree(user);
        return;
    }
    memset(name, 0, sizeof(name));
    memset(domain, 0, sizeof(domain));
    if (LookupAccountSidW(NULL, user->User.Sid, name, &nameLength, domain, &domainLength, &use)) {
        if (domain[0]) {
            swprintf(buffer, size, L"%ls\\%ls", domain, name);
        } else {
            swprintf(buffer, size, L"%ls", name);
        }
    } else if (outError) {
        *outError = GetLastError();
    }
    LocalFree(user);
}

static BOOL TokenElevated(HANDLE token) {
    TOKEN_ELEVATION info;
    DWORD size = 0;

    memset(&info, 0, sizeof(info));
    if (!GetTokenInformation(token, TokenElevation, &info, sizeof(info), &size)) {
        return FALSE;
    }
    return info.TokenIsElevated != 0;
}

/* 只看令牌里 Administrators 是否 *启用*：被 UAC 过滤的令牌里该组是 deny-only，
   TrustedInstaller 令牌里同样如此，所以不能用 CheckTokenMembership 直接判。 */
BOOL ElevateTokenHasAdminGroup(HANDLE token) {
    PSID target = NULL;
    TOKEN_GROUPS *groups = NULL;
    DWORD needed = 0;
    DWORD i;
    BOOL found = FALSE;

    if (!ConvertStringSidToSidW(ELEVATE_ADMIN_SID_STRING, &target)) {
        return FALSE;
    }
    GetTokenInformation(token, TokenGroups, NULL, 0, &needed);
    if (needed == 0) {
        LocalFree(target);
        return FALSE;
    }
    groups = (TOKEN_GROUPS *)LocalAlloc(LPTR, needed);
    if (!groups) {
        LocalFree(target);
        return FALSE;
    }
    if (GetTokenInformation(token, TokenGroups, groups, needed, &needed)) {
        for (i = 0; i < groups->GroupCount; i++) {
            if (EqualSid(groups->Groups[i].Sid, target) &&
                (groups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
                found = TRUE;
                break;
            }
        }
    }
    LocalFree(groups);
    LocalFree(target);
    return found;
}

static DWORD TokenElevationTypeOf(HANDLE token) {
    TOKEN_ELEVATION_TYPE type = TokenElevationTypeDefault;
    DWORD size = 0;

    if (!GetTokenInformation(token, TokenElevationType, &type, sizeof(type), &size)) {
        return 0;
    }
    return (DWORD)type;
}

static DWORD TokenSessionIdOf(HANDLE token) {
    DWORD id = 0;
    DWORD size = 0;

    if (!GetTokenInformation(token, TokenSessionId, &id, sizeof(id), &size)) {
        return 0xFFFFFFFFu;
    }
    return id;
}

static DWORD TokenIntegrityRidOf(HANDLE token) {
    DWORD needed = 0;
    TOKEN_MANDATORY_LABEL *label;
    DWORD rid = 0;

    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &needed);
    if (needed == 0) {
        return 0;
    }
    label = (TOKEN_MANDATORY_LABEL *)LocalAlloc(LPTR, needed);
    if (!label) {
        return 0;
    }
    if (GetTokenInformation(token, TokenIntegrityLevel, label, needed, &needed)) {
        PUCHAR count = GetSidSubAuthorityCount(label->Label.Sid);
        if (count && *count > 0) {
            rid = *GetSidSubAuthority(label->Label.Sid, (DWORD)(*count - 1));
        }
    }
    LocalFree(label);
    return rid;
}

static void QueryTokenIdentity(HANDLE token, ELEVATE_IDENTITY *identity) {
    DWORD error = ERROR_SUCCESS;

    memset(identity, 0, sizeof(*identity));
    identity->tier = ELEVATE_TIER_NONE;
    identity->sessionId = 0xFFFFFFFFu;
    if (!SidStringFromToken(token, identity->sid, sizeof(identity->sid) / sizeof(wchar_t), &error)) {
        identity->error = error;
        return;
    }
    AccountFromToken(token, identity->account, sizeof(identity->account) / sizeof(wchar_t), &error);
    identity->elevated = TokenElevated(token);
    identity->adminGroup = ElevateTokenHasAdminGroup(token);
    identity->elevationType = TokenElevationTypeOf(token);
    identity->sessionId = TokenSessionIdOf(token);
    identity->integrityRid = TokenIntegrityRidOf(token);
    if (_wcsicmp(identity->sid, ELEVATE_TI_SID_STRING) == 0) {
        identity->tier = ELEVATE_TIER_TI;
    } else if (_wcsicmp(identity->sid, ELEVATE_SYSTEM_SID_STRING) == 0) {
        identity->tier = ELEVATE_TIER_SYSTEM;
    } else if (identity->adminGroup) {
        identity->tier = ELEVATE_TIER_ADMIN;
    }
    identity->valid = TRUE;
}

static BOOL QueryProcessIdentity(ELEVATE_IDENTITY *identity) {
    HANDLE token = NULL;

    memset(identity, 0, sizeof(*identity));
    identity->tier = ELEVATE_TIER_NONE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        identity->error = GetLastError();
        return FALSE;
    }
    QueryTokenIdentity(token, identity);
    CloseHandle(token);
    return identity->valid;
}

static BOOL QueryThreadIdentity(ELEVATE_IDENTITY *identity) {
    HANDLE token = NULL;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        QueryTokenIdentity(token, identity);
        CloseHandle(token);
        return identity->valid;
    }
    return QueryProcessIdentity(identity);
}

static BOOL TokenSidEquals(HANDLE token, const wchar_t *sidText) {
    wchar_t sid[192];
    DWORD error = ERROR_SUCCESS;

    if (!SidStringFromToken(token, sid, sizeof(sid) / sizeof(wchar_t), &error)) {
        return FALSE;
    }
    return _wcsicmp(sid, sidText) == 0;
}

/* ------------------------------------------------------------------ 公共接口 */

const wchar_t *ElevateTierName(int tier) {
    switch (tier) {
    case ELEVATE_TIER_TI:
        return L"TrustedInstaller";
    case ELEVATE_TIER_SYSTEM:
        return L"SYSTEM";
    case ELEVATE_TIER_ADMIN:
        return L"admin";
    }
    return L"none";
}

const char *ElevateTierTag(int tier) {
    switch (tier) {
    case ELEVATE_TIER_TI:
        return "TI";
    case ELEVATE_TIER_SYSTEM:
        return "SYSTEM";
    case ELEVATE_TIER_ADMIN:
        return "admin";
    }
    return "-";
}

const char *ElevateUseName(int use) {
    switch (use) {
    case ELEVATE_USE_IMPERSONATE:
        return "impersonate";
    case ELEVATE_USE_SPAWN:
        return "spawn";
    }
    return "auto";
}

const char *ElevateTypeName(DWORD elevationType) {
    switch (elevationType) {
    case TokenElevationTypeDefault:
        return "default";
    case TokenElevationTypeFull:
        return "full";
    case TokenElevationTypeLimited:
        return "limited";
    }
    return "unknown";
}

int ElevateTierFromTag(const wchar_t *text, BOOL *outOk) {
    if (outOk) {
        *outOk = TRUE;
    }
    if (!text || !*text) {
        if (outOk) {
            *outOk = FALSE;
        }
        return ELEVATE_TIER_NONE;
    }
    if (_wcsicmp(text, L"ti") == 0 || _wcsicmp(text, L"trustedinstaller") == 0) {
        return ELEVATE_TIER_TI;
    }
    if (_wcsicmp(text, L"system") == 0 || _wcsicmp(text, L"local system") == 0) {
        return ELEVATE_TIER_SYSTEM;
    }
    if (_wcsicmp(text, L"admin") == 0 || _wcsicmp(text, L"administrator") == 0) {
        return ELEVATE_TIER_ADMIN;
    }
    if (outOk) {
        *outOk = FALSE;
    }
    return ELEVATE_TIER_NONE;
}

BOOL ElevateQueryIdentity(ELEVATE_STATUS *status) {
    QueryProcessIdentity(&status->process);
    status->effective = status->process;
    status->tier = status->process.tier;
    status->landed = status->process.tier >= 0;
    return status->process.valid;
}

int ElevateCurrentTier(void) {
    ELEVATE_IDENTITY identity;

    if (!QueryProcessIdentity(&identity)) {
        return ELEVATE_TIER_NONE;
    }
    return identity.tier;
}

BOOL ElevateProcessTier(HANDLE process, int *outTier, DWORD *outError) {
    HANDLE token = NULL;
    ELEVATE_IDENTITY identity;

    *outTier = ELEVATE_TIER_NONE;
    *outError = ERROR_SUCCESS;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        *outError = GetLastError();
        return FALSE;
    }
    QueryTokenIdentity(token, &identity);
    CloseHandle(token);
    if (!identity.valid) {
        *outError = identity.error != ERROR_SUCCESS ? identity.error : ERROR_ACCESS_DENIED;
        return FALSE;
    }
    *outTier = identity.tier;
    return TRUE;
}

/* -------------------------------------------------------------------- 特权 */

BOOL ElevateEnablePrivilege(LPCWSTR name, DWORD *outError) {
    HANDLE token;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    BOOL ok;
    DWORD error = ERROR_SUCCESS;

    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        error = GetLastError();
        if (outError) {
            *outError = error;
        }
        return FALSE;
    }
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        error = GetLastError();
        if (outError) {
            *outError = error;
        }
        CloseHandle(token);
        return FALSE;
    }
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    ok = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL);
    error = GetLastError();
    CloseHandle(token);
    if (outError) {
        *outError = error;
    }
    return ok && error == ERROR_SUCCESS;
}

static const wchar_t *const kElevatePrivileges[] = {
    SE_DEBUG_NAME,
    SE_IMPERSONATE_NAME,
    SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_TAKE_OWNERSHIP_NAME,
    SE_BACKUP_NAME,
    SE_RESTORE_NAME,
    SE_INCREASE_BASE_PRIORITY_NAME
};

DWORD ElevateEnablePrivileges(void) {
    DWORD firstError = ERROR_SUCCESS;
    size_t i;

    for (i = 0; i < sizeof(kElevatePrivileges) / sizeof(kElevatePrivileges[0]); i++) {
        DWORD error = ERROR_SUCCESS;
        if (!ElevateEnablePrivilege(kElevatePrivileges[i], &error) &&
            firstError == ERROR_SUCCESS) {
            firstError = error != ERROR_SUCCESS ? error : ERROR_PRIVILEGE_NOT_HELD;
        }
    }
    return firstError;
}

/* 把令牌里的所有特权打开：Luid 置零即“全部”，这是 AdjustTokenPrivileges 的约定。 */
static void EnableAllTokenPrivileges(HANDLE token) {
    TOKEN_PRIVILEGES privileges;

    memset(&privileges, 0, sizeof(privileges));
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid.LowPart = 0;
    privileges.Privileges[0].Luid.HighPart = 0;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
}

/* -------------------------------------------------------------- 令牌获取 */

/* 打开**别人**的令牌时只能要这几个：
   TOKEN_ADJUST_PRIVILEGES / GROUPS / DEFAULT 只授予令牌持有者本人，
   对 SYSTEM 令牌带上它们必定 ERROR_ACCESS_DENIED(5)。
   实测 winlogon.exe 这种 PPL 进程给 QUERY|DUPLICATE，services.exe 只给 QUERY|DUPLICATE，
   svchost 甚至只给 QUERY —— 所以外部进程令牌永远只能当兜底，不能当主路径。 */
#define ELEVATE_TOKEN_OPEN_RIGHTS \
    (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE)

/* 复制出来的新句柄是自己创建的，才可以把权利要全。 */
#define ELEVATE_TOKEN_DUP_RIGHTS TOKEN_ALL_ACCESS

static BOOL DuplicateTokenFromPid(DWORD pid, HANDLE *outToken, DWORD *outError) {
    HANDLE process;
    HANDLE token;
    HANDLE primary = NULL;

    *outToken = NULL;
    *outError = ERROR_SUCCESS;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        *outError = GetLastError();
        return FALSE;
    }
    if (!OpenProcessToken(process, ELEVATE_TOKEN_OPEN_RIGHTS, &token)) {
        *outError = GetLastError();
        CloseHandle(process);
        return FALSE;
    }
    if (!DuplicateTokenEx(
            token,
            ELEVATE_TOKEN_DUP_RIGHTS,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &primary)) {
        *outError = GetLastError();
    }
    CloseHandle(token);
    CloseHandle(process);
    if (!primary) {
        if (*outError == ERROR_SUCCESS) {
            *outError = ERROR_ACCESS_DENIED;
        }
        return FALSE;
    }
    *outToken = primary;
    return TRUE;
}

static BOOL FindProcessNamed(const wchar_t *name, DWORD *outPid) {
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    BOOL found = FALSE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) != 0) {
                continue;
            }
            *outPid = entry.th32ProcessID;
            found = TRUE;
            break;
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

static BOOL FindProcessBySid(const wchar_t *sidText, DWORD *outPid, wchar_t *outName, size_t nameSize) {
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    BOOL found = FALSE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            HANDLE process;
            HANDLE token;
            wchar_t sid[192];
            DWORD error = ERROR_SUCCESS;

            if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4) {
                continue;
            }
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
            if (!process) {
                continue;
            }
            if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
                if (SidStringFromToken(token, sid, sizeof(sid) / sizeof(wchar_t), &error) &&
                    _wcsicmp(sid, sidText) == 0) {
                    *outPid = entry.th32ProcessID;
                    wcsncpy(outName, entry.szExeFile, nameSize - 1);
                    outName[nameSize - 1] = 0;
                    found = TRUE;
                }
                CloseHandle(token);
            }
            CloseHandle(process);
            if (found) {
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

/* stage 用来回报卡在哪一步；SERVICE_STOP 不在请求里——TrustedInstaller 的服务
   描述符不一定给管理员停的权限，多要一个权利会让 OpenService 整个失败(5)。 */
static BOOL StartTrustedInstallerService(DWORD *outPid, DWORD *outError, wchar_t *stage, size_t stageSize) {
    SC_HANDLE manager;
    SC_HANDLE service;
    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0;
    int attempt;
    BOOL ok = FALSE;

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

static BOOL AcquireTrustedInstallerToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    DWORD pid = 0;
    DWORD error = ERROR_SUCCESS;
    wchar_t stage[96];

    if (FindProcessNamed(ELEVATE_TI_PROCESS_NAME, &pid) &&
        DuplicateTokenFromPid(pid, outToken, &error)) {
        result->pid = pid;
        wcsncpy(result->source, ELEVATE_TI_PROCESS_NAME, sizeof(result->source) / sizeof(wchar_t) - 1);
        wcscpy(result->note, L"existing process");
        return TRUE;
    }
    wcscpy(stage, L"no TrustedInstaller.exe running");
    if (StartTrustedInstallerService(&pid, &error, stage, sizeof(stage) / sizeof(stage[0]))) {
        result->startedService = TRUE;
        if (DuplicateTokenFromPid(pid, outToken, &error)) {
            result->pid = pid;
            wcsncpy(result->source, ELEVATE_TI_PROCESS_NAME, sizeof(result->source) / sizeof(wchar_t) - 1);
            wcscpy(result->note, L"service started");
            return TRUE;
        }
        /* 现代 Windows 上 TrustedInstaller.exe 是 PPL，令牌里只给 SYSTEM 和 TI 自己的
           服务 SID，Administrators 连 TOKEN_DUPLICATE 都拿不到——这一档拿不到是常态。 */
        if (error == ERROR_ACCESS_DENIED) {
            wcscpy(stage, L"PPL token not granted to Administrators");
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

    table[0].lpServiceName = (LPWSTR)ELEVATE_DONOR_SERVICE_NAME;
    table[0].lpServiceProc = DonorServiceMain;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    if (!StartServiceCtrlDispatcherW(table)) {
        /* 不是被 SCM 拉起来的（用户手敲了 --syndonor），直接退。 */
        return 1;
    }
    return 0;
}

/* 把上一轮可能残留的供体服务清掉：它是 HKLM 下的服务注册项，
   留着指向用户可写路径的二进制就是一个本地提权隐患。 */
static void RemoveDonorService(SC_HANDLE manager) {
    SC_HANDLE service;
    SERVICE_STATUS status;
    int attempt;

    service = OpenServiceW(
        manager,
        ELEVATE_DONOR_SERVICE_NAME,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!service) {
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
static BOOL AcquireSystemTokenViaService(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
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
    if (!SelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
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
    if (!DuplicateTokenFromPid(pid, &token, &error)) {
        result->error = error;
        wcscpy(result->note, L"open donor token failed");
        goto done;
    }
    if (!TokenSidEquals(token, ELEVATE_SYSTEM_SID_STRING)) {
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

static BOOL AcquireSystemToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    DWORD pid = 0;
    DWORD error = ERROR_SUCCESS;
    DWORD serviceError;
    wchar_t serviceNote[96];
    size_t i;

    /* 首选自建供体：令牌来源确定，不受 PPL、不受目标机器上跑了什么影响。 */
    if (AcquireSystemTokenViaService(result, outToken)) {
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

        if (!FindProcessNamed(kSystemCandidates[i], &pid)) {
            continue;
        }
        if (!DuplicateTokenFromPid(pid, &token, &error)) {
            continue;
        }
        /* 同名进程可能不是 SYSTEM（例如用户会话里的 svchost），必须核对 SID。 */
        if (TokenSidEquals(token, ELEVATE_SYSTEM_SID_STRING)) {
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
        if (!FindProcessBySid(ELEVATE_SYSTEM_SID_STRING, &pid, name, sizeof(name) / sizeof(name[0]))) {
            error = ERROR_NOT_FOUND;
        } else if (DuplicateTokenFromPid(pid, &token, &error)) {
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

BOOL ElevateAcquireToken(int tier, ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    *outToken = NULL;
    result->tried = TRUE;
    result->ok = FALSE;
    result->error = ERROR_SUCCESS;
    result->pid = 0;
    switch (tier) {
    case ELEVATE_TIER_TI:
        return AcquireTrustedInstallerToken(result, outToken);
    case ELEVATE_TIER_SYSTEM:
        return AcquireSystemToken(result, outToken);
    }
    result->error = ERROR_INVALID_PARAMETER;
    return FALSE;
}

/* ------------------------------------------------------------ 落地到本进程 */

static BOOL ImpersonateWithToken(HANDLE primary, HANDLE *outImpersonation, DWORD *outError) {
    HANDLE impersonation = NULL;

    *outError = ERROR_SUCCESS;
    EnableAllTokenPrivileges(primary);
    if (!DuplicateTokenEx(
            primary,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES,
            NULL,
            SecurityImpersonation,
            TokenImpersonation,
            &impersonation)) {
        *outError = GetLastError();
        return FALSE;
    }
    EnableAllTokenPrivileges(impersonation);
    if (!SetThreadToken(NULL, impersonation)) {
        *outError = GetLastError();
        CloseHandle(impersonation);
        return FALSE;
    }
    *outImpersonation = impersonation;
    return TRUE;
}

void ElevateRevert(void) {
    if (g_impersonation) {
        RevertToSelf();
        CloseHandle(g_impersonation);
        g_impersonation = NULL;
    }
    g_elevate.impersonating = FALSE;
    g_elevate.effective = g_elevate.process;
    g_elevate.tier = g_elevate.process.tier;
    /* landed 也要跟着回退，否则 tier==-1 却 landed==TRUE 会让两处判定打架。 */
    g_elevate.landed = g_elevate.process.tier >= 0;
}

/* ---------------------------------------------------------------- 拉起自身 */

static void AppendQuotedArg(wchar_t *buffer, size_t capacity, size_t *used, const wchar_t *arg) {
    size_t backslashes = 0;
    const wchar_t *cursor;
    size_t extra = wcslen(arg) * 2 + 8;

    if (*used + extra >= capacity) {
        return;
    }
    if (*used) {
        buffer[(*used)++] = L' ';
    }
    buffer[(*used)++] = L'"';
    for (cursor = arg; *cursor; cursor++) {
        if (*cursor == L'\\') {
            backslashes++;
            continue;
        }
        if (*cursor == L'"') {
            size_t k;
            for (k = 0; k < backslashes * 2 + 1; k++) {
                buffer[(*used)++] = L'\\';
            }
            backslashes = 0;
            buffer[(*used)++] = L'"';
            continue;
        }
        while (backslashes > 0) {
            buffer[(*used)++] = L'\\';
            backslashes--;
        }
        buffer[(*used)++] = *cursor;
    }
    /* 收尾的反斜杠必须成双：紧挨着闭合引号的那个 \ 会被解析成 \"（转义引号），
       参数就永远合不上，把后面的参数一起吞掉。规则是 2n 个 \ + " 表示 n 个 \ 加上引号结束。 */
    while (backslashes > 0) {
        buffer[(*used)++] = L'\\';
        buffer[(*used)++] = L'\\';
        backslashes--;
    }
    buffer[(*used)++] = L'"';
    buffer[*used] = 0;
}

/* 过滤掉旧的 --escalated=，再在最前面插入新的档位声明。 */
static wchar_t *BuildChildArguments(int tier, int argc, wchar_t **argv) {
    size_t capacity = 64;
    size_t used = 0;
    wchar_t *buffer;
    wchar_t marker[32];
    int i;

    for (i = 1; i < argc; i++) {
        capacity += wcslen(argv[i]) * 2 + 8;
    }
    buffer = (wchar_t *)calloc(capacity, sizeof(wchar_t));
    if (!buffer) {
        return NULL;
    }
    swprintf(marker, sizeof(marker) / sizeof(marker[0]), L"--escalated=%d", tier);
    AppendQuotedArg(buffer, capacity, &used, marker);
    for (i = 1; i < argc; i++) {
        if (wcsncmp(argv[i], L"--escalated=", 12) == 0) {
            continue;
        }
        AppendQuotedArg(buffer, capacity, &used, argv[i]);
    }
    return buffer;
}

static BOOL CreateProcessWithElevatedToken(
    HANDLE token,
    wchar_t *commandLine,
    DWORD creationFlags,
    PROCESS_INFORMATION *process,
    DWORD *outError
) {
    STARTUPINFOW startup;

    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    memset(process, 0, sizeof(*process));
    *outError = ERROR_SUCCESS;
    SetLastError(ERROR_SUCCESS);
    if (CreateProcessWithTokenW(
            token,
            0,
            NULL,
            commandLine,
            creationFlags | CREATE_UNICODE_ENVIRONMENT,
            NULL,
            NULL,
            &startup,
            process)) {
        return TRUE;
    }
    *outError = GetLastError();
    if (*outError == ERROR_PRIVILEGE_NOT_HELD ||
        *outError == ERROR_ACCESS_DENIED ||
        *outError == ERROR_NOT_ALL_ASSIGNED) {
        DWORD secondError;
        if (CreateProcessAsUserW(
                token,
                NULL,
                commandLine,
                NULL,
                NULL,
                FALSE,
                creationFlags | CREATE_UNICODE_ENVIRONMENT,
                NULL,
                NULL,
                &startup,
                process)) {
            return TRUE;
        }
        secondError = GetLastError();
        if (secondError != ERROR_SUCCESS) {
            *outError = secondError;
        }
    }
    return FALSE;
}

/* 只负责把提权后的自己拉起来并把进程句柄交给调用者：
   UAC 拉起的是**带独立控制台**的进程，父进程必须先把自己的画面画完再等，
   否则用户只会看到一个一闪而过的窗口，什么也看不到。 */
static BOOL StartElevatedSelf(int argc, wchar_t **argv, HANDLE *outProcess, DWORD *outPid, DWORD *outError) {
    wchar_t executable[MAX_PATH * 2];
    wchar_t *arguments;
    SHELLEXECUTEINFOW info;

    *outProcess = NULL;
    *outPid = 0;
    *outError = ERROR_SUCCESS;
    if (!SelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
        *outError = ERROR_INSUFFICIENT_BUFFER;
        return FALSE;
    }
    arguments = BuildChildArguments(ELEVATE_TIER_ADMIN, argc, argv);
    if (!arguments) {
        *outError = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"runas";
    info.lpFile = executable;
    info.lpParameters = arguments;
    info.lpDirectory = NULL;
    info.nShow = SW_SHOWNORMAL;
    SetLastError(ERROR_SUCCESS);
    if (!ShellExecuteExW(&info)) {
        *outError = GetLastError();
        if (*outError == ERROR_SUCCESS) {
            *outError = ERROR_ACCESS_DENIED;
        }
        free(arguments);
        return FALSE;
    }
    free(arguments);
    if (!info.hProcess) {
        /* 没拿到进程句柄就没法等、也没法透传退出码，按失败处理。 */
        *outError = ERROR_INVALID_HANDLE;
        return FALSE;
    }
    *outProcess = info.hProcess;
    *outPid = GetProcessId(info.hProcess);
    return TRUE;
}

/* ------------------------------------------------------------------ 主流程 */

static void MarkHandoff(int tier, DWORD pid) {
    g_elevate.tiers[tier].ok = TRUE;
    g_elevate.tiers[tier].handoff = TRUE;
    g_elevate.tiers[tier].pid = pid;
    g_elevate.tier = tier;
    g_elevate.landed = TRUE;
    wcscpy(g_elevate.tiers[tier].note, L"token handoff");
}

static BOOL TryHandoff(
    int tier,
    HANDLE token,
    int argc,
    wchar_t **argv,
    ELEVATE_RESULT *result
) {
    wchar_t *arguments;
    wchar_t executable[MAX_PATH * 2];
    wchar_t *commandLine;
    PROCESS_INFORMATION process;
    DWORD error = ERROR_SUCCESS;
    DWORD pid;
    int childTier = ELEVATE_TIER_NONE;
    DWORD verifyError = ERROR_SUCCESS;
    size_t length;

    if (!SelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
        g_elevate.tiers[tier].error = ERROR_INSUFFICIENT_BUFFER;
        wcscpy(g_elevate.tiers[tier].note, L"own executable path too long");
        return FALSE;
    }
    arguments = BuildChildArguments(tier, argc, argv);
    if (!arguments) {
        g_elevate.tiers[tier].error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    length = wcslen(executable) * 2 + wcslen(arguments) + 8;
    commandLine = (wchar_t *)calloc(length, sizeof(wchar_t));
    if (!commandLine) {
        free(arguments);
        g_elevate.tiers[tier].error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }
    {
        size_t used = 0;
        AppendQuotedArg(commandLine, length, &used, executable);
        if (used + wcslen(arguments) + 2 < length) {
            commandLine[used++] = L' ';
            wcsncpy(commandLine + used, arguments, length - used - 1);
            commandLine[length - 1] = 0;
        }
    }
    free(arguments);

    /* 先以挂起状态创建：这样可以在子进程跑起来之前就核验它的令牌。
       控制台输出由子进程负责，父进程只在核验通过后画出提权链。 */
    if (!CreateProcessWithElevatedToken(token, commandLine, CREATE_SUSPENDED, &process, &error)) {
        free(commandLine);
        g_elevate.tiers[tier].error = error;
        return FALSE;
    }
    free(commandLine);
    pid = process.dwProcessId;
    if (!ElevateProcessTier(process.hProcess, &childTier, &verifyError) || childTier != tier) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        g_elevate.tiers[tier].error = verifyError != ERROR_SUCCESS ? verifyError : ERROR_NOT_VERIFIED;
        return FALSE;
    }
    g_elevate.tiers[tier].pid = pid;
    MarkHandoff(tier, pid);
    /* 令牌已经复制进子进程，服务可以收工，恢复系统原状。 */
    ElevateReleaseService();
    UIElevationPanel(&g_elevate, NULL, NULL);
    ResumeThread(process.hThread);
    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &result->exitCode);
    CloseHandle(process.hProcess);
    result->handoff = TRUE;
    result->tier = tier;
    result->pid = pid;
    return TRUE;
}

BOOL ElevateRun(int argc, wchar_t **argv, ELEVATE_RESULT *result) {
    int order[ELEVATE_TIER_COUNT];
    int orderCount = 0;
    int i;

    memset(result, 0, sizeof(*result));
    result->tier = ELEVATE_TIER_NONE;
    memset(&g_elevate, 0, sizeof(g_elevate));
    g_elevate.mode = g_config.elevateMode;
    g_elevate.use = g_config.elevateUse;
    g_elevate.fallback = g_config.elevateFallback;
    g_elevate.requested = g_config.escalatedTier;
    g_elevate.keepService = g_config.elevateKeepService;
    ElevateQueryIdentity(&g_elevate);

    if (g_config.escalatedTier >= 0) {
        /* 子进程：父进程已经用对应令牌拉起，不再提权，避免递归。
           标记本身只是父进程的声明，必须拿实际令牌核对，
           否则手敲 --escalated=0 会在诊断面板上伪造出一个 ✓ TrustedInstaller。 */
        ELEVATE_TIER_RESULT *claimed = &g_elevate.tiers[g_config.escalatedTier];

        g_elevate.spawned = TRUE;
        g_elevate.landed = g_elevate.process.tier != ELEVATE_TIER_NONE;
        claimed->tried = TRUE;
        claimed->ok = g_elevate.process.tier == g_config.escalatedTier;
        if (claimed->ok) {
            claimed->pid = GetCurrentProcessId();
            wcscpy(claimed->source, L"inherited from parent");
            wcscpy(claimed->note, L"token verified");
        } else {
            claimed->error = ERROR_INVALID_ACCOUNT_NAME;
            wcscpy(claimed->note, L"parent claim does not match this token");
        }
        result->tier = g_elevate.tier;
        return TRUE;
    }
    if (g_config.elevateMode == ELEVATE_MODE_OFF) {
        result->tier = g_elevate.tier;
        return TRUE;
    }

    g_elevate.privilegeError = ElevateEnablePrivileges();

    if (g_config.elevateMode == ELEVATE_MODE_AUTO) {
        order[orderCount++] = ELEVATE_TIER_TI;
    } else {
        order[orderCount++] = g_config.elevateMode;
    }
    if (g_config.elevateFallback) {
        for (i = order[0] + 1; i < ELEVATE_TIER_COUNT; i++) {
            order[orderCount++] = i;
        }
    }

    for (i = 0; i < orderCount; i++) {
        int tier = order[i];
        ELEVATE_TIER_RESULT *info = &g_elevate.tiers[tier];
        HANDLE token = NULL;

        info->tried = TRUE;
        if (tier == ELEVATE_TIER_ADMIN) {
            /* Administrators 组已启用就意味着访问检查已经以管理员身份进行，
               不额外依赖 TokenElevation 查询成功——那一查失败会把真管理员误判成提权不可用。 */
            if (g_elevate.process.adminGroup) {
                info->ok = TRUE;
                info->pid = GetCurrentProcessId();
                wcscpy(info->source, L"current process");
                wcscpy(info->note, g_elevate.process.elevated ? L"already elevated" : L"admin group enabled");
                g_elevate.tier = ELEVATE_TIER_ADMIN;
                g_elevate.landed = TRUE;
                result->tier = ELEVATE_TIER_ADMIN;
                /* 前面 TI 档可能已经把 TrustedInstaller 服务拉起来了，成功退出前也要收摊。 */
                ElevateReleaseService();
                return TRUE;
            }
            {
                HANDLE elevated = NULL;
                DWORD pid = 0;
                DWORD exitCode = 0;
                DWORD error = ERROR_SUCCESS;
                if (StartElevatedSelf(argc, argv, &elevated, &pid, &error)) {
                    info->pid = pid;
                    wcscpy(info->source, L"UAC elevation");
                    MarkHandoff(ELEVATE_TIER_ADMIN, pid);
                    result->detached = TRUE;
                    /* 提权后的进程有自己的控制台，先把父进程这边的画面画完再去等它。 */
                    ElevateReleaseService();
                    UIElevationPanel(&g_elevate, NULL, NULL);
                    WaitForSingleObject(elevated, INFINITE);
                    GetExitCodeProcess(elevated, &exitCode);
                    CloseHandle(elevated);
                    result->handoff = TRUE;
                    result->tier = ELEVATE_TIER_ADMIN;
                    result->pid = pid;
                    result->exitCode = exitCode;
                    return TRUE;
                }
                if (error == ERROR_CANCELLED) {
                    wcscpy(info->note, L"UAC declined");
                } else if (!g_elevate.process.adminGroup) {
                    wcscpy(info->note, L"token has no Administrators group");
                }
                info->error = error != ERROR_SUCCESS ? error : ERROR_NOT_VERIFIED;
                info->ok = FALSE;
                continue;
            }
        }
        if (g_elevate.process.tier == tier) {
            info->ok = TRUE;
            info->pid = GetCurrentProcessId();
            wcscpy(info->source, L"current process");
            wcscpy(info->note, L"already running at this tier");
            g_elevate.tier = tier;
            g_elevate.landed = TRUE;
            result->tier = tier;
            ElevateReleaseService();
            return TRUE;
        }
        if (!ElevateAcquireToken(tier, info, &token)) {
            continue;
        }
        if (g_elevate.use != ELEVATE_USE_SPAWN) {
            HANDLE impersonation = NULL;
            DWORD error = ERROR_SUCCESS;
            ELEVATE_IDENTITY identity;

            if (ImpersonateWithToken(token, &impersonation, &error)) {
                QueryThreadIdentity(&identity);
                if (identity.tier == tier) {
                    g_impersonation = impersonation;
                    g_elevate.impersonating = TRUE;
                    g_elevate.effective = identity;
                    g_elevate.tier = tier;
                    g_elevate.landed = TRUE;
                    info->ok = TRUE;
                    info->impersonated = TRUE;
                    wcscpy(info->note, L"thread impersonation");
                    result->tier = tier;
                    /* 身份已经挂在当前线程上，TrustedInstaller 服务可以停掉了。 */
                    ElevateReleaseService();
                    CloseHandle(token);
                    return TRUE;
                }
                RevertToSelf();
                CloseHandle(impersonation);
                error = ERROR_NOT_VERIFIED;
            }
            info->error = error;
            if (g_elevate.use == ELEVATE_USE_IMPERSONATE) {
                CloseHandle(token);
                continue;
            }
        }
        if (TryHandoff(tier, token, argc, argv, result)) {
            info->ok = TRUE;
            CloseHandle(token);
            return TRUE;
        }
        CloseHandle(token);
    }

    ElevateReleaseService();
    g_elevate.tier = g_elevate.process.tier;
    result->tier = g_elevate.tier;
    return TRUE;
}
