#include "elevate.h"
#include "config.h"
#include "titoken.h"
#include "ui.h"

#include <sddl.h>
#include <winsvc.h>
#include <shellapi.h>

ELEVATE_STATUS g_elevate;

#define ELEVATE_MUTEX_NAME L"Global\\fuckAceElevation"
#define ELEVATE_MUTEX_LOCAL_NAME L"Local\\fuckAceElevation"
#define ELEVATE_MUTEX_WAIT_MS 60000

static HANDLE g_impersonation = NULL;
static HANDLE g_elevateMutex = NULL;
static BOOL g_elevateMutexHeld = FALSE;

/* 落地到本进程的实现放在后面，TI 的伪造/劫持路径要先用它借用 SYSTEM 身份。 */
static BOOL ImpersonateWithToken(HANDLE primary, HANDLE *outImpersonation, DWORD *outError);

/* 截断安全的宽字符格式化：swprintf 在放不下时可能既不返回长度也不补结尾 0，
   而这里的 note 就是要给人看的诊断信息，绝不能变成未终止的缓冲区。 */
static void ElevateNote(wchar_t *note, size_t capacity, const wchar_t *format, ...) {
    va_list args;

    if (!capacity) {
        return;
    }
    va_start(args, format);
    _vsnwprintf(note, capacity - 1, format, args);
    va_end(args);
    note[capacity - 1] = 0;
}

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

static BOOL ElevateMutexAcquire(DWORD *outError) {
    DWORD wait;

    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    if (g_elevateMutexHeld) {
        return TRUE;
    }
    if (g_elevateMutex) {
        CloseHandle(g_elevateMutex);
        g_elevateMutex = NULL;
    }
    ElevateEnablePrivilege(L"SeCreateGlobalPrivilege", NULL);
    g_elevateMutex = CreateMutexW(NULL, FALSE, ELEVATE_MUTEX_NAME);
    if (!g_elevateMutex) {
        g_elevateMutex = CreateMutexW(NULL, FALSE, ELEVATE_MUTEX_LOCAL_NAME);
    }
    if (!g_elevateMutex) {
        if (outError) {
            *outError = GetLastError();
        }
        return FALSE;
    }
    wait = WaitForSingleObject(g_elevateMutex, ELEVATE_MUTEX_WAIT_MS);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        if (outError) {
            *outError = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT
                                             : (wait == WAIT_FAILED ? GetLastError() : ERROR_BUSY);
        }
        CloseHandle(g_elevateMutex);
        g_elevateMutex = NULL;
        return FALSE;
    }
    g_elevateMutexHeld = TRUE;
    return TRUE;
}

static void ElevateMutexRelease(void) {
    if (!g_elevateMutex) {
        return;
    }
    if (g_elevateMutexHeld) {
        ReleaseMutex(g_elevateMutex);
    }
    g_elevateMutexHeld = FALSE;
    CloseHandle(g_elevateMutex);
    g_elevateMutex = NULL;
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
BOOL ElevateTokenHasGroup(HANDLE token, const wchar_t *sidText) {
    PSID target = NULL;
    TOKEN_GROUPS *groups = NULL;
    DWORD needed = 0;
    DWORD i;
    BOOL found = FALSE;

    if (!token || !sidText || !ConvertStringSidToSidW(sidText, &target)) {
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
                (groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
                !(groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY)) {
                found = TRUE;
                break;
            }
        }
    }
    LocalFree(groups);
    LocalFree(target);
    return found;
}

BOOL ElevateTokenHasAdminGroup(HANDLE token) {
    return ElevateTokenHasGroup(token, ELEVATE_ADMIN_SID_STRING);
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
    identity->trustedInstaller = TiTokenGroupEnabled(token, TITOKEN_TI_SID_STRING);
    identity->elevationType = TokenElevationTypeOf(token);
    identity->sessionId = TokenSessionIdOf(token);
    identity->integrityRid = TokenIntegrityRidOf(token);
    if (_wcsicmp(identity->sid, ELEVATE_TI_SID_STRING) == 0 || identity->trustedInstaller) {
        /* 真的 TI 令牌 TokenUser 就是 TI 的服务 SID；伪造出来的令牌 TokenUser 也是它，
           但组里那条 enabled 的 SID 才是真正决定 ACL 放行与否的东西，两条都认。 */
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

void ElevatePrepareDiagnose(void) {
    memset(&g_elevate, 0, sizeof(g_elevate));
    g_elevate.mode = g_config.elevateMode;
    g_elevate.use = g_config.elevateUse;
    g_elevate.fallback = g_config.elevateFallback;
    g_elevate.requested = g_config.escalatedTier;
    g_elevate.keepService = g_config.elevateKeepService;
    ElevateQueryIdentity(&g_elevate);
    g_elevate.tiKeyStale = ElevateTiKeyStale();
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

/* 把令牌里**已经存在**的特权全部打开。
   注意 AdjustTokenPrivileges 只能开关令牌里已有的特权，它**不能新增**。
   早先那版传入一个 Luid=0 的单项，指望它是"全部"的约定——那个约定并不存在，
   实际效果是什么都没打开：实测拿到的 SYSTEM 令牌里 SeAssignPrimaryTokenPrivilege
   一直是 off，于是 CreateProcessAsUser 必然 ERROR_PRIVILEGE_NOT_HELD，
   "守护进程"那条兜底其实从来没起来过。这里老老实实枚举。 */
static void EnableAllTokenPrivileges(HANDLE token) {
    BYTE buffer[16384];
    DWORD needed = 0;
    TOKEN_PRIVILEGES *current;
    DWORD i;

    if (!GetTokenInformation(token, TokenPrivileges, buffer, sizeof(buffer), &needed)) {
        return;
    }
    current = (TOKEN_PRIVILEGES *)buffer;
    for (i = 0; i < current->PrivilegeCount; i++) {
        TOKEN_PRIVILEGES single;

        if (current->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
            continue;
        }
        single.PrivilegeCount = 1;
        single.Privileges[0].Luid = current->Privileges[i].Luid;
        single.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(ERROR_SUCCESS);
        AdjustTokenPrivileges(token, FALSE, &single, 0, NULL, NULL);
    }
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
   描述符不一定给管理员停的权限，多要一个权利会让 OpenService 整个失败(5)。
   outStarted 只在**这一次真的是我们把它从"没在跑"拉起来**时才为 TRUE：
   区分"我们启动的"和"本来就在跑的"很重要，前者该被我们停回去，后者不该被我们碰。 */
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

static BOOL DuplicateTrustedInstallerTokenFromPid(DWORD pid, HANDLE *outToken, DWORD *outError) {
    HANDLE token = NULL;

    if (!DuplicateTokenFromPid(pid, &token, outError)) {
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
            if (DuplicateTrustedInstallerTokenFromPid(entry.th32ProcessID, &token, &error)) {
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

static BOOL AcquireTrustedInstallerTokenFromProcess(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
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
        if (DuplicateTrustedInstallerTokenFromPid(pid, outToken, &error)) {
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

    if (!SelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
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

/* 一轮提权里 SYSTEM 令牌会被要两次：一次是 TI 档借它当伪造底座，一次是
   SYSTEM 档自己落地。自建供体服务不便宜（建服务、起进程、复制令牌、再停掉），
   所以第一次拿到就留一份，后面直接复用。句柄只在本进程里，ElevateRun 开头清掉。 */
static HANDLE g_systemBase = NULL;
static ELEVATE_TIER_RESULT g_systemBaseInfo;

static void ReleaseSystemBase(void) {
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
static BOOL AcquireSystemTokenUncached(ELEVATE_TIER_RESULT *result, HANDLE *outToken);

static BOOL AcquireSystemToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
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
    if (!AcquireSystemTokenUncached(result, outToken)) {
        return FALSE;
    }
    g_systemBaseInfo = *result;
    if (!DuplicatePrimaryToken(*outToken, &g_systemBase, &error)) {
        /* 缓存不上不算失败：令牌本身是好的，下一档再去拿一次就行。 */
        memset(&g_systemBaseInfo, 0, sizeof(g_systemBaseInfo));
    }
    return TRUE;
}

static BOOL AcquireSystemTokenUncached(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
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

    if (!SelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
        return;
    }
    if (!token && !OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES,
            &token)) {
        return;
    }
    EnableAllTokenPrivileges(token);
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
static BOOL AcquireTrustedInstallerTokenForged(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
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
static BOOL AcquireTrustedInstallerTokenViaHijack(
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
    if (!SelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
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
    TiSpawnGuardian(g_systemBase);

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
    if (!DuplicateTrustedInstallerTokenFromPid(pid, &token, &error)) {
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
static BOOL AcquireTrustedInstallerTokenElevated(
    ELEVATE_TIER_RESULT *result,
    HANDLE *outToken,
    int serviceWasRunning
) {
    ELEVATE_TIER_RESULT forge;
    ELEVATE_TIER_RESULT hijack;

    memset(&forge, 0, sizeof(forge));
    if (AcquireTrustedInstallerTokenForged(&forge, outToken)) {
        ElevateTierResultCopy(result, &forge);
        return TRUE;
    }
    memset(&hijack, 0, sizeof(hijack));
    if (AcquireTrustedInstallerTokenViaHijack(&hijack, outToken, serviceWasRunning)) {
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
static BOOL AcquireTrustedInstallerToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
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
    if (AcquireTrustedInstallerTokenFromProcess(&direct, outToken)) {
        ElevateTierResultCopy(result, &direct);
        return TRUE;
    }
    memset(&elevated, 0, sizeof(elevated));
    /* 方法一要是启动过服务，收摊的责任得一路带到最终结果里去，否则那个由我们
       拉起来的 TrustedInstaller 就永远留在系统里跑着了。 */
    elevated.startedService = direct.startedService;
    if (g_impersonation != NULL) {
        elevated.error = ERROR_BUSY;
        wcscpy(elevated.note, L"already impersonating another identity");
        ok = FALSE;
    } else {
        if (g_elevate.process.tier != ELEVATE_TIER_SYSTEM) {
            memset(&sysInfo, 0, sizeof(sysInfo));
            sysInfo.tried = TRUE;
            if (!AcquireSystemToken(&sysInfo, &base)) {
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
            if (!ImpersonateWithToken(base, &impersonation, &error)) {
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
        ok = AcquireTrustedInstallerTokenElevated(&elevated, outToken, serviceWasRunning);
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

BOOL ElevateAcquireToken(int tier, ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    /* tried 由唯一调用方 ElevateRun 标记（它还要覆盖 admin 与“已在该档”路径），
       这里不再重复设置。 */
    *outToken = NULL;
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
    ElevateTiRestoreKey(NULL);
    if (g_impersonation) {
        RevertToSelf();
        CloseHandle(g_impersonation);
        g_impersonation = NULL;
    }
    g_elevate.impersonating = FALSE;
    g_elevate.effective = g_elevate.process;
    g_elevate.tier = g_elevate.process.tier;
    g_elevate.landed = g_elevate.process.tier >= 0;
    ReleaseSystemBase();
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
    ElevateMutexRelease();
    if (ResumeThread(process.hThread) == (DWORD)-1) {
        error = GetLastError();
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        g_elevate.tiers[tier].pid = 0;
        g_elevate.tiers[tier].ok = FALSE;
        g_elevate.tiers[tier].handoff = FALSE;
        g_elevate.tiers[tier].error = error;
        wcscpy(g_elevate.tiers[tier].note, L"ResumeThread failed");
        g_elevate.tier = g_elevate.process.tier;
        g_elevate.landed = g_elevate.process.tier >= 0;
        return FALSE;
    }
    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &result->exitCode);
    CloseHandle(process.hProcess);
    result->handoff = TRUE;
    result->tier = tier;
    result->pid = pid;
    return TRUE;
}

/* 上一次劫持要是没留下干净的服务键，这里负责收尾。
   关键点：`TrustedInstaller` 的服务键对 Administrators 只有 ReadKey，**还原也必须站在
   SYSTEM 上**，所以这里跟 TI 档一样借一次 SYSTEM 身份——否则"启动自检"只是个摆设。
   守护进程（`--tirepair=`）是更早的一层网，这里管的是"连守护进程都没了"。 */
static BOOL ElevateTiRepairWithSystemIdentity(void) {
    ELEVATE_TIER_RESULT sysInfo;
    HANDLE base = NULL;
    HANDLE impersonation = NULL;
    DWORD error = ERROR_SUCCESS;
    BOOL ok;

    if (!ElevateTiKeyStale()) {
        return TRUE;
    }
    if (g_elevate.process.tier == ELEVATE_TIER_SYSTEM || g_elevate.process.tier == ELEVATE_TIER_TI ||
        g_impersonation != NULL) {
        /* 已经是高一档的身份，直接用当前有效令牌写。 */
        return ElevateTiRestoreKey(&error);
    }
    memset(&sysInfo, 0, sizeof(sysInfo));
    sysInfo.tried = TRUE;
    if (!AcquireSystemToken(&sysInfo, &base)) {
        return FALSE;
    }
    if (!ImpersonateWithToken(base, &impersonation, &error)) {
        CloseHandle(base);
        return FALSE;
    }
    ok = ElevateTiRestoreKey(&error);
    RevertToSelf();
    CloseHandle(impersonation);
    CloseHandle(base);
    return ok;
}

BOOL ElevateRun(int argc, wchar_t **argv, ELEVATE_RESULT *result) {
    int order[ELEVATE_TIER_COUNT];
    int orderCount = 0;
    int i;

    memset(result, 0, sizeof(*result));
    result->tier = ELEVATE_TIER_NONE;
    ReleaseSystemBase();
    memset(&g_elevate, 0, sizeof(g_elevate));
    g_elevate.mode = g_config.elevateMode;
    g_elevate.use = g_config.elevateUse;
    g_elevate.fallback = g_config.elevateFallback;
    g_elevate.requested = g_config.escalatedTier;
    g_elevate.keepService = g_config.elevateKeepService;
    ElevateQueryIdentity(&g_elevate);
    g_elevate.tiKeyStale = ElevateTiKeyStale();

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

    {
        DWORD mutexError = ERROR_SUCCESS;

        if (!ElevateMutexAcquire(&mutexError)) {
            int tier = g_config.elevateMode == ELEVATE_MODE_AUTO ? ELEVATE_TIER_TI
                                                                 : g_config.elevateMode;

            g_elevate.tiers[tier].tried = TRUE;
            g_elevate.tiers[tier].error = mutexError;
            wcscpy(g_elevate.tiers[tier].note, L"another fuckAce instance is active");
            result->tier = g_elevate.tier;
            return TRUE;
        }
    }

    g_elevate.privilegeError = ElevateEnablePrivileges();
    /* 上一次劫持要是没来得及还原（崩在那几百毫秒里、连守护进程也没了），
       先把服务键修回去再谈别的。 */
    if (g_elevate.tiKeyStale) {
        ElevateTiRepairWithSystemIdentity();
        g_elevate.tiKeyStale = ElevateTiKeyStale();
    }

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
                ElevateMutexRelease();
                return TRUE;
            }
            {
                HANDLE elevated = NULL;
                DWORD pid = 0;
                DWORD exitCode = 0;
                DWORD error = ERROR_SUCCESS;
                ElevateReleaseService();
                ElevateMutexRelease();
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
            ElevateMutexRelease();
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
                    ElevateMutexRelease();
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
        {
            DWORD mutexError = ERROR_SUCCESS;

            if (!ElevateMutexAcquire(&mutexError)) {
                info->error = mutexError;
                wcscpy(info->note, L"elevation mutex lost");
                CloseHandle(token);
                break;
            }
        }
        CloseHandle(token);
    }

    ElevateReleaseService();
    ElevateMutexRelease();
    g_elevate.tier = g_elevate.process.tier;
    result->tier = g_elevate.tier;
    return TRUE;
}
