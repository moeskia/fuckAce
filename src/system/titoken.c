#include "system/titoken.h"

#include <sddl.h>

/* TrustedInstaller 令牌的构造：不碰系统上的任何持久状态，直接把
   NT SERVICE\TrustedInstaller 作为 SID 拼进一个新建令牌里。

   为什么要这么做：现代 Windows 上 TrustedInstaller.exe 是 PPL，
   Administrators 连它的 TOKEN_DUPLICATE 都拿不到，而“抢它的令牌”这条路
   本身也不该是唯一的路。访问检查认的是**令牌里的组 SID**，不是“你是不是
   那个进程”，所以只要令牌的组里有 NT SERVICE\TrustedInstaller 且 enabled，
   所有授予 TI 的 ACL 就都会对我们放行。

   NtCreateToken 需要一个只有 LocalSystem 才有的特权 SeCreateTokenPrivilege，
   所以调用方必须先把线程切到 SYSTEM 身份上（elevation/ti.c 里负责这件事）。 */

typedef NTSTATUS(NTAPI *NT_CREATE_TOKEN)(
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TOKEN_TYPE TokenType,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER User,
    PTOKEN_GROUPS Groups,
    PTOKEN_PRIVILEGES Privileges,
    PTOKEN_OWNER Owner,
    PTOKEN_PRIMARY_GROUP PrimaryGroup,
    PTOKEN_DEFAULT_DACL DefaultDacl,
    PTOKEN_SOURCE TokenSource);

typedef NTSTATUS(NTAPI *NT_SET_INFORMATION_TOKEN)(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength);

/* winternl.h（MinGW-w64）不导出这两个，从 ntdll 动态取；
   顺带避开不同 SDK 之间 NtCreateToken 签名漂移带来的链接问题。 */
static NT_CREATE_TOKEN TiNtCreateToken(void) {
    static NT_CREATE_TOKEN cached;
    static BOOL resolved;

    if (!resolved) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            FARPROC proc = GetProcAddress(ntdll, "NtCreateToken");
            memcpy(&cached, &proc, sizeof(cached));
        }
        resolved = TRUE;
    }
    return cached;
}

static NT_SET_INFORMATION_TOKEN TiNtSetInformationToken(void) {
    static NT_SET_INFORMATION_TOKEN cached;
    static BOOL resolved;

    if (!resolved) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            FARPROC proc = GetProcAddress(ntdll, "NtSetInformationToken");
            memcpy(&cached, &proc, sizeof(cached));
        }
        resolved = TRUE;
    }
    return cached;
}

/* 界面上的错误码一律按 Win32 显示，这里把几个真正常见的 NTSTATUS 翻过去，
   剩下的原样透传（最高位为 1，一眼就能看出是 NTSTATUS）。 */
static DWORD TiStatusToWin32(NTSTATUS status) {
    switch ((ULONG)status) {
    case 0xC0000061UL: /* STATUS_PRIVILEGE_NOT_HELD */
        return ERROR_PRIVILEGE_NOT_HELD;
    case 0xC0000022UL: /* STATUS_ACCESS_DENIED */
        return ERROR_ACCESS_DENIED;
    case 0xC000000DUL: /* STATUS_INVALID_PARAMETER */
        return ERROR_INVALID_PARAMETER;
    case 0xC0000062UL: /* STATUS_INVALID_ACCOUNT_NAME */
        return ERROR_INVALID_ACCOUNT_NAME;
    case 0xC00000A5UL: /* STATUS_BAD_IMPERSONATION_LEVEL */
        return ERROR_BAD_IMPERSONATION_LEVEL;
    case 0xC0000023UL: /* STATUS_BUFFER_TOO_SMALL */
        return ERROR_INSUFFICIENT_BUFFER;
    }
    return (DWORD)status;
}

/* winnt.h 里这几个是枚举值，用宏覆盖成等价数值是安全的：
   TokenSessionId = 12、TokenIntegrityLevel = 25。 */
#ifndef TokenSessionId
#define TokenSessionId ((TOKEN_INFORMATION_CLASS)12)
#endif
#ifndef TokenIntegrityLevel
#define TokenIntegrityLevel ((TOKEN_INFORMATION_CLASS)25)
#endif

BOOL TiTokenGroupEnabled(HANDLE token, const wchar_t *sidText) {
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

/* 只打开**当前线程有效身份**上的特权：借用 SYSTEM 的时候进程令牌还是 admin，
   在进程令牌上找 SeCreateTokenPrivilege 是找不到的。
   OpenAsSelf=TRUE 让句柄本身的访问检查走进程令牌，避免被模拟身份卡住。 */
static BOOL TiOpenEffectiveToken(DWORD rights, HANDLE *outToken) {
    return OpenThreadToken(GetCurrentThread(), rights, TRUE, outToken) ||
           OpenProcessToken(GetCurrentProcess(), rights, outToken);
}

BOOL TiEffectiveTokenHasPrivilege(LPCWSTR name) {
    HANDLE token = NULL;
    LUID target;
    TOKEN_PRIVILEGES *privileges;
    BYTE buffer[16384];
    DWORD needed = 0;
    DWORD i;
    BOOL found = FALSE;

    if (!TiOpenEffectiveToken(TOKEN_QUERY, &token)) {
        return FALSE;
    }
    if (LookupPrivilegeValueW(NULL, name, &target) &&
        GetTokenInformation(token, TokenPrivileges, buffer, sizeof(buffer), &needed)) {
        privileges = (TOKEN_PRIVILEGES *)buffer;
        for (i = 0; i < privileges->PrivilegeCount; i++) {
            if (privileges->Privileges[i].Luid.LowPart == target.LowPart &&
                privileges->Privileges[i].Luid.HighPart == target.HighPart) {
                found = TRUE;
                break;
            }
        }
    }
    CloseHandle(token);
    return found;
}

static BOOL TiEnableEffectivePrivilege(LPCWSTR name, DWORD *outError) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    BOOL ok;
    DWORD error = ERROR_SUCCESS;

    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    if (!TiOpenEffectiveToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        error = GetLastError();
        if (outError) {
            *outError = error;
        }
        return FALSE;
    }
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        error = GetLastError();
        CloseHandle(token);
        if (outError) {
            *outError = error;
        }
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

/* 按名字解析，省得依赖各 SDK 里 SE_*_NAME 宏是否齐全；本机没有的特权直接跳过。 */
static const wchar_t *const kForgePrivileges[] = {
    L"SeCreateTokenPrivilege",
    L"SeAssignPrimaryTokenPrivilege",
    L"SeLockMemoryPrivilege",
    L"SeIncreaseQuotaPrivilege",
    L"SeMachineAccountPrivilege",
    L"SeTcbPrivilege",
    L"SeSecurityPrivilege",
    L"SeTakeOwnershipPrivilege",
    L"SeLoadDriverPrivilege",
    L"SeSystemProfilePrivilege",
    L"SeSystemtimePrivilege",
    L"SeProfileSingleProcessPrivilege",
    L"SeIncreaseBasePriorityPrivilege",
    L"SeCreatePagefilePrivilege",
    L"SeCreatePermanentPrivilege",
    L"SeBackupPrivilege",
    L"SeRestorePrivilege",
    L"SeShutdownPrivilege",
    L"SeDebugPrivilege",
    L"SeAuditPrivilege",
    L"SeSystemEnvironmentPrivilege",
    L"SeChangeNotifyPrivilege",
    L"SeRemoteShutdownPrivilege",
    L"SeUndockPrivilege",
    L"SeSyncAgentPrivilege",
    L"SeEnableDelegationPrivilege",
    L"SeManageVolumePrivilege",
    L"SeImpersonatePrivilege",
    L"SeCreateGlobalPrivilege",
    L"SeRelabelPrivilege",
    L"SeCreateSymbolicLinkPrivilege",
    L"SeTimeZonePrivilege",
    L"SeIncreaseWorkingSetPrivilege",
    L"SeTrustedCredManAccessPrivilege"
};

#define TITOKEN_PRIV_MAX ((int)(sizeof(kForgePrivileges) / sizeof(kForgePrivileges[0])))

/* 组里的必备项：TI 是目的，SYSTEM / Administrators 让新令牌不至于比 SYSTEM 更弱。
   真实 TI 令牌里 Administrators 是 deny-only，这里刻意保持 enabled ——
   伪造出来的身份是“真实 TI 的超集”，不会因为少一条组 SID 而在别处被拦。 */
static const wchar_t *const kForgeGroups[] = {
    L"S-1-5-6",   /* SERVICE */
    L"S-1-5-18",  /* LOCAL SYSTEM */
    L"S-1-5-32-544", /* Administrators */
    L"S-1-5-11",  /* Authenticated Users */
    L"S-1-1-0",   /* Everyone */
    L"S-1-5-32-545" /* Users */
};

#define TITOKEN_GROUP_MAX (1 + (int)(sizeof(kForgeGroups) / sizeof(kForgeGroups[0])))
#define TITOKEN_EXTRA_MAX 4
#define TITOKEN_ACE_MAX 4

typedef struct _TITOKEN_GROUPS {
    ULONG GroupCount;
    SID_AND_ATTRIBUTES Groups[TITOKEN_GROUP_MAX];
} TITOKEN_GROUPS;

typedef struct _TITOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[TITOKEN_PRIV_MAX];
} TITOKEN_PRIVILEGES;

#define TITOKEN_DACL_MAX (sizeof(ACL) + TITOKEN_ACE_MAX * (sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE))

static BOOL TiBuildDefaultDacl(PSID *sids, int count, PACL acl, DWORD aclSize) {
    int i;

    if (!InitializeAcl(acl, aclSize, ACL_REVISION)) {
        return FALSE;
    }
    for (i = 0; i < count; i++) {
        if (!AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sids[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

HANDLE TiTokenForge(DWORD sessionId, DWORD *outError) {
    NT_CREATE_TOKEN createToken;
    NT_SET_INFORMATION_TOKEN setTokenInfo;
    HANDLE token = NULL;
    NTSTATUS status = 0;
    PSID user = NULL;
    PSID primaryGroup = NULL;
    PSID integrity = NULL;
    PSID groupSids[TITOKEN_GROUP_MAX];
    PSID extraSids[TITOKEN_EXTRA_MAX];
    PSID daclSids[TITOKEN_ACE_MAX];
    TITOKEN_GROUPS groups;
    TITOKEN_PRIVILEGES privileges;
    TOKEN_USER tokenUser;
    TOKEN_OWNER tokenOwner;
    TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
    TOKEN_DEFAULT_DACL tokenDacl;
    TOKEN_SOURCE source;
    BYTE daclBuffer[TITOKEN_DACL_MAX];
    LUID authenticationId;
    LARGE_INTEGER expiration;
    int groupCount = 0;
    int extraCount = 0;
    int daclCount = 0;
    int i;
    DWORD privError = ERROR_SUCCESS;

    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    createToken = TiNtCreateToken();
    setTokenInfo = TiNtSetInformationToken();
    if (!createToken) {
        if (outError) {
            *outError = ERROR_CALL_NOT_IMPLEMENTED;
        }
        return NULL;
    }
    /* SeCreateTokenPrivilege 在 LocalSystem 的令牌里是**存在但关闭**的，
       不显式打开，NtCreateToken 一定返回 STATUS_PRIVILEGE_NOT_HELD。 */
    if (!TiEnableEffectivePrivilege(L"SeCreateTokenPrivilege", &privError)) {
        if (outError) {
            *outError = privError != ERROR_SUCCESS ? privError : ERROR_PRIVILEGE_NOT_HELD;
        }
        return NULL;
    }
    TiEnableEffectivePrivilege(L"SeTcbPrivilege", NULL);

    if (!ConvertStringSidToSidW(TITOKEN_USER_SID_STRING, &user) ||
        !ConvertStringSidToSidW(TITOKEN_USER_SID_STRING, &primaryGroup)) {
        if (outError) {
            *outError = GetLastError();
        }
        goto done;
    }
    for (i = 0; i < (int)(sizeof(kForgeGroups) / sizeof(kForgeGroups[0])); i++) {
        PSID sid = NULL;
        if (ConvertStringSidToSidW(kForgeGroups[i], &sid)) {
            groupSids[groupCount] = sid;
            groups.Groups[groupCount].Sid = sid;
            groups.Groups[groupCount].Attributes =
                SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
            groupCount++;
        }
    }
    /* 目的本身：这条 SID 必须存在，否则造出来的只是个普通 SYSTEM 令牌。 */
    groupSids[groupCount] = user;
    groups.Groups[groupCount].Sid = user;
    groups.Groups[groupCount].Attributes =
        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    groupCount++;
    groups.GroupCount = (ULONG)groupCount;

    memset(&privileges, 0, sizeof(privileges));
    for (i = 0; i < TITOKEN_PRIV_MAX; i++) {
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, kForgePrivileges[i], &luid)) {
            continue;
        }
        privileges.Privileges[privileges.PrivilegeCount].Luid = luid;
        privileges.Privileges[privileges.PrivilegeCount].Attributes = SE_PRIVILEGE_ENABLED;
        privileges.PrivilegeCount++;
    }
    if (privileges.PrivilegeCount == 0) {
        if (outError) {
            *outError = ERROR_PRIVILEGE_NOT_HELD;
        }
        goto done;
    }

    /* 默认 DACL：新令牌后面创建的对象（进程、线程）都拿它当初始 DACL，
       留 NULL 等于给大家完全控制，不合适。 */
    daclSids[daclCount++] = user;
    for (i = 0; i < 2 && extraCount < TITOKEN_EXTRA_MAX; i++) {
        PSID sid = NULL;
        const wchar_t *text = i == 0 ? L"S-1-5-18" : L"S-1-5-32-544";
        if (ConvertStringSidToSidW(text, &sid)) {
            extraSids[extraCount++] = sid;
            daclSids[daclCount++] = sid;
        }
    }
    memset(&tokenDacl, 0, sizeof(tokenDacl));
    if (!TiBuildDefaultDacl(daclSids, daclCount, (PACL)daclBuffer, sizeof(daclBuffer))) {
        if (outError) {
            *outError = GetLastError();
        }
        goto done;
    }
    tokenDacl.DefaultDacl = (PACL)daclBuffer;

    /* SourceName 是 CHAR[8]，不是字符串：必须正好 8 个字符、不带结尾 0。 */
    memset(&source, 0, sizeof(source));
    memcpy(source.SourceName, "fuckAce ", 8);
    source.SourceIdentifier.LowPart = (DWORD)GetCurrentProcessId();
    source.SourceIdentifier.HighPart = 0;
    authenticationId.LowPart = 0x3e7; /* SYSTEM 的登录会话：后续 CreateProcess* 认得出 */
    authenticationId.HighPart = 0;
    expiration.QuadPart = 0; /* 0 = 不过期 */

    memset(&tokenUser, 0, sizeof(tokenUser));
    tokenUser.User.Sid = user;
    memset(&tokenOwner, 0, sizeof(tokenOwner));
    tokenOwner.Owner = user;
    memset(&tokenPrimaryGroup, 0, sizeof(tokenPrimaryGroup));
    tokenPrimaryGroup.PrimaryGroup = primaryGroup;

    status = createToken(
        &token,
        TOKEN_ALL_ACCESS,
        NULL,
        TokenPrimary,
        &authenticationId,
        &expiration,
        &tokenUser,
        (PTOKEN_GROUPS)&groups,
        (PTOKEN_PRIVILEGES)&privileges,
        &tokenOwner,
        &tokenPrimaryGroup,
        &tokenDacl,
        &source);
    if (status < 0) {
        token = NULL;
        if (outError) {
            *outError = TiStatusToWin32(status);
        }
        goto done;
    }

    /* 完整性级别必须单独设：NtCreateToken 不认组里的 S-1-16-*，不设的话内核按
       Medium 处理，写 High IL 的对象会被拦。会话号同理，不设会掉进 session 0，
       重新拉起自身时会跑到没有桌面的会话里去。 */
    if (!setTokenInfo) {
        if (outError) {
            *outError = ERROR_CALL_NOT_IMPLEMENTED;
        }
        CloseHandle(token);
        token = NULL;
        goto done;
    }
    if (!ConvertStringSidToSidW(L"S-1-16-16384", &integrity)) {
        if (outError) {
            *outError = GetLastError();
        }
        CloseHandle(token);
        token = NULL;
        goto done;
    }
    {
        TOKEN_MANDATORY_LABEL label;

        memset(&label, 0, sizeof(label));
        label.Label.Sid = integrity;
        label.Label.Attributes = SE_GROUP_INTEGRITY;
        status = setTokenInfo(token, TokenIntegrityLevel, &label, sizeof(label));
    }
    if (status < 0) {
        if (outError) {
            *outError = TiStatusToWin32(status);
        }
        CloseHandle(token);
        token = NULL;
        goto done;
    }
    if (sessionId != 0xFFFFFFFFu) {
        UINT session = sessionId;

        status = setTokenInfo(token, TokenSessionId, &session, sizeof(session));
        if (status < 0) {
            if (outError) {
                *outError = TiStatusToWin32(status);
            }
            CloseHandle(token);
            token = NULL;
            goto done;
        }
    }

done:
    for (i = 0; i < groupCount; i++) {
        if (groupSids[i] != user) {
            LocalFree(groupSids[i]);
        }
    }
    for (i = 0; i < extraCount; i++) {
        LocalFree(extraSids[i]);
    }
    if (user) {
        LocalFree(user);
    }
    if (primaryGroup) {
        LocalFree(primaryGroup);
    }
    if (integrity) {
        LocalFree(integrity);
    }
    if (!token && outError && *outError == ERROR_SUCCESS) {
        *outError = ERROR_INVALID_PARAMETER;
    }
    return token;
}
