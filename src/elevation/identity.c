#include "elevation/elevate.h"
#include "app/config.h"
#include "elevation/elevate_internal.h"
#include "system/titoken.h"

#include <sddl.h>

/* ---------------------------------------------------------------- 身份查询 */

BOOL ElevateSidStringFromToken(HANDLE token, wchar_t *buffer, size_t size, DWORD *outError) {
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
    return TiTokenGroupEnabled(token, sidText);
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
    if (!ElevateSidStringFromToken(token, identity->sid, sizeof(identity->sid) / sizeof(wchar_t), &error)) {
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

BOOL ElevateQueryThreadIdentity(ELEVATE_IDENTITY *identity) {
    HANDLE token = NULL;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        QueryTokenIdentity(token, identity);
        CloseHandle(token);
        return identity->valid;
    }
    return QueryProcessIdentity(identity);
}

BOOL ElevateTokenSidEquals(HANDLE token, const wchar_t *sidText) {
    wchar_t sid[192];
    DWORD error = ERROR_SUCCESS;

    if (!ElevateSidStringFromToken(token, sid, sizeof(sid) / sizeof(wchar_t), &error)) {
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
