#include "elevation/elevate.h"
#include "app/config.h"
#include "system/titoken.h"
#include "ui/ui.h"
#include "elevation/elevate_internal.h"

#include <shellapi.h>

ELEVATE_STATUS g_elevate;

#define ELEVATE_MUTEX_NAME L"Global\\fuckAceElevation"
#define ELEVATE_MUTEX_LOCAL_NAME L"Local\\fuckAceElevation"
#define ELEVATE_MUTEX_WAIT_MS 60000

static HANDLE g_impersonation = NULL;
static HANDLE g_elevateMutex = NULL;
static BOOL g_elevateMutexHeld = FALSE;

/* 落地到本进程的实现放在后面，TI 的伪造/劫持路径要先用它借用 SYSTEM 身份。 */
BOOL ElevateImpersonateWithToken(HANDLE primary, HANDLE *outImpersonation, DWORD *outError);

/* 截断安全的宽字符格式化：swprintf 在放不下时可能既不返回长度也不补结尾 0，
   而这里的 note 就是要给人看的诊断信息，绝不能变成未终止的缓冲区。 */
void ElevateNote(wchar_t *note, size_t capacity, const wchar_t *format, ...) {
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
BOOL ElevateSelfExecutablePath(wchar_t *buffer, size_t size) {
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

/* ------------------------------------------------------------ 落地到本进程 */

BOOL ElevateIsImpersonating(void) {
    return g_impersonation != NULL;
}

BOOL ElevateImpersonateWithToken(HANDLE primary, HANDLE *outImpersonation, DWORD *outError) {
    HANDLE impersonation = NULL;

    *outError = ERROR_SUCCESS;
    ElevateEnableAllTokenPrivileges(primary);
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
    ElevateEnableAllTokenPrivileges(impersonation);
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
    ElevateReleaseSystemBase();
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
    if (!ElevateSelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
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

    if (!ElevateSelfExecutablePath(executable, sizeof(executable) / sizeof(executable[0]))) {
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
    if (!ElevateAcquireSystemToken(&sysInfo, &base)) {
        return FALSE;
    }
    if (!ElevateImpersonateWithToken(base, &impersonation, &error)) {
        CloseHandle(base);
        return FALSE;
    }
    ok = ElevateTiRestoreKey(&error);
    RevertToSelf();
    CloseHandle(impersonation);
    CloseHandle(base);
    return ok;
}

BOOL ElevateAcquireToken(int tier, ELEVATE_TIER_RESULT *result, HANDLE *outToken) {
    *outToken = NULL;
    result->ok = FALSE;
    result->error = ERROR_SUCCESS;
    result->pid = 0;
    switch (tier) {
    case ELEVATE_TIER_TI:
        return ElevateAcquireTrustedInstallerToken(result, outToken);
    case ELEVATE_TIER_SYSTEM:
        return ElevateAcquireSystemToken(result, outToken);
    }
    result->error = ERROR_INVALID_PARAMETER;
    return FALSE;
}
BOOL ElevateRun(int argc, wchar_t **argv, ELEVATE_RESULT *result) {
    int order[ELEVATE_TIER_COUNT];
    int orderCount = 0;
    int i;

    memset(result, 0, sizeof(*result));
    result->tier = ELEVATE_TIER_NONE;
    ElevateReleaseSystemBase();
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

            if (ElevateImpersonateWithToken(token, &impersonation, &error)) {
                ElevateQueryThreadIdentity(&identity);
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
