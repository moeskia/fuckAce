#include "core/common.h"
#include "app/config.h"
#include "system/limiter.h"
#include "elevation/elevate.h"
#include "system/titoken.h"

static int g_failures;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fwprintf(stderr, L"FAIL line %d: %ls\n", __LINE__, message); \
            g_failures++; \
        } \
    } while (0)

static BOOL ParseArgs(const wchar_t **args, int count) {
    wchar_t *argv[40];
    int i;

    argv[0] = L"fuckAce";
    for (i = 0; i < count; i++) {
        argv[i + 1] = (wchar_t *)args[i];
    }
    return ConfigParseArgs(count + 1, argv);
}

static void TestConfig(void) {
    const wchar_t *removed[] = {
        L"--rate=9",
        L"--no-cap",
        L"--nest",
        L"--as=ti",
        L"--no-elevate",
        L"--no-fallback",
        L"--keep-ti",
        L"--no-service",
        L"--no-ti-forge",
        L"--ti-hijack",
        L"--no-ti-hijack",
        L"--spawn",
        L"--impersonate"
    };
    const wchar_t *diagnoseArgs[] = {L"--diagnose"};
    const wchar_t *name31[] = {L"1234567890123456789012345678901"};
    const wchar_t *name32[] = {L"12345678901234567890123456789012"};
    const wchar_t *many[31];
    wchar_t manyName[40][8];
    int i;

    CHECK(ParseArgs(NULL, 0), L"default parse failed");
    CHECK(g_config.targetNameCount == 2, L"default targets mismatch");
    CHECK(ParseArgs(diagnoseArgs, 1) && g_config.diagnose, L"--diagnose not parsed");
    for (i = 0; i < (int)(sizeof(removed) / sizeof(removed[0])); i++) {
        CHECK(!ParseArgs(&removed[i], 1), L"removed option still accepted");
    }
    CHECK(ParseArgs(name31, 1) && g_config.targetNameCount == 3, L"31-char target rejected");
    CHECK(!ParseArgs(name32, 1), L"32-char target accepted");
    for (i = 0; i < 31; i++) {
        swprintf(manyName[i], 8, L"t%d", i);
        many[i] = manyName[i];
    }
    CHECK(ParseArgs(many, 30) && g_config.targetNameCount == MAX_TARGET_NAMES, L"maximum target count rejected");
    CHECK(!ParseArgs(many, 31), L"too many targets accepted");
}

static void TestElevateConfig(void) {
    const wchar_t *escalated[] = {L"--escalated=1"};
    const wchar_t *escalatedBad[] = {L"--escalated=x"};
    const wchar_t *escalatedRange[] = {L"--escalated=3"};
    const wchar_t *escalatedEmpty[] = {L"--escalated="};

    CHECK(ParseArgs(NULL, 0), L"elevate default parse failed");
    CHECK(g_config.escalatedTier == ELEVATE_TIER_NONE, L"escalated default mismatch");
    CHECK(!g_config.diagnose, L"diagnose should default off");
    CHECK(ParseArgs(escalated, 1) && g_config.escalatedTier == 1, L"--escalated=1 not parsed");
    CHECK(!ParseArgs(escalatedBad, 1), L"bad --escalated accepted");
    CHECK(!ParseArgs(escalatedRange, 1), L"out-of-range --escalated accepted");
    CHECK(!ParseArgs(escalatedEmpty, 1), L"empty --escalated accepted");
}

static void TestElevateTiers(void) {
    ELEVATE_STATUS status;

    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_TI), L"TrustedInstaller") == 0, L"TI name mismatch");
    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_SYSTEM), L"SYSTEM") == 0, L"SYSTEM name mismatch");
    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_ADMIN), L"admin") == 0, L"admin name mismatch");
    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_NONE), L"none") == 0, L"none name mismatch");

    memset(&status, 0, sizeof(status));
    ElevateQueryIdentity(&status);
    CHECK(status.process.valid, L"process identity invalid");
    CHECK(status.process.sid[0] != 0, L"process sid empty");
    CHECK(status.process.account[0] != 0, L"process account empty");
    CHECK(status.tier == status.process.tier, L"tier should mirror the process identity");
    CHECK(ElevateCurrentTier() == status.process.tier, L"current tier mismatch");
    CHECK(status.effective.sessionId != 0xFFFFFFFFu || status.process.sessionId == 0xFFFFFFFFu,
          L"session id mismatch");
}

/* 被父进程拉起的子进程必须直接开跑，不能再提权，否则会无限递归。 */
static void TestElevateChildMode(void) {
    const wchar_t *args[] = {L"--escalated=1"};
    wchar_t *argv[2];
    ELEVATE_RESULT result;

    argv[0] = L"fuckAce.exe";
    argv[1] = (wchar_t *)args[0];
    CHECK(ParseArgs(args, 1), L"--escalated=1 parse failed");
    memset(&result, 0, sizeof(result));
    result.tier = ELEVATE_TIER_NONE;
    CHECK(ElevateRun(2, argv, &result), L"ElevateRun(child) failed");
    CHECK(!result.handoff, L"child mode must not hand off again");
    CHECK(g_elevate.spawned, L"child mode not recorded");
    CHECK(g_elevate.requested == ELEVATE_TIER_SYSTEM, L"child tier not recorded");
    CHECK(g_elevate.tiers[ELEVATE_TIER_SYSTEM].tried, L"child tier not marked tried");
    CHECK(!g_elevate.tiers[ELEVATE_TIER_TI].tried, L"child mode probed TrustedInstaller");
    CHECK(!g_elevate.tiers[ELEVATE_TIER_ADMIN].tried, L"child mode probed admin");
    CHECK(result.tier == g_elevate.tier, L"child tier result mismatch");
}

static void TestElevateDiagnose(void) {
    ELEVATE_STATUS expected;
    int tier;

    memset(&expected, 0, sizeof(expected));
    CHECK(ElevateQueryIdentity(&expected), L"diagnose identity query failed");
    memset(&g_elevate, 0xA5, sizeof(g_elevate));
    ElevatePrepareDiagnose();
    CHECK(g_elevate.process.valid == expected.process.valid, L"diagnose process validity mismatch");
    CHECK(g_elevate.process.tier == expected.process.tier, L"diagnose process tier mismatch");
    CHECK(g_elevate.effective.tier == expected.effective.tier, L"diagnose effective tier mismatch");
    CHECK(g_elevate.tiKeyStale == ElevateTiKeyStale(), L"diagnose stale backup mismatch");
    for (tier = 0; tier < ELEVATE_TIER_COUNT; tier++) {
        CHECK(!g_elevate.tiers[tier].tried, L"diagnose attempted a tier");
        CHECK(!g_elevate.tiers[tier].ok, L"diagnose reported a landed tier");
    }
}

/* TI 这一档的辅助件：内部参数识别、组匹配、以及“没备份时还原必须是 no-op”。 */
static void TestTiHelpers(void) {
    wchar_t *argv[2];
    HANDLE token = NULL;
    DWORD pid = 1234;

    argv[0] = L"fuckAce.exe";
    argv[1] = L"--tirepair=4321";
    CHECK(ElevateTiRepairRequested(2, argv, &pid) && pid == 4321, L"--tirepair=<pid> not recognised");
    argv[1] = L"--tirepair=";
    CHECK(!ElevateTiRepairRequested(2, argv, &pid), L"empty --tirepair accepted");
    argv[1] = L"--tirepair=12x";
    CHECK(!ElevateTiRepairRequested(2, argv, &pid), L"non-numeric --tirepair accepted");
    argv[1] = L"--tirepair=4294967296";
    CHECK(!ElevateTiRepairRequested(2, argv, &pid), L"overflowing --tirepair accepted");
    argv[1] = L"--tirepair=99999999999999999999999999999999999999";
    CHECK(!ElevateTiRepairRequested(2, argv, &pid), L"oversized --tirepair accepted");
    argv[1] = L"--syndonor";
    CHECK(!ElevateTiRepairRequested(2, argv, &pid), L"unrelated flag treated as repair mode");

    if (!ElevateTiKeyStale()) {
        CHECK(ElevateTiRestoreKey(NULL), L"restore without a backup must succeed");
    } else {
        fwprintf(stderr, L"SKIP TI key restore check: a stale ImagePath backup is present\n");
    }

    CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), L"open own token failed");
    if (token) {
        /* 组匹配得先证明确实能匹配：Authenticated Users 每个交互令牌里都有。 */
        CHECK(ElevateTokenHasGroup(token, L"S-1-5-11"), L"group matcher misses authenticated users");
        /* 普通令牌不能凭空声称自己是 TrustedInstaller。 */
        CHECK(!ElevateTokenHasGroup(token, TITOKEN_TI_SID_STRING), L"plain token claims the TI sid");
        CloseHandle(token);
    }
}

/* 伪造路径的“拒绝”行为：非 SYSTEM 身份下必须干净地失败。
   这是能在普通权限下真正跑到的一段伪造代码（参数拼装、ntdll 解析、特权检查），
   也是防止“没权限却造出一个看似成功的令牌”的兜底用例。 */
static void TestTiForgeRefusal(void) {
    int tier = ElevateCurrentTier();
    DWORD error = ERROR_SUCCESS;
    HANDLE token;

    if (tier == ELEVATE_TIER_SYSTEM || tier == ELEVATE_TIER_TI) {
        fwprintf(stderr, L"SKIP forge refusal case: already running as SYSTEM or above\n");
        return;
    }
    token = TiTokenForge(0, &error);
    if (token) {
        CloseHandle(token);
    }
    CHECK(!token, L"forge produced a token without SeCreateTokenPrivilege");
    CHECK(error != ERROR_SUCCESS, L"forge failure did not report an error");
}

static void TestResultState(void) {
    PROCESS_RESULT result;
    int step;

    memset(&result, 0, sizeof(result));
    CHECK(ResultState(&result) == RESULT_FAILED, L"empty result state mismatch");
    result.attempted[STEP_PRI] = TRUE;
    result.err[STEP_PRI] = ERROR_ACCESS_DENIED;
    CHECK(ResultState(&result) == RESULT_FAILED, L"failed result state mismatch");
    result.attempted[STEP_AFF] = TRUE;
    result.err[STEP_AFF] = ERROR_SUCCESS;
    CHECK(ResultState(&result) == RESULT_PARTIAL, L"partial result state mismatch");
    result.err[STEP_PRI] = ERROR_SUCCESS;
    CHECK(ResultState(&result) == RESULT_FULL, L"full result state mismatch");
    memset(&result, 0, sizeof(result));
    for (step = 0; step < STEP_COUNT; step++) {
        result.attempted[step] = step != STEP_CAP;
    }
    CHECK(ResultState(&result) == RESULT_FULL, L"skipped cap state mismatch");
    memset(&result, 0, sizeof(result));
    result.attempted[STEP_ECO] = TRUE;
    result.err[STEP_ECO] = ERROR_NOT_VERIFIABLE;
    CHECK(ResultState(&result) == RESULT_FULL, L"unverifiable result state mismatch");
    result.attempted[STEP_PRI] = TRUE;
    result.err[STEP_PRI] = ERROR_ACCESS_DENIED;
    CHECK(ResultState(&result) == RESULT_PARTIAL, L"unverifiable+failed state mismatch");
    CHECK(SummaryExitCode(0, 0, 0) == 1, L"exit code 1 mismatch");
    CHECK(SummaryExitCode(1, 1, 0) == 0, L"exit code 0 mismatch");
    CHECK(SummaryExitCode(2, 1, 1) == 2, L"exit code 2 mismatch");
    CHECK(SummaryExitCode(1, 0, 0) == 3, L"exit code 3 mismatch");
    LimiterApplyBatch(NULL, 0, 0, NULL);
}

/* 受限令牌环境（AppContainer / 沙箱）里连自身进程都拿不到
   PROCESS_SET_INFORMATION，相关用例只能跳过并明确说明原因。 */
static BOOL CanConfigureProcesses(void) {
    HANDLE process = OpenProcess(
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        GetCurrentProcessId());

    if (!process) {
        return FALSE;
    }
    CloseHandle(process);
    return TRUE;
}

static BOOL SpawnChild(wchar_t *path, size_t pathSize, PROCESS_INFORMATION *process, BOOL *breakaway) {
    STARTUPINFOW startup;
    wchar_t command[2048];
    DWORD flags = CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB;

    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    memset(process, 0, sizeof(*process));
    *breakaway = TRUE;
    if (!GetModuleFileNameW(NULL, path, (DWORD)pathSize)) {
        return FALSE;
    }
    swprintf(command, sizeof(command) / sizeof(command[0]), L"\"%ls\" --child", path);
    if (!CreateProcessW(path, command, NULL, NULL, FALSE, flags, NULL, NULL, &startup, process)) {
        *breakaway = FALSE;
        flags = CREATE_SUSPENDED;
        if (!CreateProcessW(path, command, NULL, NULL, FALSE, flags, NULL, NULL, &startup, process)) {
            return FALSE;
        }
    }
    return TRUE;
}

static void CloseProcess(PROCESS_INFORMATION *process) {
    TerminateProcess(process->hProcess, 0);
    WaitForSingleObject(process->hProcess, 2000);
    CloseHandle(process->hThread);
    CloseHandle(process->hProcess);
}

static void TestChildBatch(void) {
    wchar_t path[1024];
    wchar_t *base;
    PROCESS_INFORMATION process;
    BOOL breakaway;
    TARGET target;
    PROCESS_RESULT first;
    PROCESS_RESULT second;

    if (!CanConfigureProcesses()) {
        fwprintf(stderr, L"SKIP child batch case: PROCESS_SET_INFORMATION denied in this environment\n");
        return;
    }
    if (!SpawnChild(path, sizeof(path) / sizeof(path[0]), &process, &breakaway)) {
        CHECK(FALSE, L"failed to spawn test child");
        return;
    }
    base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    memset(&target, 0, sizeof(target));
    target.pid = process.dwProcessId;
    wcsncpy(target.name, base, TARGET_NAME_MAX - 1);
    LimiterApplyBatch(
        &target,
        1,
        LimiterGetLastCpuAffinityMask(LimiterGetCpuCount(0)),
        &first);
    CHECK(first.opened, L"child process was not opened");
    CHECK(!first.stale, L"child process was marked stale");
    CHECK(ResultState(&first) == RESULT_FULL, L"child was not fully configured");
    CHECK(RESULT_OK(&first, STEP_CAP), L"child CPU cap was not applied");
    LimiterApplyBatch(
        &target,
        1,
        LimiterGetLastCpuAffinityMask(LimiterGetCpuCount(0)),
        &second);
    CHECK(RESULT_OK(&second, STEP_CAP), L"child CPU cap was not reapplied");
    ResumeThread(process.hThread);
    CloseProcess(&process);
}

static void TestExternalJob(void) {
    wchar_t path[1024];
    wchar_t *base;
    PROCESS_INFORMATION process;
    HANDLE job;
    BOOL breakaway;
    BOOL inExternal = FALSE;
    TARGET target;
    PROCESS_RESULT result;
    int step;

    if (!CanConfigureProcesses()) {
        fwprintf(stderr, L"SKIP external job case: PROCESS_SET_INFORMATION denied in this environment\n");
        return;
    }
    if (!SpawnChild(path, sizeof(path) / sizeof(path[0]), &process, &breakaway)) {
        CHECK(FALSE, L"failed to spawn external-job child");
        return;
    }
    job = CreateJobObjectW(NULL, NULL);
    if (!job || !AssignProcessToJobObject(job, process.hProcess)) {
        if (job) {
            CloseHandle(job);
        }
        CloseProcess(&process);
        fwprintf(stderr, L"SKIP external job setup unavailable (Error=%lu)\n", (unsigned long)GetLastError());
        return;
    }
    base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    memset(&target, 0, sizeof(target));
    target.pid = process.dwProcessId;
    wcsncpy(target.name, base, TARGET_NAME_MAX - 1);
    LimiterApplyBatch(
        &target,
        1,
        LimiterGetLastCpuAffinityMask(LimiterGetCpuCount(0)),
        &result);
    CHECK(result.opened && !result.stale, L"external-job child open mismatch");
    CHECK(!result.capSkipped, L"external job cap was skipped");
    CHECK(RESULT_OK(&result, STEP_CAP), L"nested cap was not applied");
    for (step = 0; step < STEP_COUNT; step++) {
        CHECK(result.attempted[step], L"external job blocked a step");
    }
    CHECK(IsProcessInJob(process.hProcess, job, &inExternal) && inExternal, L"process left the external job");
    CloseProcess(&process);
    CloseHandle(job);
}

static void TestFailures(void) {
    TARGET target;
    PROCESS_RESULT result;
    DWORD ignored;

    if (!CanConfigureProcesses()) {
        fwprintf(stderr, L"SKIP process-open cases: PROCESS_SET_INFORMATION denied in this environment\n");
        return;
    }
    memset(&target, 0, sizeof(target));
    target.pid = 0xFFFFFFF0u;
    wcscpy(target.name, L"missing.exe");
    LimiterApplyBatch(&target, 1, 1, &result);
    CHECK(!result.opened, L"missing process opened");
    CHECK(!result.stale, L"missing process marked stale");
    target.pid = GetCurrentProcessId();
    wcscpy(target.name, L"not-this-process.exe");
    LimiterApplyBatch(&target, 1, 1, &result);
    CHECK(result.stale, L"identity mismatch was not marked stale");
    LimiterEnableDebugPrivilege(&ignored);
}

int wmain(int argc, wchar_t **argv) {
    if (argc > 1 && wcscmp(argv[1], L"--child") == 0) {
        Sleep(60000);
        return 0;
    }
    TestConfig();
    TestElevateConfig();
    TestElevateTiers();
    TestElevateChildMode();
    TestElevateDiagnose();
    TestTiHelpers();
    TestTiForgeRefusal();
    TestResultState();
    TestFailures();
    TestChildBatch();
    TestExternalJob();
    if (g_failures) {
        fwprintf(stderr, L"%d test(s) failed\n", g_failures);
        return 1;
    }
    wprintf(L"all tests passed\n");
    return 0;
}
