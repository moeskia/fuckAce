#include "common.h"
#include "config.h"
#include "limiter.h"
#include "elevate.h"

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
    const wchar_t *emptyArgs[] = {L"--rate="};
    const wchar_t *plusArgs[] = {L"--rate=+1"};
    const wchar_t *minusArgs[] = {L"--rate=-1"};
    const wchar_t *mixedArgs[] = {L"--rate=1x"};
    const wchar_t *leadingSpaceArgs[] = {L"--rate= 1"};
    const wchar_t *trailingSpaceArgs[] = {L"--rate=1 "};
    const wchar_t *hexArgs[] = {L"--rate=0x10"};
    const wchar_t *hugeArgs[] = {L"--rate=999999999999999999999999999999"};
    const wchar_t *zeroArgs[] = {L"--rate=0"};
    const wchar_t *maxArgs[] = {L"--rate=100"};
    const wchar_t *overArgs[] = {L"--rate=101"};
    const wchar_t *disabledThenRate[] = {L"--no-cap", L"--rate=9"};
    const wchar_t *rateThenDisabled[] = {L"--rate=9", L"--no-cap"};
    const wchar_t *nestArgs[] = {L"--nest"};
    const wchar_t *rateThenNest[] = {L"--rate=9", L"--nest"};
    const wchar_t *name31[] = {L"1234567890123456789012345678901"};
    const wchar_t *name32[] = {L"12345678901234567890123456789012"};
    const wchar_t *many[31];
    wchar_t manyName[40][8];
    int i;

    CHECK(ParseArgs(NULL, 0), L"default parse failed");
    CHECK(g_config.cpuCapPercent == DEFAULT_CPU_CAP, L"default rate mismatch");
    CHECK(!g_config.cpuCapNest, L"nest should be off by default");
    CHECK(g_config.targetNameCount == 2, L"default targets mismatch");
    CHECK(ParseArgs(nestArgs, 1) && g_config.cpuCapNest, L"--nest not parsed");
    CHECK(ParseArgs(rateThenNest, 2) && g_config.cpuCapNest, L"--nest after --rate not parsed");
    CHECK(ParseArgs(zeroArgs, 1) && g_config.cpuCapPercent == 0, L"rate=0 mismatch");
    CHECK(ParseArgs(maxArgs, 1) && g_config.cpuCapPercent == 100, L"rate=100 mismatch");
    CHECK(ParseArgs(overArgs, 1) && g_config.cpuCapPercent == 100, L"rate>100 not clamped");
    CHECK(ParseArgs(hugeArgs, 1) && g_config.cpuCapPercent == 100, L"huge rate not clamped");
    CHECK(ParseArgs(disabledThenRate, 2) && g_config.cpuCapPercent == 9, L"option precedence mismatch");
    CHECK(ParseArgs(rateThenDisabled, 2) && g_config.cpuCapPercent == 0, L"option precedence mismatch");
    CHECK(!ParseArgs(emptyArgs, 1), L"empty rate accepted");
    CHECK(!ParseArgs(plusArgs, 1), L"signed rate accepted");
    CHECK(!ParseArgs(minusArgs, 1), L"negative rate accepted");
    CHECK(!ParseArgs(mixedArgs, 1), L"mixed rate accepted");
    CHECK(!ParseArgs(leadingSpaceArgs, 1), L"leading space accepted");
    CHECK(!ParseArgs(trailingSpaceArgs, 1), L"trailing space accepted");
    CHECK(!ParseArgs(hexArgs, 1), L"hex rate accepted");
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
    const wchar_t *noElevate[] = {L"--no-elevate"};
    const wchar_t *asTi[] = {L"--as=ti"};
    const wchar_t *asTiLong[] = {L"--as=TrustedInstaller"};
    const wchar_t *asSystem[] = {L"--as=system"};
    const wchar_t *asAdmin[] = {L"--as=admin"};
    const wchar_t *asAuto[] = {L"--as=auto"};
    const wchar_t *asOff[] = {L"--as=off"};
    const wchar_t *asBad[] = {L"--as=root"};
    const wchar_t *asEmpty[] = {L"--as="};
    const wchar_t *noFallback[] = {L"--no-fallback"};
    const wchar_t *spawnArgs[] = {L"--spawn"};
    const wchar_t *impersonateArgs[] = {L"--impersonate"};
    const wchar_t *keepTi[] = {L"--keep-ti"};
    const wchar_t *escalated[] = {L"--escalated=1"};
    const wchar_t *escalatedBad[] = {L"--escalated=x"};
    const wchar_t *escalatedRange[] = {L"--escalated=3"};
    const wchar_t *escalatedEmpty[] = {L"--escalated="};
    const wchar_t *diagnoseArgs[] = {L"--diagnose"};
    const wchar_t *noService[] = {L"--no-service"};
    const wchar_t *mixed[] = {L"--no-elevate", L"--as=system"};

    CHECK(ParseArgs(NULL, 0), L"elevate default parse failed");
    CHECK(g_config.elevateMode == ELEVATE_MODE_AUTO, L"elevate default mode mismatch");
    CHECK(g_config.elevateUse == ELEVATE_USE_AUTO, L"elevate default use mismatch");
    CHECK(g_config.elevateFallback, L"fallback should default on");
    CHECK(g_config.escalatedTier == ELEVATE_TIER_NONE, L"escalated default mismatch");
    CHECK(!g_config.elevateKeepService, L"keep-ti should default off");
    CHECK(!g_config.diagnose, L"diagnose should default off");
    CHECK(ParseArgs(diagnoseArgs, 1) && g_config.diagnose, L"--diagnose not parsed");
    CHECK(g_config.elevateServiceDonor, L"service donor should default on");
    CHECK(ParseArgs(noService, 1) && !g_config.elevateServiceDonor, L"--no-service not parsed");

    CHECK(ParseArgs(noElevate, 1) && g_config.elevateMode == ELEVATE_MODE_OFF, L"--no-elevate not parsed");
    CHECK(ParseArgs(asTi, 1) && g_config.elevateMode == ELEVATE_TIER_TI, L"--as=ti not parsed");
    CHECK(ParseArgs(asTiLong, 1) && g_config.elevateMode == ELEVATE_TIER_TI, L"--as=TrustedInstaller not parsed");
    CHECK(ParseArgs(asSystem, 1) && g_config.elevateMode == ELEVATE_TIER_SYSTEM, L"--as=system not parsed");
    CHECK(ParseArgs(asAdmin, 1) && g_config.elevateMode == ELEVATE_TIER_ADMIN, L"--as=admin not parsed");
    CHECK(ParseArgs(asAuto, 1) && g_config.elevateMode == ELEVATE_MODE_AUTO, L"--as=auto not parsed");
    CHECK(ParseArgs(asOff, 1) && g_config.elevateMode == ELEVATE_MODE_OFF, L"--as=off not parsed");
    CHECK(ParseArgs(noFallback, 1) && !g_config.elevateFallback, L"--no-fallback not parsed");
    CHECK(ParseArgs(spawnArgs, 1) && g_config.elevateUse == ELEVATE_USE_SPAWN, L"--spawn not parsed");
    CHECK(
        ParseArgs(impersonateArgs, 1) && g_config.elevateUse == ELEVATE_USE_IMPERSONATE,
        L"--impersonate not parsed");
    CHECK(ParseArgs(keepTi, 1) && g_config.elevateKeepService, L"--keep-ti not parsed");
    CHECK(ParseArgs(escalated, 1) && g_config.escalatedTier == 1, L"--escalated=1 not parsed");
    CHECK(ParseArgs(mixed, 2) && g_config.elevateMode == ELEVATE_TIER_SYSTEM, L"last --as should win");
    CHECK(!ParseArgs(asBad, 1), L"bad --as accepted");
    CHECK(!ParseArgs(asEmpty, 1), L"empty --as accepted");
    CHECK(!ParseArgs(escalatedBad, 1), L"bad --escalated accepted");
    CHECK(!ParseArgs(escalatedRange, 1), L"out-of-range --escalated accepted");
    CHECK(!ParseArgs(escalatedEmpty, 1), L"empty --escalated accepted");
}

static void TestElevateTiers(void) {
    BOOL ok = TRUE;
    ELEVATE_STATUS status;

    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_TI), L"TrustedInstaller") == 0, L"TI name mismatch");
    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_SYSTEM), L"SYSTEM") == 0, L"SYSTEM name mismatch");
    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_ADMIN), L"admin") == 0, L"admin name mismatch");
    CHECK(wcscmp(ElevateTierName(ELEVATE_TIER_NONE), L"none") == 0, L"none name mismatch");
    CHECK(strcmp(ElevateTierTag(ELEVATE_TIER_TI), "TI") == 0, L"TI tag mismatch");
    CHECK(strcmp(ElevateTierTag(ELEVATE_TIER_COUNT + 5), "-") == 0, L"unknown tag mismatch");
    CHECK(ElevateTierFromTag(L"ti", &ok) == ELEVATE_TIER_TI && ok, L"tag ti mismatch");
    CHECK(ElevateTierFromTag(L"System", &ok) == ELEVATE_TIER_SYSTEM && ok, L"tag system mismatch");
    CHECK(ElevateTierFromTag(L"administrator", &ok) == ELEVATE_TIER_ADMIN && ok, L"tag admin mismatch");
    CHECK(ElevateTierFromTag(L"root", &ok) == ELEVATE_TIER_NONE && !ok, L"bad tag accepted");
    CHECK(ElevateTierFromTag(NULL, &ok) == ELEVATE_TIER_NONE && !ok, L"null tag accepted");
    CHECK(strcmp(ElevateUseName(ELEVATE_USE_SPAWN), "spawn") == 0, L"use spawn mismatch");
    CHECK(strcmp(ElevateUseName(ELEVATE_USE_IMPERSONATE), "impersonate") == 0, L"use impersonate mismatch");
    CHECK(strcmp(ElevateUseName(ELEVATE_USE_AUTO), "auto") == 0, L"use auto mismatch");

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

static void TestElevateOff(void) {
    const wchar_t *args[] = {L"--no-elevate"};
    wchar_t *argv[2];
    ELEVATE_RESULT result;

    argv[0] = L"fuckAce.exe";
    argv[1] = (wchar_t *)args[0];
    CHECK(ParseArgs(args, 1), L"--no-elevate parse failed");
    memset(&result, 0, sizeof(result));
    result.tier = ELEVATE_TIER_NONE;
    CHECK(ElevateRun(2, argv, &result), L"ElevateRun(--no-elevate) failed");
    CHECK(!result.handoff, L"off mode should never hand off");
    CHECK(g_elevate.mode == ELEVATE_MODE_OFF, L"off mode not recorded");
    CHECK(g_elevate.process.valid, L"off mode identity invalid");
    CHECK(result.tier == g_elevate.process.tier, L"off mode tier mismatch");
    CHECK(!g_elevate.tiers[ELEVATE_TIER_TI].tried, L"off mode still probed TrustedInstaller");
}

static void TestElevateSingleTier(void) {
    const wchar_t *args[] = {L"--as=ti", L"--no-fallback"};
    wchar_t *argv[3];
    ELEVATE_RESULT result;
    BOOL isAdmin;

    argv[0] = L"fuckAce.exe";
    argv[1] = (wchar_t *)args[0];
    argv[2] = (wchar_t *)args[1];
    CHECK(ParseArgs(args, 2), L"--as=ti parse failed");
    memset(&result, 0, sizeof(result));
    result.tier = ELEVATE_TIER_NONE;
    CHECK(ElevateRun(3, argv, &result), L"ElevateRun(--as=ti) failed");
    CHECK(g_elevate.tiers[ELEVATE_TIER_TI].tried, L"TI tier not attempted");
    CHECK(!g_elevate.tiers[ELEVATE_TIER_SYSTEM].tried, L"fallback ran despite --no-fallback");
    CHECK(!g_elevate.tiers[ELEVATE_TIER_ADMIN].tried, L"admin tier ran despite --no-fallback");
    isAdmin = LimiterIsRunAsAdmin();
    if (!isAdmin) {
        CHECK(!g_elevate.tiers[ELEVATE_TIER_TI].ok, L"TI tier succeeded without administrator");
        CHECK(!g_elevate.landed, L"landed without administrator");
    }
    ElevateRevert();
    CHECK(!g_elevate.impersonating, L"revert did not clear impersonation");
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
    LimiterApplyBatch(NULL, 0, 0, 0, FALSE, NULL);
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
        3,
        TRUE,
        &first);
    CHECK(first.opened, L"child process was not opened");
    CHECK(!first.stale, L"child process was marked stale");
    CHECK(ResultState(&first) == RESULT_FULL, L"child was not fully configured");
    CHECK(RESULT_OK(&first, STEP_CAP), L"child CPU cap was not applied");
    LimiterApplyBatch(
        &target,
        1,
        LimiterGetLastCpuAffinityMask(LimiterGetCpuCount(0)),
        3,
        TRUE,
        &second);
    CHECK(RESULT_OK(&second, STEP_CAP), L"child CPU cap was not reapplied");
    ResumeThread(process.hThread);
    CloseProcess(&process);
}

static void TestExternalJob(BOOL allowNest) {
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
        3,
        allowNest,
        &result);
    CHECK(result.opened && !result.stale, L"external-job child open mismatch");
    if (allowNest) {
        CHECK(!result.capSkipped, L"nesting was requested but the cap was skipped");
        CHECK(RESULT_OK(&result, STEP_CAP), L"nested cap was not applied");
    } else {
        CHECK(result.capSkipped, L"external job without nesting was not skipped");
        CHECK(result.capSkipErr == ERROR_JOB_CONFLICT, L"external job skip error mismatch");
    }
    for (step = 0; step < STEP_COUNT; step++) {
        if (step == STEP_CAP && !allowNest) {
            continue;
        }
        CHECK(result.attempted[step], L"external job blocked another step");
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
    LimiterApplyBatch(&target, 1, 1, 3, FALSE, &result);
    CHECK(!result.opened, L"missing process opened");
    CHECK(!result.stale, L"missing process marked stale");
    target.pid = GetCurrentProcessId();
    wcscpy(target.name, L"not-this-process.exe");
    LimiterApplyBatch(&target, 1, 1, 0, FALSE, &result);
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
    TestElevateOff();
    TestElevateSingleTier();
    TestElevateChildMode();
    TestResultState();
    TestFailures();
    TestChildBatch();
    TestExternalJob(FALSE);
    TestExternalJob(TRUE);
    if (g_failures) {
        fwprintf(stderr, L"%d test(s) failed\n", g_failures);
        return 1;
    }
    wprintf(L"all tests passed\n");
    return 0;
}
