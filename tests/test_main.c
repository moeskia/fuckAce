#include "common.h"
#include "config.h"
#include "limiter.h"

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
