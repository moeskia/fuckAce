#include "engine.h"
#include "config.h"
#include "limiter.h"
#include "ui.h"

static void TallyError(DWORD error, int *denied, int *unsupported, int *other) {
    if (error == ERROR_SUCCESS) {
        return;
    }
    if (error == ERROR_NOT_VERIFIABLE) {
        return;
    }
    if (error == ERROR_ACCESS_DENIED) {
        (*denied)++;
    } else if (error == ERROR_NOT_SUPPORTED) {
        (*unsupported)++;
    } else {
        (*other)++;
    }
}

int EngineRunOnce(BOOL isFirst) {
    ULONGLONG started = GetTickCount64();
    static TARGET targets[MAX_TARGETS];
    PROCESS_RESULT results[MAX_TARGETS];
    DWORD scanError = ERROR_SUCCESS;
    DWORD debugError = ERROR_SUCCESS;
    BOOL debugOk;
    BOOL truncated = FALSE;
    DWORD cpuCount;
    DWORD groupCpus;
    DWORD groups;
    DWORD_PTR affinity;
    int targetCount;
    int i;
    int step;

    UIResetTiming();
    if (!LimiterIsRunAsAdmin()) {
        if (isFirst) {
            UIClearScreen();
        }
        UILayoutConsole(4);
        UIResetCursor();
        UIBoxRule("┌", "┐");
        UIBoxLine(COLOR_FAIL_BG, " ✗ administrator privileges required");
        UIBoxRule("└", "┘");
        UIClearToEnd();
        return 1;
    }

    debugOk = LimiterEnableDebugPrivilege(&debugError);
    targetCount = LimiterScanTargets(targets, MAX_TARGETS, &scanError, &truncated);
    if (isFirst) {
        UIClearScreen();
    }
    UILayoutConsole(17 + 3 * (targetCount > 0 ? targetCount : 0));
    UIResetCursor();

    cpuCount = LimiterGetCpuCount(ALL_PROCESSOR_GROUPS);
    groupCpus = LimiterGetCpuCount(0);
    groups = GetActiveProcessorGroupCount();
    affinity = LimiterGetLastCpuAffinityMask(groupCpus);

    UIBoxRule("┌", "┐");
    UIBoxLine(COLOR_TITLE, " fuckAce · SGuard64 / SGuardSvc64 limiter");
    {
        SEG status[14];
        int count = 0;

        UISegSet(&status[count++], COLOR_OK_BG, " ✓ admin");
        UISegSet(&status[count++], COLOR_HEAD, " · ");
        if (debugOk) {
            UISegSet(&status[count++], COLOR_OK_BG, "✓ SeDebugPrivilege");
        } else {
            UISegSet(&status[count++], COLOR_WARN_BG, "! SeDebugPrivilege(%lu)", (unsigned long)debugError);
        }
        UISegSet(&status[count++], COLOR_HEAD, " · ");
        UISegSet(&status[count++], COLOR_WHITE, "%lu CPUs", (unsigned long)cpuCount);
        UISegSet(&status[count++], COLOR_HEAD, " → CPU ");
        UISegSet(&status[count++], COLOR_WHITE, "%lu", (unsigned long)(groupCpus - 1));
        UISegSet(&status[count++], COLOR_HEAD, " · cap ");
        if (g_config.cpuCapPercent > 0) {
            UISegSet(&status[count++], COLOR_WARN, "%lu%%/CPU", (unsigned long)g_config.cpuCapPercent);
        } else {
            UISegSet(&status[count++], COLOR_FRAME, "off");
        }
        UIBoxRow(count, status);
    }
    if (targetCount < 0) {
        UIBoxRule("├", "┤");
        UIBoxLine(COLOR_FAIL_BG, " ✗ process scan failed (Error=%lu)", (unsigned long)scanError);
        UIBoxRule("└", "┘");
        UIClearToEnd();
        return 1;
    }
    if (groups > 1) {
        UIBoxLine(COLOR_WARN, " ! %lu processor groups — affinity targets group 0", (unsigned long)groups);
    }
    if (truncated) {
        UIBoxLine(COLOR_WARN, " ! more than %d targets found — extra processes skipped", MAX_TARGETS);
    }
    UIBoxRule("├", "┤");
    {
        SEG header[3 + STEP_COUNT * 2];
        int count = 0;

        UISegSet(&header[count++], COLOR_HEAD, "%2s  %-*s %5s  ", "#", NAME_W, "PROCESS", "PID");
        for (step = 0; step < STEP_COUNT; step++) {
            if (step) {
                UISegSet(&header[count++], COLOR_HEAD, " ");
            }
            UISegSet(&header[count++], COLOR_HEAD, "%-*s", CELL_W, kStepHead[step]);
        }
        UIBoxRow(count, header);
    }

    LimiterApplyBatch(targets, targetCount, affinity, g_config.cpuCapPercent, g_config.cpuCapNest, results);
    {
        int foundCount = 0;
        int skippedCount = 0;
        int fullCount = 0;
        int partialCount = 0;
        int failedCount = 0;
        int openedCount = 0;
        int applied[STEP_COUNT];
        int deniedCount = 0;
        int unsupportedCount = 0;
        int otherErrorCount = 0;
        int capRightsSkipped = 0;
        int capJobSkipped = 0;
        int capOtherSkipped = 0;
        int exitCode;

        memset(applied, 0, sizeof(applied));
        for (i = 0; i < targetCount; i++) {
            PROCESS_RESULT *result = &results[i];
            int state;

            if (result->stale) {
                skippedCount++;
                continue;
            }
            foundCount++;
            UIReportProcess(foundCount, &targets[i], result);
            if (result->opened) {
                openedCount++;
            } else {
                TallyError(result->openErr, &deniedCount, &unsupportedCount, &otherErrorCount);
            }
            for (step = 0; step < STEP_COUNT; step++) {
                if (!result->attempted[step]) {
                    continue;
                }
                TallyError(result->err[step], &deniedCount, &unsupportedCount, &otherErrorCount);
                if (RESULT_ACCEPTED(result, step)) {
                    applied[step]++;
                }
            }
            if (result->capSkipped) {
                if (result->capSkipReason == CAP_SKIP_RIGHTS) {
                    capRightsSkipped++;
                } else if (result->capSkipReason == CAP_SKIP_JOB) {
                    capJobSkipped++;
                } else {
                    capOtherSkipped++;
                }
            }
            state = ResultState(result);
            if (state == RESULT_FULL) {
                fullCount++;
            } else if (state == RESULT_PARTIAL) {
                partialCount++;
            } else {
                failedCount++;
            }
        }

        UIBoxRule("├", "┤");
        {
            SEG summary[12];
            int count = 0;

            UISegSet(&summary[count++], COLOR_HEAD, " found ");
            UISegSet(&summary[count++], COLOR_WHITE, "%d", foundCount);
            UISegSet(&summary[count++], COLOR_HEAD, " · full ");
            UISegSet(&summary[count++], COLOR_OK, "%d", fullCount);
            UISegSet(&summary[count++], COLOR_HEAD, " · partial ");
            UISegSet(&summary[count++], COLOR_WARN, "%d", partialCount);
            UISegSet(&summary[count++], COLOR_HEAD, " · failed ");
            UISegSet(&summary[count++], COLOR_FAIL, "%d", failedCount);
            UIBoxRow(count, summary);
        }
        if (foundCount > 0) {
            SEG appliedSegments[3 * STEP_COUNT + 4];
            int count = 0;

            UISegSet(&appliedSegments[count++], COLOR_HEAD, " applied ");
            for (step = 0; step < STEP_COUNT; step++) {
                if (step) {
                    UISegSet(&appliedSegments[count++], COLOR_HEAD, " · ");
                }
                UISegSet(&appliedSegments[count++], COLOR_HEAD, "%s ", kStepShort[step]);
                UISegSet(
                    &appliedSegments[count++],
                    applied[step] ? COLOR_OK : COLOR_FAIL,
                    "%d",
                    applied[step]);
            }
            UIBoxRow(count, appliedSegments);
            UIBoxLine(
                COLOR_HEAD,
                "          opened %d/%d · cpu cap %d · io: proc+threads · eco/mem: proc",
                openedCount,
                foundCount,
                applied[STEP_CAP]);
            if (capRightsSkipped > 0) {
                UIBoxLine(COLOR_WARN, "          %d CPU cap skipped — insufficient quota rights", capRightsSkipped);
            }
            if (capJobSkipped > 0) {
                UIBoxLine(COLOR_WARN, "          %d CPU cap skipped — process already in another job", capJobSkipped);
            }
            if (capOtherSkipped > 0) {
                UIBoxLine(COLOR_WARN, "          %d CPU cap skipped — job membership not verified", capOtherSkipped);
            }
            if (skippedCount > 0) {
                UIBoxLine(COLOR_WARN, "          %d pid(s) recycled before they could be configured — skipped", skippedCount);
            }
            if (deniedCount == 0 && unsupportedCount == 0 && otherErrorCount == 0) {
                UIBoxLine(COLOR_OK, " diagnostics  no errors — attempted operations verified");
            } else {
                SEG diagnostics[8];
                int diagnosticCount = 0;

                UISegSet(&diagnostics[diagnosticCount++], COLOR_HEAD, " diagnostics ");
                if (deniedCount > 0) {
                    UISegSet(&diagnostics[diagnosticCount++], COLOR_FAIL, " access-denied %d", deniedCount);
                }
                if (unsupportedCount > 0) {
                    UISegSet(&diagnostics[diagnosticCount++], COLOR_WARN, "%sunsupported %d", deniedCount > 0 ? " · " : " ", unsupportedCount);
                }
                if (otherErrorCount > 0) {
                    UISegSet(
                        &diagnostics[diagnosticCount++],
                        COLOR_WARN,
                        "%sother %d",
                        deniedCount > 0 || unsupportedCount > 0 ? " · " : " ",
                        otherErrorCount);
                }
                UIBoxRow(diagnosticCount, diagnostics);
            }
        }

        exitCode = SummaryExitCode(foundCount, fullCount, partialCount);
        if (exitCode == 1) {
            UIBoxLine(COLOR_FAIL_BG, " ✗ FAILED - no target process found");
        } else if (exitCode == 0) {
            UIBoxLine(COLOR_OK_BG, " ✓ SUCCESS - all attempted settings verified on %d processes", foundCount);
        } else if (exitCode == 2) {
            UIBoxLine(COLOR_WARN_BG, " ! PARTIAL - %d of %d processes fully configured", fullCount, foundCount);
        } else {
            UIBoxLine(COLOR_FAIL_BG, " ✗ FAILED - found %d processes but no setting applied", foundCount);
            UIBoxLine(COLOR_FAIL_BG, "   access denied, protected process, or unsupported operation");
        }

        {
            char machine[MAX_COMPUTERNAME_LENGTH + 2];
            DWORD machineLength = sizeof(machine);

            if (!GetComputerNameA(machine, &machineLength)) {
                machine[0] = 0;
            }
            UIBoxRule("├", "┤");
            if (foundCount > 0) {
                SEG targetSegments[16];
                int counts[MAX_TARGET_NAMES];
                int segmentCount = 0;
                int uniqueCount = 0;
                int shown = 0;
                int j;

                memset(counts, 0, sizeof(counts));
                for (i = 0; i < targetCount; i++) {
                    for (j = 0; j < g_config.targetNameCount; j++) {
                        if (_wcsicmp(targets[i].name, g_config.targetNames[j]) == 0) {
                            counts[j]++;
                        }
                    }
                }
                for (j = 0; j < g_config.targetNameCount; j++) {
                    uniqueCount += counts[j] > 0;
                }
                UISegSet(&targetSegments[segmentCount++], COLOR_HEAD, " targets ");
                for (j = 0; j < g_config.targetNameCount && shown < 4; j++) {
                    if (counts[j] == 0) {
                        continue;
                    }
                    if (shown) {
                        UISegSet(&targetSegments[segmentCount++], COLOR_HEAD, " · ");
                    }
                    UISegSet(&targetSegments[segmentCount++], COLOR_WHITE, "%ls", g_config.targetNames[j]);
                    UISegSet(&targetSegments[segmentCount++], COLOR_WARN, " ×%d", counts[j]);
                    shown++;
                }
                if (uniqueCount > shown) {
                    UISegSet(&targetSegments[segmentCount++], COLOR_HEAD, " · …+%d", uniqueCount - shown);
                }
                UIBoxRow(segmentCount, targetSegments);
            }
            UIDrawTiming(GetTickCount64() - started, machine);
        }
        UIBoxRule("└", "┘");
        UIClearToEnd();
        return exitCode;
    }
}
