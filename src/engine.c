#include "engine.h"
#include "common.h"
#include "config.h"
#include "limiter.h"
#include "ui.h"

static void TallyError(DWORD err, int *denied, int *unsupported, int *other) {
    if (err == ERROR_SUCCESS) {
        return;
    }
    if (err == ERROR_ACCESS_DENIED) {
        (*denied)++;
    } else if (err == ERROR_NOT_SUPPORTED) {
        (*unsupported)++;
    } else {
        (*other)++;
    }
}

int EngineRunOnce(BOOL isFirst) {
    ULONGLONG t0 = GetTickCount64();
    static TARGET targets[MAX_TARGETS];
    DWORD scanErr = 0;
    BOOL truncated = FALSE;
    int targetCount;
    DWORD dbgErr = ERROR_SUCCESS;
    BOOL dbgOk;
    DWORD cpuCount;
    DWORD_PTR affinityMask;
    DWORD groups;
    int i;
    int s;

    if (!LimiterIsRunAsAdmin()) {
        if (isFirst) {
            UIClearScreen();
        }
        UILayoutConsole(4);
        UIResetCursor();
        UIBoxRule("┌", "┐");
        UIBoxBar(COLOR_FAIL_BG, " ✗ administrator privileges required");
        UIBoxRule("└", "┘");
        UIClearToEnd();
        return 1;
    }

    dbgOk = LimiterEnableDebugPrivilege(&dbgErr);

    targetCount = LimiterScanTargets(targets, MAX_TARGETS, &scanErr, &truncated);

    if (isFirst) {
        UIClearScreen();
    }
    UILayoutConsole(17 + 3 * (targetCount > 0 ? targetCount : 0));
    UIResetCursor();

    cpuCount = LimiterGetLogicalCpuCount();
    affinityMask = LimiterGetLastCpuAffinityMask(cpuCount);
    groups = GetActiveProcessorGroupCount();

    UIBoxRule("┌", "┐");
    UIBoxBar(COLOR_TITLE, " fuckAce · SGuard64 / SGuardSvc64 limiter");

    {
        SEG status[14];
        int n = 0;

        UISegSet(&status[n++], COLOR_OK_BG, " ✓ admin");
        UISegSet(&status[n++], COLOR_HEAD, " · ");
        if (dbgOk) {
            UISegSet(&status[n++], COLOR_OK_BG, " ✓ SeDebugPrivilege");
        } else {
            UISegSet(&status[n++], COLOR_WARN_BG, " ! SeDebugPrivilege(%lu)",
                     (unsigned long)dbgErr);
        }
        UISegSet(&status[n++], COLOR_HEAD, " · ");
        UISegSet(&status[n++], COLOR_WHITE, "%lu CPUs", (unsigned long)cpuCount);
        UISegSet(&status[n++], COLOR_HEAD, " → CPU ");
        UISegSet(&status[n++], COLOR_WHITE, "%lu", (unsigned long)(cpuCount - 1));
        UISegSet(&status[n++], COLOR_HEAD, " · cap ");
        if (g_config.cpuCapPercent > 0) {
            UISegSet(&status[n++], COLOR_WARN, "%lu%%/CPU", (unsigned long)g_config.cpuCapPercent);
        } else {
            UISegSet(&status[n++], COLOR_FRAME, "off");
        }
        UIBoxRow(n, status);
    }

    if (targetCount < 0) {
        UIBoxRule("├", "┤");
        UIBoxBar(COLOR_FAIL_BG, " ✗ process scan failed (Error=%lu)", (unsigned long)scanErr);
        UIBoxRule("└", "┘");
        return 1;
    }

    if (groups > 1) {
        UIBoxBar(COLOR_WARN, " ! %lu processor groups — affinity targets group 0",
                 (unsigned long)groups);
    }
    if (truncated) {
        UIBoxBar(COLOR_WARN, " ! more than %d targets found — extra processes skipped",
                 MAX_TARGETS);
    }

    UIBoxRule("├", "┤");

    {
        SEG head[3 + STEP_COUNT * 2];
        int n = 0;

        UISegSet(&head[n++], COLOR_HEAD, " %2s  %-*s %5s  ", "#", NAME_W, "PROCESS", "PID");
        for (s = 0; s < STEP_COUNT; s++) {
            if (s) {
                UISegSet(&head[n++], COLOR_HEAD, " ");
            }
            UISegSet(&head[n++], COLOR_HEAD, "%-*s", CELL_W, kStepHead[s]);
        }
        UIBoxRow(n, head);
    }
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
        int otherErrCount = 0;
        int existingJobCount = 0;
        int exitCode;

        memset(applied, 0, sizeof(applied));

        for (i = 0; i < targetCount; i++) {
            PROCESS_RESULT r = LimiterApplySettings(
                targets[i].pid, targets[i].name, affinityMask, g_config.cpuCapPercent);

            if (r.stale) {
                skippedCount++;
                continue;
            }

            foundCount++;
            UIReportProcess(foundCount, &targets[i], &r);

            if (r.opened) {
                openedCount++;
            }

            TallyError(r.openErr, &deniedCount, &unsupportedCount, &otherErrCount);

            for (s = 0; s < STEP_COUNT; s++) {
                if (!r.attempted[s]) {
                    continue;
                }
                TallyError(r.err[s], &deniedCount, &unsupportedCount, &otherErrCount);
                if (r.ok[s]) {
                    applied[s]++;
                }
            }

            if (g_config.cpuCapPercent > 0 && r.opened && !r.attempted[STEP_CAP]) {
                existingJobCount++;
            }

            if (r.opened && r.attemptCount > 0 && r.okCount == r.attemptCount) {
                fullCount++;
            } else if (r.opened && r.okCount > 0) {
                partialCount++;
            } else {
                failedCount++;
            }
        }

        UIBoxRule("├", "┤");

        {
            SEG sum[8];
            int k = 0;

            UISegSet(&sum[k++], COLOR_HEAD, " found ");
            UISegSet(&sum[k++], COLOR_WHITE, "%d", foundCount);
            UISegSet(&sum[k++], COLOR_HEAD, " · full ");
            UISegSet(&sum[k++], COLOR_OK, "%d", fullCount);
            UISegSet(&sum[k++], COLOR_HEAD, " · partial ");
            UISegSet(&sum[k++], COLOR_WARN, "%d", partialCount);
            UISegSet(&sum[k++], COLOR_HEAD, " · failed ");
            UISegSet(&sum[k++], COLOR_FAIL, "%d", failedCount);
            UIBoxRow(k, sum);
        }

        if (foundCount > 0) {
            SEG ap[3 * STEP_COUNT + 4];
            int a = 0;

            UISegSet(&ap[a++], COLOR_HEAD, " applied ");
            for (s = 0; s < STEP_COUNT; s++) {
                if (s) {
                    UISegSet(&ap[a++], COLOR_HEAD, " · ");
                }
                UISegSet(&ap[a++], COLOR_HEAD, "%s ", kStepShort[s]);
                UISegSet(&ap[a++], applied[s] ? COLOR_OK : COLOR_FAIL, "%d", applied[s]);
            }
            UIBoxRow(a, ap);

            UIBoxLine(COLOR_HEAD, "          opened %d/%d · cpu cap %d · eco/io/mem are process-wide",
                      openedCount, foundCount, applied[STEP_CAP]);

            if (existingJobCount > 0) {
                UIBoxLine(COLOR_WARN,
                          "          %d process(es) lacked quota rights — CPU cap skipped",
                          existingJobCount);
            }

            if (skippedCount > 0) {
                UIBoxLine(COLOR_WARN,
                          "          %d pid(s) recycled before they could be configured — skipped",
                          skippedCount);
            }

            if (deniedCount == 0 && unsupportedCount == 0 && otherErrCount == 0) {
                UIBoxLine(COLOR_OK, " diagnostics  no errors — every attempted operation stuck");
            } else {
                SEG diag[8];
                int d = 0;

                UISegSet(&diag[d++], COLOR_HEAD, " diagnostics ");
                if (deniedCount > 0) {
                    UISegSet(&diag[d++], COLOR_FAIL, " access-denied %d", deniedCount);
                }
                if (unsupportedCount > 0) {
                    UISegSet(&diag[d++], COLOR_WARN, "%sunsupported %d",
                             deniedCount > 0 ? " · " : " ", unsupportedCount);
                }
                if (otherErrCount > 0) {
                    UISegSet(&diag[d++], COLOR_WARN, "%sother %d",
                             (deniedCount > 0 || unsupportedCount > 0) ? " · " : " ",
                             otherErrCount);
                }
                UIBoxRow(d, diag);
            }
        }

        if (foundCount == 0) {
            UIBoxBar(COLOR_FAIL_BG, " ✗ FAILED - no target process found");
            exitCode = 1;
        } else if (fullCount == foundCount) {
            UIBoxBar(COLOR_OK_BG, " ✓ SUCCESS - all %d processes fully configured", foundCount);
            exitCode = 0;
        } else if (fullCount > 0 || partialCount > 0) {
            UIBoxBar(COLOR_WARN_BG, " ! PARTIAL - %d of %d processes fully configured",
                     fullCount, foundCount);
            exitCode = 2;
        } else {
            UIBoxBar(COLOR_FAIL_BG, " ✗ FAILED - found %d processes but no setting applied",
                     foundCount);
            UIBoxBar(COLOR_FAIL_BG, "   access denied, protected process, or unsupported operation");
            exitCode = 3;
        }

        {
            SYSTEMTIME st;
            char machine[MAX_COMPUTERNAME_LENGTH + 2];
            DWORD machineLen = sizeof(machine);

            GetLocalTime(&st);

            if (!GetComputerNameA(machine, &machineLen)) {
                machine[0] = 0;
            }

            UIBoxRule("├", "┤");

            if (foundCount > 0) {
                SEG tgt[16];
                wchar_t uniq[8][32];
                int counts[8];
                int u = 0;
                int t = 0;
                int j;
                int shown;

                for (i = 0; i < targetCount; i++) {
                    int hit = -1;

                    for (j = 0; j < u; j++) {
                        if (_wcsicmp(uniq[j], targets[i].name) == 0) {
                            hit = j;
                            break;
                        }
                    }
                    if (hit < 0) {
                        if (u >= 8) {
                            continue;
                        }
                        hit = u;
                        wcsncpy(uniq[u], targets[i].name, 31);
                        uniq[u][31] = 0;
                        counts[u] = 0;
                        u++;
                    }
                    counts[hit]++;
                }

                UISegSet(&tgt[t++], COLOR_HEAD, " targets ");
                shown = u > 4 ? 4 : u;
                for (j = 0; j < shown; j++) {
                    if (j) {
                        UISegSet(&tgt[t++], COLOR_HEAD, " · ");
                    }
                    UISegSet(&tgt[t++], COLOR_WHITE, "%ls", uniq[j]);
                    UISegSet(&tgt[t++], COLOR_WARN, " ×%d", counts[j]);
                }
                if (u > shown) {
                    UISegSet(&tgt[t++], COLOR_HEAD, " · …+%d", u - shown);
                }
                UIBoxRow(t, tgt);
            }

            {
                SEG timing[8];
                int m = 0;

                UISegSet(&timing[m++], COLOR_HEAD, " timing   ");
                UISegSet(&timing[m++], COLOR_WHITE, "%04d-%02d-%02d %02d:%02d:%02d",
                         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                UISegSet(&timing[m++], COLOR_HEAD, " · ");
                UISegSet(&timing[m++], COLOR_WHITE, "%llu ms",
                         (unsigned long long)(GetTickCount64() - t0));
                UISegSet(&timing[m++], COLOR_HEAD, " · ");
                UISegSet(&timing[m++], COLOR_WHITE, "%s", machine);
                UIBoxRow(m, timing);
            }
        }

        UIBoxRule("└", "┘");
        UIClearToEnd();

        return exitCode;
    }
}
