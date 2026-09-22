#include "config.h"

const char *const kStepHead[STEP_COUNT] = {
    "PRIO", "AFF", "ECO", "CAP", "IO", "MEM", "THR"
};

const char *const kStepShort[STEP_COUNT] = {
    "pri", "aff", "eco", "cap", "io", "mem", "thr"
};

static const wchar_t *const kDefaultTargets[] = {
    L"SGuard64.exe",
    L"SGuardSvc64.exe"
};

#define DEFAULT_TARGET_COUNT ((int)(sizeof(kDefaultTargets) / sizeof(kDefaultTargets[0])))

APP_CONFIG g_config;

void ConfigInit(void) {
    int i;
    memset(&g_config, 0, sizeof(g_config));
    g_config.cpuCapPercent = DEFAULT_CPU_CAP;

    for (i = 0; i < DEFAULT_TARGET_COUNT; i++) {
        ConfigAddTarget(kDefaultTargets[i]);
    }
}

BOOL ConfigAddTarget(const wchar_t *name) {
    if (g_config.targetNameCount >= MAX_TARGET_NAMES) {
        return FALSE;
    }

    g_config.targetNames[g_config.targetNameCount++] = name;
    return TRUE;
}

BOOL ConfigIsTargetProcess(const wchar_t *name) {
    int i;

    for (i = 0; i < g_config.targetNameCount; i++) {
        if (_wcsicmp(name, g_config.targetNames[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL ConfigParseArgs(int argc, wchar_t **argv) {
    int i;

    ConfigInit();

    for (i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--no-cap") == 0) {
            g_config.cpuCapPercent = 0;
            continue;
        }

        if (wcsncmp(argv[i], L"--rate=", 7) == 0) {
            int v = _wtoi(argv[i] + 7);

            if (v <= 0) {
                g_config.cpuCapPercent = 0;
            } else if (v > 100) {
                g_config.cpuCapPercent = 100;
            } else {
                g_config.cpuCapPercent = (DWORD)v;
            }
            continue;
        }

        if (argv[i][0] == L'-') {
            fwprintf(stderr, L"unknown option: %ls\n", argv[i]);
            fwprintf(stderr, L"usage: fuckAce [--rate=PERCENT] [--no-cap] [process.exe ...]\n");
            fflush(stderr);
            return FALSE;
        }

        if (!ConfigAddTarget(argv[i])) {
            fwprintf(stderr, L"too many target names (max %d)\n", MAX_TARGET_NAMES);
            fflush(stderr);
            return FALSE;
        }
    }

    return TRUE;
}
