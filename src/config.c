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
    if (!name || !*name || wcslen(name) >= TARGET_NAME_MAX) {
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
            const wchar_t *text = argv[i] + 7;
            wchar_t *end = NULL;
            long v;

            errno = 0;
            v = wcstol(text, &end, 10);

            /* Reject anything that is not a plain non-negative number: a
               typo must not silently turn the hard cap off. */
            if (end == text || *end != 0 || v < 0) {
                fwprintf(stderr, L"invalid --rate value: \"%ls\" (expected 0-100)\n", text);
                fflush(stderr);
                return FALSE;
            }

            if (errno == ERANGE || v > 100) {
                fwprintf(stderr, L"warning: --rate=%ld clamped to 100\n", v);
                fflush(stderr);
                v = 100;
            }

            g_config.cpuCapPercent = (DWORD)v;
            continue;
        }

        if (argv[i][0] == L'-') {
            fwprintf(stderr, L"unknown option: %ls\n", argv[i]);
            fwprintf(stderr, L"usage: fuckAce [--rate=PERCENT] [--no-cap] [process.exe ...]\n");
            fflush(stderr);
            return FALSE;
        }

        if (!argv[i][0] || wcslen(argv[i]) >= TARGET_NAME_MAX) {
            fwprintf(
                stderr, L"target name must be 1-%d characters: %ls\n",
                TARGET_NAME_MAX - 1, argv[i]);
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
