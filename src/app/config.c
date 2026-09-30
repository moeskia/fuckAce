#include "app/config.h"
#include "elevation/elevate.h"

const char *const kStepHead[STEP_COUNT] = {
    "PRIO", "AFF", "ECO", "CAP", "IO", "MEM", "THR"
};

const char *const kStepShort[STEP_COUNT] = {
    "pri", "aff", "eco", "cap", "io", "mem", "thr"
};

static const wchar_t *const defaultTargets[] = {
    L"SGuard64.exe",
    L"SGuardSvc64.exe"
};

APP_CONFIG g_config;

void ConfigInit(void) {
    int i;

    memset(&g_config, 0, sizeof(g_config));
    g_config.escalatedTier = ELEVATE_TIER_NONE;
    for (i = 0; i < (int)(sizeof(defaultTargets) / sizeof(defaultTargets[0])); i++) {
        ConfigAddTarget(defaultTargets[i]);
    }
}

BOOL ConfigAddTarget(const wchar_t *name) {
    if (g_config.targetNameCount >= MAX_TARGET_NAMES ||
        !name || !*name || wcslen(name) >= TARGET_NAME_MAX) {
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
        if (_wcsicmp(argv[i], L"--diagnose") == 0) {
            g_config.diagnose = TRUE;
            continue;
        }
        if (wcsncmp(argv[i], L"--escalated=", 12) == 0) {
            const wchar_t *text = argv[i] + 12;
            const wchar_t *cursor;
            int tier = 0;

            if (!*text) {
                fwprintf(stderr, L"invalid --escalated value: \"%ls\"\n", text);
                fflush(stderr);
                return FALSE;
            }
            for (cursor = text; *cursor; cursor++) {
                if (*cursor < L'0' || *cursor > L'9') {
                    fwprintf(stderr, L"invalid --escalated value: \"%ls\"\n", text);
                    fflush(stderr);
                    return FALSE;
                }
                tier = tier * 10 + (int)(*cursor - L'0');
                if (tier > 99) {
                    break;
                }
            }
            if (tier < 0 || tier >= ELEVATE_TIER_COUNT) {
                fwprintf(stderr, L"invalid --escalated tier: %d (expected 0-%d)\n", tier, ELEVATE_TIER_COUNT - 1);
                fflush(stderr);
                return FALSE;
            }
            g_config.escalatedTier = tier;
            continue;
        }
        if (argv[i][0] == L'-') {
            fwprintf(stderr, L"unknown option: %ls\n", argv[i]);
            fwprintf(stderr, L"usage: fuckAce [--diagnose] [process.exe ...]\n");
            fflush(stderr);
            return FALSE;
        }
        if (!argv[i][0] || wcslen(argv[i]) >= TARGET_NAME_MAX) {
            fwprintf(stderr, L"target name must be 1-%d characters: %ls\n", TARGET_NAME_MAX - 1, argv[i]);
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
