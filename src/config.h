#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

typedef struct _APP_CONFIG {
    const wchar_t *targetNames[MAX_TARGET_NAMES];
    int targetNameCount;
    DWORD cpuCapPercent;
} APP_CONFIG;

extern APP_CONFIG g_config;

void ConfigInit(void);
BOOL ConfigAddTarget(const wchar_t *name);
BOOL ConfigIsTargetProcess(const wchar_t *name);
BOOL ConfigParseArgs(int argc, wchar_t **argv);

#endif /* CONFIG_H */
