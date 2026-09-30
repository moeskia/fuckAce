#ifndef CONFIG_H
#define CONFIG_H

#include "core/common.h"

typedef struct _APP_CONFIG {
    const wchar_t *targetNames[MAX_TARGET_NAMES];
    int targetNameCount;
    int escalatedTier;        /* 内部：父进程已用该档位拉起本进程，-1 表示没有 */
    BOOL diagnose;            /* --diagnose：只读打印身份与残留备份，不尝试提权 */
} APP_CONFIG;

extern APP_CONFIG g_config;

void ConfigInit(void);
BOOL ConfigAddTarget(const wchar_t *name);
BOOL ConfigIsTargetProcess(const wchar_t *name);
BOOL ConfigParseArgs(int argc, wchar_t **argv);

#endif
