#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

typedef struct _APP_CONFIG {
    const wchar_t *targetNames[MAX_TARGET_NAMES];
    int targetNameCount;
    DWORD cpuCapPercent;
    BOOL cpuCapNest;
    int elevateMode;         /* --as=，ELEVATE_MODE_AUTO / 档位 / ELEVATE_MODE_OFF */
    int elevateUse;          /* 拿到令牌后是模拟还是重新拉起 */
    BOOL elevateFallback;    /* 是否允许沿档位依次回退 */
    int escalatedTier;       /* 内部：父进程已用该档位拉起本进程，-1 表示没有 */
    BOOL elevateKeepService; /* 用完不停止 TrustedInstaller 服务 */
    BOOL elevateServiceDonor; /* 允许用临时 LocalSystem 服务做 SYSTEM 令牌供体 */
    BOOL diagnose;           /* --diagnose：只打印提权链诊断，不碰任何目标进程 */
} APP_CONFIG;

extern APP_CONFIG g_config;

void ConfigInit(void);
BOOL ConfigAddTarget(const wchar_t *name);
BOOL ConfigIsTargetProcess(const wchar_t *name);
BOOL ConfigParseArgs(int argc, wchar_t **argv);

#endif
