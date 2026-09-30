#ifndef CONFIG_H
#define CONFIG_H

#include "core/common.h"

/* TI 服务镜像劫持的强度。命令行不再暴露开关，默认固定 FORCE：
   为了拿到 TI 身份，连正在跑的 TrustedInstaller 也先停掉再改 ImagePath。 */
#define TI_HIJACK_OFF 0   /* 仅在服务已经停下来时劫持 */
#define TI_HIJACK_SAFE 1  /* 保留的状态常量，用于区分“不打断在跑的 TI”这一档 */
#define TI_HIJACK_FORCE 2 /* 默认：正在跑的也停掉再劫持 */

typedef struct _APP_CONFIG {
    const wchar_t *targetNames[MAX_TARGET_NAMES];
    int targetNameCount;
    int elevateMode;          /* 固定 ELEVATE_MODE_AUTO */
    int elevateUse;           /* 固定 ELEVATE_USE_AUTO：先模拟，失败再重拉 */
    BOOL elevateFallback;     /* 固定 TRUE：始终沿档位依次回退 */
    int escalatedTier;        /* 内部：父进程已用该档位拉起本进程，-1 表示没有 */
    BOOL elevateKeepService;  /* 固定 FALSE：用完即停自己拉起的 TrustedInstaller */
    BOOL elevateServiceDonor; /* 固定 TRUE：允许临时 LocalSystem 服务做 SYSTEM 供体 */
    BOOL tiForge;             /* 固定 TRUE：允许在 SYSTEM 上伪造带 TI 服务 SID 的令牌 */
    int tiHijack;             /* 固定 TI_HIJACK_FORCE：临时改写 TI 服务的 ImagePath */
    BOOL diagnose;            /* --diagnose：只读打印身份与残留备份，不尝试提权 */
} APP_CONFIG;

extern APP_CONFIG g_config;

void ConfigInit(void);
BOOL ConfigAddTarget(const wchar_t *name);
BOOL ConfigIsTargetProcess(const wchar_t *name);
BOOL ConfigParseArgs(int argc, wchar_t **argv);

#endif
