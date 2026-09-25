#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

/* TI 服务镜像劫持的强度。
   默认是 SAFE 而不是 OFF：TI 才是这套工具的默认档位，而 Windows 11 客户端上
   只有劫持能拿到 TI。但默认**不去打断一个正在跑的 TrustedInstaller**——
   它跑起来通常就是在装更新，硬停会把维护打断，那种情况直接往 SYSTEM 回退。 */
#define TI_HIJACK_OFF 0   /* --no-ti-hijack */
#define TI_HIJACK_SAFE 1  /* 默认：只在服务已经停下来时劫持 */
#define TI_HIJACK_FORCE 2 /* --ti-hijack：正在跑的也停掉再劫持 */

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
    BOOL tiForge;            /* 允许在 SYSTEM 上伪造带 TI 服务 SID 的令牌 */
    int tiHijack;            /* TI_HIJACK_*：临时改写 TI 服务的 ImagePath */
    BOOL diagnose;           /* --diagnose：只读打印身份与残留备份，不尝试提权 */
} APP_CONFIG;

extern APP_CONFIG g_config;

void ConfigInit(void);
BOOL ConfigAddTarget(const wchar_t *name);
BOOL ConfigIsTargetProcess(const wchar_t *name);
BOOL ConfigParseArgs(int argc, wchar_t **argv);

#endif
