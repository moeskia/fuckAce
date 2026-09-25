#ifndef ELEVATE_H
#define ELEVATE_H

#include "common.h"

/* 档位按“依次回退”顺序排列：TrustedInstaller 最高，admin 保底。 */
enum {
    ELEVATE_TIER_TI = 0,
    ELEVATE_TIER_SYSTEM,
    ELEVATE_TIER_ADMIN,
    ELEVATE_TIER_COUNT
};

#define ELEVATE_TIER_NONE (-1)

/* --as= 未指定时从最高档位开始依次回退 */
#define ELEVATE_MODE_AUTO (-1)
/* --no-elevate：不做任何提权，用当前令牌运行 */
#define ELEVATE_MODE_OFF ELEVATE_TIER_COUNT

/* 拿到令牌之后的落地方式 */
enum {
    ELEVATE_USE_AUTO = 0,     /* 先线程模拟，失败再重新拉起 */
    ELEVATE_USE_IMPERSONATE,  /* 只做线程模拟 */
    ELEVATE_USE_SPAWN         /* 只用令牌重新拉起自身 */
};

#define ELEVATE_TI_SID_STRING \
    L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
#define ELEVATE_SYSTEM_SID_STRING L"S-1-5-18"
#define ELEVATE_ADMIN_SID_STRING L"S-1-5-32-544"
#define ELEVATE_TI_SERVICE_NAME L"TrustedInstaller"
#define ELEVATE_TI_PROCESS_NAME L"TrustedInstaller.exe"
#define ELEVATE_SERVICE_WAIT_MS 10000

/* 临时服务供体：自己造一个 LocalSystem 进程，令牌来源确定、不受 PPL 影响。 */
#define ELEVATE_DONOR_SERVICE_NAME L"fuckAceSystemDonor"
#define ELEVATE_DONOR_FLAG L"--syndonor"
#define ELEVATE_DONOR_WAIT_MS 15000
#define ELEVATE_DONOR_LIFETIME_MS 60000

typedef struct _ELEVATE_IDENTITY {
    BOOL valid;
    DWORD error;
    int tier;
    DWORD sessionId;
    DWORD integrityRid;
    DWORD elevationType; /* TokenElevationType：1=default 2=full 3=limited */
    BOOL elevated;
    BOOL adminGroup;
    wchar_t sid[192];
    wchar_t account[160];
} ELEVATE_IDENTITY;

typedef struct _ELEVATE_TIER_RESULT {
    BOOL tried;
    BOOL ok;
    DWORD error;
    DWORD pid;
    BOOL startedService;
    BOOL impersonated;
    BOOL handoff;
    wchar_t source[64];
    wchar_t note[96];
} ELEVATE_TIER_RESULT;

typedef struct _ELEVATE_STATUS {
    int mode;        /* --as= 的取值，ELEVATE_MODE_AUTO / 档位 / ELEVATE_MODE_OFF */
    int use;         /* ELEVATE_USE_* */
    BOOL fallback;   /* 是否允许向更低档位回退 */
    int requested;   /* 父进程通过 --escalated=N 声明的档位，-1 表示本进程自己提权 */
    int tier;        /* 当前生效档位，ELEVATE_TIER_NONE 表示没有拿到 */
    BOOL landed;     /* 是否成功落到目标档位 */
    BOOL impersonating;
    BOOL spawned;    /* 本进程是被父进程用令牌拉起的 */
    BOOL keepService;
    DWORD privilegeError;
    ELEVATE_IDENTITY process;    /* 进程令牌身份 */
    ELEVATE_IDENTITY effective;  /* 生效身份（模拟后为线程令牌身份） */
    ELEVATE_TIER_RESULT tiers[ELEVATE_TIER_COUNT];
} ELEVATE_STATUS;

typedef struct _ELEVATE_RESULT {
    BOOL handoff;    /* 已用令牌重新拉起子进程并等待其结束 */
    BOOL detached;   /* 子进程有自己的控制台（UAC 自提权就是这种），父进程要自己收尾 */
    int tier;        /* 回退链最终落到的档位 */
    DWORD pid;       /* 子进程 pid（handoff 时有效） */
    DWORD exitCode;  /* 子进程退出码 */
} ELEVATE_RESULT;

extern ELEVATE_STATUS g_elevate;

/* 当前进程令牌是否已经“够权限”：
   admin 组已启用、SYSTEM、TrustedInstaller 任意一档都算。
   注意提权后的令牌里 Administrators 往往是 deny-only（TI 令牌就是如此），
   所以不能只看 admin 组。 */
static inline BOOL ElevateHasRights(void) {
    return g_elevate.process.valid && g_elevate.tier >= 0;
}

const wchar_t *ElevateTierName(int tier);
const char *ElevateTierTag(int tier);
int ElevateTierFromTag(const wchar_t *text, BOOL *outOk);
const char *ElevateUseName(int use);
const char *ElevateTypeName(DWORD elevationType);

BOOL ElevateEnablePrivilege(LPCWSTR name, DWORD *outError);
DWORD ElevateEnablePrivileges(void);
BOOL ElevateTokenHasAdminGroup(HANDLE token);

BOOL ElevateQueryIdentity(ELEVATE_STATUS *status);
int ElevateCurrentTier(void);
BOOL ElevateProcessTier(HANDLE process, int *outTier, DWORD *outError);

BOOL ElevateAcquireToken(int tier, ELEVATE_TIER_RESULT *result, HANDLE *outToken);
void ElevateReleaseService(void);
void ElevateRevert(void);

/* 服务供体模式：SCM 拉起的是 session 0、无控制台的进程，
   必须在任何界面/参数解析之前分流出去。 */
BOOL ElevateDonorRequested(int argc, wchar_t **argv);
int ElevateDonorMain(void);

BOOL ElevateRun(int argc, wchar_t **argv, ELEVATE_RESULT *result);

#endif
