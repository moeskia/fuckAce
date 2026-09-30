#ifndef ELEVATE_H
#define ELEVATE_H

#include "core/common.h"

/* 档位按“依次回退”顺序排列：TrustedInstaller 最高，admin 保底。 */
enum {
    ELEVATE_TIER_TI = 0,
    ELEVATE_TIER_SYSTEM,
    ELEVATE_TIER_ADMIN,
    ELEVATE_TIER_COUNT
};

#define ELEVATE_TIER_NONE (-1)

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

/* 服务镜像劫持：把 TrustedInstaller 服务的 ImagePath 临时换成本程序，
   让 SCM 用真实的 TI 服务身份（ServiceSidType=1 会补上 NT SERVICE\TrustedInstaller）
   把本程序拉起来。改键之前必须先落一份备份，崩了要能自己修回去。 */
#define ELEVATE_TI_KEY_PATH L"SYSTEM\\CurrentControlSet\\Services\\TrustedInstaller"
#define ELEVATE_TI_IMAGE_VALUE L"ImagePath"
#define ELEVATE_TI_BACKUP_KEY L"SOFTWARE\\fuckAce"
#define ELEVATE_TI_BACKUP_VALUE L"TiImagePathBackup"
#define ELEVATE_TI_REPAIR_FLAG L"--tirepair="
#define ELEVATE_TI_GUARDIAN_WAIT_MS 30000
#define ELEVATE_TI_STOP_WAIT_MS 15000

typedef struct _ELEVATE_IDENTITY {
    BOOL valid;
    DWORD error;
    int tier;
    DWORD sessionId;
    DWORD integrityRid;
    DWORD elevationType; /* TokenElevationType：1=default 2=full 3=limited */
    BOOL elevated;
    BOOL adminGroup;
    BOOL trustedInstaller; /* 令牌组里有 enabled 的 NT SERVICE\TrustedInstaller */
    wchar_t sid[192];
    wchar_t account[160];
} ELEVATE_IDENTITY;

typedef struct _ELEVATE_TIER_RESULT {
    BOOL tried;
    BOOL ok;
    DWORD error;
    DWORD pid;
    BOOL startedService;
    wchar_t source[64];
    /* 96 个字符会把"哪条路为什么没成"这种复合诊断从中间切断，
       而这段文字正是提权失败时唯一有用的东西。给足空间，剩下的交给界面折行。 */
    wchar_t note[160];
} ELEVATE_TIER_RESULT;

typedef struct _ELEVATE_STATUS {
    int tier;        /* 当前生效档位，ELEVATE_TIER_NONE 表示没有拿到 */
    BOOL spawned;    /* 本进程是被父进程用令牌拉起的 */
    BOOL tiKeyStale; /* 上次劫持没来得及还原：HKLM 里还留着 ImagePath 备份 */
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

/* 没有任何档位可用时的统一提示：main 与 engine 两处共用，避免文案漂移。 */
#define ELEVATE_NO_RIGHTS_FOOTER \
    "✗ administrator privileges required · rerun with --diagnose"

const wchar_t *ElevateTierName(int tier);
const char *ElevateTypeName(DWORD elevationType);

void ElevatePrepareDiagnose(void);
void ElevateRevert(void);

/* 服务供体模式：SCM 拉起的是 session 0、无控制台的进程，
   必须在任何界面/参数解析之前分流出去。 */
BOOL ElevateDonorRequested(int argc, wchar_t **argv);
int ElevateDonorMain(void);

/* TI 键修复模式：劫持期间被父进程拉起来的守护进程，父进程没了就替它收尾。
   同样是 session 0、无控制台，也要在参数解析之前分流。 */
BOOL ElevateTiRepairRequested(int argc, wchar_t **argv, DWORD *outParentPid);
int ElevateTiRepairMain(DWORD parentPid);

BOOL ElevateRun(int argc, wchar_t **argv, ELEVATE_RESULT *result);

#endif
