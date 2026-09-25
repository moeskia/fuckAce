#ifndef TITOKEN_H
#define TITOKEN_H

#include "core/common.h"

/* NT SERVICE\TrustedInstaller 的服务 SID：由服务名 "TrustedInstaller" 经 SHA1 派生，
   全系统固定，不随机器变化。 */
#define TITOKEN_TI_SID_STRING \
    L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

/* 伪造令牌里 TokenUser 用的 SID：直接用 TI 的服务 SID，让伪造出来的身份在
   “看 TokenUser”的判定里也和真正的 TrustedInstaller 一致。 */
#define TITOKEN_USER_SID_STRING TITOKEN_TI_SID_STRING

/* 令牌的组里是否存在该 SID，且处于 enabled（不是 deny-only）状态。
   访问检查是按组 SID 匹配的，所以这一条就是“这个令牌能不能过 TI 的 ACL”的判据。 */
BOOL TiTokenGroupEnabled(HANDLE token, const wchar_t *sidText);

/* 当前线程的**有效**令牌里有没有这个特权（不看开没开）。
   SeCreateTokenPrivilege 在 Windows 11 客户端的 LocalSystem 令牌里**根本不存在**，
   早点问出来比让 NtCreateToken 返回一个 STATUS_PRIVILEGE_NOT_HELD 更好解释。 */
BOOL TiEffectiveTokenHasPrivilege(LPCWSTR name);

/* 用调用线程**当前的有效身份**造一个主令牌：
     TokenUser     = NT SERVICE\TrustedInstaller
     TokenGroups   = 〔TI(enabled)、SYSTEM(enabled)、Administrators(enabled)、
                      Users、Everyone、Authenticated Users、SERVICE〕
     Integrity     = System（S-1-16-16384）
     SessionId     = sessionId
     特权          = 常见特权全部置 SE_PRIVILEGE_ENABLED
   前提是当前有效身份具备 SeCreateTokenPrivilege（只有 LocalSystem 有）。
   成功返回 TokenPrimary 句柄（TOKEN_ALL_ACCESS），失败返回 NULL 并把
   Win32 错误码写进 outError（NTSTATUS 会被翻译成等价 Win32 码，便于界面显示）。 */
HANDLE TiTokenForge(DWORD sessionId, DWORD *outError);

#endif
