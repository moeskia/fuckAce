#ifndef LIMITER_H
#define LIMITER_H

#include "common.h"

BOOL LimiterIsRunAsAdmin(void);
BOOL LimiterEnableDebugPrivilege(DWORD *outError);
DWORD LimiterGetLogicalCpuCount(void);
DWORD LimiterGetGroupCpuCount(void);
DWORD_PTR LimiterGetLastCpuAffinityMask(DWORD cpuCount);
int LimiterScanTargets(TARGET *targets, int cap, DWORD *outError, BOOL *outTruncated);
PROCESS_RESULT LimiterApplySettings(
    DWORD pid,
    const wchar_t *expectedName,
    DWORD_PTR affinityMask,
    DWORD cpuCapPercent
);

#endif /* LIMITER_H */
