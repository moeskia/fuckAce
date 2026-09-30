#ifndef LIMITER_H
#define LIMITER_H

#include "core/common.h"

BOOL LimiterEnableDebugPrivilege(DWORD *outError);
DWORD LimiterGetCpuCount(DWORD group);
DWORD_PTR LimiterGetLastCpuAffinityMask(DWORD cpuCount);
int LimiterScanTargets(TARGET *targets, int cap, DWORD *outError, BOOL *outTruncated);
void LimiterApplyBatch(
    const TARGET *targets,
    int count,
    DWORD_PTR affinityMask,
    PROCESS_RESULT *results
);

#endif
