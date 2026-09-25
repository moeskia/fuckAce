#include "common.h"
#include "config.h"
#include "ui.h"
#include "engine.h"
#include "elevate.h"

int wmain(int argc, wchar_t **argv) {
    int code;
    BOOL isFirst = TRUE;
    ELEVATE_RESULT elevate;

    /* SCM 拉起的供体进程跑在 session 0、没有控制台，必须在任何界面代码之前分流。 */
    if (ElevateDonorRequested(argc, argv)) {
        return ElevateDonorMain();
    }

    UIInit();
    UIShowCursor(FALSE);

    if (!ConfigParseArgs(argc, argv)) {
        UIShowCursor(TRUE);
        return 1;
    }

    /* 先按 TrustedInstaller → SYSTEM → admin 依次回退拿到最高可用令牌，
       拿到就地把当前线程切到那个身份；拿不到才退回管理员权限继续。 */
    if (!ElevateRun(argc, argv, &elevate)) {
        UIShowCursor(TRUE);
        return 1;
    }
    if (elevate.handoff) {
        /* 已用令牌重新拉起自身并等它跑完：退出码原样传回，独立控制台的子进程
           再补一份结果摘要，免得用户只看到一个一闪而过的窗口。 */
        UIHandoffSummary(&elevate);
        if (elevate.detached) {
            UICountdown("Auto-exit in", "Enter = exit now", EXIT_SECONDS);
        }
        UIShowCursor(TRUE);
        return (int)elevate.exitCode;
    }
    if (g_config.diagnose) {
        /* 只报告提权链，不扫描、不修改任何进程。 */
        UIDiagnosePanel(&g_elevate);
        UIShowCursor(TRUE);
        return g_elevate.landed ? 0 : 1;
    }
    if (!ElevateHasRights()) {
        /* 一档都没拿到，重试多少次结果都一样，画一次面板直接退出，别空转。 */
        UIElevationPanel(&g_elevate, NULL, "✗ administrator privileges required · rerun with --diagnose");
        UIShowCursor(TRUE);
        return 1;
    }

    for (;;) {
        code = EngineRunOnce(isFirst);
        isFirst = FALSE;

        if (code == 0) {
            UICountdown("Auto-exit in", "Enter = exit now", EXIT_SECONDS);
            break;
        }

        if (!UICountdown("Auto-retry in", "Enter = retry now, Esc = exit", RETRY_SECONDS)) {
            break;
        }
    }

    ElevateRevert();
    UIShowCursor(TRUE);
    return code;
}
