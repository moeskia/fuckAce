#include "common.h"
#include "config.h"
#include "ui.h"
#include "engine.h"

int wmain(int argc, wchar_t **argv) {
    int code;
    BOOL isFirst = TRUE;

    UIInit();
    UIShowCursor(FALSE);

    if (!ConfigParseArgs(argc, argv)) {
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

    UIShowCursor(TRUE);
    return code;
}
