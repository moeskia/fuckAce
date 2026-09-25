#include "ui/ui.h"
#include "elevation/elevate.h"

static HANDLE g_console;
static int g_width = 60;
static BOOL g_timingDrawn = FALSE;
static ULONGLONG g_lastElapsedMs = 0;
static char g_lastMachine[MAX_COMPUTERNAME_LENGTH + 2] = {0};

void UIInit(void) {
    DWORD mode = 0;

    SetConsoleOutputCP(CP_UTF8);
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(g_console, &mode)) {
        SetConsoleMode(g_console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

void UIShowCursor(BOOL show) {
    CONSOLE_CURSOR_INFO info;

    if (GetConsoleCursorInfo(g_console, &info)) {
        info.bVisible = show;
        SetConsoleCursorInfo(g_console, &info);
    }
}

void UIResetCursor(void) {
    DWORD mode = 0;

    if (GetConsoleMode(g_console, &mode) && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        fputs("\x1b[H", stdout);
        fflush(stdout);
        return;
    }
    {
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (GetConsoleScreenBufferInfo(g_console, &info)) {
            COORD origin = {0, info.srWindow.Top};
            SetConsoleCursorPosition(g_console, origin);
        }
    }
}

void UIClearToEnd(void) {
    DWORD mode = 0;

    if (GetConsoleMode(g_console, &mode) && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        fputs("\x1b[J", stdout);
        fflush(stdout);
        return;
    }
    {
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (GetConsoleScreenBufferInfo(g_console, &info)) {
            DWORD position = (DWORD)info.dwCursorPosition.Y * (DWORD)info.dwSize.X + (DWORD)info.dwCursorPosition.X;
            DWORD total = (DWORD)info.dwSize.X * (DWORD)info.dwSize.Y;
            if (total > position) {
                DWORD cells = total - position;
                DWORD written;
                FillConsoleOutputCharacterW(g_console, L' ', cells, info.dwCursorPosition, &written);
                FillConsoleOutputAttribute(g_console, COLOR_DEFAULT, cells, info.dwCursorPosition, &written);
            }
        }
    }
    /* 画完必须落盘：后面可能就阻塞在等待子进程上，缓冲区里的画面用户看不到。 */
    fflush(stdout);
}

static void UISetColor(WORD color) {
    SetConsoleTextAttribute(g_console, color);
}

static int UIUtf8Len(const char *text) {
    int length = 0;

    for (; *text; text++) {
        if ((*text & 0xC0) != 0x80) {
            length++;
        }
    }
    return length;
}

static const char *UIShortReason(DWORD error) {
    switch (error) {
    case ERROR_SUCCESS:
        return "ok";
    case ERROR_ACCESS_DENIED:
        return "access denied";
    case ERROR_INVALID_PARAMETER:
        return "invalid param";
    case ERROR_NOT_SUPPORTED:
        return "unsupported";
    case ERROR_INVALID_HANDLE:
        return "invalid handle";
    case ERROR_INVALID_FUNCTION:
        return "invalid function";
    case ERROR_PRIVILEGE_NOT_HELD:
        return "privilege not held";
    case ERROR_NOT_FOUND:
        return "not found";
    case ERROR_CANCELLED:
        return "declined";
    case ERROR_SERVICE_NOT_ACTIVE:
        return "service not active";
    case ERROR_SERVICE_DOES_NOT_EXIST:
        return "no such service";
    case ERROR_TIMEOUT:
        return "timed out";
    case ERROR_INVALID_ACCOUNT_NAME:
        return "wrong account";
    case ERROR_NOT_ENOUGH_MEMORY:
        return "out of memory";
    case ERROR_PARTIAL_COPY:
        return "partial copy";
    case ERROR_NOT_VERIFIED:
        return "not applied";
    case ERROR_NOT_VERIFIABLE:
        return "set, not verifiable";
    case ERROR_JOB_CONFLICT:
        return "job conflict";
    }
    return "";
}

void UIClearScreen(void) {
    DWORD mode = 0;

    if (GetConsoleMode(g_console, &mode) &&
        SetConsoleMode(g_console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        fputs("\x1b[2J\x1b[3J\x1b[H", stdout);
        fflush(stdout);
        return;
    }
    {
        CONSOLE_SCREEN_BUFFER_INFO info;
        DWORD cells;
        DWORD written;
        COORD origin = {0, 0};

        if (!GetConsoleScreenBufferInfo(g_console, &info)) {
            return;
        }
        cells = (DWORD)info.dwSize.X * (DWORD)info.dwSize.Y;
        FillConsoleOutputCharacterW(g_console, L' ', cells, origin, &written);
        FillConsoleOutputAttribute(g_console, COLOR_DEFAULT, cells, origin, &written);
        SetConsoleCursorPosition(g_console, origin);
    }
}

void UILayoutConsole(int contentRows) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    COORD maximum;
    COORD size;
    COORD origin = {0, 0};
    SMALL_RECT temporary;
    SMALL_RECT rect;
    DWORD cells;
    DWORD written;
    int currentWidth;
    int currentHeight;
    int wantedWidth;
    int wantedHeight;

    if (!GetConsoleScreenBufferInfo(g_console, &info)) {
        g_width = CONTENT_WIDTH;
        return;
    }
    currentWidth = info.srWindow.Right - info.srWindow.Left + 1;
    currentHeight = info.srWindow.Bottom - info.srWindow.Top + 1;
    maximum = GetLargestConsoleWindowSize(g_console);
    wantedWidth = CONTENT_WIDTH;
    wantedHeight = contentRows + 1;
    if (wantedHeight < 18) {
        wantedHeight = 18;
    }
    if (maximum.X <= 0 || maximum.Y <= 0) {
        g_width = CONTENT_WIDTH;
        return;
    }
    if (wantedWidth > maximum.X) {
        wantedWidth = maximum.X;
    }
    if (wantedWidth < 20) {
        wantedWidth = 20;
    }
    if (wantedHeight > maximum.Y) {
        wantedHeight = maximum.Y;
    }
    if (currentWidth == wantedWidth &&
        currentHeight == wantedHeight &&
        info.dwSize.X == wantedWidth &&
        info.dwSize.Y == wantedHeight) {
        g_width = wantedWidth;
        return;
    }
    temporary.Left = 0;
    temporary.Top = 0;
    temporary.Right = 1;
    temporary.Bottom = 1;
    SetConsoleWindowInfo(g_console, TRUE, &temporary);
    size.X = (SHORT)wantedWidth;
    size.Y = (SHORT)wantedHeight;
    if (!SetConsoleScreenBufferSize(g_console, size)) {
        SetConsoleWindowInfo(g_console, TRUE, &info.srWindow);
        g_width = currentWidth;
        return;
    }
    rect.Left = 0;
    rect.Top = 0;
    rect.Right = (SHORT)(wantedWidth - 1);
    rect.Bottom = (SHORT)(wantedHeight - 1);
    SetConsoleWindowInfo(g_console, TRUE, &rect);
    cells = (DWORD)wantedWidth * (DWORD)wantedHeight;
    FillConsoleOutputCharacterW(g_console, L' ', cells, origin, &written);
    FillConsoleOutputAttribute(g_console, COLOR_DEFAULT, cells, origin, &written);
    SetConsoleCursorPosition(g_console, origin);
    if (GetConsoleScreenBufferInfo(g_console, &info)) {
        g_width = info.srWindow.Right - info.srWindow.Left + 1;
    } else {
        g_width = wantedWidth;
    }
}

static void DrawTiming(ULONGLONG elapsedMs, const char *machine) {
    SYSTEMTIME time;
    SEG timing[8];
    int count = 0;

    GetLocalTime(&time);
    UISegSet(&timing[count++], COLOR_HEAD, " Time ");
    UISegSet(
        &timing[count++],
        COLOR_WHITE,
        "%04d-%02d-%02d %02d:%02d:%02d",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond);
    UISegSet(&timing[count++], COLOR_HEAD, " · ");
    UISegSet(&timing[count++], COLOR_WHITE, "%llu ms", (unsigned long long)elapsedMs);
    UISegSet(&timing[count++], COLOR_HEAD, " · ");
    UISegSet(&timing[count++], COLOR_WHITE, "%s", machine ? machine : "");
    UIBoxRow(count, timing);
}

void UIResetTiming(void) {
    g_timingDrawn = FALSE;
    g_lastElapsedMs = 0;
    g_lastMachine[0] = 0;
}

void UIDrawTiming(ULONGLONG elapsedMs, const char *machine) {
    g_lastElapsedMs = elapsedMs;
    if (machine) {
        strncpy(g_lastMachine, machine, sizeof(g_lastMachine) - 1);
        g_lastMachine[sizeof(g_lastMachine) - 1] = 0;
    } else {
        g_lastMachine[0] = 0;
    }
    g_timingDrawn = TRUE;
    DrawTiming(g_lastElapsedMs, g_lastMachine);
}

#define TIMING_ROWS_ABOVE_COUNTDOWN 3

static void UIUpdateTiming(void) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    COORD saved;
    COORD target;

    if (!g_timingDrawn || !GetConsoleScreenBufferInfo(g_console, &info)) {
        return;
    }
    saved = info.dwCursorPosition;
    target.Y = (SHORT)(saved.Y - TIMING_ROWS_ABOVE_COUNTDOWN);
    if (target.Y < 0) {
        target.Y = 0;
    }
    target.X = 0;
    SetConsoleCursorPosition(g_console, target);
    DrawTiming(g_lastElapsedMs, g_lastMachine);
    fflush(stdout);
    SetConsoleCursorPosition(g_console, saved);
}

static void DrawCountdownLine(const char *label, const char *hint, int remaining) {
    UISetColor(COLOR_HEAD);
    printf(" %s ", label);
    UISetColor(COLOR_WHITE);
    printf("%d s", remaining);
    UISetColor(COLOR_FRAME);
    printf("  (%s)", hint);
    UISetColor(COLOR_DEFAULT);
    fflush(stdout);
}

int UICountdown(const char *label, const char *hint, int seconds) {
    int remaining = seconds;
    int tick;

    putchar('\n');
    DrawCountdownLine(label, hint, remaining);
    for (;;) {
        for (tick = 0; tick < 20; tick++) {
            if (_kbhit()) {
                int key = _getch();
                if (key == 27) {
                    printf("\n");
                    return 0;
                }
                if (key == '\r' || key == '\n') {
                    return 1;
                }
            }
            Sleep(50);
        }
        if (--remaining <= 0) {
            break;
        }
        UIUpdateTiming();
        printf("\r");
        DrawCountdownLine(label, hint, remaining);
    }
    return 1;
}

SEG *UISegSet(SEG *segment, WORD color, const char *format, ...) {
    va_list args;

    va_start(args, format);
    vsnprintf(segment->text, sizeof(segment->text), format, args);
    va_end(args);
    segment->color = color;
    return segment;
}

void UIBoxRule(const char *left, const char *right) {
    int i;

    UISetColor(COLOR_FRAME);
    fputs(left, stdout);
    for (i = 0; i < g_width - 2; i++) {
        fputs("─", stdout);
    }
    fputs(right, stdout);
    putchar('\n');
    UISetColor(COLOR_DEFAULT);
}

void UIBoxRow(int count, const SEG *segments) {
    int used = 0;
    int budget = g_width - 4;
    int i;

    if (budget < 1) {
        budget = 1;
    }
    UISetColor(COLOR_FRAME);
    fputs("│ ", stdout);
    for (i = 0; i < count && used < budget; i++) {
        const char *text = segments[i].text;

        if (*text == ' ') {
            UISetColor(COLOR_FRAME);
            do {
                putchar(' ');
                text++;
                used++;
            } while (*text == ' ' && used < budget);
        }
        UISetColor(segments[i].color);
        /* 逐码点输出，超出内容宽度就截断，别把右边框顶出去。
           长度按 NUL 兜底：万一字符串尾部是残缺的 UTF-8 序列，
           直接按首字节推断长度会读到 NUL 之后。 */
        while (*text && used < budget) {
            unsigned char lead = (unsigned char)*text;
            int length = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
            int at;

            for (at = 1; at < length && text[at]; at++) {
            }
            fwrite(text, 1, (size_t)at, stdout);
            text += at;
            used++;
        }
    }
    UISetColor(COLOR_FRAME);
    for (i = 0; i < budget - used; i++) {
        putchar(' ');
    }
    fputs(" │", stdout);
    putchar('\n');
    UISetColor(COLOR_DEFAULT);
}

void UIBoxLine(WORD color, const char *format, ...) {
    SEG segment;
    va_list args;

    va_start(args, format);
    vsnprintf(segment.text, sizeof(segment.text), format, args);
    va_end(args);
    segment.color = color;
    UIBoxRow(1, &segment);
}

static void UIBoxWrap(WORD color, const char *text) {
    const int indent = 7;

    while (*text) {
        int budget = g_width - 4 - indent;
        const char *lastSpace = NULL;
        char buffer[200];
        int length = 0;
        SEG row[2];

        if (budget < 16) {
            budget = 16;
        }
        if (budget > (int)sizeof(buffer) - 1) {
            budget = (int)sizeof(buffer) - 1;
        }
        while (text[length] && length < budget) {
            if (text[length] == ' ') {
                lastSpace = text + length;
            }
            length++;
        }
        if (text[length] && lastSpace && lastSpace > text) {
            length = (int)(lastSpace - text);
        } else if (text[length]) {
            while (length > 1 && ((unsigned char)text[length] & 0xC0) == 0x80) {
                length--;
            }
        }
        memcpy(buffer, text, (size_t)length);
        buffer[length] = 0;
        UISegSet(&row[0], COLOR_FRAME, "%*s", indent, "");
        UISegSet(&row[1], color, "%s", buffer);
        UIBoxRow(2, row);
        text += length;
        while (*text == ' ') {
            text++;
        }
    }
}

static void UISegCell(SEG *segment, BOOL attempted, DWORD error) {
    char body[32];
    char cell[sizeof(body) + CELL_W];
    size_t bodyLength;
    int columns;
    int padding;
    WORD color;

    if (!attempted) {
        snprintf(body, sizeof(body), "-");
        color = COLOR_FRAME;
    } else if (error == ERROR_SUCCESS) {
        snprintf(body, sizeof(body), "OK");
        color = COLOR_OK_BG;
    } else if (error == ERROR_NOT_VERIFIABLE) {
        snprintf(body, sizeof(body), "OK~");
        color = COLOR_WARN;
    } else if (error == ERROR_NOT_VERIFIED) {
        snprintf(body, sizeof(body), "✗nv");
        color = COLOR_FAIL_BG;
    } else {
        snprintf(body, sizeof(body), "✗%lu", (unsigned long)error);
        if (UIUtf8Len(body) > CELL_W) {
            snprintf(body, sizeof(body), "✗");
        }
        color = COLOR_FAIL_BG;
    }
    columns = UIUtf8Len(body);
    if (columns > CELL_W) {
        columns = CELL_W;
    }
    padding = CELL_W - columns;
    bodyLength = strlen(body);
    memcpy(cell, body, bodyLength);
    memset(cell + bodyLength, ' ', (size_t)padding);
    cell[bodyLength + (size_t)padding] = 0;
    UISegSet(segment, color, "%s", cell);
}

static void UIAddNote(char *buffer, size_t size, size_t *position, const char *format, ...) {
    va_list args;
    int written;

    if (*position >= size - 1) {
        return;
    }
    va_start(args, format);
    written = vsnprintf(buffer + *position, size - *position, format, args);
    va_end(args);
    if (written > 0) {
        *position += (size_t)written;
        if (*position >= size - 1) {
            *position = size - 1;
        }
    }
}

static void UIAddStepError(
    char *note,
    size_t size,
    size_t *position,
    int step,
    const PROCESS_RESULT *result
) {
    if (step == STEP_THR) {
        UIAddNote(note, size, position, "thr %d/%d", result->thrSet, result->thrTotal);
    } else if (step == STEP_IO && result->ioThreadFailed) {
        UIAddNote(note, size, position, "io %d/%d", result->ioThrSet, result->ioThrTotal);
    } else if (result->err[step] == ERROR_NOT_VERIFIABLE) {
        UIAddNote(note, size, position, "%s:set(unverified)", kStepShort[step]);
        return;
    } else if (result->err[step] == ERROR_NOT_VERIFIED) {
        UIAddNote(note, size, position, "%s:nv", kStepShort[step]);
        return;
    } else {
        UIAddNote(
            note,
            size,
            position,
            "%s:%lu(%s)",
            kStepShort[step],
            (unsigned long)result->err[step],
            UIShortReason(result->err[step]));
        return;
    }
    if (result->err[step] == ERROR_NOT_VERIFIED) {
        UIAddNote(note, size, position, "(nv)");
    } else {
        UIAddNote(note, size, position, "(err %lu)", (unsigned long)result->err[step]);
    }
}

void UIReportProcess(int index, const TARGET *target, const PROCESS_RESULT *result) {
    SEG row[3 + STEP_COUNT * 2];
    int count = 0;
    int step;

    UISegSet(&row[count++], COLOR_HEAD, "%2d  ", index);
    UISegSet(&row[count++], COLOR_WHITE, "%-*ls", NAME_W, target->name);
    UISegSet(&row[count++], COLOR_WARN, " %5lu  ", (unsigned long)target->pid);
    for (step = 0; step < STEP_COUNT; step++) {
        if (step) {
            UISegSet(&row[count++], COLOR_FRAME, " ");
        }
        UISegCell(&row[count++], result->attempted[step], result->err[step]);
    }
    UIBoxRow(count, row);

    if (!result->opened) {
        char note[256];
        snprintf(note, sizeof(note), "open:%lu(%s)", (unsigned long)result->openErr, UIShortReason(result->openErr));
        UIBoxWrap(COLOR_WARN, note);
        return;
    }
    {
        BOOL unverifiable = FALSE;

        for (step = 0; step < STEP_COUNT; step++) {
            if (result->attempted[step] && result->err[step] == ERROR_NOT_VERIFIABLE) {
                unverifiable = TRUE;
            }
        }
        if (result->capSkipped || unverifiable || ResultState(result) != RESULT_FULL) {
            char note[512] = "";
            size_t position = 0;

            if (result->capSkipped) {
                if (result->capSkipReason == CAP_SKIP_RIGHTS) {
                    UIAddNote(note, sizeof(note), &position, "cap skipped(insufficient rights)");
                } else if (result->capSkipReason == CAP_SKIP_JOB) {
                    if (result->capSkipErr == ERROR_JOB_CONFLICT) {
                        UIAddNote(note, sizeof(note), &position, "cap skipped(existing job)");
                    } else {
                        UIAddNote(
                            note,
                            sizeof(note),
                            &position,
                            "cap skipped(cannot nest, err %lu)",
                            (unsigned long)result->capSkipErr);
                    }
                } else {
                    UIAddNote(note, sizeof(note), &position, "cap skipped(not verified)");
                }
            }
            for (step = 0; step < STEP_COUNT; step++) {
                if (!result->attempted[step] || RESULT_OK(result, step)) {
                    continue;
                }
                if (position) {
                    UIAddNote(note, sizeof(note), &position, " · ");
                }
                UIAddStepError(note, sizeof(note), &position, step, result);
            }
            UIBoxWrap(COLOR_WARN, note);
        }
    }
}

static void UIElevationTierRow(const ELEVATE_TIER_RESULT *info, int tier) {
    SEG row[8];
    int count = 0;
    WORD color;
    const char *mark;

    if (!info->tried) {
        color = COLOR_FRAME;
        mark = "·";
    } else if (info->ok) {
        color = COLOR_OK;
        mark = "✓";
    } else {
        color = COLOR_FAIL;
        mark = "✗";
    }
    UISegSet(&row[count++], COLOR_FRAME, "  ");
    UISegSet(&row[count++], color, "%s ", mark);
    UISegSet(&row[count++], color, "%-16ls ", ElevateTierName(tier));
    if (!info->tried) {
        UISegSet(&row[count++], COLOR_FRAME, "not attempted");
    } else if (info->ok) {
        UISegSet(&row[count++], COLOR_WHITE, "pid %lu", (unsigned long)info->pid);
        if (info->source[0]) {
            UISegSet(&row[count++], COLOR_HEAD, " · %ls", info->source);
        }
        if (info->note[0]) {
            UISegSet(&row[count++], COLOR_FRAME, " · %ls", info->note);
        }
    } else {
        const char *reason = UIShortReason(info->error);

        if (*reason) {
            UISegSet(&row[count++], COLOR_WARN, "err %lu (%s)", (unsigned long)info->error, reason);
        } else {
            UISegSet(&row[count++], COLOR_WARN, "err %lu", (unsigned long)info->error);
        }
        if (info->source[0]) {
            UISegSet(&row[count++], COLOR_HEAD, " · %ls", info->source);
        }
    }
    UIBoxRow(count, row);
}

void UIElevationPanel(const ELEVATE_STATUS *status, const ELEVATE_RESULT *result, const char *footer) {
    int tier;

    UIClearScreen();
    UILayoutConsole(7 + ELEVATE_TIER_COUNT);
    UIResetCursor();

    UIBoxRule("┌", "┐");
    UIBoxLine(COLOR_TITLE, " fuckAce · privilege chain · as=%s · use=%s",
              status->mode == ELEVATE_MODE_AUTO ? "auto"
                                                 : status->mode == ELEVATE_MODE_OFF ? "off"
                                                                                    : ElevateTierTag(status->mode),
              ElevateUseName(status->use));
    UIBoxRule("├", "┤");
    for (tier = 0; tier < ELEVATE_TIER_COUNT; tier++) {
        UIElevationTierRow(&status->tiers[tier], tier);
    }
    UIBoxRule("├", "┤");
    if (result && result->handoff) {
        UIBoxLine(COLOR_OK_BG, " → resumed as %ls (pid %lu)", ElevateTierName(result->tier), (unsigned long)result->pid);
    } else if (result && result->tier >= 0) {
        UIBoxLine(COLOR_OK_BG, " → running as %ls", ElevateTierName(result->tier));
    } else if (status->landed && status->tier >= 0) {
        UIBoxLine(COLOR_OK_BG, " → running as %ls", ElevateTierName(status->tier));
    } else {
        UIBoxLine(COLOR_WARN_BG, " ! no escalation — continuing with the current token");
    }
    if (footer && *footer) {
        UIBoxLine(COLOR_FAIL_BG, " %s", footer);
    }
    UIBoxRule("└", "┘");
    UIClearToEnd();
}

static const char *UIIntegrityName(DWORD rid) {
    switch (rid) {
    case 0x0000:
        return "untrusted";
    case 0x1000:
        return "low";
    case 0x2000:
        return "medium";
    case 0x2100:
        return "medium-plus";
    case 0x3000:
        return "high";
    case 0x4000:
        return "system";
    case 0x5000:
        return "protected";
    }
    return "";
}

/* 提权失败时最需要的不是“失败了”，而是“卡在哪一档、系统原话是什么”。 */
void UIDiagnosePanel(const ELEVATE_STATUS *status) {
    int tier;

    UIClearScreen();
    UILayoutConsole(24 + ELEVATE_TIER_COUNT);
    UIResetCursor();
    UIBoxRule("┌", "┐");
    UIBoxLine(COLOR_TITLE, " fuckAce · privilege diagnostics");
    UIBoxLine(COLOR_FRAME, " read-only: no tier attempted, no service or registry changes");
    UIBoxRule("├", "┤");
    UIBoxLine(COLOR_HEAD, " process token");
    if (status->process.valid) {
        UIBoxLine(COLOR_WHITE, "   account    %ls", status->process.account);
        UIBoxLine(COLOR_FRAME, "   sid        %ls", status->process.sid);
    } else {
        UIBoxLine(COLOR_FAIL, "   token query failed (Error=%lu)", (unsigned long)status->process.error);
    }
    UIBoxLine(
        COLOR_WHITE,
        "   elevation  %s · Administrators %s · session %lu",
        ElevateTypeName(status->process.elevationType),
        status->process.adminGroup ? "enabled" : "absent or deny-only",
        (unsigned long)status->process.sessionId);
    UIBoxLine(
        COLOR_WHITE,
        "   integrity  0x%04lX (%s)%s",
        (unsigned long)status->process.integrityRid,
        UIIntegrityName(status->process.integrityRid),
        status->process.elevated ? " · TokenElevation yes" : " · TokenElevation no");
    UIBoxLine(
        COLOR_HEAD,
        "   ti sid     %s · TrustedInstaller key backup %s",
        status->process.trustedInstaller ? "in token groups" : "absent",
        status->tiKeyStale ? "STALE" : "clean");
    UIBoxRule("├", "┤");
    /* 引擎真正以谁的身份在跑，跟"进程令牌"经常不是一回事（TI/SYSTEM 两档都是就地
       把当前线程切过去）。不把这一栏画出来，面板就会只显示进程令牌，
       让人以为提权没生效。 */
    UIBoxLine(COLOR_HEAD, " effective token  (what the engine actually runs as)");
    if (status->effective.valid) {
        UIBoxLine(COLOR_WHITE, "   identity   %ls", ElevateTierName(status->effective.tier));
        UIBoxLine(
            COLOR_WHITE,
            "   logon      %ls%s",
            status->effective.account[0] ? status->effective.account : L"-",
            status->effective.trustedInstaller ? " · NT SERVICE\\TrustedInstaller in groups" : "");
        if (status->effective.trustedInstaller) {
            /* 这一条就是为了解释"为什么提到 TI 了还显示 SYSTEM"：
               真正的 TrustedInstaller.exe 服务进程也是这副令牌。 */
            UIBoxLine(COLOR_FRAME, "              a TI token IS a LocalSystem logon with the TI service");
            UIBoxLine(COLOR_FRAME, "              SID added to its groups - the real TrustedInstaller.exe");
            UIBoxLine(COLOR_FRAME, "              service runs on exactly the same kind of token.");
        }
    } else {
        UIBoxLine(COLOR_FAIL, "   token query failed (Error=%lu)", (unsigned long)status->effective.error);
    }
    UIBoxRule("├", "┤");
    UIBoxLine(COLOR_HEAD, " tier attempts  (as=%s · use=%s · fallback=%s)",
              status->mode == ELEVATE_MODE_AUTO ? "auto"
                                                 : status->mode == ELEVATE_MODE_OFF ? "off"
                                                                                    : ElevateTierTag(status->mode),
              ElevateUseName(status->use),
              status->fallback ? "on" : "off");
    for (tier = 0; tier < ELEVATE_TIER_COUNT; tier++) {
        const ELEVATE_TIER_RESULT *info = &status->tiers[tier];

        if (!info->tried) {
            UIBoxLine(COLOR_FRAME, "   ·  %-16ls not attempted", ElevateTierName(tier));
        } else if (info->ok) {
            UIBoxLine(
                COLOR_OK,
                "   ✓  %-16ls pid %lu · %ls · %ls",
                ElevateTierName(tier),
                (unsigned long)info->pid,
                info->source[0] ? info->source : L"-",
                info->note[0] ? info->note : L"-");
        } else {
            const char *reason = UIShortReason(info->error);

            /* 分隔符必须是窄字符串：走 %ls 的宽字符 U+00B7 在窄 printf 里会按当前
               locale 转换，默认 C locale 下转不出来，输出会变成乱码或直接截断。 */
            UIBoxLine(
                COLOR_FAIL,
                "   ✗  %-16ls err %lu (%s)",
                ElevateTierName(tier),
                (unsigned long)info->error,
                *reason ? reason : "unknown");
            /* 失败原因单独占一行：这一档现在的诊断信息（借不到 SYSTEM 底座、
               伪造被拒、劫持跳过…）比一个错误码长得多，挤在错误码后面只会被边框裁掉。
               它还常常超过一整行，所以交给按宽度折行的实现，别让最关键的那句被切掉。 */
            if (info->note[0]) {
                char note[512];

                if (WideCharToMultiByte(CP_UTF8, 0, info->note, -1, note, sizeof(note), NULL, NULL)) {
                    UIBoxWrap(COLOR_FRAME, note);
                }
            }
        }
    }
    UIBoxRule("├", "┤");
    if (status->landed && status->tier >= 0) {
        UIBoxLine(COLOR_OK_BG, " ✓ landed on %ls", ElevateTierName(status->tier));
    } else {
        UIBoxLine(COLOR_FAIL_BG, " ✗ no tier available — the engine will refuse to run");
        if (!status->process.adminGroup) {
            UIBoxLine(
                COLOR_WARN,
                "   this token has no enabled Administrators group, so UAC cannot grant admin:");
            UIBoxLine(COLOR_WARN, "   start fuckAce.exe from a normal desktop session and accept the UAC prompt.");
        }
    }
    UIBoxLine(
        COLOR_HEAD,
        " privilege enable: %s",
        status->privilegeError == ERROR_SUCCESS ? "ok" : "failed");
    if (status->privilegeError != ERROR_SUCCESS) {
        UIBoxLine(COLOR_WARN, "   Error=%lu", (unsigned long)status->privilegeError);
    }
    UIBoxRule("└", "┘");
    UIClearToEnd();
}

/* 提权后的子进程可能是独立控制台：它自己的报告留在那个窗口里，
   父进程必须把结果和退出码再说一遍，否则用户只看到窗口一闪。 */
void UIHandoffSummary(const ELEVATE_RESULT *result) {
    SEG row[6];
    int count = 0;
    BOOL ok = result->exitCode == 0;

    if (!result->detached) {
        return;
    }
    putchar('\n');
    UIBoxRule("┌", "┐");
    UISegSet(&row[count++], ok ? COLOR_OK_BG : COLOR_FAIL_BG, " %ls instance finished",
             result->tier == ELEVATE_TIER_ADMIN ? L"elevated" : ElevateTierName(result->tier));
    UISegSet(&row[count++], COLOR_HEAD, "  pid %lu · exit code ", (unsigned long)result->pid);
    UISegSet(&row[count++], ok ? COLOR_OK : COLOR_FAIL, "%lu", (unsigned long)result->exitCode);
    UIBoxRow(count, row);
    if (result->detached) {
        UIBoxLine(COLOR_FRAME, " window above ran in its own console (UAC always does)");
    }
    UIBoxRule("└", "┘");
    UIClearToEnd();
}
