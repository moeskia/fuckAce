#include "ui.h"

static HANDLE g_console;
static int g_width = 60;

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
    if (GetConsoleMode(g_console, &mode) &&
        (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        fputs("\x1b[H", stdout);
        fflush(stdout);
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_console, &csbi)) {
        COORD origin = {0, csbi.srWindow.Top};
        SetConsoleCursorPosition(g_console, origin);
    }
}

void UIClearToEnd(void) {
    DWORD mode = 0;
    if (GetConsoleMode(g_console, &mode) &&
        (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        fputs("\x1b[J", stdout);
        fflush(stdout);
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_console, &csbi)) {
        DWORD curPos = (DWORD)csbi.dwCursorPosition.Y * (DWORD)csbi.dwSize.X + (DWORD)csbi.dwCursorPosition.X;
        DWORD total = (DWORD)csbi.dwSize.X * (DWORD)csbi.dwSize.Y;
        if (total > curPos) {
            DWORD cells = total - curPos;
            DWORD written;
            FillConsoleOutputCharacterW(g_console, L' ', cells, csbi.dwCursorPosition, &written);
            FillConsoleOutputAttribute(g_console, COLOR_DEFAULT, cells, csbi.dwCursorPosition, &written);
        }
    }
}

void UISetColor(WORD color) {
    SetConsoleTextAttribute(g_console, color);
}

int UIUtf8Len(const char *s) {
    int n = 0;

    for (; *s; s++) {
        if ((*s & 0xC0) != 0x80) {
            n++;
        }
    }

    return n;
}

const char *UIShortReason(DWORD err) {
    switch (err) {
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
    case ERROR_NOT_ENOUGH_MEMORY:
        return "out of memory";
    case ERROR_PARTIAL_COPY:
        return "partial copy";
    case ERROR_NOT_VERIFIED:
        return "not applied";
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

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD cells;
    DWORD written;
    COORD origin = {0, 0};

    if (!GetConsoleScreenBufferInfo(g_console, &csbi)) {
        return;
    }

    cells = (DWORD)csbi.dwSize.X * (DWORD)csbi.dwSize.Y;

    FillConsoleOutputCharacterW(g_console, L' ', cells, origin, &written);
    FillConsoleOutputAttribute(g_console, COLOR_DEFAULT, cells, origin, &written);
    SetConsoleCursorPosition(g_console, origin);
}

void UILayoutConsole(int contentRows) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    COORD max;
    COORD size;
    COORD origin = {0, 0};
    SMALL_RECT tmp;
    SMALL_RECT rect;
    DWORD cells;
    DWORD written;
    int curW;
    int curH;
    int wantW;
    int wantH;
    int bufH;

    if (!GetConsoleScreenBufferInfo(g_console, &csbi)) {
        g_width = CONTENT_WIDTH;
        return;
    }

    curW = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    curH = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    max = GetLargestConsoleWindowSize(g_console);

    wantW = CONTENT_WIDTH;
    wantH = contentRows + 4;

    if (wantH < 24) {
        wantH = 24;
    }
    if (max.X <= 0 || max.Y <= 0) {
        g_width = CONTENT_WIDTH;
        return;
    }
    if (wantW > max.X) {
        wantW = max.X;
    }
    if (wantW < 20) {
        wantW = 20;
    }
    if (wantH > max.Y) {
        wantH = max.Y;
    }

    bufH = wantH;

    if (curW == wantW && curH == wantH &&
        csbi.dwSize.X == wantW && csbi.dwSize.Y == bufH) {
        g_width = wantW;
        return;
    }

    tmp.Left = 0;
    tmp.Top = 0;
    tmp.Right = 1;
    tmp.Bottom = 1;
    SetConsoleWindowInfo(g_console, TRUE, &tmp);

    size.X = (SHORT)wantW;
    size.Y = (SHORT)bufH;

    if (!SetConsoleScreenBufferSize(g_console, size)) {
        SetConsoleWindowInfo(g_console, TRUE, &csbi.srWindow);
        g_width = curW;
        return;
    }

    rect.Left = 0;
    rect.Top = 0;
    rect.Right = (SHORT)(wantW - 1);
    rect.Bottom = (SHORT)(wantH - 1);
    SetConsoleWindowInfo(g_console, TRUE, &rect);

    cells = (DWORD)wantW * (DWORD)bufH;
    FillConsoleOutputCharacterW(g_console, L' ', cells, origin, &written);
    FillConsoleOutputAttribute(g_console, COLOR_DEFAULT, cells, origin, &written);
    SetConsoleCursorPosition(g_console, origin);

    if (GetConsoleScreenBufferInfo(g_console, &csbi)) {
        g_width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    } else {
        g_width = wantW;
    }
}

static COORD g_timingPos = {-1, -1};
static ULONGLONG g_lastElapsedMs = 0;
static char g_lastMachine[MAX_COMPUTERNAME_LENGTH + 2] = {0};

void UIDrawTiming(ULONGLONG elapsedMs, const char *machine) {
    SYSTEMTIME st;
    SEG timing[8];
    int m = 0;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    g_lastElapsedMs = elapsedMs;
    if (machine) {
        strncpy(g_lastMachine, machine, sizeof(g_lastMachine) - 1);
        g_lastMachine[sizeof(g_lastMachine) - 1] = 0;
    }

    if (GetConsoleScreenBufferInfo(g_console, &csbi)) {
        g_timingPos = csbi.dwCursorPosition;
    }

    GetLocalTime(&st);

    UISegSet(&timing[m++], COLOR_HEAD, " timing   ");
    UISegSet(&timing[m++], COLOR_WHITE, "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    UISegSet(&timing[m++], COLOR_HEAD, " · ");
    UISegSet(&timing[m++], COLOR_WHITE, "%llu ms", (unsigned long long)g_lastElapsedMs);
    UISegSet(&timing[m++], COLOR_HEAD, " · ");
    UISegSet(&timing[m++], COLOR_WHITE, "%s", g_lastMachine);
    UIBoxRow(m, timing);
}

void UIUpdateTiming(void) {
    DWORD mode = 0;
    BOOL isVT = GetConsoleMode(g_console, &mode) && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    if (isVT) {
        fputs("\x1b[s\x1b[3A\r", stdout);
        UIDrawTiming(g_lastElapsedMs, g_lastMachine);
        fputs("\x1b[u", stdout);
        fflush(stdout);
        return;
    }

    if (g_timingPos.Y >= 0) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        COORD savedPos = {0, 0};
        if (GetConsoleScreenBufferInfo(g_console, &csbi)) {
            savedPos = csbi.dwCursorPosition;
        }
        SetConsoleCursorPosition(g_console, g_timingPos);
        UIDrawTiming(g_lastElapsedMs, g_lastMachine);
        SetConsoleCursorPosition(g_console, savedPos);
    }
}

int UICountdown(const char *label, const char *hint, int seconds) {
    int remaining = seconds;
    int ch;
    int tick;

    putchar('\n');
    UISetColor(COLOR_HEAD);
    printf(" %s ", label);
    UISetColor(COLOR_WHITE);
    printf("%d s", remaining);
    UISetColor(COLOR_FRAME);
    printf("  (%s)", hint);
    UISetColor(COLOR_DEFAULT);
    fflush(stdout);

    for (;;) {
        for (tick = 0; tick < 20; tick++) {
            if (_kbhit()) {
                ch = _getch();

                if (ch == 27) {
                    printf("\n");
                    return 0;
                }
                if (ch == '\r' || ch == '\n') {
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
        UISetColor(COLOR_HEAD);
        printf(" %s ", label);
        UISetColor(COLOR_WHITE);
        printf("%d s", remaining);
        UISetColor(COLOR_FRAME);
        printf("  (%s)", hint);
        UISetColor(COLOR_DEFAULT);
        fflush(stdout);
    }

    return 1;
}

SEG *UISegSet(SEG *seg, WORD color, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vsnprintf(seg->text, sizeof(seg->text), fmt, args);
    va_end(args);
    seg->color = color;
    return seg;
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

void UIBoxRow(int count, const SEG *segs) {
    int used = 0;
    int pad;
    int i;

    UISetColor(COLOR_FRAME);
    fputs("│ ", stdout);
    for (i = 0; i < count; i++) {
        UISetColor(segs[i].color);
        fputs(segs[i].text, stdout);
        used += UIUtf8Len(segs[i].text);
    }
    UISetColor(COLOR_FRAME);
    if (used > g_width - 4) {
        used = g_width - 4;
    }
    pad = g_width - 4 - used;
    for (i = 0; i < pad; i++) {
        putchar(' ');
    }
    fputs(" │", stdout);
    putchar('\n');
    UISetColor(COLOR_DEFAULT);
}

void UIBoxLine(WORD color, const char *fmt, ...) {
    SEG seg;
    va_list args;

    va_start(args, fmt);
    vsnprintf(seg.text, sizeof(seg.text), fmt, args);
    va_end(args);
    seg.color = color;
    UIBoxRow(1, &seg);
}

void UIBoxWrap(WORD color, const char *text) {
    const int indent = 7;

    while (*text) {
        int budget = g_width - 4 - indent;
        const char *lastSpace = NULL;
        char buf[200];
        int len = 0;
        SEG row[2];

        if (budget < 16) {
            budget = 16;
        }
        if (budget > (int)sizeof(buf) - 1) {
            budget = (int)sizeof(buf) - 1;
        }

        while (text[len] && len < budget) {
            if (text[len] == ' ') {
                lastSpace = text + len;
            }
            len++;
        }

        if (text[len] && lastSpace && lastSpace > text) {
            len = (int)(lastSpace - text);
        }

        memcpy(buf, text, (size_t)len);
        buf[len] = 0;

        UISegSet(&row[0], COLOR_FRAME, "%*s", indent, "");
        UISegSet(&row[1], color, "%s", buf);
        UIBoxRow(2, row);

        text += len;
        while (*text == ' ') {
            text++;
        }
    }
}

void UIBoxBar(WORD color, const char *fmt, ...) {
    char text[200];
    va_list args;
    int used;
    int pad;
    int i;

    va_start(args, fmt);
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);

    used = UIUtf8Len(text);

    UISetColor(COLOR_FRAME);
    fputs("│ ", stdout);
    UISetColor(color);
    fputs(text, stdout);
    if (used > g_width - 4) {
        used = g_width - 4;
    }
    pad = g_width - 4 - used;
    for (i = 0; i < pad; i++) {
        putchar(' ');
    }
    UISetColor(COLOR_FRAME);
    fputs(" │", stdout);
    putchar('\n');
    UISetColor(COLOR_DEFAULT);
}

void UISegCell(SEG *seg, BOOL attempted, BOOL ok, DWORD err) {
    char body[32];
    WORD color;

    if (!attempted) {
        snprintf(body, sizeof(body), "-");
        color = COLOR_FRAME;
    } else if (ok) {
        snprintf(body, sizeof(body), "OK");
        color = COLOR_OK_BG;
    } else {
        snprintf(body, sizeof(body), "✗%lu", (unsigned long)err);
        if (UIUtf8Len(body) > CELL_W) {
            snprintf(body, sizeof(body), "✗");
        }
        color = COLOR_FAIL_BG;
    }

    UISegSet(seg, color, "%-*s", CELL_W, body);
}

void UIAddNote(char *buf, size_t size, size_t *pos, const char *fmt, ...) {
    va_list args;
    int written;

    if (*pos >= size - 1) {
        return;
    }

    va_start(args, fmt);
    written = vsnprintf(buf + *pos, size - *pos, fmt, args);
    va_end(args);

    if (written > 0) {
        *pos += (size_t)written;
        if (*pos >= size - 1) {
            *pos = size - 1;
        }
    }
}

void UIReportProcess(int index, const TARGET *target, const PROCESS_RESULT *r) {
    SEG row[3 + STEP_COUNT * 2];
    int n = 0;
    int i;

    UISegSet(&row[n++], COLOR_HEAD, " %2d  ", index);
    UISegSet(&row[n++], COLOR_WHITE, "%-*ls", NAME_W, target->name);
    UISegSet(&row[n++], COLOR_WARN, " %5lu  ", (unsigned long)target->pid);

    for (i = 0; i < STEP_COUNT; i++) {
        if (i) {
            UISegSet(&row[n++], COLOR_FRAME, " ");
        }
        UISegCell(&row[n++], r->opened && r->attempted[i], r->ok[i], r->err[i]);
    }

    UIBoxRow(n, row);

    if (!r->opened) {
        char note[256];

        snprintf(
            note, sizeof(note),
            "open:%lu(%s)",
            (unsigned long)r->openErr, UIShortReason(r->openErr));
        UIBoxWrap(COLOR_WARN, note);
        return;
    }

    if (r->okCount < r->attemptCount) {
        char note[512] = "";
        size_t pos = 0;

        for (i = 0; i < STEP_COUNT; i++) {
            if (!r->attempted[i] || r->ok[i]) {
                continue;
            }

            if (pos) {
                UIAddNote(note, sizeof(note), &pos, " · ");
            }

            if (i == STEP_THR) {
                UIAddNote(
                    note, sizeof(note), &pos,
                    "thr %d/%d (err %lu)",
                    r->thrSet, r->thrTotal, (unsigned long)r->err[i]);
            } else {
                UIAddNote(
                    note, sizeof(note), &pos,
                    "%s:%lu(%s)",
                    kStepShort[i], (unsigned long)r->err[i], UIShortReason(r->err[i]));
            }
        }

        UIBoxWrap(COLOR_WARN, note);
    }
}
