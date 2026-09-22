#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

/* ------------------------------------------------------------------ */
/* forward-compatibility shims for older headers                       */
/* ------------------------------------------------------------------ */

#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
typedef struct _PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} PROCESS_POWER_THROTTLING_STATE;
#endif

#ifndef MEMORY_PRIORITY_VERY_LOW
#define MEMORY_PRIORITY_VERY_LOW 1
#endif

#ifndef JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
#define JOB_OBJECT_CPU_RATE_CONTROL_ENABLE 0x1
#define JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED 0x2
#define JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP 0x4
#endif

/* PROCESS_INFORMATION_CLASS values, kept as explicit casts so the code
   does not depend on the SDK enum being present. */
#define PIC_MEMORY_PRIORITY  ((PROCESS_INFORMATION_CLASS)0)
#define PIC_POWER_THROTTLING ((PROCESS_INFORMATION_CLASS)4)

/* NtSetInformationProcess(ProcessIoPriority); PROCESSINFOCLASS 0x21 */
#define NT_PROCESS_IO_PRIORITY 0x21
#define IO_PRIORITY_VERY_LOW 0
#define NT_SUCCESS(status) ((LONG)(status) >= 0)

/* Layout-compatible with JOBOBJECT_CPU_RATE_CONTROL_INFORMATION. */
typedef struct _ACE_CPU_RATE {
    DWORD ControlFlags;
    DWORD CpuRate;
} ACE_CPU_RATE;

/* our own code: the API reported success but the state did not stick */
#define ERROR_NOT_VERIFIED 0x20000001

#define COLOR_DEFAULT 7
#define COLOR_WHITE   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_FRAME   (FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_HEAD    (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_OK      (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_FAIL    (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COLOR_WARN    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)

#define COLOR_TITLE   (BACKGROUND_BLUE | BACKGROUND_INTENSITY | \
                       FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_OK_BG   (BACKGROUND_GREEN | BACKGROUND_INTENSITY)
#define COLOR_FAIL_BG (BACKGROUND_RED | BACKGROUND_INTENSITY | \
                       FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_WARN_BG (BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_INTENSITY)

/* priority, affinity, ecoqos, cpu cap, io, memory, threads */
#define STEP_COUNT 7
#define MAX_TARGETS 256
#define CONTENT_WIDTH 86
#define CELL_W 6
#define NAME_W 15
#define RETRY_SECONDS 5
#define EXIT_SECONDS 10
#define DEFAULT_CPU_CAP 10

enum {
    STEP_PRI = 0,
    STEP_AFF,
    STEP_ECO,
    STEP_CAP,
    STEP_IO,
    STEP_MEM,
    STEP_THR
};

static const char *const kStepHead[STEP_COUNT] = {
    "PRIO", "AFF", "ECO", "CAP", "IO", "MEM", "THR"
};

static const char *const kStepShort[STEP_COUNT] = {
    "pri", "aff", "eco", "cap", "io", "mem", "thr"
};

static const wchar_t *const kDefaultTargets[] = {
    L"SGuard64.exe",
    L"SGuardSvc64.exe"
};

#define DEFAULT_TARGET_COUNT ((int)(sizeof(kDefaultTargets) / sizeof(kDefaultTargets[0])))

typedef struct _TARGET {
    DWORD pid;
    wchar_t name[32];
} TARGET;

typedef struct _PROCESS_RESULT {
    BOOL opened;
    BOOL stale;                         /* pid was recycled: not a target */
    DWORD openErr;
    BOOL attempted[STEP_COUNT];
    BOOL ok[STEP_COUNT];
    DWORD err[STEP_COUNT];
    int attemptCount;
    int okCount;
    int thrSet;
    int thrTotal;
} PROCESS_RESULT;

typedef struct _SEG {
    char text[200];
    WORD color;
} SEG;

#define MAX_TARGET_NAMES 32

static const wchar_t *g_targetNames[MAX_TARGET_NAMES];
static int g_targetNameCount = 0;
static DWORD g_cpuCapPercent = DEFAULT_CPU_CAP;
static HANDLE g_console;
static int g_width = 60;

static BOOL AddTargetName(const wchar_t *name) {
    if (g_targetNameCount >= MAX_TARGET_NAMES) {
        return FALSE;
    }

    g_targetNames[g_targetNameCount++] = name;
    return TRUE;
}

static int Utf8Len(const char *s) {
    int n = 0;

    for (; *s; s++) {
        if ((*s & 0xC0) != 0x80) {
            n++;
        }
    }

    return n;
}

static void SetColor(WORD color) {
    SetConsoleTextAttribute(g_console, color);
}

static const char *ShortReason(DWORD err) {
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
static void ClearScreen(void) {
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

static void LayoutConsole(int contentRows) {
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
    wantH = contentRows + 3;

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

/* Shared countdown used for both "exit now" and "retry" waits.
   Returns 1 to continue (retry) and 0 when the user pressed Esc. */
static int Countdown(const char *label, const char *hint, int seconds) {
    int remaining = seconds;
    int ch;
    int tick;
    COORD numPos = {0, 0};
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    SetColor(COLOR_HEAD);
    printf("\n%s", label);
    fflush(stdout);

    if (GetConsoleScreenBufferInfo(g_console, &csbi)) {
        numPos = csbi.dwCursorPosition;
    }

    printf("%2d s  (%s)", remaining, hint);
    SetColor(COLOR_DEFAULT);
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
                    printf("\n");
                    return 1;
                }
            }
            Sleep(50);
        }

        if (--remaining <= 0) {
            break;
        }

        SetConsoleCursorPosition(g_console, numPos);
        SetColor(COLOR_HEAD);
        printf("%2d", remaining);
        SetColor(COLOR_DEFAULT);
        fflush(stdout);
    }

    printf("\n");
    return 1;
}
static SEG *SegSet(SEG *seg, WORD color, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vsnprintf(seg->text, sizeof(seg->text), fmt, args);
    va_end(args);
    seg->color = color;
    return seg;
}

static void BoxRule(const char *left, const char *right) {
    int i;

    SetColor(COLOR_FRAME);
    fputs(left, stdout);
    for (i = 0; i < g_width - 2; i++) {
        fputs("─", stdout);
    }
    fputs(right, stdout);
    putchar('\n');
    SetColor(COLOR_DEFAULT);
}

static void BoxRow(int count, const SEG *segs) {
    int used = 0;
    int pad;
    int i;

    SetColor(COLOR_FRAME);
    fputs("│ ", stdout);
    for (i = 0; i < count; i++) {
        SetColor(segs[i].color);
        fputs(segs[i].text, stdout);
        used += Utf8Len(segs[i].text);
    }
    SetColor(COLOR_FRAME);
    if (used > g_width - 4) {
        used = g_width - 4;
    }
    pad = g_width - 4 - used;
    for (i = 0; i < pad; i++) {
        putchar(' ');
    }
    fputs(" │", stdout);
    putchar('\n');
    SetColor(COLOR_DEFAULT);
}

static void BoxLine(WORD color, const char *fmt, ...) {
    SEG seg;
    va_list args;

    va_start(args, fmt);
    vsnprintf(seg.text, sizeof(seg.text), fmt, args);
    va_end(args);
    seg.color = color;
    BoxRow(1, &seg);
}

/* Emit a long message as one or more box rows, indented and word-wrapped
   so the right border always stays put. */
static void BoxWrap(WORD color, const char *text) {
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

        SegSet(&row[0], COLOR_FRAME, "%*s", indent, "");
        SegSet(&row[1], color, "%s", buf);
        BoxRow(2, row);

        text += len;
        while (*text == ' ') {
            text++;
        }
    }
}

static void BoxBar(WORD color, const char *fmt, ...) {
    char text[200];
    va_list args;
    int used;
    int pad;
    int i;

    va_start(args, fmt);
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);

    used = Utf8Len(text);

    SetColor(COLOR_FRAME);
    fputs("│ ", stdout);
    SetColor(color);
    fputs(text, stdout);
    if (used > g_width - 4) {
        used = g_width - 4;
    }
    pad = g_width - 4 - used;
    for (i = 0; i < pad; i++) {
        putchar(' ');
    }
    SetColor(COLOR_FRAME);
    fputs(" │", stdout);
    putchar('\n');
    SetColor(COLOR_DEFAULT);
}

static void SegCell(SEG *seg, BOOL attempted, BOOL ok, DWORD err) {
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
        if (Utf8Len(body) > CELL_W) {
            snprintf(body, sizeof(body), "✗");
        }
        color = COLOR_FAIL_BG;
    }

    SegSet(seg, color, "%-*s", CELL_W, body);
}

static void AddNote(char *buf, size_t size, size_t *pos, const char *fmt, ...) {
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

static void TallyError(DWORD err, int *denied, int *unsupported, int *other) {
    if (err == ERROR_SUCCESS) {
        return;
    }
    if (err == ERROR_ACCESS_DENIED) {
        (*denied)++;
    } else if (err == ERROR_NOT_SUPPORTED) {
        (*unsupported)++;
    } else {
        (*other)++;
    }
}
static BOOL IsRunAsAdmin(void) {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin;
}

static BOOL EnableDebugPrivilege(DWORD *outError) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL ok;

    *outError = ERROR_SUCCESS;

    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hToken)) {
        *outError = GetLastError();
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        *outError = GetLastError();
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);

    ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    *outError = GetLastError();
    CloseHandle(hToken);

    return ok && *outError == ERROR_SUCCESS;
}

static DWORD GetLogicalCpuCount(void) {
    SYSTEM_INFO si;

    GetSystemInfo(&si);

    return si.dwNumberOfProcessors > 0 ? si.dwNumberOfProcessors : 1;
}

static DWORD_PTR GetLastCpuAffinityMask(DWORD cpuCount) {
    DWORD bitCount = (DWORD)(sizeof(DWORD_PTR) * 8);

    if (cpuCount < 1) {
        cpuCount = 1;
    }

    if (cpuCount > bitCount) {
        cpuCount = bitCount;
    }

    return ((DWORD_PTR)1) << (cpuCount - 1);
}

static BOOL IsTargetProcess(const wchar_t *name) {
    int i;

    for (i = 0; i < g_targetNameCount; i++) {
        if (_wcsicmp(name, g_targetNames[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static int ScanTargets(TARGET *targets, int cap, DWORD *outError, BOOL *outTruncated) {
    HANDLE snapshot;
    PROCESSENTRY32W pe;
    int n = 0;

    *outError = 0;
    *outTruncated = FALSE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        *outError = GetLastError();
        return -1;
    }

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snapshot, &pe)) {
        *outError = GetLastError();
        CloseHandle(snapshot);
        return -1;
    }

    do {
        if (!IsTargetProcess(pe.szExeFile)) {
            continue;
        }
        if (n < cap) {
            targets[n].pid = pe.th32ProcessID;
            wcsncpy(targets[n].name, pe.szExeFile, 31);
            targets[n].name[31] = 0;
            n++;
        } else {
            *outTruncated = TRUE;
        }
    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);
    return n;
}
static BOOL EnableEfficiencyMode(HANDLE hProcess, DWORD *outError) {
    PROCESS_POWER_THROTTLING_STATE state = {
        PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED
    };
    PROCESS_POWER_THROTTLING_STATE check;

    *outError = ERROR_SUCCESS;

    if (!SetProcessInformation(
            hProcess,
            PIC_POWER_THROTTLING,
            &state,
            sizeof(state))) {
        *outError = GetLastError();
        return FALSE;
    }

    if (GetProcessInformation(
            hProcess,
            PIC_POWER_THROTTLING,
            &check,
            sizeof(check)) &&
        !(check.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED)) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    return TRUE;
}

typedef LONG (NTAPI *PFN_NtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);

static PFN_NtSetInformationProcess LoadNtSetInformationProcess(void) {
    static PFN_NtSetInformationProcess fn = NULL;
    static BOOL tried = FALSE;
    HMODULE ntdll;

    if (!tried) {
        tried = TRUE;
        ntdll = GetModuleHandleW(L"ntdll.dll");

        if (ntdll) {
            fn = (PFN_NtSetInformationProcess)(void *)GetProcAddress(
                ntdll, "NtSetInformationProcess");
        }
    }

    return fn;
}

/* I/O priority has no Win32 API; it is set through NtSetInformationProcess
   with ProcessIoPriority (PROCESSINFOCLASS 0x21). */
static BOOL SetVeryLowIoPriority(HANDLE hProcess, DWORD *outError) {
    PFN_NtSetInformationProcess fn = LoadNtSetInformationProcess();
    ULONG hint = IO_PRIORITY_VERY_LOW;
    LONG status;

    *outError = ERROR_SUCCESS;

    if (!fn) {
        *outError = ERROR_NOT_SUPPORTED;
        return FALSE;
    }

    status = fn(hProcess, NT_PROCESS_IO_PRIORITY, &hint, sizeof(hint));

    if (!NT_SUCCESS(status)) {
        *outError = (DWORD)status;
        return FALSE;
    }

    return TRUE;
}

static BOOL SetVeryLowMemoryPriority(HANDLE hProcess, DWORD *outError) {
    MEMORY_PRIORITY_INFORMATION mp;
    MEMORY_PRIORITY_INFORMATION check;

    *outError = ERROR_SUCCESS;
    mp.MemoryPriority = MEMORY_PRIORITY_VERY_LOW;

    if (!SetProcessInformation(
            hProcess,
            PIC_MEMORY_PRIORITY,
            &mp,
            sizeof(mp))) {
        *outError = GetLastError();
        return FALSE;
    }

    if (GetProcessInformation(
            hProcess,
            PIC_MEMORY_PRIORITY,
            &check,
            sizeof(check)) &&
        check.MemoryPriority != MEMORY_PRIORITY_VERY_LOW) {
        *outError = ERROR_NOT_VERIFIED;
        return FALSE;
    }

    return TRUE;
}

/* A job's CpuRate is a share of the whole machine, not of one logical CPU,
   so a per-CPU percentage has to be scaled by the processor count. */
static DWORD CpuRateFromPercent(DWORD percent, DWORD cpuCount) {
    unsigned long long rate;

    if (cpuCount < 1) {
        cpuCount = 1;
    }
    if (percent < 1) {
        percent = 1;
    }

    rate = ((unsigned long long)percent * 100ULL) / cpuCount;

    if (rate < 1) {
        rate = 1;
    }
    if (rate > 10000) {
        rate = 10000;
    }

    return (DWORD)rate;
}

/* Hard CPU ceiling. A process cannot leave a job it did not create, so
   unlike the other knobs this one cannot be undone by the target.
   Needs PROCESS_SET_QUOTA | PROCESS_TERMINATE on the handle. */
static BOOL ApplyCpuCap(HANDLE hProcess, DWORD percent, DWORD *outError) {
    HANDLE job;
    ACE_CPU_RATE info;
    ACE_CPU_RATE check;
    DWORD returned = 0;

    *outError = ERROR_SUCCESS;

    if (percent < 1) {
        percent = 1;
    }
    if (percent > 100) {
        percent = 100;
    }

    job = CreateJobObjectW(NULL, NULL);

    if (!job) {
        *outError = GetLastError();
        return FALSE;
    }

    info.ControlFlags =
        JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    info.CpuRate = CpuRateFromPercent(percent, GetLogicalCpuCount());

    if (!SetInformationJobObject(job, JobObjectCpuRateControlInformation, &info, sizeof(info))) {
        *outError = GetLastError();
        CloseHandle(job);
        return FALSE;
    }

    if (!AssignProcessToJobObject(job, hProcess)) {
        *outError = GetLastError();
        CloseHandle(job);
        return FALSE;
    }

    if (QueryInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            &check,
            sizeof(check),
            &returned) &&
        !(check.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)) {
        *outError = ERROR_NOT_VERIFIED;
        CloseHandle(job);
        return FALSE;
    }

    /* Documented: the job survives while its processes run, so dropping
       our handle keeps the cap in force without holding the process. */
    CloseHandle(job);
    return TRUE;
}

/* SetPriorityClass only shifts the base priority of threads that are at
   their normal value, so pin every thread explicitly. */
static BOOL IdleThreads(DWORD pid, int *setCount, int *totalCount, DWORD *outError) {
    HANDLE snapshot;
    THREADENTRY32 te;
    int total = 0;
    int done = 0;
    int failed = 0;
    DWORD firstErr = ERROR_SUCCESS;

    *outError = ERROR_SUCCESS;
    *setCount = 0;
    *totalCount = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        *outError = GetLastError();
        return FALSE;
    }

    memset(&te, 0, sizeof(te));
    te.dwSize = sizeof(te);

    if (!Thread32First(snapshot, &te)) {
        DWORD err = GetLastError();
        CloseHandle(snapshot);

        if (err == ERROR_NO_MORE_FILES) {
            return TRUE;
        }

        *outError = err;
        return FALSE;
    }

    do {
        HANDLE hThread;
        DWORD err;

        if (te.th32OwnerProcessID != pid) {
            continue;
        }

        total++;
        hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);

        if (!hThread) {
            err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER) {
                continue;   /* thread exited between snapshot and open */
            }
            failed++;
            if (firstErr == ERROR_SUCCESS) {
                firstErr = err;
            }
            continue;
        }

        if (SetThreadPriority(hThread, THREAD_PRIORITY_IDLE)) {
            done++;
        } else {
            failed++;
            if (firstErr == ERROR_SUCCESS) {
                firstErr = GetLastError();
            }
        }

        CloseHandle(hThread);
    } while (Thread32Next(snapshot, &te));

    CloseHandle(snapshot);

    *setCount = done;
    *totalCount = total;

    if (failed > 0) {
        *outError = firstErr;
        return FALSE;
    }

    return TRUE;
}
static HANDLE OpenTargetProcess(DWORD pid, DWORD *outRights, DWORD *outError) {
    static const DWORD kFullRights =
        PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE |
        PROCESS_QUERY_LIMITED_INFORMATION;
    static const DWORD kBasicRights =
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
    DWORD firstErr = ERROR_SUCCESS;
    HANDLE hProcess;

    *outRights = 0;
    *outError = ERROR_SUCCESS;

    hProcess = OpenProcess(kFullRights, FALSE, pid);
    if (hProcess) {
        *outRights = kFullRights;
        return hProcess;
    }
    firstErr = GetLastError();

    hProcess = OpenProcess(kBasicRights, FALSE, pid);
    if (hProcess) {
        *outRights = kBasicRights;
        return hProcess;
    }

    if (firstErr == ERROR_SUCCESS) {
        firstErr = GetLastError();
    }

    hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hProcess) {
        *outRights = PROCESS_SET_INFORMATION;
        return hProcess;
    }

    *outError = firstErr;
    return NULL;
}

/* Guards against a pid that was recycled between scan and open. If the
   name cannot be read we assume the handle is still the right process. */
static BOOL VerifyTargetName(HANDLE hProcess, const wchar_t *expected) {
    wchar_t path[MAX_PATH];
    DWORD len = MAX_PATH;
    const wchar_t *base;

    if (!QueryFullProcessImageNameW(hProcess, 0, path, &len)) {
        return TRUE;
    }

    base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;

    return _wcsicmp(base, expected) == 0;
}

static PROCESS_RESULT ApplySettings(
    DWORD pid,
    const wchar_t *expectedName,
    DWORD_PTR affinityMask
) {
    PROCESS_RESULT r;
    HANDLE hProcess;
    DWORD rights = 0;
    DWORD openErr = 0;
    BOOL haveJobRights;
    int i;

    memset(&r, 0, sizeof(r));

    hProcess = OpenTargetProcess(pid, &rights, &openErr);

    if (!hProcess) {
        r.openErr = openErr;
        return r;
    }

    r.opened = TRUE;

    if (!VerifyTargetName(hProcess, expectedName)) {
        r.stale = TRUE;
        CloseHandle(hProcess);
        return r;
    }

    haveJobRights = (rights & PROCESS_SET_QUOTA) && (rights & PROCESS_TERMINATE);

    r.attempted[STEP_PRI] = TRUE;
    if (SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS)) {
        if (GetPriorityClass(hProcess) == IDLE_PRIORITY_CLASS) {
            r.ok[STEP_PRI] = TRUE;
        } else {
            r.err[STEP_PRI] = ERROR_NOT_VERIFIED;
        }
    } else {
        r.err[STEP_PRI] = GetLastError();
    }

    r.attempted[STEP_AFF] = TRUE;
    if (SetProcessAffinityMask(hProcess, affinityMask)) {
        DWORD_PTR procMask = 0;
        DWORD_PTR sysMask = 0;

        if (GetProcessAffinityMask(hProcess, &procMask, &sysMask) &&
            procMask != affinityMask) {
            r.err[STEP_AFF] = ERROR_NOT_VERIFIED;
        } else {
            r.ok[STEP_AFF] = TRUE;
        }
    } else {
        r.err[STEP_AFF] = GetLastError();
    }

    r.attempted[STEP_ECO] = TRUE;
    if (!EnableEfficiencyMode(hProcess, &r.err[STEP_ECO])) {
        r.ok[STEP_ECO] = FALSE;
    } else {
        r.ok[STEP_ECO] = TRUE;
    }

    if (g_cpuCapPercent > 0 && haveJobRights) {
        r.attempted[STEP_CAP] = TRUE;
        if (ApplyCpuCap(hProcess, g_cpuCapPercent, &r.err[STEP_CAP])) {
            r.ok[STEP_CAP] = TRUE;
        }
    }

    r.attempted[STEP_IO] = TRUE;
    if (SetVeryLowIoPriority(hProcess, &r.err[STEP_IO])) {
        r.ok[STEP_IO] = TRUE;
    }

    r.attempted[STEP_MEM] = TRUE;
    if (SetVeryLowMemoryPriority(hProcess, &r.err[STEP_MEM])) {
        r.ok[STEP_MEM] = TRUE;
    }

    CloseHandle(hProcess);

    r.attempted[STEP_THR] = TRUE;
    if (IdleThreads(pid, &r.thrSet, &r.thrTotal, &r.err[STEP_THR])) {
        r.ok[STEP_THR] = TRUE;
    }

    for (i = 0; i < STEP_COUNT; i++) {
        if (r.attempted[i]) {
            r.attemptCount++;
            if (r.ok[i]) {
                r.okCount++;
            }
        }
    }

    return r;
}
static void ReportProcess(int index, const TARGET *target, const PROCESS_RESULT *r) {
    SEG row[3 + STEP_COUNT * 2];
    int n = 0;
    int i;

    SegSet(&row[n++], COLOR_HEAD, " %2d  ", index);
    SegSet(&row[n++], COLOR_WHITE, "%-*ls", NAME_W, target->name);
    SegSet(&row[n++], COLOR_WARN, " %5lu  ", (unsigned long)target->pid);

    for (i = 0; i < STEP_COUNT; i++) {
        if (i) {
            SegSet(&row[n++], COLOR_FRAME, " ");
        }
        SegCell(&row[n++], r->opened && r->attempted[i], r->ok[i], r->err[i]);
    }

    BoxRow(n, row);

    if (!r->opened) {
        char note[256];

        snprintf(
            note, sizeof(note),
            "open:%lu(%s)",
            (unsigned long)r->openErr, ShortReason(r->openErr));
        BoxWrap(COLOR_WARN, note);
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
                AddNote(note, sizeof(note), &pos, " · ");
            }

            if (i == STEP_THR) {
                AddNote(
                    note, sizeof(note), &pos,
                    "thr %d/%d (err %lu)",
                    r->thrSet, r->thrTotal, (unsigned long)r->err[i]);
            } else {
                AddNote(
                    note, sizeof(note), &pos,
                    "%s:%lu(%s)",
                    kStepShort[i], (unsigned long)r->err[i], ShortReason(r->err[i]));
            }
        }

        BoxWrap(COLOR_WARN, note);
    }
}

static int RunOnce(void) {
    ULONGLONG t0 = GetTickCount64();
    static TARGET targets[MAX_TARGETS];
    DWORD scanErr = 0;
    BOOL truncated = FALSE;
    int targetCount;
    DWORD dbgErr = ERROR_SUCCESS;
    BOOL dbgOk;
    DWORD cpuCount;
    DWORD_PTR affinityMask;
    DWORD groups;
    int i;
    int s;

    if (!IsRunAsAdmin()) {
        ClearScreen();
        LayoutConsole(4);
        BoxRule("┌", "┐");
        BoxBar(COLOR_FAIL_BG, " ✗ administrator privileges required");
        BoxRule("└", "┘");
        return 1;
    }

    dbgOk = EnableDebugPrivilege(&dbgErr);

    targetCount = ScanTargets(targets, MAX_TARGETS, &scanErr, &truncated);

    ClearScreen();
    LayoutConsole(17 + 3 * (targetCount > 0 ? targetCount : 0));

    cpuCount = GetLogicalCpuCount();
    affinityMask = GetLastCpuAffinityMask(cpuCount);
    groups = GetActiveProcessorGroupCount();

    BoxRule("┌", "┐");
    BoxBar(COLOR_TITLE, " fuckAce · SGuard64 / SGuardSvc64 limiter");

    {
        SEG status[14];
        int n = 0;

        SegSet(&status[n++], COLOR_OK_BG, " ✓ admin");
        SegSet(&status[n++], COLOR_HEAD, " · ");
        if (dbgOk) {
            SegSet(&status[n++], COLOR_OK_BG, " ✓ SeDebugPrivilege");
        } else {
            SegSet(&status[n++], COLOR_WARN_BG, " ! SeDebugPrivilege(%lu)",
                   (unsigned long)dbgErr);
        }
        SegSet(&status[n++], COLOR_HEAD, " · ");
        SegSet(&status[n++], COLOR_WHITE, "%lu CPUs", (unsigned long)cpuCount);
        SegSet(&status[n++], COLOR_HEAD, " → CPU ");
        SegSet(&status[n++], COLOR_WHITE, "%lu", (unsigned long)(cpuCount - 1));
        SegSet(&status[n++], COLOR_HEAD, " · cap ");
        if (g_cpuCapPercent > 0) {
            SegSet(&status[n++], COLOR_WARN, "%lu%%/CPU", (unsigned long)g_cpuCapPercent);
        } else {
            SegSet(&status[n++], COLOR_FRAME, "off");
        }
        BoxRow(n, status);
    }

    if (targetCount < 0) {
        BoxRule("├", "┤");
        BoxBar(COLOR_FAIL_BG, " ✗ process scan failed (Error=%lu)", (unsigned long)scanErr);
        BoxRule("└", "┘");
        return 1;
    }

    if (groups > 1) {
        BoxBar(COLOR_WARN, " ! %lu processor groups — affinity targets group 0",
               (unsigned long)groups);
    }
    if (truncated) {
        BoxBar(COLOR_WARN, " ! more than %d targets found — extra processes skipped",
               MAX_TARGETS);
    }

    BoxRule("├", "┤");

    {
        SEG head[3 + STEP_COUNT * 2];
        int n = 0;

        SegSet(&head[n++], COLOR_HEAD, " %2s  %-*s %5s  ", "#", NAME_W, "PROCESS", "PID");
        for (s = 0; s < STEP_COUNT; s++) {
            if (s) {
                SegSet(&head[n++], COLOR_HEAD, " ");
            }
            SegSet(&head[n++], COLOR_HEAD, "%-*s", CELL_W, kStepHead[s]);
        }
        BoxRow(n, head);
    }
    {
        int foundCount = 0;
        int skippedCount = 0;
        int fullCount = 0;
        int partialCount = 0;
        int failedCount = 0;
        int openedCount = 0;
        int applied[STEP_COUNT];
        int deniedCount = 0;
        int unsupportedCount = 0;
        int otherErrCount = 0;
        int existingJobCount = 0;
        int exitCode;

        memset(applied, 0, sizeof(applied));

        for (i = 0; i < targetCount; i++) {
            PROCESS_RESULT r = ApplySettings(
                targets[i].pid, targets[i].name, affinityMask);

            if (r.stale) {
                skippedCount++;
                continue;
            }

            foundCount++;
            ReportProcess(foundCount, &targets[i], &r);

            if (r.opened) {
                openedCount++;
            }

            TallyError(r.openErr, &deniedCount, &unsupportedCount, &otherErrCount);

            for (s = 0; s < STEP_COUNT; s++) {
                if (!r.attempted[s]) {
                    continue;
                }
                TallyError(r.err[s], &deniedCount, &unsupportedCount, &otherErrCount);
                if (r.ok[s]) {
                    applied[s]++;
                }
            }

            if (g_cpuCapPercent > 0 && r.opened && !r.attempted[STEP_CAP]) {
                existingJobCount++;
            }

            if (r.opened && r.attemptCount > 0 && r.okCount == r.attemptCount) {
                fullCount++;
            } else if (r.opened && r.okCount > 0) {
                partialCount++;
            } else {
                failedCount++;
            }
        }

        BoxRule("├", "┤");

        {
            SEG sum[8];
            int k = 0;

            SegSet(&sum[k++], COLOR_HEAD, " found ");
            SegSet(&sum[k++], COLOR_WHITE, "%d", foundCount);
            SegSet(&sum[k++], COLOR_HEAD, " · full ");
            SegSet(&sum[k++], COLOR_OK, "%d", fullCount);
            SegSet(&sum[k++], COLOR_HEAD, " · partial ");
            SegSet(&sum[k++], COLOR_WARN, "%d", partialCount);
            SegSet(&sum[k++], COLOR_HEAD, " · failed ");
            SegSet(&sum[k++], COLOR_FAIL, "%d", failedCount);
            BoxRow(k, sum);
        }

        if (foundCount > 0) {
            SEG ap[3 * STEP_COUNT + 4];
            int a = 0;

            SegSet(&ap[a++], COLOR_HEAD, " applied ");
            for (s = 0; s < STEP_COUNT; s++) {
                if (s) {
                    SegSet(&ap[a++], COLOR_HEAD, " · ");
                }
                SegSet(&ap[a++], COLOR_HEAD, "%s ", kStepShort[s]);
                SegSet(&ap[a++], applied[s] ? COLOR_OK : COLOR_FAIL, "%d", applied[s]);
            }
            BoxRow(a, ap);

            BoxLine(COLOR_HEAD, "          opened %d/%d · cpu cap %d · eco/io/mem are process-wide",
                    openedCount, foundCount, applied[STEP_CAP]);

            if (existingJobCount > 0) {
                BoxLine(COLOR_WARN,
                        "          %d process(es) lacked quota rights — CPU cap skipped",
                        existingJobCount);
            }

            if (skippedCount > 0) {
                BoxLine(COLOR_WARN,
                        "          %d pid(s) recycled before they could be configured — skipped",
                        skippedCount);
            }

            if (deniedCount == 0 && unsupportedCount == 0 && otherErrCount == 0) {
                BoxLine(COLOR_OK, " diagnostics  no errors — every attempted operation stuck");
            } else {
                SEG diag[8];
                int d = 0;

                SegSet(&diag[d++], COLOR_HEAD, " diagnostics ");
                if (deniedCount > 0) {
                    SegSet(&diag[d++], COLOR_FAIL, " access-denied %d", deniedCount);
                }
                if (unsupportedCount > 0) {
                    SegSet(&diag[d++], COLOR_WARN, "%sunsupported %d",
                           deniedCount > 0 ? " · " : " ", unsupportedCount);
                }
                if (otherErrCount > 0) {
                    SegSet(&diag[d++], COLOR_WARN, "%sother %d",
                           (deniedCount > 0 || unsupportedCount > 0) ? " · " : " ",
                           otherErrCount);
                }
                BoxRow(d, diag);
            }
        }

        if (foundCount == 0) {
            BoxBar(COLOR_FAIL_BG, " ✗ FAILED - no target process found");
            exitCode = 1;
        } else if (fullCount == foundCount) {
            BoxBar(COLOR_OK_BG, " ✓ SUCCESS - all %d processes fully configured", foundCount);
            exitCode = 0;
        } else if (fullCount > 0 || partialCount > 0) {
            BoxBar(COLOR_WARN_BG, " ! PARTIAL - %d of %d processes fully configured",
                   fullCount, foundCount);
            exitCode = 2;
        } else {
            BoxBar(COLOR_FAIL_BG, " ✗ FAILED - found %d processes but no setting applied",
                   foundCount);
            BoxBar(COLOR_FAIL_BG, "   access denied, protected process, or unsupported operation");
            exitCode = 3;
        }

        {
            SYSTEMTIME st;
            char machine[MAX_COMPUTERNAME_LENGTH + 2];
            DWORD machineLen = sizeof(machine);

            GetLocalTime(&st);

            if (!GetComputerNameA(machine, &machineLen)) {
                machine[0] = 0;
            }

            BoxRule("├", "┤");

            if (foundCount > 0) {
                SEG tgt[16];
                wchar_t uniq[8][32];
                int counts[8];
                int u = 0;
                int t = 0;
                int j;
                int shown;

                for (i = 0; i < targetCount; i++) {
                    int hit = -1;

                    for (j = 0; j < u; j++) {
                        if (_wcsicmp(uniq[j], targets[i].name) == 0) {
                            hit = j;
                            break;
                        }
                    }
                    if (hit < 0) {
                        if (u >= 8) {
                            continue;
                        }
                        hit = u;
                        wcsncpy(uniq[u], targets[i].name, 31);
                        uniq[u][31] = 0;
                        counts[u] = 0;
                        u++;
                    }
                    counts[hit]++;
                }

                SegSet(&tgt[t++], COLOR_HEAD, " targets ");
                shown = u > 4 ? 4 : u;
                for (j = 0; j < shown; j++) {
                    if (j) {
                        SegSet(&tgt[t++], COLOR_HEAD, " · ");
                    }
                    SegSet(&tgt[t++], COLOR_WHITE, "%ls", uniq[j]);
                    SegSet(&tgt[t++], COLOR_WARN, " ×%d", counts[j]);
                }
                if (u > shown) {
                    SegSet(&tgt[t++], COLOR_HEAD, " · …+%d", u - shown);
                }
                BoxRow(t, tgt);
            }

            {
                SEG timing[8];
                int m = 0;

                SegSet(&timing[m++], COLOR_HEAD, " timing   ");
                SegSet(&timing[m++], COLOR_WHITE, "%04d-%02d-%02d %02d:%02d:%02d",
                       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                SegSet(&timing[m++], COLOR_HEAD, " · ");
                SegSet(&timing[m++], COLOR_WHITE, "%llu ms",
                       (unsigned long long)(GetTickCount64() - t0));
                SegSet(&timing[m++], COLOR_HEAD, " · ");
                SegSet(&timing[m++], COLOR_WHITE, "%s", machine);
                BoxRow(m, timing);
            }
        }

        BoxRule("└", "┘");

        return exitCode;
    }
}

static BOOL ParseArgs(int argc, wchar_t **argv) {
    int i;

    for (i = 0; i < DEFAULT_TARGET_COUNT; i++) {
        AddTargetName(kDefaultTargets[i]);
    }

    for (i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--no-cap") == 0) {
            g_cpuCapPercent = 0;
            continue;
        }

        if (wcsncmp(argv[i], L"--rate=", 7) == 0) {
            int v = _wtoi(argv[i] + 7);

            if (v <= 0) {
                g_cpuCapPercent = 0;
            } else if (v > 100) {
                g_cpuCapPercent = 100;
            } else {
                g_cpuCapPercent = (DWORD)v;
            }
            continue;
        }

        if (argv[i][0] == L'-') {
            fwprintf(stderr, L"unknown option: %ls\n", argv[i]);
            fwprintf(stderr, L"usage: fuckAce [--rate=PERCENT] [--no-cap] [process.exe ...]\n");
            return FALSE;
        }

        if (!AddTargetName(argv[i])) {
            fwprintf(stderr, L"too many target names (max %d)\n", MAX_TARGET_NAMES);
            return FALSE;
        }
    }

    return TRUE;
}

int wmain(int argc, wchar_t **argv) {
    int code;

    SetConsoleOutputCP(CP_UTF8);
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!ParseArgs(argc, argv)) {
        return 1;
    }

    for (;;) {
        code = RunOnce();

        if (code == 0) {
            Countdown("Auto-exit in", "Enter = exit now", EXIT_SECONDS);
            break;
        }

        if (!Countdown("Auto-retry in", "Enter = retry now, Esc = exit", RETRY_SECONDS)) {
            break;
        }
    }

    return code;
}
