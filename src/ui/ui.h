#ifndef UI_H
#define UI_H

#include "core/common.h"

#define COLOR_DEFAULT 7
#define COLOR_WHITE   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_FRAME   (FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_HEAD    (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_OK      (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_FAIL    (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COLOR_WARN    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_TITLE   (BACKGROUND_BLUE | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_OK_BG   (BACKGROUND_GREEN | BACKGROUND_INTENSITY)
#define COLOR_FAIL_BG (BACKGROUND_RED | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COLOR_WARN_BG (BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_INTENSITY)

#define CONTENT_WIDTH 81
#define CELL_W 6
#define NAME_W 15

typedef struct _SEG {
    char text[200];
    WORD color;
} SEG;

struct _ELEVATE_STATUS;
struct _ELEVATE_RESULT;

void UIInit(void);
void UIShowCursor(BOOL show);
void UIClearScreen(void);
void UIResetCursor(void);
void UIClearToEnd(void);
void UILayoutConsole(int contentRows);
void UIResetTiming(void);
SEG *UISegSet(SEG *segment, WORD color, const char *format, ...);
void UIBoxRule(const char *left, const char *right);
void UIBoxRow(int count, const SEG *segments);
void UIBoxLine(WORD color, const char *format, ...);
void UIReportProcess(int index, const TARGET *target, const PROCESS_RESULT *result);
void UIDrawTiming(ULONGLONG elapsedMs, const char *machine);
int UICountdown(const char *label, const char *hint, int seconds);
void UIElevationPanel(
    const struct _ELEVATE_STATUS *status,
    const struct _ELEVATE_RESULT *result,
    const char *footer);
void UIDiagnosePanel(const struct _ELEVATE_STATUS *status);
void UIHandoffSummary(const struct _ELEVATE_RESULT *result);

#endif
