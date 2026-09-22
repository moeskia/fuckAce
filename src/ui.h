#ifndef UI_H
#define UI_H

#include "common.h"

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

#define CONTENT_WIDTH 86
#define CELL_W 6
#define NAME_W 15

typedef struct _SEG {
    char text[200];
    WORD color;
} SEG;

void UIInit(void);
void UIShowCursor(BOOL show);
void UIClearScreen(void);
void UIResetCursor(void);
void UIClearToEnd(void);
void UILayoutConsole(int contentRows);
void UISetColor(WORD color);
int UIUtf8Len(const char *s);
SEG *UISegSet(SEG *seg, WORD color, const char *fmt, ...);
void UIBoxRule(const char *left, const char *right);
void UIBoxRow(int count, const SEG *segs);
void UIBoxLine(WORD color, const char *fmt, ...);
void UIBoxWrap(WORD color, const char *text);
void UIBoxBar(WORD color, const char *fmt, ...);
void UISegCell(SEG *seg, BOOL attempted, BOOL ok, DWORD err);
const char *UIShortReason(DWORD err);
void UIAddNote(char *buf, size_t size, size_t *pos, const char *fmt, ...);
void UIReportProcess(int index, const TARGET *target, const PROCESS_RESULT *r);
int UICountdown(const char *label, const char *hint, int seconds);

#endif /* UI_H */
