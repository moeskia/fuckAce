#include "elevation/elevate.h"
#include "elevation/elevate_internal.h"

/* -------------------------------------------------------------------- 特权 */

BOOL ElevateEnablePrivilege(LPCWSTR name, DWORD *outError) {
    HANDLE token;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    BOOL ok;
    DWORD error = ERROR_SUCCESS;

    if (outError) {
        *outError = ERROR_SUCCESS;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        error = GetLastError();
        if (outError) {
            *outError = error;
        }
        return FALSE;
    }
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        error = GetLastError();
        if (outError) {
            *outError = error;
        }
        CloseHandle(token);
        return FALSE;
    }
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    ok = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL);
    error = GetLastError();
    CloseHandle(token);
    if (outError) {
        *outError = error;
    }
    return ok && error == ERROR_SUCCESS;
}

static const wchar_t *const kElevatePrivileges[] = {
    SE_DEBUG_NAME,
    SE_IMPERSONATE_NAME,
    SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_TAKE_OWNERSHIP_NAME,
    SE_BACKUP_NAME,
    SE_RESTORE_NAME,
    SE_INCREASE_BASE_PRIORITY_NAME
};

DWORD ElevateEnablePrivileges(void) {
    DWORD firstError = ERROR_SUCCESS;
    size_t i;

    for (i = 0; i < sizeof(kElevatePrivileges) / sizeof(kElevatePrivileges[0]); i++) {
        DWORD error = ERROR_SUCCESS;
        if (!ElevateEnablePrivilege(kElevatePrivileges[i], &error) &&
            firstError == ERROR_SUCCESS) {
            firstError = error != ERROR_SUCCESS ? error : ERROR_PRIVILEGE_NOT_HELD;
        }
    }
    return firstError;
}

/* 把令牌里**已经存在**的特权全部打开。
   注意 AdjustTokenPrivileges 只能开关令牌里已有的特权，它**不能新增**。
   早先那版传入一个 Luid=0 的单项，指望它是"全部"的约定——那个约定并不存在，
   实际效果是什么都没打开：实测拿到的 SYSTEM 令牌里 SeAssignPrimaryTokenPrivilege
   一直是 off，于是 CreateProcessAsUser 必然 ERROR_PRIVILEGE_NOT_HELD，
   "守护进程"那条兜底其实从来没起来过。这里老老实实枚举。 */
void ElevateEnableAllTokenPrivileges(HANDLE token) {
    BYTE buffer[16384];
    DWORD needed = 0;
    TOKEN_PRIVILEGES *current;
    DWORD i;

    if (!GetTokenInformation(token, TokenPrivileges, buffer, sizeof(buffer), &needed)) {
        return;
    }
    current = (TOKEN_PRIVILEGES *)buffer;
    for (i = 0; i < current->PrivilegeCount; i++) {
        TOKEN_PRIVILEGES single;

        if (current->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
            continue;
        }
        single.PrivilegeCount = 1;
        single.Privileges[0].Luid = current->Privileges[i].Luid;
        single.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(ERROR_SUCCESS);
        AdjustTokenPrivileges(token, FALSE, &single, 0, NULL, NULL);
    }
}

/* -------------------------------------------------------------- 令牌获取 */

/* 打开**别人**的令牌时只能要这几个：
   TOKEN_ADJUST_PRIVILEGES / GROUPS / DEFAULT 只授予令牌持有者本人，
   对 SYSTEM 令牌带上它们必定 ERROR_ACCESS_DENIED(5)。
   实测 winlogon.exe 这种 PPL 进程给 QUERY|DUPLICATE，services.exe 只给 QUERY|DUPLICATE，
   svchost 甚至只给 QUERY —— 所以外部进程令牌永远只能当兜底，不能当主路径。 */
#define ELEVATE_TOKEN_OPEN_RIGHTS \
    (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE)

/* 复制出来的新句柄是自己创建的，才可以把权利要全。 */
#define ELEVATE_TOKEN_DUP_RIGHTS TOKEN_ALL_ACCESS

BOOL ElevateDuplicateTokenFromPid(DWORD pid, HANDLE *outToken, DWORD *outError) {
    HANDLE process;
    HANDLE token;
    HANDLE primary = NULL;

    *outToken = NULL;
    *outError = ERROR_SUCCESS;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        *outError = GetLastError();
        return FALSE;
    }
    if (!OpenProcessToken(process, ELEVATE_TOKEN_OPEN_RIGHTS, &token)) {
        *outError = GetLastError();
        CloseHandle(process);
        return FALSE;
    }
    if (!DuplicateTokenEx(
            token,
            ELEVATE_TOKEN_DUP_RIGHTS,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &primary)) {
        *outError = GetLastError();
    }
    CloseHandle(token);
    CloseHandle(process);
    if (!primary) {
        if (*outError == ERROR_SUCCESS) {
            *outError = ERROR_ACCESS_DENIED;
        }
        return FALSE;
    }
    *outToken = primary;
    return TRUE;
}

BOOL ElevateFindProcessNamed(const wchar_t *name, DWORD *outPid) {
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    BOOL found = FALSE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) != 0) {
                continue;
            }
            *outPid = entry.th32ProcessID;
            found = TRUE;
            break;
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

BOOL ElevateFindProcessBySid(const wchar_t *sidText, DWORD *outPid, wchar_t *outName, size_t nameSize) {
    HANDLE snapshot;
    PROCESSENTRY32W entry;
    BOOL found = FALSE;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            HANDLE process;
            HANDLE token;
            wchar_t sid[192];
            DWORD error = ERROR_SUCCESS;

            if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4) {
                continue;
            }
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
            if (!process) {
                continue;
            }
            if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
                if (ElevateSidStringFromToken(token, sid, sizeof(sid) / sizeof(wchar_t), &error) &&
                    _wcsicmp(sid, sidText) == 0) {
                    *outPid = entry.th32ProcessID;
                    wcsncpy(outName, entry.szExeFile, nameSize - 1);
                    outName[nameSize - 1] = 0;
                    found = TRUE;
                }
                CloseHandle(token);
            }
            CloseHandle(process);
            if (found) {
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}
