#ifndef ELEVATE_INTERNAL_H
#define ELEVATE_INTERNAL_H

#include "elevation/elevate.h"

BOOL ElevateEnablePrivilege(LPCWSTR name, DWORD *outError);
BOOL ElevateQueryIdentity(ELEVATE_STATUS *status);
BOOL ElevateTiKeyStale(void);
BOOL ElevateTiRestoreKey(DWORD *outError);
void ElevateNote(wchar_t *note, size_t capacity, const wchar_t *format, ...);
BOOL ElevateSelfExecutablePath(wchar_t *buffer, size_t size);
BOOL ElevateImpersonateWithToken(HANDLE primary, HANDLE *outImpersonation, DWORD *outError);
BOOL ElevateIsImpersonating(void);
HANDLE ElevateSystemBaseToken(void);
void ElevateReleaseSystemBase(void);
DWORD ElevateEnablePrivileges(void);
void ElevateReleaseService(void);
BOOL ElevateProcessTier(HANDLE process, int *outTier, DWORD *outError);
BOOL ElevateSidStringFromToken(HANDLE token, wchar_t *buffer, size_t size, DWORD *outError);

BOOL ElevateTokenSidEquals(HANDLE token, const wchar_t *sidText);
BOOL ElevateQueryThreadIdentity(ELEVATE_IDENTITY *identity);

void ElevateEnableAllTokenPrivileges(HANDLE token);
BOOL ElevateDuplicateTokenFromPid(DWORD pid, HANDLE *outToken, DWORD *outError);
BOOL ElevateFindProcessNamed(const wchar_t *name, DWORD *outPid);
BOOL ElevateFindProcessBySid(const wchar_t *sidText, DWORD *outPid, wchar_t *outName, size_t nameSize);

BOOL ElevateDuplicateTrustedInstallerToken(DWORD pid, HANDLE *outToken, DWORD *outError);
BOOL ElevateAcquireTrustedInstallerTokenFromProcess(ELEVATE_TIER_RESULT *result, HANDLE *outToken);
BOOL ElevateAcquireSystemToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken);
BOOL ElevateAcquireTrustedInstallerToken(ELEVATE_TIER_RESULT *result, HANDLE *outToken);

#endif