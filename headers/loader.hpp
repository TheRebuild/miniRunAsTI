#pragma once
#include "pch.hpp"
#include "winsafer.h"

// Required functions (loaded dynamically)
using PFN_OpenProcessToken = BOOL(WINAPI *)(HANDLE, DWORD, PHANDLE);
using PFN_LookupPrivilegeValueW = BOOL(WINAPI *)(LPCWSTR, LPCWSTR, PLUID);
using PFN_AdjustTokenPrivileges = BOOL(WINAPI *)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
using PFN_OpenProcess = HANDLE(WINAPI *)(DWORD, BOOL, DWORD);
using PFN_DuplicateTokenEx = BOOL(WINAPI *)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
                                            TOKEN_TYPE, PHANDLE);
using PFN_SetThreadToken = BOOL(WINAPI *)(PHANDLE, HANDLE);
using PFN_OpenThreadToken = BOOL(WINAPI *)(HANDLE, DWORD, BOOL, PHANDLE);
using PFN_SetTokenInformation = BOOL(WINAPI *)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);
using PFN_CreateProcessAsUserW = BOOL(WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                                BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using PFN_ShellExecuteExW = BOOL(WINAPI *)(SHELLEXECUTEINFOW *);
using PFN_WTSGetActiveConsoleSessionId = DWORD(WINAPI *)();
using PFN_WTSEnumerateProcessesW = BOOL(WINAPI *)(HANDLE, DWORD, DWORD, PWTS_PROCESS_INFOW *, PDWORD);
using PFN_WTSFreeMemory = void(WINAPI *)(PVOID);
using PFN_WTSQueryUserToken = BOOL(WINAPI *)(ULONG, PHANDLE);
using PFN_OpenSCManagerW = SC_HANDLE(WINAPI *)(LPCWSTR, LPCWSTR, DWORD);
using PFN_OpenServiceW = SC_HANDLE(WINAPI *)(SC_HANDLE, LPCWSTR, DWORD);
using PFN_CloseServiceHandle = BOOL(WINAPI *)(SC_HANDLE);
using PFN_QueryServiceStatusEx = BOOL(WINAPI *)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
using PFN_StartServiceW = BOOL(WINAPI *)(SC_HANDLE, DWORD, LPCWSTR *);
using PFN_SaferCreateLevel = BOOL(WINAPI *)(DWORD, DWORD, DWORD, SAFER_LEVEL_HANDLE *, LPVOID);
using PFN_SaferComputeTokenFromLevel = BOOL(WINAPI *)(SAFER_LEVEL_HANDLE, HANDLE, PHANDLE, DWORD, LPVOID);
using PFN_SaferCloseLevel = BOOL(WINAPI *)(SAFER_LEVEL_HANDLE);
using PFN_CreateEnvironmentBlock = BOOL(WINAPI *)(LPVOID *, HANDLE, BOOL);
using PFN_DestroyEnvironmentBlock = BOOL(WINAPI *)(LPVOID);

using PFN_RegOpenKeyExW = LSTATUS(WINAPI *)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using PFN_RegQueryValueExW = LSTATUS(WINAPI *)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using PFN_RegSetValueExW = LSTATUS(WINAPI *)(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
using PFN_RegCloseKey = LSTATUS(WINAPI *)(HKEY);

extern PFN_OpenProcessToken pfnOpenProcessToken;
extern PFN_LookupPrivilegeValueW pfnLookupPrivilegeValueW;
extern PFN_AdjustTokenPrivileges pfnAdjustTokenPrivileges;
extern PFN_OpenProcess pfnOpenProcess;
extern PFN_DuplicateTokenEx pfnDuplicateTokenEx;
extern PFN_SetThreadToken pfnSetThreadToken;
extern PFN_OpenThreadToken pfnOpenThreadToken;
extern PFN_SetTokenInformation pfnSetTokenInformation;
extern PFN_CreateProcessAsUserW pfnCreateProcessAsUserW;
extern PFN_ShellExecuteExW pfnShellExecuteExW;
extern PFN_WTSGetActiveConsoleSessionId pfnWTSGetActiveConsoleSessionId;
extern PFN_WTSEnumerateProcessesW pfnWTSEnumerateProcessesW;
extern PFN_WTSFreeMemory pfnWTSFreeMemory;
extern PFN_WTSQueryUserToken pfnWTSQueryUserToken;
extern PFN_OpenSCManagerW pfnOpenSCManagerW;
extern PFN_OpenServiceW pfnOpenServiceW;
extern PFN_CloseServiceHandle pfnCloseServiceHandle;
extern PFN_QueryServiceStatusEx pfnQueryServiceStatusEx;
extern PFN_StartServiceW pfnStartServiceW;
extern PFN_SaferCreateLevel pfnSaferCreateLevel;
extern PFN_SaferComputeTokenFromLevel pfnSaferComputeTokenFromLevel;
extern PFN_SaferCloseLevel pfnSaferCloseLevel;

extern PFN_RegOpenKeyExW pfnRegOpenKeyExW;
extern PFN_RegQueryValueExW pfnRegQueryValueExW;
extern PFN_RegCloseKey pfnRegCloseKey;
extern PFN_RegSetValueExW pfnRegSetValueExW;

extern PFN_CreateEnvironmentBlock pfnCreateEnvironmentBlock;
extern PFN_DestroyEnvironmentBlock pfnDestroyEnvironmentBlock;

bool LoadApiFunctions();
