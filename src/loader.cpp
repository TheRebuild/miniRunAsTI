#include "loader.hpp"

// Advapi32
PFN_OpenProcessToken pfnOpenProcessToken = nullptr;
PFN_LookupPrivilegeValueW pfnLookupPrivilegeValueW = nullptr;
PFN_AdjustTokenPrivileges pfnAdjustTokenPrivileges = nullptr;
PFN_OpenProcess pfnOpenProcess = nullptr;
PFN_DuplicateTokenEx pfnDuplicateTokenEx = nullptr;
PFN_SetThreadToken pfnSetThreadToken = nullptr;
PFN_OpenThreadToken pfnOpenThreadToken = nullptr;
PFN_SetTokenInformation pfnSetTokenInformation = nullptr;
PFN_CreateProcessAsUserW pfnCreateProcessAsUserW = nullptr;
PFN_OpenSCManagerW pfnOpenSCManagerW = nullptr;
PFN_OpenServiceW pfnOpenServiceW = nullptr;
PFN_CloseServiceHandle pfnCloseServiceHandle = nullptr;
PFN_QueryServiceStatusEx pfnQueryServiceStatusEx = nullptr;
PFN_StartServiceW pfnStartServiceW = nullptr;
PFN_SaferCreateLevel pfnSaferCreateLevel = nullptr;
PFN_SaferComputeTokenFromLevel pfnSaferComputeTokenFromLevel = nullptr;
PFN_SaferCloseLevel pfnSaferCloseLevel = nullptr;
PFN_RegOpenKeyExW pfnRegOpenKeyExW = nullptr;
PFN_RegQueryValueExW pfnRegQueryValueExW = nullptr;
PFN_RegSetValueExW pfnRegSetValueExW = nullptr;
PFN_RegCloseKey pfnRegCloseKey = nullptr;

// Shell32
PFN_ShellExecuteExW pfnShellExecuteExW = nullptr;

// Kernel32
PFN_WTSGetActiveConsoleSessionId pfnWTSGetActiveConsoleSessionId = nullptr;

// wtsapi32
PFN_WTSEnumerateProcessesW pfnWTSEnumerateProcessesW = nullptr;
PFN_WTSFreeMemory pfnWTSFreeMemory = nullptr;
PFN_WTSQueryUserToken pfnWTSQueryUserToken = nullptr;

// userenv
PFN_CreateEnvironmentBlock pfnCreateEnvironmentBlock = nullptr;
PFN_DestroyEnvironmentBlock pfnDestroyEnvironmentBlock = nullptr;

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)

#define LOAD_FUNCTION(dllHandle, funcPtr, funcType, funcName)                                                          \
    funcPtr = (funcType)GetProcAddress(dllHandle, funcName);                                                           \
    if (!funcPtr)                                                                                                      \
    {                                                                                                                  \
        std::wstring errorMsg = L"Failed to get address for function: '";                                              \
        errorMsg += WIDEN(#funcName);                                                                                  \
        errorMsg += L"'";                                                                                              \
        MessageBoxW(nullptr, errorMsg.c_str(), L"API Load Error", MB_OK | MB_ICONERROR);                               \
        return false;                                                                                                  \
    }

bool LoadApiFunctions()
{
    HMODULE advapi32 = LoadLibraryW(L"advapi32.dll");
    if (!advapi32)
    {
        MessageBoxW(nullptr, L"Failed to load advapi32.dll", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    LOAD_FUNCTION(advapi32, pfnOpenProcessToken, PFN_OpenProcessToken, "OpenProcessToken");
    LOAD_FUNCTION(advapi32, pfnLookupPrivilegeValueW, PFN_LookupPrivilegeValueW, "LookupPrivilegeValueW");
    LOAD_FUNCTION(advapi32, pfnAdjustTokenPrivileges, PFN_AdjustTokenPrivileges, "AdjustTokenPrivileges");
    LOAD_FUNCTION(advapi32, pfnDuplicateTokenEx, PFN_DuplicateTokenEx, "DuplicateTokenEx");
    LOAD_FUNCTION(advapi32, pfnSetTokenInformation, PFN_SetTokenInformation, "SetTokenInformation");
    LOAD_FUNCTION(advapi32, pfnCreateProcessAsUserW, PFN_CreateProcessAsUserW, "CreateProcessAsUserW");
    LOAD_FUNCTION(advapi32, pfnOpenSCManagerW, PFN_OpenSCManagerW, "OpenSCManagerW");
    LOAD_FUNCTION(advapi32, pfnOpenServiceW, PFN_OpenServiceW, "OpenServiceW");
    LOAD_FUNCTION(advapi32, pfnCloseServiceHandle, PFN_CloseServiceHandle, "CloseServiceHandle");
    LOAD_FUNCTION(advapi32, pfnQueryServiceStatusEx, PFN_QueryServiceStatusEx, "QueryServiceStatusEx");
    LOAD_FUNCTION(advapi32, pfnStartServiceW, PFN_StartServiceW, "StartServiceW");
    LOAD_FUNCTION(advapi32, pfnSetThreadToken, PFN_SetThreadToken, "SetThreadToken");
    LOAD_FUNCTION(advapi32, pfnOpenThreadToken, PFN_OpenThreadToken, "OpenThreadToken");

    LOAD_FUNCTION(advapi32, pfnSaferCreateLevel, PFN_SaferCreateLevel, "SaferCreateLevel");
    LOAD_FUNCTION(advapi32, pfnSaferComputeTokenFromLevel, PFN_SaferComputeTokenFromLevel,
                  "SaferComputeTokenFromLevel");
    LOAD_FUNCTION(advapi32, pfnSaferCloseLevel, PFN_SaferCloseLevel, "SaferCloseLevel");

    LOAD_FUNCTION(advapi32, pfnRegOpenKeyExW, PFN_RegOpenKeyExW, "RegOpenKeyExW");
    LOAD_FUNCTION(advapi32, pfnRegQueryValueExW, PFN_RegQueryValueExW, "RegQueryValueExW");
    LOAD_FUNCTION(advapi32, pfnRegCloseKey, PFN_RegCloseKey, "RegCloseKey");

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32)
    {
        MessageBoxW(nullptr, L"Failed to get handle to kernel32.dll", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    LOAD_FUNCTION(kernel32, pfnOpenProcess, PFN_OpenProcess, "OpenProcess");
    LOAD_FUNCTION(kernel32, pfnWTSGetActiveConsoleSessionId, PFN_WTSGetActiveConsoleSessionId,
                  "WTSGetActiveConsoleSessionId");

    HMODULE shell32 = LoadLibraryW(L"shell32.dll");
    if (!shell32)
    {
        MessageBoxW(nullptr, L"Failed to load shell32.dll", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    LOAD_FUNCTION(shell32, pfnShellExecuteExW, PFN_ShellExecuteExW, "ShellExecuteExW");

    HMODULE wtsapi32 = LoadLibraryW(L"wtsapi32.dll");
    if (!wtsapi32)
    {
        MessageBoxW(nullptr, L"Failed to load wtsapi32.dll", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    LOAD_FUNCTION(wtsapi32, pfnWTSEnumerateProcessesW, PFN_WTSEnumerateProcessesW, "WTSEnumerateProcessesW");
    LOAD_FUNCTION(wtsapi32, pfnWTSFreeMemory, PFN_WTSFreeMemory, "WTSFreeMemory");
    LOAD_FUNCTION(wtsapi32, pfnWTSQueryUserToken, PFN_WTSQueryUserToken, "WTSQueryUserToken");

    HMODULE userenv = LoadLibraryW(L"userenv.dll");
    if (!userenv)
    {
        MessageBoxW(nullptr, L"Failed to load userenv.dll", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    LOAD_FUNCTION(userenv, pfnCreateEnvironmentBlock, PFN_CreateEnvironmentBlock, "CreateEnvironmentBlock");
    LOAD_FUNCTION(userenv, pfnDestroyEnvironmentBlock, PFN_DestroyEnvironmentBlock, "DestroyEnvironmentBlock");

    return true;
}
