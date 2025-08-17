#include "execution.hpp"
#include "loader.hpp"
#include "pch.hpp"
#include "utils.hpp"

#include <iostream>

namespace
{
std::optional<Error> EnablePrivilege(const std::wstring &privilegeName)
{
    HANDLE hToken;
    if (!pfnOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return Error{GetLastError(), L"OpenProcessToken failed for self"};

    ScopeGuard tokenGuard([&] { CloseHandle(hToken); });
    LUID luid;
    if (!pfnLookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid))
        return Error{GetLastError(), L"LookupPrivilegeValueW failed"};

    TOKEN_PRIVILEGES tp{
        .PrivilegeCount = 1,
        .Privileges = {{
            .Luid = luid,
            .Attributes = SE_PRIVILEGE_ENABLED,
        }},
    };

    if (!pfnAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
        return Error{GetLastError(), L"AdjustTokenPrivileges failed for self"};

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return Error{GetLastError(), L"Not all privileges referenced are assigned to the caller."};

    return std::nullopt;
}

std::optional<Error> EnablePrivilegesOnToken(HANDLE hToken, const std::vector<std::wstring> &privileges)
{
    if (privileges.empty())
        return std::nullopt;

    const auto tp_size = sizeof(TOKEN_PRIVILEGES) + (privileges.size() - 1) * sizeof(LUID_AND_ATTRIBUTES);
    const auto p_tp = static_cast<PTOKEN_PRIVILEGES>(_malloca(tp_size));

    if (!p_tp)
        return Error{ERROR_OUTOFMEMORY, L"Failed to allocate memory for TOKEN_PRIVILEGES"};

    ScopeGuard tpGuard([&] { _freea(p_tp); });
    p_tp->PrivilegeCount = static_cast<DWORD>(privileges.size());

    for (size_t i = 0; i < privileges.size(); ++i)
    {
        if (!pfnLookupPrivilegeValueW(nullptr, privileges[i].c_str(), &p_tp->Privileges[i].Luid))
            return Error{GetLastError(), L"LookupPrivilegeValueW failed for token"};
        p_tp->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }

    if (!pfnAdjustTokenPrivileges(hToken, FALSE, p_tp, static_cast<DWORD>(tp_size), nullptr, nullptr))
        return Error{GetLastError(), L"AdjustTokenPrivileges failed for token"};
    return std::nullopt;
}

std::optional<Error> ImpersonateSystem(std::optional<ScopeGuard> &impersonationGuard)
{
    if (auto err = EnablePrivilege(L"SeDebugPrivilege"))
        return err;

    const DWORD consoleSessionId = pfnWTSGetActiveConsoleSessionId();

    DWORD winlogonPid = 0;
    PWTS_PROCESS_INFOW pProcInfo = nullptr;
    DWORD count = 0;

    if (pfnWTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pProcInfo, &count))
    {
        ScopeGuard procInfoGuard([&] { pfnWTSFreeMemory(pProcInfo); });
        for (DWORD i = 0; i < count; ++i)
        {
            if (pProcInfo[i].SessionId == consoleSessionId && _wcsicmp(pProcInfo[i].pProcessName, L"winlogon.exe") == 0)
            {
                winlogonPid = pProcInfo[i].ProcessId;
                break;
            }
        }
    }

    if (winlogonPid == 0)
        return Error{0, L"Could not find the winlogon.exe process."};

    HANDLE hWinlogon = pfnOpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);
    if (!hWinlogon)
        return Error{GetLastError(), L"Failed to open the winlogon.exe process."};

    ScopeGuard processGuard([&] { CloseHandle(hWinlogon); });
    HANDLE hToken;
    if (!pfnOpenProcessToken(hWinlogon, MAXIMUM_ALLOWED, &hToken))
        return Error{GetLastError(), L"Failed to open the winlogon.exe token."};

    ScopeGuard tokenGuard([&] { CloseHandle(hToken); });
    HANDLE hImpersonationToken;
    if (!pfnDuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenImpersonation,
                             &hImpersonationToken))
        return Error{GetLastError(), L"Failed to duplicate token for impersonation."};

    const std::vector<std::wstring> privileges = {L"SeAssignPrimaryTokenPrivilege", L"SeIncreaseQuotaPrivilege",
                                                  L"SeTcbPrivilege"};
    EnablePrivilegesOnToken(hImpersonationToken, privileges);
    if (!pfnSetThreadToken(nullptr, hImpersonationToken))
    {
        CloseHandle(hImpersonationToken);
        return Error{GetLastError(), L"SetThreadToken failed."};
    }

    impersonationGuard.emplace([hImpersonationToken] {
        pfnSetThreadToken(nullptr, nullptr);
        CloseHandle(hImpersonationToken);
    });
    return std::nullopt;
}

std::optional<Error> RunAsUserWithToken(HANDLE hToken, const std::vector<std::wstring> &command,
                                        const std::wstring &userType)
{
    ScopeGuard tokenGuard([&] { CloseHandle(hToken); });
    DWORD consoleSessionId = pfnWTSGetActiveConsoleSessionId();

    if (consoleSessionId == 0xFFFFFFFF)
        return Error{GetLastError(), L"Failed to get active console session ID."};

    if (!pfnSetTokenInformation(hToken, TokenSessionId, &consoleSessionId, sizeof(DWORD)))
        return Error{GetLastError(), L"SetTokenInformation failed"};

    STARTUPINFOW si = {.cb = sizeof(si), .lpDesktop = const_cast<LPWSTR>(L"winsta0\\default")};

    PROCESS_INFORMATION pi = {};
    std::wstring commandLine = JoinCommandArgs(command);
    if (!pfnCreateProcessAsUserW(hToken, nullptr, commandLine.data(), nullptr, nullptr, FALSE,
                                 CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi))
        return Error{GetLastError(), L"CreateProcessAsUserW failed"};

    std::wcout << L"[SUCCESS] Process launched as " << userType << L". PID: " << pi.dwProcessId << std::endl;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return std::nullopt;
}

bool IsLUAEnabled()
{
    HKEY hKey;
    if (pfnRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0,
                         KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    ScopeGuard keyGuard([&] { pfnRegCloseKey(hKey); });

    DWORD value = 0;
    DWORD dataSize = sizeof(value);
    if (pfnRegQueryValueExW(hKey, L"EnableLUA", nullptr, nullptr, reinterpret_cast<LPBYTE>(&value), &dataSize) !=
        ERROR_SUCCESS)
        return false;

    return value != 0;
}

} // namespace

std::optional<Error> RunAsSystem(const std::vector<std::wstring> &command)
{
    std::optional<ScopeGuard> impersonationGuard;
    if (auto err = ImpersonateSystem(impersonationGuard))
        return err;

    HANDLE hThreadToken;
    if (!pfnOpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hThreadToken))
        return Error{GetLastError(), L"Failed to open thread token after impersonation."};

    ScopeGuard threadTokenGuard([&] { CloseHandle(hThreadToken); });
    HANDLE hPrimaryToken;
    if (!pfnDuplicateTokenEx(hThreadToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary,
                             &hPrimaryToken))
        return Error{GetLastError(), L"Failed to duplicate primary token from impersonated token."};

    return RunAsUserWithToken(hPrimaryToken, command, L"NT AUTHORITY\\SYSTEM");
}

std::optional<Error> RunAsTi(const std::vector<std::wstring> &command)
{
    std::optional<ScopeGuard> impersonationGuard;
    if (auto err = ImpersonateSystem(impersonationGuard))
        return err;

    SC_HANDLE hScm = pfnOpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm)
        return Error{GetLastError(), L"Failed to open SCM."};

    ScopeGuard scmGuard([&] { pfnCloseServiceHandle(hScm); });
    SC_HANDLE hService = pfnOpenServiceW(hScm, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService)
        return Error{GetLastError(), L"Failed to open the TrustedInstaller service."};

    ScopeGuard serviceGuard([&] { pfnCloseServiceHandle(hService); });
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded;
    for (auto i = 0; i < 10; ++i)
    {
        if (!pfnQueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp),
                                     &bytesNeeded))
            return Error{GetLastError(), L"QueryServiceStatusEx failed."};

        if (ssp.dwCurrentState == SERVICE_RUNNING)
            break;

        if (ssp.dwCurrentState == SERVICE_STOPPED)
            if (!pfnStartServiceW(hService, 0, nullptr))
                return Error{GetLastError(), L"Failed to start the TrustedInstaller service."};

        Sleep(500);
    }

    if (ssp.dwCurrentState != SERVICE_RUNNING)
        return Error{0, L"TrustedInstaller service failed to start."};

    HANDLE hTiProcess = pfnOpenProcess(MAXIMUM_ALLOWED, FALSE, ssp.dwProcessId);
    if (!hTiProcess)
        return Error{GetLastError(), L"Failed to open the TrustedInstaller process."};

    ScopeGuard tiProcessGuard([&] { CloseHandle(hTiProcess); });
    HANDLE hToken;
    if (!pfnOpenProcessToken(hTiProcess, MAXIMUM_ALLOWED, &hToken))
        return Error{GetLastError(), L"Failed to open the TrustedInstaller token."};

    ScopeGuard tiTokenGuard([&] { CloseHandle(hToken); });
    HANDLE hPrimaryToken;
    if (!pfnDuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &hPrimaryToken))
        return Error{GetLastError(), L"Failed to duplicate the TrustedInstaller token."};

    return RunAsUserWithToken(hPrimaryToken, command, L"TrustedInstaller");
}

std::optional<Error> RunElevated(const std::vector<std::wstring> &command)
{
    const std::wstring &file = command[0];
    std::wstring params;
    if (command.size() > 1)
    {
        const std::vector args(command.begin() + 1, command.end());
        params = JoinCommandArgs(args);
    }

    SHELLEXECUTEINFOW sei = {
        .cbSize = sizeof(sei),
        .fMask = SEE_MASK_NOCLOSEPROCESS,
        .lpVerb = L"runas",
        .lpFile = file.c_str(),
        .lpParameters = params.empty() ? nullptr : params.c_str(),
        .nShow = SW_SHOWNORMAL,
    };

    if (!pfnShellExecuteExW(&sei))
        return Error{GetLastError(), L"ShellExecuteExW failed."};

    std::wcout << L"[SUCCESS] Process launched with PID: " << GetProcessId(sei.hProcess) << std::endl;
    CloseHandle(sei.hProcess);
    return std::nullopt;
}

std::optional<Error> RunAsNormalUser(const std::vector<std::wstring> &command)
{
    if (!isRunningAsAdmin())
    {
        return Error{static_cast<DWORD>(-1), L"[-] This function is intended to be run from an elevated process..."};
    }

    auto err = EnablePrivilege(L"SeTcbPrivilege");

    // System & TrustedInstaller
    if (!err)
    {
        std::wcout << L"[?] Running as SYSTEM." << std::endl;

        DWORD consoleSessionId = pfnWTSGetActiveConsoleSessionId();
        if (consoleSessionId == 0xFFFFFFFF)
            return Error{GetLastError(), L"Failed to get active console session ID."};

        HANDLE hUserToken = nullptr;
        if (!pfnWTSQueryUserToken(consoleSessionId, &hUserToken))
            return Error{GetLastError(), L"WTSQueryUserToken failed."};

        ScopeGuard userTokenGuard([&] { CloseHandle(hUserToken); });
        HANDLE hPrimaryToken;
        if (!pfnDuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary,
                                 &hPrimaryToken))
            return Error{GetLastError(), L"Failed to duplicate user token."};

        ScopeGuard primaryTokenGuard([&] { CloseHandle(hPrimaryToken); });

        std::wstring runas_params = L"/trustlevel:0x20000 " + JoinCommandArgs(command);
        std::wstring runas_command_line = L"runas.exe " + runas_params;

        LPVOID lpEnvironment = nullptr;
        if (!pfnCreateEnvironmentBlock(&lpEnvironment, hPrimaryToken, FALSE))
            return Error{GetLastError(), L"CreateEnvironmentBlock failed."};
        ScopeGuard environmentGuard([&] { pfnDestroyEnvironmentBlock(lpEnvironment); });

        STARTUPINFOW si = {.cb = sizeof(si), .lpDesktop = const_cast<LPWSTR>(L"winsta0\\default")};

        PROCESS_INFORMATION pi = {};
        if (!pfnCreateProcessAsUserW(hPrimaryToken, nullptr, runas_command_line.data(), nullptr, nullptr, FALSE,
                                     CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &si, &pi))
            return Error{GetLastError(), L"CreateProcessAsUserW to launch runas.exe failed."};

        std::wcout << L"[SUCCESS] Process launched as user. PID: " << pi.dwProcessId << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return std::nullopt;
    }

    // Administrator
    if (err->code == ERROR_NOT_ALL_ASSIGNED)
    {
        if (IsLUAEnabled())
        {
            std::wcout << L"[+] LUA is enabled, using Safer API..." << std::endl;

            HANDLE hCurrentToken = nullptr;
            if (!pfnOpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hCurrentToken))
                return Error{GetLastError(), L"Failed to open current process token."};

            ScopeGuard currentTokenGuard([&] { CloseHandle(hCurrentToken); });
            SAFER_LEVEL_HANDLE hSaferLevel = nullptr;
            if (!pfnSaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &hSaferLevel,
                                     nullptr))
                return Error{GetLastError(), L"SaferCreateLevel failed."};

            ScopeGuard saferLevelGuard([&] { pfnSaferCloseLevel(hSaferLevel); });
            HANDLE hRestrictedToken = nullptr;
            if (!pfnSaferComputeTokenFromLevel(hSaferLevel, hCurrentToken, &hRestrictedToken, 0, nullptr))
                return Error{GetLastError(), L"SaferComputeTokenFromLevel failed."};

            ScopeGuard restrictedTokenGuard([&] { CloseHandle(hRestrictedToken); });

            STARTUPINFOW si = {.cb = sizeof(si), .lpDesktop = const_cast<LPWSTR>(L"winsta0\\default")};

            PROCESS_INFORMATION pi = {};

            std::wstring commandLine = JoinCommandArgs(command);
            if (!pfnCreateProcessAsUserW(hRestrictedToken, nullptr, commandLine.data(), nullptr, nullptr, FALSE,
                                         CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi))
                return Error{GetLastError(), L"CreateProcessAsUserW failed with restricted token."};

            std::wcout << L"[SUCCESS] Process launched as de-escalated user. PID: " << pi.dwProcessId << std::endl;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return std::nullopt;
        }

        std::wcout << L"[?] LUA is disabled, Using runas directly..." << std::endl;

        std::wstring params = L"/trustlevel:0x20000 " + JoinCommandArgs(command);
        SHELLEXECUTEINFOW sei = {
            .cbSize = sizeof(sei),
            .fMask = SEE_MASK_NOCLOSEPROCESS,
            .lpVerb = L"open",
            .lpFile = L"runas.exe",
            .lpParameters = params.c_str(),
            .nShow = SW_SHOWNORMAL,
        };

        if (!pfnShellExecuteExW(&sei))
            return Error{GetLastError(), L"ShellExecuteExW with runas failed."};

        std::wcout << L"[SUCCESS] Process launched via runas.exe. PID: " << GetProcessId(sei.hProcess) << std::endl;
        CloseHandle(sei.hProcess);
        return std::nullopt;
    }

    err->message = L"[-] Failed to enable SeTcbPrivilege. " + err->message;
    return err;
}

std::optional<Error> RunAsWinDeploy(const wchar_t *appname, const std::vector<std::wstring> &command)
{
    if (!isRunningAsAdmin())
        return Error{ERROR_ACCESS_DENIED, L"[-] Not running as administrator."};

    std::wcout << L"[+] Getting SYSTEM access" << std::endl;
    std::optional<ScopeGuard> impersonationGuard;
    if (auto err = ImpersonateSystem(impersonationGuard))
    {
        err->message = L"Failed to elevate to SYSTEM. " + err->message;
        return err;
    }
    std::wcout << L"[+] Granted. Now writing registry..." << std::endl;

    const auto isUndoCommand = (command.size() == 1 && command[0] == L"undo");

    HKEY hKey;
    LSTATUS status = pfnRegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", 0, KEY_SET_VALUE, &hKey);

    if (status != ERROR_SUCCESS)
    {
        return Error{static_cast<DWORD>(status),
                     L"RegOpenKeyExW for HKLM\\SYSTEM\\Setup failed while running as SYSTEM."};
    }

    ScopeGuard keyGuard([&] { pfnRegCloseKey(hKey); });

    if (isUndoCommand)
    {
        constexpr DWORD setupTypeValue = 0;

        status = pfnRegSetValueExW(hKey, L"SetupType", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&setupTypeValue),
                                   sizeof(setupTypeValue));
        if (status != ERROR_SUCCESS)
        {
            return Error{static_cast<DWORD>(status), L"Failed to reset SetupType to 0."};
        }

        const DWORD cmdLineDataSize = static_cast<DWORD>(wcslen(L"") + 1) * sizeof(wchar_t);
        status = pfnRegSetValueExW(hKey, L"CmdLine", 0, REG_SZ, reinterpret_cast<const BYTE *>(L""), cmdLineDataSize);
        if (status != ERROR_SUCCESS)
        {
            return Error{static_cast<DWORD>(status), L"Failed to clear CmdLine."};
        }

        std::wcout << L"[SUCCESS] WinDeploy command has been undone. System will boot normally." << std::endl;
    }
    else
    {
        const std::wstring fullCommand = JoinCommandArgs(command);
        constexpr DWORD setupTypeValue = 2;

        const DWORD dataSize = static_cast<DWORD>(fullCommand.length() + 1) * sizeof(wchar_t);
        status = pfnRegSetValueExW(hKey, L"CmdLine", 0, REG_SZ, reinterpret_cast<const BYTE *>(fullCommand.c_str()),
                                   dataSize);
        if (status != ERROR_SUCCESS)
        {
            return Error{static_cast<DWORD>(status), L"RegSetValueExW for CmdLine failed while running as SYSTEM."};
        }

        status = pfnRegSetValueExW(hKey, L"SetupType", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&setupTypeValue),
                                   sizeof(setupTypeValue));
        if (status != ERROR_SUCCESS)
        {
            return Error{static_cast<DWORD>(status), L"RegSetValueExW for SetupType failed."};
        }

        std::wcout << L"[SUCCESS] Next boot will run command `" << fullCommand << "` with SYSTEM rights" << std::endl;
        std::wcout << L"--------------------------------------------------------------------------------" << std::endl;
        std::wcout << L"[WARNING]" << std::endl;
        std::wcout << L"The registry change for WinDeploy is persistent and will NOT be cleared automatically."
                   << std::endl;
        std::wcout << L"To ensure your system boots normally in the future and to prevent the command" << std::endl;
        std::wcout << L"from running again, you MUST undo this change after your task is complete." << std::endl;
        std::wcout << L"" << std::endl;
        std::wcout << L"To undo, run this from an administrative command prompt on your desktop:" << std::endl;
        std::wcout << std::format(L"  {} -u windeploy undo", appname) << std::endl;
        std::wcout << L"--------------------------------------------------------------------------------" << std::endl;
        return std::nullopt;
    }

    return std::nullopt;
}
