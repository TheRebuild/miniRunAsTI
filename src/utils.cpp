#include <chrono>
#include <iostream>

#include "utils.hpp"
#include "version.h"

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)

ScopeGuard::ScopeGuard(std::function<void()> onExit) : onExit_(std::move(onExit))
{
}

ScopeGuard::~ScopeGuard()
{
    if (onExit_)
        onExit_();
}

ScopeGuard::ScopeGuard(ScopeGuard &&other) noexcept : onExit_(std::move(other.onExit_))
{
    other.onExit_ = nullptr;
}

bool isRunningAsAdmin()
{
    auto bIsAdmin = FALSE;
    PSID pAdminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
                                 0, &pAdminGroup))
    {
        if (!CheckTokenMembership(nullptr, pAdminGroup, &bIsAdmin))
            bIsAdmin = FALSE;

        FreeSid(pAdminGroup);
    }

    return bIsAdmin == TRUE;
}

std::wstring GetErrorMessage(const DWORD errorCode)
{
    wchar_t *buffer = nullptr;

    const DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    if (size == 0)
        return L"Failed to retrieve error description.";

    std::wstring message(buffer, size);
    LocalFree(buffer);

    return message;
}

std::wstring JoinCommandArgs(const std::vector<std::wstring> &args)
{
    std::wstring commandLine;

    for (const auto &arg : args)
        commandLine += L"\"" + arg + L"\" ";

    return commandLine;
}

void PrintUsage(const wchar_t *appname)
{
    const std::chrono::year_month_day ymd{std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now())};
    std::wcerr << std::format(L"miniRunAsTi ver. {}\n", WIDEN(miniRunAsTI_VERSION_STRING)) << L"Usage: " << appname
               << L" -u <level> <command> [args...]\n\n"
               << L"Levels:\n"
               << L"  user         - As an current (limited) user.\n"
               << L"  elevated     - As an administrator (shows UAC prompt).\n"
               << L"  system       - As the NT AUTHORITY\\SYSTEM user.\n"
               << L"  ti           - As the TrustedInstaller user.\n\n"
               << L"Examples:\n"
               << L"  " << appname << L" -u elevated cmd.exe\n"
               << L"  " << appname << L" -u system powershell.exe -c whoami\n"
               << L"  " << appname << L" -u ti regedit.exe\n"
               << std::format(
                      L"\n\nSource Code: https://github.com/TheRebuild/miniRunAsTI\n(c) TheRebuild, nixxoq - {}",
                      ymd.year());
}
