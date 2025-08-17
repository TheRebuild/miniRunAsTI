#include "execution.hpp"
#include "loader.hpp"
#include "pch.hpp"
#include "utils.hpp"

#include <iostream>

int wmain(const int argc, wchar_t *argv[])
{
    if (!LoadApiFunctions())
    {
        return 1;
    }

    if (argc < 4 || (std::wstring(argv[1]) != L"-u" && std::wstring(argv[1]) != L"--user"))
    {
        PrintUsage(argv[0]);
        return 1;
    }

    if (!isRunningAsAdmin())
    {
        std::wcout << L"[?] Administrative rights are required. Attempting to self-elevate..." << std::endl;

        const wchar_t *exePath = argv[0];

        std::vector<std::wstring> args;
        for (auto i = 1; i < argc; ++i)
        {
            args.emplace_back(argv[i]);
        }
        const std::wstring params = JoinCommandArgs(args);

        SHELLEXECUTEINFOW sei = {
            .cbSize = sizeof(sei),
            .fMask = SEE_MASK_NOCLOSEPROCESS,
            .lpVerb = L"runas",
            .lpFile = exePath,
            .lpParameters = params.empty() ? nullptr : params.c_str(),
            .nShow = SW_SHOWNORMAL,
        };

        if (pfnShellExecuteExW(&sei))
        {
            CloseHandle(sei.hProcess);
            return 0;
        }

        const DWORD error = GetLastError();

        std::wcerr << std::format(L"[ERROR] {}", error == ERROR_CANCELLED
                                                     ? L"Elevation was cancelled by the user."
                                                     : L"Failed to self-elevate. Code: " + std::to_wstring(error))
                   << std::endl;
        return static_cast<int>(error);
    }

    const std::wstring level = argv[2];
    std::vector<std::wstring> command;

    for (auto i = 3; i < argc; ++i)
    {
        command.emplace_back(argv[i]);
    }

    std::optional<Error> result;

    if (level == L"user")
    {
        result = RunAsNormalUser(command);
    }
    else if (level == L"elevated")
    {
        result = RunElevated(command);
    }
    else if (level == L"system")
    {
        result = RunAsSystem(command);
    }
    else if (level == L"ti")
    {
        result = RunAsTi(command);
    }
    else if (level == L"windeploy")
    {
        if (command.empty())
        {
            std::wcerr << L"Error: windeploy level requires a command to execute.\n";
            PrintUsage(argv[0]);
            return 1;
        }
        result = RunAsWinDeploy(argv[0], command);
    }
    else
    {
        std::wcerr << L"Error: unknown privilege level '" << level << L"'\n";
        PrintUsage(argv[0]);
        return 1;
    }

    if (result)
    {
        std::wcerr << L"[ERROR] " << result->message << L" (Code: " << result->code << L")\n"
                   << L"        System Message: " << GetErrorMessage(result->code) << std::endl;
        return static_cast<int>(result->code);
    }

    return 0;
}
