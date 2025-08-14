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
