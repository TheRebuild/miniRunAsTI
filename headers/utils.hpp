#pragma once

#include "pch.hpp"

class ScopeGuard
{
  public:
    explicit ScopeGuard(std::function<void()> onExit);
    ~ScopeGuard();
    ScopeGuard(const ScopeGuard &) = delete;
    ScopeGuard &operator=(const ScopeGuard &) = delete;
    ScopeGuard(ScopeGuard &&other) noexcept;
    ScopeGuard &operator=(ScopeGuard &&other) = delete;

  private:
    std::function<void()> onExit_;
};

struct Error
{
    DWORD code;
    std::wstring message;
};

bool isRunningAsAdmin();
std::wstring GetErrorMessage(DWORD errorCode);
std::wstring JoinCommandArgs(const std::vector<std::wstring> &args);
void PrintUsage(const wchar_t *appname);
