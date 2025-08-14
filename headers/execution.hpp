#pragma once
#include "utils.hpp"

std::optional<Error> RunElevated(const std::vector<std::wstring> &command);
std::optional<Error> RunAsSystem(const std::vector<std::wstring> &command);
std::optional<Error> RunAsTi(const std::vector<std::wstring> &command);
std::optional<Error> RunAsNormalUser(const std::vector<std::wstring> &command);
