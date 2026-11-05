#pragma once

#include <string>
#include <string_view>
#include <cstring>

std::string LogValue(std::string_view value);

std::string LogErrno(int code);
