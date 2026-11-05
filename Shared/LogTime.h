#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

std::string FormatLogTime(std::chrono::system_clock::time_point time);
