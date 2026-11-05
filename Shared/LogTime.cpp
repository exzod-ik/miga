#include "LogTime.h"

std::string FormatLogTime(std::chrono::system_clock::time_point time) {
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(time);
    const auto value = std::chrono::system_clock::to_time_t(seconds);
    std::tm local{};
#ifdef __linux__
    localtime_r(&value, &local);
#else
    localtime_s(&local, &value);
#endif
    std::ostringstream out;
    out << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3)
        << std::chrono::duration_cast<std::chrono::milliseconds>(time - seconds).count();
    return out.str();
}
