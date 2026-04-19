#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>

#ifdef __linux__
#include <syslog.h>
#endif

#define LOGGER_LEVEL_NONE  0
#define LOGGER_LEVEL_ERROR 1
#define LOGGER_LEVEL_INFO  2
#define LOGGER_LEVEL_DEBUG 3

class Logger {
private:
    std::ofstream m_LogFile;
    std::mutex m_Mutex;
    std::string m_LogPath;
    int m_level = LOGGER_LEVEL_NONE;
    bool m_useSyslog = false;
    bool m_consoleOutput = true;

#ifdef __linux__
    bool m_syslogOpened = false;
#endif

    std::string getCurrentTime();

public:
    Logger();
    ~Logger();

    void enable(int level, bool consoleOutput = true);
    void log(const int level, const std::string& message);
    bool isEnabled() const { return m_level > LOGGER_LEVEL_NONE; }
};