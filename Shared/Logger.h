#pragma once

#include <string>
#include "LogFormat.h"
#include "LogTime.h"
#include <array>
#include <cstdint>
#include <atomic>
#include <fstream>
#include <mutex>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#ifndef __linux__
#include <condition_variable>
#include <deque>
#include <thread>
#endif

#ifdef __linux__
#include <syslog.h>
#endif

#define LOGGER_LEVEL_NONE  0
#define LOGGER_LEVEL_ERROR 1
#define LOGGER_LEVEL_WARNING 2
#define LOGGER_LEVEL_INFO  3
#define LOGGER_LEVEL_DEBUG 4

enum class NetworkWarning {
    BatchProcessing, PendingPidFallback, RoutingDrop, ClientPacketProcessing, InternetPacketProcessing, LargeTunnelPacket, Count
};

class Logger {
private:
    std::ofstream m_LogFile;
    std::mutex m_Mutex;
    std::string m_LogPath;
    std::atomic<int> m_level{LOGGER_LEVEL_INFO};
    bool m_useSyslog = false;
    bool m_consoleOutput = true;

#ifdef __linux__
    bool m_syslogOpened = false;
#endif

    std::array<std::atomic<uint64_t>, static_cast<size_t>(NetworkWarning::Count)> m_warningCounts{};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(NetworkWarning::Count)> m_warningValues{};
    struct LogEntry { int level; std::string message; std::chrono::system_clock::time_point time; };
    void write(int level, const std::string& message, std::chrono::system_clock::time_point time);
#ifndef __linux__
    std::mutex m_QueueMutex;
    std::condition_variable m_QueueChanged;
    std::deque<LogEntry> m_Queue;
    std::thread m_Writer;
    bool m_Async = false;
    bool m_Closing = false;
    size_t m_QueueBytes = 0;
    uint64_t m_Dropped = 0;
    void writerLoop();
#endif

public:
    Logger();
    ~Logger();

    void enable(int level, bool consoleOutput = true);
    void setLevel(int level);
    void log(const int level, const std::string& message,
        std::chrono::system_clock::time_point time = std::chrono::system_clock::now());
#ifndef __linux__
    void startAsync();
    void stopAsync();
#endif
    void recordWarning(NetworkWarning event, uint64_t value = 0, uint64_t count = 1);
    void flushWarnings();
    void recordDelay(NetworkWarning event, std::chrono::steady_clock::time_point started);
    bool isEnabled(int level = LOGGER_LEVEL_ERROR) const;

    template<class Factory>
    void logLazy(int level, Factory&& message) {
        if (isEnabled(level)) log(level, message());
    }
};
