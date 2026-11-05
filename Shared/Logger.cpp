#include "Logger.h"
#include <sstream>
#include <iomanip>

#ifdef __linux__
#include <time.h>
#include <unistd.h>
#include <limits.h>
#else
#include <windows.h>
#endif

using namespace std;

Logger::Logger() : m_level(LOGGER_LEVEL_INFO) {
}

Logger::~Logger() {
#ifndef __linux__
    stopAsync();
#endif
    if (m_LogFile.is_open()) {
        m_LogFile.close();
    }
#ifdef __linux__
    if (m_syslogOpened) {
        closelog();
        m_syslogOpened = false;
    }
#endif
}

void Logger::enable(int level, bool consoleOutput) {
    lock_guard<mutex> lock(m_Mutex);
    m_level = level;
    m_LogPath = ".";
    m_consoleOutput = consoleOutput;
#ifdef __linux__
    char buffer[PATH_MAX];
    if (getcwd(buffer, sizeof(buffer)) != nullptr) {
        m_LogPath = buffer;
    }
#else
    char buffer[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, buffer)) {
        m_LogPath = buffer;
    }
#endif

    string filename = m_LogPath + "/session.log";

    if (!m_consoleOutput) {
#ifdef __linux__
        openlog("miga_server", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        m_syslogOpened = true;
        m_useSyslog = true;
#else
        if (m_LogFile.is_open()) {
            m_LogFile.close();
        }
        m_LogFile.open(filename, ios::trunc);
#endif
    }
    else {
        m_useSyslog = false;

        if (m_LogFile.is_open()) {
            m_LogFile.close();
        }
        m_LogFile.open(filename, ios::trunc);
        cout << "log_opened path=" << LogValue(filename) << endl;
    }
}

void Logger::log(const int level, const string& message, chrono::system_clock::time_point time) {
    if (!isEnabled(level)) return;
#ifndef __linux__
    {
        unique_lock lock(m_QueueMutex);
        if (m_Async) {
            if (m_Closing || m_Queue.size() >= 4096 || message.size() > 4 * 1024 * 1024 - m_QueueBytes) {
                ++m_Dropped;
                return;
            }
            m_Queue.push_back({level, message, time});
            m_QueueBytes += message.size();
            lock.unlock();
            m_QueueChanged.notify_one();
            return;
        }
    }
#endif
    write(level, message, time);
}

#ifndef __linux__
void Logger::startAsync() {
    lock_guard lock(m_QueueMutex);
    if (m_Async) return;
    m_Closing = false;
    m_Writer = thread(&Logger::writerLoop, this);
    m_Async = true;
}

void Logger::stopAsync() {
    {
        lock_guard lock(m_QueueMutex);
        if (!m_Async) return;
        m_Closing = true;
    }
    m_QueueChanged.notify_all();
    if (m_Writer.joinable()) m_Writer.join();
    lock_guard lock(m_QueueMutex);
    m_Async = false;
    m_Closing = false;
}

void Logger::writerLoop() {
    for (;;) {
        deque<LogEntry> batch;
        uint64_t dropped;
        {
            unique_lock lock(m_QueueMutex);
            m_QueueChanged.wait(lock, [&] { return m_Closing || !m_Queue.empty(); });
            if (m_Closing && m_Queue.empty() && !m_Dropped) return;
            batch.swap(m_Queue);
            m_QueueBytes = 0;
            dropped = m_Dropped;
            m_Dropped = 0;
        }
        if (dropped) write(LOGGER_LEVEL_WARNING, "log_queue_overflow dropped=" + to_string(dropped), chrono::system_clock::now());
        for (const auto& item : batch) write(item.level, item.message, item.time);
    }
}
#endif

void Logger::write(int level, const string& message, chrono::system_clock::time_point time) {
    lock_guard<mutex> lock(m_Mutex);

    string lvlString;
    switch (level) {
    case LOGGER_LEVEL_ERROR:
        lvlString = "ERROR";
        break;
    case LOGGER_LEVEL_WARNING:
        lvlString = "WARNING";
        break;
    case LOGGER_LEVEL_INFO:
        lvlString = "INFO";
        break;
    case LOGGER_LEVEL_DEBUG:
        lvlString = "DEBUG";
        break;
    default:
        lvlString = "UNKNOWN";
    }

    if (m_consoleOutput) {
        const auto timestamp = FormatLogTime(time);
        cout << "[" << timestamp << "] " << lvlString << ": " << message << endl;
        if (m_LogFile.is_open()) {
            m_LogFile << "[" << timestamp << "] " << lvlString << ": " << message << endl;
        }
    }
    else {
#ifdef __linux__
        int syslogPriority;
        switch (level) {
        case LOGGER_LEVEL_ERROR: syslogPriority = LOG_ERR; break;
        case LOGGER_LEVEL_WARNING: syslogPriority = LOG_WARNING; break;
        case LOGGER_LEVEL_INFO:  syslogPriority = LOG_INFO; break;
        case LOGGER_LEVEL_DEBUG: syslogPriority = LOG_DEBUG; break;
        default: syslogPriority = LOG_INFO;
        }
        syslog(syslogPriority, "%s", message.c_str());
#else
        if (m_LogFile.is_open()) {
            const auto timestamp = FormatLogTime(time);
            m_LogFile << "[" << timestamp << "] " << lvlString << ": " << message << endl;
        }
#endif
    }
}

void Logger::recordWarning(NetworkWarning event, uint64_t value, uint64_t count) {
    if (!isEnabled(LOGGER_LEVEL_WARNING)) return;
    const auto index = static_cast<size_t>(event);
    if (index >= m_warningCounts.size()) return;
    m_warningValues[index].fetch_add(value, std::memory_order_relaxed);
    m_warningCounts[index].fetch_add(count, std::memory_order_relaxed);
}

void Logger::recordDelay(NetworkWarning event, std::chrono::steady_clock::time_point started) {
    if (!isEnabled(LOGGER_LEVEL_WARNING)) return;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    if (elapsed >= 100) recordWarning(event, static_cast<uint64_t>(elapsed));
}

void Logger::flushWarnings() {
    static constexpr const char* names[] = {
        "batch_processing", "pending_pid_direct_fallback", "routing_drop",
        "client_packet_processing", "internet_packet_processing", "large_tunnel_packet"
    };
    static constexpr const char* units[] = { "ms", "none", "none", "ms", "ms", "bytes" };
    static_assert(std::size(names) == static_cast<size_t>(NetworkWarning::Count));
    static_assert(std::size(units) == std::size(names));
    for (size_t i = 0; i < m_warningCounts.size(); ++i) {
        const auto count = m_warningCounts[i].exchange(0, std::memory_order_relaxed);
        const auto value = m_warningValues[i].exchange(0, std::memory_order_relaxed);
        if (count == 0 && value == 0) continue;
        logLazy(LOGGER_LEVEL_WARNING, [&] {
            return std::string(names[i]) + " count=" + std::to_string(count) +
                " total_value=" + std::to_string(value) + " value_unit=" + units[i] +
                " window=approximate";
        });
    }
}

void Logger::setLevel(int level) { m_level.store(level, std::memory_order_relaxed); }

bool Logger::isEnabled(int level) const {
    return level > LOGGER_LEVEL_NONE && level <= m_level.load(std::memory_order_relaxed);
}
