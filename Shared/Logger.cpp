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

string Logger::getCurrentTime() {
    auto now = chrono::system_clock::now();
    auto in_time_t = chrono::system_clock::to_time_t(now);
    struct tm bt;

#ifdef __linux__
    localtime_r(&in_time_t, &bt);
#else
    localtime_s(&bt, &in_time_t);
#endif

    stringstream ss;
    ss << put_time(&bt, "%Y-%m-%d %H:%M:%S");
    return ss.str();
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

void Logger::log(const int level, const string& message) {
    if (!isEnabled(level)) return;
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
        const auto timestamp = getCurrentTime();
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
            const auto timestamp = getCurrentTime();
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
        "receive_buffer_wait", "receive_event_queue_wait", "batch_age_after_receive", "batch_processing",
        "pending_pid_direct_fallback", "tunnel_packet_over_1500_bytes_mtu_risk",
        "incomplete_fragment_sets_expired", "client_packet_processing", "internet_packet_processing", "routing_drop"
    };
    for (size_t i = 0; i < m_warningCounts.size(); ++i) {
        const auto count = m_warningCounts[i].exchange(0, std::memory_order_relaxed);
        const auto value = m_warningValues[i].exchange(0, std::memory_order_relaxed);
        if (count == 0 && value == 0) continue;
        logLazy(LOGGER_LEVEL_WARNING, [&] {
            return std::string(names[i]) + " count=" + std::to_string(count) +
                " total_value=" + std::to_string(value) + " value_unit=" + (i == static_cast<size_t>(NetworkWarning::LargeTunnelPacket) ? "bytes" :
                    (i == static_cast<size_t>(NetworkWarning::PendingPidFallback) ||
                     i == static_cast<size_t>(NetworkWarning::IncompleteFragments) ||
                     i == static_cast<size_t>(NetworkWarning::RoutingDrop)) ? "none" : "ms") +
                " window=approximate";
        });
    }
}
