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
        cout << "Session log opened to " << filename << endl;
    }
}

void Logger::log(const int level, const string& message) {
    if (level > m_level) return;

    string lvlString;
    switch (level) {
    case LOGGER_LEVEL_ERROR:
        lvlString = "ERROR";
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
        lock_guard<mutex> lock(m_Mutex);
        cout << "[" << getCurrentTime() << "] " << lvlString << ": " << message << endl;
        if (m_LogFile.is_open()) {
            m_LogFile << "[" << getCurrentTime() << "] " << lvlString << ": " << message << endl;
            m_LogFile.flush();
        }
    }
    else {
#ifdef __linux__
        int syslogPriority;
        switch (level) {
        case LOGGER_LEVEL_ERROR: syslogPriority = LOG_ERR; break;
        case LOGGER_LEVEL_INFO:  syslogPriority = LOG_INFO; break;
        case LOGGER_LEVEL_DEBUG: syslogPriority = LOG_DEBUG; break;
        default: syslogPriority = LOG_INFO;
        }
        syslog(syslogPriority, "%s", message.c_str());
#else
        lock_guard<mutex> lock(m_Mutex);
        if (m_LogFile.is_open()) {
            m_LogFile << "[" << getCurrentTime() << "] " << lvlString << ": " << message << endl;
            m_LogFile.flush();
        }
#endif
    }
}