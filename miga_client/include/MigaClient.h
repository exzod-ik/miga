#pragma once

#include "Logger.h"
#include "ConfigManager.h"
#include "PacketMonitor.h"

class CMigaClient {
private:
    Logger m_Logger;
    ConfigManager m_Config;
    PacketMonitor m_PacketMonitor;
    std::atomic<bool> m_StopRequested;
    std::atomic<bool> m_ReloadConfigRequested;

public:
    CMigaClient();
    ~CMigaClient();

    bool Initialize(const std::string& configPath, bool consoleOutput);
    void RunConsole();
    void RunService();
    void Stop();

    void RequestStop();
    void RequestReloadConfig();
    void ReloadConfig();

    Logger& GetLogger() { return m_Logger; }
};

extern CMigaClient* g_Client;