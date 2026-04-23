#include "MigaClient.h"
#include "ServiceManager.h"

using namespace std;

CMigaClient::CMigaClient()
    : m_Config(&m_Logger)
    , m_PacketMonitor(&m_Config, &m_Logger) {
    m_Logger.log(LOGGER_LEVEL_INFO, "CMigaClient instance created");
}

CMigaClient::~CMigaClient() {
    Stop();
    m_Logger.log(LOGGER_LEVEL_INFO, "CMigaClient instance destroyed");
}

bool CMigaClient::Initialize(const string& configPath, bool consoleOutput) {
    m_Logger.log(LOGGER_LEVEL_INFO, "Initializing Miga Client...");

    if (!m_Config.Load(configPath)) {
        m_Logger.log(LOGGER_LEVEL_ERROR, "Failed to load configuration");
        return false;
    }

    m_Logger.enable(m_Config.GetLogLevel(), consoleOutput);

    m_Logger.log(LOGGER_LEVEL_INFO, "Miga Client initialized successfully");
    return true;
}

void CMigaClient::RunConsole() {
    m_Logger.log(LOGGER_LEVEL_INFO, "Starting in CONSOLE mode");

    if (!m_PacketMonitor.Start())
        return;

    m_Logger.log(LOGGER_LEVEL_INFO, "Miga Client is running. Press Enter to stop...");
    cin.get();

    Stop();
}

void CMigaClient::RunService() {
    m_Logger.log(LOGGER_LEVEL_INFO, "Starting in SERVICE mode");
    m_StopRequested = false;
    m_ReloadConfigRequested = false;

    if (!m_PacketMonitor.Start()) {
        m_Logger.log(LOGGER_LEVEL_ERROR, "PacketMonitor failed to start");
        return;
    }

    m_Logger.log(LOGGER_LEVEL_INFO, "Miga Client service is running. Waiting for stop signal...");

    while (!m_StopRequested) {
        if (m_ReloadConfigRequested.exchange(false)) {
            ReloadConfig();
        }
        Sleep(1000);
    }

    Stop();
}

void CMigaClient::Stop() {
    m_StopRequested = true;
    if (m_PacketMonitor.IsRunning()) {
        m_Logger.log(LOGGER_LEVEL_INFO, "Stopping Miga Client...");
        m_PacketMonitor.Stop();
        m_Logger.log(LOGGER_LEVEL_INFO, "Miga Client stopped");
    }
}

void CMigaClient::RequestStop() {
    m_StopRequested = true;
}

void CMigaClient::RequestReloadConfig() {
    m_ReloadConfigRequested = true;
}

void CMigaClient::ReloadConfig() {
    m_Logger.log(LOGGER_LEVEL_INFO, "Reloading configuration...");
    m_PacketMonitor.Stop();

    if (!m_Config.Load(CONFIG_FILE_NAME, true)) {
        m_Logger.log(LOGGER_LEVEL_ERROR, "Failed to reload configuration, keeping old settings");
        if (!m_PacketMonitor.Start()) {
            m_Logger.log(LOGGER_LEVEL_ERROR, "Failed to restart PacketMonitor after config reload failure");
        }
        return;
    }

    m_Logger.enable(m_Config.GetLogLevel(), !m_StopRequested);

    if (!m_PacketMonitor.Start()) {
        m_Logger.log(LOGGER_LEVEL_ERROR, "Failed to restart PacketMonitor after config reload");
    }
    else {
        m_Logger.log(LOGGER_LEVEL_INFO, "Configuration reloaded successfully");
    }
}
extern CMigaClient* g_Client;