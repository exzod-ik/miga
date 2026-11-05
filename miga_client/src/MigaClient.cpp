#include "MigaClient.h"
#include "ServiceManager.h"

using namespace std;

CMigaClient::CMigaClient()
    : m_Config(&m_Logger)
    , m_NetworkRuntime(&m_Config, &m_Logger) {
    m_Logger.log(LOGGER_LEVEL_INFO, "client_created");
}

CMigaClient::~CMigaClient() {
    Stop();
    m_Logger.log(LOGGER_LEVEL_INFO, "client_destroyed");
}

bool CMigaClient::Initialize(const string& configPath, bool consoleOutput) {
    m_Logger.log(LOGGER_LEVEL_INFO, "client_initializing");

    if (!m_Config.Load(configPath)) {
        m_Logger.log(LOGGER_LEVEL_ERROR, "config_load_failed");
        return false;
    }

    m_Logger.enable(m_Config.GetLogLevel(), consoleOutput);
    m_Logger.startAsync();

    m_Logger.log(LOGGER_LEVEL_INFO, "client_initialized");
    return true;
}

void CMigaClient::RunConsole() {
    m_Logger.log(LOGGER_LEVEL_INFO, "client_starting mode=console");

    if (!m_NetworkRuntime.Start())
        return;

    m_Logger.log(LOGGER_LEVEL_INFO, "client_running mode=console stop_action=press_enter");
    cin.get();

    Stop();
}

void CMigaClient::RunService() {
    m_Logger.log(LOGGER_LEVEL_INFO, "client_starting mode=service");
    m_StopRequested = false;
    m_ReloadConfigRequested = false;

    if (!m_NetworkRuntime.Start()) {
        m_Logger.log(LOGGER_LEVEL_ERROR, "network_runtime_start_failed");
        return;
    }

    m_Logger.log(LOGGER_LEVEL_INFO, "client_running mode=service stop_action=signal");

    while (!m_StopRequested && m_NetworkRuntime.IsRunning()) {
        if (m_ReloadConfigRequested.exchange(false)) {
            ReloadConfig();
        }
        Sleep(1000);
    }

    Stop();
}

void CMigaClient::Stop() {
    m_StopRequested = true;
    m_Logger.log(LOGGER_LEVEL_INFO, "client_stopping");
    m_NetworkRuntime.Stop();
    m_Logger.log(LOGGER_LEVEL_INFO, "client_stopped");
}

void CMigaClient::RequestStop() {
    m_StopRequested = true;
}

void CMigaClient::RequestReloadConfig() {
    m_ReloadConfigRequested = true;
}

void CMigaClient::ReloadConfig() {
    m_Logger.log(LOGGER_LEVEL_INFO, "config_reloading");
    if (m_NetworkRuntime.ReloadConfig(CONFIG_FILE_NAME))
        m_Logger.log(LOGGER_LEVEL_INFO, "config_reloaded");
    else
        m_Logger.log(LOGGER_LEVEL_ERROR, "config_reload_failed");
}
extern CMigaClient* g_Client;

Logger& CMigaClient::GetLogger() { return m_Logger; }
