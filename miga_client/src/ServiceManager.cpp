#include "ServiceManager.h"
#include "MigaClient.h"

#pragma comment(lib , "Advapi32.lib")

using namespace std;

const wchar_t* ServiceManager::SERVICE_NAME = L"MigaClient";
const wchar_t* ServiceManager::DISPLAY_NAME = L"Miga Client - Traffic Redirector";
const wchar_t* ServiceManager::DESCRIPTION = L"Redirects traffic of specified processes and IP addresses";

SERVICE_STATUS ServiceManager::m_Status;
SERVICE_STATUS_HANDLE ServiceManager::m_StatusHandle;

extern CMigaClient* g_Client;

bool ServiceManager::Install() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        cerr << "Failed to open SCM. Error: " << GetLastError() << endl;
        return false;
    }

    WCHAR path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    wstring cmdLine = wstring(path) + L" --service";

    SC_HANDLE service = CreateServiceW(
        scm,
        SERVICE_NAME,
        DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        cmdLine.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);

    if (service) {
        SERVICE_DESCRIPTIONW desc;
        desc.lpDescription = (LPWSTR)DESCRIPTION;
        ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);

        cout << "Service installed successfully" << endl;
        CloseServiceHandle(service);
    }
    else {
        cerr << "Failed to install service. Error: " << GetLastError() << endl;
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(scm);
    return true;
}

bool ServiceManager::Uninstall() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        cerr << "Failed to open SCM" << endl;
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!service) {
        cerr << "Service not found" << endl;
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        cout << "Stopping service..." << endl;
        int waitSeconds = 0;
        while (waitSeconds < 30) {
            if (!QueryServiceStatus(service, &status)) break;
            if (status.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(1000);
            waitSeconds++;
        }
        if (status.dwCurrentState != SERVICE_STOPPED) {
            cerr << "Warning: Service did not stop within 30 seconds" << endl;
        }
        else {
            cout << "Service stopped successfully" << endl;
        }
    }

    if (DeleteService(service)) {
        cout << "Service uninstalled successfully" << endl;
    }
    else {
        cerr << "Failed to delete service. Error: " << GetLastError() << endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool ServiceManager::IsInstalled() {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

void WINAPI ServiceManager::ServiceMain(DWORD argc, LPWSTR* argv) {
    if (!g_Client) return;

    m_StatusHandle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME,
        ServiceCtrlHandler,
        nullptr);

    if (!m_StatusHandle) return;

    WCHAR path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        WCHAR* lastSlash = wcsrchr(path, L'\\');
        if (lastSlash) {
            *lastSlash = L'\0';
            SetCurrentDirectoryW(path);
        }
    }
    m_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_Status.dwCurrentState = SERVICE_START_PENDING;
    m_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    m_Status.dwWin32ExitCode = NO_ERROR;
    m_Status.dwCheckPoint = 1;
    m_Status.dwWaitHint = 30000;
    SetServiceStatus(m_StatusHandle, &m_Status);

    if (!g_Client->Initialize(CONFIG_FILE_NAME, false)) {
        m_Status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(m_StatusHandle, &m_Status);
        return;
    }

    m_Status.dwCurrentState = SERVICE_RUNNING;
    m_Status.dwCheckPoint = 0;
    m_Status.dwWaitHint = 0;
    SetServiceStatus(m_StatusHandle, &m_Status);

    g_Client->RunService();

    m_Status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(m_StatusHandle, &m_Status);
}

DWORD WINAPI ServiceManager::ServiceCtrlHandler(DWORD control, DWORD eventType,
    LPVOID eventData, LPVOID context) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
        if (g_Client) {
            g_Client->RequestStop();
        }
        m_Status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(m_StatusHandle, &m_Status);
        return NO_ERROR;

    case 128:
        if (g_Client) {
            g_Client->RequestReloadConfig();
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(m_StatusHandle, &m_Status);
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

bool ServiceManager::Run() {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { (LPWSTR)SERVICE_NAME, ServiceMain },
        { nullptr, nullptr }
    };
    return StartServiceCtrlDispatcherW(serviceTable) ? true : false;
}