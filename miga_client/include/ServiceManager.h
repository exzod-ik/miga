#pragma once

#include <windows.h>
#include <string>

const std::string CONFIG_FILE_NAME = "config.json";

class ServiceManager {
private:
    static const wchar_t* SERVICE_NAME;
    static const wchar_t* DISPLAY_NAME;
    static const wchar_t* DESCRIPTION;

    static SERVICE_STATUS m_Status;
    static SERVICE_STATUS_HANDLE m_StatusHandle;

    static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType,
        LPVOID eventData, LPVOID context);

public:
    static bool Install();
    static bool Uninstall();
    static bool IsInstalled();
    static bool Run();
};