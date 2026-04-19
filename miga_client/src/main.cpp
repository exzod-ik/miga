#include "MigaClient.h"
#include "ServiceManager.h"

using namespace std;

CMigaClient* g_Client = nullptr;

void PrintHelp() {
    cout << "Miga Client - traffic redirector\n"
        << "Usage:\n"
        << "  miga_client.exe [options]\n\n"
        << "Options:\n"
        << "  --service           Run as Windows service\n"
        << "  --log               Enable logging\n"
        << "  --config <file>     Configuration file (default: config.json)\n"
        << "  --install           Install as Windows service\n"
        << "  --uninstall         Uninstall Windows service\n"
        << "  --help              Show this help\n";
}

int main(int argc, char* argv[]) {
    bool serviceMode = false;
    string configPath = CONFIG_FILE_NAME;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];

        if (arg == "--service") {
            serviceMode = true;
        }
        else if (arg == "--config" && i + 1 < argc) {
            configPath = argv[++i];
        }
        else if (arg == "--install") {
            return ServiceManager::Install() ? 0 : 1;
        }
        else if (arg == "--uninstall") {
            return ServiceManager::Uninstall() ? 0 : 1;
        }
        else if (arg == "--help") {
            PrintHelp();
            return 0;
        }
        else {
            cerr << "Unknown option: " << arg << endl;
            PrintHelp();
            return 1;
        }
    }

    CMigaClient client;
    g_Client = &client;

    if (serviceMode) {
        client.GetLogger().log(LOGGER_LEVEL_INFO, "Starting in service mode");
        return ServiceManager::Run() ? 0 : 1;
    }
    else {
        if (!client.Initialize(configPath, !serviceMode)) {
            cerr << "Failed to initialize application" << endl;
            return 1;
        }
        client.GetLogger().log(LOGGER_LEVEL_INFO, "Starting in console mode");
        client.RunConsole();
    }

    return 0;
}