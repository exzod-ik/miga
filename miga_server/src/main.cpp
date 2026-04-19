#include "ServerCore.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <csignal>
#include <atomic>
#include <sys/stat.h>
#include <errno.h>
#include <cstring>

using namespace std;

atomic<bool> g_running(true);

void signalHandler(int) {
    cout << "Shutting down..." << endl;
    g_running = false;
}

static bool CreateDirectory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    if (mkdir(path.c_str(), 0755) == 0) {
        return true;
    }
    return errno == EEXIST;
}

bool GenerateConfigFile(const std::string& path) {
    using json = nlohmann::json;

    string xorKey = Encryption::GenerateXorKeyBase64();
    string swapKey = Encryption::GenerateSwapKeyBase64();

    json config;
    config["log_level"] = "none";
    config["client_ports"]["start"] = 10000;
    config["client_ports"]["end"] = 15000;
    config["encryption"]["xor_key"] = xorKey;
    config["encryption"]["swap_key"] = swapKey;

    size_t lastSlash = path.find_last_of('/');
    if (lastSlash != std::string::npos) {
        string dir = path.substr(0, lastSlash);
        if (!CreateDirectory(dir)) {
            cerr << "Failed to create directory: " << dir << endl;
            return false;
        }
    }

    ofstream ofs(path);
    if (!ofs.is_open()) {
        cerr << "Failed to open config file for writing: " << path << endl;
        return false;
    }
    ofs << config.dump(4, ' ', false, json::error_handler_t::ignore);
    cout << "Configuration file generated at: " << path << endl;
    cout << "XOR key (base64): " << xorKey << endl;
    cout << "Swap key (base64): " << swapKey << endl;
    return true;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    string configPath = "/etc/miga/config.json";

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (string(argv[i]) == "--generate-keys") {
            string configPath = "/etc/miga/config.json";
            if (!GenerateConfigFile(configPath)) {
                return 1;
            }
            return 0;
        }
        if (arg == "--help") {
            cout << "M.I.G.A. Server\n"
                << "Usage:\n"
                << "  ./miga_server [options]\n\n"
                << "Options:\n"
                << "  --generate-keys     Generate new keys\n"
                << "  --help              Show this help\n";
            return 0;
        }
    }

    ServerCore server;

    if (!server.Initialize(configPath)) {
        cerr << "Failed to initialize server" << endl;
        return 1;
    }

    server.Start();
    cout << "Server started. Press Ctrl+C to stop..." << endl;

    while (g_running) {
        pause();
    }

    server.Stop();
    cout << "Server stopped" << endl;

    return 0;
}