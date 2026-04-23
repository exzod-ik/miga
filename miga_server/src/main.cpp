#include "ServerCore.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <csignal>
#include <atomic>
#include <sys/stat.h>
#include <errno.h>
#include <cstring>

#define VERSION "1.1.0"

using namespace std;
using json = nlohmann::json;

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

static ServerConfig GetDefaultConfig() {
    ServerConfig def;
    def.xorKeyBase64 = Encryption::GenerateXorKeyBase64();
    def.swapKeyBase64 = Encryption::GenerateSwapKeyBase64();
    return def;
}

static bool UpdateConfigFile(const string& configPath, bool generateKeys) {
    json currentJson;
    ifstream ifs(configPath);
    if (ifs.is_open()) {
        try {
            ifs >> currentJson;
        }
        catch (const exception& e) {
            cerr << "Error parsing existing config: " << e.what() << endl;
            return false;
        }
    }
    else {
        cout << "No existing config file, will create a new one." << endl;
    }

    ServerConfig defaultConfig = GetDefaultConfig();

    if (currentJson.contains("client_ports")) {
        if (currentJson["client_ports"].contains("start"))
            defaultConfig.client_port_start = currentJson["client_ports"]["start"];
        if (currentJson["client_ports"].contains("end"))
            defaultConfig.client_port_end = currentJson["client_ports"]["end"];
    }
    if (!generateKeys) {
        if (currentJson.contains("encryption")) {
            if (currentJson["encryption"].contains("xor_key"))
                defaultConfig.xorKeyBase64 = currentJson["encryption"]["xor_key"];
            if (currentJson["encryption"].contains("swap_key"))
                defaultConfig.swapKeyBase64 = currentJson["encryption"]["swap_key"];
        }
    }
    if (currentJson.contains("interface"))
        defaultConfig.interface = currentJson["interface"];
    if (currentJson.contains("log_level")) {
        string levelStr = currentJson["log_level"];
        if (levelStr == "error") defaultConfig.log_level = LOGGER_LEVEL_ERROR;
        else if (levelStr == "info") defaultConfig.log_level = LOGGER_LEVEL_INFO;
        else if (levelStr == "debug") defaultConfig.log_level = LOGGER_LEVEL_DEBUG;
        else defaultConfig.log_level = LOGGER_LEVEL_NONE;
    }
    if (currentJson.contains("dns_server")) {
        string dns = currentJson["dns_server"];
        defaultConfig.dns_server = inet_addr(dns.c_str());
    }

    json newConfig;
    newConfig["log_level"] =
        (defaultConfig.log_level == LOGGER_LEVEL_ERROR) ? "error" :
        (defaultConfig.log_level == LOGGER_LEVEL_INFO) ? "info" :
        (defaultConfig.log_level == LOGGER_LEVEL_DEBUG) ? "debug" : "none";

    newConfig["client_ports"]["start"] = defaultConfig.client_port_start;
    newConfig["client_ports"]["end"] = defaultConfig.client_port_end;
    newConfig["encryption"]["xor_key"] = defaultConfig.xorKeyBase64;
    newConfig["encryption"]["swap_key"] = defaultConfig.swapKeyBase64;
    newConfig["interface"] = defaultConfig.interface;
    struct in_addr addr;
    addr.s_addr = defaultConfig.dns_server;
    char* ip_str = inet_ntoa(addr);
    string dns_string(ip_str);
    newConfig["dns_server"] = dns_string;

    size_t lastSlash = configPath.find_last_of('/');
    if (lastSlash != string::npos) {
        string dir = configPath.substr(0, lastSlash);
        if (!CreateDirectory(dir)) {
            cerr << "Failed to create directory: " << dir << endl;
            return false;
        }
    }

    ofstream ofs(configPath);
    if (!ofs.is_open()) {
        cerr << "Failed to open config file for writing: " << configPath << endl;
        return false;
    }
    ofs << newConfig.dump(4, ' ', false, json::error_handler_t::ignore);
    cout << "Configuration file updated at: " << configPath << endl;
    return true;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    string configPath = "/etc/miga/config.json";

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (string(argv[i]) == "--generate-keys") {
            if (!UpdateConfigFile(configPath, true)) return 1;
            return 0;
        }
        if (arg == "--update") {
            if (!UpdateConfigFile(configPath, false)) return 1;
            return 0;
        }
        if (arg == "--version") {
            cout << VERSION << endl;
            return 0;
        }
        if (arg == "--help") {
            cout << "M.I.G.A. Server\n"
                << "Usage:\n"
                << "  ./miga_server [options]\n\n"
                << "Options:\n"
                << "  --generate-keys     Generate new keys\n"
                << "  --update            Update config file to current version (preserve existing values)\n"
                << "  --version           Show version\n"
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