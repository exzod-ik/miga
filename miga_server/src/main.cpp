#include "V2Server.h"
#include <iostream>
#include <csignal>
#include <atomic>
#include <string>

constexpr auto ServerVersion =
#include "../ServerVersion.inc"
    ;

std::atomic<bool> g_running(true);

void signalHandler(int) {
    g_running = false;
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::string configPath = "/etc/miga/config.json";
    for (int i = 1; i + 1 < argc; ++i)
        if (std::string(argv[i]) == "--config") configPath = argv[i + 1];
    if (argc > 1 && (std::string(argv[1]) == "client" || std::string(argv[1]) == "settings"))
        return miga::v2::V2Server::Admin(argc, argv, configPath);
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) { ++i; continue; }
        if (arg == "--version") { std::cout << ServerVersion << std::endl; return 0; }
        if (arg == "--help") {
            std::cout << "M.I.G.A. Server (protocol 2)\n"
                "Usage: miga_server [--config PATH] [--version|--help]\n"
                "Administration: miga_server client ... | settings ...\n"
                "Client list: miga_server client list [--page [--after ID]] [--json]\n";
            return 0;
        }
        std::cerr << "argument_invalid" << std::endl;
        return 1;
    }
    miga::v2::V2Server server;
    if (!server.Initialize(configPath)) {
        std::cerr << "server_init_failed protocol=2" << std::endl;
        return 1;
    }
    server.Run(g_running);
    return 0;
}
