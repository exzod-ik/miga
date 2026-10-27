#include <ws2tcpip.h>
#include "ConfigManager.h"
#include <cstdlib>
#include <filesystem>
#include <random>
#include <thread>

void Require(bool value, const char* message) {
    if (!value) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

void TestRanges() {
    std::mt19937 rng(42);
    for (int run = 0; run < 100; ++run) {
        IPRule rule;
        for (int i = 0; i < 100; ++i)
            rule.ipRanges.push_back({static_cast<uint32_t>(rng() % 1000), static_cast<uint32_t>(rng() % 1000)});
        auto reference = rule.ipRanges;
        rule.Normalize();
        for (uint32_t ip = 0; ip < 1100; ++ip) {
            bool expected = false;
            for (const auto& range : reference) expected |= range.contains(ip);
            Require(rule.matches(ip) == expected, "normalized range lookup differs from linear lookup");
        }
    }
    IPRule edges;
    edges.ipRanges = {{0xFFFFFFFFu, 0xFFFFFFFFu}, {0, 0}, {0xFFFFFFFEu, 0xFFFFFFFEu}, {9, 3}};
    edges.Normalize();
    Require(edges.matches(0) && edges.matches(0xFFFFFFFFu) && edges.matches(0xFFFFFFFEu), "range boundary overflow");
    Require(!edges.matches(1) && !edges.matches(5) && edges.ipRanges.size() == 2, "range gaps and invalid ranges");
    IPRule empty;
    empty.Normalize();
    Require(!empty.matches(0), "empty ranges");
}

int main() {
    TestRanges();
    const std::string path = "Build/tests/routing-index-fixture.json";
    auto writeFixture = [&](bool revised) {
        std::ofstream file(path);
        file << R"({"log_level":"warning","servers":[{"server_ip":"192.0.2.1","redirect_processes":[")"
            << (revised ? "new.exe" : "App.EXE")
            << R"("],"redirect_ips":["203.0.113.20-203.0.113.30","203.0.113.1-203.0.113.22"]},{"server_ip":"192.0.2.2","redirect_processes":["app.exe","other.exe"],"redirect_ips":["203.0.113.10-203.0.113.40"]}]})";
    };
    Logger logger;
    ConfigManager config(&logger);
    writeFixture(false);
    Require(config.Load(path), "load fixture");
    Require(config.GetLogLevel() == LOGGER_LEVEL_WARNING, "warning configuration level");
    auto first = &config.GetServers()[0];
    auto second = &config.GetServers()[1];
    Require(config.FindServerByProcess("aPP.eXe") == first, "process case and first-server priority");
    Require(config.FindServerByProcess("OTHER.EXE") == second, "second process rule");
    Require(config.FindServerByProcess("missing.exe") == nullptr, "unknown process");
    Require(first->staticIPRule.ipRanges.size() == 1 && first->staticIPRule.matches(0xCB00710Au), "loaded static range normalization");
    config.AddDynamicIP(1, 123);
    Require(config.FindServerByDynamicIP(123) == second, "dynamic lookup");
    config.AddDynamicIP(0, 123);
    config.AddDynamicIP(1, 123);
    Require(config.FindServerByDynamicIP(123) == first && first->dynamicIPs.size() == 1, "dynamic first-server priority independent of arrival order");
    std::thread writer([&] { for (uint32_t i = 1000; i < 11000; ++i) config.AddDynamicIP(1, i); });
    std::thread reader([&] { for (uint32_t i = 1000; i < 11000; ++i) config.FindServerByDynamicIP(i); });
    writer.join();
    reader.join();
    for (uint32_t i = 1000; i < 11000; ++i)
        Require(config.FindServerByDynamicIP(i) == second, "dynamic index after concurrent inserts");
    writeFixture(true);
    Require(config.Load(path, true), "hot reload");
    Require(config.FindServerByProcess("app.exe") == &config.GetServers()[1], "process index rebuilt on reload");
    Require(config.FindServerByProcess("NEW.EXE") == &config.GetServers()[0], "new process indexed");
    Require(config.FindServerByDynamicIP(123) == &config.GetServers()[0], "hot reload retains existing dynamic behavior");
    {
        std::ofstream file(path);
        file << R"({"log_level":"warning","servers":[]})";
    }
    Require(!config.Load(path, true), "invalid reload rejected");
    Require(config.FindServerByProcess("new.exe") == &config.GetServers()[0], "failed reload preserves index");
    writeFixture(false);
    Require(config.Load(path, false) && config.FindServerByDynamicIP(123) == nullptr, "cold load clears dynamic index");
    std::filesystem::remove(path);
    std::cout << "Routing index tests passed\n";
}
