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
        file << R"({"protocol":2,"log_level":"warning","servers":[{"protocol":2,"profile_id":"first","redirect_processes":[")"
            << (revised ? "new.exe" : "App.EXE")
            << R"("],"redirect_ips":["203.0.113.20-203.0.113.30","203.0.113.1-203.0.113.22"]},{"protocol":2,"profile_id":"second","redirect_processes":["app.exe","other.exe"],"redirect_ips":["203.0.113.10-203.0.113.40"]}]})";
    };
    Logger logger;
    std::vector<std::string> loadedProfiles;
    ConfigManager config(&logger, [&](const std::string& id, miga::v2::Invitation& invitation) {
        loadedProfiles.push_back(id);
        invitation.host = id == "first" ? "192.0.2.1" : "192.0.2.2";
        return id == "first" || id == "second";
    });
    writeFixture(false);
    Require(config.Load(path), "load fixture");
    Require(config.GetLogLevel() == LOGGER_LEVEL_WARNING, "warning configuration level");
    const auto& first = config.GetServers()[0];
    Require(first.processRules[0] == "app.exe", "process names normalized while loading");
    Require(first.staticIPRule.ipRanges.size() == 1 && first.staticIPRule.matches(0xCB00710Au), "loaded static range normalization");
    writeFixture(true);
    Require(config.Load(path), "replacement configuration loads");
    Require(config.GetServers()[0].processRules[0] == "new.exe", "new process rules replace old rules");
    {
        std::ofstream file(path);
        file << R"({"log_level":"warning","servers":[]})";
    }
    Require(!config.Load(path), "invalid configuration rejected");
    Require(config.GetServers()[0].processRules[0] == "new.exe", "failed load preserves previous configuration");
    writeFixture(false);
    Require(config.Load(path) && config.GetServers()[0].processRules[0] == "app.exe", "configuration can be loaded again");
    for (const auto* invalid : {
        R"({"protocol":1,"servers":[]})",
        R"({"protocol":2,"servers":[{"protocol":1,"profile_id":"first"}]})",
        R"({"protocol":2,"servers":[{"protocol":2,"profile_id":"first","server_ports":{}}]})",
        R"({"protocol":2,"servers":[{"protocol":2,"profile_id":"first","encryption":{}}]})"}) {
        { std::ofstream file(path); file << invalid; }
        Require(!config.Load(path), "obsolete configuration accepted");
        Require(config.GetServers()[0].processRules[0] == "app.exe", "rejected load changed active rules");
    }
    { std::ofstream file(path); file << R"({"protocol":2,"servers":[{"protocol":2,"requires_invitation":true,"redirect_processes":["old.exe"]},{"protocol":2,"profile_id":"first"}]})"; }
    Require(config.Load(path) && config.GetServers().empty(), "pending invitation disables forwarding for all servers");
    for (const auto* invalid : {
        R"({"protocol":2,"servers":[{"protocol":2,"requires_invitation":true,"profile_id":"first"}]})",
        R"({"protocol":2,"servers":[{"protocol":2,"requires_invitation":"true"}]})",
        R"({"protocol":2,"servers":[{"protocol":2,"requires_invitation":false}]})"}) {
        { std::ofstream file(path); file << invalid; }
        Require(!config.Load(path) && config.GetServers().empty(), "invalid pending state rejected");
    }
    writeFixture(false);
    Require(config.Load(path) && config.GetServers().size() == 2, "profiles restore forwarding after migration");
    Require(config.GetDnsResolverEnabled(), "active servers default to the split resolver");
    loadedProfiles.clear();
    { std::ofstream file(path); file << R"({"protocol":2,"servers":[{"protocol":2,"enabled":false,"profile_id":"unavailable","redirect_processes":["app.exe"]},{"protocol":2,"enabled":false,"requires_invitation":true},{"protocol":2,"enabled":true,"profile_id":"second"}]})"; }
    Require(config.Load(path) && config.GetServers().size() == 1 && config.GetServers()[0].profileId == "second" &&
        config.GetDnsResolverEnabled() && loadedProfiles == std::vector<std::string>{"second"}, "inactive profiles and pending invitations do not participate");
    loadedProfiles.clear();
    { std::ofstream file(path); file << R"({"protocol":2,"routing_mode":"full","full_routing_profile_id":"second","servers":[{"protocol":2,"enabled":false,"profile_id":"second"},{"protocol":2,"enabled":false,"requires_invitation":true},{"protocol":2,"profile_id":"second"}]})"; }
    Require(config.Load(path) && config.GetFullRoutingProfileId() == "second" && loadedProfiles == std::vector<std::string>{"second"},
        "full mode selects only the active profile and disregards inactive pending invitations");
    { std::ofstream file(path); file << R"({"protocol":2,"routing_mode":"full","full_routing_profile_id":"second","servers":[{"protocol":2,"profile_id":"first"},{"protocol":2,"profile_id":"second"}]})"; }
    Require(config.Load(path) && config.GetFullRoutingProfileId() == "second", "full mode selects the requested profile");
    Require(!config.GetDnsResolverEnabled(), "full mode disables the default resolver");
    { std::ofstream file(path); file << R"({"protocol":2,"routing_mode":"full","full_routing_profile_id":"second","dns_resolver_enabled":true,"servers":[{"protocol":2,"profile_id":"first"},{"protocol":2,"profile_id":"second"}]})"; }
    Require(config.Load(path) && !config.GetDnsResolverEnabled(), "full mode disables the explicitly enabled resolver");
    for (const auto* invalid : {
        R"({"protocol":2,"routing_mode":"unknown","servers":[]})",
        R"({"protocol":2,"routing_mode":"full","servers":[{"protocol":2,"profile_id":"first"}]})",
        R"({"protocol":2,"routing_mode":"full","full_routing_profile_id":"second","servers":[{"protocol":2,"profile_id":"first"}]})",
        R"({"protocol":2,"routing_mode":"full","full_routing_profile_id":"second","servers":[{"protocol":2,"enabled":false,"profile_id":"second"}]})",
        R"({"protocol":2,"routing_mode":"full","full_routing_profile_id":"first","servers":[{"protocol":2,"profile_id":"first"},{"protocol":2,"profile_id":"first"}]})",
        R"({"protocol":2,"routing_mode":"split","full_routing_profile_id":"first","servers":[{"protocol":2,"profile_id":"first"}]})"}) {
        { std::ofstream file(path); file << invalid; }
        Require(!config.Load(path) && config.GetFullRoutingProfileId() == "second", "invalid mode preserves active selection");
    }
    { std::ofstream file(path); file << R"({"protocol":2,"servers":[]})"; }
    Require(config.Load(path) && config.GetServers().empty() && config.GetFullRoutingProfileId().empty(),
        "empty v2 bootstrap configuration defaults to split");
    Require(!config.GetDnsResolverEnabled(), "empty configuration has no synthetic resolver");
    loadedProfiles.clear();
    { std::ofstream file(path); file << R"({"protocol":2,"dns_resolver_enabled":true,"servers":[{"protocol":2,"enabled":false,"profile_id":"unavailable"}]})"; }
    Require(config.Load(path) && config.GetServers().empty() && !config.GetDnsResolverEnabled() && loadedProfiles.empty(),
        "all disabled servers leave no routing or synthetic DNS exits");
    { std::ofstream file(path); file << R"({"protocol":2,"dns_resolver_enabled":true,"servers":[{"protocol":2,"profile_id":"first"}]})"; }
    Require(config.Load(path) && config.GetDnsResolverEnabled(), "enable resolver");
    { std::ofstream file(path); file << R"({"protocol":2,"servers":[{"protocol":2,"enabled":"false","profile_id":"second"}]})"; }
    Require(!config.Load(path) && config.GetServers()[0].profileId == "first", "invalid enabled flag preserves previous configuration");
    { std::ofstream file(path); file << R"({"protocol":2,"dns_resolver_enabled":"false","servers":[]})"; }
    Require(!config.Load(path) && config.GetDnsResolverEnabled(), "invalid resolver option preserves previous configuration");
    { std::ofstream file(path); file << R"({"protocol":2,"dns_resolver_enabled":false,"servers":[{"protocol":2,"profile_id":"first"}]})"; }
    Require(config.Load(path) && !config.GetDnsResolverEnabled(), "disable resolver");
    std::filesystem::remove(path);
    std::cout << "Routing index tests passed\n";
}
