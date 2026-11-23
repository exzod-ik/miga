#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <unordered_set>
#include <functional>
#include "../../Shared/ProtocolV2.h"

using json = nlohmann::json;

struct IPRange {
    uint32_t startIP;
    uint32_t endIP;

    bool contains(uint32_t ip) const;
};

struct IPRule {
    std::vector<IPRange> ipRanges;

    bool matches(uint32_t ip) const;

    void Normalize();

};

struct ServerConfig {
    std::string serverIP;
    std::string profileId;
    uint16_t portStart = 10000;
    uint16_t portEnd = 15000;


    std::vector<std::string> processRules;
    IPRule staticIPRule;
    std::vector<std::string> domainRules;
    std::vector<std::string> wildcardDomainSuffixes;

    bool IsDomainRedirect(std::string domain) const;
    bool SameTransport(const ServerConfig& other) const;
};

class ConfigManager {
private:
    std::vector<ServerConfig> m_Servers;

    Logger* m_Logger;
    std::function<bool(const std::string&, miga::v2::Invitation&)> loadProfile_;
    int m_LogLevel;
    uint16_t m_TunnelMaxMss = 1400;
    std::string m_FullRoutingProfileId;
    bool m_DnsResolverEnabled = false;
    std::string m_ConfigPath;

    bool ParseServer(const json& serverJson, ServerConfig& server);
    bool ParseProcessRules(const json& config, ServerConfig& server);
    bool ParseIPRules(const json& config, ServerConfig& server);
    bool ParseDomainRules(const json& config, ServerConfig& server);

public:
    ConfigManager(Logger* logger, std::function<bool(const std::string&, miga::v2::Invitation&)> loadProfile = {});

    bool Load(const std::string& configPath);

    const std::vector<ServerConfig>& GetServers() const;


    int GetLogLevel() const;
    uint16_t GetTunnelMaxMss() const;
    bool GetDnsResolverEnabled() const { return m_DnsResolverEnabled; }
    const std::string& GetConfigPath() const { return m_ConfigPath; }
    const std::string& GetFullRoutingProfileId() const { return m_FullRoutingProfileId; }
};
