#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <unordered_set>

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
    uint16_t portStart = 10000;
    uint16_t portEnd = 15000;

    std::string xorKeyBase64;
    std::string swapKeyBase64;

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
    int m_LogLevel;
    uint16_t m_TunnelMaxMss = 1400;

    bool ParseServer(const json& serverJson, ServerConfig& server);
    bool ParseProcessRules(const json& config, ServerConfig& server);
    bool ParseIPRules(const json& config, ServerConfig& server);
    bool ParseDomainRules(const json& config, ServerConfig& server);

public:
    ConfigManager(Logger* logger);

    bool Load(const std::string& configPath);

    const std::vector<ServerConfig>& GetServers() const;


    int GetLogLevel() const;
    uint16_t GetTunnelMaxMss() const;
};
