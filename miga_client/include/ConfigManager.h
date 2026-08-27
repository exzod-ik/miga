#pragma once

#include "NetworkStructures.h"
#include "Logger.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct IPRange {
    uint32_t startIP;
    uint32_t endIP;

    bool contains(uint32_t ip) const {
        return (ip >= startIP && ip <= endIP);
    }
};

struct IPRule {
    std::vector<IPRange> ipRanges;

    bool matches(uint32_t ip) const {
        for (const auto& range : ipRanges) {
            if (range.contains(ip)) return true;
        }
        return false;
    }

    bool isEmpty() const {
        return ipRanges.empty();
    }
};

struct ServerConfig {
    std::string serverIP;
    uint16_t portStart = 10000;
    uint16_t portEnd = 15000;

    std::string xorKeyBase64;
    std::string swapKeyBase64;

    std::vector<std::string> processRules;
    IPRule staticIPRule;
    IPRule dynamicIPRule;
    std::vector<std::string> domainRules;
    std::vector<std::string> wildcardDomainSuffixes;

    bool IsDomainRedirect(std::string domain) const;
};

class ConfigManager {
private:
    std::vector<ServerConfig> m_Servers;

    Logger* m_Logger;
    int m_LogLevel;

    bool ParseServer(const json& serverJson, ServerConfig& server);
    bool ParseProcessRules(const json& config, ServerConfig& server);
    bool ParseIPRules(const json& config, ServerConfig& server);
    bool ParseDomainRules(const json& config, ServerConfig& server);

public:
    ConfigManager(Logger* logger);

    bool Load(const std::string& configPath, bool hotLoad = false);

    const std::vector<ServerConfig>& GetServers() const { return m_Servers; }

    const ServerConfig* FindServerByDomain(const std::string& domain) const;
    void AddDynamicIP(size_t serverIndex, uint32_t ip);

    int GetLogLevel() const { return m_LogLevel; }
};
