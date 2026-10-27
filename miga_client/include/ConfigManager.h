#pragma once

#include "NetworkStructures.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <functional>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

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
        auto it = std::upper_bound(ipRanges.begin(), ipRanges.end(), ip,
            [](uint32_t value, const IPRange& range) { return value < range.startIP; });
        return it != ipRanges.begin() && std::prev(it)->contains(ip);
    }

    void Normalize() {
        std::sort(ipRanges.begin(), ipRanges.end(), [](const IPRange& a, const IPRange& b) {
            return a.startIP < b.startIP;
        });
        size_t count = 0;
        for (const auto range : ipRanges) {
            if (range.startIP > range.endIP) continue;
            if (count && uint64_t(range.startIP) <= uint64_t(ipRanges[count - 1].endIP) + 1) {
                ipRanges[count - 1].endIP = (std::max)(ipRanges[count - 1].endIP, range.endIP);
            }
            else {
                ipRanges[count++] = range;
            }
        }
        ipRanges.resize(count);
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
    std::unordered_set<uint32_t> dynamicIPs;
    std::vector<std::string> domainRules;
    std::vector<std::string> wildcardDomainSuffixes;

    bool IsDomainRedirect(std::string domain) const;
    bool SameTransport(const ServerConfig& other) const {
        return serverIP == other.serverIP && portStart == other.portStart && portEnd == other.portEnd &&
            xorKeyBase64 == other.xorKeyBase64 && swapKeyBase64 == other.swapKeyBase64;
    }
};

class ConfigManager {
private:
    std::vector<ServerConfig> m_Servers;
    std::unordered_map<std::string, size_t> m_ProcessIndex;
    std::unordered_map<uint32_t, size_t> m_DynamicIPIndex;
    mutable std::shared_mutex m_DynamicIPMutex;

    Logger* m_Logger;
    int m_LogLevel;
    uint16_t m_TunnelMaxMss = 1400;

    bool ParseServer(const json& serverJson, ServerConfig& server);
    bool ParseProcessRules(const json& config, ServerConfig& server);
    bool ParseIPRules(const json& config, ServerConfig& server);
    bool ParseDomainRules(const json& config, ServerConfig& server);

public:
    ConfigManager(Logger* logger);

    bool Load(const std::string& configPath, bool hotLoad = false,
        const std::function<bool(const std::vector<ServerConfig>&)>& prepare = {});

    const std::vector<ServerConfig>& GetServers() const { return m_Servers; }

    const ServerConfig* FindServerByDomain(const std::string& domain) const;
    const ServerConfig* FindServerByProcess(const std::string& processName) const;
    const ServerConfig* FindServerByDynamicIP(uint32_t ip) const;
    void AddDynamicIP(size_t serverIndex, uint32_t ip);

    int GetLogLevel() const { return m_LogLevel; }
    uint16_t GetTunnelMaxMss() const { return m_TunnelMaxMss; }
};
