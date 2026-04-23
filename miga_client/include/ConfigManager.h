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

class ConfigManager {
private:
    std::vector<std::string> m_ProcessRules;
    IPRule m_StaticIPRule;
    IPRule m_DynamicIPRule;
    std::vector<std::string> m_DomainRules;
    std::vector<std::string> m_WildcardDomainSuffixes; // *.domain

    Logger* m_Logger;
    int m_LogLevel;

    std::string m_ServerIP;
    uint16_t m_PortStart;
    uint16_t m_PortEnd;

    std::string m_XorKeyBase64;
    std::string m_SwapKeyBase64;

    bool ParseProcessRules(const json& config);
    bool ParseIPRules(const json& config);
    bool ParseDomainRules(const json& config);

public:
    ConfigManager(Logger* logger);

    bool Load(const std::string& configPath, bool hotLoad = false);

    const std::vector<std::string>& GetProcessRules() const { return m_ProcessRules; }
    const IPRule& GetStaticIPRule() const { return m_StaticIPRule; }
    const IPRule& GetDynamicIPRule() const { return m_DynamicIPRule; }
    const std::vector<std::string>& GetDomainRules() const { return m_DomainRules; }
    const std::vector<std::string>& GetWildcardSuffixes() const { return m_WildcardDomainSuffixes; }

    bool IsDomainRedirect(const std::string& domain) const;
    void AddDynamicIP(uint32_t ip);

    const std::string& GetServerIP() const { return m_ServerIP; }
    uint16_t GetPortStart() const { return m_PortStart; }
    uint16_t GetPortEnd() const { return m_PortEnd; }

    const std::string& GetXorKeyBase64() const { return m_XorKeyBase64; }
    const std::string& GetSwapKeyBase64() const { return m_SwapKeyBase64; }

    int GetLogLevel() const { return m_LogLevel; }
};