#include <ws2tcpip.h>
#include "ConfigManager.h"

using namespace std;

ConfigManager::ConfigManager(Logger* logger)
    : m_Logger(logger)
    , m_PortStart(10000)
    , m_PortEnd(15000)
    , m_LogLevel(LOGGER_LEVEL_NONE) {
}

bool ConfigManager::ParseProcessRules(const json& config) {
    if (config.contains("redirect_processes") && config["redirect_processes"].is_array()) {
        for (const auto& procJson : config["redirect_processes"]) {
            string procName = procJson.get<string>();
            transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
            m_ProcessRules.push_back(procName);
            m_Logger->log(LOGGER_LEVEL_INFO, "Process rule: " + procName);
        }
    }
    return true;
}

bool ConfigManager::ParseIPRules(const json& config) {
    if (config.contains("redirect_ips") && config["redirect_ips"].is_array()) {
        for (const auto& ipJson : config["redirect_ips"]) {
            string ipStr = ipJson.get<string>();
            size_t dashPos = ipStr.find('-');

            IPRange range;
            if (dashPos != string::npos) {
                string startStr = ipStr.substr(0, dashPos);
                string endStr = ipStr.substr(dashPos + 1);
                struct in_addr addr;
                if (inet_pton(AF_INET, startStr.c_str(), &addr) == 1) {
                    range.startIP = ntohl(addr.s_addr);
                }
                else {
                    m_Logger->log(LOGGER_LEVEL_ERROR, "IP address " + startStr + " is incorect. ");
                    return false;
                }
                if (inet_pton(AF_INET, endStr.c_str(), &addr) == 1) {
                    range.endIP = ntohl(addr.s_addr);
                }
                else {
                    m_Logger->log(LOGGER_LEVEL_ERROR, "IP address " + endStr + " is incorect. ");
                    return false;
                }
                m_Logger->log(LOGGER_LEVEL_INFO, "IP range: " + startStr + " - " + endStr);
            }
            else {
                struct in_addr addr;
                if (inet_pton(AF_INET, ipStr.c_str(), &addr) == 1) {
                    range.startIP = ntohl(addr.s_addr);
                }
                else {
                    m_Logger->log(LOGGER_LEVEL_ERROR, "IP address " + ipStr + " is incorect. ");
                    return false;
                }
                range.endIP = range.startIP;
                m_Logger->log(LOGGER_LEVEL_INFO, "IP rule: " + ipStr);
            }

            m_StaticIPRule.ipRanges.push_back(range);
        }
    }
    return true;
}

bool ConfigManager::ParseDomainRules(const json& config) {
    if (config.contains("redirect_domains") && config["redirect_domains"].is_array()) {
        for (const auto& domainJson : config["redirect_domains"]) {
            string domain = domainJson.get<std::string>();
            transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

            if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
                string suffix = domain.substr(2); // remove "*."
                m_WildcardDomainSuffixes.push_back(suffix);
                m_Logger->log(LOGGER_LEVEL_INFO, "Wildcard domain rule: *." + suffix);
            }
            else {
                m_DomainRules.push_back(domain);
                m_Logger->log(LOGGER_LEVEL_INFO, "Domain rule: " + domain);
            }
        }
    }
    return true;
}

bool ConfigManager::Load(const string& configPath, bool hotLoad) {
    m_Logger->log(LOGGER_LEVEL_INFO, "Loading configuration from: " + configPath);

    try {
        ifstream configFile(configPath);
        if (!configFile.is_open()) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to open config file");
            return false;
        }

        json config;
        configFile >> config;

        if (config.contains("server_ip")) {
            m_ServerIP = config["server_ip"];
            m_Logger->log(LOGGER_LEVEL_INFO, "Server IP: " + m_ServerIP);
        }

        if (config.contains("server_ports")) {
            m_PortStart = config["server_ports"]["start"];
            m_PortEnd = config["server_ports"]["end"];
            m_Logger->log(LOGGER_LEVEL_INFO, "Server ports: " + to_string(m_PortStart) + "-" + to_string(m_PortEnd));
        }

        if (config.contains("encryption")) {
            m_XorKeyBase64 = config["encryption"]["xor_key"];
            m_SwapKeyBase64 = config["encryption"]["swap_key"];
            m_Logger->log(LOGGER_LEVEL_INFO, "Encryption keys loaded");
        }

        if (config.contains("log_level")) {
            string levelStr = config["log_level"];
            if (levelStr == "error") {
                m_LogLevel = LOGGER_LEVEL_ERROR;
            }
            else if (levelStr == "info") {
                m_LogLevel = LOGGER_LEVEL_INFO;
            }
            else if (levelStr == "debug") {
                m_LogLevel = LOGGER_LEVEL_DEBUG;
            }
            else {
                m_LogLevel = LOGGER_LEVEL_NONE;
            }
            m_Logger->log(LOGGER_LEVEL_INFO, "Log level: " + levelStr);
        }
        else {
            m_LogLevel = LOGGER_LEVEL_NONE;
        }

        m_ProcessRules.clear();
        m_StaticIPRule = IPRule();
        if (!hotLoad)
            m_DynamicIPRule = IPRule();

        ParseProcessRules(config);
        ParseIPRules(config);
        ParseDomainRules(config);

        m_Logger->log(LOGGER_LEVEL_INFO, "Configuration loaded: " +
            to_string(m_ProcessRules.size()) + " processes, " +
            to_string(m_StaticIPRule.ipRanges.size()) + " static IP ranges, " +
            to_string(m_DomainRules.size()) + " domains");

        return true;

    }
    catch (const exception& e) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Config parse error: " + string(e.what()));
        return false;
    }
}


bool ConfigManager::IsDomainRedirect(const std::string& domain) const {
    string lowerDomain = domain;
    transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(), ::tolower);

    for (const auto& rule : m_DomainRules) {
        if (rule == lowerDomain) {
            return true;
        }
    }

    for (const auto& suffix : m_WildcardDomainSuffixes) {
        if (lowerDomain.size() > suffix.size() &&
            lowerDomain[lowerDomain.size() - suffix.size() - 1] == '.' &&
            lowerDomain.compare(lowerDomain.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        if (lowerDomain == suffix) return true;
    }
    return false;
}

void ConfigManager::AddDynamicIP(uint32_t ip) {
    for (const auto& range : m_DynamicIPRule.ipRanges) {
        if (range.startIP == ip && range.endIP == ip) {
            return;
        }
    }
    IPRange newRange;
    newRange.startIP = ip;
    newRange.endIP = ip;
    m_DynamicIPRule.ipRanges.push_back(newRange);
}