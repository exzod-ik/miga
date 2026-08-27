#include <ws2tcpip.h>
#include "ConfigManager.h"

using namespace std;

bool ServerConfig::IsDomainRedirect(std::string domain) const {
    transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

    for (const auto& rule : domainRules) {
        if (rule == domain) {
            return true;
        }
    }

    for (const auto& suffix : wildcardDomainSuffixes) {
        if (domain.size() > suffix.size() &&
            domain[domain.size() - suffix.size() - 1] == '.' &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        if (domain == suffix) return true;
    }
    return false;
}

ConfigManager::ConfigManager(Logger* logger)
    : m_Logger(logger)
    , m_LogLevel(LOGGER_LEVEL_NONE) {
}

bool ConfigManager::ParseProcessRules(const json& config, ServerConfig& server) {
    if (config.contains("redirect_processes") && config["redirect_processes"].is_array()) {
        for (const auto& procJson : config["redirect_processes"]) {
            string procName = procJson.get<string>();
            transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
            server.processRules.push_back(procName);
            m_Logger->log(LOGGER_LEVEL_INFO, "Process rule: " + procName);
        }
    }
    return true;
}

bool ConfigManager::ParseIPRules(const json& config, ServerConfig& server) {
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

            server.staticIPRule.ipRanges.push_back(range);
        }
    }
    return true;
}

bool ConfigManager::ParseDomainRules(const json& config, ServerConfig& server) {
    if (config.contains("redirect_domains") && config["redirect_domains"].is_array()) {
        for (const auto& domainJson : config["redirect_domains"]) {
            string domain = domainJson.get<std::string>();
            transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

            if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
                string suffix = domain.substr(2); // remove "*."
                server.wildcardDomainSuffixes.push_back(suffix);
                m_Logger->log(LOGGER_LEVEL_INFO, "Wildcard domain rule: *." + suffix);
            }
            else {
                server.domainRules.push_back(domain);
                m_Logger->log(LOGGER_LEVEL_INFO, "Domain rule: " + domain);
            }
        }
    }
    return true;
}

bool ConfigManager::ParseServer(const json& serverJson, ServerConfig& server) {
    if (!serverJson.contains("server_ip")) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "\"server_ip\" is missing for one of the servers");
        return false;
    }

    server.serverIP = serverJson["server_ip"];
    m_Logger->log(LOGGER_LEVEL_INFO, "Server IP: " + server.serverIP);

    if (serverJson.contains("server_ports")) {
        server.portStart = serverJson["server_ports"]["start"];
        server.portEnd = serverJson["server_ports"]["end"];
        m_Logger->log(LOGGER_LEVEL_INFO, "Server ports: " + to_string(server.portStart) + "-" + to_string(server.portEnd));
    }

    if (serverJson.contains("encryption")) {
        server.xorKeyBase64 = serverJson["encryption"]["xor_key"];
        server.swapKeyBase64 = serverJson["encryption"]["swap_key"];
        m_Logger->log(LOGGER_LEVEL_INFO, "Encryption keys loaded");
    }

    if (!ParseProcessRules(serverJson, server)) return false;
    if (!ParseIPRules(serverJson, server)) return false;
    if (!ParseDomainRules(serverJson, server)) return false;

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

        if (!config.contains("servers") || !config["servers"].is_array()) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "\"servers\" array is missing in config");
            return false;
        }

        vector<ServerConfig> newServers;
        newServers.reserve(config["servers"].size());

        for (const auto& serverJson : config["servers"]) {
            ServerConfig server;
            if (!ParseServer(serverJson, server))
                return false;
            newServers.push_back(move(server));
        }

        if (newServers.empty()) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "No servers configured");
            return false;
        }

        if (hotLoad && newServers.size() == m_Servers.size()) {
            for (size_t i = 0; i < newServers.size(); ++i) {
                newServers[i].dynamicIPRule = m_Servers[i].dynamicIPRule;
            }
        }

        m_Servers = move(newServers);

        m_Logger->log(LOGGER_LEVEL_INFO, "Configuration loaded: " +
            to_string(m_Servers.size()) + " server(s)");

        return true;

    }
    catch (const exception& e) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Config parse error: " + string(e.what()));
        return false;
    }
}

const ServerConfig* ConfigManager::FindServerByDomain(const string& domain) const {
    for (const auto& server : m_Servers) {
        if (server.IsDomainRedirect(domain))
            return &server;
    }
    return nullptr;
}

void ConfigManager::AddDynamicIP(size_t serverIndex, uint32_t ip) {
    if (serverIndex >= m_Servers.size())
        return;

    IPRule& rule = m_Servers[serverIndex].dynamicIPRule;
    for (const auto& range : rule.ipRanges) {
        if (range.startIP == ip && range.endIP == ip) {
            return;
        }
    }
    IPRange newRange;
    newRange.startIP = ip;
    newRange.endIP = ip;
    rule.ipRanges.push_back(newRange);
}
