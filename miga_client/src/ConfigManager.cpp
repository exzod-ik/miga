#include <ws2tcpip.h>
#include "ConfigManager.h"
#include "ProtocolProfiles.h"

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

ConfigManager::ConfigManager(Logger* logger, std::function<bool(const std::string&, miga::v2::Invitation&)> loadProfile)
    : m_Logger(logger)
    , loadProfile_(loadProfile ? std::move(loadProfile) : ProtocolProfiles::Load)
    , m_LogLevel(LOGGER_LEVEL_NONE) {
}

bool ConfigManager::ParseProcessRules(const json& config, ServerConfig& server) {
    if (config.contains("redirect_processes") && config["redirect_processes"].is_array()) {
        for (const auto& procJson : config["redirect_processes"]) {
            string procName = procJson.get<string>();
            transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
            server.processRules.push_back(procName);
            m_Logger->log(LOGGER_LEVEL_INFO, "process_rule_loaded process=" + LogValue(procName));
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
                    m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid field=redirect_ips reason=invalid_ipv4 value=" + LogValue(startStr));
                    return false;
                }
                if (inet_pton(AF_INET, endStr.c_str(), &addr) == 1) {
                    range.endIP = ntohl(addr.s_addr);
                }
                else {
                    m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid field=redirect_ips reason=invalid_ipv4 value=" + LogValue(endStr));
                    return false;
                }
                m_Logger->log(LOGGER_LEVEL_INFO, "ip_range_loaded start=" + LogValue(startStr) + " end=" + LogValue(endStr));
            }
            else {
                struct in_addr addr;
                if (inet_pton(AF_INET, ipStr.c_str(), &addr) == 1) {
                    range.startIP = ntohl(addr.s_addr);
                }
                else {
                    m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid field=redirect_ips reason=invalid_ipv4 value=" + LogValue(ipStr));
                    return false;
                }
                range.endIP = range.startIP;
                m_Logger->log(LOGGER_LEVEL_INFO, "ip_rule_loaded ip=" + LogValue(ipStr));
            }

            server.staticIPRule.ipRanges.push_back(range);
        }
    }
    server.staticIPRule.Normalize();
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
                m_Logger->log(LOGGER_LEVEL_INFO, "domain_rule_loaded kind=wildcard suffix=" + LogValue(suffix));
            }
            else {
                server.domainRules.push_back(domain);
                m_Logger->log(LOGGER_LEVEL_INFO, "domain_rule_loaded kind=exact domain=" + LogValue(domain));
            }
        }
    }
    return true;
}

bool ConfigManager::ParseServer(const json& serverJson, ServerConfig& server) {
    if (serverJson.value("protocol", 0) != 2 || serverJson.contains("encryption") || serverJson.contains("server_ports")) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid reason=unsupported_protocol expected=2");
        return false;
    }
    if (serverJson.contains("requires_invitation") && !serverJson["requires_invitation"].is_boolean()) return false;
    if (serverJson.value("requires_invitation", false)) {
        if (serverJson.contains("profile_id") && serverJson["profile_id"] != "") return false;
        return ParseProcessRules(serverJson, server) && ParseIPRules(serverJson, server) && ParseDomainRules(serverJson, server);
    }
    server.profileId = serverJson.value("profile_id", "");
    miga::v2::Invitation invitation;
    if (!miga::v2::Initialize() || !loadProfile_(server.profileId, invitation)) return false;
    server.serverIP = invitation.host;
    server.portStart = invitation.portStart;
    server.portEnd = invitation.portEnd;
    return ParseProcessRules(serverJson, server) && ParseIPRules(serverJson, server) && ParseDomainRules(serverJson, server);
}

bool ConfigManager::Load(const string& configPath) {
    m_Logger->log(LOGGER_LEVEL_INFO, "config_loading path=" + LogValue(configPath));

    int logLevel = LOGGER_LEVEL_NONE;
    try {
        ifstream configFile(configPath);
        if (!configFile.is_open()) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "config_open_failed");
            return false;
        }

        json config;
        configFile >> config;

        const auto dnsResolver = config.find("dns_resolver_enabled");
        if (dnsResolver != config.end() && !dnsResolver->is_boolean()) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid field=dns_resolver_enabled expected=boolean");
            return false;
        }
        const bool dnsResolverEnabled = dnsResolver == config.end() || dnsResolver->get<bool>();
        auto loadedPath = configPath;

        uint16_t tunnelMaxMss = 1400;
        if (config.contains("tunnel_max_mss")) {
            const auto& value = config["tunnel_max_mss"];
            if (!value.is_number_integer() || value < 1 || value > 65535) {
                m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid field=tunnel_max_mss expected=integer min=1 max=65535");
                return false;
            }
            tunnelMaxMss = value.get<uint16_t>();
        }

        if (config.contains("log_level")) {
            string levelStr = config["log_level"];
            if (levelStr == "error") {
                logLevel = LOGGER_LEVEL_ERROR;
            }
            else if (levelStr == "warning") {
                logLevel = LOGGER_LEVEL_WARNING;
            }
            else if (levelStr == "info") {
                logLevel = LOGGER_LEVEL_INFO;
            }
            else if (levelStr == "debug") {
                logLevel = LOGGER_LEVEL_DEBUG;
            }
            else {
                logLevel = LOGGER_LEVEL_NONE;
            }
            m_Logger->log(LOGGER_LEVEL_INFO, "log_level_selected level=" + LogValue(levelStr));
        }
        else {
            logLevel = LOGGER_LEVEL_NONE;
        }

        if (!config.contains("servers") || !config["servers"].is_array()) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid reason=missing_array field=servers");
            return false;
        }

        vector<ServerConfig> newServers;
        newServers.reserve(config["servers"].size());

        bool invitationsPending = false;
        for (const auto& serverJson : config["servers"]) {
            const auto enabled = serverJson.find("enabled");
            if (enabled != serverJson.end() && !enabled->is_boolean()) {
                m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid field=enabled expected=boolean");
                return false;
            }
            if (enabled != serverJson.end() && !enabled->get<bool>()) continue;
            ServerConfig server;
            if (!ParseServer(serverJson, server))
                return false;
            invitationsPending = invitationsPending || serverJson.value("requires_invitation", false);
            newServers.push_back(move(server));
        }

        if (config.value("protocol", 0) != 2) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid reason=unsupported_protocol expected=2");
            return false;
        }

        const auto routingMode = config.value("routing_mode", std::string("split"));
        auto fullProfileId = config.value("full_routing_profile_id", std::string());
        if ((routingMode != "split" && routingMode != "full") ||
            (routingMode == "split" && !fullProfileId.empty()) ||
            (routingMode == "full" && (fullProfileId.empty() || invitationsPending ||
                std::count_if(newServers.begin(), newServers.end(), [&](const auto& server) {
                    return server.profileId == fullProfileId;
                }) != 1))) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "config_invalid reason=invalid_routing_mode_or_profile");
            return false;
        }

        if (invitationsPending) {
            newServers.clear();
            m_Logger->log(LOGGER_LEVEL_WARNING, "config_pending_invitation forwarding=disabled");
        }
        m_LogLevel = logLevel;
        m_Servers = move(newServers);
        m_TunnelMaxMss = tunnelMaxMss;
        m_FullRoutingProfileId = std::move(fullProfileId);
        m_DnsResolverEnabled = dnsResolverEnabled && m_FullRoutingProfileId.empty() && !m_Servers.empty();
        m_ConfigPath = std::move(loadedPath);

        m_Logger->log(LOGGER_LEVEL_INFO, "config_loaded server_count=" +
            to_string(m_Servers.size()));

        return true;

    }
    catch (const exception& e) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "config_parse_failed error=" + LogValue(e.what()));
        return false;
    }
}

bool IPRange::contains(uint32_t ip) const {
    return (ip >= startIP && ip <= endIP);
}

bool IPRule::matches(uint32_t ip) const {
    auto it = std::upper_bound(ipRanges.begin(), ipRanges.end(), ip,
        [](uint32_t value, const IPRange& range) { return value < range.startIP; });
    return it != ipRanges.begin() && std::prev(it)->contains(ip);
}

void IPRule::Normalize() {
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

bool ServerConfig::SameTransport(const ServerConfig& other) const {
    return profileId == other.profileId && serverIP == other.serverIP && portStart == other.portStart && portEnd == other.portEnd;
}

const std::vector<ServerConfig>& ConfigManager::GetServers() const { return m_Servers; }

int ConfigManager::GetLogLevel() const { return m_LogLevel; }

uint16_t ConfigManager::GetTunnelMaxMss() const { return m_TunnelMaxMss; }
