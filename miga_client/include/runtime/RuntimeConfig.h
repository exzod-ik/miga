#pragma once

#include "RuntimeTypes.h"
#include "../ConfigManager.h"
#include "../TunnelRouteCache.h"
#include "Encryption.h"
#include <cctype>

namespace miga::runtime {
struct Transport {
    size_t id = 0;
    uint32_t destination = 0;
    uint16_t localPort = 0;
    SOCKET reservation = INVALID_SOCKET;
    Encryption transform;
    ~Transport();
};
struct Server {
    ServerConfig rules;
    std::shared_ptr<Transport> transport;
};
struct Configuration {
    uint64_t version = 0;
    uint16_t mss = 1400;
    int logLevel = LOGGER_LEVEL_WARNING;
    std::vector<Server> servers;
    std::unordered_map<std::string, size_t> processes;
    std::unordered_map<size_t, size_t> transports;
    std::unordered_map<uint16_t, size_t> inboundPorts;
    bool hasDomainRules = false;
    void Index();
    static std::string Lower(std::string value);
    const Server* Process(const std::string& name) const;
    const Server* Domain(const std::string& name) const;
    const Server* ById(size_t id) const;
};
bool Local(uint32_t ip);
uint16_t Read16(const uint8_t* data);
uint32_t Read32(const uint8_t* data);
void Write16(uint8_t* data, uint16_t value);
void Write32(uint8_t* data, uint32_t value);
bool ClampMss(uint8_t* data, const PacketView& view, uint16_t maximum);
}
