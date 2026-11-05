#include "runtime/RuntimeConfig.h"

namespace miga::runtime {
Transport::~Transport() { if (reservation != INVALID_SOCKET) closesocket(reservation); }

void Configuration::Index() {
    processes.clear(); transports.clear(); inboundPorts.clear();
    hasDomainRules = false;
    for (size_t i = 0; i < servers.size(); ++i) {
        hasDomainRules |= !servers[i].rules.domainRules.empty() || !servers[i].rules.wildcardDomainSuffixes.empty();
        transports.emplace(servers[i].transport->id, i);
        inboundPorts.emplace(servers[i].transport->localPort, i);
        for (const auto& process : servers[i].rules.processRules) processes.emplace(Lower(process), i);
    }
}

std::string Configuration::Lower(std::string value) {
    for (auto& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

const Server* Configuration::Process(const std::string& name) const {
    auto found = processes.find(Lower(name));
    return found == processes.end() ? nullptr : &servers[found->second];
}

const Server* Configuration::Domain(const std::string& name) const {
    for (const auto& server : servers) if (server.rules.IsDomainRedirect(name)) return &server;
    return nullptr;
}

const Server* Configuration::ById(size_t id) const {
    auto found = transports.find(id);
    return found == transports.end() ? nullptr : &servers[found->second];
}

bool Local(uint32_t ip) {
    return (ip >> 24) == 127 || (ip >> 24) == 10 || (ip & 0xfff00000) == 0xac100000 ||
        (ip >> 16) == 0xc0a8 || (ip >> 16) == 0xa9fe || (ip >> 28) == 14 || ip == 0xffffffff;
}

uint16_t Read16(const uint8_t* data) { return static_cast<uint16_t>((uint16_t(data[0]) << 8) | data[1]); }

uint32_t Read32(const uint8_t* data) {
    return (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
}

void Write16(uint8_t* data, uint16_t value) { data[0] = uint8_t(value >> 8); data[1] = uint8_t(value); }

void Write32(uint8_t* data, uint32_t value) {
    data[0] = uint8_t(value >> 24); data[1] = uint8_t(value >> 16); data[2] = uint8_t(value >> 8); data[3] = uint8_t(value);
}

bool ClampMss(uint8_t* data, const PacketView& view, uint16_t maximum) {
    if (view.tuple.protocol != 6 || !view.syn) return false;
    const auto end = view.header + (size_t(data[view.header + 12] >> 4) * 4);
    for (size_t offset = view.header + 20; offset < end;) {
        const auto type = data[offset];
        if (!type) break;
        if (type == 1) { ++offset; continue; }
        if (offset + 2 > end) break;
        const auto size = data[offset + 1];
        if (size < 2 || offset + size > end) break;
        if (type == 2 && size == 4) {
            if (Read16(data + offset + 2) <= maximum) return false;
            Write16(data + offset + 2, maximum);
            return true;
        }
        offset += size;
    }
    return false;
}

}
