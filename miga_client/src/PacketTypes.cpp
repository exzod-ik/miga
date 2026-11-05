#include "PacketTypes.h"

bool ReadSocketPacket(const uint8_t* packet, size_t length, SocketTuple& tuple, bool& syn,
    TcpPacketState* tcp) {
    if (!packet || length < 20 || (packet[0] >> 4) != 4) return false;
    const size_t ihl = (packet[0] & 15) * 4;
    const size_t total = (size_t(packet[2]) << 8) | packet[3];
    if (ihl < 20 || total > length || total < ihl || (packet[6] & 31) != 0 || packet[7] != 0) return false;
    const auto protocol = packet[9];
    if (protocol != 6 && protocol != 17) return false;
    if (total - ihl < (protocol == 6 ? 20u : 8u)) return false;
    if (protocol == 6) {
        const size_t tcpLength = (packet[ihl + 12] >> 4) * 4;
        if (tcpLength < 20 || tcpLength > total - ihl) return false;
    }
    if (protocol == 17) {
        const size_t udpLength = (size_t(packet[ihl + 4]) << 8) | packet[ihl + 5];
        if (udpLength < 8 || udpLength > total - ihl) return false;
    }
    const auto ip = [&](size_t offset) {
        return (uint32_t(packet[offset]) << 24) | (uint32_t(packet[offset + 1]) << 16) |
            (uint32_t(packet[offset + 2]) << 8) | packet[offset + 3];
    };
    const auto port = [&](size_t offset) {
        return static_cast<uint16_t>((unsigned(packet[offset]) << 8) | packet[offset + 1]);
    };
    tuple = { protocol, ip(12), port(ihl), ip(16), port(ihl + 2) };
    syn = protocol == 6 && (packet[ihl + 13] & 2) != 0;
    if (tcp) {
        *tcp = {};
        if (protocol == 6) *tcp = { ip(ihl + 4), ip(ihl + 8), packet[ihl + 13] };
    }
    return true;
}

bool FlowKey::operator==(const FlowKey& o) const {
    return proto == o.proto && srcIp == o.srcIp && srcPort == o.srcPort &&
        dstIp == o.dstIp && dstPort == o.dstPort;
}

FlowKey FlowKey::From(const SocketTuple& tuple) {
    return { tuple.protocol, tuple.localIp, tuple.localPort, tuple.remoteIp, tuple.remotePort };
}

size_t FlowKeyHash::operator()(const FlowKey& key) const {
    size_t hash = key.proto;
    for (auto value : { key.srcIp, uint32_t(key.srcPort), key.dstIp, uint32_t(key.dstPort) })
        hash ^= std::hash<uint32_t>()(value) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    return hash;
}
