#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <initializer_list>

struct SocketTuple {
    uint8_t protocol = 0;
    uint32_t localIp = 0;
    uint16_t localPort = 0;
    uint32_t remoteIp = 0;
    uint16_t remotePort = 0;
};

struct TcpPacketState {
    uint32_t sequence = 0;
    uint32_t acknowledgment = 0;
    uint8_t flags = 0;
};

bool ReadSocketPacket(const uint8_t* packet, size_t length, SocketTuple& tuple, bool& syn,
    TcpPacketState* tcp = nullptr);

struct FlowKey {
    uint8_t proto;
    uint32_t srcIp;
    uint16_t srcPort;
    uint32_t dstIp;
    uint16_t dstPort;

    bool operator==(const FlowKey& o) const;
    static FlowKey From(const SocketTuple& tuple);
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const;
};

struct FlowRoute {
    enum class Kind { Direct, Tunnel, Unavailable };
    Kind kind = Kind::Direct;
    size_t serverId = 0;
    uint32_t translatedIp = 0;
};
