#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

struct TcpSegment {
    uint32_t sequence = 0;
    uint32_t acknowledgment = 0;
    uint32_t payloadSize = 0;
    bool syn = false;
    bool fin = false;
    bool ack = false;
    bool rst = false;

    static bool Parse(const uint8_t* packet, size_t size, TcpSegment& result) {
        if (!packet || size < 20 || (packet[0] >> 4) != 4 || packet[9] != 6)
            return false;
        const size_t ipSize = (packet[0] & 15) * 4;
        const size_t totalSize = (static_cast<size_t>(packet[2]) << 8) | packet[3];
        if (ipSize < 20 || totalSize > size || totalSize < ipSize + 20 ||
            (packet[6] & 0x3F) != 0 || packet[7] != 0)
            return false;
        const uint8_t* tcp = packet + ipSize;
        const size_t tcpSize = (tcp[12] >> 4) * 4;
        if (tcpSize < 20 || ipSize + tcpSize > totalSize)
            return false;
        auto read32 = [](const uint8_t* p) {
            return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                (uint32_t(p[2]) << 8) | uint32_t(p[3]);
        };
        result.sequence = read32(tcp + 4);
        result.acknowledgment = read32(tcp + 8);
        result.payloadSize = static_cast<uint32_t>(totalSize - ipSize - tcpSize);
        result.fin = (tcp[13] & 1) != 0;
        result.syn = (tcp[13] & 2) != 0;
        result.rst = (tcp[13] & 4) != 0;
        result.ack = (tcp[13] & 16) != 0;
        return true;
    }
};

class TcpConnectionState {
    struct Direction {
        bool finSeen = false;
        bool ackSeen = false;
        uint32_t finEnd = 0;
        uint32_t highestAck = 0;

        bool FinAcknowledged() const {
            return finSeen && ackSeen && AtOrAfter(highestAck, finEnd);
        }
    };

    Direction m_client;
    Direction m_remote;
    bool m_synSeen = false;
    uint32_t m_initialSequence = 0;
    bool m_reset = false;
    bool m_retired = false;

    static bool AtOrAfter(uint32_t value, uint32_t reference) {
        return uint32_t(value - reference) < 0x80000000u;
    }

public:
    void Observe(const TcpSegment& segment, bool fromClient) {
        auto& sender = fromClient ? m_client : m_remote;
        auto& receiver = fromClient ? m_remote : m_client;
        if (fromClient && segment.syn && !segment.ack && !m_synSeen) {
            m_synSeen = true;
            m_initialSequence = segment.sequence;
        }
        if (segment.rst) {
            m_reset = true;
            return;
        }
        if (segment.ack && (!receiver.ackSeen || AtOrAfter(segment.acknowledgment, receiver.highestAck))) {
            receiver.ackSeen = true;
            receiver.highestAck = segment.acknowledgment;
        }
        if (segment.fin && !sender.finSeen) {
            sender.finSeen = true;
            sender.finEnd = segment.sequence + segment.payloadSize + uint32_t(segment.syn) + 1u;
        }
    }

    bool IsClosed() const {
        return m_client.FinAcknowledged() && m_remote.FinAcknowledged();
    }

    bool IsNewConnection(const TcpSegment& segment) const {
        return segment.syn && !segment.ack && !segment.rst &&
            (m_reset || (m_synSeen && segment.sequence != m_initialSequence &&
                (m_client.finSeen || m_remote.finSeen)));
    }

    void Retire() {
        m_retired = true;
    }

    std::chrono::minutes IdleTimeout() const {
        return std::chrono::minutes(m_retired || m_reset || IsClosed() ||
            (m_client.finSeen && m_remote.finSeen) ? 4 : 124);
    }
};
