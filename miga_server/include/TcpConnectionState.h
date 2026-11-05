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

    static bool Parse(const uint8_t* packet, size_t size, TcpSegment& result);
};

class TcpConnectionState {
    struct Direction {
        bool finSeen = false;
        bool ackSeen = false;
        uint32_t finEnd = 0;
        uint32_t highestAck = 0;

        bool FinAcknowledged() const;
    };

    Direction m_client;
    Direction m_remote;
    bool m_synSeen = false;
    uint32_t m_initialSequence = 0;
    bool m_reset = false;
    bool m_retired = false;

    static bool AtOrAfter(uint32_t value, uint32_t reference);

public:
    void Observe(const TcpSegment& segment, bool fromClient);

    bool IsClosed() const;

    bool IsNewConnection(const TcpSegment& segment) const;

    void Retire();

    std::chrono::minutes IdleTimeout() const;
};
