#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <random>
#include <vector>

class PortPool {
    std::vector<uint16_t> m_ports;
    std::vector<bool> m_available;
    uint16_t m_first;
    uint16_t m_last;

public:
    PortPool(uint16_t first, uint16_t last);

    template<class Generator>
    std::optional<uint16_t> Acquire(Generator& generator) {
        if (m_ports.empty()) return std::nullopt;
        const size_t index = std::uniform_int_distribution<size_t>(0, m_ports.size() - 1)(generator);
        const uint16_t port = m_ports[index];
        m_ports[index] = m_ports.back();
        m_ports.pop_back();
        m_available[port] = false;
        return port;
    }

    void Release(uint16_t port);
};
