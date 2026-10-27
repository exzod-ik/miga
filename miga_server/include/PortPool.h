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
    PortPool(uint16_t first, uint16_t last)
        : m_available(65536, false), m_first(first), m_last(last) {
        if (first > last) return;
        m_ports.reserve(uint32_t(last) - first + 1);
        for (uint32_t port = first; port <= last; ++port) {
            m_ports.push_back(static_cast<uint16_t>(port));
            m_available[port] = true;
        }
    }

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

    void Release(uint16_t port) {
        if (port < m_first || port > m_last || m_available[port]) return;
        m_ports.push_back(port);
        m_available[port] = true;
    }
};
