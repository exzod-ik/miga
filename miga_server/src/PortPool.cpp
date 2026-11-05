#include "PortPool.h"

PortPool::PortPool(uint16_t first, uint16_t last)
    : m_available(65536, false), m_first(first), m_last(last) {
    if (first > last) return;
    m_ports.reserve(uint32_t(last) - first + 1);
    for (uint32_t port = first; port <= last; ++port) {
        m_ports.push_back(static_cast<uint16_t>(port));
        m_available[port] = true;
    }
}

void PortPool::Release(uint16_t port) {
    if (port < m_first || port > m_last || m_available[port]) return;
    m_ports.push_back(port);
    m_available[port] = true;
}
