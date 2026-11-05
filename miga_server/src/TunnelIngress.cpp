#include "TunnelIngress.h"

bool TunnelIngress::Parse(uint8_t* packet, size_t size, uint16_t first, uint16_t last, TunnelIngress& result) {
    if (!packet || size < 20 || (packet[0] >> 4) != 4 || packet[9] != 17) return false;
    const auto read16 = [](const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); };
    const size_t ihl = (packet[0] & 15) * 4;
    const size_t total = read16(packet + 2);
    if (ihl < 20 || total > size || total < ihl + 8 || (read16(packet + 6) & 0x3fff)) return false;
    constexpr uint8_t tunnelAddress[] = {10, 0, 0, 2};
    if (std::memcmp(packet + 12, tunnelAddress, 4) == 0 || std::memcmp(packet + 16, tunnelAddress, 4) == 0)
        return false;
    const auto* udp = packet + ihl;
    const uint16_t port = read16(udp + 2);
    const size_t datagram = read16(udp + 4);
    if (port < first || port > last || datagram < 8 + 20 || datagram > total - ihl) return false;
    uint32_t clientAddress;
    std::memcpy(&clientAddress, packet + 12, sizeof(clientAddress));
    result = {packet + ihl + 8, datagram - 8, clientAddress, read16(udp), port};
    return true;
}
