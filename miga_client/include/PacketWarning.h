#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

struct PacketWarningSample {
    std::array<uint8_t, 80> header{};
    size_t captured = 0;
    size_t size = 0;
    int64_t ageMs = 0;
    int64_t packetTimestampQpc = 0;
    const char* ownerLookup = "not_recorded";
};

inline std::string FormatPacketWarning(const PacketWarningSample& sample) {
    const auto* p = sample.header.data();
    const auto available = sample.captured;
    if (available > sample.header.size() || available < 20 || (p[0] >> 4) != 4)
        return "reason=invalid_ipv4 size=" + std::to_string(sample.size);
    const size_t ihl = (p[0] & 15) * 4;
    const size_t total = (size_t(p[2]) << 8) | p[3];
    if (ihl < 20 || ihl > available || total < ihl || total > sample.size)
        return "reason=invalid_ipv4 size=" + std::to_string(sample.size);
    const auto address = [&](size_t offset) {
        return std::to_string(p[offset]) + "." + std::to_string(p[offset + 1]) + "." +
            std::to_string(p[offset + 2]) + "." + std::to_string(p[offset + 3]);
    };
    const std::string protocol = p[9] == 6 ? "TCP" : p[9] == 17 ? "UDP" : std::to_string(p[9]);
    const bool portsAvailable = (p[9] == 6 || p[9] == 17) &&
        (p[6] & 31) == 0 && p[7] == 0 && total >= ihl + 4 && available >= ihl + 4;
    const auto port = [&](size_t offset) {
        return portsAvailable ? std::to_string((unsigned(p[offset]) << 8) | p[offset + 1]) : "unknown";
    };
    std::string flags;
    if (p[9] == 6) {
        flags = " tcp_flags=unknown";
        if (portsAvailable && total >= ihl + 14 && available >= ihl + 14) {
            static constexpr char hex[] = "0123456789abcdef";
            flags = " tcp_flags=0x";
            flags += hex[p[ihl + 13] >> 4];
            flags += hex[p[ihl + 13] & 15];
        }
    }
    return "protocol=" + protocol + " src=" + address(12) + ":" + port(ihl) +
        " dst=" + address(16) + ":" + port(ihl + 2) +
        " size=" + std::to_string(sample.size) + " age_ms=" + std::to_string(sample.ageMs) +
        " packet_timestamp_qpc=" + std::to_string(sample.packetTimestampQpc) + flags + " owner_lookup=" + sample.ownerLookup;
}
