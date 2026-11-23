#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace miga::runtime {
struct SyntheticDnsQuestion {
    std::string name;
    uint16_t type;
    uint16_t id;
    uint16_t flags;
    bool requiresPassthrough = false;
};

struct SyntheticDnsResponse {
    std::string name;
    std::vector<std::pair<uint32_t, uint32_t>> addresses;
    uint32_t negativeTtl = 0;
    uint16_t responseCode = 0;
    bool truncated = false;
};

std::optional<std::string> NormalizeSyntheticDnsName(std::string_view name);
std::optional<SyntheticDnsQuestion> ParseSyntheticDnsQuestion(std::span<const uint8_t> payload);
std::optional<SyntheticDnsResponse> ReadSyntheticDnsResponse(std::span<const uint8_t> payload);
bool RewriteSyntheticDnsResponseQuestion(std::vector<uint8_t>& payload, const SyntheticDnsQuestion& question);
std::vector<uint8_t> BuildSyntheticDnsAnswer(const SyntheticDnsQuestion& question,
    std::optional<uint32_t> address, uint8_t responseCode = 0, uint32_t ttl = 60);
std::vector<uint8_t> BuildSyntheticDnsQuery(std::string_view name, uint16_t type, uint16_t id);
std::vector<uint8_t> BuildSyntheticDnsQuery(std::string_view name, uint16_t type, uint16_t id, uint16_t udpPayloadSize);
}
