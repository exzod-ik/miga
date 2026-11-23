#include "runtime/SyntheticDnsWire.h"
#include <algorithm>
#include <limits>

namespace miga::runtime {
namespace {
uint16_t Read16(std::span<const uint8_t> data, size_t offset) {
    return static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
}
uint32_t Read32(std::span<const uint8_t> data, size_t offset) {
    return (uint32_t(Read16(data, offset)) << 16) | Read16(data, offset + 2);
}
void Write16(std::vector<uint8_t>& data, uint16_t value) {
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value));
}
void WriteName(std::vector<uint8_t>& data, std::string_view name) {
    while (!name.empty()) {
        const auto separator = name.find('.');
        const auto label = name.substr(0, separator);
        data.push_back(static_cast<uint8_t>(label.size()));
        data.insert(data.end(), label.begin(), label.end());
        if (separator == std::string_view::npos)
            break;
        name.remove_prefix(separator + 1);
    }
    data.push_back(0);
}
std::vector<uint8_t> Question(std::string_view name, uint16_t type, uint16_t id, uint16_t flags, uint16_t answers) {
    std::vector<uint8_t> data;
    data.reserve(18 + name.size() + answers * 16);
    Write16(data, id);
    Write16(data, flags);
    Write16(data, 1);
    Write16(data, answers);
    Write16(data, 0);
    Write16(data, 0);
    WriteName(data, name);
    Write16(data, type);
    Write16(data, 1);
    return data;
}
bool ValidOpt(std::span<const uint8_t> data, bool& requiresPassthrough) {
    if (data.size() < 11 || data[0] != 0 || Read16(data, 1) != 41 || data[5] != 0 || data[6] != 0 ||
        Read16(data, 9) != data.size() - 11)
        return false;
    requiresPassthrough |= Read16(data, 7) != 0;
    data = data.subspan(11);
    while (!data.empty()) {
        if (data.size() < 4 || Read16(data, 2) > data.size() - 4)
            return false;
        requiresPassthrough |= Read16(data, 0) != 12;
        data = data.subspan(4 + Read16(data, 2));
    }
    return true;
}

bool ReadName(std::span<const uint8_t> data, size_t& offset, std::string& name, bool compression) {
    size_t cursor = offset;
    bool jumped = false;
    size_t expanded = 1;
    for (size_t steps = 0; steps < 128 && cursor < data.size(); ++steps) {
        const auto labelOffset = cursor;
        const auto length = data[cursor++];
        if ((length & 0xc0u) == 0xc0u) {
            if (!compression || cursor == data.size())
                return false;
            const auto target = (size_t(length & 0x3fu) << 8) | data[cursor++];
            if (target < 12 || target >= labelOffset)
                return false;
            if (!jumped)
                offset = cursor;
            jumped = true;
            cursor = target;
            continue;
        }
        if (!length) {
            if (!jumped)
                offset = cursor;
            return true;
        }
        expanded += 1 + length;
        if (length > 63 || length > data.size() - cursor || expanded > 255)
            return false;
        if (!name.empty())
            name.push_back('.');
        const auto label = data.subspan(cursor, length);
        if (std::find(label.begin(), label.end(), '.') != label.end())
            return false;
        name.append(reinterpret_cast<const char*>(label.data()), label.size());
        cursor += length;
    }
    return false;
}

bool ReadQuestion(std::span<const uint8_t> data, size_t& offset, std::string& name, uint16_t& type) {
    if (!ReadName(data, offset, name, false) || !NormalizeSyntheticDnsName(name) ||
        data.size() - offset < 4 || Read16(data, offset + 2) != 1)
        return false;
    type = Read16(data, offset);
    offset += 4;
    return type != 0;
}

struct DnsRecord {
    std::string name;
    uint16_t type;
    uint16_t klass;
    uint32_t ttl;
    size_t dataOffset;
    size_t dataSize;
};

bool ReadRecord(std::span<const uint8_t> data, size_t& offset, DnsRecord& record) {
    if (!ReadName(data, offset, record.name, true) || data.size() - offset < 10)
        return false;
    record.type = Read16(data, offset);
    record.klass = Read16(data, offset + 2);
    record.ttl = Read32(data, offset + 4);
    record.dataSize = Read16(data, offset + 8);
    offset += 10;
    if (record.dataSize > data.size() - offset)
        return false;
    record.dataOffset = offset;
    offset += record.dataSize;
    return true;
}
}

std::optional<std::string> NormalizeSyntheticDnsName(std::string_view name) {
    if (name.empty() || name.size() > 253)
        return std::nullopt;
    std::string result;
    result.reserve(name.size());
    size_t label = 0;
    for (char value : name) {
        if (value == '.') {
            if (label == 0)
                return std::nullopt;
            label = 0;
        } else {
            if (value >= 'A' && value <= 'Z')
                value = static_cast<char>(value - 'A' + 'a');
            if (!((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-' || value == '_') ||
                ++label > 63)
                return std::nullopt;
        }
        result.push_back(value);
    }
    if (label == 0)
        return std::nullopt;
    return result;
}

std::optional<SyntheticDnsQuestion> ParseSyntheticDnsQuestion(std::span<const uint8_t> data) {
    if (data.size() < 17 || Read16(data, 4) != 1 || Read16(data, 6) || Read16(data, 8) || Read16(data, 10) > 1)
        return std::nullopt;
    const auto flags = Read16(data, 2);
    if (flags & ~0x0130u)
        return std::nullopt;
    size_t offset = 12;
    std::string name;
    uint16_t type = 0;
    if (!ReadQuestion(data, offset, name, type))
        return std::nullopt;
    const auto additional = data.subspan(offset);
    bool requiresPassthrough = (flags & 0x0030u) != 0;
    if (Read16(data, 10) ? !ValidOpt(additional, requiresPassthrough) : !additional.empty())
        return std::nullopt;
    return SyntheticDnsQuestion{std::move(name), type, Read16(data, 0), flags, requiresPassthrough};
}

std::optional<SyntheticDnsResponse> ReadSyntheticDnsResponse(std::span<const uint8_t> data) {
    if (data.size() < 17 || Read16(data, 4) != 1 || (Read16(data, 2) & 0xf840u) != 0x8000u)
        return std::nullopt;
    size_t offset = 12;
    std::string name;
    uint16_t type = 0;
    if (!ReadQuestion(data, offset, name, type) || type != 1)
        return std::nullopt;
    SyntheticDnsResponse response{*NormalizeSyntheticDnsName(name), {}};
    const auto flags = Read16(data, 2);
    response.responseCode = flags & 0x000fu;
    response.truncated = (flags & 0x0200u) != 0;
    if (response.truncated) return response;

    const size_t answerCount = Read16(data, 6);
    const size_t authorityCount = Read16(data, 8);
    const size_t total = answerCount + authorityCount + Read16(data, 10);
    if (total > 256)
        return std::nullopt;
    std::vector<DnsRecord> answers;
    answers.reserve(answerCount);
    bool seenOpt = false;
    std::optional<uint32_t> negativeTtl;
    for (size_t index = 0; index < total; ++index) {
        DnsRecord record{};
        if (!ReadRecord(data, offset, record))
            return std::nullopt;
        if (record.type == 41) {
            if (seenOpt || index < answerCount + authorityCount || !record.name.empty())
                return std::nullopt;
            seenOpt = true;
            response.responseCode |= static_cast<uint16_t>((record.ttl >> 24) << 4);
        }
        if (index >= answerCount && index < answerCount + authorityCount && record.klass == 1 && record.type == 6) {
            const auto end = record.dataOffset + record.dataSize;
            auto member = record.dataOffset;
            std::string ignored;
            if (!ReadName(data, member, ignored, true) || member > end ||
                !ReadName(data, member, ignored, true) || member > end || end - member != 20)
                return std::nullopt;
            const auto ttl = std::min(record.ttl, Read32(data, member + 16));
            negativeTtl = std::min(negativeTtl.value_or(ttl), ttl);
        }
        if (index >= answerCount || record.klass != 1 || (record.type != 1 && record.type != 5))
            continue;
        auto owner = NormalizeSyntheticDnsName(record.name);
        if (!owner || (record.type == 1 && record.dataSize != 4))
            return std::nullopt;
        record.name = std::move(*owner);
        answers.push_back(std::move(record));
    }
    if (offset != data.size())
        return std::nullopt;
    response.negativeTtl = negativeTtl.value_or(0);
    if (response.responseCode != 0) return response;

    std::string current = response.name;
    uint32_t chainTtl = (std::numeric_limits<uint32_t>::max)();
    for (size_t depth = 0; depth <= 16; ++depth) {
        std::optional<std::string> canonical;
        for (const auto& record : answers) {
            if (record.name != current)
                continue;
            if (record.type == 1) {
                response.addresses.emplace_back(Read32(data, record.dataOffset), std::min(chainTtl, record.ttl));
                continue;
            }
            std::string target;
            auto targetOffset = record.dataOffset;
            if (!ReadName(data, targetOffset, target, true) || targetOffset != record.dataOffset + record.dataSize)
                return std::nullopt;
            auto normalized = NormalizeSyntheticDnsName(target);
            if (!normalized || (canonical && *canonical != *normalized))
                return std::nullopt;
            canonical = std::move(*normalized);
            chainTtl = std::min(chainTtl, record.ttl);
        }
        if (!canonical)
            return response;
        if (!response.addresses.empty())
            return std::nullopt;
        current = std::move(*canonical);
    }
    return std::nullopt;
}

bool RewriteSyntheticDnsResponseQuestion(std::vector<uint8_t>& payload, const SyntheticDnsQuestion& question) {
    if (payload.size() < 17)
        return false;
    size_t offset = 12;
    std::string name;
    uint16_t type = 0;
    if (!ReadQuestion(payload, offset, name, type) || type != question.type ||
        NormalizeSyntheticDnsName(name) != NormalizeSyntheticDnsName(question.name))
        return false;
    std::vector<uint8_t> nameBytes;
    WriteName(nameBytes, question.name);
    if (nameBytes.size() != offset - 16)
        return false;
    payload[0] = static_cast<uint8_t>(question.id >> 8);
    payload[1] = static_cast<uint8_t>(question.id);
    std::copy(nameBytes.begin(), nameBytes.end(), payload.begin() + 12);
    return true;
}

std::vector<uint8_t> BuildSyntheticDnsAnswer(const SyntheticDnsQuestion& question,
    std::optional<uint32_t> address, uint8_t responseCode, uint32_t ttl) {
    if (!NormalizeSyntheticDnsName(question.name) || responseCode > 15)
        return {};
    const bool answer = address.has_value() && question.type == 1 && responseCode == 0;
    auto data = Question(question.name, question.type, question.id,
        static_cast<uint16_t>(0x8080u | (question.flags & 0x0110u) | responseCode), answer ? 1 : 0);
    if (answer) {
        const auto ip = *address;
        Write16(data, 0xc00c);
        Write16(data, 1);
        Write16(data, 1);
        Write16(data, static_cast<uint16_t>(ttl >> 16));
        Write16(data, static_cast<uint16_t>(ttl));
        Write16(data, 4);
        Write16(data, static_cast<uint16_t>(ip >> 16));
        Write16(data, static_cast<uint16_t>(ip));
    }
    return data;
}

std::vector<uint8_t> BuildSyntheticDnsQuery(std::string_view name, uint16_t type, uint16_t id) {
    if (!NormalizeSyntheticDnsName(name) || type == 0)
        return {};
    return Question(name, type, id, 0x0100, 0);
}

std::vector<uint8_t> BuildSyntheticDnsQuery(std::string_view name, uint16_t type, uint16_t id, uint16_t udpPayloadSize) {
    auto query = BuildSyntheticDnsQuery(name, type, id);
    if (query.empty() || udpPayloadSize < 512)
        return query;
    query[11] = 1;
    query.push_back(0);
    Write16(query, 41);
    Write16(query, udpPayloadSize);
    query.resize(query.size() + 6, 0);
    return query;
}
}
