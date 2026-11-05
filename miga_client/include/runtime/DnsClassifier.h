#pragma once

#include "RuntimeConfig.h"
#include "../PacketBufferPool.h"

namespace miga::runtime {
struct DnsMessage {
    std::string question;
    uint16_t id = 0, type = 0;
    bool response = false;
    std::vector<std::pair<uint32_t, uint32_t>> addresses;
    static bool Name(const uint8_t* data, size_t size, size_t& offset, std::string& result);
    bool Read(const Packet& packet);
};
class DnsClassifier {
public:
    DnsClassifier();
    uint64_t TakeOverflows();
    void Reconfigure(const Configuration& config);
    struct Output { Packet packet; FlowRoute route; };
    const Server* Select(const Configuration& config, const std::string& process, uint32_t ip, Clock::time_point now);
    uint32_t Translate(uint32_t ip, size_t server, Clock::time_point now) const;
    std::vector<Output> Query(const Packet& packet, const Configuration& config, const std::string& process,
        PacketBufferPool& pool, Clock::time_point now);
    std::optional<Packet> Response(Packet packet, size_t serverId, const Configuration& config, Clock::time_point now);
    void Cleanup(Clock::time_point now);
    void Clear();
private:
    struct MappingKey {
        uint32_t ip = 0; size_t server = 0;
        bool operator==(const MappingKey& other) const;
    };
    struct MappingHash { size_t operator()(const MappingKey& key) const; };
    struct Group {
        struct Answer {std::vector<std::pair<uint32_t, uint32_t>> addresses; Clock::time_point received;};
        uint16_t original = 0;
        size_t primary = 0;
        std::string question;
        SocketTuple tuple;
        Clock::time_point expires;
        std::unordered_map<size_t, Answer> answers;
    };
    struct QueryState { std::shared_ptr<Group> group; size_t server; };
    struct Translation { uint32_t ip; Clock::time_point expires; };
    struct Dynamic { Clock::time_point expires; std::string question; };
    std::optional<uint16_t> Allocate(Clock::time_point now);
    void ResetIds();
    std::deque<uint16_t> freeIds_;
    uint64_t overflows_ = 0;
    uint64_t version_ = 0;
    std::unordered_map<uint16_t, QueryState> queries_;
    std::unordered_map<MappingKey, Translation, MappingHash> translations_;
    std::unordered_map<MappingKey, Dynamic, MappingHash> dynamic_;
    DeadlineIndex<uint16_t> queryDeadlines_;
    DeadlineIndex<MappingKey, MappingHash> translationDeadlines_, dynamicDeadlines_;
};
}
