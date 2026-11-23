#pragma once

#include "DnsClassifier.h"
#include "SyntheticDnsStore.h"
#include "SyntheticDnsWire.h"

namespace miga::runtime {
class SyntheticDnsResolver {
public:
    using Output = DnsClassifier::Output;
    using Outputs = std::vector<Output>;
    static bool Contains(const Configuration& config, uint32_t ip) {
        return config.dnsResolverReserveRange && SyntheticDnsStore::Contains(ip) &&
            ip != SyntheticDnsStore::DiagnosticEchoAddress &&
            (config.dnsResolverReservedThrough == 0xc613ffff ||
                (ip != 0xc6120000 && ip <= config.dnsResolverReservedThrough));
    }
    explicit SyntheticDnsResolver(Logger* logger = nullptr) : logger_(logger) {}
    ~SyntheticDnsResolver();
    std::optional<uint32_t> Preflight(bool enabled);
    uint32_t LastAllocated() const { return store_.LastAllocated(); }
    void Stop();
    Clock::time_point NextDeadline() const { return deadlines_.Next((Clock::time_point::max)()); }
    uint16_t Port() const { return port_.load(std::memory_order_relaxed); }
    void Cleanup(Clock::time_point now, const Configuration& config, PacketBufferPool& buffers, Outputs& outputs);
    bool Query(const Packet& packet, const Configuration& config, PacketBufferPool& buffers,
        Clock::time_point now, Outputs& outputs, size_t replyServer = 0);
    void Route(const Packet& packet, const Configuration& config, const std::string& process,
        PacketBufferPool& buffers, Clock::time_point now, RouteDecision& decision, Outputs& outputs,
        std::optional<size_t> serverOverride = std::nullopt);
    void Response(const Packet& packet, size_t server, const Configuration& config, PacketBufferPool& buffers,
        Clock::time_point now, Outputs& outputs, uint32_t& wakeAddress);
private:
    friend struct SyntheticDnsResolverTestAccess;
    struct Key {
        std::string name;
        size_t server = 0;
        uint32_t upstream = 0;
        uint32_t source = 0;
        bool operator==(const Key&) const = default;
    };
    struct KeyHash {
        size_t operator()(const Key& key) const;
    };
    struct QueryState {
        Key key;
        SocketTuple tuple;
        WINDIVERT_ADDRESS address;
        std::vector<uint8_t> wire;
        Clock::time_point expires;
        uint32_t wakeAddress = 0;
        std::vector<Packet> listeners;
    };
    struct Answer {
        std::vector<uint32_t> addresses;
        uint32_t ttl = 0;
        uint16_t responseCode = 0;
    };
    bool StartQuery(const Key& key, const Packet& origin, PacketBufferPool& buffers,
        Clock::time_point now, Outputs& outputs, uint32_t wakeAddress = 0, const Packet* listener = nullptr);
    static void QueueQuery(const QueryState& state, PacketBufferPool& buffers, Clock::time_point now, Outputs& outputs);
    const Answer* Resolve(const Key& key, const Packet& origin, PacketBufferPool& buffers,
        Clock::time_point now, Outputs& outputs, uint32_t wakeAddress);
    void Reply(const Packet& query, std::span<const uint8_t> wire, PacketBufferPool& buffers, Outputs& outputs);
    void FailClient(const Packet& query, PacketBufferPool& buffers, Outputs& outputs);
    void AnswerClient(const Packet& query, const Answer& answer, PacketBufferPool& buffers, Outputs& outputs);
    bool Configure(const Configuration& config);
    void Start();
    Logger* logger_;
    SyntheticDnsStore store_;
    std::unordered_map<uint16_t, QueryState> queries_;
    DeadlineIndex<uint16_t> deadlines_;
    std::unordered_map<Key, uint16_t, KeyHash> pending_;
    std::unordered_map<Key, Answer, KeyHash> cache_;
    std::unordered_map<uint32_t, uint32_t> upstreams_;
    SOCKET socket_ = INVALID_SOCKET;
    std::atomic<uint16_t> port_{0};
    uint32_t defaultUpstream_ = 0;
    uint64_t version_ = 0;
    size_t listeners_ = 0;
};
}
