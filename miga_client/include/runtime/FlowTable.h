#pragma once

#include "SocketDirectory.h"

namespace miga::runtime {
class FlowTable {
public:
    enum class Action { Send, Classify, Wait, Drop };
    struct Decision {
        Action action = Action::Classify;
        FlowRoute route;
        uint64_t generation = 0;
        OwnerRecord owner;
        const char* reason = "new_flow";
    };
    explicit FlowTable(SocketDirectory& sockets);
    struct Probe { FlowKey key; uint64_t id; Clock::time_point activity; OwnerRecord owner; uint64_t version; };
    using ProbeHandler = std::function<bool(std::vector<Probe>)>;
    void SetProbeHandler(ProbeHandler handler);
    void Seed(const SocketTuple& tuple, int64_t timestamp, Clock::time_point now);
    Decision Lookup(const PacketView& packet, int64_t timestamp, Clock::time_point now);
    bool Commit(const PacketView& packet, int64_t timestamp, const RouteDecision& decision, Clock::time_point now);
    Decision Expire(const PacketView& packet, int64_t timestamp, Clock::time_point now);
    void Inbound(const PacketView& packet, int64_t timestamp, size_t server, Clock::time_point now);
    void Servers(const std::unordered_set<size_t>& live);
    void Cleanup(Clock::time_point now, size_t budget = 128);
    void Probed(const Probe& probe, std::optional<bool> present, Clock::time_point now);
    std::optional<uint32_t> Reverse(const SocketTuple& wire, size_t server, int64_t timestamp, Clock::time_point now) const;
    size_t Size() const;
    void Clear();
private:
    struct Flow {
        uint64_t id = 0;
        uint64_t socketVersion = 0;
        uint64_t probeVersion = 0;
        int64_t first = 0;
        Clock::time_point lastSeen;
        FlowRoute route;
        OwnerRecord owner, successor;
        std::optional<uint32_t> syn;
        bool finOut = false, finIn = false, reset = false;
        bool seeded = false;
    };
    static Clock::time_point Due(const Flow& flow, uint8_t protocol);
    bool CanProbe(const Flow& flow, uint8_t protocol) const;
    void RefreshSuccessor(Flow& flow, const SocketTuple& tuple, Clock::time_point now);
    bool Usable(const Flow& flow, uint8_t protocol, Clock::time_point now) const;
    struct ReverseKey {
        FlowKey flow; size_t server;
        bool operator==(const ReverseKey& other) const;
    };
    struct ReverseHash {
        size_t operator()(const ReverseKey& key) const;
    };
    void RemoveReverse(const FlowKey& key, const Flow& flow);
    void Touch(Flow& flow, const SocketTuple& tuple, int64_t timestamp, Clock::time_point now,
        const TcpPacketState* tcp, bool incoming);
    SocketDirectory& sockets_;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    DeadlineIndex<FlowKey, FlowKeyHash> deadlines_;
    uint64_t nextId_ = 0;
    std::unordered_map<ReverseKey, FlowKey, ReverseHash> reverse_;
    ProbeHandler probe_;
};
}
