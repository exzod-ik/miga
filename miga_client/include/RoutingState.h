#pragma once

#include "SocketOwnerTable.h"
#include <unordered_set>

struct FlowKey {
    uint8_t proto;
    uint32_t srcIp;
    uint16_t srcPort;
    uint32_t dstIp;
    uint16_t dstPort;

    bool operator==(const FlowKey& o) const {
        return proto == o.proto && srcIp == o.srcIp && srcPort == o.srcPort &&
            dstIp == o.dstIp && dstPort == o.dstPort;
    }
    static FlowKey From(const SocketTuple& tuple) {
        return { tuple.protocol, tuple.localIp, tuple.localPort, tuple.remoteIp, tuple.remotePort };
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const {
        size_t hash = key.proto;
        for (auto value : { key.srcIp, uint32_t(key.srcPort), key.dstIp, uint32_t(key.dstPort) })
            hash ^= std::hash<uint32_t>()(value) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        return hash;
    }
};

struct FlowRoute {
    enum class Kind { Direct, Tunnel, Unavailable };
    Kind kind = Kind::Direct;
    size_t serverId = 0;
    uint32_t translatedIp = 0;
};

class RoutingState {
public:
    using Clock = std::chrono::steady_clock;
    using Owner = SocketOwnerTable::Owner;
    enum class Action { AwaitOwner, SelectRoute, Send, Drop };
    struct Decision {
        Action action;
        Owner owner;
        FlowRoute route;
        const char* reason;
    };

    explicit RoutingState(size_t capacity = 65536) : capacity_(capacity) {}
    void SetProbeHandler(SocketOwnerTable::ProbeHandler handler) {
        managedTcp_ = static_cast<bool>(handler);
        sockets_.SetProbeHandler(std::move(handler));
    }
    void ApplyProbe(const SocketOwnerTable::Probe& probe, SocketOwnerTable::ProbeResult result, Clock::time_point now) {
        sockets_.ApplyProbe(probe, result, now);
    }

    void SetEvictionHandler(SocketOwnerTable::EvictionHandler handler) {
        sockets_.SetEvictionHandler(std::move(handler));
    }

    void SetOwnerChangeHandler(SocketOwnerTable::ChangeHandler handler) {
        sockets_.SetChangeHandler(std::move(handler));
    }

    Owner Observe(const SocketTuple& tuple, Owner owner, Clock::time_point now) {
        return sockets_.Update(tuple, std::move(owner), now);
    }

    void Close(uint8_t protocol, uint16_t port, uint64_t endpoint, int64_t timestamp, Clock::time_point now) {
        sockets_.Close(protocol, port, endpoint, timestamp, now);
    }

    void CloseSnapshot(const SocketTuple& tuple, uint32_t pid, int64_t timestamp, Clock::time_point now) {
        sockets_.CloseSnapshot(tuple, pid, timestamp, now);
    }

    Decision Resolve(const SocketTuple& tuple, int64_t timestamp, bool syn, Clock::time_point now) {
        auto it = flows_.find(FlowKey::From(tuple));
        auto owner = sockets_.Find(tuple, timestamp, syn, now,
            it == flows_.end() ? nullptr : &it->second.lookup);
        if (it != flows_.end() && timestamp < (it->second.owner ? it->second.owner->timestamp : it->second.firstPacket))
            return { Action::Drop, owner, {}, "older_flow_generation" };
        if (owner) {
            if (it != flows_.end() && !it->second.owner && tuple.protocol == 6 &&
                owner->timestamp <= it->second.firstPacket) {
                it->second.owner = owner;
                it->second.life = sockets_.State(tuple, owner);
                it->second.lastSeen = now;
                return { Action::Send, owner, it->second.route, "committed_direct_route" };
            }
            if (it != flows_.end() && it->second.owner == owner) {
                it->second.lastSeen = now;
                return { it->second.route.kind == FlowRoute::Kind::Unavailable ? Action::Drop : Action::Send,
                    owner, it->second.route, "saved_route" };
            }
            return { Action::SelectRoute, owner, {}, "owner_resolved" };
        }
        if (it != flows_.end() && !it->second.owner && !syn) {
            it->second.lastSeen = now;
            return { Action::Send, {}, it->second.route, "committed_direct_route" };
        }
        return { Action::AwaitOwner, {}, {}, sockets_.DescribeMiss(tuple, timestamp, now) };
    }

    Decision Expire(const SocketTuple& tuple, int64_t timestamp, bool syn, Clock::time_point now) {
        auto decision = Resolve(tuple, timestamp, syn, now);
        if (decision.action != Action::AwaitOwner) return decision;
        auto it = flows_.find(FlowKey::From(tuple));
        if (it != flows_.end() && it->second.route.kind != FlowRoute::Kind::Direct)
            return { Action::Drop, {}, {}, "known_tunnel_owner_unresolved" };
        if (it == flows_.end()) {
            if (flows_.size() >= capacity_)
                return { Action::Drop, {}, {}, "flow_capacity" };
            flows_.emplace(FlowKey::From(tuple), Flow{ {}, {}, timestamp, now, {} });
            deadlines_.Set(FlowKey::From(tuple), now + std::chrono::minutes(tuple.protocol == 6 ? 124 : 20));
        }
        return { Action::Send, {}, {}, "owner_deadline_direct" };
    }

    bool Commit(const SocketTuple& tuple, int64_t timestamp, const Owner& owner, FlowRoute route,
        Clock::time_point now) {
        const auto key = FlowKey::From(tuple);
        auto it = flows_.find(key);
        if (it != flows_.end()) {
            if (timestamp < (it->second.owner ? it->second.owner->timestamp : it->second.firstPacket)) return false;
            if (it->second.owner == owner) return true;
        }
        else if (flows_.size() >= capacity_) {
            return false;
        }
        flows_[key] = { owner, route, timestamp, now, {}, sockets_.State(tuple, owner) };
        deadlines_.Set(key, now + std::chrono::minutes(tuple.protocol == 6 ? 124 : 20));
        return true;
    }

    void ObserveInbound(const SocketTuple& tuple, int64_t timestamp, Clock::time_point now, size_t serverId = 0) {
        auto it = flows_.find(FlowKey::From(tuple));
        if (it == flows_.end()) {
            if (serverId == 0) sockets_.Find(tuple, timestamp, false, now);
            return;
        }
        auto& flow = it->second;
        if (flow.route.kind == FlowRoute::Kind::Unavailable ||
            (serverId == 0 && flow.route.kind != FlowRoute::Kind::Direct) ||
            (serverId != 0 && (flow.route.kind != FlowRoute::Kind::Tunnel || flow.route.serverId != serverId)) ||
            timestamp < (flow.owner ? flow.owner->timestamp : flow.firstPacket) ||
            (!(managedTcp_ && tuple.protocol == 6 && flow.life && flow.life->present) &&
                now - flow.lastSeen >= std::chrono::minutes(tuple.protocol == 6 ? 124 : 20))) return;
        if (flow.owner && !sockets_.Touch(tuple, flow.owner, timestamp, now)) return;
        flow.lastSeen = now;
    }

    void RetainServers(const std::unordered_set<size_t>& serverIds) {
        for (auto& item : flows_) {
            auto& route = item.second.route;
            if (route.kind == FlowRoute::Kind::Tunnel && !serverIds.count(route.serverId))
                route.kind = FlowRoute::Kind::Unavailable;
        }
    }

    void Cleanup(Clock::time_point now, size_t budget = 128) {
        sockets_.Cleanup(now, budget);
        FlowKey key{};
        while (budget-- && deadlines_.PopDue(now, key)) {
            auto it = flows_.find(key);
            if (it == flows_.end()) continue;
            auto& flow = it->second;
            const auto ttl = std::chrono::minutes(key.proto == 6 ? 124 : 20);
            const auto activity = key.proto == 6 && flow.life ? flow.life->lastSeen : flow.lastSeen;
            if (managedTcp_ && key.proto == 6 && flow.life && flow.life->present &&
                !flow.life->closedAt && !flow.life->cutoff) {
                deadlines_.Set(key, (std::max)(activity + ttl, now + std::chrono::seconds(60)));
            } else if (now - activity >= ttl || (flow.life && !flow.life->present)) {
                flows_.erase(it);
            } else deadlines_.Set(key, activity + ttl);
        }
    }

    void Clear() { sockets_.Clear(); flows_.clear(); deadlines_.Clear(); }
    size_t Size() const { return flows_.size(); }
    Clock::time_point NextDeadline(Clock::time_point otherwise) const {
        return sockets_.NextDeadline(deadlines_.Next(otherwise));
    }

private:
    struct Flow {
        Owner owner;
        FlowRoute route;
        int64_t firstPacket;
        Clock::time_point lastSeen;
        SocketOwnerTable::LookupCache lookup;
        std::shared_ptr<SocketOwnerTable::Lifetime> life;
    };
    SocketOwnerTable sockets_;
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    DeadlineIndex<FlowKey, FlowKeyHash> deadlines_;
    bool managedTcp_ = false;
    size_t capacity_;
};
