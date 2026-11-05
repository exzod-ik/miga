#include "runtime/FlowTable.h"

namespace miga::runtime {
FlowTable::FlowTable(SocketDirectory& sockets) : sockets_(sockets) { flows_.reserve(65536); }

void FlowTable::SetProbeHandler(ProbeHandler handler) { probe_ = std::move(handler); }

void FlowTable::Seed(const SocketTuple& tuple, int64_t timestamp, Clock::time_point now) {
    PacketView packet; packet.tuple = tuple;
    RouteDecision decision; decision.owner = sockets_.Find(tuple, timestamp, false, now);
    if (Commit(packet, timestamp, decision, now)) flows_.at(FlowKey::From(tuple)).seeded = true;
}

FlowTable::Decision FlowTable::Lookup(const PacketView& packet, int64_t timestamp, Clock::time_point now) {
    const auto key = FlowKey::From(packet.tuple);
    auto found = flows_.find(key);
    if (found == flows_.end()) return {};
    auto& flow = found->second;
    if (timestamp < flow.first) return {Action::Drop, {}, flow.id, {}, "older_flow_generation"};
    const auto revision = sockets_.Version(packet.tuple);
    if (revision != flow.socketVersion) {
        RefreshSuccessor(flow, packet.tuple, now);
        flow.socketVersion = revision;
    }
    const bool replaced = flow.successor && flow.successor->owner->timestamp <= timestamp &&
        (!flow.owner || flow.successor->owner != flow.owner->owner);
    if (packet.tuple.protocol == 6 && !replaced && Usable(flow, 6, now) &&
        (!packet.syn || (flow.seeded && !flow.syn) || (flow.syn && *flow.syn == packet.tcp.sequence))) {
        if (packet.syn && !flow.syn) flow.syn = packet.tcp.sequence;
        Touch(flow, packet.tuple, timestamp, now, &packet.tcp, false);
        return {Action::Send, flow.route, flow.id, flow.owner, "saved_tcp_route"};
    }
    if (packet.tuple.protocol == 17 && !replaced && now < Due(flow, 17) &&
        ((flow.owner && flow.owner->Eligible(packet.tuple, timestamp, false, Millis(now))) ||
            (!flow.owner && flow.route.kind == FlowRoute::Kind::Direct))) {
        Touch(flow, packet.tuple, timestamp, now, nullptr, false);
        return {Action::Send, flow.route, flow.id, flow.owner, "saved_udp_route"};
    }
    if (packet.tuple.protocol == 6 && packet.syn && flow.owner && !replaced && flow.syn &&
        *flow.syn != packet.tcp.sequence)
        return {Action::Wait, {}, flow.id, {}, "syn_generation_unresolved"};
    if (packet.tuple.protocol == 6 && !packet.syn && replaced)
        return {Action::Wait, {}, flow.id, {}, "tcp_generation_awaiting_syn"};
    return {Action::Classify, {}, flow.id, {}, "route_needs_owner"};
}

bool FlowTable::Commit(const PacketView& packet, int64_t timestamp, const RouteDecision& decision, Clock::time_point now) {
    const auto key = FlowKey::From(packet.tuple);
    auto existing = flows_.find(key);
    if (existing == flows_.end() && flows_.size() >= 65536) return false;
    const auto revision = sockets_.Version(packet.tuple);
    if (decision.owner) {
        if (!decision.owner->Eligible(packet.tuple, timestamp, packet.syn, Millis(now))) return false;
        auto latest = sockets_.Find(packet.tuple, timestamp, packet.syn, now);
        if (!latest || latest->owner != decision.owner->owner) return false;
    }
    if (existing != flows_.end()) {
        auto& old = existing->second;
        if (timestamp < old.first) return false;
        if (packet.tuple.protocol == 6 && old.owner && decision.owner &&
            old.owner->owner != decision.owner->owner && !packet.syn) return false;
        if (packet.tuple.protocol == 6 && old.owner && decision.owner &&
            old.owner->owner == decision.owner->owner && packet.syn && old.syn &&
            *old.syn != packet.tcp.sequence) return false;
    }
    if (decision.route.kind == FlowRoute::Kind::Tunnel && decision.route.translatedIp) {
        auto wire = key; wire.dstIp = decision.route.translatedIp;
        auto reverse = reverse_.find({wire, decision.route.serverId});
        if (reverse != reverse_.end() && !(reverse->second == key)) return false;
    }
    if (existing != flows_.end()) RemoveReverse(key, existing->second);
    Flow flow;
    flow.id = ++nextId_;
    flow.first = timestamp;
    flow.owner = decision.owner;
    flow.route = decision.route;
    flow.lastSeen = now;
    flow.socketVersion = revision;
    if (packet.tuple.protocol == 6 && packet.syn) flow.syn = packet.tcp.sequence;
    Touch(flow, packet.tuple, timestamp, now, packet.tuple.protocol == 6 ? &packet.tcp : nullptr, false);
    flows_.insert_or_assign(key, std::move(flow));
    const auto& committed = flows_.at(key);
    if (committed.route.kind == FlowRoute::Kind::Tunnel && committed.route.translatedIp) {
        auto wire = key; wire.dstIp = committed.route.translatedIp;
        reverse_[{wire, committed.route.serverId}] = key;
    }
    deadlines_.Set(key, Due(flows_.at(key), packet.tuple.protocol));
    return true;
}

FlowTable::Decision FlowTable::Expire(const PacketView& packet, int64_t timestamp, Clock::time_point now) {
    auto decision = Lookup(packet, timestamp, now);
    if (decision.action == Action::Send || decision.action == Action::Drop) return decision;
    auto found = flows_.find(FlowKey::From(packet.tuple));
    if (found != flows_.end() && (found->second.route.kind != FlowRoute::Kind::Direct ||
        (packet.tuple.protocol == 6 && (packet.syn || found->second.successor))))
        return {Action::Drop, {}, found->second.id, {}, packet.tuple.protocol == 6 ?
            "tcp_generation_unresolved" : "known_tunnel_owner_unresolved"};
    if (found == flows_.end() && !Commit(packet, timestamp, {}, now))
        return {Action::Drop, {}, 0, {}, "flow_capacity"};
    return {Action::Send, {}, flows_.at(FlowKey::From(packet.tuple)).id, {}, "owner_deadline_direct"};
}

void FlowTable::Inbound(const PacketView& packet, int64_t timestamp, size_t server, Clock::time_point now) {
    auto tuple = packet.IncomingTuple();
    auto found = flows_.find(FlowKey::From(tuple));
    if (found == flows_.end()) return;
    auto& flow = found->second;
    if (timestamp < flow.first || !Usable(flow, tuple.protocol, now)) return;
    if (flow.route.kind == FlowRoute::Kind::Unavailable ||
        (flow.route.kind == FlowRoute::Kind::Tunnel ? flow.route.serverId != server : server != 0)) return;
    const auto revision = sockets_.Version(tuple);
    if (revision != flow.socketVersion) {
        RefreshSuccessor(flow, tuple, now);
        flow.socketVersion = revision;
    }
    if (flow.successor && timestamp >= flow.successor->owner->timestamp &&
        (!flow.owner || flow.successor->owner != flow.owner->owner)) return;
    Touch(flow, tuple, timestamp, now, tuple.protocol == 6 ? &packet.tcp : nullptr, true);
}

void FlowTable::Servers(const std::unordered_set<size_t>& live) {
    for (auto& item : flows_) if (item.second.route.kind == FlowRoute::Kind::Tunnel &&
        !live.count(item.second.route.serverId)) item.second.route.kind = FlowRoute::Kind::Unavailable;
}

void FlowTable::Cleanup(Clock::time_point now, size_t budget) {
    FlowKey key{};
    std::vector<Probe> probes;
    while (budget-- && deadlines_.PopDue(now, key)) {
        auto found = flows_.find(key);
        if (found == flows_.end()) continue;
        const auto due = Due(found->second, key.proto);
        if (due > now) deadlines_.Set(key, due);
        else if (CanProbe(found->second, key.proto)) {
            probes.push_back({key, found->second.id, found->second.lastSeen, found->second.owner, ++found->second.probeVersion});
            deadlines_.Set(key, now + std::chrono::seconds(30));
        } else { RemoveReverse(key, found->second); flows_.erase(found); }
    }
    if (!probes.empty()) probe_(std::move(probes));
}

void FlowTable::Probed(const Probe& probe, std::optional<bool> present, Clock::time_point now) {
    auto found = flows_.find(probe.key);
    if (found == flows_.end() || found->second.id != probe.id || found->second.lastSeen != probe.activity ||
        !CanProbe(found->second, probe.key.proto) || found->second.probeVersion != probe.version) return;
    if (present && !*present) {RemoveReverse(probe.key, found->second); flows_.erase(found);}
    else deadlines_.Set(probe.key, now + std::chrono::seconds(present ? 60 : 30));
}

std::optional<uint32_t> FlowTable::Reverse(const SocketTuple& wire, size_t server, int64_t timestamp, Clock::time_point now) const {
    auto mapping = reverse_.find({FlowKey::From(wire), server});
    if (mapping == reverse_.end()) return {};
    auto found = flows_.find(mapping->second);
    if (found == flows_.end() || found->second.first > timestamp || !Usable(found->second, wire.protocol, now) ||
        found->second.route.kind != FlowRoute::Kind::Tunnel) return {};
    return mapping->second.dstIp;
}

size_t FlowTable::Size() const { return flows_.size(); }

void FlowTable::Clear() { flows_.clear(); deadlines_.Clear(); reverse_.clear(); }

Clock::time_point FlowTable::Due(const Flow& flow, uint8_t protocol) {
    return flow.lastSeen + std::chrono::minutes(protocol == 17 ? 20 :
        (flow.reset || (flow.finIn && flow.finOut) ? 4 : 124));
}

bool FlowTable::CanProbe(const Flow& flow, uint8_t protocol) const {
    return probe_ && protocol == 6 && flow.owner && !flow.reset && !(flow.finIn && flow.finOut) &&
        !flow.owner->activity->closed.load() && !flow.owner->activity->cutoff.load();
}

void FlowTable::RefreshSuccessor(Flow& flow, const SocketTuple& tuple, Clock::time_point now) {
    const auto baseline = flow.owner && !flow.seeded && !flow.owner->owner->snapshot ? flow.owner->owner->timestamp : flow.first;
    const bool provisional = tuple.protocol == 6 && flow.syn && flow.owner &&
        flow.owner->owner->origin == SocketOrigin::Bind && !flow.owner->tuple.remotePort &&
        flow.owner->Eligible(tuple, flow.first, true, Millis(now));
    OwnerRecord refinement;
    auto next = sockets_.Successor(tuple, baseline, now, provisional ? flow.owner : nullptr, flow.first, refinement);
    if (refinement && (!flow.successor || flow.successor->id == refinement->id)) {
        flow.owner = refinement;
        flow.successor.reset();
        if (next && next->id == refinement->id) return;
    }
    if (next && (!flow.successor || next->owner->timestamp > flow.successor->owner->timestamp)) flow.successor = std::move(next);
}

bool FlowTable::Usable(const Flow& flow, uint8_t protocol, Clock::time_point now) const {
    return now < Due(flow, protocol) || CanProbe(flow, protocol);
}

bool FlowTable::ReverseKey::operator==(const ReverseKey& other) const {return server == other.server && flow == other.flow;}

size_t FlowTable::ReverseHash::operator()(const ReverseKey& key) const {return FlowKeyHash{}(key.flow) ^ (key.server * 0x9e3779b9);}

void FlowTable::RemoveReverse(const FlowKey& key, const Flow& flow) {
    if (!flow.route.translatedIp) return;
    auto wire = key; wire.dstIp = flow.route.translatedIp;
    auto found = reverse_.find({wire, flow.route.serverId});
    if (found != reverse_.end() && found->second == key) reverse_.erase(found);
}

void FlowTable::Touch(Flow& flow, const SocketTuple& tuple, int64_t timestamp, Clock::time_point now,
    const TcpPacketState* tcp, bool incoming) {
    const bool previouslyShort = flow.reset || (flow.finOut && flow.finIn);
    flow.lastSeen = now;
    if (tcp) {
        flow.reset |= (tcp->flags & 4) != 0;
        if (tcp->flags & 1) (incoming ? flow.finIn : flow.finOut) = true;
    }
    if (!previouslyShort && (flow.reset || (flow.finOut && flow.finIn)))
        deadlines_.Set(FlowKey::From(tuple), Due(flow, tuple.protocol));
    if (flow.owner && flow.owner->Eligible(tuple, timestamp, false, Millis(now)))
        flow.owner->activity->Touch(Millis(now));
}

}
