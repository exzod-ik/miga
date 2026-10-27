#include "RoutingState.h"
#include "PendingPackets.h"
#include "BoundedQueue.h"
#include <cstdlib>
#include <iostream>
#include <vector>

void Check(bool condition, const char* message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}

int main() {
    using Action = RoutingState::Action;
    using Kind = FlowRoute::Kind;
    const auto now = RoutingState::Clock::now();
    auto process = std::make_shared<const ProcessIdentity>(10, [] { return true; }, [] { return "game.exe"; });
    auto other = std::make_shared<const ProcessIdentity>(11, [] { return true; }, [] { return "direct.exe"; });
    auto a = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 100});
    auto b = std::make_shared<const SocketOwner>(SocketOwner{other, 2, 300});
    SocketTuple tcp{6, 0xc0000201, 5000, 0xc6336401, 443};
    auto udp = tcp; udp.protocol = 17;
    for (const auto tuple : { tcp, udp }) {
        const auto ttl = std::chrono::minutes(tuple.protocol == 6 ? 124 : 20);
        for (const size_t serverId : { size_t(0), size_t(7) }) {
            RoutingState incoming;
            incoming.Observe(tuple, a, now);
            incoming.Commit(tuple, 120, a, {serverId ? Kind::Tunnel : Kind::Direct, serverId, 0}, now);
            incoming.ObserveInbound(tuple, 150, now + ttl - std::chrono::seconds(1), serverId);
            incoming.Cleanup(now + ttl);
            Check(incoming.Size() == 1, "incoming traffic preserves route past original expiry");
            Check(incoming.Resolve(tuple, 160, false, now + ttl).owner == a, "incoming traffic preserves owner");
            incoming.Cleanup(now + ttl + ttl);
            Check(incoming.Size() == 0, "route expires after bidirectional silence");
        }
        RoutingState wrongSource;
        wrongSource.Observe(tuple, a, now);
        wrongSource.Commit(tuple, 120, a, {Kind::Tunnel, 7, 0}, now);
        wrongSource.ObserveInbound(tuple, 150, now + ttl - std::chrono::seconds(1), 8);
        wrongSource.ObserveInbound(tuple, 150, now + ttl - std::chrono::seconds(1));
        wrongSource.ObserveInbound(tuple, 99, now + ttl - std::chrono::seconds(1), 7);
        wrongSource.Cleanup(now + ttl);
        Check(wrongSource.Size() == 0, "wrong transport and older generation cannot refresh route");
        Check(wrongSource.Resolve(tuple, 160, false, now + ttl).action == Action::AwaitOwner,
            "wrong transport cannot refresh owner");
        RoutingState closed;
        closed.Observe(tuple, a, now);
        closed.Commit(tuple, 120, a, {Kind::Tunnel, 7, 0}, now);
        closed.Close(tuple.protocol, tuple.localPort, 1, 140, now);
        closed.ObserveInbound(tuple, 150, now + std::chrono::seconds(29), 7);
        closed.Cleanup(now + std::chrono::seconds(30));
        Check(closed.Resolve(tuple, 160, false, now + std::chrono::seconds(30)).action == Action::AwaitOwner,
            "incoming traffic does not resurrect closed owner");
    }
    RoutingState state;
    Check(state.Resolve(tcp, 120, true, now).action == Action::AwaitOwner, "packet before socket event");
    state.Observe(tcp, a, now);
    auto decision = state.Resolve(tcp, 120, true, now);
    Check(decision.action == Action::SelectRoute && decision.owner == a, "delayed CONNECT resolves owner");
    Check(state.Commit(tcp, 120, a, {Kind::Tunnel, 7, 123}, now), "commit tunnel");
    Check(state.Resolve(tcp, 110, true, now).route.serverId == 7, "reordered same-generation packet");
    state.Close(6, 5000, 1, 200, now);
    Check(state.Resolve(tcp, 220, false, now).route.serverId == 7, "late TCP keeps route");
    Check(state.Resolve(tcp, 250, true, now).action == Action::AwaitOwner, "new SYN cannot use closed owner");
    Check(state.Expire(tcp, 250, true, now).action == Action::Drop, "unknown generation cannot escape old tunnel");
    state.Observe(tcp, b, now);
    Check(state.Resolve(tcp, 320, true, now).action == Action::SelectRoute, "new owner gets fresh route");
    Check(state.Commit(tcp, 320, b, {}, now), "commit direct");
    Check(state.Resolve(tcp, 330, false, now).route.kind == Kind::Direct, "direct route stable");
    Check(state.Resolve(tcp, 150, false, now).action == Action::Drop, "old packet cannot overwrite new generation");
    state.RetainServers({});
    Check(state.Resolve(tcp, 340, false, now).action == Action::Send, "direct survives server removal");

    state.Clear();
    auto binding = udp; binding.localIp = 0; binding.remoteIp = 0; binding.remotePort = 0;
    state.Observe(binding, a, now);
    Check(state.Resolve(udp, 120, false, now).owner == a, "UDP binding");
    state.Commit(udp, 120, a, {Kind::Tunnel, 7, 0}, now);
    auto peer = udp; peer.remotePort++;
    auto connect = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 130});
    state.Observe(peer, connect, now);
    Check(state.Resolve(udp, 140, false, now).route.serverId == 7, "UDP CONNECT keeps other peer");
    Check(state.Resolve(peer, 140, false, now).action == Action::SelectRoute, "UDP peer has its own route");
    state.Commit(peer, 140, a, {}, now);
    Check(state.Resolve(peer, 145, false, now).route.kind == Kind::Direct, "UDP peer direct route");
    state.Close(17, 5000, 1, 200, now);
    Check(state.Resolve(udp, 210, false, now).action == Action::AwaitOwner, "UDP closed owner rejected");
    Check(state.Expire(udp, 210, false, now).action == Action::Drop, "no second-table tunnel bypass after CLOSE");
    Check(state.Resolve(udp, 150, false, now).route.serverId == 7, "captured before CLOSE still routable");
    state.Observe(binding, b, now);
    Check(state.Resolve(udp, 310, false, now).owner == b, "UDP reuse resolves new owner");
    state.Commit(udp, 310, b, {}, now);
    Check(state.Resolve(udp, 320, false, now).route.kind == Kind::Direct, "UDP reuse cannot inherit tunnel");

    state.Clear();
    state.Observe(tcp, a, now);
    state.Commit(tcp, 120, a, {Kind::Tunnel, 7, 123}, now);
    state.RetainServers({9, 7});
    Check(state.Resolve(tcp, 140, false, now).route.serverId == 7, "server reorder keeps identity");
    state.RetainServers({9});
    Check(state.Resolve(tcp, 150, false, now).action == Action::Drop, "removed server never becomes direct");
    state.Clear();
    Check(state.Size() == 0 && state.Resolve(tcp, 160, false, now).action == Action::AwaitOwner,
        "cold restart clears owner and route together");

    Check(state.Expire(tcp, 120, true, now).route.kind == Kind::Direct, "unknown deadline direct policy");
    state.Observe(tcp, a, now);
    Check(state.Resolve(tcp, 125, true, now).route.kind == Kind::Direct, "late identity cannot move committed TCP");
    state.Clear();
    auto snapshot = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 100, true});
    state.Observe(udp, snapshot, now);
    state.Commit(udp, 120, snapshot, {Kind::Tunnel, 7, 0}, now);
    state.CloseSnapshot(udp, 10, 200, now);
    Check(state.Expire(udp, 210, false, now).action == Action::Drop, "snapshot owner closed by socket tuple");
    RoutingState bounded(1);
    bounded.Observe(tcp, a, now);
    Check(bounded.Commit(tcp, 120, a, {}, now), "flow limit first");
    Check(!bounded.Commit(udp, 120, a, {}, now), "flow limit refuses overflow");

    struct Packet { std::vector<uint8_t> packetData; int id; };
    PendingPackets<Packet> pending;
    Check(pending.Push({std::vector<uint8_t>(40), 1}, now), "pending first");
    Check(pending.Push({std::vector<uint8_t>(40), 2}, now + std::chrono::milliseconds(50)), "pending second");
    std::vector<int> sent;
    pending.DrainExpired(now + std::chrono::milliseconds(4999), [&](Packet&, bool expired) {
        Check(!expired, "owner wait remains active before five seconds");
        return expired;
    });
    Check(pending.Size() == 2, "no early deadline release");
    pending.DrainExpired(now + std::chrono::seconds(5), [&](Packet& packet, bool expired) {
        if (expired) sent.push_back(packet.id);
        return expired;
    });
    Check(sent.size() == 1 && sent[0] == 1 && pending.Size() == 1 && pending.Bytes() == 40,
        "individual deadline does not release younger packets");
    pending.DrainExpired(now + std::chrono::milliseconds(5050), [&](Packet& packet, bool expired) {
        if (expired) sent.push_back(packet.id);
        return expired;
    });
    Check(sent.size() == 2 && pending.Bytes() == 0, "second deadline");
    for (size_t i = 0; i < PendingPackets<Packet>::MaxPackets; ++i)
        Check(pending.Push({std::vector<uint8_t>(1), 0}, now), "pending capacity");
    Check(!pending.Push({std::vector<uint8_t>(1), 0}, now), "packet limit enforced");
    pending.Clear();
    Check(pending.Push({std::vector<uint8_t>(PendingPackets<Packet>::MaxBytes), 0}, now), "byte limit exact");
    Check(!pending.Push({std::vector<uint8_t>(1), 0}, now), "byte limit enforced");
    pending.Clear();
    pending.Push({std::vector<uint8_t>(40), 1}, now, 6u << 16 | 5000);
    pending.Push({std::vector<uint8_t>(50), 2}, now, 17u << 16 | 5000);
    pending.Push({std::vector<uint8_t>(60), 3}, now, 6u << 16 | 5000);
    pending.Push({std::vector<uint8_t>(70), 4}, now, 6u << 16 | 5001);
    sent.clear();
    pending.DrainMatching(6u << 16 | 5000, now, [&](Packet& packet, bool expired) {
        Check(!expired, "matching event before deadline");
        sent.push_back(packet.id);
        return packet.id == 1;
    });
    Check(sent == std::vector<int>({1, 3}) && pending.Size() == 3 && pending.Bytes() == 180,
        "only matching protocol and port visited in FIFO order");
    size_t visited = 0;
    pending.DrainMatching(6u << 16 | 4999, now, [&](Packet&, bool) { ++visited; return true; });
    pending.DrainExpired(now, [&](Packet&, bool) { ++visited; return true; });
    Check(visited == 0, "unrelated event and unexpired timer do no packet work");
    sent.clear();
    pending.DrainExpired(now + PendingPackets<Packet>::Wait, [&](Packet& packet, bool expired) {
        Check(expired, "timer callback always expired");
        sent.push_back(packet.id);
        return true;
    });
    Check(sent == std::vector<int>({2, 3, 4}) && pending.Size() == 0 && pending.Bytes() == 0,
        "expiry cleans both indexes in insertion order");
    pending.Push({std::vector<uint8_t>(1), 5}, now, 6u << 16 | 5000);
    pending.Clear();
    pending.DrainMatching(6u << 16 | 5000, now, [&](Packet&, bool) { ++visited; return true; });
    Check(visited == 0, "clear removes pending index");
    BoundedQueue<int, 1> events;
    int value = 0;
    Check(events.PopUntil(value, now) == BoundedQueue<int, 1>::WaitResult::Timeout, "timer with empty queue");
    events.Push(42);
    Check(events.PopUntil(value, now) == BoundedQueue<int, 1>::WaitResult::Item && value == 42, "event before timer");
    events.Close();
    Check(events.PopUntil(value, now) == BoundedQueue<int, 1>::WaitResult::Closed, "stop wakes timer");
    std::cout << "Routing state and pending deadline tests passed\n";
}
