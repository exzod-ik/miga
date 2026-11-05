#include "runtime/FlowTable.h"
#include "runtime/RuntimeMailbox.h"
#include <cassert>
#include <iostream>
#include <future>

using namespace miga::runtime;
static void TestDelayedConnect(uint64_t parent, bool sameProcess, bool ambiguous) {
    auto directory = std::make_unique<SocketDirectory>();
    FlowTable flows(*directory);
    const auto now = Clock::now();
    auto process = std::make_shared<const ProcessIdentity>(3476, [] {return true;}, [] {return "app.exe";});
    auto differentInstance = std::make_shared<const ProcessIdentity>(3476, [] {return true;}, [] {return "other.exe";});
    PacketView syn;
    syn.tuple = {6, 1, 57759, 2, 443};
    syn.syn = true;
    syn.tcp = {2721291674u, 0, 2};
    SocketTuple wildcard{6, 0, 57759, 0, 0};
    auto bind = directory->Observe(wildcard, std::make_shared<const SocketOwner>(
        SocketOwner{process, 145541, 100, false, SocketOrigin::Bind}), now);
    assert(flows.Commit(syn, 120, {{FlowRoute::Kind::Tunnel, 1, 0}, bind}, now));
    const auto generation = flows.Lookup(syn, 120, now).generation;
    if (ambiguous) directory->Observe(syn.tuple, std::make_shared<const SocketOwner>(
        SocketOwner{process, 145556, 109, false, SocketOrigin::Connect}), now);
    auto connected = directory->Observe(syn.tuple, std::make_shared<const SocketOwner>(
        SocketOwner{sameProcess ? process : differentInstance, 145557, 110, false, SocketOrigin::Connect, parent}), now);
    PacketView ack = syn;
    ack.syn = false;
    ack.tcp = {2721291675u, 386768894, 16};
    auto result = flows.Lookup(ack, 130, now);
    if (ambiguous || !sameProcess || (parent && parent != 145541)) {
        assert(result.action == FlowTable::Action::Wait);
        return;
    }
    assert(result.action == FlowTable::Action::Send && result.owner == connected);
    assert(result.generation == generation && result.route.serverId == 1);
    auto reused = directory->Observe(syn.tuple, std::make_shared<const SocketOwner>(
        SocketOwner{differentInstance, 145558, 150, false, SocketOrigin::Connect}), now);
    assert(flows.Lookup(ack, 160, now).action == FlowTable::Action::Wait);
    assert(flows.Lookup(syn, 160, now).action == FlowTable::Action::Classify);
    assert(flows.Commit(syn, 160, {{}, reused}, now));
    result = flows.Lookup(ack, 161, now);
    assert(result.action == FlowTable::Action::Send && result.generation != generation);
    assert(result.route.kind == FlowRoute::Kind::Direct && result.owner == reused);
}

int main() {
    TestDelayedConnect(0, true, false);
    TestDelayedConnect(145541, true, false);
    TestDelayedConnect(123, true, false);
    TestDelayedConnect(0, false, false);
    TestDelayedConnect(0, true, true);
    auto sockets = std::make_unique<SocketDirectory>();
    FlowTable flows(*sockets);
    auto now = Clock::now();
    const auto process = std::make_shared<const ProcessIdentity>(100, [] {return true;}, [] {return "app.exe";});
    const auto system = std::make_shared<const ProcessIdentity>(4, [] {return true;}, [] {return "System";});
    PacketView packet;
    packet.tuple = {6, 0xc0000201, 5000, 0xcb007101, 443};
    packet.syn = true;
    packet.tcp = {123, 0, 2};
    auto owner = sockets->Observe(packet.tuple, std::make_shared<const SocketOwner>(SocketOwner{process, 1, 100}), now);
    assert(owner);
    assert(!sockets->Observe(packet.tuple, std::make_shared<const SocketOwner>(SocketOwner{system, 2, 110}), now));
    assert(flows.Commit(packet, 120, {{FlowRoute::Kind::Tunnel, 1, 0}, owner}, now));
    sockets->Close(packet.tuple, 1, 100, 200, now);
    assert(flows.Lookup(packet, 210, now).action == FlowTable::Action::Send);
    sockets->Cleanup(now + std::chrono::seconds(31));
    assert(!owner->activity->present);
    assert(flows.Lookup(packet, 220, now + std::chrono::seconds(31)).action == FlowTable::Action::Send);
    ++packet.tcp.sequence;
    assert(flows.Lookup(packet, 230, now + std::chrono::seconds(31)).action == FlowTable::Action::Wait);
    packet.syn = false; packet.tcp.flags = 16;
    for (int i = 1; i <= 10; ++i)
        assert(flows.Lookup(packet, 230 + i, now + std::chrono::seconds(45 * i)).action == FlowTable::Action::Send);
    auto wildcard = packet.tuple; wildcard.localIp = 0;
    auto next = sockets->Observe(wildcard, std::make_shared<const SocketOwner>(SocketOwner{process, 3, 500}), now);
    assert(flows.Lookup(packet, 510, now).action == FlowTable::Action::Wait);
    packet.syn = true; packet.tcp.flags = 2; packet.tcp.sequence = 123;
    assert(flows.Lookup(packet, 510, now).action == FlowTable::Action::Classify);
    assert(flows.Commit(packet, 510, {{FlowRoute::Kind::Direct, 0, 0}, next}, now));
    sockets->Close(wildcard, 1, 100, 600, now);
    assert(sockets->Find(packet.tuple, 610, true, now)->id == next->id);
    assert(flows.Lookup(packet, 610, now).route.kind == FlowRoute::Kind::Direct);
    packet.syn = false; packet.tcp.flags = 4;
    assert(flows.Lookup(packet, 620, now).action == FlowTable::Action::Send);
    flows.Cleanup(now + std::chrono::minutes(4));
    assert(flows.Size() == 0);
    auto probingSockets = std::make_unique<SocketDirectory>();
    FlowTable probingFlows(*probingSockets);
    std::vector<SocketDirectory::Probe> ownerProbes;
    std::vector<FlowTable::Probe> routeProbes;
    probingSockets->SetProbeHandler([&](auto probes) {ownerProbes = std::move(probes); return true;});
    probingFlows.SetProbeHandler([&](auto probes) {routeProbes = std::move(probes); return true;});
    packet.syn = true; packet.tcp = {1000, 0, 2};
    auto probeOwner = probingSockets->Observe(packet.tuple,
        std::make_shared<const SocketOwner>(SocketOwner{process, 50, 1000}), now);
    assert(probingFlows.Commit(packet, 1001, {{FlowRoute::Kind::Tunnel, 1, 0}, probeOwner}, now));
    const auto idle = now + std::chrono::minutes(125);
    probingSockets->Cleanup(idle); probingFlows.Cleanup(idle);
    assert(ownerProbes.size() == 1 && routeProbes.size() == 1);
    probingSockets->Probed(ownerProbes[0], std::nullopt, idle);
    probingFlows.Probed(routeProbes[0], std::nullopt, idle);
    assert(probingFlows.Size() == 1 && probeOwner->activity->present);
    packet.syn = false; packet.tcp.flags = 16;
    assert(probingFlows.Lookup(packet, 1002, idle).action == FlowTable::Action::Send);
    probingSockets->Probed(ownerProbes[0], false, idle);
    probingFlows.Probed(routeProbes[0], false, idle);
    assert(probingFlows.Size() == 1 && probeOwner->activity->present);
    const auto idleAgain = idle + std::chrono::minutes(125);
    probingSockets->Cleanup(idleAgain); probingFlows.Cleanup(idleAgain);
    probingSockets->Probed(ownerProbes[0], false, idleAgain);
    probingFlows.Probed(routeProbes[0], false, idleAgain);
    assert(!probeOwner->activity->present && probingFlows.Size() == 0);
    auto seedSockets = std::make_unique<SocketDirectory>(); FlowTable seeded(*seedSockets);
    auto seedOwner = seedSockets->Observe(packet.tuple,
        std::make_shared<const SocketOwner>(SocketOwner{process, 60, 1100}), now);
    seeded.Seed(packet.tuple, 1200, now);
    packet.syn = true; packet.tcp = {333, 0, 2};
    assert(seeded.Lookup(packet, 1300, now).action == FlowTable::Action::Send);
    assert(seeded.Lookup(packet, 1300, now).route.kind == FlowRoute::Kind::Direct);
    auto seededNext = seedSockets->Observe(packet.tuple,
        std::make_shared<const SocketOwner>(SocketOwner{process, 61, 1400}), now);
    assert(seeded.Lookup(packet, 1500, now).action == FlowTable::Action::Classify);
    std::vector<uint8_t> truncated(80, 0);
    PacketView parsed;
    for (size_t length = 0; length < truncated.size(); ++length) assert(!parsed.Read(truncated.data(), length));
    truncated[0] = 0x45; truncated[3] = 40; truncated[9] = 6; truncated[32] = 0x50;
    assert(parsed.Read(truncated.data(), 40)); truncated[6] = 0x20;
    assert(!parsed.Read(truncated.data(), 40));
    {
        auto owners = std::make_unique<SocketDirectory>(); FlowTable routes(*owners);
        PacketView tcpPacket; tcpPacket.tuple = {6, 0xc0000201, 6000, 0xcb007101, 443};
        tcpPacket.syn = true; tcpPacket.tcp = {123, 0, 2};
        auto tcpOwner = owners->Observe(tcpPacket.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{process, 70, 100}), now);
        assert(routes.Commit(tcpPacket, 110, {{FlowRoute::Kind::Tunnel, 7, 0}, tcpOwner}, now));
        tcpPacket.syn = false; tcpPacket.tcp.flags = 17;
        assert(routes.Lookup(tcpPacket, 120, now).action == FlowTable::Action::Send);
        routes.Cleanup(now + std::chrono::minutes(4)); assert(routes.Size() == 1);
        auto reply = tcpPacket; reply.tuple = tcpPacket.IncomingTuple();
        routes.Inbound(reply, 130, 7, now + std::chrono::minutes(5));
        routes.Cleanup(now + std::chrono::minutes(9)); assert(routes.Size() == 0);
        tcpPacket.syn = true; tcpPacket.tcp.flags = 2;
        assert(routes.Commit(tcpPacket, 140, {{FlowRoute::Kind::Tunnel, 7, 0}, tcpOwner}, now));
        routes.Inbound(reply, 150, 8, now + std::chrono::minutes(123));
        routes.Cleanup(now + std::chrono::minutes(124)); assert(routes.Size() == 0);
        PacketView udp; udp.tuple = {17, 0xc0000201, 7000, 0xcb007101, 443};
        auto udpOwner = owners->Observe(udp.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{process, 80, 200}), now);
        auto peer = udp; ++peer.tuple.remoteIp;
        assert(owners->Find(peer.tuple, 210, false, now) == udpOwner);
        assert(routes.Commit(udp, 210, {{FlowRoute::Kind::Tunnel, 7, 0}, udpOwner}, now));
        assert(routes.Commit(peer, 210, {{}, udpOwner}, now));
        owners->Close(udp.tuple, 80, 100, 220, now);
        assert(routes.Expire(udp, 230, now).action == FlowTable::Action::Drop);
        owners->Cleanup(now + std::chrono::seconds(31));
        auto replacement = owners->Observe(udp.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{process, 81, 240}), now + std::chrono::seconds(31));
        assert(routes.Commit(udp, 250, {{FlowRoute::Kind::Tunnel, 7, 0}, replacement}, now + std::chrono::seconds(31)));
        routes.Servers({});
        assert(routes.Lookup(udp, 260, now + std::chrono::seconds(32)).route.kind == FlowRoute::Kind::Unavailable);
        routes.Cleanup(now + std::chrono::minutes(21)); assert(routes.Size() == 0);
    }
    Mailbox<int, 2> queue;
    assert(queue.TryPush(1) && queue.TryPush(2) && !queue.TryPush(3));
    int value = 0;
    assert(queue.Pop(value) && value == 1);
    assert(queue.Pop(value) && value == 2);
    assert(WaitForSingleObject(queue.Event(), 0) == WAIT_TIMEOUT);
    queue.Close(); assert(!queue.TryPush(3));
    queue.Reset(); assert(queue.TryPush(3) && queue.Pop(value) && value == 3);
    assert(queue.TryPush(1) && queue.TryPush(2));
    auto blocked = std::async(std::launch::async, [&] {return queue.Push(3);});
    assert(blocked.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
    queue.Close(); assert(!blocked.get());
    std::cout << "Runtime state tests passed\n";
}
