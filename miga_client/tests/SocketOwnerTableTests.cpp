#include "SocketOwnerTable.h"
#include <cassert>
#include <iostream>
#include <vector>

int main() {
    const auto now = SocketOwnerTable::Clock::now();
    auto process = std::make_shared<const ProcessIdentity>(10, [] { return true; }, [] { return "game.exe"; });
    auto other = std::make_shared<const ProcessIdentity>(11, [] { return true; }, [] { return "other.exe"; });
    auto a = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 100});
    auto b = std::make_shared<const SocketOwner>(SocketOwner{other, 2, 300});
    SocketTuple tuple{6, 0xc0000201, 5000, 0xc6336401, 443};
    auto system = std::make_shared<const ProcessIdentity>(4, [] { return true; }, [] { return "System"; });
    auto systemOwner = std::make_shared<const SocketOwner>(SocketOwner{system, 55, 200});
    {
        SocketOwnerTable history;
        std::vector<SocketOwnerTable::Change> changes;
        history.SetChangeHandler([&](const auto& change) { changes.push_back(change); });
        auto wildcard = tuple;
        wildcard.localIp = 0;
        history.Update(wildcard, a, now);
        assert(changes.size() == 1 && std::string(changes.back().event) == "socket_owner_added");
        assert(changes.back().state.owner == a && changes.back().state.owner->timestamp == 100);
        assert(history.Find(tuple, 150, false, now) == a);
        assert(std::string(changes.back().reason) == "local_address_resolved");
        assert(changes.back().previous->tuple.localIp == 0);
        assert(changes.back().state.tuple.localIp == tuple.localIp);
        auto count = changes.size();
        SocketOwnerTable::LookupCache cache;
        assert(history.Find(tuple, 160, false, now, &cache) == a);
        assert(history.Find(tuple, 170, false, now, &cache) == a);
        assert(!history.Update(tuple, systemOwner, now));
        history.Close(6, tuple.localPort, 999, 180, now);
        assert(changes.size() == count);
        auto update = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 180});
        history.Update(tuple, update, now);
        assert(changes.back().state.owner == a);
        assert(changes.back().previous->lastEvent == 100 && changes.back().state.lastEvent == 180);
        history.Close(6, tuple.localPort, 1, 200, now);
        assert(std::string(changes.back().event) == "socket_owner_closed");
        assert(changes.back().previous->closedAt == 0 && changes.back().state.closedAt == 200);
        assert(!history.Find(tuple, 250, true, now));
        assert(std::string(changes.back().reason) == "syn_after_close");
        assert(changes.back().previous->cutoff == 0 && changes.back().state.cutoff == 250);
        history.Cleanup(now + std::chrono::seconds(30));
        assert(std::string(changes.back().reason) == "close_grace_expired" && history.Size() == 0);
        history.Update(tuple, a, now);
        history.Update(tuple, b, now);
        assert(std::string(changes[changes.size() - 2].reason) == "generation_replaced");
        assert(changes[changes.size() - 2].state.cutoff == 300);
        history.Cleanup(now + std::chrono::minutes(124));
        assert(std::string(changes.back().reason) == "idle_timeout" && history.Size() == 0);
        auto snapshot = std::make_shared<const SocketOwner>(SocketOwner{process, 3, 400, true});
        history.Update(tuple, snapshot, now);
        assert(std::string(changes.back().reason) == "snapshot");
        history.CloseSnapshot(tuple, 10, 500, now);
        assert(std::string(changes.back().reason) == "snapshot_close");
        history.Clear();
        assert(std::string(changes.back().reason) == "clear");
        for (size_t i = 0; i < changes.size(); ++i) assert(changes[i].sequence == i + 1);
        const auto message = changes[2].Describe();
        assert(message.find("previous_state=\"") != std::string::npos);
        assert(message.find("process=\"game.exe\"") != std::string::npos);
        assert(message.find("owner_timestamp_qpc=100") != std::string::npos);
        SocketOwnerTable bounded(1);
        size_t evictions = 0;
        size_t removals = 0;
        bounded.SetEvictionHandler([&](const auto& entry) {
            ++evictions;
            assert(entry.owner == a);
            assert(entry.Describe().find("socket_owner_evicted reason=capacity") == 0);
        });
        bounded.SetChangeHandler([&](const auto& change) {
            if (std::string(change.event) == "socket_owner_removed") ++removals;
        });
        bounded.Update(tuple, a, now);
        bounded.Update(tuple, b, now);
        assert(evictions == 1 && removals == 0);
    }
    for (uint8_t protocol : {uint8_t(6), uint8_t(17)}) {
        SocketOwnerTable guarded(1);
        SocketOwnerTable::LookupCache cache;
        auto flow = tuple; flow.protocol = protocol;
        assert(guarded.Update(flow, a, now) == a);
        assert(guarded.Find(flow, 150, false, now, &cache) == a);
        assert(!guarded.Update(flow, systemOwner, now));
        assert(guarded.Size() == 1);
        assert(guarded.Find(flow, 250, false, now, &cache) == a);
        auto peer = flow; peer.remoteIp++;
        assert(!guarded.Update(peer, systemOwner, now));
        assert(guarded.Find(flow, 260, false, now) == a);
        guarded.Close(protocol, flow.localPort, 55, 270, now);
        assert(guarded.Find(flow, 280, false, now) == a);
        assert(guarded.Update(flow, b, now) == b);
        assert(guarded.Find(flow, 310, false, now) == b);
        guarded.Close(protocol, flow.localPort, 2, 400, now);
        assert(!guarded.Update(flow, systemOwner, now + std::chrono::seconds(29)));
        assert(guarded.Update(flow, systemOwner, now + std::chrono::seconds(30)) == systemOwner);
        guarded.Clear();
        assert(guarded.Update(flow, systemOwner, now) == systemOwner);
        assert(guarded.Find(flow, 250, false, now) == systemOwner);
        guarded.Clear();
        guarded.Update(flow, a, now);
        auto independent = flow; independent.protocol = protocol == 6 ? 17 : 6;
        assert(guarded.Update(independent, systemOwner, now) == systemOwner);
        guarded.Clear();
        guarded.Update(flow, a, now);
        assert(guarded.Update(flow, systemOwner,
            now + std::chrono::minutes(protocol == 6 ? 124 : 20)) == systemOwner);
    }
    SocketOwnerTable table;
    assert(!table.Find(tuple, 110, true, now));
    assert(table.Update(tuple, a, now) == a);
    assert(table.Find(tuple, 110, true, now) == a);
    assert(!table.Find(tuple, 99, false, now));
    table.Close(6, 5000, 99, 200, now);
    assert(table.Find(tuple, 210, false, now) == a);
    table.Close(6, 5000, 1, 200, now);
    assert(table.Find(tuple, 150, false, now) == a);
    assert(table.Find(tuple, 250, false, now) == a);
    auto different = tuple;
    different.remoteIp++;
    assert(!table.Find(different, 250, false, now));
    assert(!table.Find(tuple, 270, true, now));
    assert(!table.Find(tuple, 280, false, now));
    assert(table.Find(tuple, 260, false, now) == a);
    assert(table.Update(tuple, b, now) == b);
    assert(table.Find(tuple, 310, false, now) == b);
    assert(table.Find(tuple, 150, false, now) == a);
    table.Close(6, 5000, 1, 400, now);
    assert(table.Find(tuple, 410, false, now) == b);
    auto parallel = std::make_shared<const SocketOwner>(SocketOwner{process, 3, 350});
    table.Update(different, parallel, now);
    assert(table.Find(tuple, 420, false, now) == b);
    assert(table.Find(different, 420, false, now) == parallel);
    table.Cleanup(now + std::chrono::seconds(31));
    assert(table.Size() == 2);
    assert(!table.Find(tuple, 150, false, now + std::chrono::seconds(31)));
    table.Clear();
    assert(table.Size() == 0);

    SocketTuple udp{17, 0, 5000, 0, 0};
    table.Update(udp, a, now);
    auto udpPacket = tuple; udpPacket.protocol = 17;
    assert(table.Find(udpPacket, 150, false, now) == a);
    table.Close(17, 5000, 1, 200, now);
    assert(table.Find(udpPacket, 150, false, now) == a);
    assert(!table.Find(udpPacket, 201, false, now));
    table.Update(udp, b, now);
    assert(table.Find(udpPacket, 310, false, now) == b);
    assert(table.Find(udpPacket, 150, false, now) == a);
    table.Clear();

    SocketOwnerTable udpPeers;
    udpPeers.Update(udp, a, now);
    auto udpConnect = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 120});
    auto udpPeer2 = udpPacket; udpPeer2.remoteIp++; udpPeer2.remotePort++;
    udpPeers.Update(udpPacket, udpConnect, now);
    assert(udpPeers.Find(udpPeer2, 130, false, now) == a);
    auto udpConnect2 = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 140});
    udpPeers.Update(udpPeer2, udpConnect2, now);
    assert(udpPeers.Find(udpPacket, 150, false, now) == a);
    assert(udpPeers.Find(udpPacket, 110, false, now) == a);
    assert(udpPeers.Size() == 1);
    udpPeers.Close(17, 5000, 1, 160, now);
    assert(!udpPeers.Find(udpPacket, 170, false, now));
    assert(!udpPeers.Find(udpPeer2, 170, false, now));
    udpPeers.Update(udpPeer2, b, now);
    assert(udpPeers.Find(udpPacket, 310, false, now) == b);
    assert(!udpPeers.Find(udpPacket, 290, false, now));
    assert(udpPeers.Find(udpPacket, 150, false, now) == a);

    SocketOwnerTable udpWithoutBind;
    udpWithoutBind.Update(udpPacket, a, now);
    udpWithoutBind.Update(udpPeer2, udpConnect, now);
    assert(udpWithoutBind.Find(udpPacket, 150, false, now) == a);
    assert(udpWithoutBind.Find(udpPeer2, 150, false, now) == a);
    auto udpOtherInterface = udpPacket; udpOtherInterface.localIp++;
    assert(!udpWithoutBind.Find(udpOtherInterface, 150, false, now));

    for (uint16_t port = 10000; port < 15000; ++port) {
        auto peer = udpPacket; peer.remotePort = port;
        auto event = std::make_shared<const SocketOwner>(SocketOwner{process, 1, port});
        assert(udpWithoutBind.Update(peer, event, now) == a);
        assert(udpWithoutBind.Find(udpPacket, port + 1, false, now) == a);
        assert(udpWithoutBind.Find(peer, port + 1, false, now) == a);
    }
    assert(udpWithoutBind.Size() == 1);

    SocketOwnerTable bounded(2);
    std::vector<SocketOwnerTable::Eviction> evicted;
    bounded.SetEvictionHandler([&](const auto& entry) { evicted.push_back(entry); });
    bounded.Update(tuple, a, now);
    bounded.Update(different, b, now);
    auto third = different; third.remoteIp++;
    bounded.Update(third, parallel, now);
    assert(bounded.Size() == 2);
    assert(evicted.size() == 1);
    assert(evicted[0].owner == a);
    assert(evicted[0].tuple.localIp == tuple.localIp && evicted[0].tuple.remoteIp == tuple.remoteIp);
    assert(evicted[0].tuple.localPort == tuple.localPort && evicted[0].tuple.remotePort == tuple.remotePort);
    assert(evicted[0].capacity == 2 && evicted[0].closedAt == 0);
    const auto evictionText = evicted[0].Describe();
    assert(evictionText.find("socket_owner_evicted reason=capacity protocol=TCP") != std::string::npos);
    assert(evictionText.find("endpoint_id=" + std::to_string(a->endpointId)) != std::string::npos);
    assert(evictionText.find("pid=" + std::to_string(process->pid)) != std::string::npos);
    assert(!bounded.Find(tuple, 450, false, now));
    assert(bounded.Find(different, 450, false, now) == b);
    bounded.Cleanup(now + std::chrono::minutes(125));
    assert(bounded.Size() == 0);
    bounded.Clear();
    assert(evicted.size() == 1);

    SocketOwnerTable binding;
    auto bind = tuple; bind.localIp = 0; bind.remoteIp = 0; bind.remotePort = 0;
    binding.Update(bind, a, now);
    assert(!binding.Find(tuple, 110, true, now));
    auto connect = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 120});
    assert(binding.Update(tuple, connect, now) == a);
    assert(binding.Find(tuple, 125, true, now) == a);
    binding.Close(6, 5000, 1, 115, now);
    assert(binding.Find(tuple, 150, true, now) == a);

    SocketOwnerTable wildcard;
    auto wildcardTuple = tuple; wildcardTuple.localIp = 0;
    wildcard.Update(wildcardTuple, a, now);
    assert(wildcard.Find(tuple, 150, false, now) == a);
    wildcard.Close(6, 5000, 1, 200, now);
    assert(wildcard.Find(tuple, 250, false, now) == a);
    assert(std::string(wildcard.DescribeMiss(different, 250, now)) == "socket_tuple_mismatch");
    assert(std::string(wildcard.DescribeMiss(tuple, 99, now)) == "packet_precedes_socket");
    assert(std::string(wildcard.DescribeMiss(tuple, 250, now)) == "socket_closed");

    for (uint8_t protocol : {uint8_t(6), uint8_t(17)}) {
        SocketOwnerTable cached(2), reference(2);
        SocketOwnerTable::LookupCache cache;
        auto flow = tuple; flow.protocol = protocol;
        auto peer = flow; peer.remoteIp++;
        const auto update = [&](SocketTuple socket, const SocketOwnerTable::Owner& owner) {
            assert(cached.Update(socket, owner, now) == reference.Update(socket, owner, now));
        };
        const auto compare = [&](SocketTuple socket, int64_t timestamp, bool syn, int seconds = 0) {
            const auto at = now + std::chrono::seconds(seconds);
            assert(cached.Find(socket, timestamp, syn, at, &cache) ==
                reference.Find(socket, timestamp, syn, at));
        };
        update(flow, a);
        for (int64_t timestamp = 110; timestamp < 150; ++timestamp) compare(flow, timestamp, false);
        update(flow, b);
        compare(flow, 200, false);
        compare(flow, 250, false);
        compare(flow, 300, false);
        compare(flow, 310, false);
        compare(flow, 150, false);
        compare(peer, 320, false);
        compare(flow, 330, false);
        cached.Close(protocol, 5000, 1, 400, now);
        reference.Close(protocol, 5000, 1, 400, now);
        compare(flow, 420, false);
        cached.Close(protocol, 5000, 2, 450, now);
        reference.Close(protocol, 5000, 2, 450, now);
        compare(flow, 440, false);
        compare(flow, 460, false);
        compare(flow, 470, false);
        compare(flow, 480, protocol == 6);
        compare(flow, 490, false);
        compare(flow, 460, false, 29);
        compare(flow, 460, false, 30);
        cached.Cleanup(now + std::chrono::seconds(31));
        reference.Cleanup(now + std::chrono::seconds(31));
        compare(flow, 440, false, 31);
        update(flow, a);
        compare(flow, 150, false);
        auto anotherPort = flow; anotherPort.localPort++;
        update(anotherPort, b);
        auto thirdPort = flow; thirdPort.localPort += 2;
        update(thirdPort, parallel);
        compare(flow, 160, false);
        cached.Clear(); reference.Clear();
        compare(thirdPort, 400, false);
        update(flow, a);
        compare(flow, 150, false);
        compare(flow, 160, false, protocol == 6 ? 7440 : 1200);
    }

    std::vector<uint8_t> packet(80, 0);
    packet[0] = 0x4f; packet[3] = 80; packet[9] = 6;
    packet[12] = 192; packet[15] = 1; packet[16] = 198; packet[19] = 2;
    packet[60] = 0x13; packet[61] = 0x88; packet[62] = 1; packet[63] = 0xbb;
    packet[72] = 0x50; packet[73] = 2;
    SocketTuple parsed; bool syn = false;
    assert(ReadSocketPacket(packet.data(), packet.size(), parsed, syn));
    assert(parsed.localIp == 0xc0000001 && parsed.remoteIp == 0xc6000002);
    assert(parsed.localPort == 5000 && parsed.remotePort == 443 && syn);
    for (size_t length = 0; length < packet.size(); ++length)
        assert(!ReadSocketPacket(packet.data(), length, parsed, syn));
    packet[7] = 1;
    assert(!ReadSocketPacket(packet.data(), packet.size(), parsed, syn));
    packet[7] = 0; packet[72] = 0x40;
    assert(!ReadSocketPacket(packet.data(), packet.size(), parsed, syn));
    assert(!ReadSocketPacket(nullptr, 80, parsed, syn));
    std::cout << "Socket owner table tests passed\n";
}
