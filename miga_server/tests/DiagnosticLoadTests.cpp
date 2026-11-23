#include "DiagnosticLoadSocket.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <iostream>

using namespace miga::diagnostics;
using Json = nlohmann::json;
int main() {
    Json settings{{"run", "123456789abcdef0"}, {"step", 1}, {"rate", 100}, {"seconds", 1}, {"direction", 0}, {"bytes", 64}};
    LoadCounters counters; counters.Configure(settings);
    Probe p{0x123456789abcdef0ULL, 1, 99, 0};
    counters.Record(LoadCounters::Captured, p); counters.Record(LoadCounters::Captured, p);
    p.sequence = 0; counters.Record(LoadCounters::Captured, p);
    p.sequence = 100; counters.Record(LoadCounters::Captured, p);
    p.sequence = 1; p.step = 2; counters.Record(LoadCounters::Captured, p);
    p.step = 1; p.direction = 1; counters.Record(LoadCounters::Captured, p);
    auto stats = counters.Snapshot()["captured"];
    assert(stats["unique"] == 2 && stats["duplicates"] == 1 && stats["reordered"] == 1 && stats["seconds"][0] == 2);
    counters.Clear(); p.direction = 0; counters.Record(LoadCounters::Captured, p); assert(counters.Snapshot()["captured"]["unique"] == 0);
    for (const auto& bad : {Json{{"rate", 10001}}, Json{{"seconds", 301}}, Json{{"direction", 3}}, Json{{"run", "not-a-run"}}}) {
        auto invalid = settings; invalid.update(bad); bool rejected = false;
        try { counters.Configure(invalid); } catch (...) { rejected = true; } assert(rejected);
    }
    std::array<uint8_t, 60> packet{}; packet[0] = 0x45; packet[3] = 60; packet[9] = 17; packet[25] = 40;
    p.sequence = 0; WriteProbe(packet.data() + 28, 32, p); Probe decoded;
    assert(ReadProbePacket(packet.data(), packet.size(), decoded));
    assert(!ReadProbePacket(packet.data(), 59, decoded)); packet[6] = 0x20; assert(!ReadProbePacket(packet.data(), packet.size(), decoded)); packet[6] = 0;
    int client = socket(AF_INET, SOCK_DGRAM, 0); assert(client >= 0);
    sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(client, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0);
    socklen_t len = sizeof(local); assert(getsockname(client, reinterpret_cast<sockaddr*>(&local), &len) == 0);
    timeval timeout{2, 0}; setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    settings["local_port"] = ntohs(local.sin_port);
    DiagnosticLoadSocket load; int rules = 0;
    load.firewall = [&](uint16_t port, bool add) { assert(port > 15000); rules += add ? 1 : -1; return true; };
    auto handshake = [&](const Json& parameters) {
        sockaddr_in endpoint{}; endpoint.sin_family = AF_INET; endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK); endpoint.sin_port = htons(parameters["port"].get<uint16_t>());
        std::memcpy(packet.data() + 12, &local.sin_addr.s_addr, 4); std::memcpy(packet.data() + 16, &local.sin_addr.s_addr, 4);
        std::memcpy(packet.data() + 20, &local.sin_port, 2); std::memcpy(packet.data() + 22, &endpoint.sin_port, 2);
        p.direction = 2; WriteProbe(packet.data() + 28, 32, p); load.Observe(packet.data(), packet.size());
        assert(sendto(client, packet.data() + 28, 32, 0, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) == 32);
        uint8_t reply[128]; assert(recv(client, reply, sizeof(reply), 0) == 32);
        return endpoint;
    };
    auto ready = load.Prepare(settings, local.sin_addr.s_addr); assert(ready["receive_buffer"] >= 8388608 && rules == 1);
    auto endpoint = handshake(ready);
    p.direction = 0;
    for (uint32_t i = 0; i < 100; ++i) { p.sequence = 99 - i; WriteProbe(packet.data() + 28, 32, p); assert(sendto(client, packet.data() + 28, 32, 0, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) == 32); }
    for (int i = 0; i < 200 && load.Stats()["stages"]["app_received"]["unique"] != 100; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    assert(load.Stats()["stages"]["app_received"]["unique"] == 100);
    assert(load.Stats()["stages"]["app_received"]["reordered"] == 99);
    load.Stop(); load.Stop(); assert(rules == 0);
    settings["direction"] = 1; settings["step"] = 2; p.step = 2; p.sequence = 0;
    ready = load.Prepare(settings, local.sin_addr.s_addr); endpoint = handshake(ready); assert(load.StartSending()["ok"] == true);
    uint8_t data[128]; int received = 0;
    for (;;) { const auto size = recv(client, data, sizeof(data), 0); if (size < 0) break; assert(ReadProbe(data, size_t(size), decoded) && decoded.step == 2 && decoded.direction == 1); ++received; }
    assert(received >= 90 && received <= 100); assert(load.Stats()["stages"]["app_sent"]["unique"] == received);
    load.Stop(); assert(rules == 0); close(client);
    std::cout << "diagnostic load: limits, unique sequences, stale step, malformed packets, real UDP receiver/sender and cleanup passed\n";
}
