#include "PortPool.h"
#include "ConnectionKey.h"
#include <cstdlib>
#include <iostream>
#include <unordered_set>
#include <unordered_map>

void Require(bool value, const char* message) {
    if (!value) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

int main() {
    auto key = [](uint32_t src, uint16_t srcPort, uint32_t dst, uint16_t dstPort, uint8_t protocol) {
        return ConnectionKey{src, srcPort, dst, dstPort, protocol};
    };
    std::unordered_map<ConnectionKey, int, ConnectionKeyHash> connections;
    connections[key(1, 2, 3, 4, 6)] = 10;
    connections[key(1, 2, 3, 4, 17)] = 20;
    connections[key(1, 2, 3, 5, 6)] = 30;
    connections[key(2, 2, 3, 4, 6)] = 40;
    connections[key(1, 3, 3, 4, 6)] = 50;
    connections[key(1, 2, 4, 4, 6)] = 60;
    Require(connections.size() == 6 && connections.at(key(1, 2, 3, 4, 6)) == 10,
        "connection hash preserves the complete five-tuple");
    std::mt19937 generator(42);
    PortPool pool(1000, 65535);
    std::unordered_set<uint16_t> ports;
    for (size_t i = 0; i < 64536; ++i) {
        auto port = pool.Acquire(generator);
        Require(port && *port >= 1000 && ports.insert(*port).second, "all free ports must be allocated exactly once");
    }
    Require(!pool.Acquire(generator), "exhausted pool");
    pool.Release(12345);
    pool.Release(12345);
    pool.Release(10);
    Require(pool.Acquire(generator) == 12345, "only free port is found without probabilistic failure");
    Require(!pool.Acquire(generator), "duplicate release does not duplicate port");
    for (auto port : ports) pool.Release(port);
    ports.clear();
    for (size_t i = 0; i < 64536; ++i) {
        auto port = pool.Acquire(generator);
        Require(port && ports.insert(*port).second, "pool can be fully reused");
    }
    PortPool tcp(65535, 65535), udp(65535, 65535);
    Require(tcp.Acquire(generator) == 65535 && udp.Acquire(generator) == 65535, "protocol pools are independent");
    PortPool empty(5, 4);
    Require(!empty.Acquire(generator), "invalid interval is empty");
    std::cout << "Port pool tests passed\n";
}
