#include "PacketBufferPool.h"
#include <cassert>
#include <thread>
#include <iostream>

int main() {
    PacketBufferPool pool;
    std::vector<uint8_t> packet(1500, 42);
    auto first = pool.Copy(packet.data(), packet.size());
    const auto* address = first->data();
    auto second = pool.Copy(packet.data(), packet.size());
    assert(first->data() != second->data());
    packet[0] = 99;
    assert((*first)[0] == 42);
    first.reset();
    auto reused = pool.Copy(packet.data(), 20);
    assert(reused->data() == address && reused->size() == 20 && (*reused)[0] == 99);
    std::thread release([value = std::move(reused)]() mutable { value.reset(); });
    release.join();
    reused = pool.Copy(packet.data(), packet.size());
    assert(reused->data() == address && reused->size() == 1500);
    packet.resize(65507, 17);
    auto medium = pool.Copy(packet.data(), 2049);
    assert(medium->capacity() == 4096);
    const auto* mediumAddress = medium->data();
    medium.reset();
    medium = pool.Copy(packet.data(), 3000);
    assert(medium->data() == mediumAddress && medium->size() == 3000);
    auto large = pool.Copy(packet.data(), packet.size());
    assert(large->size() == 65507 && large->back() == 17);
    const auto* largeAddress = large->data();
    large.reset();
    large = pool.Copy(packet.data(), packet.size());
    assert(large->data() == largeAddress);
    std::shared_ptr<std::vector<uint8_t>> survivor;
    { PacketBufferPool temporary; survivor = temporary.Copy(packet.data(), packet.size()); }
    assert(survivor->back() == 17);
    survivor.reset();
    std::cout << "Packet buffer pool tests passed\n";
}
