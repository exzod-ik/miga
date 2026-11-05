#include "runtime/RuntimeMailbox.h"
#include "Ipv4Batch.h"
#include "PacketTypes.h"
#include <cassert>
#include <future>
#include <iostream>
#include <memory>
#include <vector>
#include <thread>

using namespace std::chrono_literals;
void Require(bool condition, const char* message) {
    if (!condition) { std::cerr << message << '\n'; std::abort(); }
}

void TestBatchBoundaries() {
    std::vector<uint8_t> data(20 + 60 + 65535, 0);
    size_t offset = 0;
    for (size_t length : {size_t(20), size_t(60), size_t(65535)}) {
        data[offset] = 0x45;
        data[offset + 2] = static_cast<uint8_t>(length >> 8);
        data[offset + 3] = static_cast<uint8_t>(length);
        offset += length;
    }
    offset = 0;
    for (size_t length : {size_t(20), size_t(60), size_t(65535)}) {
        Require(Ipv4BatchPacketLength(data.data(), data.size(), offset) == length, "mixed packet lengths including maximum IPv4 packet");
        offset += length;
    }
    Require(Ipv4BatchPacketLength(data.data(), data.size(), offset) == 0, "batch end");
    Require(Ipv4BatchPacketLength(data.data(), data.size(), offset + 1) == 0, "offset outside batch");
    Require(Ipv4BatchPacketLength(data.data(), data.size() - 1, 80) == 0, "truncated final packet");
    for (size_t size = 0; size < 20; ++size)
        Require(Ipv4BatchPacketLength(data.data(), size, 0) == 0, "short header");
    data[0] = 0x46;
    Require(Ipv4BatchPacketLength(data.data(), data.size(), 0) == 0, "IHL exceeds total length");
    data[0] = 0x44;
    Require(Ipv4BatchPacketLength(data.data(), data.size(), 0) == 0, "invalid IHL");
    data[0] = 0x65;
    Require(Ipv4BatchPacketLength(data.data(), data.size(), 0) == 0, "unexpected IPv6");
    Require(Ipv4BatchPacketLength(nullptr, 20, 0) == 0, "null buffer");
}


int main() {
    TestBatchBoundaries();
    miga::runtime::Mailbox<std::unique_ptr<int>, 1> queue;
    assert(queue.Push(std::make_unique<int>(1)));
    auto next = std::make_unique<int>(2); auto* identity = next.get();
    auto producer = std::async(std::launch::async, [&] { return queue.Push(std::move(next)); });
    assert(producer.wait_for(20ms) == std::future_status::timeout);
    std::unique_ptr<int> item;
    assert(queue.Pop(item) && *item == 1);
    assert(producer.wait_for(2s) == std::future_status::ready && producer.get());
    assert(queue.Pop(item) && *item == 2 && item.get() == identity);
    assert(queue.Push(std::make_unique<int>(3)));
    std::this_thread::sleep_for(120ms);
    assert(queue.Pop(item));
    const auto delay = queue.TakeDelay();
    assert(delay.count >= 1 && delay.maxMs >= 100 && delay.maxDepth == 1);
    assert(queue.TakeDelay().count == 0);
    assert(queue.Push(std::make_unique<int>(4)));
    queue.Close(); assert(!queue.Pop(item) && !queue.Push(std::make_unique<int>(5)));
    queue.Reset(); assert(!queue.Pop(item));
    assert(WaitForSingleObject(queue.Event(), 0) == WAIT_TIMEOUT);
    miga::runtime::Mailbox<int, 16> transfer;
    auto sending = std::async(std::launch::async, [&] {
        for (int i = 0; i < 10000; ++i) assert(transfer.Push(i));
    });
    for (int expected = 0; expected < 10000; ++expected) {
        int received = -1;
        while (!transfer.Pop(received)) assert(WaitForSingleObject(transfer.Event(), 2000) == WAIT_OBJECT_0);
        assert(received == expected);
    }
    assert(sending.wait_for(2s) == std::future_status::ready); sending.get();
    std::vector<uint8_t> packet(44, 0);
    packet[0] = 0x46; packet[3] = 44; packet[9] = 6; packet[36] = 0x50; packet[37] = 2;
    packet[25] = 42; packet[27] = 80; packet[31] = 17; packet[35] = 19;
    SocketTuple tuple; TcpPacketState tcp; bool syn = false;
    assert(ReadSocketPacket(packet.data(), packet.size(), tuple, syn, &tcp));
    assert(syn && tuple.localPort == 42 && tuple.remotePort == 80 && tcp.sequence == 17 && tcp.acknowledgment == 19);
    for (size_t length = 0; length < packet.size(); ++length) assert(!ReadSocketPacket(packet.data(), length, tuple, syn));
    packet[36] = 0x40; assert(!ReadSocketPacket(packet.data(), packet.size(), tuple, syn));
    packet[36] = 0x60; assert(!ReadSocketPacket(packet.data(), packet.size(), tuple, syn));
    assert(!ReadSocketPacket(nullptr, 44, tuple, syn));
    std::cout << "Runtime mailbox, packet parsing and batch tests passed\n";
}
