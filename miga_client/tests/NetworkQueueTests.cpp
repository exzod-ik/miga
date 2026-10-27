#include "BoundedQueue.h"
#include "Ipv4Batch.h"
#include "EventQueueDelay.h"
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <vector>

using namespace std::chrono_literals;

void Require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

void TestBackpressure() {
    BoundedQueue<std::unique_ptr<int>, 1> queue;
    Require(queue.Push(std::make_unique<int>(1)), "first push");
    auto second = std::make_unique<int>(2);
    auto* identity = second.get();
    auto producer = std::async(std::launch::async, [&] { return queue.Push(std::move(second)); });
    Require(producer.wait_for(50ms) == std::future_status::timeout, "full queue must block producer");
    std::unique_ptr<int> item;
    Require(queue.Pop(item) && *item == 1, "FIFO first packet");
    Require(producer.wait_for(2s) == std::future_status::ready && producer.get(), "producer wakes after pop");
    Require(queue.Pop(item) && *item == 2 && item.get() == identity, "batch ownership transferred without copying");
    queue.Close();
}

void TestStopAndRestart() {
    BoundedQueue<int, 1> queue;
    auto consumer = std::async(std::launch::async, [&] { int item; return queue.Pop(item); });
    Require(consumer.wait_for(50ms) == std::future_status::timeout, "empty queue blocks consumer");
    queue.Close();
    Require(consumer.wait_for(2s) == std::future_status::ready && !consumer.get(), "stop wakes consumer");
    queue.Reset();
    Require(queue.Push(1), "reset opens queue");
    auto producer = std::async(std::launch::async, [&] { return queue.Push(2); });
    Require(producer.wait_for(50ms) == std::future_status::timeout, "producer waiting on full queue");
    queue.Close();
    Require(producer.wait_for(2s) == std::future_status::ready && !producer.get(), "stop wakes producer");
    int item = 0;
    Require(!queue.Pop(item) && !queue.Push(3), "closed queue refuses operations");
    queue.Reset();
    Require(queue.Push(4) && queue.Pop(item) && item == 4, "restart clears stale packets");
    queue.Close();
}

void TestConcurrentOrder() {
    BoundedQueue<int, 16> queue;
    auto producer = std::async(std::launch::async, [&] {
        for (int i = 0; i < 10000; ++i)
            if (!queue.Push(int(i))) return false;
        return true;
    });
    auto consumer = std::async(std::launch::async, [&] {
        for (int i = 0; i < 10000; ++i) {
            int value;
            if (!queue.Pop(value) || value != i) return false;
        }
        return true;
    });
    Require(consumer.wait_for(10s) == std::future_status::ready && consumer.get(), "concurrent transfer preserves order without loss");
    Require(producer.wait_for(2s) == std::future_status::ready && producer.get(), "producer completed");
    queue.Close();
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

void TestQueueDelay() {
    using Clock = std::chrono::steady_clock;
    struct Item { Clock::time_point queuedAt; int value = 0; };
    BoundedQueue<Item, 1> queue;
    Item first{{}, 1};
    Require(queue.Push(std::move(first), &first.queuedAt), "timestamped first push");
    Item second{{}, 2};
    auto producer = std::async(std::launch::async, [&] {
        return queue.Push(std::move(second), &second.queuedAt);
    });
    Require(producer.wait_for(50ms) == std::future_status::timeout, "timestamped push waits for space");
    const auto releasedAt = Clock::now();
    Item received;
    size_t depth = 99;
    Require(queue.PopUntil(received, Clock::now() + 2s, &depth) == decltype(queue)::WaitResult::Item &&
        depth == 1 && received.value == 1, "depth includes removed event");
    Require(producer.get(), "timestamped producer succeeds");
    Require(queue.PopUntil(received, Clock::now() + 2s, &depth) == decltype(queue)::WaitResult::Item &&
        received.value == 2 && received.queuedAt >= releasedAt, "queue age excludes producer backpressure");
    Require(queue.PopUntil(received, Clock::now(), &depth) == decltype(queue)::WaitResult::Timeout &&
        depth == 0, "timeout clears depth");
    queue.Close();
    Require(queue.PopUntil(received, Clock::now(), &depth) == decltype(queue)::WaitResult::Closed &&
        depth == 0, "closed queue clears depth");
    EventQueueDelay delays;
    std::vector<std::string> messages;
    const auto write = [&](const std::string& message) { messages.push_back(message); };
    delays.Record(EventQueueDelay::Type::Network, 99ms, 256);
    delays.Flush(write);
    Require(messages.empty(), "subthreshold events omitted");
    delays.Record(EventQueueDelay::Type::Network, 100ms, 2);
    delays.Record(EventQueueDelay::Type::Network, 350ms, 1);
    delays.Record(EventQueueDelay::Type::Socket, 200ms, 3);
    delays.Record(EventQueueDelay::Type::Control, 150ms, 4);
    delays.Flush(write);
    Require(messages.size() == 3 && messages[0] ==
        "event_queue_delay type=NETWORK count=2 max_wait_ms=350 max_queue_depth_at_pop=2 threshold_ms=100",
        "delay counts and maxima aggregate by type");
    Require(messages[1].find("type=SOCKET count=1") != std::string::npos &&
        messages[2].find("type=CONTROL count=1") != std::string::npos, "socket and control categories");
    delays.Flush(write);
    Require(messages.size() == 3, "flush resets counters");
    delays.Record(EventQueueDelay::Type::Socket, 500ms, 1);
    delays.Clear();
    delays.Flush(write);
    Require(messages.size() == 3, "restart clears counters");
}

int main() {
    TestQueueDelay();
    TestBackpressure();
    TestStopAndRestart();
    TestConcurrentOrder();
    TestBatchBoundaries();
    std::cout << "Network queue tests passed\n";
}
