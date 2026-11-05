#pragma once

#include <winsock2.h>
#include <windivert.h>
#include "../PacketTypes.h"
#include "../ProcessIdentityCache.h"
#include "../DeadlineIndex.h"
#include <algorithm>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <atomic>
#include <deque>
#include <optional>

namespace miga::runtime {
using Clock = std::chrono::steady_clock;
int64_t Millis(Clock::time_point now);
uint32_t PortKey(const SocketTuple& tuple);
bool Exact(const SocketTuple& a, const SocketTuple& b);
bool Matches(const SocketTuple& owner, const SocketTuple& packet);
struct PacketView {
    SocketTuple tuple;
    TcpPacketState tcp;
    bool syn = false;
    size_t header = 0;
    size_t length = 0;
    bool Read(const uint8_t* data, size_t size);
    SocketTuple IncomingTuple() const;
};
struct Packet {
    std::shared_ptr<std::vector<uint8_t>> bytes;
    WINDIVERT_ADDRESS address{};
    PacketView view;
    Clock::time_point received;
};
struct SocketActivity {
    std::atomic<int64_t> lastSeen{0};
    std::atomic<int64_t> closed{0};
    std::atomic<int64_t> retired{0};
    std::atomic<int64_t> cutoff{0};
    std::atomic<bool> present{true};
    std::atomic<uint64_t> probeVersion{0};
    void Touch(int64_t now);
};
struct SocketRecord {
    uint64_t id = 0;
    SocketTuple tuple;
    std::shared_ptr<const SocketOwner> owner;
    std::shared_ptr<SocketActivity> activity;
    int64_t lastEvent = 0;
    bool Eligible(const SocketTuple& packet, int64_t timestamp, bool syn, int64_t now) const;
};
using OwnerRecord = std::shared_ptr<const SocketRecord>;
struct RouteDecision {
    FlowRoute route;
    OwnerRecord owner;
    uint64_t configVersion = 0;
    uint64_t request = 0;
};
}
