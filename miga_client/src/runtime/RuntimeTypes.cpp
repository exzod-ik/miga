#include "runtime/RuntimeTypes.h"

namespace miga::runtime {
int64_t Millis(Clock::time_point now) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

uint32_t PortKey(const SocketTuple& tuple) {
    return (uint32_t(tuple.protocol == 17) << 16) | tuple.localPort;
}

bool Exact(const SocketTuple& a, const SocketTuple& b) {
    return FlowKey::From(a) == FlowKey::From(b);
}

bool Matches(const SocketTuple& owner, const SocketTuple& packet) {
    return owner.protocol == packet.protocol && owner.localPort == packet.localPort &&
        (!owner.localIp || owner.localIp == packet.localIp) &&
        (owner.protocol == 17 || ((!owner.remoteIp || owner.remoteIp == packet.remoteIp) &&
            (!owner.remotePort || owner.remotePort == packet.remotePort)));
}

bool PacketView::Read(const uint8_t* data, size_t size) {
    if (!ReadSocketPacket(data, size, tuple, syn, &tcp)) return false;
    if ((data[6] & 0x20) != 0) return false;
    header = size_t(data[0] & 15) * 4;
    length = (size_t(data[2]) << 8) | data[3];
    return true;
}

SocketTuple PacketView::IncomingTuple() const {
    return {tuple.protocol, tuple.remoteIp, tuple.remotePort, tuple.localIp, tuple.localPort};
}

void SocketActivity::Touch(int64_t now) {
    auto previous = lastSeen.load(std::memory_order_relaxed);
    while (previous < now && !lastSeen.compare_exchange_weak(previous, now, std::memory_order_relaxed)) {}
}

bool SocketRecord::Eligible(const SocketTuple& packet, int64_t timestamp, bool syn, int64_t now) const {
    if (!activity->present.load() || !Matches(tuple, packet) || owner->timestamp > timestamp) return false;
    const auto cutoff = activity->cutoff.load();
    if (cutoff && timestamp >= cutoff) return false;
    const auto closed = activity->closed.load();
    if (closed) {
        if (now - activity->retired.load() >= 30000) return false;
        if (timestamp > closed && (syn || packet.protocol != 6 || !Exact(tuple, packet))) return false;
    }
    else if (packet.protocol == 17 && now - activity->lastSeen.load() >= 1200000) return false;
    return true;
}

}
