#pragma once

#include "ProcessIdentityCache.h"
#include "../../Shared/LogFormat.h"
#include <algorithm>
#include <cstddef>
#include <functional>
#include <optional>
#include <list>
#include <limits>
#include <unordered_map>

struct SocketTuple {
    uint8_t protocol = 0;
    uint32_t localIp = 0;
    uint16_t localPort = 0;
    uint32_t remoteIp = 0;
    uint16_t remotePort = 0;
};

inline bool ReadSocketPacket(const uint8_t* packet, size_t length, SocketTuple& tuple, bool& syn) {
    if (!packet || length < 20 || (packet[0] >> 4) != 4) return false;
    const size_t ihl = (packet[0] & 15) * 4;
    const size_t total = (size_t(packet[2]) << 8) | packet[3];
    if (ihl < 20 || total > length || total < ihl || (packet[6] & 31) != 0 || packet[7] != 0) return false;
    const auto protocol = packet[9];
    if (protocol != 6 && protocol != 17) return false;
    if (total - ihl < (protocol == 6 ? 20u : 8u)) return false;
    if (protocol == 6) {
        const size_t tcpLength = (packet[ihl + 12] >> 4) * 4;
        if (tcpLength < 20 || tcpLength > total - ihl) return false;
    }
    if (protocol == 17) {
        const size_t udpLength = (size_t(packet[ihl + 4]) << 8) | packet[ihl + 5];
        if (udpLength < 8 || udpLength > total - ihl) return false;
    }
    const auto ip = [&](size_t offset) {
        return (uint32_t(packet[offset]) << 24) | (uint32_t(packet[offset + 1]) << 16) |
            (uint32_t(packet[offset + 2]) << 8) | packet[offset + 3];
    };
    const auto port = [&](size_t offset) {
        return static_cast<uint16_t>((unsigned(packet[offset]) << 8) | packet[offset + 1]);
    };
    tuple = { protocol, ip(12), port(ihl), ip(16), port(ihl + 2) };
    syn = protocol == 6 && (packet[ihl + 13] & 2) != 0;
    return true;
}

class SocketOwnerTable {
    struct Entry;
public:
    struct LookupCache {
    private:
        friend class SocketOwnerTable;
        uint64_t revision = 0;
        std::list<Entry>::iterator entry;
        SocketTuple tuple;
        int64_t from = 0;
        int64_t until = 0;
    };
    using Clock = std::chrono::steady_clock;
    using Owner = std::shared_ptr<const SocketOwner>;

    struct Eviction {
        SocketTuple tuple;
        Owner owner;
        int64_t lastEvent;
        int64_t closedAt;
        int64_t cutoff;
        int64_t idleMs;
        size_t capacity;

        std::string Describe(const char* event = "socket_owner_evicted", const char* reason = "capacity") const {
            const auto address = [](uint32_t ip) {
                return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." +
                    std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
            };
            return std::string(event) + " reason=" + reason + " protocol=" +
                (tuple.protocol == 6 ? "TCP" : "UDP") +
                " local=" + address(tuple.localIp) + ":" + std::to_string(tuple.localPort) +
                " remote=" + address(tuple.remoteIp) + ":" + std::to_string(tuple.remotePort) +
                " pid=" + std::to_string(owner->process->pid) +
                " process=" + LogValue(owner->process->Name()) +
                " endpoint_id=" + std::to_string(owner->endpointId) +
                " snapshot=" + std::to_string(owner->snapshot) +
                " state=" + (closedAt != 0 ? "closed" : "open") +
                " owner_timestamp_qpc=" + std::to_string(owner->timestamp) +
                " last_event_qpc=" + std::to_string(lastEvent) +
                " closed_at_qpc=" + std::to_string(closedAt) +
                " cutoff_qpc=" + std::to_string(cutoff) +
                " idle_ms=" + std::to_string(idleMs) +
                " capacity=" + std::to_string(capacity);
        }
    };
    using EvictionHandler = std::function<void(const Eviction&)>;

    struct Change {
        const char* event;
        const char* reason;
        Eviction state;
        std::optional<Eviction> previous;
        uint64_t sequence;

        std::string Describe() const {
            auto result = state.Describe(event, reason) + " change_sequence=" + std::to_string(sequence);
            if (previous) result += " previous_state=" + LogValue(previous->Describe("socket_owner_state", "before_change"));
            return result;
        }
    };
    using ChangeHandler = std::function<void(const Change&)>;
    void SetChangeHandler(ChangeHandler handler) { onChange_ = std::move(handler); }

    explicit SocketOwnerTable(size_t capacity = 8192) : capacity_(capacity) {}
    void SetEvictionHandler(EvictionHandler handler) { onEviction_ = std::move(handler); }

    Owner Update(SocketTuple tuple, Owner owner, Clock::time_point now) {
        if (capacity_ == 0) return nullptr;
        if (tuple.protocol == 17) {
            tuple.remoteIp = 0;
            tuple.remotePort = 0;
        }
        const auto range = ports_.equal_range(Key(tuple));
        if (owner->process->pid == 4) {
            for (auto it = range.first; it != range.second; ++it) {
                const auto& entry = *it->second;
                if (entry.owner->process->pid != 4 && !Expired(entry, now)) return nullptr;
            }
        }
        ++revision_;
        for (auto it = range.first; it != range.second; ++it) {
            auto& entry = *it->second;
            if (entry.owner->snapshot != owner->snapshot || entry.owner->endpointId != owner->endpointId) continue;
            if (entry.lastEvent > owner->timestamp || entry.closedAt != 0) return nullptr;
            if (entry.owner->process->pid != owner->process->pid) return nullptr;
            const auto previous = Snapshot(entry, now);
            if (tuple.protocol != 17) entry.tuple = tuple;
            entry.lastEvent = owner->timestamp;
            entry.lastSeen = now;
            order_.splice(order_.end(), order_, it->second);
            Notify("socket_owner_updated", "socket_event", entry, now, previous);
            return entry.owner;
        }
        for (auto it = range.first; it != range.second; ++it) {
            auto& entry = *it->second;
            if (SameTuple(entry.tuple, tuple) && entry.owner->timestamp < owner->timestamp) {
                if (entry.cutoff == 0 || owner->timestamp < entry.cutoff) {
                    const auto previous = Snapshot(entry, now);
                    entry.cutoff = owner->timestamp;
                    Notify("socket_owner_updated", "generation_replaced", entry, now, previous);
                }
            }
        }
        while (order_.size() >= capacity_) {
            const auto& entry = order_.front();
            if (onEviction_) onEviction_({ entry.tuple, entry.owner, entry.lastEvent, entry.closedAt,
                entry.cutoff, std::chrono::duration_cast<std::chrono::milliseconds>(now - entry.lastSeen).count(),
                capacity_ });
            Erase(order_.begin());
        }
        order_.push_back({ tuple, owner, owner->timestamp, 0, 0, now, {} });
        ports_.emplace(Key(tuple), std::prev(order_.end()));
        Notify("socket_owner_added", owner->snapshot ? "snapshot" : "socket_event", order_.back(), now);
        return owner;
    }

    void Close(uint8_t protocol, uint16_t port, uint64_t endpoint, int64_t timestamp, Clock::time_point now) {
        ++revision_;
        const auto range = ports_.equal_range((uint32_t(protocol) << 16) | port);
        for (auto it = range.first; it != range.second; ++it) {
            auto& entry = *it->second;
            if (entry.owner->endpointId != endpoint || timestamp < entry.lastEvent || entry.closedAt != 0) continue;
            const auto previous = Snapshot(entry, now);
            entry.closedAt = timestamp;
            entry.lastEvent = timestamp;
            entry.retiredAt = now;
            Notify("socket_owner_closed", "socket_close", entry, now, previous);
        }
    }

    void CloseSnapshot(const SocketTuple& tuple, uint32_t pid, int64_t timestamp, Clock::time_point now) {
        ++revision_;
        const auto range = ports_.equal_range(Key(tuple));
        for (auto it = range.first; it != range.second; ++it) {
            auto& entry = *it->second;
            if (!entry.owner->snapshot || entry.owner->process->pid != pid ||
                timestamp < entry.lastEvent || entry.closedAt != 0) continue;
            if (tuple.localIp && entry.tuple.localIp && tuple.localIp != entry.tuple.localIp) continue;
            if (tuple.protocol == 6 && tuple.remotePort &&
                (tuple.remoteIp != entry.tuple.remoteIp || tuple.remotePort != entry.tuple.remotePort)) continue;
            const auto previous = Snapshot(entry, now);
            entry.closedAt = timestamp;
            entry.lastEvent = timestamp;
            entry.retiredAt = now;
            Notify("socket_owner_closed", "snapshot_close", entry, now, previous);
        }
    }

    Owner Find(const SocketTuple& tuple, int64_t timestamp, bool syn, Clock::time_point now,
        LookupCache* cache = nullptr) {
        if (cache && cache->revision == revision_ && !syn &&
            timestamp >= cache->from && timestamp < cache->until && SameTuple(cache->tuple, tuple)) {
            auto entry = cache->entry;
            if (Key(entry->tuple) == Key(tuple) && Matches(entry->tuple, tuple) && !Expired(*entry, now) &&
                (entry->cutoff == 0 || timestamp < entry->cutoff) &&
                (entry->closedAt == 0 || timestamp <= entry->closedAt ||
                    (tuple.protocol == 6 && SameTuple(entry->tuple, tuple)))) {
                entry->lastSeen = now;
                order_.splice(order_.end(), order_, entry);
                return entry->owner;
            }
        }
        if (cache) cache->revision = 0;
        int64_t until = (std::numeric_limits<int64_t>::max)();
        const auto range = ports_.equal_range(Key(tuple));
        auto best = order_.end();
        for (auto it = range.first; it != range.second; ++it) {
            auto entry = it->second;
            if (!Matches(entry->tuple, tuple)) continue;
            if (entry->owner->timestamp > timestamp) {
                until = (std::min)(until, entry->owner->timestamp);
                continue;
            }
            if (Expired(*entry, now) || (entry->cutoff != 0 && timestamp >= entry->cutoff)) continue;
            if (entry->closedAt != 0 && timestamp > entry->closedAt) {
                if (syn) {
                    if (entry->cutoff == 0 || timestamp < entry->cutoff) {
                        const auto previous = Snapshot(*entry, now);
                        entry->cutoff = timestamp;
                        Notify("socket_owner_updated", "syn_after_close", *entry, now, previous);
                        ++revision_;
                    }
                    continue;
                }
                if (tuple.protocol != 6 || !SameTuple(entry->tuple, tuple)) continue;
            }
            if (best == order_.end() || entry->owner->timestamp > best->owner->timestamp ||
                (entry->owner->timestamp == best->owner->timestamp && entry->tuple.remotePort != 0)) best = entry;
        }
        if (best == order_.end()) return nullptr;
        if (tuple.protocol == 6 && best->tuple.localIp == 0 && best->closedAt == 0) {
            const auto previous = Snapshot(*best, now);
            best->tuple.localIp = tuple.localIp;
            Notify("socket_owner_updated", "local_address_resolved", *best, now, previous);
            ++revision_;
        }
        if (cache) {
            cache->revision = revision_;
            cache->entry = best;
            cache->tuple = tuple;
            cache->from = timestamp;
            cache->until = until;
        }
        best->lastSeen = now;
        order_.splice(order_.end(), order_, best);
        return best->owner;
    }

    bool Touch(const SocketTuple& tuple, const Owner& owner, int64_t timestamp, Clock::time_point now) {
        const auto range = ports_.equal_range(Key(tuple));
        for (auto it = range.first; it != range.second; ++it) {
            auto entry = it->second;
            if (entry->owner != owner || !Matches(entry->tuple, tuple) || Expired(*entry, now) ||
                timestamp < owner->timestamp || (entry->cutoff != 0 && timestamp >= entry->cutoff)) continue;
            if (entry->closedAt != 0 && timestamp > entry->closedAt &&
                (tuple.protocol != 6 || !SameTuple(entry->tuple, tuple))) continue;
            entry->lastSeen = now;
            order_.splice(order_.end(), order_, entry);
            return true;
        }
        return false;
    }

    const char* DescribeMiss(const SocketTuple& tuple, int64_t timestamp, Clock::time_point now) const {
        const auto range = ports_.equal_range(Key(tuple));
        if (range.first == range.second) return "no_socket_record";
        const Entry* latest = nullptr;
        for (auto it = range.first; it != range.second; ++it) {
            const auto& entry = *it->second;
            if (Matches(entry.tuple, tuple) && (!latest || entry.owner->timestamp > latest->owner->timestamp)) latest = &entry;
        }
        if (!latest) return "socket_tuple_mismatch";
        if (Expired(*latest, now)) return "socket_record_expired";
        if (timestamp < latest->owner->timestamp) return "packet_precedes_socket";
        if (latest->cutoff != 0 && timestamp >= latest->cutoff) return "socket_generation_ended";
        if (latest->closedAt != 0 && timestamp > latest->closedAt) return "socket_closed";
        return "no_eligible_socket_owner";
    }

    void Cleanup(Clock::time_point now) {
        for (auto it = order_.begin(); it != order_.end();) {
            auto current = it++;
            if (Expired(*current, now)) {
                Notify("socket_owner_removed", current->closedAt != 0 ? "close_grace_expired" : "idle_timeout", *current, now);
                Erase(current);
            }
        }
    }

    void Clear() {
        const auto now = Clock::now();
        for (const auto& entry : order_) Notify("socket_owner_removed", "clear", entry, now);
        ++revision_;
        ports_.clear();
        order_.clear();
    }
    size_t Size() const { return order_.size(); }

private:
    struct Entry {
        SocketTuple tuple;
        Owner owner;
        int64_t lastEvent;
        int64_t closedAt;
        int64_t cutoff;
        Clock::time_point lastSeen;
        Clock::time_point retiredAt;
    };
    std::list<Entry> order_;
    std::unordered_multimap<uint32_t, std::list<Entry>::iterator> ports_;
    size_t capacity_;
    uint64_t revision_ = 1;
    EvictionHandler onEviction_;
    ChangeHandler onChange_;
    uint64_t changeSequence_ = 0;

    Eviction Snapshot(const Entry& entry, Clock::time_point now) const {
        return { entry.tuple, entry.owner, entry.lastEvent, entry.closedAt, entry.cutoff,
            std::chrono::duration_cast<std::chrono::milliseconds>(now - entry.lastSeen).count(), capacity_ };
    }
    void Notify(const char* event, const char* reason, const Entry& entry, Clock::time_point now,
        std::optional<Eviction> previous = std::nullopt) {
        ++changeSequence_;
        if (onChange_) onChange_({ event, reason, Snapshot(entry, now), std::move(previous), changeSequence_ });
    }

    static uint32_t Key(const SocketTuple& tuple) { return (uint32_t(tuple.protocol) << 16) | tuple.localPort; }
    static bool SameTuple(const SocketTuple& a, const SocketTuple& b) {
        return Key(a) == Key(b) && a.localIp == b.localIp && a.remoteIp == b.remoteIp && a.remotePort == b.remotePort;
    }
    static bool Matches(const SocketTuple& socket, const SocketTuple& packet) {
        if (socket.localIp != 0 && socket.localIp != packet.localIp) return false;
        if (socket.protocol == 6 && socket.remotePort == 0) return false;
        return (socket.remoteIp == 0 || socket.remoteIp == packet.remoteIp) &&
            (socket.remotePort == 0 || socket.remotePort == packet.remotePort);
    }
    static bool Expired(const Entry& entry, Clock::time_point now) {
        if (entry.closedAt != 0) return now - entry.retiredAt >= std::chrono::seconds(30);
        return now - entry.lastSeen >= std::chrono::minutes(entry.tuple.protocol == 6 ? 124 : 20);
    }
    void Erase(std::list<Entry>::iterator entry) {
        ++revision_;
        const auto range = ports_.equal_range(Key(entry->tuple));
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second == entry) { ports_.erase(it); break; }
        }
        order_.erase(entry);
    }
};
