#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <unordered_map>
#include <utility>

template<class Packet>
class PendingPackets {
    struct Entry;
    using Iterator = typename std::list<Entry>::iterator;
    using Bucket = std::list<Iterator>;
public:
    using Clock = std::chrono::steady_clock;
    static constexpr auto Wait = std::chrono::seconds(5);
    static constexpr size_t MaxPackets = 1024;
    static constexpr size_t MaxBytes = 4 * 1024 * 1024;

    bool Push(Packet&& packet, Clock::time_point now, uint32_t key = 0) {
        const auto size = packet.packetData.size();
        if (packets_.size() >= MaxPackets || size > MaxBytes - bytes_) return false;
        packets_.push_back({ std::move(packet), now + Wait, key, {} });
        auto entry = std::prev(packets_.end());
        auto& bucket = buckets_[key];
        bucket.push_back(entry);
        entry->position = std::prev(bucket.end());
        bytes_ += size;
        return true;
    }

    template<class Resolve>
    void DrainMatching(uint32_t key, Clock::time_point now, Resolve&& resolve) {
        auto found = buckets_.find(key);
        if (found == buckets_.end()) return;
        auto& bucket = found->second;
        for (auto it = bucket.begin(); it != bucket.end();) {
            auto entry = *it++;
            if (resolve(entry->packet, now >= entry->deadline)) {
                bytes_ -= entry->packet.packetData.size();
                bucket.erase(entry->position);
                packets_.erase(entry);
            }
        }
        if (bucket.empty()) buckets_.erase(found);
    }

    template<class Resolve>
    void DrainExpired(Clock::time_point now, Resolve&& resolve) {
        for (auto it = packets_.begin(); it != packets_.end() && now >= it->deadline;) {
            auto entry = it++;
            if (resolve(entry->packet, true)) {
                auto found = buckets_.find(entry->key);
                found->second.erase(entry->position);
                if (found->second.empty()) buckets_.erase(found);
                bytes_ -= entry->packet.packetData.size();
                packets_.erase(entry);
            }
        }
    }

    Clock::time_point Deadline(Clock::time_point otherwise) const {
        return packets_.empty() ? otherwise : (std::min)(otherwise, packets_.front().deadline);
    }

    void Clear() { buckets_.clear(); packets_.clear(); bytes_ = 0; }
    size_t Size() const { return packets_.size(); }
    size_t Bytes() const { return bytes_; }

private:
    struct Entry {
        Packet packet;
        Clock::time_point deadline;
        uint32_t key;
        typename Bucket::iterator position;
    };
    std::list<Entry> packets_;
    std::unordered_map<uint32_t, Bucket> buckets_;
    size_t bytes_ = 0;
};
