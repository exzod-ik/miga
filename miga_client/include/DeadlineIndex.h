#pragma once

#include <chrono>
#include <algorithm>
#include <map>
#include <unordered_map>

template<class Key, class Hash = std::hash<Key>>
class DeadlineIndex {
public:
    using Clock = std::chrono::steady_clock;
    DeadlineIndex() = default;
    DeadlineIndex(const DeadlineIndex&) = delete;
    DeadlineIndex& operator=(const DeadlineIndex&) = delete;
    void Set(const Key& key, Clock::time_point deadline) {
        Erase(key);
        positions_.emplace(key, deadlines_.emplace(deadline, key));
    }
    void Erase(const Key& key) {
        auto found = positions_.find(key);
        if (found == positions_.end()) return;
        deadlines_.erase(found->second);
        positions_.erase(found);
    }
    bool PopDue(Clock::time_point now, Key& key) {
        if (deadlines_.empty() || deadlines_.begin()->first > now) return false;
        key = deadlines_.begin()->second;
        positions_.erase(key);
        deadlines_.erase(deadlines_.begin());
        return true;
    }
    Clock::time_point Next(Clock::time_point otherwise) const {
        return deadlines_.empty() ? otherwise : (std::min)(otherwise, deadlines_.begin()->first);
    }
    void Clear() { positions_.clear(); deadlines_.clear(); }
    size_t Size() const { return positions_.size(); }
private:
    using Deadlines = std::multimap<Clock::time_point, Key>;
    Deadlines deadlines_;
    std::unordered_map<Key, typename Deadlines::iterator, Hash> positions_;
};
