#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <list>
#include <iterator>
#include <utility>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

class ProcessIdentity {
public:
    const uint32_t pid;
    const std::function<bool()> isAlive;

    ProcessIdentity(uint32_t id, std::function<bool()> alive, std::function<std::string()> readName)
        : pid(id), isAlive(std::move(alive)), readName_(std::move(readName)) {}

    std::string Name() const {
        std::lock_guard lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (name_ == "unknown" && now >= retryAt_) {
            name_ = readName_();
            retryAt_ = now + std::chrono::seconds(1);
        }
        return name_;
    }

private:
    std::function<std::string()> readName_;
    mutable std::mutex mutex_;
    mutable std::string name_ = "unknown";
    mutable std::chrono::steady_clock::time_point retryAt_{};
};

using ProcessOwner = std::shared_ptr<const ProcessIdentity>;

struct SocketOwner {
    ProcessOwner process;
    uint64_t endpointId;
    int64_t timestamp;
    bool snapshot = false;

    bool Matches(int64_t packetTimestamp) const {
        return timestamp <= packetTimestamp;
    }
};

class ProcessIdentityCache {
public:
    template<class Loader>
    ProcessOwner Get(uint32_t pid, Loader&& load) {
        ProcessOwner cached;
        {
            std::lock_guard lock(mutex_);
            auto it = entries_.find(pid);
            if (it != entries_.end()) {
                cached = it->second.process;
                order_.splice(order_.end(), order_, it->second.position);
            }
        }
        if (cached && cached->isAlive()) return cached;
        auto process = load(pid);
        if (!process->isAlive()) return process;
        std::lock_guard lock(mutex_);
        auto it = entries_.find(pid);
        if (it != entries_.end()) {
            if (it->second.process != cached && it->second.process->isAlive()) return it->second.process;
            order_.erase(it->second.position);
            entries_.erase(it);
        }
        while (entries_.size() >= 1024) {
            entries_.erase(order_.front());
            order_.pop_front();
        }
        order_.push_back(pid);
        entries_.emplace(pid, Entry{ process, std::prev(order_.end()) });
        return process;
    }

    void Cleanup() {
        std::lock_guard lock(mutex_);
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (!it->second.process->isAlive()) {
                order_.erase(it->second.position);
                it = entries_.erase(it);
            }
            else ++it;
        }
    }

    void Clear() {
        std::lock_guard lock(mutex_);
        entries_.clear();
        order_.clear();
    }

private:
    struct Entry {
        ProcessOwner process;
        std::list<uint32_t>::iterator position;
    };
    std::mutex mutex_;
    std::list<uint32_t> order_;
    std::unordered_map<uint32_t, Entry> entries_;
};
