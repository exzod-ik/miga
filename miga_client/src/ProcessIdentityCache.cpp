#include "ProcessIdentityCache.h"

ProcessIdentity::ProcessIdentity(uint32_t id, std::function<bool()> alive, std::function<std::string()> readName)
    : pid(id), isAlive(std::move(alive)), readName_(std::move(readName)) {}

std::string ProcessIdentity::Name() const {
    std::lock_guard lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    if (name_ == "unknown" && now >= retryAt_) {
        name_ = readName_();
        retryAt_ = now + std::chrono::seconds(1);
    }
    return name_;
}

void ProcessIdentityCache::Cleanup() {
    std::lock_guard lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (!it->second.process->isAlive()) {
            order_.erase(it->second.position);
            it = entries_.erase(it);
        }
        else ++it;
    }
}

void ProcessIdentityCache::Clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
    order_.clear();
}
