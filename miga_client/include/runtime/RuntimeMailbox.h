#pragma once

#include <windows.h>
#include <array>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <utility>
#include <chrono>
#include <cstdint>
#include <algorithm>

namespace miga::runtime {
template<class T, size_t Capacity>
class Mailbox {
public:
    struct Delay {uint64_t count = 0, maxMs = 0; size_t maxDepth = 0;};
    Mailbox() : event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}
    ~Mailbox() { Close(); if (event_) CloseHandle(event_); }
    Mailbox(const Mailbox&) = delete;
    Mailbox& operator=(const Mailbox&) = delete;
    HANDLE Event() const { return event_; }
    bool TryPush(T value) {
        std::lock_guard lock(mutex_);
        if (closed_ || count_ == Capacity || !event_) return false;
        Put(std::move(value));
        return true;
    }
    bool Push(T value) {
        std::unique_lock lock(mutex_);
        space_.wait(lock, [&] { return closed_ || count_ < Capacity; });
        if (closed_ || !event_) return false;
        Put(std::move(value));
        return true;
    }
    bool Pop(T& value) {
        std::unique_lock lock(mutex_);
        if (closed_ || !count_) return false;
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - items_[head_]->enqueued).count();
        if (elapsed >= 100) {
            ++delay_.count; delay_.maxMs = (std::max)(delay_.maxMs, static_cast<uint64_t>(elapsed));
            delay_.maxDepth = (std::max)(delay_.maxDepth, count_);
        }
        value = std::move(items_[head_]->value);
        items_[head_].reset();
        head_ = (head_ + 1) % Capacity;
        if (--count_ == 0) ResetEvent(event_);
        lock.unlock();
        space_.notify_one();
        return true;
    }
    Delay TakeDelay() {std::lock_guard lock(mutex_); auto result = delay_; delay_ = {}; return result;}
    void Close() {
        { std::lock_guard lock(mutex_); closed_ = true; if (event_) SetEvent(event_); }
        space_.notify_all();
    }
    void Reset() {
        std::lock_guard lock(mutex_);
        for (auto& item : items_) item.reset();
        head_ = count_ = 0;
        closed_ = false;
        delay_ = {};
        if (event_) ResetEvent(event_);
    }
private:
    void Put(T value) {
        items_[(head_ + count_) % Capacity].emplace(Item{std::move(value), std::chrono::steady_clock::now()});
        ++count_;
        SetEvent(event_);
    }
    std::mutex mutex_;
    std::condition_variable space_;
    struct Item {T value; std::chrono::steady_clock::time_point enqueued;};
    std::array<std::optional<Item>, Capacity> items_{};
    Delay delay_;
    size_t head_ = 0, count_ = 0;
    bool closed_ = false;
    HANDLE event_ = nullptr;
};
}
