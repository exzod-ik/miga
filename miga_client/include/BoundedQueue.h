#pragma once

#include <condition_variable>
#include <chrono>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

template<class T, size_t Capacity>
class BoundedQueue {
    static_assert(Capacity > 0);
    std::mutex m_mutex;
    std::condition_variable m_changed;
    std::deque<T> m_items;
    bool m_closed = false;

public:
    bool Push(T&& item, std::chrono::steady_clock::time_point* queuedAt = nullptr) {
        std::unique_lock lock(m_mutex);
        m_changed.wait(lock, [&] { return m_closed || m_items.size() < Capacity; });
        if (m_closed) return false;
        if (queuedAt) *queuedAt = std::chrono::steady_clock::now();
        m_items.push_back(std::move(item));
        lock.unlock();
        m_changed.notify_all();
        return true;
    }

    bool Pop(T& item) {
        std::unique_lock lock(m_mutex);
        m_changed.wait(lock, [&] { return m_closed || !m_items.empty(); });
        if (m_closed) return false;
        item = std::move(m_items.front());
        m_items.pop_front();
        lock.unlock();
        m_changed.notify_all();
        return true;
    }

    enum class WaitResult { Item, Timeout, Closed };

    WaitResult PopUntil(T& item, std::chrono::steady_clock::time_point deadline, size_t* queueDepth = nullptr) {
        if (queueDepth) *queueDepth = 0;
        std::unique_lock lock(m_mutex);
        if (!m_changed.wait_until(lock, deadline, [&] { return m_closed || !m_items.empty(); }))
            return WaitResult::Timeout;
        if (m_closed) return WaitResult::Closed;
        if (queueDepth) *queueDepth = m_items.size();
        item = std::move(m_items.front());
        m_items.pop_front();
        lock.unlock();
        m_changed.notify_all();
        return WaitResult::Item;
    }

    void Close() {
        {
            std::lock_guard lock(m_mutex);
            m_closed = true;
        }
        m_changed.notify_all();
    }

    void Reset() {
        std::lock_guard lock(m_mutex);
        m_items.clear();
        m_closed = false;
    }
};
