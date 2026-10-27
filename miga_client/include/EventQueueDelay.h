#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

class EventQueueDelay {
public:
    enum class Type { Network, Socket, Control };
    void Record(Type type, std::chrono::steady_clock::duration delay, size_t depth) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(delay).count();
        if (ms < 100) return;
        auto& sample = samples_[static_cast<size_t>(type)];
        ++sample.count;
        sample.maxMs = (std::max)(sample.maxMs, static_cast<uint64_t>(ms));
        sample.maxDepth = (std::max)(sample.maxDepth, depth);
    }

    template<class Write>
    void Flush(Write&& write) {
        static constexpr const char* names[] = { "NETWORK", "SOCKET", "CONTROL" };
        for (size_t i = 0; i < samples_.size(); ++i) {
            const auto sample = samples_[i];
            samples_[i] = {};
            if (sample.count == 0) continue;
            write(std::string("event_queue_delay type=") + names[i] +
                " count=" + std::to_string(sample.count) +
                " max_wait_ms=" + std::to_string(sample.maxMs) +
                " max_queue_depth_at_pop=" + std::to_string(sample.maxDepth) +
                " threshold_ms=100");
        }
    }

    void Clear() { samples_ = {}; }

private:
    struct Sample { uint64_t count = 0; uint64_t maxMs = 0; size_t maxDepth = 0; };
    std::array<Sample, 3> samples_{};
};
