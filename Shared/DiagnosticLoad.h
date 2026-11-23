#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <vector>
#include <nlohmann/json.hpp>

namespace miga::diagnostics {
struct Probe { uint64_t run = 0; uint32_t step = 0, sequence = 0; uint8_t direction = 0; };
bool ReadProbe(const uint8_t* data, size_t size, Probe& probe);
bool ReadProbePacket(const uint8_t* packet, size_t size, Probe& probe);
void WriteProbe(uint8_t* data, size_t size, const Probe& probe);
class LoadCounters {
public:
    enum Stage { AppSent, Captured, Selected, WireSent, ServerReceived, TunWritten, AppReceived, TunRead, ClientReceived, Reinject, Count };
    std::atomic<bool> enabled{false};
    void Configure(const nlohmann::json& request);
    void Clear();
    void Record(Stage stage, const Probe& probe, bool success = true);
    void Packet(Stage stage, const uint8_t* packet, size_t size, bool success = true);
    nlohmann::json Snapshot();
private:
    struct Counter { std::vector<uint64_t> bits, seconds; uint64_t unique = 0, duplicates = 0, reordered = 0, errors = 0; uint32_t high = 0; bool any = false; };
    std::mutex mutex_;
    Probe identity_;
    uint32_t limit_ = 0, rate_ = 0;
    std::array<Counter, Count> counters_;
};
}
