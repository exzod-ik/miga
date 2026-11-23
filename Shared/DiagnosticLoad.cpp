#include "DiagnosticLoad.h"
#include <cstring>
#include <stdexcept>

namespace miga::diagnostics {
namespace {
uint32_t U32(const uint8_t* p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
void Put32(uint8_t* p, uint32_t v) { p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v); }
}
bool ReadProbe(const uint8_t* p, size_t n, Probe& v) {
    if (!p || n < 32 || std::memcmp(p, "MGL2", 4) || p[20] > 2) return false;
    v = {uint64_t(U32(p + 4)) << 32 | U32(p + 8), U32(p + 12), U32(p + 16), p[20]};
    return v.run != 0;
}
bool ReadProbePacket(const uint8_t* p, size_t n, Probe& v) {
    if (!p || n < 60 || p[0] >> 4 != 4 || p[9] != 17 || (p[6] & 0x3f) || p[7]) return false;
    const size_t h = size_t(p[0] & 15) * 4;
    if (h < 20 || h + 40 > n || (size_t(p[2]) << 8 | p[3]) != n || (size_t(p[h + 4]) << 8 | p[h + 5]) != n - h) return false;
    return ReadProbe(p + h + 8, n - h - 8, v);
}
void WriteProbe(uint8_t* p, size_t n, const Probe& v) {
    if (n < 32) throw std::invalid_argument("probe_size");
    std::memcpy(p, "MGL2", 4); Put32(p + 4, uint32_t(v.run >> 32)); Put32(p + 8, uint32_t(v.run));
    Put32(p + 12, v.step); Put32(p + 16, v.sequence); p[20] = v.direction;
}
void LoadCounters::Configure(const nlohmann::json& r) {
    const auto run = r.at("run").get<std::string>();
    if (run.size() != 16 || run.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) throw std::invalid_argument("probe_run");
    const auto rate = r.at("rate").get<int>(), seconds = r.at("seconds").get<int>(), direction = r.at("direction").get<int>();
    const auto id = std::stoull(run, nullptr, 16);
    if (!id || rate < 1 || rate > 10000 || seconds < 1 || seconds > 300 || direction < 0 || direction > 1) throw std::invalid_argument("probe_limits");
    std::lock_guard lock(mutex_); enabled.store(false);
    identity_ = {id, r.at("step").get<uint32_t>(), 0, uint8_t(direction)};
    rate_ = uint32_t(rate); limit_ = uint32_t(rate * seconds);
    for (auto& c : counters_) { c = {}; c.bits.resize((limit_ + 63) / 64); c.seconds.resize(size_t(seconds)); }
    enabled.store(true);
}
void LoadCounters::Clear() {
    enabled.store(false); std::lock_guard lock(mutex_); limit_ = 0;
    for (auto& c : counters_) c = {};
}
void LoadCounters::Record(Stage stage, const Probe& p, bool success) {
    if (!enabled.load(std::memory_order_relaxed)) return;
    std::lock_guard lock(mutex_);
    if (!enabled.load() || stage >= Count || p.run != identity_.run || p.step != identity_.step || p.direction != identity_.direction || p.sequence >= limit_) return;
    auto& c = counters_[stage];
    if (!success) { ++c.errors; return; }
    auto& word = c.bits[p.sequence / 64]; const uint64_t bit = uint64_t(1) << (p.sequence % 64);
    if (word & bit) { ++c.duplicates; return; }
    word |= bit; ++c.unique; ++c.seconds[p.sequence / rate_];
    if (c.any && p.sequence < c.high) ++c.reordered;
    if (!c.any || p.sequence > c.high) c.high = p.sequence;
    c.any = true;
}
void LoadCounters::Packet(Stage stage, const uint8_t* packet, size_t size, bool success) {
    if (!enabled.load(std::memory_order_relaxed)) return;
    Probe p; if (ReadProbePacket(packet, size, p)) Record(stage, p, success);
}
nlohmann::json LoadCounters::Snapshot() {
    std::lock_guard lock(mutex_); nlohmann::json result = nlohmann::json::object();
    static const char* names[] = {"app_sent", "captured", "selected", "wire_sent", "server_received", "tun_written", "app_received", "tun_read", "client_received", "reinject"};
    for (size_t i = 0; i < Count; ++i) { const auto& c = counters_[i]; result[names[i]] = {{"unique", c.unique}, {"duplicates", c.duplicates}, {"reordered", c.reordered}, {"errors", c.errors}, {"seconds", c.seconds}}; }
    return result;
}
}
