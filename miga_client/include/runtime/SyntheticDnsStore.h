#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace miga::runtime {
class SyntheticDnsStore {
public:
    void Clear();
    std::optional<uint32_t> FindOrAllocate(std::string_view name);
    const std::string* Lookup(uint32_t address) const;
    uint32_t LastAllocated() const { return lastAllocated_.load(std::memory_order_relaxed); }
    static constexpr uint32_t DiagnosticEchoAddress = 0xc6120001;
    static constexpr bool Contains(uint32_t address) { return (address & 0xfffe0000u) == 0xc6120000u; }

private:
    std::atomic<uint32_t> lastAllocated_{0};
    std::unordered_map<uint32_t, std::string> names_;
    std::unordered_map<std::string, uint32_t> addresses_;
};
}
