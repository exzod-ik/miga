#include "runtime/SyntheticDnsStore.h"
#include "runtime/SyntheticDnsWire.h"
#include <algorithm>

namespace miga::runtime {
namespace {
constexpr uint32_t FirstAddress = SyntheticDnsStore::DiagnosticEchoAddress + 1;
constexpr uint32_t LastAddress = 0xc613fffe;
constexpr size_t Capacity = LastAddress - FirstAddress + 1;
}

void SyntheticDnsStore::Clear() {
    names_.clear();
    addresses_.clear();
    lastAllocated_.store(0, std::memory_order_relaxed);
}

std::optional<uint32_t> SyntheticDnsStore::FindOrAllocate(std::string_view name) {
    auto normalized = NormalizeSyntheticDnsName(name);
    if (!normalized)
        return std::nullopt;
    if (const auto found = addresses_.find(*normalized); found != addresses_.end())
        return found->second;
    if (names_.size() == Capacity)
        return std::nullopt;

    auto address = FirstAddress + static_cast<uint32_t>(std::hash<std::string>{}(*normalized) % Capacity);
    while (names_.contains(address)) address = address == LastAddress ? FirstAddress : address + 1;
    names_.emplace(address, *normalized);
    try {
        addresses_.emplace(std::move(*normalized), address);
    } catch (...) {
        names_.erase(address);
        throw;
    }
    lastAllocated_.store((std::max)(LastAllocated(), address), std::memory_order_relaxed);
    return address;
}

const std::string* SyntheticDnsStore::Lookup(uint32_t address) const {
    const auto found = names_.find(address);
    return found == names_.end() ? nullptr : &found->second;
}
}
