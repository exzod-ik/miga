#pragma once

#include "RuntimeTypes.h"
#include <shared_mutex>
#include <array>

namespace miga::runtime {
class SocketDirectory {
public:
    static constexpr size_t Capacity = 8192;
    struct Probe { OwnerRecord record; int64_t activity; uint64_t version; };
    using ProbeHandler = std::function<bool(std::vector<Probe>)>;
    void SetProbeHandler(ProbeHandler handler);
    uint64_t TakeCapacityFailures();
    SocketDirectory();
    uint64_t Version(const SocketTuple& tuple) const;
    OwnerRecord Observe(SocketTuple tuple, std::shared_ptr<const SocketOwner> owner, Clock::time_point now);
    void Close(const SocketTuple& tuple, uint64_t endpoint, uint32_t pid, int64_t timestamp, Clock::time_point now);
    OwnerRecord Find(const SocketTuple& tuple, int64_t timestamp, bool syn, Clock::time_point now) const;
    OwnerRecord Successor(const SocketTuple& tuple, int64_t first, Clock::time_point now,
        const OwnerRecord& bind, int64_t synTime, OwnerRecord& refinement) const;
    void Cleanup(Clock::time_point now, size_t budget = 128);
    void Probed(const Probe& probe, std::optional<bool> present, Clock::time_point now);
    void Clear();
private:
    static int64_t Due(const SocketRecord& record);
    void Erase(OwnerRecord record);
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, std::vector<OwnerRecord>> ports_;
    std::unordered_map<uint64_t, OwnerRecord> records_;
    std::array<std::atomic<uint64_t>, 131072> revisions_{};
    DeadlineIndex<uint64_t> deadlines_;
    DeadlineIndex<uint64_t> retired_;
    uint64_t nextId_ = 0;
    ProbeHandler probe_;
    std::atomic<uint64_t> capacityFailures_{0};
};
}
