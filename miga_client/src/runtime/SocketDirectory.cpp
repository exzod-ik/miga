#include "runtime/SocketDirectory.h"

namespace miga::runtime {
void SocketDirectory::SetProbeHandler(ProbeHandler handler) { probe_ = std::move(handler); }

uint64_t SocketDirectory::TakeCapacityFailures() {return capacityFailures_.exchange(0);}

SocketDirectory::SocketDirectory() { for (auto& revision : revisions_) revision.store(1); }

uint64_t SocketDirectory::Version(const SocketTuple& tuple) const { return revisions_[PortKey(tuple)].load(); }

OwnerRecord SocketDirectory::Observe(SocketTuple tuple, std::shared_ptr<const SocketOwner> owner, Clock::time_point now) {
    std::unique_lock lock(mutex_);
    if (tuple.protocol == 17) { tuple.remoteIp = 0; tuple.remotePort = 0; }
    const auto key = PortKey(tuple);
    auto found = ports_.find(key);
    if (found != ports_.end()) {
        if (owner->snapshot) for (const auto& record : found->second)
            if (!record->owner->snapshot && record->lastEvent >= owner->timestamp && Matches(record->tuple, tuple)) return {};
        if (owner->process->pid == 4) {
            for (const auto& record : found->second)
                if (record->owner->process->pid != 4 && (Due(*record) > Millis(now) ||
                    (record->tuple.protocol == 6 && !record->activity->closed.load() && !record->activity->cutoff.load()))) return {};
        }
        for (auto& record : found->second) {
            if (record->owner->endpointId != owner->endpointId || record->owner->snapshot != owner->snapshot) continue;
            if (record->lastEvent > owner->timestamp || record->activity->closed.load() ||
                record->owner->process->pid != owner->process->pid) return {};
            auto replacement = std::make_shared<SocketRecord>(*record);
            replacement->tuple = tuple;
            replacement->lastEvent = owner->timestamp;
            replacement->activity->Touch(Millis(now));
            records_[record->id] = replacement;
            record = replacement;
            ++revisions_[key];
            return record;
        }
    }
    if (records_.size() >= Capacity) {
        uint64_t retired = 0;
        if (!retired_.PopDue((Clock::time_point::max)(), retired)) {++capacityFailures_; return {};}
        auto entry = records_.find(retired);
        if (entry == records_.end()) return {};
        Erase(entry->second);
    }
    auto record = std::make_shared<SocketRecord>();
    record->id = ++nextId_;
    record->tuple = tuple;
    record->lastEvent = owner->timestamp;
    record->owner = std::move(owner);
    record->activity = std::make_shared<SocketActivity>();
    record->activity->Touch(Millis(now));
    auto& bucket = ports_[key];
    for (const auto& old : bucket) {
        if (Exact(old->tuple, tuple) && old->owner->timestamp < record->owner->timestamp) {
            const auto cutoff = old->activity->cutoff.load();
            if (!cutoff || cutoff > record->owner->timestamp) old->activity->cutoff.store(record->owner->timestamp);
        }
    }
    bucket.push_back(record);
    records_.emplace(record->id, record);
    deadlines_.Set(record->id, Clock::time_point(std::chrono::milliseconds(Due(*record))));
    ++revisions_[key];
    return record;
}

void SocketDirectory::Close(const SocketTuple& tuple, uint64_t endpoint, uint32_t pid, int64_t timestamp, Clock::time_point now) {
    std::unique_lock lock(mutex_);
    auto found = ports_.find(PortKey(tuple));
    if (found == ports_.end()) return;
    for (auto& record : found->second) {
        if (record->owner->endpointId != endpoint &&
            !(record->owner->snapshot && record->owner->process->pid == pid && Exact(record->tuple, tuple))) continue;
        if (record->lastEvent > timestamp || record->activity->closed.load()) continue;
        record->activity->retired.store(Millis(now));
        record->activity->closed.store(timestamp);
        deadlines_.Set(record->id, now + std::chrono::seconds(30));
        retired_.Set(record->id, now);
    }
    ++revisions_[PortKey(tuple)];
}

OwnerRecord SocketDirectory::Find(const SocketTuple& tuple, int64_t timestamp, bool syn, Clock::time_point now) const {
    std::shared_lock lock(mutex_);
    auto found = ports_.find(PortKey(tuple));
    if (found == ports_.end()) return {};
    OwnerRecord best;
    for (const auto& record : found->second) {
        if (!record->Eligible(tuple, timestamp, syn, Millis(now))) continue;
        if (!best || best->owner->timestamp < record->owner->timestamp ||
            (best->owner->timestamp == record->owner->timestamp && record->tuple.remotePort)) best = record;
    }
    return best;
}

OwnerRecord SocketDirectory::Successor(const SocketTuple& tuple, int64_t first, Clock::time_point now,
    const OwnerRecord& bind, int64_t synTime, OwnerRecord& refinement) const {
    std::shared_lock lock(mutex_);
    auto found = ports_.find(PortKey(tuple));
    if (found == ports_.end()) return {};
    OwnerRecord best;
    size_t candidates = 0;
    for (const auto& record : found->second) {
        if (!Matches(record->tuple, tuple) || record->owner->timestamp <= first || Due(*record) <= Millis(now)) continue;
        if (tuple.protocol == 6 && !record->tuple.remotePort) continue;
        if (bind && record->owner->timestamp <= synTime) {
            ++candidates;
            const auto& owner = *record->owner;
            if (owner.origin == SocketOrigin::Connect && owner.process == bind->owner->process &&
                Exact(record->tuple, tuple) && record->Eligible(tuple, synTime, true, Millis(now)) &&
                (!owner.parentEndpointId || owner.parentEndpointId == bind->owner->endpointId)) refinement = record;
        }
        if (!best || best->owner->timestamp < record->owner->timestamp) best = record;
    }
    if (candidates != 1) refinement.reset();
    return best;
}

void SocketDirectory::Cleanup(Clock::time_point now, size_t budget) {
    std::unique_lock lock(mutex_);
    std::vector<Probe> probes;
    uint64_t id = 0;
    while (budget-- && deadlines_.PopDue(now, id)) {
        auto found = records_.find(id);
        if (found == records_.end()) continue;
        const auto due = Due(*found->second);
        if (due > Millis(now)) deadlines_.Set(id, Clock::time_point(std::chrono::milliseconds(due)));
        else if (probe_ && found->second->tuple.protocol == 6 && found->second->tuple.remotePort &&
            !found->second->activity->closed.load() && !found->second->activity->cutoff.load()) {
            probes.push_back({found->second, found->second->activity->lastSeen.load(), ++found->second->activity->probeVersion});
            deadlines_.Set(id, now + std::chrono::seconds(30));
        }
        else Erase(found->second);
    }
    lock.unlock();
    if (!probes.empty()) probe_(std::move(probes));
}

void SocketDirectory::Probed(const Probe& probe, std::optional<bool> present, Clock::time_point now) {
    std::unique_lock lock(mutex_);
    const auto& record = probe.record;
    auto found = records_.find(record->id);
    if (found == records_.end() || found->second != record || record->activity->lastSeen.load() != probe.activity ||
        record->activity->closed.load() || record->activity->cutoff.load() || record->activity->probeVersion != probe.version) return;
    if (present && !*present) Erase(record);
    else deadlines_.Set(record->id, now + std::chrono::seconds(present ? 60 : 30));
}

void SocketDirectory::Clear() {
    std::unique_lock lock(mutex_);
    for (const auto& item : records_) item.second->activity->present.store(false);
    records_.clear(); ports_.clear(); deadlines_.Clear(); retired_.Clear();
    for (auto& revision : revisions_) ++revision;
    capacityFailures_.store(0);
}

int64_t SocketDirectory::Due(const SocketRecord& record) {
    if (record.activity->closed.load()) return record.activity->retired.load() + 30000;
    return record.activity->lastSeen.load() + (record.tuple.protocol == 6 ? 7440000 : 1200000);
}

void SocketDirectory::Erase(OwnerRecord record) {
    record->activity->present.store(false);
    const auto key = PortKey(record->tuple);
    auto found = ports_.find(key);
    if (found != ports_.end()) {
        auto& bucket = found->second;
        bucket.erase(std::remove_if(bucket.begin(), bucket.end(), [&](const auto& candidate) {
            return candidate->id == record->id;
        }), bucket.end());
        if (bucket.empty()) ports_.erase(found);
    }
    records_.erase(record->id); deadlines_.Erase(record->id); retired_.Erase(record->id); ++revisions_[key];
}

}
