#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "RoutingState.h"
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>
#include <unordered_map>

class TcpSocketMaintenance {
public:
    using Probe = SocketOwnerTable::Probe;
    using Status = SocketOwnerTable::ProbeResult;
    struct Result { Probe probe; Status status; DWORD error; };
    using Snapshot = std::unordered_multimap<FlowKey, DWORD, FlowKeyHash>;
    using Reader = std::function<DWORD(Snapshot&)>;
    explicit TcpSocketMaintenance(Reader reader = Read) : reader_(std::move(reader)) {}
    ~TcpSocketMaintenance() { Stop(); }
    void Start() {
        Stop();
        { std::lock_guard lock(mutex_); stopped_ = false; }
        thread_ = std::thread([this] { Run(); });
    }
    void Stop() {
        { std::lock_guard lock(mutex_); stopped_ = true; }
        changed_.notify_all();
        if (thread_.joinable()) thread_.join();
        requests_.clear(); results_.clear();
    }
    bool Submit(const Probe& probe) {
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (!lock || stopped_ || requests_.size() >= 128) return false;
        requests_.push_back(probe);
        lock.unlock(); changed_.notify_one();
        return true;
    }
    std::vector<Result> Take() {
        std::unique_lock lock(mutex_, std::try_to_lock);
        if (!lock) return {};
        std::vector<Result> result;
        result.swap(results_);
        lock.unlock(); changed_.notify_one();
        return result;
    }
    static Status Check(const Probe& probe, const Snapshot& snapshot) {
        const auto range = snapshot.equal_range(FlowKey::From(probe.tuple));
        for (auto it = range.first; it != range.second; ++it)
            if (it->second == probe.owner->process->pid && probe.owner->process->isAlive()) return Status::Present;
        return Status::Absent;
    }
private:
    Reader reader_;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::thread thread_;
    bool stopped_ = true;
    std::vector<Probe> requests_;
    std::vector<Result> results_;
    static DWORD Read(Snapshot& snapshot) {
        DWORD size = 0;
        auto error = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<uint8_t> buffer;
        for (int attempt = 0; error == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt) {
            if (size > 16 * 1024 * 1024) return ERROR_NOT_ENOUGH_MEMORY;
            buffer.resize(size);
            error = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        }
        if (error != NO_ERROR) return error;
        if (buffer.size() < sizeof(DWORD)) return ERROR_INVALID_DATA;
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        if (table->dwNumEntries > (buffer.size() - offsetof(MIB_TCPTABLE_OWNER_PID, table)) / sizeof(MIB_TCPROW_OWNER_PID))
            return ERROR_INVALID_DATA;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwState == MIB_TCP_STATE_CLOSED ||
                row.dwState == MIB_TCP_STATE_TIME_WAIT || row.dwState == MIB_TCP_STATE_DELETE_TCB || !row.dwOwningPid) continue;
            snapshot.emplace(FlowKey{6, ntohl(row.dwLocalAddr), ntohs(static_cast<u_short>(row.dwLocalPort)),
                ntohl(row.dwRemoteAddr), ntohs(static_cast<u_short>(row.dwRemotePort))}, row.dwOwningPid);
        }
        return NO_ERROR;
    }
    void Run() {
        for (;;) {
            std::vector<Probe> batch;
            {
                std::unique_lock lock(mutex_);
                changed_.wait(lock, [&] { return stopped_ || (!requests_.empty() && results_.empty()); });
                if (stopped_) return;
                batch.swap(requests_);
            }
            Snapshot snapshot;
            DWORD error;
            try { error = reader_(snapshot); } catch (...) { error = ERROR_NOT_ENOUGH_MEMORY; }
            std::vector<Result> results;
            for (const auto& probe : batch)
                results.push_back({probe, error == NO_ERROR ? Check(probe, snapshot) : Status::Unknown, error});
            {
                std::lock_guard lock(mutex_);
                if (stopped_) return;
                results_.swap(results);
            }
        }
    }
};
