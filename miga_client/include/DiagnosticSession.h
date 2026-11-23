#pragma once

#include <winsock2.h>
#include <windows.h>
#include "runtime/RuntimeTypes.h"
#include <nlohmann/json.hpp>
#include <thread>
#include <mutex>
#include <functional>
#include <array>
#include "DiagnosticLoad.h"

class DiagnosticSession {
    friend struct NetworkRuntimeTests;
public:
    using Json = nlohmann::json;
    using Begin = std::function<Json(DWORD, const Json&)>;
    std::atomic<bool> enabled{false};
    miga::diagnostics::LoadCounters load;
    void Start(Begin begin);
    void Stop();
    ~DiagnosticSession();
    void Configure(ProcessOwner owner, size_t server, bool force);
    bool Route(const ProcessOwner& owner, FlowRoute& route);
    bool DirectProbeMatches(const SocketTuple& tuple);
    struct PacketOptions {
        uint64_t session = 0;
        bool dontFragment = false;
        bool preserveMss = false;
        uint32_t sequence = 0;
        miga::diagnostics::Probe probe;
    };
    PacketOptions Options(const SocketTuple& tuple, size_t server, const uint8_t* packet = nullptr, size_t length = 0);
    void ObserveProbe(const SocketTuple& tuple, const uint8_t* packet, size_t length);
    bool RejectFallback(const SocketTuple& tuple, const FlowRoute& route);
    void ObserveUnowned(const SocketTuple& tuple);
    bool Selected(const ProcessOwner& process) const { return process && process->pid == targetPid_.load(std::memory_order_relaxed); }
    bool TracksPort(const SocketTuple& tuple) const {
        const auto key = (unsigned(tuple.protocol == 17) << 16) | tuple.localPort;
        return portMask_[key / 64].load(std::memory_order_relaxed) & (uint64_t(1) << (key % 64));
    }
    void Observe(const SocketTuple& tuple, const ProcessOwner& owner, const FlowRoute& route, const char* reason);
    void Sent(uint64_t session, bool success, uint32_t sequence = 0);
    void Submitted(uint64_t session);
    void RejectBeforeSend(uint64_t session);
private:
    std::mutex mutex_;
    std::thread thread_;
    std::atomic<bool> stopping_{false};
    ProcessOwner owner_;
    ProcessOwner directProbeOwner_;
    SocketTuple directProbeTuple_;
    std::atomic<uint16_t> directProbePort_{0};
    bool RegisterDirectProbe(DWORD pid, const Json& request);
    void ClearDirectProbe();
    size_t server_ = 0;
    bool force_ = false, mss_ = false;
    uint16_t probePort_ = 0;
    std::atomic<DWORD> targetPid_{0};
    std::array<std::atomic<uint64_t>, 2048> portMask_{};
    void MarkPort(uint8_t protocol, uint16_t port);
    uint64_t session_ = 0;
    std::unordered_set<uint32_t> registrations_;
    bool IsRegistered(const SocketTuple& tuple) const;
    std::unordered_map<FlowKey, size_t, FlowKeyHash> flows_;
    uint64_t captured_ = 0, unowned_ = 0, submitted_ = 0, completed_ = 0, rejected_ = 0, preSendRejected_ = 0;
    Json stats_;
    bool observing_ = false;
    SocketTuple observationTuple_{};
    uint64_t observationCaptured_ = 0, observationUnowned_ = 0;
    Json observationFlows_;
    std::unordered_map<FlowKey, size_t, FlowKeyHash> observationFlowIndices_;
    bool MatchesObservation(const SocketTuple& tuple) const;
    Json BeginObservation(const SocketTuple& tuple);
    Json EndObservation();
    uint16_t sequencePort_ = 0;
    std::unordered_set<uint16_t> capturedSequences_, completedSequences_;
    void Serve(Begin begin);
    void Clear();
};
