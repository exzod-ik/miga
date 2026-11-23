#pragma once
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
#endif
#include "../../Shared/ProtocolV2.h"
#include <future>
#include <atomic>
#include <memory>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace miga::v2 {
struct AndroidSendActivity {
    explicit AndroidSendActivity(int64_t connected) : connected(connected) {}
    bool Stale(int64_t now) const;
    const int64_t connected;
    std::atomic<int64_t> lastData{0};
    std::atomic<int64_t> lastKeepalive{0};
};
struct SessionSnapshot {
    Id session{};
    SessionKeys keys{};
    uint16_t port = 0;
    uint64_t generation = 0;
    bool dataProbeSupported = false;
#ifdef __ANDROID__
    std::shared_ptr<AndroidSendActivity> sendActivity;
#endif
    std::unordered_map<uint32_t, uint32_t> addresses;
};
class ProtocolV2Session {
    friend struct ProtocolV2SessionTestAccess;
public:
    ProtocolV2Session(Invitation invitation, uint32_t networkServerIp, SOCKET reservation);
    ~ProtocolV2Session();
    bool Start(uint32_t localAddress, SOCKET control = INVALID_SOCKET);
    void Stop();
    std::shared_ptr<const SessionSnapshot> Snapshot() const;
    std::string Status() const;
    bool RequestAddress(uint32_t localAddress);
    Bytes OpenDiagnostics();
    void MarkActivity();
#ifdef __ANDROID__
    bool AndroidSendStale(const SessionSnapshot& session) const;
    void MarkAndroidDataSent(uint16_t port);
#endif
    void RequestResume();
    void SetMaximumPayload(size_t payload);
    bool IsControlTuple(uint32_t remoteIp, uint16_t remotePort, uint16_t localPort, bool outbound = false) const;
private:
    using Clock = std::chrono::steady_clock;
    void Publish(std::shared_ptr<const SessionSnapshot> state);
    void Run(uint32_t localAddress);
    bool Connect(uint32_t localAddress);
    bool Activate(const OpenReply& reply, const Key& hash, Clock::time_point deadline);
    bool Exchange(const Bytes& packet, SOCKET socket, uint16_t port, const Id& request, Operation expected, const SessionSnapshot* session, Message& response, Clock::time_point deadline);
    bool Control(const SessionSnapshot& session, Operation operation, const Bytes& body, Operation expected, Message& response, SOCKET socket = INVALID_SOCKET, uint16_t port = 0, Clock::time_point deadline = (Clock::time_point::max)());
    bool Receive(Message& message, const SessionSnapshot* session, Clock::time_point until);
    bool Resume(const SessionSnapshot& session);
    void CloseSession(const SessionSnapshot& session);
    void UpdatePorts();
#ifdef _WIN32
    static int64_t SuspendedMillis();
    int64_t (*suspendedMillis_)() = SuspendedMillis;
#endif
    enum class State { Connecting, Unavailable, Ready, Recovering };
    std::atomic<State> state_{State::Connecting};
    Invitation invitation_;
    Key envelope_{};
    Key hash_{};
    Key pendingHash_{};
    std::shared_ptr<SessionSnapshot> pending_;
    Clock::time_point pendingUntil_{};
    uint64_t boundAccepted_ = 0, boundGeneration_ = 0;
    int64_t boundObservedAt_ = 0;
    uint32_t serverIp_;
    SOCKET reservation_;
    SOCKET control_ = INVALID_SOCKET;
    std::atomic<uint16_t> controlLocal_{0}, dataLocal_{0};
    std::atomic<uint16_t> dailyPrevious_{0}, dailyCurrent_{0}, dailyNext_{0}, pendingPort_{0};
    std::atomic<bool> stopping_{false}, binding_{false}, resumeRequested_{false};
    std::atomic<int64_t> lastActivity_{0};
    std::atomic<uint64_t> sent_{0};
    std::atomic<size_t> maximumPayload_{65507};
#if defined(__cpp_lib_atomic_shared_ptr)
    std::atomic<std::shared_ptr<const SessionSnapshot>> snapshot_;
#else
    std::shared_ptr<const SessionSnapshot> snapshot_;
#endif
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<uint32_t> addresses_;
    std::shared_ptr<std::promise<Bytes>> diagnostic_;
    uint64_t counter_ = 0, generation_ = 0;
    ReplayWindow receiveWindow_;
};
}
