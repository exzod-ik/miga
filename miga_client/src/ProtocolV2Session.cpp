#include "../include/ProtocolV2Session.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <utility>
#ifdef _WIN32
#include <windows.h>
#else
#include <poll.h>
#endif
#ifdef __ANDROID__
#include <time.h>
#endif

namespace miga::v2 {
namespace {
#ifdef _WIN32
using SocketLength = int;
#else
using SocketLength = socklen_t;
void closesocket(SOCKET socket) { close(socket); }
#endif
uint16_t LocalPort(SOCKET socket) {
    sockaddr_storage address{};
    SocketLength length = sizeof(address);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) == SOCKET_ERROR) return 0;
    if (address.ss_family == AF_INET) return ntohs(reinterpret_cast<const sockaddr_in&>(address).sin_port);
#ifndef _WIN32
    if (address.ss_family == AF_INET6) return ntohs(reinterpret_cast<const sockaddr_in6&>(address).sin6_port);
#endif
    return 0;
}
int64_t NowMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
#ifdef __ANDROID__
int64_t BootMillis() {
    timespec elapsed{};
    if (clock_gettime(CLOCK_BOOTTIME, &elapsed) != 0) return 0;
    return int64_t(elapsed.tv_sec) * 1000 + elapsed.tv_nsec / 1000000;
}
#endif
uint64_t UnixTime() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
bool Send(SOCKET socket, uint32_t ip, uint16_t port, const Bytes& bytes) {
    if (socket == INVALID_SOCKET || bytes.empty()) return false;
#ifndef _WIN32
    sockaddr_storage local{};
    socklen_t length = sizeof(local);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&local), &length) != 0) return false;
    if (local.ss_family == AF_INET6) {
        sockaddr_in6 target{};
        target.sin6_family = AF_INET6;
        target.sin6_port = htons(port);
        target.sin6_addr.s6_addr[10] = 0xff;
        target.sin6_addr.s6_addr[11] = 0xff;
        std::memcpy(target.sin6_addr.s6_addr + 12, &ip, sizeof(ip));
        return sendto(socket, bytes.data(), bytes.size(), 0, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == static_cast<ssize_t>(bytes.size());
    }
#endif
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = ip;
    target.sin_port = htons(port);
    return sendto(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == static_cast<int>(bytes.size());
}
Id NewRequest() { Id id{}; Random(id.data(), id.size()); return id; }
uint32_t Uniform(uint32_t bound) {
    uint32_t random = 0;
    do { Random(reinterpret_cast<uint8_t*>(&random), sizeof(random)); } while (random >= UINT32_MAX - (UINT32_MAX % bound));
    return random % bound;
}
}
ProtocolV2Session::ProtocolV2Session(Invitation invitation, uint32_t networkServerIp, SOCKET reservation)
    : invitation_(std::move(invitation)), envelope_(EnvelopeKey(invitation_.serverSecret)), serverIp_(networkServerIp), reservation_(reservation) {}
ProtocolV2Session::~ProtocolV2Session() { Stop(); }
bool ProtocolV2Session::Start(uint32_t localAddress, SOCKET control) {
    if (thread_.joinable() || reservation_ == INVALID_SOCKET || !Initialize()) {
        if (control != INVALID_SOCKET) closesocket(control);
        return false;
    }
    const auto dataPort = LocalPort(reservation_);
    if (!dataPort) {
        if (control != INVALID_SOCKET) closesocket(control);
        return false;
    }
    dataLocal_.store(dataPort);
    control_ = control == INVALID_SOCKET ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : control;
    if (control_ == INVALID_SOCKET) return false;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    if ((control == INVALID_SOCKET && bind(control_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR) || !LocalPort(control_)) {
        closesocket(control_);
        control_ = INVALID_SOCKET;
        return false;
    }
    controlLocal_.store(LocalPort(control_));
    stopping_.store(false);
    resumeRequested_.store(false);
    state_.store(State::Connecting);
    UpdatePorts();
    thread_ = std::thread(&ProtocolV2Session::Run, this, localAddress);
    return true;
}
Bytes ProtocolV2Session::OpenDiagnostics() {
    auto request = std::make_shared<std::promise<Bytes>>();
    auto result = request->get_future();
    {
        std::lock_guard lock(mutex_);
        if (stopping_.load() || state_.load() != State::Ready || diagnostic_) return {};
        diagnostic_ = request;
    }
    wake_.notify_all();
    if (result.wait_for(std::chrono::seconds(12)) != std::future_status::ready) {
        std::lock_guard lock(mutex_);
        if (diagnostic_ == request) diagnostic_.reset();
        return {};
    }
    return result.get();
}
void ProtocolV2Session::Stop() {
    stopping_.store(true);
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    if (control_ != INVALID_SOCKET) {
        closesocket(control_);
        control_ = INVALID_SOCKET;
    }
    controlLocal_.store(0);
    dataLocal_.store(0);
    pendingPort_.store(0);
    binding_.store(false);
    Publish({});
    state_.store(State::Unavailable);
    std::lock_guard lock(mutex_);
    addresses_.clear();
    if (diagnostic_) {diagnostic_->set_value({}); diagnostic_.reset();}
    pending_.reset();
}
std::shared_ptr<const SessionSnapshot> ProtocolV2Session::Snapshot() const {
#if defined(__cpp_lib_atomic_shared_ptr)
    return snapshot_.load();
#else
    return std::atomic_load(&snapshot_);
#endif
}
void ProtocolV2Session::Publish(std::shared_ptr<const SessionSnapshot> state) {
#if defined(__cpp_lib_atomic_shared_ptr)
    snapshot_.store(std::move(state));
#else
    std::atomic_store(&snapshot_, std::move(state));
#endif
}
std::string ProtocolV2Session::Status() const {
    switch (state_.load()) {
    case State::Connecting: return "connecting";
    case State::Ready: return Snapshot() ? "ready" : "unavailable";
    case State::Recovering: return "recovering";
    default: return "unavailable";
    }
}
bool ProtocolV2Session::RequestAddress(uint32_t address) {
    if (!address || stopping_.load()) return false;
    auto current = Snapshot();
    if (current && std::any_of(current->addresses.begin(), current->addresses.end(), [address](const auto& entry) { return entry.first == address; })) return true;
    std::lock_guard lock(mutex_);
    if (std::find(addresses_.begin(), addresses_.end(), address) != addresses_.end()) return true;
    if (addresses_.size() + (current ? current->addresses.size() : 0) >= 16) return false;
    addresses_.push_back(address);
    wake_.notify_one();
    return true;
}
void ProtocolV2Session::MarkActivity() {
    lastActivity_.store(NowMillis(), std::memory_order_relaxed);
    sent_.fetch_add(1, std::memory_order_relaxed);
}
bool AndroidSendActivity::Stale(int64_t now) const {
    const auto last = (std::max)({connected, lastData.load(std::memory_order_relaxed),
                                  lastKeepalive.load(std::memory_order_relaxed)});
    return last > 0 && now - last >= 90000;
}
#ifdef __ANDROID__
bool ProtocolV2Session::AndroidSendStale(const SessionSnapshot& session) const {
    return session.sendActivity && session.sendActivity->Stale(BootMillis());
}
void ProtocolV2Session::MarkAndroidDataSent(uint16_t port) {
    const auto current = Snapshot();
    if (!current || current->port != port) return;
    if (const auto now = BootMillis(); now && current->sendActivity)
        current->sendActivity->lastData.store(now, std::memory_order_relaxed);
    MarkActivity();
}
#endif
void ProtocolV2Session::RequestResume() {
    if (stopping_.load()) return;
    resumeRequested_.store(true);
    if (Snapshot()) state_.store(State::Recovering);
    wake_.notify_one();
}
void ProtocolV2Session::SetMaximumPayload(size_t payload) { maximumPayload_.store((std::min)(size_t(65507), payload), std::memory_order_relaxed); }
bool ProtocolV2Session::IsControlTuple(uint32_t remoteIp, uint16_t remotePort, uint16_t localPort, bool outbound) const {
    if (remoteIp != ntohl(serverIp_)) return false;
    if (localPort == controlLocal_.load() && localPort != 0)
        return remotePort == dailyPrevious_.load() || remotePort == dailyCurrent_.load() || remotePort == dailyNext_.load();
    const auto current = Snapshot();
    return (outbound || binding_.load()) && localPort == dataLocal_.load() &&
        (remotePort == pendingPort_.load() || (outbound && current && remotePort == current->port));
}
void ProtocolV2Session::UpdatePorts() {
    const uint64_t day = UnixTime() / 86400;
    const auto key = ScheduleKey(invitation_.serverSecret);
    dailyPrevious_.store(DailyPort(key, day ? day - 1 : 0, invitation_.portStart, invitation_.portEnd));
    dailyCurrent_.store(DailyPort(key, day, invitation_.portStart, invitation_.portEnd));
    dailyNext_.store(DailyPort(key, day + 1, invitation_.portStart, invitation_.portEnd));
}
bool ProtocolV2Session::Receive(Message& message, const SessionSnapshot* session, Clock::time_point until) {
    std::array<uint8_t, MaxControl + 1> buffer{};
    while (!stopping_.load() && Clock::now() < until) {
        #ifdef _WIN32
        fd_set read;
        FD_ZERO(&read);
        FD_SET(control_, &read);
        timeval timeout{0, 100000};
        if (select(static_cast<int>(control_) + 1, &read, nullptr, nullptr, &timeout) <= 0) continue;
        #else
        pollfd ready{control_, POLLIN, 0};
        if (poll(&ready, 1, 100) <= 0 || !(ready.revents & POLLIN)) continue;
        #endif
        sockaddr_storage peer{};
        SocketLength peerLength = sizeof(peer);
        const int count = recvfrom(control_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr*>(&peer), &peerLength);
        if (count <= 0 || count > static_cast<int>(MaxControl)) continue;
        uint32_t peerIp = 0;
        uint16_t port = 0;
        if (peer.ss_family == AF_INET) {
            const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(peer);
            peerIp = ipv4.sin_addr.s_addr;
            port = ntohs(ipv4.sin_port);
        }
#ifndef _WIN32
        else if (peer.ss_family == AF_INET6) {
            const auto& ipv6 = reinterpret_cast<const sockaddr_in6&>(peer);
            if (!IN6_IS_ADDR_V4MAPPED(&ipv6.sin6_addr)) continue;
            std::memcpy(&peerIp, ipv6.sin6_addr.s6_addr + 12, sizeof(peerIp));
            port = ntohs(ipv6.sin6_port);
        }
#endif
        if (peerIp != serverIp_) continue;
        if (port != dailyPrevious_.load() && port != dailyCurrent_.load() && port != dailyNext_.load()) continue;
        if (session) {
            Id id{};
            uint64_t counter = 0;
            if (!UnsealControl(envelope_, session->keys.controlS2C, buffer.data(), count, id, counter, message) || id != session->session || !receiveWindow_.Accept(counter)) continue;
        } else {
            Bytes plaintext;
            if (!Unseal(envelope_, buffer.data(), count, plaintext) || !DecodeMessage(plaintext, message)) continue;
        }
        return true;
    }
    return false;
}
bool ProtocolV2Session::Exchange(const Bytes& packet, SOCKET socket, uint16_t port, const Id& request, Operation expected, const SessionSnapshot* session, Message& response, Clock::time_point deadline) {
    static constexpr int retries[] = {1000, 2000, 4000, 8000, 15000};
    size_t attempt = 0;
    for (int delay : retries) {
        if (stopping_.load() || Clock::now() >= deadline) return false;
        uint16_t destination = port;
        const auto daySecond = UnixTime() % 86400;
        if (socket == control_ && port == dailyCurrent_.load() && attempt % 2 == 1) {
            if (daySecond < 300) destination = dailyPrevious_.load();
            else if (daySecond >= 86100) destination = dailyNext_.load();
        }
        ++attempt;
        Send(socket, serverIp_, destination, packet);
        uint32_t random = 0;
        Random(reinterpret_cast<uint8_t*>(&random), sizeof(random));
        const auto until = (std::min)(deadline, Clock::now() + std::chrono::milliseconds(delay * (800 + random % 401) / 1000));
        while (Receive(response, session, until)) {
            if (response.request != request) continue;
            if (response.operation == Operation::Error) return false;
            if (response.operation == expected) return true;
        }
    }
    return false;
}
bool ProtocolV2Session::Control(const SessionSnapshot& session, Operation operation, const Bytes& body, Operation expected, Message& response, SOCKET socket, uint16_t port, Clock::time_point deadline) {
    UpdatePorts();
    Message request{operation, NewRequest(), body};
    auto packet = SealControl(envelope_, session.keys.controlC2S, session.session, ++counter_, request);
    const bool result = Exchange(packet, socket == INVALID_SOCKET ? control_ : socket, port ? port : dailyCurrent_.load(), request.request, expected, &session, response, (std::min)(deadline, Clock::now() + std::chrono::seconds(30)));
    return result;
}
bool ProtocolV2Session::Connect(uint32_t localAddress) {
    NoiseHandshake noise;
    if (!noise.Start(true, invitation_.serverKey)) return false;
    Bytes payload{1};
    Put32(payload, localAddress);
    Hello hello;
    hello.client = invitation_.clientId;
    hello.time = UnixTime();
    if (!noise.Write(payload, hello.noise)) return false;
    Message request{Operation::Hello, NewRequest(), {}};
    hello.proof = HelloProof(invitation_.clientSecret, hello.client, hello.time, request.request, invitation_.serverKey, hello.noise);
    request.body = EncodeHello(hello);
    const auto packet = Seal(envelope_, EncodeMessage(request));
    Message response;
    UpdatePorts();
    const auto deadline = Clock::now() + std::chrono::seconds(30);
    if (!Exchange(packet, control_, dailyCurrent_.load(), request.request, Operation::HelloReply, nullptr, response, deadline)) return false;
    Bytes replyPayload;
    Key hash{};
    OpenReply reply;
    if (!noise.Read(response.body, replyPayload) || !noise.Complete() || !noise.Hash(hash) || !DecodeOpenReply(replyPayload, reply)) return false;
    return Activate(reply, hash, deadline);
}
bool ProtocolV2Session::Activate(const OpenReply& reply, const Key& hash, Clock::time_point deadline) {
    if (reply.port < 1024 || (reply.port >= invitation_.portStart && reply.port <= invitation_.portEnd) || reply.addresses.empty() || reply.addresses.size() > 16) return false;
    auto pending = std::make_shared<SessionSnapshot>();
    pending->session = reply.session;
    pending->keys = DeriveSession(reply.secret, hash, invitation_.clientId, reply.session);
    pending->port = reply.port;
    for (const auto& address : reply.addresses) {
        if (!address.first || !address.second || std::any_of(pending->addresses.begin(), pending->addresses.end(), [&address](const auto& item) { return item.second == address.second; }) || !pending->addresses.emplace(address).second) return false;
    }
    pending->generation = generation_ + 1;
    const auto oldCounter = counter_;
    const auto oldWindow = receiveWindow_;
    counter_ = 0;
    receiveWindow_ = {};
    pendingPort_.store(reply.port);
    binding_.store(true);
    Message response;
    const Bytes challenge(reply.challenge.begin(), reply.challenge.end());
    bool ready = Control(*pending, Operation::Bind, challenge, Operation::Ready, response, reservation_, reply.port, (std::min)(deadline, Clock::now() + std::chrono::seconds(8)));
    if (!ready && !stopping_.load()) ready = Control(*pending, Operation::Status, {}, Operation::Ready, response, INVALID_SOCKET, 0, deadline);
    binding_.store(false);
    if (!ready) {
        if (!stopping_.load()) {
            pending_ = pending;
            pendingHash_ = hash;
            pendingUntil_ = Clock::now() + std::chrono::seconds(30);
        } else {
            counter_ = oldCounter;
            receiveWindow_ = oldWindow;
        }
        return false;
    }
    if (response.body.size() == 16) {
        boundAccepted_ = Get64(response.body.data());
        boundGeneration_ = Get64(response.body.data() + 8);
        pending->dataProbeSupported = (boundGeneration_ & DataProbeCapability) != 0;
        boundObservedAt_ = NowMillis();
    }
    hash_ = hash;
    generation_ = pending->generation;
#ifdef __ANDROID__
    pending->sendActivity = std::make_shared<AndroidSendActivity>(BootMillis());
#endif
    Publish(pending);
    state_.store(State::Ready);
    lastActivity_.store(NowMillis(), std::memory_order_relaxed);
    return true;
}
bool ProtocolV2Session::Resume(const SessionSnapshot& session) {
    state_.store(State::Recovering);
    const auto deadline = Clock::now() + std::chrono::seconds(30);
    Bytes body(session.keys.resume.begin(), session.keys.resume.end());
    body.push_back(static_cast<uint8_t>(session.addresses.size()));
    for (const auto& address : session.addresses) Put32(body, address.first);
    Message response;
    OpenReply reply;
    if (!Control(session, Operation::Resume, body, Operation::OpenReply, response, INVALID_SOCKET, 0, deadline) || !DecodeOpenReply(response.body, reply)) return false;
    if (reply.session != session.session || reply.port == session.port || reply.addresses.size() != session.addresses.size()) return false;
    for (const auto& address : reply.addresses) {
        const auto existing = session.addresses.find(address.first);
        if (existing == session.addresses.end() || existing->second != address.second) return false;
    }
    return Activate(reply, hash_, deadline);
}
void ProtocolV2Session::CloseSession(const SessionSnapshot& session) {
    Message close{Operation::Close, NewRequest(), {}};
    Send(control_, serverIp_, dailyCurrent_.load(), SealControl(envelope_, session.keys.controlC2S, session.session, ++counter_, close));
}
#ifdef _WIN32
int64_t ProtocolV2Session::SuspendedMillis() {
    ULONGLONG awake = 0;
    QueryUnbiasedInterruptTime(&awake);
    return static_cast<int64_t>(GetTickCount64()) - static_cast<int64_t>(awake / 10000);
}
#endif
void ProtocolV2Session::Run(uint32_t localAddress) {
    int64_t observedActivity = 0;
    int64_t keepaliveDeadline = 0;
    Clock::time_point resumeFailure{};
    int64_t healthDeadline = NowMillis() + 90000 + Uniform(60001);
    int64_t healthObservedAt = 0;
    uint64_t healthSent = 0, healthAccepted = 0, healthGeneration = 0, healthSessionGeneration = 0;
#ifdef _WIN32
    auto lastSuspended = suspendedMillis_();
    bool expiredDuringSleep = false;
    const auto observeSleep = [&] {
        const auto suspended = suspendedMillis_();
        constexpr auto timeout = std::chrono::milliseconds(std::chrono::minutes(5)).count();
        expiredDuringSleep |= suspended - lastSuspended >= timeout;
        lastSuspended = suspended;
    };
#endif
    const auto recover = [&](const SessionSnapshot& current) {
#ifdef _WIN32
        observeSleep();
        const bool expiredBeforeResume = expiredDuringSleep;
#endif
        const bool resumed = Resume(current);
#ifdef _WIN32
        observeSleep();
        if (resumed) expiredDuringSleep = false;
        else if (!stopping_.load() && expiredBeforeResume) {
            CloseSession(pending_ ? *pending_ : current);
            pending_.reset();
            pendingPort_.store(0);
            Publish({});
            state_.store(State::Unavailable);
            resumeFailure = {};
            return;
        } else if (!stopping_.load() && expiredDuringSleep) {
            resumeRequested_.store(true);
            return;
        }
#endif
        if (!resumed && !stopping_.load()) {
            if (pending_) return;
            if (resumeFailure == Clock::time_point{}) resumeFailure = Clock::now();
            if (Clock::now() - resumeFailure >= std::chrono::minutes(5)) {
                Publish({});
                state_.store(State::Unavailable);
                resumeFailure = {};
            } else {
                resumeRequested_.store(true);
                std::unique_lock lock(mutex_);
                wake_.wait_for(lock, std::chrono::seconds(5), [this] { return stopping_.load(); });
            }
        } else {
            resumeFailure = {};
            healthObservedAt = 0;
            healthSent = sent_.load(std::memory_order_relaxed);
        }
    };
    while (!stopping_.load()) {
#ifdef _WIN32
        observeSleep();
#endif
        if (pending_) {
            Message response;
            if (Control(*pending_, Operation::Status, {}, Operation::Ready, response, INVALID_SOCKET, 0, (std::min)(pendingUntil_, Clock::now() + std::chrono::seconds(10)))) {
                if (response.body.size() == 16) {
                    boundAccepted_ = Get64(response.body.data());
                    boundGeneration_ = Get64(response.body.data() + 8);
                    pending_->dataProbeSupported = (boundGeneration_ & DataProbeCapability) != 0;
                    boundObservedAt_ = NowMillis();
                }
                hash_ = pendingHash_;
                generation_ = pending_->generation;
                lastActivity_.store(NowMillis(), std::memory_order_relaxed);
#ifdef __ANDROID__
                pending_->sendActivity = std::make_shared<AndroidSendActivity>(BootMillis());
#endif
                Publish(pending_);
                state_.store(State::Ready);
                pending_.reset();
                healthObservedAt = 0;
                resumeRequested_.store(false);
#ifdef _WIN32
                observeSleep();
                expiredDuringSleep = false;
#endif
            } else {
#ifdef _WIN32
                observeSleep();
                if (expiredDuringSleep) {
                    pendingPort_.store(0);
                    resumeFailure = {};
                }
                const bool discard = expiredDuringSleep || Clock::now() >= pendingUntil_;
#else
                const bool discard = Clock::now() >= pendingUntil_;
#endif
                if (!discard) {
                    std::unique_lock lock(mutex_);
                    wake_.wait_for(lock, std::chrono::seconds(1), [this] { return stopping_.load(); });
                    continue;
                }
                CloseSession(*pending_);
                pending_.reset();
                Publish({});
                state_.store(State::Unavailable);
            }
        }
        auto current = Snapshot();
        if (!current) {
#ifdef _WIN32
            if (expiredDuringSleep) resumeRequested_.store(false);
            expiredDuringSleep = false;
#endif
            if (!localAddress) {
                std::unique_lock lock(mutex_);
                if (addresses_.empty()) {
                    wake_.wait_for(lock, std::chrono::milliseconds(250), [this] { return stopping_.load() || !addresses_.empty() || diagnostic_; });
                    continue;
                }
                localAddress = addresses_.front();
                addresses_.pop_front();
            }
            if (!Connect(localAddress)) {
                state_.store(State::Unavailable);
                std::unique_lock lock(mutex_);
                wake_.wait_for(lock, std::chrono::seconds(5), [this] { return stopping_.load(); });
                continue;
            }
            current = Snapshot();
        }
#ifdef _WIN32
        if (expiredDuringSleep) {
            resumeRequested_.store(false);
            recover(*current);
            continue;
        }
#endif
        if (healthSessionGeneration != current->generation) {
            healthSessionGeneration = current->generation;
            healthObservedAt = boundObservedAt_;
            healthAccepted = boundAccepted_;
            healthGeneration = boundGeneration_;
            healthSent = sent_.load(std::memory_order_relaxed);
            healthDeadline = NowMillis() + 90000 + Uniform(60001);
        }
        std::shared_ptr<std::promise<Bytes>> diagnostic;
        {
            std::lock_guard lock(mutex_);
            diagnostic = std::move(diagnostic_);
        }
        if (diagnostic) {
            Message response;
            const bool received = Control(*current, Operation::DiagnosticOpen, {}, Operation::DiagnosticReply,
                response, INVALID_SOCKET, 0, Clock::now() + std::chrono::seconds(8));
            diagnostic->set_value(received ? std::move(response.body) : Bytes{});
        }
        uint32_t address = 0;
        {
            std::lock_guard lock(mutex_);
            if (!addresses_.empty()) {
                address = addresses_.front();
                addresses_.pop_front();
            }
        }
        if (address && !current->addresses.count(address)) {
            Bytes body;
            Put32(body, address);
            Message response;
            if (Control(*current, Operation::AddAddress, body, Operation::AddressReply, response) && response.body.size() == 8 && Get32(response.body.data()) == address && Get32(response.body.data() + 4) != 0 && std::none_of(current->addresses.begin(), current->addresses.end(), [&response](const auto& entry) { return entry.second == Get32(response.body.data() + 4); })) {
                auto updated = std::make_shared<SessionSnapshot>(*current);
                if (updated->addresses.size() < 16 && std::none_of(updated->addresses.begin(), updated->addresses.end(), [address](const auto& entry) { return entry.first == address; })) {
                    updated->addresses.emplace(address, Get32(response.body.data() + 4));
                    Publish(updated);
                }
            }
        }
        current = Snapshot();
        const auto activity = lastActivity_.load(std::memory_order_relaxed);
        if (activity != observedActivity || !keepaliveDeadline) {
            observedActivity = activity;
            keepaliveDeadline = activity + 30000 + Uniform(30001);
        }
        if (NowMillis() >= keepaliveDeadline
#ifdef __ANDROID__
            && !AndroidSendStale(*current)
#endif
        ) {
            Bytes keepalive;
            if (EncryptKeepalive(current->keys.dataC2S, current->keys.prefixC2S, keepalive, maximumPayload_.load(std::memory_order_relaxed)) && Send(reservation_, serverIp_, current->port, keepalive)) {
#ifdef __ANDROID__
                if (const auto now = BootMillis(); now && current->sendActivity)
                    current->sendActivity->lastKeepalive.store(now, std::memory_order_relaxed);
#endif
                MarkActivity();
            }
        }
        if (NowMillis() >= healthDeadline) {
            const auto outgoing = sent_.load(std::memory_order_relaxed);
            if (outgoing > healthSent) {
                Message response;
                if (Control(*current, Operation::Status, {}, Operation::Ready, response) && response.body.size() == 16) {
                    const auto accepted = Get64(response.body.data());
                    const auto generation = Get64(response.body.data() + 8);
                    if (healthObservedAt && generation == healthGeneration && accepted == healthAccepted && outgoing > healthSent && NowMillis() - healthObservedAt >= 30000)
                        RequestResume();
                    healthObservedAt = NowMillis();
                    healthAccepted = accepted;
                    healthGeneration = generation;
                    healthSent = outgoing;
                } else if (!stopping_.load()) RequestResume();
            }
            healthDeadline = NowMillis() + 90000 + Uniform(60001);
        }
        if (resumeRequested_.exchange(false)) {
            recover(*current);
            if (pending_) continue;
        }
        std::unique_lock lock(mutex_);
        wake_.wait_for(lock, std::chrono::milliseconds(250), [this] { return stopping_.load() || resumeRequested_.load() || !addresses_.empty() || diagnostic_; });
    }
    if (auto current = pending_ ? std::shared_ptr<const SessionSnapshot>(pending_) : Snapshot())
        CloseSession(*current);
}
}
