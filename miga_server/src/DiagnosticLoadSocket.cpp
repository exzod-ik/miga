#include "DiagnosticLoadSocket.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <cerrno>
#include <chrono>
#include <stdexcept>
#include <iostream>

using namespace miga::diagnostics;
DiagnosticLoadSocket::~DiagnosticLoadSocket() { Stop(); }
void DiagnosticLoadSocket::Stop() {
    enabled.store(false); stopping_.store(true);
    if (thread_.joinable()) thread_.join();
    if (socket_ >= 0) { close(socket_); socket_ = -1; }
    if (firewallAdded_ && firewall && !firewall(port_, false))
        std::cerr << "diagnostic_load_firewall_cleanup_failed port=" << port_ << "\n";
    firewallAdded_ = false; counters.Clear();
}
DiagnosticLoadSocket::Json DiagnosticLoadSocket::Prepare(const Json& r, uint32_t address) {
    Stop();
    const int bytes = r.at("bytes"), port = r.at("local_port");
    if (!address || bytes < 32 || bytes > 1200 || port < 1 || port > 65535) throw std::invalid_argument("load_parameters");
    counters.Configure(r);
    try {
        socket_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (socket_ < 0) throw std::runtime_error("load_socket");
        sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = address;
        if (bind(socket_, reinterpret_cast<sockaddr*>(&local), sizeof(local))) throw std::runtime_error("load_bind");
        socklen_t size = sizeof(local);
        if (getsockname(socket_, reinterpret_cast<sockaddr*>(&local), &size)) throw std::runtime_error("load_port");
        port_ = ntohs(local.sin_port);
        if (port_ <= 15000) throw std::runtime_error("load_port_range");
        int buffer = 4 * 1024 * 1024;
        setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)); size = sizeof(receiveBuffer_);
        getsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &receiveBuffer_, &size);
        if (receiveBuffer_ < 8 * 1024 * 1024) {
            setsockopt(socket_, SOL_SOCKET, SO_RCVBUFFORCE, &buffer, sizeof(buffer));
            if (getsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &receiveBuffer_, &size) || receiveBuffer_ < 8 * 1024 * 1024) throw std::runtime_error("load_receive_buffer");
        }
        int yes = 1;
        if (setsockopt(socket_, SOL_SOCKET, SO_RXQ_OVFL, &yes, sizeof(yes))) throw std::runtime_error("load_drop_counter");
        if (!firewall || !firewall(port_, true)) throw std::runtime_error("load_firewall");
        firewallAdded_ = true;
        {
            std::lock_guard lock(mutex_);
            address_ = address; clientPort_ = uint16_t(port); peer_ = {}; peerReady_ = false;
            identity_ = {std::stoull(r.at("run").get<std::string>(), nullptr, 16), r.at("step").get<uint32_t>(), 0, r.at("direction").get<uint8_t>()};
            rate_ = r.at("rate"); seconds_ = r.at("seconds"); bytes_ = bytes;
        }
        socketDrops_.store(0); sendLate_.store(0); sending_.store(false); stopping_.store(false); enabled.store(true);
        thread_ = std::thread([this] {
            try { Run(); } catch (...) { std::cerr << "diagnostic_load_worker_failed\n"; }
            enabled.store(false);
        });
        char text[INET_ADDRSTRLEN]{}; in_addr ip{address}; inet_ntop(AF_INET, &ip, text, sizeof(text));
        return {{"ok", true}, {"ip", text}, {"port", port_}, {"receive_buffer", receiveBuffer_}};
    } catch (...) { Stop(); throw; }
}
void DiagnosticLoadSocket::Observe(const uint8_t* p, size_t n) {
    if (!enabled.load(std::memory_order_relaxed)) return;
    Probe probe; if (!ReadProbePacket(p, n, probe)) return;
    const size_t h = size_t(p[0] & 15) * 4;
    std::lock_guard lock(mutex_);
    uint32_t destination; std::memcpy(&destination, p + 16, 4);
    if (probe.run != identity_.run || probe.step != identity_.step || probe.direction != 2 || destination != address_ ||
        (unsigned(p[h]) << 8 | p[h + 1]) != clientPort_ || (unsigned(p[h + 2]) << 8 | p[h + 3]) != port_) return;
    if (!peer_.sin_family) { peer_.sin_family = AF_INET; peer_.sin_port = htons(clientPort_); std::memcpy(&peer_.sin_addr.s_addr, p + 12, 4); }
}
DiagnosticLoadSocket::Json DiagnosticLoadSocket::StartSending() {
    std::lock_guard lock(mutex_);
    if (!enabled.load() || !peerReady_ || identity_.direction != 1 || sending_.exchange(true)) return {{"ok", false}, {"error", "load_peer_not_ready"}};
    return {{"ok", true}};
}
DiagnosticLoadSocket::Json DiagnosticLoadSocket::Stats() {
    return {{"ok", true}, {"stages", counters.Snapshot()}, {"socket_drops", socketDrops_.load()},
        {"receive_buffer", receiveBuffer_}, {"sender_late", sendLate_.load()}};
}
void DiagnosticLoadSocket::Run() {
    using Clock = std::chrono::steady_clock;
    const auto expires = Clock::now() + std::chrono::seconds(seconds_ + 30);
    auto start = Clock::time_point{};
    uint32_t sequence = 0;
    std::vector<uint8_t> output(size_t(bytes_), 0xa5);
    std::array<uint8_t, 2048> input{};
    while (!stopping_.load() && Clock::now() < expires) {
        if (sending_.load()) {
            if (start == Clock::time_point{}) start = Clock::now();
            if (Clock::now() - start >= std::chrono::seconds(seconds_)) sequence = uint32_t(rate_ * seconds_);
            for (int batch = 0; batch < 32 && sequence < uint32_t(rate_ * seconds_); ++batch) {
                const auto due = start + std::chrono::nanoseconds(int64_t(sequence) * 1000000000 / rate_);
                if (Clock::now() < due) break;
                if (Clock::now() - due > std::chrono::milliseconds(10)) sendLate_.fetch_add(1);
                auto probe = identity_; probe.sequence = sequence++; WriteProbe(output.data(), output.size(), probe);
                sockaddr_in peer; { std::lock_guard lock(mutex_); peer = peer_; }
                const auto sent = sendto(socket_, output.data(), output.size(), 0, reinterpret_cast<sockaddr*>(&peer), sizeof(peer));
                counters.Record(LoadCounters::AppSent, probe, sent == static_cast<ssize_t>(output.size()));
            }
        }
        pollfd event{socket_, POLLIN, 0}; poll(&event, 1, 1);
        for (int batch = 0; batch < 64; ++batch) {
            sockaddr_in peer{}; std::array<char, CMSG_SPACE(sizeof(uint32_t))> control{};
            iovec io{input.data(), input.size()}; msghdr message{}; message.msg_name = &peer; message.msg_namelen = sizeof(peer);
            message.msg_iov = &io; message.msg_iovlen = 1; message.msg_control = control.data(); message.msg_controllen = control.size();
            const auto size = recvmsg(socket_, &message, 0); if (size < 0) break;
            for (auto* c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c))
                if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_RXQ_OVFL && c->cmsg_len >= CMSG_LEN(sizeof(uint32_t))) {
                    uint32_t drops; std::memcpy(&drops, CMSG_DATA(c), sizeof(drops)); socketDrops_.store(drops);
                }
            Probe probe; if ((message.msg_flags & MSG_TRUNC) || !ReadProbe(input.data(), size_t(size), probe)) continue;
            {
                std::lock_guard lock(mutex_);
                if (probe.run != identity_.run || probe.step != identity_.step || peer.sin_addr.s_addr != peer_.sin_addr.s_addr || peer.sin_port != peer_.sin_port) continue;
                if (probe.direction == 2) {
                    peerReady_ = true;
                    sendto(socket_, input.data(), size_t(size), 0, reinterpret_cast<sockaddr*>(&peer), sizeof(peer));
                    continue;
                }
            }
            counters.Record(LoadCounters::AppReceived, probe);
        }
    }
}
