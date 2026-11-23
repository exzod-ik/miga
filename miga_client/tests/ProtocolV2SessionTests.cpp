#include "../include/ProtocolV2Session.h"
#include <array>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <stdexcept>

using namespace miga::v2;
using Clock = std::chrono::steady_clock;
#ifdef _WIN32
namespace miga::v2 {
struct ProtocolV2SessionTestAccess {
    static void SetSuspendedMillis(ProtocolV2Session& session, int64_t (*clock)()) {
        session.suspendedMillis_ = clock;
    }
};
}
#endif
namespace {
#ifdef _WIN32
using SocketLength = int;
#else
using SocketLength = socklen_t;
void closesocket(SOCKET socket) { close(socket); }
void WSACleanup() {}
SOCKET DualSocket() {
    const auto socket = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    int only = 0;
    if (socket < 0 || setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only))) throw std::runtime_error("dual socket");
    sockaddr_in6 local{}; local.sin6_family = AF_INET6;
    if (bind(socket, reinterpret_cast<sockaddr*>(&local), sizeof(local))) { close(socket); throw std::runtime_error("dual bind"); }
    return socket;
}
#endif
void Require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
SOCKET BoundSocket() {
    SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Require(socket != INVALID_SOCKET, "socket");
    sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(socket, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) { closesocket(socket); throw std::runtime_error("bind loopback"); }
    return socket;
}
uint16_t Port(SOCKET socket) {
    sockaddr_in local{}; SocketLength size = sizeof(local);
    Require(getsockname(socket, reinterpret_cast<sockaddr*>(&local), &size) == 0, "getsockname");
    return ntohs(local.sin_port);
}
void Send(SOCKET socket, const sockaddr_in& peer, const Bytes& bytes) {
    Require(sendto(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) == static_cast<int>(bytes.size()), "sendto");
}
struct Responder {
    enum class ResumeMode { Accept, Reject, RejectConfirmation };
    SOCKET control = BoundSocket(), data = BoundSocket(), replacement = INVALID_SOCKET;
    Invitation invitation;
    Key privateKey{}, hash{}, envelope{};
    OpenReply offer;
    SessionKeys keys;
    sockaddr_in controlPeer{};
    uint64_t counter = 0, generation = 0;
    bool tamper, dropBindReady;
    std::chrono::seconds dropAllDuration;
    Clock::time_point dropAllUntil{};
    Id firstSession{};
    std::atomic<unsigned> helloCount{0}, resumeCount{0}, rejectedStatusCount{0}, droppedReadyCount{0}, droppedStatusCount{0};
    std::atomic<ResumeMode> resumeMode{ResumeMode::Accept};
    uint16_t lastBoundPort = 0;
    std::atomic<bool> stopping{false}, failed{false}, closed{false}, sawHello{false};
    std::thread thread;
    explicit Responder(bool tamperReply = false, bool loseReady = false, std::chrono::seconds loseAll = std::chrono::seconds(0)) : tamper(tamperReply), dropBindReady(loseReady), dropAllDuration(loseAll) {
        Require(NoiseHandshake::GenerateKeypair(privateKey, invitation.serverKey), "server keypair");
        Random(invitation.serverSecret.data(), invitation.serverSecret.size());
        Random(invitation.clientSecret.data(), invitation.clientSecret.size());
        Random(invitation.clientId.data(), invitation.clientId.size());
        invitation.host = "127.0.0.1";
        invitation.portStart = invitation.portEnd = Port(control);
        envelope = EnvelopeKey(invitation.serverSecret);
        thread = std::thread([this] {
            try { Run(); }
            catch (const std::exception& error) {
                std::fprintf(stderr, "Responder failure: %s\n", error.what());
                failed.store(true);
            }
        });
    }
    ~Responder() {
        stopping.store(true); if (thread.joinable()) thread.join();
        closesocket(control); closesocket(data); if (replacement != INVALID_SOCKET) closesocket(replacement);
    }
    void Ready(const Message& request) {
        if (resumeMode.load() == ResumeMode::RejectConfirmation && offer.port != Port(data)) {
            ReplyError(request);
            if (request.operation == Operation::Status) rejectedStatusCount.fetch_add(1);
            return;
        }
        if (dropAllUntil != Clock::time_point{} && Clock::now() < dropAllUntil) {
            droppedReadyCount.fetch_add(1);
            if (request.operation == Operation::Status) droppedStatusCount.fetch_add(1);
            return;
        }
        Message reply{Operation::Ready, request.request, {}};
        Put64(reply.body, 0); Put64(reply.body, generation);
        Send(control, controlPeer, SealControl(envelope, keys.controlS2C, offer.session, ++counter, reply));
    }
    void ReplyError(const Message& request) {
        const Message reply{Operation::Error, request.request, {}};
        Send(control, controlPeer, SealControl(envelope, keys.controlS2C, offer.session, ++counter, reply));
    }
    void HandleControl(const uint8_t* packet, size_t length, const sockaddr_in& peer) {
        Bytes plaintext; Message request;
        if (Unseal(envelope, packet, length, plaintext) && DecodeMessage(plaintext, request) && request.operation == Operation::Hello) {
            Hello hello;
            Require(DecodeHello(request.body, hello), "decode hello");
            Require(hello.client == invitation.clientId && hello.proof == HelloProof(invitation.clientSecret, hello.client, hello.time, request.request, invitation.serverKey, hello.noise), "personal hello proof");
            NoiseHandshake noise; Require(noise.Start(false, invitation.serverKey, &privateKey), "noise responder start");
            Bytes payload; Require(noise.Read(hello.noise, payload) && payload.size() == 5 && payload[0] == 1, "noise hello payload");
            controlPeer = peer;
            Random(offer.session.data(), offer.session.size());
            if (helloCount.load() == 0) firstSession = offer.session;
            helloCount.fetch_add(1);
            Random(offer.secret.data(), offer.secret.size()); Random(offer.challenge.data(), offer.challenge.size());
            offer.port = Port(data); offer.addresses = {{Get32(payload.data() + 1), 0x0a4d0002}};
            Message reply{Operation::HelloReply, request.request, {}};
            Require(noise.Write(EncodeOpenReply(offer), reply.body) && noise.Complete() && noise.Hash(hash), "noise reply");
            keys = DeriveSession(offer.secret, hash, invitation.clientId, offer.session);
            auto sealed = Seal(envelope, EncodeMessage(reply));
            if (tamper) sealed.back() ^= 1;
            Send(control, peer, sealed); sawHello.store(true); return;
        }
        Id session{}; uint64_t received = 0;
        if (!UnsealControl(envelope, keys.controlC2S, packet, length, session, received, request) || session != offer.session) return;
        if (request.operation == Operation::AddAddress) {
            Require(request.body.size() == 4, "address request");
            const uint32_t local = Get32(request.body.data());
            const uint32_t virtualIp = 0x0a4d0002 + static_cast<uint32_t>(offer.addresses.size());
            offer.addresses.emplace_back(local, virtualIp);
            Message reply{Operation::AddressReply, request.request, request.body}; Put32(reply.body, virtualIp);
            Send(control, peer, SealControl(envelope, keys.controlS2C, offer.session, ++counter, reply));
        } else if (request.operation == Operation::Resume) {
            Require(request.body.size() == 33 + offer.addresses.size() * 4 && std::equal(keys.resume.begin(), keys.resume.end(), request.body.begin()), "resume proof");
            resumeCount.fetch_add(1);
            if (resumeMode.load() == ResumeMode::Reject) { ReplyError(request); return; }
            replacement = BoundSocket();
            OpenReply next = offer;
            Random(next.secret.data(), next.secret.size()); Random(next.challenge.data(), next.challenge.size());
            next.port = Port(replacement);
            Message reply{Operation::OpenReply, request.request, EncodeOpenReply(next)};
            Send(control, peer, SealControl(envelope, keys.controlS2C, offer.session, ++counter, reply));
            offer = next; keys = DeriveSession(offer.secret, hash, invitation.clientId, offer.session); counter = 0;
        } else if (request.operation == Operation::DiagnosticOpen) {
            Message reply{Operation::DiagnosticReply, request.request, Bytes(66, 7)};
            Send(control, peer, SealControl(envelope, keys.controlS2C, offer.session, ++counter, reply));
        } else if (request.operation == Operation::Status) Ready(request);
        else if (request.operation == Operation::Close) closed.store(true);
    }
    void Run() {
        while (!stopping.load()) {
            fd_set read; FD_ZERO(&read); FD_SET(control, &read); FD_SET(data, &read);
            if (replacement != INVALID_SOCKET) FD_SET(replacement, &read);
            timeval timeout{0, 50000};
            const int selected = select(static_cast<int>((std::max)(control, (std::max)(data, replacement == INVALID_SOCKET ? data : replacement))) + 1, &read, nullptr, nullptr, &timeout); if (selected < 0) throw std::runtime_error("select failed"); if (!selected) continue;
            const std::array<SOCKET, 3> sockets{control, data, replacement};
            for (auto socket : sockets) {
                if (socket == INVALID_SOCKET || !FD_ISSET(socket, &read)) continue;
                std::array<uint8_t, MaxControl + 1> packet{}; sockaddr_in peer{}; SocketLength peerSize = sizeof(peer);
                const int length = recvfrom(socket, reinterpret_cast<char*>(packet.data()), static_cast<int>(packet.size()), 0, reinterpret_cast<sockaddr*>(&peer), &peerSize);
                if (length <= 0) continue;
                if (socket == control) HandleControl(packet.data(), static_cast<size_t>(length), peer);
                else {
                    Id session{}; uint64_t received = 0; Message request;
                    if (!UnsealControl(envelope, keys.controlC2S, packet.data(), static_cast<size_t>(length), session, received, request)) {
                        Bytes plaintext;
                        Require(DecryptData(keys.dataC2S, keys.prefixC2S, packet.data(), static_cast<size_t>(length), plaintext), "data or keepalive decryption");
                        size_t actual = 0;
                        bool keepalive = false;
                        Require(ValidateInner(plaintext.data(), plaintext.size(), actual, keepalive) && keepalive, "test responder accepts only keepalive data");
                        continue;
                    }
                    Require(session == offer.session && request.operation == Operation::Bind && request.body == Bytes(offer.challenge.begin(), offer.challenge.end()), "bind challenge");
                    if (lastBoundPort != offer.port) {
                        ++generation;
                        lastBoundPort = offer.port;
                        if (generation == 1 && dropAllDuration.count() != 0)
                            dropAllUntil = Clock::now() + dropAllDuration;
                    }
                    if (!dropBindReady || generation != 1) Ready(request);
                }
            }
        }
    }
};
template<class Predicate> void Await(Predicate predicate, const Responder& server, const char* reason, std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        Require(!server.failed.load(), "responder assertion");
        if (predicate()) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    throw std::runtime_error(reason);
}
void ConnectedLifecycle(bool dual = false) {
    Responder server;
    SOCKET reservation = BoundSocket();
    SOCKET supplied = INVALID_SOCKET;
#ifndef _WIN32
    if (dual) { closesocket(reservation); reservation = DualSocket(); supplied = DualSocket(); }
#else
    (void)dual;
#endif
    {
        ProtocolV2Session client(server.invitation, htonl(INADDR_LOOPBACK), reservation);
        client.SetMaximumPayload(1200);
        Require(client.Start(0, supplied), "start without route");
        Require(!client.Snapshot() && client.Status() == "connecting", "no ready status before address");
        Require(client.RequestAddress(0x7f000001), "first address request");
        Await([&] { return client.Snapshot() != nullptr; }, server, "initial session timeout");
        Require(client.OpenDiagnostics() == Bytes(66, 7), "diagnostic parameters through authenticated control");
        auto initial = client.Snapshot();
        Require(client.Status() == "ready", "ready status after BIND");
        Require(initial->addresses.at(0x7f000001) == 0x0a4d0002 && initial->port == Port(server.data), "initial mapping and endpoint");
        Require(client.IsControlTuple(INADDR_LOOPBACK, initial->port, Port(reservation), true), "own outbound bypass");
        Require(!client.IsControlTuple(INADDR_LOOPBACK, initial->port, Port(reservation), false), "inbound data retained");
        Require(client.RequestAddress(0x7f000002), "additional address request");
        Await([&] { return client.Snapshot()->addresses.count(0x7f000002) != 0; }, server, "additional address timeout");
        auto beforeResume = client.Snapshot();
        client.RequestResume();
        Require(client.Status() == "recovering", "recovery status");
        Await([&] { auto state = client.Snapshot(); return state && state->generation > beforeResume->generation; }, server, "resume timeout");
        auto resumed = client.Snapshot();
        Require(resumed->session == initial->session && resumed->port != initial->port && resumed->addresses == beforeResume->addresses && resumed->keys.dataC2S != initial->keys.dataC2S, "resume preserves identity and mappings with fresh transport");
        client.Stop();
        Await([&] { return server.closed.load(); }, server, "authenticated close timeout", std::chrono::seconds(1));
        Require(!client.Snapshot() && client.Status() == "unavailable", "stop clears snapshot and status");
    }
    closesocket(reservation);
}
#ifdef _WIN32
std::atomic<int64_t> suspendedMillis{0};
int64_t SuspendedMillis() { return suspendedMillis.load(); }
void LongSleepRecovery(Responder::ResumeMode mode, bool alreadyPending = false) {
    Responder server;
    SOCKET reservation = BoundSocket();
    {
        ProtocolV2Session client(server.invitation, htonl(INADDR_LOOPBACK), reservation);
        suspendedMillis.store(0);
        ProtocolV2SessionTestAccess::SetSuspendedMillis(client, SuspendedMillis);
        Require(client.Start(0x7f000001), "sleep recovery start");
        Await([&] { return client.Snapshot() != nullptr; }, server, "sleep recovery initial session");
        const auto initial = client.Snapshot();
        server.resumeMode.store(mode);
        if (alreadyPending) {
            client.RequestResume();
            Await([&] { return server.rejectedStatusCount.load() >= 2; }, server, "pending recovery before sleep");
        } else if (mode == Responder::ResumeMode::Accept) {
            suspendedMillis.store(299999);
            std::this_thread::sleep_for(std::chrono::milliseconds(600));
            Require(server.resumeCount.load() == 0, "sleep below the server idle timeout does not force recovery");
        }
        suspendedMillis.fetch_add(300000);
        Await([&] {
            const auto next = client.Snapshot();
            return next && next->generation > initial->generation;
        }, server, "recovery after five minutes of sleep");
        const auto recovered = client.Snapshot();
        const bool resumed = mode == Responder::ResumeMode::Accept;
        Require((recovered->session == initial->session) == resumed, "resume preserves the session, failure opens a fresh one");
        Require(server.helloCount.load() == (resumed ? 1u : 2u) && server.resumeCount.load() == 1, "one resume before reconnect");
        if (mode == Responder::ResumeMode::RejectConfirmation && !alreadyPending)
            Require(server.rejectedStatusCount.load() == 1, "failed resume confirmation skips pending reconciliation");
        client.Stop();
    }
    closesocket(reservation);
}
#endif
void LostReadyStatusRecovery() {
    Responder server(false, true);
    SOCKET reservation = BoundSocket();
    {
        ProtocolV2Session client(server.invitation, htonl(INADDR_LOOPBACK), reservation);
        Require(client.Start(0x7f000001), "lost READY start");
        Await([&] { return client.Snapshot() != nullptr; }, server, "STATUS reconciles lost READY", std::chrono::seconds(10));
        Require(client.Snapshot()->addresses.at(0x7f000001) == 0x0a4d0002, "lost READY mapping");
        client.Stop();
    }
    closesocket(reservation);
}
void InitialAllConfirmationLossRecovery() {
    Responder server(false, false, std::chrono::seconds(31));
    SOCKET reservation = BoundSocket();
    {
        ProtocolV2Session client(server.invitation, htonl(INADDR_LOOPBACK), reservation);
        const auto started = Clock::now();
        Require(client.Start(0x7f000001), "initial complete loss start");
        Await([&] { return server.sawHello.load(); }, server, "initial complete loss hello");
        const Id original = server.firstSession;
        std::this_thread::sleep_until(started + std::chrono::seconds(31));
        Require(!server.failed.load(), "complete loss responder remains valid");
        Require(!client.Snapshot() && client.Status() != "ready", "no ready snapshot after initial thirty-second loss");
        Require(server.droppedReadyCount.load() > 1 && server.droppedStatusCount.load() > 0, "all BIND and STATUS confirmations dropped");
        Require(server.helloCount.load() == 1, "no new HELLO after initial deadline");
        Await([&] { return client.Snapshot() != nullptr; }, server, "pending initial STATUS reconciliation", std::chrono::seconds(12));
        const auto recovered = client.Snapshot();
        Require(recovered->session == original && recovered->generation == 1 && recovered->port == Port(server.data), "same initial session and reservation recovered");
        Require(recovered->addresses.at(0x7f000001) == 0x0a4d0002 && client.Status() == "ready", "initial recovered mapping and status");
        Require(server.helloCount.load() == 1, "reconciliation did not allocate another handshake or session");
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
        std::printf("Initial confirmation loss: elapsed_ms=%lld hello_count=%u dropped_confirmations=%u dropped_status=%u same_session=true generation=1\n", static_cast<long long>(elapsed), server.helloCount.load(), server.droppedReadyCount.load(), server.droppedStatusCount.load());
        client.Stop();
        Await([&] { return server.closed.load(); }, server, "reconciled session authenticated close", std::chrono::seconds(1));
    }
    closesocket(reservation);
}
void TamperedReplyAndStop() {
    Responder server(true);
    SOCKET reservation = BoundSocket();
    {
        ProtocolV2Session client(server.invitation, htonl(INADDR_LOOPBACK), reservation);
        Require(client.Start(0x7f000001), "tampered test start");
        Await([&] { return server.sawHello.load(); }, server, "tampered hello timeout");
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        Require(!client.Snapshot() && client.Status() != "ready", "tampered envelope cannot become ready");
        const auto before = Clock::now(); client.Stop();
        Require(Clock::now() - before < std::chrono::seconds(1), "stop cancels outstanding handshake");
    }
    closesocket(reservation);
}
}
int main() {
#ifdef _WIN32
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
#endif
    if (!Initialize()) return 1;
    try {
        AndroidSendActivity activity(1000);
        Require(!activity.Stale(90999) && activity.Stale(91000), "initial Android activity deadline");
        activity.lastData.store(50000);
        activity.lastKeepalive.store(80000);
        Require(!activity.Stale(169999) && activity.Stale(170000), "Android keepalive extends activity deadline");
        activity.lastData.store(150000);
        Require(!activity.Stale(239999) && activity.Stale(240000), "Android data extends activity deadline");
        ConnectedLifecycle();
#ifndef _WIN32
        ConnectedLifecycle(true);
#else
        LongSleepRecovery(Responder::ResumeMode::Accept);
        LongSleepRecovery(Responder::ResumeMode::Reject);
        LongSleepRecovery(Responder::ResumeMode::RejectConfirmation);
        LongSleepRecovery(Responder::ResumeMode::RejectConfirmation, true);
        std::puts("ProtocolV2Session: short and long sleep, resume rejection and pending recovery passed");
#endif
        LostReadyStatusRecovery(); InitialAllConfirmationLossRecovery(); TamperedReplyAndStop();
        std::puts("ProtocolV2Session: loopback Noise/BIND/ADD_ADDRESS/RESUME/CLOSE lost READY/STATUS and tampered reply/Stop passed");
    } catch (const std::exception& error) { std::fprintf(stderr, "ProtocolV2Session failure: %s\n", error.what()); WSACleanup(); return 1; }
    WSACleanup(); return 0;
}
