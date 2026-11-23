#include "../src/NetworkRuntimeImpl.h"
#include <cassert>
#include <iostream>
#include <filesystem>

namespace miga::v2 {
struct ProtocolV2SessionTestAccess {
    static void Ready(ProtocolV2Session& session, uint16_t port) {
        auto state = std::make_shared<SessionSnapshot>();
        state->port = port;
        state->addresses.emplace(0xc0000201, 0x0a420001);
        Random(state->keys.dataC2S.data(), state->keys.dataC2S.size());
        Random(state->keys.dataS2C.data(), state->keys.dataS2C.size());
        session.Publish(state);
    }
    static void SetControl(ProtocolV2Session& session, uint16_t localPort, uint16_t remotePort) {
        session.controlLocal_.store(localPort);
        session.dailyCurrent_.store(remotePort);
    }
    static bool TakeResume(ProtocolV2Session& session) { return session.resumeRequested_.exchange(false); }
    static size_t MaximumPayload(ProtocolV2Session& session) { return session.maximumPayload_.load(); }
};
}

namespace {
std::vector<std::vector<uint8_t>> submissions;
std::mutex submissionMutex;
struct SendState {DWORD length; bool cancelled = false;};
std::unordered_map<OVERLAPPED*, SendState> pendingSends;
BOOL PendingSend(HANDLE, const VOID*, UINT length, UINT*, UINT64,
    const WINDIVERT_ADDRESS*, UINT, OVERLAPPED* operation) {
    pendingSends.emplace(operation, SendState{length}); SetLastError(ERROR_IO_PENDING); return FALSE;
}
BOOL WINAPI SendResult(HANDLE, OVERLAPPED* operation, DWORD* bytes, BOOL) {
    auto found = pendingSends.find(operation); assert(found != pendingSends.end());
    *bytes = found->second.length; const auto cancelled = found->second.cancelled; pendingSends.erase(found);
    if (cancelled) {SetLastError(ERROR_OPERATION_ABORTED); return FALSE;}
    return TRUE;
}
BOOL WINAPI CancelSend(HANDLE, OVERLAPPED* operation) {
    pendingSends.at(operation).cancelled = true; SetEvent(operation->hEvent); return TRUE;
}
struct ReceiveState {
    void* bytes; UINT capacity; WINDIVERT_ADDRESS* addresses; UINT* addressLength;
    DWORD length = 0; bool complete = false, cancelled = false;
};
std::mutex receiveMutex;
std::condition_variable receiveChanged;
std::unordered_map<OVERLAPPED*, ReceiveState> receiveStates;
BOOL ReceiveMock(HANDLE, void* bytes, UINT capacity, UINT*, UINT64, WINDIVERT_ADDRESS* addresses,
    UINT* addressLength, OVERLAPPED* operation) {
    std::lock_guard lock(receiveMutex);
    assert(operation && bytes && capacity >= 65535);
    receiveStates.emplace(operation, ReceiveState{bytes, capacity, addresses, addressLength});
    receiveChanged.notify_all(); SetLastError(ERROR_IO_PENDING); return FALSE;
}
BOOL WINAPI ResultMock(HANDLE, OVERLAPPED* operation, DWORD* bytes, BOOL wait) {
    if (wait) WaitForSingleObject(operation->hEvent, INFINITE);
    std::lock_guard lock(receiveMutex);
    auto found = receiveStates.find(operation); assert(found != receiveStates.end());
    if (!found->second.complete && !found->second.cancelled) {SetLastError(ERROR_IO_INCOMPLETE); return FALSE;}
    *bytes = found->second.length; const bool cancelled = found->second.cancelled;
    receiveStates.erase(found);
    if (cancelled) {SetLastError(ERROR_OPERATION_ABORTED); return FALSE;}
    return TRUE;
}
BOOL WINAPI CancelMock(HANDLE, OVERLAPPED* operation) {
    std::lock_guard lock(receiveMutex);
    auto found = receiveStates.find(operation);
    if (found == receiveStates.end()) {SetLastError(ERROR_NOT_FOUND); return FALSE;}
    found->second.cancelled = true; SetEvent(operation->hEvent); return TRUE;
}
BOOL CloseMock(HANDLE) {return TRUE;}
BOOL ShutdownMock(HANDLE, WINDIVERT_SHUTDOWN) {return TRUE;}
BOOL SendMock(HANDLE, const VOID* data, UINT length, UINT* sent, UINT64,
    const WINDIVERT_ADDRESS*, UINT addresses, OVERLAPPED*) {
    std::lock_guard lock(submissionMutex);
    size_t offset = 0;
    for (UINT i = 0; i < addresses / sizeof(WINDIVERT_ADDRESS); ++i) {
        const auto size = Ipv4BatchPacketLength(static_cast<const uint8_t*>(data), length, offset);
        assert(size);
        const auto* packet = static_cast<const uint8_t*>(data) + offset;
        submissions.emplace_back(packet, packet + size); offset += size;
    }
    assert(offset == length);
    if (sent) *sent = length;
    return TRUE;
}
Packet MakePacket(bool tcp, uint16_t port = 5000, uint16_t remote = 443, uint32_t sequence = 123) {
    Packet packet;
    packet.bytes = std::make_shared<std::vector<uint8_t>>(tcp ? 40 : 29, 0);
    auto* data = packet.bytes->data();
    data[0] = 0x45; Write16(data + 2, static_cast<uint16_t>(packet.bytes->size()));
    data[8] = 64; data[9] = tcp ? 6 : 17;
    Write32(data + 12, 0xc0000201); Write32(data + 16, 0xcb007101);
    Write16(data + 20, port); Write16(data + 22, remote);
    if (tcp) {data[32] = 0x50; data[33] = 2; Write32(data + 24, sequence);}
    else {Write16(data + 24, 9); data[28] = 42;}
    packet.address.Outbound = 1; packet.address.Timestamp = 200;
    packet.received = Clock::now(); assert(packet.view.Read(data, packet.bytes->size()));
    return packet;
}
ProcessOwner Identity(uint32_t pid, const char* name) {
    return std::make_shared<const ProcessIdentity>(pid, [] {return true;}, [name] {return std::string(name);});
}
Packet DnsPacket(uint16_t id, bool response, std::vector<uint32_t> answers = {}) {
    auto packet = MakePacket(false, 53000, 53);
    auto& data = *packet.bytes; data.resize(28 + 12, 0);
    const uint8_t question[]{7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    data.insert(data.end(), std::begin(question), std::end(question));
    Write16(data.data() + 28, id); Write16(data.data() + 30, response ? 0x8180 : 0x100);
    Write16(data.data() + 32, 1); Write16(data.data() + 34, static_cast<uint16_t>(answers.size()));
    for (auto ip : answers) {
        const size_t offset = data.size(); data.resize(offset + 16, 0);
        Write16(data.data() + offset, 0xc00c); Write16(data.data() + offset + 2, 1);
        Write16(data.data() + offset + 4, 1); Write32(data.data() + offset + 6, 60);
        Write16(data.data() + offset + 10, 4); Write32(data.data() + offset + 12, ip);
    }
    Write16(data.data() + 2, static_cast<uint16_t>(data.size()));
    Write16(data.data() + 24, static_cast<uint16_t>(data.size() - 20));
    if (response) {
        Write32(data.data() + 12, 0xcb007101); Write32(data.data() + 16, 0xc0000201);
        Write16(data.data() + 20, 53); Write16(data.data() + 22, 53000); packet.address.Outbound = 0;
    }
    assert(packet.view.Read(data.data(), data.size()));
    return packet;
}
Configuration ConfigurationFixture() {
    Configuration config; config.version = 1;
    for (size_t i = 1; i <= 2; ++i) {
        Server server; server.transport = std::make_shared<Transport>(); server.transport->id = i;
        server.transport->destination = htonl(0xc6336400 + static_cast<uint32_t>(i));
        server.transport->localPort = static_cast<uint16_t>(60000 + i);
        server.rules.portStart = server.rules.portEnd = static_cast<uint16_t>(20000 + i);
        server.rules.processRules = {i == 1 ? "chrome.exe" : "other.exe"};
        server.transport->session = std::make_shared<miga::v2::ProtocolV2Session>(miga::v2::Invitation{}, server.transport->destination, INVALID_SOCKET);
        miga::v2::ProtocolV2SessionTestAccess::Ready(*server.transport->session, static_cast<uint16_t>(20000 + i));
        config.servers.push_back(std::move(server));
    }
    config.Index(); return config;
}
void DnsTests() {
    DnsClassifier dns; PacketBufferPool pool; auto config = ConfigurationFixture();
    const auto now = Clock::now();
    auto requests = dns.Query(DnsPacket(1234, false), config, "chrome.exe", pool, now);
    assert(requests.size() == 2);
    auto other = dns.Query(DnsPacket(1234, false), config, "unrelated.exe", pool, now);
    assert(other.size() == 1 && other[0].route.kind == FlowRoute::Kind::Direct);
    const auto primaryId = Read16(requests[0].packet.bytes->data() + 28);
    const auto secondaryId = Read16(requests[1].packet.bytes->data() + 28);
    assert(primaryId != secondaryId);
    assert(!dns.Response(DnsPacket(secondaryId, true, {0xcb007120, 0xcb007121}), 2, config, now));
    auto response = dns.Response(DnsPacket(primaryId, true, {0xcb007110, 0xcb007111}), 1, config, now);
    assert(response && Read16(response->bytes->data() + 28) == 1234);
    assert(!dns.Select(config, "unrelated.exe", 0xcb007110, now));
    assert(dns.Select(config, "CHROME.EXE", 0xcb007110, now)->transport->id == 1);
    assert(dns.Translate(0xcb007110, 2, now) == 0xcb007120);
    assert(dns.Translate(0xcb007111, 2, now) == 0xcb007121);
    assert(!dns.Translate(0xcb007110, 2, now + std::chrono::seconds(61)));
    config.servers[1].rules.domainRules = {"example.com"};
    assert(dns.Response(DnsPacket(5555, true, {0xcb007130}), 0, config, now));
    assert(dns.Select(config, "unrelated.exe", 0xcb007130, now)->transport->id == 2);
    config.servers[1].rules.domainRules.clear();
    assert(!dns.Select(config, "unrelated.exe", 0xcb007130, now));
    auto malformed = DnsPacket(1, false);
    (*malformed.bytes)[40] = 0xc0; (*malformed.bytes)[41] = 12;
    DnsMessage parsed; assert(!parsed.Read(malformed));
    auto second = dns.Query(DnsPacket(1234, false), config, "chrome.exe", pool, now);
    assert(Read16(second[0].packet.bytes->data() + 28) != primaryId);
    auto primaryFirst = dns.Response(DnsPacket(Read16(second[0].packet.bytes->data() + 28), true,
        {0xcb007180, 0xcb007181}), 1, config, now);
    assert(primaryFirst && Read16(primaryFirst->bytes->data() + 28) == 1234);
    assert(!dns.Response(DnsPacket(Read16(second[1].packet.bytes->data() + 28), true,
        {0xcb007190}), 2, config, now + std::chrono::seconds(20)));
    assert(dns.Translate(0xcb007181, 2, now + std::chrono::seconds(30)) == 0xcb007190);
    assert(!dns.Translate(0xcb007181, 2, now + std::chrono::seconds(61)));
    config.servers[1].rules.processRules.push_back("chrome.exe");
    config.servers[0].rules.staticIPRule.ipRanges = {{0xcb007200, 0xcb0072ff}};
    config.servers[1].rules.domainRules = {"example.com"}; config.Index(); ++config.version;
    assert(config.Process("CHROME.EXE")->transport->id == 1);
    assert(dns.Response(DnsPacket(7777, true, {0xcb007201}), 0, config, now));
    assert(dns.Select(config, "other.exe", 0xcb007201, now)->transport->id == 2);
    assert(dns.Select(config, "unrelated.exe", 0xcb007201, now)->transport->id == 1);
    config.servers[0].rules.staticIPRule.ipRanges.clear();
    assert(dns.Select(config, "unrelated.exe", 0xcb007201, now)->transport->id == 2);
    std::swap(config.servers[0], config.servers[1]); config.Index(); ++config.version;
    assert(config.Process("chrome.exe")->transport->id == 2);
    assert(dns.Select(config, "unrelated.exe", 0xcb007201, now)->transport->id == 2);
    assert(!dns.Select(config, "unrelated.exe", 0xcb007201, now + std::chrono::seconds(61)));
}
}

namespace miga::runtime {
struct SyntheticDnsResolverTestAccess {
    static void StartResolver(SyntheticDnsResolver& resolver) {
        assert(resolver.Preflight(true) == 0xc613ffffu);
    }
};
}

struct NetworkRuntimeTests {
#include "SyntheticDnsNetworkTests.inl"
    using Impl = NetworkRuntime::Impl;
    static std::unique_ptr<Impl> Fixture(Logger& logger, ConfigManager& source) {
        auto runtime = std::make_unique<Impl>(&source, &logger);
        runtime->config = std::make_shared<Configuration>(ConfigurationFixture());
        runtime->published.store(runtime->config);
        assert(runtime->reinject.Reset() && runtime->tunnel.Reset());
        AsyncTunnelSender::Api api; api.send = SendMock;
        runtime->reinject.SetApi(api); runtime->tunnel.SetApi(api);
        for (const auto& server : runtime->config->servers)
            runtime->routes[server.transport->id] = {{htonl(0xc0000201)}, 1500, runtime->windowsRoutes.Revision(), Clock::now()};
        return runtime;
    }
    static void RouteRefresh(Logger& logger, ConfigManager& source) {
        using Access = miga::v2::ProtocolV2SessionTestAccess;
        const auto runtime = Fixture(logger, source);
        auto& session = *runtime->config->ById(1)->transport->session;
        auto& other = *runtime->config->ById(2)->transport->session;
        const auto refresh = [&](const TunnelRouteCache::Route& route, bool resume) {
            auto updates = runtime->routes;
            updates[1] = route;
            runtime->ApplyRoutes(*runtime->config, std::move(updates));
            assert(Access::TakeResume(session) == resume);
            assert(!Access::TakeResume(other));
        };
        auto route = runtime->routes.at(1);
        ++route.revision;
        route.mtu = 1400;
        refresh(route, false);
        assert(Access::MaximumPayload(session) == 1372);

        ++route.revision;
        route.path.interfaceLuid = 42;
        refresh(route, true);
        ++route.revision;
        route.path.nextHop = htonl(0xc00002fe);
        refresh(route, true);
        ++route.revision;
        route.path.source = htonl(0xc0000202);
        refresh(route, true);

        refresh({{}, 0, ++route.revision, Clock::now()}, false);
        assert(!runtime->routes.at(1).mtu && Access::MaximumPayload(session) == 0);
        assert(runtime->routes.at(1).path == route.path);
        ++route.revision;
        refresh(route, false);
        refresh({{}, 0, ++route.revision, Clock::now()}, false);
        ++route.revision;
        route.path.nextHop = htonl(0xc00002fd);
        refresh(route, true);
    }
    static void Pump(Impl& runtime) {
        for (size_t i = 0; i < 100; ++i) {
            bool progress = false; std::function<void()> action;
            while (runtime.classifierCommands.Pop(action)) {action(); action = {}; progress = true;}
            while (runtime.networkCommands.Pop(action)) {action(); action = {}; progress = true;}
            if (!runtime.readyWaiting.empty()) {runtime.DrainReady(); progress = true;}
            if (!progress) return;
        }
        assert(false);
    }
#include "NetworkRuntimeBenchmark.inl"
    static void Receive(Impl& runtime, Packet packet) {
        packet.bytes = std::make_shared<std::vector<uint8_t>>(*packet.bytes);
        runtime.PacketReceived(packet.bytes->data(), packet.bytes->size(), packet.address);
    }
    static void Run() {
        Logger logger; logger.enable(LOGGER_LEVEL_NONE, false); ConfigManager source(&logger);
        RouteRefresh(logger, source);
        V2PendingTests(logger, source);
        SummaryPreservesPendingTests(logger, source);
        DiagnosticObservationTests();
        {
            auto diagnostic = Fixture(logger, source);
            diagnostic->config->dnsResolverEnabled = true;
            diagnostic->config->dnsResolverReserveRange = true;
            auto owner = Identity(1203, "miga_diagnostics.exe");
            diagnostic->diagnostics.Configure(owner, 2, true);
            auto probe = MakePacket(false, 5203, 47901);
            probe.bytes->resize(48);
            Write16(probe.bytes->data() + 2, 48);
            Write16(probe.bytes->data() + 24, 28);
            Write32(probe.bytes->data() + 16, 0xc6120001);
            assert(probe.view.Read(probe.bytes->data(), probe.bytes->size()));
            diagnostic->directory.Observe(probe.view.tuple,
                std::make_shared<const SocketOwner>(SocketOwner{owner, 40, 100}), Clock::now());

            const auto before = submissions.size();
            Receive(*diagnostic, probe);
            Pump(*diagnostic);
            assert(submissions.size() == before + 1);
            const auto& outer = submissions.back();
            assert(Read16(outer.data() + 22) == 20002);
            const auto session = diagnostic->config->ById(2)->transport->session->Snapshot();
            miga::v2::Bytes inner;
            assert(miga::v2::DecryptData(session->keys.dataC2S, session->keys.prefixC2S,
                outer.data() + 28, outer.size() - 28, inner));
            assert(inner.size() == 48 && Read32(inner.data() + 16) == 0xc6120001);
            assert(Read16(inner.data() + 22) == 47901);
            submissions.resize(before);
        }
        {
            auto diagnostic = Fixture(logger, source);
            auto owner = Identity(1202, "other.exe");
            diagnostic->diagnostics.Configure(owner, 2, false);
            auto packet = MakePacket(true, 5201);
            diagnostic->directory.Observe(packet.view.tuple,
                std::make_shared<const SocketOwner>(SocketOwner{owner, 38, 100}), Clock::now());
            AsyncTunnelSender::Api api; api.send = PendingSend; api.result = SendResult; api.cancel = CancelSend;
            diagnostic->tunnel.SetApi(api);
            Receive(*diagnostic, packet); Pump(*diagnostic);
            assert(diagnostic->diagnostics.submitted_ == 1 && diagnostic->diagnostics.completed_ == 0);
            assert(diagnostic->diagnostics.rejected_ == 0 && pendingSends.size() == 1);
            SetEvent(pendingSends.begin()->first->hEvent); diagnostic->tunnel.Reap();
            assert(diagnostic->diagnostics.completed_ == 1 && pendingSends.empty());
            Receive(*diagnostic, packet);
            assert(diagnostic->diagnostics.submitted_ == 2 && pendingSends.size() == 1);
            diagnostic->tunnel.RequestStop(); diagnostic->tunnel.Drain();
            assert(diagnostic->diagnostics.completed_ == 1 && diagnostic->diagnostics.rejected_ == 1);
            assert(diagnostic->tunnel.Reset());
            Receive(*diagnostic, packet);
            const auto oldSession = diagnostic->diagnostics.session_;
            diagnostic->diagnostics.Configure(owner, 2, false);
            diagnostic->tunnel.RequestStop(); diagnostic->tunnel.Drain();
            diagnostic->diagnostics.Submitted(oldSession);
            diagnostic->diagnostics.RejectBeforeSend(oldSession);
            assert(diagnostic->diagnostics.submitted_ == 0 && diagnostic->diagnostics.completed_ == 0);
            assert(diagnostic->diagnostics.rejected_ == 0 && diagnostic->diagnostics.preSendRejected_ == 0);
            diagnostic->diagnostics.RejectBeforeSend(diagnostic->diagnostics.session_);
            assert(diagnostic->diagnostics.preSendRejected_ == 1 && diagnostic->diagnostics.submitted_ == 0);
            Receive(*diagnostic, packet);
            assert(diagnostic->diagnostics.submitted_ == 1 && diagnostic->diagnostics.rejected_ == 1);
            diagnostic->diagnostics.Configure(owner, 2, false);
            auto oversize = MakePacket(false, 5202);
            oversize.bytes->resize(64, 0); Write16(oversize.bytes->data() + 2, 64); Write16(oversize.bytes->data() + 24, 44);
            assert(oversize.view.Read(oversize.bytes->data(), oversize.bytes->size()));
            diagnostic->diagnostics.mss_ = true; diagnostic->diagnostics.probePort_ = 5202;
            diagnostic->routes[2].mtu = 68;
            diagnostic->directory.Observe(oversize.view.tuple,
                std::make_shared<const SocketOwner>(SocketOwner{owner, 39, 100}), Clock::now());
            Receive(*diagnostic, oversize); Pump(*diagnostic);
            assert(diagnostic->diagnostics.preSendRejected_ == 1 && diagnostic->diagnostics.submitted_ == 0);
            assert(diagnostic->diagnostics.rejected_ == 0);
        }
        {
            auto diagnostic = Fixture(logger, source);
            auto owner = Identity(1201, "miga_diagnostics.exe");
            diagnostic->diagnostics.Configure(owner, 2, true);
            auto probe = MakePacket(false, 5200);
            diagnostic->directory.Observe(probe.view.tuple,
                std::make_shared<const SocketOwner>(SocketOwner{owner, 37, 100}), Clock::now());
            Receive(*diagnostic, probe);
            Pump(*diagnostic);
            assert(submissions.size() == 1 && Read16(submissions.back().data() + 22) == 20002);
            diagnostic->diagnostics.sequencePort_ = 5200;
            probe.bytes->resize(30); Write16(probe.bytes->data() + 2, 30); Write16(probe.bytes->data() + 24, 10);
            (*probe.bytes)[28] = 0; (*probe.bytes)[29] = 0;
            assert(probe.view.Read(probe.bytes->data(), probe.bytes->size()));
            diagnostic->diagnostics.ObserveProbe(probe.view.tuple, probe.bytes->data(), probe.bytes->size());
            diagnostic->diagnostics.ObserveProbe(probe.view.tuple, probe.bytes->data(), probe.bytes->size());
            auto options = diagnostic->diagnostics.Options(probe.view.tuple, 2, probe.bytes->data(), probe.bytes->size());
            assert(options.sequence == 1);
            diagnostic->diagnostics.Submitted(options.session);
            diagnostic->diagnostics.Sent(options.session, true, options.sequence);
            diagnostic->diagnostics.Submitted(options.session);
            diagnostic->diagnostics.Sent(options.session, true, options.sequence);
            diagnostic->diagnostics.Submitted(options.session + 1);
            diagnostic->diagnostics.Sent(options.session + 1, true, 2);
            diagnostic->diagnostics.Submitted(options.session);
            diagnostic->diagnostics.Sent(options.session, false, 3);
            assert(diagnostic->diagnostics.submitted_ == diagnostic->diagnostics.completed_ + diagnostic->diagnostics.rejected_);
            assert(diagnostic->diagnostics.capturedSequences_.size() == 1);
            assert(diagnostic->diagnostics.completedSequences_.size() == 1);
            (*probe.bytes)[28] = 255; (*probe.bytes)[29] = 255;
            assert(diagnostic->diagnostics.Options(probe.view.tuple, 2, probe.bytes->data(), 30).sequence == 65536);
            (*probe.bytes)[0] = 0x4f;
            assert(!diagnostic->diagnostics.Options(probe.view.tuple, 2, probe.bytes->data(), 30).sequence);
            assert(!diagnostic->diagnostics.Options(probe.view.tuple, 2, probe.bytes->data(), 19).sequence);
            auto different = probe.view.tuple;
            different.remotePort++;
            assert(diagnostic->diagnostics.Options(probe.view.tuple, 2).session);
            assert(!diagnostic->diagnostics.Options(different, 2).session);
            assert(!diagnostic->diagnostics.Options(probe.view.tuple, 1).session);
            FlowRoute isolated;
            assert(!diagnostic->diagnostics.Route(Identity(1201, "replacement.exe"), isolated));
            diagnostic->diagnostics.load.Configure({{"run", "000000000000007b"}, {"step", 1}, {"direction", 0}, {"rate", 10}, {"seconds", 1}});
            probe.bytes->resize(60); (*probe.bytes)[0] = 0x45;
            Write16(probe.bytes->data() + 2, 60); Write16(probe.bytes->data() + 24, 40);
            miga::diagnostics::Probe loadProbe{123, 1, 0, 0};
            miga::diagnostics::WriteProbe(probe.bytes->data() + 28, 32, loadProbe);
            assert(probe.view.Read(probe.bytes->data(), probe.bytes->size()));
            diagnostic->diagnostics.ObserveProbe(probe.view.tuple, probe.bytes->data(), probe.bytes->size());
            const auto loadOptions = diagnostic->diagnostics.Options(probe.view.tuple, 2, probe.bytes->data(), probe.bytes->size());
            assert(loadOptions.probe.run == 123 && loadOptions.probe.step == 1);
            assert(diagnostic->diagnostics.load.Snapshot()["captured"]["unique"] == 1);
            diagnostic->diagnostics.load.Configure({{"run", "000000000000007b"}, {"step", 2}, {"direction", 0}, {"rate", 10}, {"seconds", 1}});
            diagnostic->diagnostics.load.Record(miga::diagnostics::LoadCounters::WireSent, loadOptions.probe);
            assert(diagnostic->diagnostics.load.Snapshot()["wire_sent"]["unique"] == 0);
            diagnostic->diagnostics.Stop();
            assert(!diagnostic->diagnostics.load.enabled);
            assert(!diagnostic->diagnostics.enabled && !diagnostic->diagnostics.TracksPort(probe.view.tuple));
            submissions.clear();
        }
        auto runtime = Fixture(logger, source);
        auto packet = MakePacket(true);
        auto owner = runtime->directory.Observe(packet.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(100, "chrome.exe"), 10, 100}), Clock::now());
        Receive(*runtime, packet); assert(runtime->pendingPackets == 1); Pump(*runtime);
        assert(runtime->pendingPackets == 0 && submissions.size() == 1);
        auto encrypted = submissions.back();
        const auto sentState = runtime->config->servers[0].transport->session->Snapshot();
        miga::v2::Bytes plain;
        assert(miga::v2::DecryptData(sentState->keys.dataC2S, sentState->keys.prefixC2S, encrypted.data() + 28, encrypted.size() - 28, plain));
        assert(plain[9] == 6 && Read32(plain.data() + 24) == 123);
        runtime->directory.Close(packet.view.tuple, 10, 100, 220, Clock::now());
        packet.address.Timestamp = 230;
        Receive(*runtime, packet); assert(submissions.size() == 2 && runtime->pendingPackets == 0);
        auto newSyn = MakePacket(true, 5000, 443, 124); newSyn.address.Timestamp = 240;
        Receive(*runtime, newSyn); Pump(*runtime); assert(runtime->pendingPackets == 1);
        auto ack = MakePacket(true); (*ack.bytes)[33] = 16; ack.address.Timestamp = 250;
        assert(ack.view.Read(ack.bytes->data(), ack.bytes->size()));
        Receive(*runtime, ack); assert(submissions.size() == 3 && runtime->pendingPackets == 1);
        auto separate = MakePacket(true, 5001);
        runtime->directory.Observe(separate.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(200, "unrelated.exe"), 20, 100}), Clock::now());
        Receive(*runtime, separate); Pump(*runtime);
        assert(submissions.back().size() == 40 && Read32(submissions.back().data() + 16) == 0xcb007101);
        runtime->directory.Observe(newSyn.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(200, "unrelated.exe"), 30, 235}), Clock::now());
        runtime->RetryPort(PortKey(newSyn.view.tuple)); Pump(*runtime);
        assert(runtime->pendingPackets == 0 && submissions.back().size() == 40);
        assert(Read32(submissions.back().data() + 24) == 124);
        auto translated = MakePacket(true, 5002);
        auto translatedOwner = runtime->directory.Observe(translated.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(300, "other.exe"), 40, 100}), Clock::now());
        assert(runtime->flows.Commit(translated.view, 200, {{FlowRoute::Kind::Tunnel, 2, 0xcb007150}, translatedOwner}, Clock::now()));
        auto wire = translated.view.tuple; wire.remoteIp = 0xcb007150;
        assert(runtime->flows.Reverse(wire, 2, 210, Clock::now()) == 0xcb007101);
        assert(!runtime->flows.Reverse(wire, 1, 210, Clock::now()));
        runtime->routes[2] = {};
        Receive(*runtime, translated); assert(runtime->routeWaiting.size() == 1);
        runtime->routes[2] = {{htonl(0xc0000201)}, 1500, runtime->windowsRoutes.Revision(), Clock::now()};
        runtime->ResumeRoutes(); assert(runtime->routeWaiting.empty());
        auto reply = MakePacket(true, 443, 5002);
        Write32(reply.bytes->data() + 12, 0xcb007150); Write32(reply.bytes->data() + 16, 0xc0000201);
        (*reply.bytes)[33] = 16;
        const auto replyState = runtime->config->servers[1].transport->session->Snapshot();
        Write32(reply.bytes->data() + 16, 0x0a420001);
        WinDivertHelperCalcChecksums(reply.bytes->data(), static_cast<UINT>(reply.bytes->size()), nullptr, 0);
        miga::v2::Bytes replyPayload;
        assert(miga::v2::EncryptData(replyState->keys.dataS2C, replyState->keys.prefixS2C, reply.bytes->data(), reply.bytes->size(), replyPayload));
        TunnelDatagram wrapper;
        std::vector<uint8_t> outer;
        assert(wrapper.Build(replyPayload.data(), replyPayload.size(), htonl(0xc6336402), htonl(0xc0000201),
            20002, 60002, 1, 1500, [&](const uint8_t* data, size_t length, size_t count) {
                assert(count == 1); outer.assign(data, data + length); return true;
            }));
        WINDIVERT_ADDRESS inbound{}; inbound.Timestamp = 250;
        runtime->PacketReceived(outer.data(), outer.size(), inbound);
        assert(submissions.back().size() == 40 && Read32(submissions.back().data() + 12) == 0xcb007101);
        InternetChecksum checksum; checksum.Add(submissions.back().data(), 20); assert(checksum.Value() == 0);
        auto unknown = MakePacket(false, 5003);
        Receive(*runtime, unknown); Pump(*runtime); assert(runtime->pendingPackets == 1);
        auto& group = runtime->waiting.at(FlowKey::From(unknown.view.tuple));
        group.packets.front().received -= std::chrono::seconds(6);
        runtime->waitingDeadlines.Set(FlowKey::From(unknown.view.tuple), Clock::now());
        runtime->ExpireWaiting(); assert(runtime->pendingPackets == 0 && submissions.back().size() == 29);
        auto ordered = MakePacket(false, 5500);
        runtime->directory.Observe(ordered.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(200, "unrelated.exe"), 50, 100}), Clock::now());
        const auto firstSubmission = submissions.size();
        for (uint8_t i = 0; i < 200; ++i) {(*ordered.bytes)[28] = i; Receive(*runtime, ordered);}
        assert(runtime->pendingPackets == 200); Pump(*runtime);
        assert(submissions.size() == firstSubmission + 200);
        for (size_t i = 0; i < 200; ++i) assert(submissions[firstSubmission + i][28] == i);
        runtime->config->servers[0].rules.domainRules = {"example.com"}; runtime->config->Index();
        auto observedDns = DnsPacket(5555, true, {0xcb007160});
        const auto beforeDns = submissions.size(); Receive(*runtime, observedDns);
        assert(submissions.size() == beforeDns + 1 && submissions.back() == *observedDns.bytes);
        Pump(*runtime);
        assert(runtime->dns.Select(*runtime->config, "unrelated.exe", 0xcb007160, Clock::now())->transport->id == 1);
        DelayedConnect(*runtime);
        DnsTests();
        ReloadTests(logger, source);
        NoActiveServersTests(logger, source);
        LocalDnsTests(logger, source);
        SyntheticDnsNetworkTests(logger, source);
        FullRoutingTests(logger, source);
        BootstrapDnsTests(logger, source);
        LoopTests(logger, source);
        std::cout << "Network runtime routing and DNS tests passed\n";
    }
    static void DelayedConnect(Impl& runtime) {
        auto process = Identity(3476, "unrelated.exe");
        auto syn = MakePacket(true, 57759);
        auto now = Clock::now();
        runtime.directory.Observe({6, 0, 57759, 0, 0}, std::make_shared<const SocketOwner>(
            SocketOwner{process, 145541, 100, false, SocketOrigin::Bind}), now);
        const auto before = submissions.size();
        Receive(runtime, syn);
        Pump(runtime);
        assert(submissions.size() == before + 1 && submissions.back() == *syn.bytes);

        runtime.directory.Observe(syn.view.tuple, std::make_shared<const SocketOwner>(
            SocketOwner{process, 145557, 190, false, SocketOrigin::Connect}), now);
        auto reply = MakePacket(true, 443, 57759, 500);
        reply.address.Outbound = 0;
        reply.address.Timestamp = 210;
        Write32(reply.bytes->data() + 12, syn.view.tuple.remoteIp);
        Write32(reply.bytes->data() + 16, syn.view.tuple.localIp);
        Write32(reply.bytes->data() + 28, 124);
        (*reply.bytes)[33] = 18;
        Receive(runtime, reply);
        assert(submissions.size() == before + 2 && submissions.back() == *reply.bytes);

        auto ack = MakePacket(true, 57759, 443, 124);
        ack.address.Timestamp = 211;
        Write32(ack.bytes->data() + 28, 501);
        (*ack.bytes)[33] = 16;
        Receive(runtime, ack);
        assert(runtime.pendingPackets == 0 && submissions.size() == before + 3 && submissions.back() == *ack.bytes);
    }
    static void V2PendingTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        auto& server = runtime->config->servers[0];
        miga::v2::Invitation invitation;
        server.transport->session = std::make_shared<miga::v2::ProtocolV2Session>(invitation, server.transport->destination, INVALID_SOCKET);
        auto packet = MakePacket(false); const auto before = submissions.size();
        for (size_t i = 0; i < 1025; ++i) runtime->Send(packet, {FlowRoute::Kind::Tunnel, server.transport->id, 0}, false);
        assert(runtime->sessionWaiting.size() == 1024 && runtime->sessionWaitingBytes == 1024 * packet.view.length);
        assert(submissions.size() == before);
        for (auto& pending : runtime->sessionWaiting) pending.packet.received -= std::chrono::seconds(31);
        for (size_t i = 0; i < 8; ++i) runtime->DrainSessions();
        assert(runtime->sessionWaiting.empty() && runtime->sessionWaitingBytes == 0 && submissions.size() == before);
    }
    static void DiagnosticObservationTests() {
        DiagnosticSession diagnostics;
        const auto owner = Identity(102, "miga_diagnostics.exe");
        const auto unrelated = Identity(202, "unrelated.exe");
        diagnostics.Configure(owner, 1, true);
        const SocketTuple target{17, 0xc0000202, 53531, 0xc0000201, 47901};
        auto other = target;
        ++other.remotePort;
        diagnostics.registrations_.insert((uint32_t(target.protocol) << 16) | target.localPort);
        const FlowRoute chosen{FlowRoute::Kind::Tunnel, 1, 0};
        const FlowRoute another{FlowRoute::Kind::Tunnel, 2, 0};
        diagnostics.Observe(target, owner, chosen, "previous_step");
        assert(diagnostics.BeginObservation(target)["ok"] == true);
        diagnostics.Observe(target, unrelated, chosen, "unrelated_owner");
        diagnostics.Observe(other, owner, chosen, "unrelated_endpoint");
        diagnostics.ObserveUnowned(other);
        const auto empty = diagnostics.EndObservation();
        assert(empty["ok"] == true && empty["captured"] == 0 && empty["unowned"] == 0 && empty["flows"].empty());

        assert(diagnostics.BeginObservation(target)["ok"] == true);
        diagnostics.ObserveUnowned(target);
        diagnostics.Observe(target, owner, another, "other_server");
        diagnostics.Observe(target, owner, chosen, "selected_server");
        const auto result = diagnostics.EndObservation();
        assert(result["ok"] == true && result["captured"] == 2 && result["unowned"] == 1);
        assert(result["flows"].size() == 1 && result["flows"][0]["server_id"] == 1 &&
            result["flows"][0]["reason"] == "selected_server");
    }
    static void SummaryPreservesPendingTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        auto& server = runtime->config->servers[0];
        server.transport->session = std::make_shared<miga::v2::ProtocolV2Session>(
            miga::v2::Invitation{}, server.transport->destination, INVALID_SOCKET);
        auto packet = MakePacket(false);
        const auto before = submissions.size();
        runtime->Send(packet, {FlowRoute::Kind::Tunnel, server.transport->id, 0}, false);
        assert(runtime->sessionWaiting.size() == 1 && runtime->sessionWaitingBytes == packet.view.length);

        miga::v2::Bytes first(28), second(28), complete;
        for (auto* fragment : {&first, &second}) {
            std::copy_n(packet.bytes->begin(), 20, fragment->begin());
            Write16(fragment->data() + 2, static_cast<uint16_t>(fragment->size()));
        }
        Write16(first.data() + 6, 0x2000);
        Write16(second.data() + 6, 1);
        first[20] = 0x56; second[20] = 0x78;
        using Result = miga::v2::Ipv4Reassembler::Result;
        for (auto* assembler : {&runtime->reassembler, &runtime->innerReassembler})
            assert(assembler->Add(first.data(), first.size(), complete) == Result::Waiting);

        runtime->lastSummary = Clock::now() - std::chrono::seconds(5);
        runtime->Summary();
        assert(runtime->sessionWaiting.size() == 1 && runtime->sessionWaitingBytes == packet.view.length);
        for (auto* assembler : {&runtime->reassembler, &runtime->innerReassembler}) {
            assert(assembler->Add(second.data(), second.size(), complete) == Result::Complete);
            assert(complete.size() == 36 && complete[20] == 0x56 && complete[28] == 0x78);
        }

        miga::v2::ProtocolV2SessionTestAccess::Ready(*server.transport->session, 20000);
        runtime->DrainSessions();
        assert(runtime->sessionWaiting.empty() && runtime->sessionWaitingBytes == 0);
        assert(submissions.size() == before + 1);
        submissions.resize(before);
    }
    static void ReloadTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        AsyncTunnelSender::Api api; api.send = PendingSend; api.result = SendResult; api.cancel = CancelSend;
        runtime->reinject.SetApi(api); runtime->tunnel.SetApi(api);
        auto packet = MakePacket(false);
        runtime->Send(packet, {}, false);
        runtime->Send(packet, {FlowRoute::Kind::Tunnel, 1, 0}, false);
        assert(pendingSends.size() == 2);
        Impl::Prepared reload;
        reload.config = std::make_shared<Configuration>(*runtime->config); reload.config->version = 2;
        std::swap(reload.config->servers[0], reload.config->servers[1]); reload.config->Index();
        reload.routes = runtime->routes; reload.completion = std::make_shared<std::promise<bool>>();
        auto future = reload.completion->get_future(); runtime->prepared.emplace(std::move(reload));
        runtime->ApplyPrepared(); assert(runtime->config->version == 1);
        auto pending = pendingSends.begin()->first; SetEvent(pending->hEvent);
        runtime->ApplyPrepared(); assert(runtime->config->version == 1);
        for (const auto& item : pendingSends) SetEvent(item.first->hEvent);
        runtime->ApplyPrepared(); assert(runtime->config->version == 2 && future.get());
        assert(runtime->config->ById(1)->rules.processRules[0] == "chrome.exe");
        runtime->Send(packet, {}, false); assert(pendingSends.size() == 1);
        runtime->reinject.RequestStop(); runtime->reinject.Drain(); assert(pendingSends.empty());
    }
    static void NoActiveServersTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        runtime->config->dnsResolverEnabled = true;
        runtime->nextConfiguration = runtime->config->version;
        Impl::Prepared reload;
        reload.config = runtime->Prepare({}, 1400, LOGGER_LEVEL_NONE, "", false, 0, runtime->config, reload.routes);
        assert(reload.config);
        runtime->prepared.emplace(std::move(reload));
        runtime->ApplyPrepared();
        assert(runtime->config->servers.empty() && !runtime->config->dnsResolverEnabled);
        auto owner = Identity(1202, "chrome.exe");
        for (auto packet : {MakePacket(true), MakePacket(false), DnsPacket(1234, false)}) {
            assert(WinDivertHelperCalcChecksums(packet.bytes->data(), static_cast<UINT>(packet.bytes->size()), nullptr, 0));
            runtime->directory.Observe(packet.view.tuple,
                std::make_shared<const SocketOwner>(SocketOwner{owner, 10, 100}), Clock::now());
            const auto before = submissions.size();
            Receive(*runtime, packet);
            Pump(*runtime);
            assert(submissions.size() == before + 1 && submissions.back() == *packet.bytes);
        }
    }
    static void LocalDnsTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        auto query = DnsPacket(1234, false);
        const uint32_t resolver = 0xc0a80001;
        Write32(query.bytes->data() + 16, resolver);
        assert(WinDivertHelperCalcChecksums(query.bytes->data(), static_cast<UINT>(query.bytes->size()), nullptr, 0));
        assert(query.view.Read(query.bytes->data(), query.bytes->size()));
        runtime->directory.Observe(query.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(100, "unrelated.exe"), 10, 100}), Clock::now());

        const auto before = submissions.size();
        Receive(*runtime, query);
        Pump(*runtime);
        assert(submissions.size() == before + 1 && submissions.back() == *query.bytes);

        auto rules = std::make_shared<Configuration>(*runtime->config);
        ++rules->version;
        rules->servers[1].rules.domainRules.push_back("example.com");
        rules->Index();
        runtime->config = rules;
        runtime->published.store(rules);
        Receive(*runtime, query);
        Pump(*runtime);
        assert(submissions.size() == before + 3);

        const auto reply = [&](size_t serverId, const std::vector<uint8_t>& outer, uint32_t answer) {
            const auto* server = rules->ById(serverId);
            const auto state = server->transport->session->Snapshot();
            assert(Read32(outer.data() + 16) == ntohl(server->transport->destination));
            miga::v2::Bytes inner;
            assert(miga::v2::DecryptData(state->keys.dataC2S, state->keys.prefixC2S,
                outer.data() + 28, outer.size() - 28, inner));
            assert(Read32(inner.data() + 16) == resolver);
            auto response = DnsPacket(Read16(inner.data() + 28), true, {answer});
            Write32(response.bytes->data() + 12, resolver);
            Write32(response.bytes->data() + 16, Read32(inner.data() + 12));
            miga::v2::Bytes encrypted;
            assert(miga::v2::EncryptData(state->keys.dataS2C, state->keys.prefixS2C,
                response.bytes->data(), response.bytes->size(), encrypted));
            TunnelDatagram datagram;
            assert(datagram.Build(encrypted.data(), encrypted.size(), server->transport->destination, htonl(query.view.tuple.localIp),
                state->port, server->transport->localPort, 1, 1500, [&](const uint8_t* data, size_t length, size_t count) {
                    assert(count == 1);
                    auto outerReply = response;
                    outerReply.bytes = std::make_shared<std::vector<uint8_t>>(data, data + length);
                    Receive(*runtime, outerReply);
                    return true;
                }));
            Pump(*runtime);
        };
        reply(1, submissions[before + 2], 0xcb007120);
        assert(submissions.size() == before + 3);
        reply(2, submissions[before + 1], 0xcb007110);
        assert(submissions.size() == before + 4);
        assert(Read32(submissions.back().data() + 12) == resolver &&
            Read32(submissions.back().data() + 16) == query.view.tuple.localIp &&
            Read16(submissions.back().data() + 28) == 1234);
        PacketView answerView;
        DnsMessage answer;
        assert(answerView.Read(submissions.back().data(), submissions.back().size()));
        assert(answer.Read(submissions.back().data(), answerView) && answer.addresses.size() == 1 &&
            answer.addresses.front().first == 0xcb007110);

        runtime->directory.Observe(query.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(101, "chrome.exe"), 11, 201}), Clock::now());
        query.address.Timestamp = 202;
        Receive(*runtime, query);
        Pump(*runtime);
        assert(submissions.size() == before + 6 && Read32(submissions[before + 4].data() + 16) == 0xc6336401);
    }
    static void BootstrapDnsTests(Logger& logger, ConfigManager& source) {
        assert(Impl::BootstrapHosts("# comment\r\n198.18.0.1 vps.example\r\n::1 vps.example\r\n"
            "192.0.2.34 alias VPS.EXAMPLE # comment\r\n", "vps.example") == 0xc0000222u);
        assert(!Impl::BootstrapHosts("192.0.2.34 other.example # vps.example\n", "vps.example"));
        auto runtime = Fixture(logger, source);
        runtime->config->dnsResolverEnabled = true;
        runtime->config->fullRoutingServerId = 1;
        auto query = DnsPacket(1234, false);
        auto reply = DnsPacket(1234, true, {0xcb007110});
        runtime->bootstrapDnsTuple.store(Impl::BootstrapDnsKey(query.view.tuple));
        const auto before = submissions.size();
        Receive(*runtime, query);
        Receive(*runtime, reply);
        assert(submissions.size() == before + 2);
        assert(submissions[before] == *query.bytes && submissions[before + 1] == *reply.bytes);
        auto unrelated = query;
        unrelated.bytes = std::make_shared<std::vector<uint8_t>>(*query.bytes);
        Write32(unrelated.bytes->data() + 16, 0xcb007102);
        Receive(*runtime, unrelated);
        assert(submissions.size() == before + 2);
        runtime->bootstrapDnsTuple.store(0);
        Receive(*runtime, query);
        assert(submissions.size() == before + 2);
    }
    static void FullRoutingTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        auto packet = MakePacket(true);
        runtime->directory.Observe(packet.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(100, "chrome.exe"), 10, 100}), Clock::now());
        Receive(*runtime, packet); Pump(*runtime);

        auto apply = [&](size_t serverId) {
            Impl::Prepared next;
            next.config = std::make_shared<Configuration>(*runtime->config);
            ++next.config->version;
            next.config->fullRoutingServerId = serverId;
            next.routes = runtime->routes;
            runtime->prepared.emplace(std::move(next));
            runtime->ApplyPrepared();
        };
        auto checkTunnel = [&](Packet testPacket, uint16_t port) {
            const auto before = submissions.size();
            Receive(*runtime, testPacket);
            assert(submissions.size() == before + 1 && runtime->pendingPackets == 0);
            assert(Read32(submissions.back().data() + 16) == 0xc6336402);
            assert(Read16(submissions.back().data() + 22) == port);
            const auto state = runtime->config->ById(2)->transport->session->Snapshot();
            miga::v2::Bytes data;
            const auto& outer = submissions.back();
            assert(miga::v2::DecryptData(state->keys.dataC2S, state->keys.prefixC2S, outer.data() + 28, outer.size() - 28, data));
            assert(data[9] == testPacket.view.tuple.protocol && Read32(data.data() + 16) == testPacket.view.tuple.remoteIp);
            if (testPacket.view.tuple.remotePort == 53)
                assert(Read16(data.data() + 28) == Read16(testPacket.bytes->data() + 28));
        };
        apply(2);
        checkTunnel(packet, 20002);
        checkTunnel(MakePacket(false, 5201), 20002);
        auto stun = MakePacket(false, 5201, 3478);
        checkTunnel(stun, 20002);
        runtime->diagnostics.directProbeOwner_ = Identity(1201, "miga_diagnostics.exe");
        runtime->diagnostics.directProbeTuple_ = stun.view.tuple;
        runtime->diagnostics.directProbePort_.store(5201);
        const auto directBefore = submissions.size();
        Receive(*runtime, stun);
        assert(submissions.size() == directBefore + 1 && submissions.back() == *stun.bytes);
        auto stunReply = MakePacket(false, 3478, 5201);
        Write32(stunReply.bytes->data() + 12, stun.view.tuple.remoteIp);
        Write32(stunReply.bytes->data() + 16, stun.view.tuple.localIp);
        stunReply.address.Outbound = 0;
        Receive(*runtime, stunReply);
        assert(submissions.size() == directBefore + 2 && submissions.back() == *stunReply.bytes);
        checkTunnel(MakePacket(false, 5201, 3479), 20002);
        checkTunnel(MakePacket(false, 5202, 3478), 20002);
        apply(0);
        Receive(*runtime, stun);
        assert(submissions.back() == *stun.bytes);
        apply(2);
        runtime->diagnostics.Clear();
        checkTunnel(stun, 20002);

        WSADATA winsock{};
        assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
        const SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        assert(udp != INVALID_SOCKET);
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        endpoint.sin_port = htons(3478);
        assert(connect(udp, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) == 0);
        sockaddr_in bound{};
        int size = sizeof(bound);
        assert(getsockname(udp, reinterpret_cast<sockaddr*>(&bound), &size) == 0);
        const SocketTuple boundTuple{17, ntohl(bound.sin_addr.s_addr), ntohs(bound.sin_port), INADDR_LOOPBACK, 3478};
        const DiagnosticSession::Json registration{{"local_ip", boundTuple.localIp}, {"local_port", boundTuple.localPort},
            {"remote_ip", boundTuple.remoteIp}};
        assert(!runtime->diagnostics.RegisterDirectProbe(0, registration));
        assert(runtime->diagnostics.RegisterDirectProbe(GetCurrentProcessId(), registration));
        assert(runtime->diagnostics.DirectProbeMatches(boundTuple));
        runtime->diagnostics.ClearDirectProbe();
        assert(!runtime->diagnostics.DirectProbeMatches(boundTuple));
        closesocket(udp);
        WSACleanup();

        checkTunnel(DnsPacket(1234, false), 20002);
        auto localDns = DnsPacket(1234, false);
        Write32(localDns.bytes->data() + 16, 0xc0a80001);
        assert(localDns.view.Read(localDns.bytes->data(), localDns.bytes->size()));
        checkTunnel(localDns, 20002);
        auto invalidDns = MakePacket(false, 53000, 53);
        Write32(invalidDns.bytes->data() + 16, 0xc0a80001);
        Receive(*runtime, invalidDns);
        assert(submissions.back() == *invalidDns.bytes);
        auto localTcp = MakePacket(true);
        Write32(localTcp.bytes->data() + 16, 0xc0a80001);
        Receive(*runtime, localTcp);
        assert(submissions.back() == *localTcp.bytes);
        auto candidate = std::make_shared<miga::v2::ProtocolV2Session>(miga::v2::Invitation{}, htonl(0xcb007101), INVALID_SOCKET);
        miga::v2::ProtocolV2SessionTestAccess::SetControl(*candidate, 54000, 24000);
        auto candidates = std::make_shared<std::vector<std::weak_ptr<miga::v2::ProtocolV2Session>>>();
        candidates->push_back(candidate);
        runtime->preparingSessions.store(candidates);
        auto control = MakePacket(false, 54000, 24000);
        Receive(*runtime, control);
        assert(submissions.back() == *control.bytes);
        checkTunnel(MakePacket(false, 54000, 24001), 20002);

        auto directReply = DnsPacket(1234, true);
        const auto before = submissions.size();
        Receive(*runtime, directReply);
        assert(submissions.size() == before);

        const auto state = runtime->config->ById(2)->transport->session->Snapshot();
        Write32(directReply.bytes->data() + 12, localDns.view.tuple.remoteIp);
        Write32(directReply.bytes->data() + 16, 0x0a420001);
        miga::v2::Bytes encrypted;
        assert(miga::v2::EncryptData(state->keys.dataS2C, state->keys.prefixS2C,
            directReply.bytes->data(), directReply.bytes->size(), encrypted));
        TunnelDatagram wrapper;
        assert(wrapper.Build(encrypted.data(), encrypted.size(), htonl(0xc6336402), htonl(0xc0000201),
            20002, 60002, 1, 1500, [&](const uint8_t* data, size_t length, size_t count) {
                assert(count == 1);
                std::vector<uint8_t> outer(data, data + length);
                runtime->PacketReceived(outer.data(), outer.size(), directReply.address);
                return true;
            }));
        assert(submissions.size() == before + 1);
        assert(Read32(submissions.back().data() + 12) == localDns.view.tuple.remoteIp &&
            Read32(submissions.back().data() + 16) == 0xc0000201 &&
            Read16(submissions.back().data() + 28) == 1234);

        runtime->routes[2] = {};
        Receive(*runtime, packet);
        assert(runtime->routeWaiting.size() == 1 && submissions.size() == before + 1);
        apply(0);
        assert(runtime->routeWaiting.empty());
        Receive(*runtime, packet); Pump(*runtime);
        assert(submissions.size() == before + 2 && Read32(submissions.back().data() + 16) == 0xc6336401);
    }
    static void LoopTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        runtime->api.receive = ReceiveMock; runtime->api.result = ResultMock; runtime->api.cancel = CancelMock;
        runtime->api.close = CloseMock; runtime->api.shutdown = ShutdownMock;
        for (size_t iteration = 0; iteration < 3; ++iteration) {
            ResetEvent(runtime->stop); runtime->networkCommands.Reset();
            runtime->config = std::make_shared<Configuration>(ConfigurationFixture());
            runtime->network = reinterpret_cast<HANDLE>(1); runtime->running.store(true);
            assert(runtime->reinject.Reset() && runtime->tunnel.Reset());
            runtime->networkThread = std::thread([&] {runtime->NetworkLoop();});
            {
                std::unique_lock lock(receiveMutex);
                assert(receiveChanged.wait_for(lock, std::chrono::seconds(2), [] {return !receiveStates.empty();}));
            }
            std::promise<void> woke; auto future = woke.get_future();
            assert(runtime->networkCommands.TryPush([&] {woke.set_value();}));
            assert(future.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
            auto packet = MakePacket(false); packet.address.Outbound = 0;
            const auto before = runtime->captured.load();
            {
                std::lock_guard lock(receiveMutex);
                auto& item = *receiveStates.begin();
                std::memcpy(item.second.bytes, packet.bytes->data(), packet.bytes->size());
                item.second.addresses[0] = packet.address; *item.second.addressLength = sizeof(WINDIVERT_ADDRESS);
                item.second.length = static_cast<DWORD>(packet.bytes->size()); item.second.complete = true;
                SetEvent(item.first->hEvent);
            }
            const auto deadline = Clock::now() + std::chrono::seconds(2);
            while (runtime->captured.load() == before && Clock::now() < deadline) Sleep(1);
            assert(runtime->captured.load() > before);
            const auto stopped = Clock::now(); runtime->Stop();
            assert(Clock::now() - stopped < std::chrono::seconds(2));
            assert(receiveStates.empty());
        }
    }
};

int main(int argc, char** argv) {
    assert(miga::v2::Initialize());
    std::filesystem::create_directories("Build/tests/runtime");
    assert(SetCurrentDirectoryW(L"Build/tests/runtime"));
    const std::string_view option = argc == 2 ? argv[1] : "";
    if (option == "--benchmark" || option == "--benchmark-valid-checksums") {
        for (bool enabled : {false, true})
            for (bool tunnelled : {false, true})
                for (bool inbound : {false, true})
                    for (size_t bytes : {40, 1400})
                        for (bool tcp : {true, false})
                            NetworkRuntimeTests::Benchmark(tcp, tunnelled, inbound, enabled, bytes, option == "--benchmark-valid-checksums");
        return 0;
    }
    NetworkRuntimeTests::Run();
}
