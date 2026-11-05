#include "../src/NetworkRuntimeImpl.h"
#include <cassert>
#include <iostream>
#include <filesystem>

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
        assert(server.transport->transform.Initialize(Encryption::GenerateXorKeyBase64(), Encryption::GenerateSwapKeyBase64()));
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

struct NetworkRuntimeTests {
    using Impl = NetworkRuntime::Impl;
    static std::unique_ptr<Impl> Fixture(Logger& logger, ConfigManager& source) {
        auto runtime = std::make_unique<Impl>(&source, &logger);
        runtime->config = std::make_shared<Configuration>(ConfigurationFixture());
        runtime->published.store(runtime->config);
        assert(runtime->reinject.Reset() && runtime->tunnel.Reset());
        AsyncTunnelSender::Api api; api.send = SendMock;
        runtime->reinject.SetApi(api); runtime->tunnel.SetApi(api);
        for (const auto& server : runtime->config->servers)
            runtime->routes[server.transport->id] = {htonl(0xc0000201), 1500, runtime->windowsRoutes.Revision(), Clock::now()};
        return runtime;
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
    static void Receive(Impl& runtime, Packet packet) {
        packet.bytes = std::make_shared<std::vector<uint8_t>>(*packet.bytes);
        runtime.PacketReceived(packet.bytes->data(), packet.bytes->size(), packet.address);
    }
    static void Run() {
        Logger logger; logger.enable(LOGGER_LEVEL_NONE, false); ConfigManager source(&logger);
        auto runtime = Fixture(logger, source);
        auto packet = MakePacket(true);
        auto owner = runtime->directory.Observe(packet.view.tuple,
            std::make_shared<const SocketOwner>(SocketOwner{Identity(100, "chrome.exe"), 10, 100}), Clock::now());
        Receive(*runtime, packet); assert(runtime->pendingPackets == 1); Pump(*runtime);
        assert(runtime->pendingPackets == 0 && submissions.size() == 1);
        auto encrypted = submissions.back();
        runtime->config->servers[0].transport->transform.Decrypt(encrypted.data() + 28, encrypted.size() - 28, 20001);
        assert(encrypted[28 + 9] == 6 && Read32(encrypted.data() + 28 + 24) == 123);
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
        runtime->routes[2] = {htonl(0xc0000201), 1500, runtime->windowsRoutes.Revision(), Clock::now()};
        runtime->ResumeRoutes(); assert(runtime->routeWaiting.empty());
        auto reply = MakePacket(true, 443, 5002);
        Write32(reply.bytes->data() + 12, 0xcb007150); Write32(reply.bytes->data() + 16, 0xc0000201);
        (*reply.bytes)[33] = 16;
        runtime->config->servers[1].transport->transform.Encrypt(reply.bytes->data(), reply.bytes->size(), 20002);
        TunnelDatagram wrapper;
        std::vector<uint8_t> outer;
        assert(wrapper.Build(reply.bytes->data(), reply.bytes->size(), htonl(0xc6336402), htonl(0xc0000201),
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

int main() {
    std::filesystem::create_directories("Build/tests/runtime");
    assert(SetCurrentDirectoryW(L"Build/tests/runtime"));
    NetworkRuntimeTests::Run();
}
