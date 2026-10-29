#include <winsock2.h>
#include <ws2tcpip.h>
#include "PacketMonitor.h"
#include <cstdlib>
#include <filesystem>

static std::vector<std::vector<uint8_t>> injected;
static std::mutex injectedMutex;
static std::condition_variable injectedChanged;
static BOOL ReinjectSendEx(HANDLE, const VOID* packet, UINT length, UINT* sent, UINT64,
    const WINDIVERT_ADDRESS*, UINT, LPOVERLAPPED) {
    std::lock_guard lock(injectedMutex);
    const auto* bytes = static_cast<const uint8_t*>(packet);
    injected.emplace_back(bytes, bytes + length);
    if (sent) *sent = length;
    injectedChanged.notify_all();
    return TRUE;
}

void Require(bool value, const char* message) {
    if (!value) { std::cerr << message << '\n'; std::exit(1); }
}

extern "C" BOOL WinDivertSendEx(HANDLE, const VOID* packet, UINT length, UINT* sent, UINT64,
    const WINDIVERT_ADDRESS* addresses, UINT addressLength, LPOVERLAPPED) {
    Require(addressLength == sizeof(WINDIVERT_ADDRESS), "fixture expects unfragmented tunnel");
    Require(addresses[0].Outbound && addresses[0].IPChecksum && addresses[0].UDPChecksum, "outer injection flags");
    const auto* bytes = static_cast<const uint8_t*>(packet);
    Require(length >= 29 && bytes[0] == 0x45 && bytes[9] == 17, "outer IPv4 UDP headers");
    Require(((UINT(bytes[2]) << 8) | bytes[3]) == length, "outer total length");
    InternetChecksum ip;
    ip.Add(bytes, 20);
    Require(ip.Value() == 0, "outer IP checksum");
    InternetChecksum udp;
    udp.Add(bytes + 12, 8);
    const uint8_t pseudo[] = {0, 17, bytes[24], bytes[25]};
    udp.Add(pseudo, 4);
    udp.Add(bytes + 20, length - 20);
    Require(udp.Value() == 0, "outer UDP checksum");
    sockaddr_in target{};
    target.sin_family = AF_INET;
    std::memcpy(&target.sin_addr, bytes + 16, 4);
    std::memcpy(&target.sin_port, bytes + 22, 2);
    SOCKET relay = socket(AF_INET, SOCK_DGRAM, 0);
    const auto result = sendto(relay, reinterpret_cast<const char*>(bytes + 28), length - 28, 0,
        reinterpret_cast<sockaddr*>(&target), sizeof(target));
    closesocket(relay);
    Require(result == static_cast<int>(length - 28), "relay injected payload to fixture server");
    if (sent) *sent = length;
    return TRUE;
}
struct Receiver {
    SOCKET socket = INVALID_SOCKET;
    uint16_t port = 0;
    Receiver() {
        socket = ::socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        Require(::bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "loopback bind");
        int size = sizeof(address);
        Require(getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size) == 0, "loopback port");
        port = ntohs(address.sin_port);
        DWORD timeout = 1000;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    }
    ~Receiver() { closesocket(socket); }
    std::vector<uint8_t> Receive() {
        std::vector<uint8_t> packet(65536);
        const int length = recv(socket, reinterpret_cast<char*>(packet.data()), static_cast<int>(packet.size()), 0);
        if (length <= 0) std::cerr << "receive error=" << WSAGetLastError() << ", injected=" << injected.size() << ", port=" << port << "\n";
        Require(length > 0, "expected tunneled datagram");
        packet.resize(length);
        return packet;
    }
    bool Empty() {
        u_long bytes = 0;
        Require(ioctlsocket(socket, FIONREAD, &bytes) == 0, "query receiver");
        return bytes == 0;
    }
};

std::vector<uint8_t> Packet(bool tcp, uint16_t port, uint16_t remote = 443, bool syn = false) {
    std::vector<uint8_t> packet(tcp ? 40 : 29, 0);
    packet[0] = 0x45;
    packet[3] = static_cast<uint8_t>(packet.size());
    packet[8] = 64;
    packet[9] = tcp ? 6 : 17;
    packet[12] = 192; packet[14] = 2; packet[15] = 1;
    packet[16] = 203; packet[18] = 113; packet[19] = 1;
    packet[20] = static_cast<uint8_t>(port >> 8); packet[21] = static_cast<uint8_t>(port);
    packet[22] = static_cast<uint8_t>(remote >> 8); packet[23] = static_cast<uint8_t>(remote);
    if (tcp) { packet[32] = 0x50; packet[33] = syn ? 2 : 16; }
    else { packet[25] = 9; packet[28] = 42; }
    return packet;
}

struct PacketMonitorTests {
    static void Run() {
        WSADATA data;
        Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "winsock");
        Receiver first, second;
        const auto originalDirectory = std::filesystem::current_path();
        const auto runtime = originalDirectory / "Build/tests/packet-monitor-runtime";
        std::filesystem::create_directories(runtime);
        const auto path = (runtime / "fixture.json").string();
        std::filesystem::current_path(runtime);
        nlohmann::json servers = nlohmann::json::array();
        for (auto port : { first.port, second.port }) {
            servers.push_back({
                {"server_ip", "127.0.0.1"},
                {"server_ports", {{"start", port}, {"end", port}}},
                {"encryption", {{"xor_key", Encryption::GenerateXorKeyBase64()},
                    {"swap_key", Encryption::GenerateSwapKeyBase64()}}},
                {"redirect_processes", {"game.exe"}}
            });
        }
        const auto write = [&] {
            std::ofstream file(path);
            file << nlohmann::json{{"log_level", "none"}, {"servers", servers}};
        };
        write();
        Logger logger;

        ConfigManager config(&logger);
        Require(config.Load(path), "fixture configuration");
        PacketMonitor monitor(&config, &logger);
        Require(monitor.InitUdpSocket(config.GetServers()), "prepare transports");
        monitor.m_TunnelSender.SetErrorHandler([](DWORD) { Require(false, "unexpected async send error"); });
        Require(monitor.m_TunnelSender.Reset(), "initialize test sender");
        monitor.m_ReinjectSender.SetApi({&ReinjectSendEx, &GetOverlappedResult, &CancelIoEx});
        monitor.m_ReinjectSender.SetErrorHandler([](DWORD) { Require(false, "unexpected reinject error"); });
        Require(monitor.m_ReinjectSender.Reset(), "initialize reinject sender");
        const auto serverId = monitor.m_Servers[0].id;
        const auto localPort = monitor.m_Servers[0].localPort;
        auto game = std::make_shared<const ProcessIdentity>(123, [] { return true; }, [] { return "game.exe"; });
        auto direct = std::make_shared<const ProcessIdentity>(124, [] { return true; }, [] { return "direct.exe"; });
        const auto event = [&](uint8_t protocol, uint16_t port, uint64_t endpoint, int64_t timestamp,
            ProcessOwner process, WINDIVERT_EVENT kind, uint16_t remote) {
            PacketMonitor::WorkItem item;
            item.socket.Event = kind;
            item.socket.Timestamp = timestamp;
            item.socket.Socket.Protocol = protocol;
            item.socket.Socket.LocalAddr[0] = 0xc0000201;
            item.socket.Socket.LocalPort = port;
            item.socket.Socket.RemoteAddr[0] = remote ? 0xcb007101 : 0;
            item.socket.Socket.RemotePort = remote;
            item.socket.Socket.EndpointId = endpoint;
            item.socket.Socket.ProcessId = process->pid;
            if (kind != WINDIVERT_EVENT_SOCKET_CLOSE)
                item.owner = std::make_shared<const SocketOwner>(SocketOwner{process, endpoint, timestamp});
            monitor.ProcessSocketEvent(item);
        };
        const auto send = [&](std::vector<uint8_t> packet, int64_t timestamp) {
            WINDIVERT_ADDRESS address{};
            address.Outbound = 1;
            address.Timestamp = timestamp;
            monitor.ProcessNetworkPacket(packet.data(), static_cast<UINT>(packet.size()), address);
        };
        send(Packet(true, 5000, 443, true), 120);
        Require(monitor.m_Pending.Size() == 1 && first.Empty() && injected.empty(), "unknown SYN held");
        event(6, 5000, 1, 100, game, WINDIVERT_EVENT_SOCKET_CONNECT, 443);
        Require(monitor.m_Pending.Size() == 0, "socket event drains pending");
        std::cout << "delayed SYN processed\n";
        auto encrypted = first.Receive();
        monitor.m_Servers[0].encryption.Decrypt(encrypted.data(), encrypted.size(), first.port);
        Require(encrypted[9] == 6 && encrypted[33] == 2, "actual tunnel transformation preserves SYN");
        WINDIVERT_ADDRESS outgoingAddress{};
        for (size_t size : {size_t(1400), size_t(29), size_t(300), size_t(29)}) {
            auto payload = Packet(false, 5900);
            payload.resize(size, 0x5a);
            payload[2] = static_cast<uint8_t>(size >> 8);
            payload[3] = static_cast<uint8_t>(size);
            payload[24] = static_cast<uint8_t>((size - 20) >> 8);
            payload[25] = static_cast<uint8_t>(size - 20);
            const auto original = payload;
            const auto* buffer = monitor.m_OutgoingPacket.data();
            const auto capacity = monitor.m_OutgoingPacket.capacity();
            monitor.RedirectPacket(payload.data(), static_cast<UINT>(payload.size()), outgoingAddress,
                monitor.m_Servers[0], 0);
            auto received = first.Receive();
            monitor.m_Servers[0].encryption.Decrypt(received.data(), received.size(), first.port);
            Require(payload == original && received == original,
                "reused output buffer preserves source and exact datagram length");
            if (size <= capacity)
                Require(monitor.m_OutgoingPacket.data() == buffer, "output buffer allocation reused");
        }
        auto system = std::make_shared<const ProcessIdentity>(4, [] { return true; }, [] { return "System"; });
        event(6, 5000, 55, 160, system, WINDIVERT_EVENT_SOCKET_CONNECT, 443);
        send(Packet(true, 5000), 170);
        first.Receive();
        Require(injected.empty(), "SYSTEM cannot replace established TCP tunnel owner");
        event(6, 5000, 1, 200, game, WINDIVERT_EVENT_SOCKET_CLOSE, 443);
        send(Packet(true, 5000), 220);
        first.Receive();
        event(6, 5001, 2, 100, direct, WINDIVERT_EVENT_SOCKET_CONNECT, 443);
        send(Packet(true, 5001, 443, true), 120);
        Require(injected.size() == 1, "direct SYN delivered");
        std::swap(servers[0], servers[1]);
        write();
        Require(config.Load(path, true, [&](const auto& next) { return monitor.InitUdpSocket(next); }), "hot reload");
        Require(monitor.m_Servers[1].id == serverId && monitor.m_Servers[1].localPort == localPort,
            "reorder preserves transport identity and UDP source port");
        send(Packet(true, 5000), 230);
        first.Receive();
        Require(second.Empty(), "existing tunnel does not follow new first-server priority");
        send(Packet(true, 5001), 140);
        Require(injected.size() == 2 && monitor.m_Pending.Size() == 0, "direct flow survives reload");

        event(17, 6000, 3, 100, game, WINDIVERT_EVENT_SOCKET_BIND, 0);
        send(Packet(false, 6000), 120);
        second.Receive();
        event(17, 6000, 55, 125, system, WINDIVERT_EVENT_SOCKET_BIND, 0);
        send(Packet(false, 6000), 126);
        second.Receive();
        Require(injected.size() == 2, "SYSTEM cannot replace established UDP tunnel owner");
        event(17, 6000, 3, 130, game, WINDIVERT_EVENT_SOCKET_CONNECT, 444);
        send(Packet(false, 6000), 140);
        second.Receive();
        send(Packet(false, 6000, 444), 145);
        second.Receive();
        event(17, 6000, 3, 200, game, WINDIVERT_EVENT_SOCKET_CLOSE, 0);
        auto udp = Packet(false, 6000);
        WINDIVERT_ADDRESS address{}; address.Outbound = 1; address.Timestamp = 220;
        Require(monitor.ResolvePacket(udp.data(), static_cast<UINT>(udp.size()), address, true,
            std::chrono::steady_clock::now()), "expired UDP decision");
        Require(second.Empty() && injected.size() == 2, "closed UDP never escapes by stale tunnel or direct fallback");
        event(17, 6000, 4, 300, direct, WINDIVERT_EVENT_SOCKET_BIND, 0);
        send(Packet(false, 6000), 320);
        Require(injected.size() == 3 && second.Empty(), "reused UDP port chooses new process route");

        auto reply = Packet(true, 5000);
        std::swap_ranges(reply.begin() + 12, reply.begin() + 16, reply.begin() + 16);
        std::swap(reply[20], reply[22]); std::swap(reply[21], reply[23]);
        monitor.m_Servers[1].encryption.Encrypt(reply.data(), reply.size(), first.port);
        UdpPacketInfo response{};
        response.payload = reply.data();
        response.payloadSize = reply.size();
        response.srcPort = htons(first.port);
        address.Outbound = 0;
        Require(monitor.SendUdpPacketToMstcp(&response, &address, monitor.m_Servers[1]), "inbound TCP inject");
        Require(injected.back()[9] == 6 && injected.back()[16] == 192, "inbound TCP restored");

        auto inboundUdp = Packet(false, 6000);
        std::swap_ranges(inboundUdp.begin() + 12, inboundUdp.begin() + 16, inboundUdp.begin() + 16);
        std::swap(inboundUdp[20], inboundUdp[22]); std::swap(inboundUdp[21], inboundUdp[23]);
        monitor.m_Servers[0].encryption.Encrypt(inboundUdp.data(), inboundUdp.size(), second.port);
        auto outer = Packet(false, second.port, monitor.m_Servers[0].localPort);
        outer.resize(28 + inboundUdp.size());
        outer[2] = 0; outer[3] = static_cast<uint8_t>(outer.size());
        outer[24] = 0; outer[25] = static_cast<uint8_t>(8 + inboundUdp.size());
        outer[12] = 127; outer[13] = 0; outer[14] = 0; outer[15] = 1;
        std::copy(inboundUdp.begin(), inboundUdp.end(), outer.begin() + 28);
        monitor.ProcessNetworkPacket(outer.data(), static_cast<UINT>(outer.size()), address);
        Require(injected.back()[9] == 17 && injected.back()[16] == 192 && injected.back()[28] == 42,
            "inbound UDP selects correct transport on shared server IP");

        const auto answer = [](uint16_t id, uint8_t last) {
            std::vector<uint8_t> dns(12);
            dns[0] = static_cast<uint8_t>(id >> 8); dns[1] = static_cast<uint8_t>(id);
            dns[2] = 0x81; dns[3] = 0x80; dns[7] = 2;
            for (auto octet : { last, static_cast<uint8_t>(last + 1) }) {
                const uint8_t record[] = {0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, octet};
                dns.insert(dns.end(), std::begin(record), std::end(record));
            }
            return dns;
        };
        for (bool auxiliaryFirst : {true, false}) {
            monitor.ClearDnsState();
            monitor.m_ActualDns[1000] = 0;
            monitor.m_AuxiliaryDns[2000] = 1;
            monitor.m_ActualToAuxiliary[2000] = 1000;
            auto actual = answer(1000, 20);
            auto auxiliary = answer(2000, 40);
            const auto mainReply = [&] {
                Require(monitor.HandleDNSResponse(actual.data(), actual.size(), 0, 1000), "main DNS injected");
            };
            const auto auxReply = [&] {
                Require(!monitor.HandleDNSResponse(auxiliary.data(), auxiliary.size(), 1, 2000), "aux DNS suppressed");
            };
            if (auxiliaryFirst) { auxReply(); mainReply(); }
            else { mainReply(); auxReply(); }
            uint32_t translated = 0;
            Require(monitor.LookupIpTranslation(0xcb007114, 1, translated) && translated == 0xcb007128,
                "DNS translation independent of response order");
            Require(config.GetServers()[0].dynamicIPs.count(0xcb007115) == 1, "multiple A records retained");
            std::swap(servers[0], servers[1]);
            write();
            Require(config.Load(path, true, [&](const auto& next) { return monitor.InitUdpSocket(next); }),
                "reload with active DNS correspondence");
            Require(monitor.LookupIpTranslation(0xcb007114, 0, translated) && translated == 0xcb007128,
                "DNS correspondence follows server identity");
        }

        const auto previousId = monitor.m_Servers[0].id;
        servers[0]["encryption"]["xor_key"] = "invalid";
        write();
        Require(!config.Load(path, true, [&](const auto&) { return false; }),
            "transport preparation failure rejects reload");
        Require(monitor.m_Servers[0].id == previousId &&
            config.GetServers()[0].xorKeyBase64 != "invalid", "failed preparation preserves config and transports");
        std::vector<uint8_t> shortPayload(1);
        response.payload = shortPayload.data(); response.payloadSize = shortPayload.size();
        Require(!monitor.SendUdpPacketToMstcp(&response, &address, monitor.m_Servers[0]), "short inner packet rejected");

        for (size_t size = 0; size < 20; ++size) {
            auto truncated = Packet(true, 5000); truncated.resize(size);
            Require(monitor.ResolvePacket(truncated.data(), static_cast<UINT>(size), address, true,
                std::chrono::steady_clock::now()), "truncated packet consumed");
        }
        servers[0]["encryption"]["xor_key"] = config.GetServers()[0].xorKeyBase64;
        write();
        const auto injectedBeforeWorker = injected.size();
        monitor.m_Work.Reset();
        monitor.m_FreeNetworkBatches.Reset();
        monitor.m_Running.store(true);
        monitor.m_EventProcessThread = std::thread(&PacketMonitor::EventProcessThread, &monitor);
        PacketMonitor::WorkItem waiting;
        waiting.batch = std::make_unique<PacketMonitor::NetworkBatch>();
        auto unknown = Packet(true, 7000, 443, true);
        std::copy(unknown.begin(), unknown.end(), waiting.batch->data.begin());
        waiting.batch->length = static_cast<UINT>(unknown.size());
        waiting.batch->addressLength = sizeof(WINDIVERT_ADDRESS);
        waiting.batch->addresses[0] = {};
        waiting.batch->addresses[0].Outbound = 1;
        waiting.batch->addresses[0].Timestamp = 1000;
        waiting.batch->receivedAt = std::chrono::steady_clock::now();
        Require(monitor.m_Work.Push(std::move(waiting), &waiting.queuedAt), "worker enqueue");
        {
            std::unique_lock lock(injectedMutex);
            Require(injectedChanged.wait_for(lock, std::chrono::seconds(8), [&] {
                return injected.size() > injectedBeforeWorker;
            }), "idle worker expires pending packet at its deadline");
        }
        Require(monitor.ReloadConfig(path), "reload serialized through running worker");
        monitor.Stop();
        Require(monitor.m_Routing.Size() == 0 && monitor.m_Pending.Size() == 0, "stop clears complete routing state");
        monitor.m_Work.Reset();
        monitor.m_FreeNetworkBatches.Reset();
        monitor.m_Running.store(true);
        monitor.m_EventProcessThread = std::thread(&PacketMonitor::EventProcessThread, &monitor);
        Require(monitor.ReloadConfig(path), "worker restart and reload");
        monitor.Stop();

        Require(monitor.m_ReinjectSender.Reset(), "restart reinject sender for activity checks");
        Require(monitor.InitUdpSocket(config.GetServers()), "prepare activity transports");
        for (const bool tcp : { false, true }) {
            for (const bool tunnel : { false, true }) {
                monitor.m_Routing.Clear();
                const auto current = RoutingState::Clock::now();
                const auto ttl = std::chrono::minutes(tcp ? 124 : 20);
                auto packet = Packet(tcp, 7500);
                SocketTuple tuple;
                bool syn = false;
                Require(ReadSocketPacket(packet.data(), packet.size(), tuple, syn), "activity fixture tuple");
                auto owner = std::make_shared<const SocketOwner>(SocketOwner{game, 900, 100});
                auto& server = monitor.m_Servers[0];
                monitor.m_Routing.Observe(tuple, owner, current - ttl + std::chrono::minutes(1));
                monitor.m_Routing.Commit(tuple, 120, owner,
                    {tunnel ? FlowRoute::Kind::Tunnel : FlowRoute::Kind::Direct, tunnel ? server.id : 0, 0},
                    current - ttl + std::chrono::minutes(1));
                std::swap_ranges(packet.begin() + 12, packet.begin() + 16, packet.begin() + 16);
                std::swap(packet[20], packet[22]); std::swap(packet[21], packet[23]);
                WINDIVERT_ADDRESS incoming{};
                incoming.Timestamp = 200;
                if (tunnel) {
                    const auto port = server.transport.portStart;
                    server.encryption.Encrypt(packet.data(), packet.size(), port);
                    UdpPacketInfo info{};
                    info.payload = packet.data();
                    info.payloadSize = packet.size();
                    info.srcPort = htons(port);
                    Require(monitor.SendUdpPacketToMstcp(&info, &incoming, server), "activity tunnel reply injected");
                } else {
                    monitor.ProcessNetworkPacket(packet.data(), static_cast<UINT>(packet.size()), incoming);
                }
                monitor.m_Routing.Cleanup(current + std::chrono::minutes(2));
                Require(monitor.m_Routing.Size() == 1, "actual inbound path refreshes route");
                Require(monitor.m_Routing.Resolve(tuple, 210, false, current + std::chrono::minutes(2)).owner == owner,
                    "actual inbound path refreshes owner");
            }
        }
        monitor.CloseUdpSockets();
        std::filesystem::remove(path);
        std::filesystem::current_path(originalDirectory);
        std::cout << "PacketMonitor flow integration tests passed\n";
    }
};

int main() { PacketMonitorTests::Run(); }
