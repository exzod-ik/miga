#include "NetworkRuntimeImpl.h"
#include "runtime/SyntheticDnsWire.h"
#include <fstream>

namespace {
void TranslateDirect(uint8_t* bytes, const PacketView& view, WINDIVERT_ADDRESS& address,
    uint32_t translatedIp, bool source, bool dirty = false) {
    const auto original = source ? view.tuple.localIp : view.tuple.remoteIp;
    const bool transportValid = view.tuple.protocol == 6 ? address.TCPChecksum : address.UDPChecksum;
    if (!dirty && address.IPChecksum && transportValid &&
        miga::v2::TranslateAddress(bytes, view.length, original, translatedIp, source))
        return;
    Write32(bytes + (source ? 12 : 16), translatedIp);
    WinDivertHelperCalcChecksums(bytes, static_cast<UINT>(view.length), &address, 0);
}

constexpr uint16_t BootstrapDnsPort = 53;
constexpr uint16_t BootstrapDnsPayload = 1232;
constexpr size_t MaximumHostsBytes = 1024 * 1024;

bool BootstrapAddress(uint32_t address) {
    return address >= 0x01000000 && address < 0xe0000000 && !SyntheticDnsStore::Contains(address);
}

std::vector<uint32_t> BootstrapDnsServers() {
    ULONG length = 0;
    if (GetNetworkParams(nullptr, &length) != ERROR_BUFFER_OVERFLOW || !length || length > 1024 * 1024)
        return {};
    std::vector<uint8_t> buffer(length);
    auto* info = reinterpret_cast<FIXED_INFO*>(buffer.data());
    if (GetNetworkParams(info, &length) != NO_ERROR)
        return {};
    std::vector<uint32_t> servers;
    for (const auto* item = &info->DnsServerList; item && servers.size() < 3; item = item->Next) {
        in_addr address{};
        if (inet_pton(AF_INET, item->IpAddress.String, &address) != 1)
            continue;
        const auto ip = ntohl(address.s_addr);
        if (BootstrapAddress(ip) && std::find(servers.begin(), servers.end(), ip) == servers.end())
            servers.push_back(ip);
    }
    return servers;
}

struct BootstrapSocket {
    SOCKET handle = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ~BootstrapSocket() { if (handle != INVALID_SOCKET) closesocket(handle); }
};

struct BootstrapScope {
    std::atomic<uint64_t>& active;
    explicit BootstrapScope(std::atomic<uint64_t>& tuple, uint64_t key) : active(tuple) {
        active.store(key, std::memory_order_release);
    }
    ~BootstrapScope() { active.store(0, std::memory_order_release); }
};
}

NetworkRuntime::NetworkRuntime(ConfigManager* config, Logger* logger) : impl_(std::make_unique<Impl>(config, logger)) {}
NetworkRuntime::~NetworkRuntime() = default;
bool NetworkRuntime::Start() {
    try { if (impl_->Start()) return true; } catch (...) { impl_->Error("runtime_start_failed", ERROR_NOT_ENOUGH_MEMORY); }
    impl_->Stop(); return false;
}
void NetworkRuntime::Stop() { impl_->Stop(); }
bool NetworkRuntime::ReloadConfig(const std::string& path) { return impl_->Reload(path); }
bool NetworkRuntime::IsRunning() const { return impl_->running.load() && WaitForSingleObject(impl_->stop, 0) == WAIT_TIMEOUT; }

NetworkRuntime::Impl::Receive::Receive() { operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr); }

NetworkRuntime::Impl::Receive::~Receive() {
    if (pending && handle != INVALID_HANDLE_VALUE && api) {
        api->cancel(handle, &operation); DWORD bytes = 0; api->result(handle, &operation, &bytes, TRUE);
    }
    if (operation.hEvent) CloseHandle(operation.hEvent);
}

NetworkRuntime::Impl::Impl(ConfigManager* source, Logger* output) : initial(source), logger(output), syntheticDns(output) {}

NetworkRuntime::Impl::~Impl() { Stop(); if (stop) CloseHandle(stop); }

void NetworkRuntime::Impl::Error(const char* event, DWORD code) {
    logger->log(LOGGER_LEVEL_ERROR, std::string(event) + " win32_error=" + std::to_string(code));
}

void NetworkRuntime::Impl::ReceiveError(const char* event) {
    const auto error = GetLastError();
    if (WaitForSingleObject(stop, 0) != WAIT_TIMEOUT && (error == ERROR_OPERATION_ABORTED || error == ERROR_NO_DATA)) return;
    Error(event, error);
}

std::string NetworkRuntime::Impl::Ip(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." +
        std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}

std::string NetworkRuntime::Impl::Describe(const SocketTuple& tuple) {
    return " protocol=" + std::to_string(tuple.protocol) + " local=" + Ip(tuple.localIp) + ":" +
        std::to_string(tuple.localPort) + " remote=" + Ip(tuple.remoteIp) + ":" + std::to_string(tuple.remotePort);
}

std::string NetworkRuntime::Impl::Describe(const PacketView& packet, const WINDIVERT_ADDRESS& address) {
    return Describe(packet.tuple) + " outbound=" + std::to_string(address.Outbound) +
        " packet_timestamp_qpc=" + std::to_string(address.Timestamp) + " tcp_flags=" + std::to_string(packet.tcp.flags) +
        " sequence=" + std::to_string(packet.tcp.sequence) + " ack=" + std::to_string(packet.tcp.acknowledgment);
}

void NetworkRuntime::Impl::Halt() {
    SetEvent(stop);
    networkCommands.Close(); classifierCommands.Close(); windowsCommands.Close(); socketCommands.Close();
}

void NetworkRuntime::Impl::SeedSockets() {
    LARGE_INTEGER timestamp{}; QueryPerformanceCounter(&timestamp);
    uint64_t endpoint = 0;
    std::vector<SocketTuple> existingTcp;
    for (bool udp : {false, true}) {
        WindowsSnapshot snapshot;
        const auto error = snapshot.Read(udp);
        if (error != NO_ERROR) {Error("socket_snapshot_failed", error); continue;}
        for (const auto& item : snapshot.entries) {
            auto identity = processes.Get(item.pid, LoadWindowsProcessIdentity);
            if (!identity->isAlive()) continue;
            const auto now = Clock::now();
            directory.Observe(item.tuple, std::make_shared<const SocketOwner>(SocketOwner{
                identity, ++endpoint, timestamp.QuadPart, true}), now);
            if (!udp) existingTcp.push_back(item.tuple);
        }
    }
    QueryPerformanceCounter(&timestamp);
    for (const auto& tuple : existingTcp)
        if (!SyntheticAddress(tuple.remoteIp)) flows.Seed(tuple, timestamp.QuadPart, Clock::now());
}

void NetworkRuntime::Impl::ConfigureProbes() {
    directory.SetProbeHandler([this](std::vector<SocketDirectory::Probe> batch) {
        return windowsCommands.TryPush([this, batch = std::move(batch)] {
            WindowsSnapshot snapshot; const auto error = snapshot.Read(false);
            const auto index = snapshot.MakeIndex();
            std::vector<std::optional<bool>> results; results.reserve(batch.size());
            for (const auto& probe : batch) results.push_back(error == NO_ERROR ?
                std::optional<bool>(WindowsSnapshot::Contains(index, probe.record->tuple, probe.record->owner->process)) : std::nullopt);
            if (error != NO_ERROR) Error("tcp_snapshot_failed", error);
            socketCommands.Push([this, batch, results] {
                for (size_t i = 0; i < batch.size(); ++i) directory.Probed(batch[i], results[i], Clock::now());
            });
        });
    });
    flows.SetProbeHandler([this](std::vector<FlowTable::Probe> batch) {
        return windowsCommands.TryPush([this, batch = std::move(batch)] {
            WindowsSnapshot snapshot; const auto error = snapshot.Read(false);
            const auto index = snapshot.MakeIndex();
            std::vector<std::optional<bool>> results; results.reserve(batch.size());
            for (const auto& probe : batch) {
                SocketTuple tuple{probe.key.proto, probe.key.srcIp, probe.key.srcPort, probe.key.dstIp, probe.key.dstPort};
                results.push_back(error == NO_ERROR ?
                    std::optional<bool>(WindowsSnapshot::Contains(index, tuple, probe.owner->owner->process)) : std::nullopt);
            }
            if (error != NO_ERROR) Error("tcp_snapshot_failed", error);
            networkCommands.Push([this, batch, results] {
                for (size_t i = 0; i < batch.size(); ++i) flows.Probed(batch[i], results[i], Clock::now());
            });
        });
    });
}

void NetworkRuntime::Impl::Drop(const char* reason) {
    ++dropped;
    auto& sample = dropSamples[reason];
    if (!sample.count++) sample.first = std::chrono::system_clock::now();
    logger->recordWarning(NetworkWarning::RoutingDrop);
    logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {return std::string("routing_drop reason=") + reason;});
}

uint64_t NetworkRuntime::Impl::BootstrapDnsKey(const SocketTuple& tuple) {
    return uint64_t(tuple.remoteIp) << 16 | tuple.localPort;
}

std::optional<uint32_t> NetworkRuntime::Impl::BootstrapHosts(std::string_view contents, std::string_view name) {
    if (contents.starts_with("\xef\xbb\xbf"))
        contents.remove_prefix(3);
    while (!contents.empty()) {
        const auto newline = contents.find('\n');
        auto line = contents.substr(0, newline);
        contents.remove_prefix(newline == std::string_view::npos ? contents.size() : newline + 1);
        line = line.substr(0, line.find('#'));
        const auto token = [&] {
            const auto first = line.find_first_not_of(" \t\r");
            if (first == std::string_view::npos) {
                line = {};
                return std::string_view{};
            }
            line.remove_prefix(first);
            const auto end = line.find_first_of(" \t\r");
            const auto value = line.substr(0, end);
            line.remove_prefix(value.size());
            return value;
        };
        const auto ip = token();
        if (ip.empty() || ip.size() >= INET_ADDRSTRLEN)
            continue;
        in_addr address{};
        if (inet_pton(AF_INET, std::string(ip).c_str(), &address) != 1 || !BootstrapAddress(ntohl(address.s_addr)))
            continue;
        for (auto alias = token(); !alias.empty(); alias = token()) {
            if (NormalizeSyntheticDnsName(alias) == name)
                return ntohl(address.s_addr);
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> NetworkRuntime::Impl::ResolveBootstrapHostname(std::string_view host) {
    const auto name = NormalizeSyntheticDnsName(host);
    if (!name)
        return std::nullopt;
    wchar_t systemDirectory[MAX_PATH]{};
    const auto size = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (size && size < MAX_PATH) {
        const auto hostsPath = std::filesystem::path(systemDirectory) / L"drivers" / L"etc" / L"hosts";
        std::ifstream hosts(hostsPath, std::ios::binary | std::ios::ate);
        const auto length = hosts.tellg();
        if (length >= 0 && length <= static_cast<std::streamoff>(MaximumHostsBytes)) {
            std::string contents(static_cast<size_t>(length), '\0');
            hosts.seekg(0);
            if (hosts.read(contents.data(), static_cast<std::streamsize>(contents.size()))) {
                if (const auto address = BootstrapHosts(contents, *name))
                    return address;
            }
        }
    }

    for (const auto server : BootstrapDnsServers()) {
        if (WaitForSingleObject(stop, 0) != WAIT_TIMEOUT)
            break;
        BootstrapSocket channel;
        if (channel.handle == INVALID_SOCKET)
            continue;
        const BOOL exclusive = TRUE;
        const DWORD timeout = 1250;
        sockaddr_in local{}; local.sin_family = AF_INET;
        sockaddr_in destination{}; destination.sin_family = AF_INET;
        destination.sin_port = htons(BootstrapDnsPort);
        destination.sin_addr.s_addr = htonl(server);
        if (setsockopt(channel.handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                sizeof(exclusive)) != 0 ||
            setsockopt(channel.handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
                sizeof(timeout)) != 0 ||
            bind(channel.handle, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0 ||
            connect(channel.handle, reinterpret_cast<const sockaddr*>(&destination), sizeof(destination)) != 0)
            continue;
        int localSize = sizeof(local);
        if (getsockname(channel.handle, reinterpret_cast<sockaddr*>(&local), &localSize) != 0 || !local.sin_port)
            continue;
        const BootstrapScope direct(bootstrapDnsTuple, BootstrapDnsKey({17, ntohl(local.sin_addr.s_addr),
            ntohs(local.sin_port), server, BootstrapDnsPort}));
        uint16_t id = 0;
        miga::v2::Random(reinterpret_cast<uint8_t*>(&id), sizeof(id));
        const auto query = BuildSyntheticDnsQuery(*name, 1, id, BootstrapDnsPayload);
        if (query.empty() || send(channel.handle, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0)
            != static_cast<int>(query.size()))
            continue;
        std::array<uint8_t, BootstrapDnsPayload> response{};
        const auto received = recv(channel.handle, reinterpret_cast<char*>(response.data()), static_cast<int>(response.size()), 0);
        if (received < 12 || Read16(response.data()) != id)
            continue;
        const auto parsed = ReadSyntheticDnsResponse(std::span(response).first(static_cast<size_t>(received)));
        if (!parsed || parsed->name != *name)
            continue;
        for (const auto& [address, ttl] : parsed->addresses)
            if (BootstrapAddress(address))
                return address;
    }
    return std::nullopt;
}

std::shared_ptr<Configuration> NetworkRuntime::Impl::Prepare(const std::vector<ServerConfig>& servers, uint16_t mss, int level,
    const std::string& fullRoutingProfileId, bool dnsResolverEnabled, uint32_t dnsResolverReservedThrough, const std::shared_ptr<const Configuration>& previous, std::unordered_map<size_t, TunnelRouteCache::Route>& ready) {
    auto result = std::make_shared<Configuration>();
    result->version = ++nextConfiguration; result->mss = mss; result->logLevel = level;
    result->dnsResolverEnabled = dnsResolverEnabled && fullRoutingProfileId.empty();
    result->dnsResolverReserveRange = dnsResolverReservedThrough != 0;
    result->dnsResolverReservedThrough = dnsResolverReservedThrough;
    std::unordered_set<size_t> reused;
    std::vector<std::shared_ptr<Transport>> newTransports;
    auto newSessions = std::make_shared<std::vector<std::weak_ptr<miga::v2::ProtocolV2Session>>>();
    for (const auto& rules : servers) {
        std::shared_ptr<Transport> transport;
        if (previous) for (const auto& old : previous->servers)
            if (!reused.count(old.transport->id) && old.rules.SameTransport(rules)) { transport = old.transport; break; }
        if (!transport) {
            transport = std::make_shared<Transport>();
            transport->id = ++nextServer;
            in_addr address{};
            if (inet_pton(AF_INET, rules.serverIP.c_str(), &address) != 1) {
                if (dnsResolverReservedThrough || (previous && previous->dnsResolverReserveRange)) {
                    const auto resolved = ResolveBootstrapHostname(rules.serverIP);
                    if (!resolved) { Error("tunnel_endpoint_dns_failed", WSAHOST_NOT_FOUND); return {}; }
                    address.s_addr = htonl(*resolved);
                } else {
                    addrinfo hint{}; hint.ai_family = AF_INET; hint.ai_socktype = SOCK_DGRAM;
                    addrinfo* resolved = nullptr;
                    if (getaddrinfo(rules.serverIP.c_str(), nullptr, &hint, &resolved) != 0) return {};
                    address = reinterpret_cast<sockaddr_in*>(resolved->ai_addr)->sin_addr;
                    freeaddrinfo(resolved);
                }
            }
            transport->destination = address.s_addr;
            transport->reservation = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (transport->reservation == INVALID_SOCKET) return {};
            BOOL exclusive = TRUE;
            if (setsockopt(transport->reservation, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) != 0) return {};
            sockaddr_in local{}; local.sin_family = AF_INET;
            if (bind(transport->reservation, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) return {};
            int length = sizeof(local);
            if (getsockname(transport->reservation, reinterpret_cast<sockaddr*>(&local), &length) != 0) return {};
            transport->localPort = ntohs(local.sin_port);
        }
        TunnelRouteCache::Route route;
        const auto error = windowsRoutes.Resolve(transport->destination, route);
        if (error != NO_ERROR) Error("tunnel_route_failed", error);
        if (!transport->session) {
            miga::v2::Invitation invitation;
            if (!ProtocolProfiles::Load(rules.profileId, invitation)) return {};
            transport->session = std::make_shared<miga::v2::ProtocolV2Session>(invitation, transport->destination, transport->reservation);
            transport->session->SetMaximumPayload(route.mtu > 28 ? route.mtu - 28 : 0);
            newTransports.push_back(transport);
            newSessions->push_back(transport->session);
        }
        ready.emplace(transport->id, route);
        reused.insert(transport->id);
        if (!fullRoutingProfileId.empty() && rules.profileId == fullRoutingProfileId)
            result->fullRoutingServerId = transport->id;
        result->servers.push_back({rules, std::move(transport)});
    }
    if (previous && !newSessions->empty()) preparingSessions.store(newSessions);
    for (const auto& transport : newTransports)
        if (!transport->session->Start(ntohl(ready.at(transport->id).path.source))) return {};
    result->Index();
    return result;
}

void NetworkRuntime::Impl::RefreshRoutes() {
    auto current = published.load();
    if (!current) {routeRefreshPending.store(false); return;}
    std::unordered_map<size_t, TunnelRouteCache::Route> updates;
    for (const auto& server : current->servers) {
        auto& route = routeCache[server.transport->id];
        const auto error = windowsRoutes.Resolve(server.transport->destination, route);
        if (error != NO_ERROR) Error("tunnel_route_failed", error);
        updates.emplace(server.transport->id, route);
    }
    routeCache = updates;
    networkCommands.Push([this, version = current->version, updates = std::move(updates)]() mutable {
        if (config && config->version == version) {
            ApplyRoutes(*config, std::move(updates));
            ResumeRoutes();
        }
    });
    routeRefreshPending.store(false);
}

void NetworkRuntime::Impl::ApplyRoutes(const Configuration& current, std::unordered_map<size_t, TunnelRouteCache::Route> updates) {
    for (const auto& server : current.servers) {
        const auto next = updates.find(server.transport->id);
        if (next == updates.end() || !server.transport->session) continue;
        auto& route = next->second;
        const auto previous = routes.find(server.transport->id);
        if (previous != routes.end()) {
            const auto& old = previous->second;
            if (route.revision < old.revision || (route.revision == old.revision && route.checked < old.checked))
                route = old;
            if (!route.mtu)
                route.path = old.path;
            else if (old.path.source && route.path != old.path)
                server.transport->session->RequestResume();
        }
        server.transport->session->SetMaximumPayload(route.mtu > 28 ? route.mtu - 28 : 0);
    }
    routes = std::move(updates);
}

void NetworkRuntime::Impl::QueueRouteRefresh() {
    if (!routeRefreshPending.exchange(true) && !windowsCommands.TryPush([this] {RefreshRoutes();}))
        routeRefreshPending.store(false);
}

DWORD NetworkRuntime::Impl::DnsWait() {
    auto deadline = syntheticDns.NextDeadline();
    if (deadline == (Clock::time_point::max)()) return INFINITE;
    if (deadline <= Clock::now()) {
        const auto current = published.load();
        if (!current) return INFINITE;
        SyntheticDnsResolver::Outputs output;
        syntheticDns.Cleanup(Clock::now(), *current, buffers, output);
        if (!output.empty()) networkCommands.Push([this, current, output = std::move(output)] {
            if (prepared || config != current) return;
            for (const auto& item : output) Send(item.packet, item.route, true);
        });
        deadline = syntheticDns.NextDeadline();
        if (deadline == (Clock::time_point::max)()) return INFINITE;
    }
    const auto delay = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return delay > 0 ? static_cast<DWORD>(delay) : 0;
}

void NetworkRuntime::Impl::Maintenance() {
    size_t ticks = 0;
    while (WaitForSingleObject(stop, 1000) == WAIT_TIMEOUT) {
        socketCommands.TryPush([this] {directory.Cleanup(Clock::now());});
        classifierCommands.TryPush([this] {
            dns.Cleanup(Clock::now());
            const auto overflow = dns.TakeOverflows();
            if (overflow) logger->log(LOGGER_LEVEL_WARNING, "dns_capacity_exceeded count=" + std::to_string(overflow));
        });
        QueueRouteRefresh();
        if (++ticks % 30 == 0) windowsCommands.TryPush([this] {processes.Cleanup();});
        networkCommands.TryPush([this] {flows.Cleanup(Clock::now()); Summary();});
    }
}

void NetworkRuntime::Impl::Summary() {
    const auto now = Clock::now();
    if (now - lastSummary < std::chrono::seconds(5)) return;
    lastSummary = now;
    const auto rejected = tunnel.TakeOverflows() + reinject.TakeOverflows();
    if (rejected) logger->log(LOGGER_LEVEL_WARNING, "send_pool_full rejected_submissions=" + std::to_string(rejected));
    const auto ownerFailures = directory.TakeCapacityFailures();
    if (ownerFailures) logger->log(LOGGER_LEVEL_WARNING, "socket_owner_capacity count=" + std::to_string(ownerFailures));
    for (const auto& entry : dropSamples)
        logger->log(LOGGER_LEVEL_WARNING, "runtime_drop reason=" + std::string(entry.first) +
            " count=" + std::to_string(entry.second.count), entry.second.first);
    dropSamples.clear();
    if (dnsObservationsLost) {
        logger->log(LOGGER_LEVEL_WARNING, "dns_observation_rejected count=" + std::to_string(dnsObservationsLost));
        dnsObservationsLost = 0;
    }
    const auto queueDelay = [&](auto& queue, const char* name) {
        const auto delay = queue.TakeDelay();
        if (delay.count) logger->log(LOGGER_LEVEL_WARNING, std::string("runtime_queue_delay queue=") + name +
            " count=" + std::to_string(delay.count) + " max_wait_ms=" + std::to_string(delay.maxMs) +
            " max_queue_depth_at_pop=" + std::to_string(delay.maxDepth));
    };
    queueDelay(networkCommands, "NETWORK_COMMAND"); queueDelay(classifierCommands, "CLASSIFIER");
    queueDelay(windowsCommands, "WINDOWS"); queueDelay(socketCommands, "SOCKET_COMMAND");
    logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {
        return "runtime_counters captured=" + std::to_string(captured.exchange(0)) +
            " direct=" + std::to_string(sentDirect.exchange(0)) + " tunnel=" + std::to_string(sentTunnel.exchange(0)) +
            " deferred=" + std::to_string(deferred.exchange(0)) + " dropped=" + std::to_string(dropped.exchange(0));
    });
    logger->flushWarnings();
}

void NetworkRuntime::Impl::SocketLoop() {
    Receive receive;
    receive.api = &api;
    receive.handle = socket;
    if (!receive.operation.hEvent) {Halt(); return;}
    bool active = false;
    HANDLE events[]{stop, receive.operation.hEvent, socketCommands.Event()};
    while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) {
        std::function<void()> command;
        for (size_t i = 0; i < 32 && socketCommands.Pop(command); ++i) {command(); command = {};}
        if (!active) {
            ResetEvent(receive.operation.hEvent);
            receive.addressLength = static_cast<UINT>(sizeof(receive.addresses));
            if (api.receive(socket, nullptr, 0, nullptr, 0, receive.addresses.data(),
                &receive.addressLength, &receive.operation)) receive.ready = true;
            else if (GetLastError() == ERROR_IO_PENDING) active = receive.pending = true;
            else {ReceiveError("socket_receive_failed"); break;}
        }
        if (active && WaitForSingleObject(receive.operation.hEvent, 0) == WAIT_OBJECT_0) {
            DWORD bytes = 0;
            if (!api.result(socket, &receive.operation, &bytes, FALSE)) {ReceiveError("socket_receive_failed"); break;}
            active = receive.pending = false; receive.ready = true;
        }
        if (receive.ready) {
            receive.ready = false;
            if (!receive.addressLength || receive.addressLength > sizeof(receive.addresses) ||
                receive.addressLength % sizeof(WINDIVERT_ADDRESS)) {Error("socket_batch_invalid", ERROR_INVALID_DATA); break;}
            std::vector<uint32_t> changed;
            for (size_t i = 0; i < receive.addressLength / sizeof(WINDIVERT_ADDRESS); ++i) {
                const auto& address = receive.addresses[i];
                if (address.IPv6 || (address.Socket.Protocol != 6 && address.Socket.Protocol != 17)) continue;
                SocketTuple tuple{address.Socket.Protocol, address.Socket.LocalAddr[0], address.Socket.LocalPort,
                    address.Socket.RemoteAddr[0], address.Socket.RemotePort};
                const auto pid = address.Socket.ProcessId;
                const bool observesOwner = address.Event == WINDIVERT_EVENT_SOCKET_BIND ||
                    address.Event == WINDIVERT_EVENT_SOCKET_CONNECT || address.Event == WINDIVERT_EVENT_SOCKET_ACCEPT;
                auto identity = observesOwner ? processes.Get(pid, LoadWindowsProcessIdentity) : ProcessOwner{};
                logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {
                    auto process = identity;
                    if (!process) {
                        const auto owner = directory.Find(tuple, address.Timestamp, false, Clock::now());
                        if (owner && owner->owner->endpointId == address.Socket.EndpointId && owner->owner->process->pid == pid)
                            process = owner->owner->process;
                    }
                    return "socket_event type=" + std::to_string(address.Event) + Describe(tuple) +
                        " pid=" + std::to_string(pid) + " process=" + LogValue(process ? process->Name() : "unknown") +
                        " endpoint_id=" + std::to_string(address.Socket.EndpointId) +
                        " parent_endpoint_id=" + std::to_string(address.Socket.ParentEndpointId) +
                        " event_timestamp_qpc=" + std::to_string(address.Timestamp);
                });
                if (address.Event == WINDIVERT_EVENT_SOCKET_CLOSE)
                    directory.Close(tuple, address.Socket.EndpointId, pid, address.Timestamp, Clock::now());
                else if (observesOwner) {
                    directory.Observe(tuple, std::make_shared<const SocketOwner>(SocketOwner{
                        std::move(identity), address.Socket.EndpointId, address.Timestamp, false,
                        address.Event == WINDIVERT_EVENT_SOCKET_BIND ? SocketOrigin::Bind :
                        address.Event == WINDIVERT_EVENT_SOCKET_CONNECT ? SocketOrigin::Connect : SocketOrigin::Other,
                        address.Socket.ParentEndpointId}), Clock::now());
                } else continue;
                changed.push_back(PortKey(tuple));
            }
            std::sort(changed.begin(), changed.end()); changed.erase(std::unique(changed.begin(), changed.end()), changed.end());
            networkCommands.Push([this, changed = std::move(changed)] {for (auto port : changed) RetryPort(port);});
            continue;
        }
        WaitForMultipleObjects(3, events, FALSE, INFINITE);
    }
    Halt();
}

void NetworkRuntime::Impl::RetryPort(uint32_t port) {
    const auto range = waitingPorts.equal_range(port);
    for (auto it = range.first; it != range.second; ++it) Request(it->second);
}

void NetworkRuntime::Impl::Request(const FlowKey& key) {
    auto found = waiting.find(key);
    if (prepared || found == waiting.end() || found->second.outstanding || found->second.retryQueued || found->second.packets.empty()) return;
    auto& group = found->second;
    const auto packet = group.packets.front();
    auto current = config;
    const auto request = ++nextRequest;
    if (!classifierCommands.TryPush([this, packet, current, request, key] {
        auto active = published.load();
        if (!active || active->version != current->version) {
            networkCommands.Push([this, key, request, version = current->version] {
                RouteDecision stale; stale.request = request; stale.configVersion = version; Classified(key, stale, false, {}, {});
            });
            return;
        }
        const auto now = Clock::now();
        const bool synthetic = SyntheticDnsResolver::Contains(*current, packet.view.tuple.remoteIp);
        auto owner = directory.Find(packet.view.tuple, packet.address.Timestamp, packet.view.syn, now);
        RouteDecision decision;
        decision.request = request; decision.configVersion = current->version;
        decision.owner = owner;
        std::vector<DnsClassifier::Output> dnsOutput;
        std::string processName;
        bool dnsQuery = false;
        if (synthetic) {
            if (owner) {
                const auto& process = owner->owner->process;
                processName = process->Name();
                std::optional<size_t> serverOverride;
                FlowRoute forcedRoute;
                if (process->pid == 4 || process->pid == ownPid || _stricmp(processName.c_str(), "MIGA Agent.exe") == 0)
                    serverOverride = 0;
                else if (diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.Route(process, forcedRoute))
                    serverOverride = forcedRoute.serverId;
                syntheticDns.Route(packet, *current, processName, buffers, now, decision, dnsOutput, serverOverride);
                if (decision.route.translatedIp && serverOverride)
                    decision.reason = *serverOverride ? "diagnostic_override" : "synthetic_direct_bypass";
            } else {
                decision.route = {FlowRoute::Kind::Unavailable};
                decision.reason = "synthetic_owner_unavailable";
            }
        } else if (owner) {
            const auto pid = owner->owner->process->pid;
            if (pid != 4 && pid != ownPid) {
                processName = owner->owner->process->Name();
                const bool bypass = _stricmp(processName.c_str(), "MIGA Agent.exe") == 0;
                const bool forced = !bypass && !Local(packet.view.tuple.remoteIp) &&
                    diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.Route(owner->owner->process, decision.route);
                if (forced) decision.reason = "diagnostic_override";
                if (bypass) decision.reason = "agent_control";
                dnsQuery = !bypass && !forced && packet.view.tuple.protocol == 17 && packet.view.tuple.remotePort == 53;
                if (dnsQuery) dnsOutput = dns.Query(packet, *current, processName, buffers, now);
                else if (!bypass && !forced && !(packet.view.tuple.protocol == 6 && !packet.view.syn)) {
                    if (const auto* server = dns.Select(*current, processName, packet.view.tuple.remoteIp, now, &decision.reason))
                        decision.route = {FlowRoute::Kind::Tunnel, server->transport->id,
                            dns.Translate(packet.view.tuple.remoteIp, server->transport->id, now)};
                }
            }
        }
        if (processName.empty() && owner && logger->isEnabled(LOGGER_LEVEL_DEBUG))
            processName = owner->owner->process->Name();
        networkCommands.Push([this, key, decision, dnsQuery, dnsOutput = std::move(dnsOutput),
            processName = std::move(processName)]() mutable {
            Classified(key, decision, dnsQuery, std::move(dnsOutput), processName);
        });
    })) {group.retryQueued = true; classificationRetries.push_back(key); return;}
    group.outstanding = true; group.request = request;
}

void NetworkRuntime::Impl::RemoveWaiting(const FlowKey& key) {
    waiting.erase(key); waitingDeadlines.Erase(key);
    const auto port = (uint32_t(key.proto == 17) << 16) | key.srcPort;
    const auto range = waitingPorts.equal_range(port);
    for (auto it = range.first; it != range.second;) {
        if (it->second == key) it = waitingPorts.erase(it); else ++it;
    }
}

Packet NetworkRuntime::Impl::Take(Waiting& group) {
    Packet packet = std::move(group.packets.front()); group.packets.pop_front();
    --pendingPackets; pendingBytes -= packet.bytes->size(); return packet;
}

void NetworkRuntime::Impl::Classified(const FlowKey& key, const RouteDecision& decision, bool dnsQuery,
    std::vector<DnsClassifier::Output> output, const std::string& processName) {
    auto found = waiting.find(key);
    if (found == waiting.end() || found->second.request != decision.request) return;
    auto& group = found->second; group.outstanding = false;
    if (prepared) return;
    if (decision.configVersion != config->version) {Request(key); return;}
    const auto& first = group.packets.front();
    if (!decision.ownerIndependent) {
        const auto latest = directory.Find(first.view.tuple, first.address.Timestamp, first.view.syn, Clock::now());
        if (!decision.owner || !latest || latest->owner != decision.owner->owner) {
            if (latest) Request(key);
            return;
        }
    }
    if (decision.resolutionPending) {
        for (auto& item : output) Send(item.packet, item.route, true);
        return;
    }
    if (decision.owner && diagnostics.enabled.load(std::memory_order_relaxed) &&
        (diagnostics.Selected(decision.owner->owner->process) || diagnostics.TracksPort(first.view.tuple)))
        diagnostics.Observe(first.view.tuple, decision.owner->owner->process, decision.route, decision.reason);
    if (SyntheticAddress(first.view.tuple.remoteIp) &&
        decision.route.kind == FlowRoute::Kind::Unavailable) {
        while (!group.packets.empty()) {Take(group); Drop(decision.reason);}
        RemoveWaiting(key);
        return;
    }
    if (dnsQuery) {
        decision.owner->activity->Touch(Millis(Clock::now()));
        Take(group);
        for (auto& item : output) Send(item.packet, item.route, true);
    } else {
        if (!flows.Commit(first.view, first.address.Timestamp, decision, Clock::now())) return;
        group.readyGeneration = flows.Lookup(first.view, first.address.Timestamp, Clock::now()).generation;
        logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {
            auto description = "route_created" + Describe(first.view, first.address) +
                " generation=" + std::to_string(group.readyGeneration) + " server_id=" + std::to_string(decision.route.serverId);
            if (decision.owner) description += " pid=" + std::to_string(decision.owner->owner->process->pid) +
                " process=" + LogValue(processName.empty() ? "unknown" : processName) +
                " endpoint_id=" + std::to_string(decision.owner->owner->endpointId) +
                " owner_timestamp_qpc=" + std::to_string(decision.owner->owner->timestamp);
            return description;
        });
        ScheduleReady(key, group);
        return;
    }
    if (group.packets.empty()) RemoveWaiting(key);
    else {waitingDeadlines.Set(key, group.packets.front().received + std::chrono::seconds(5)); Request(key);}
}

void NetworkRuntime::Impl::ScheduleReady(const FlowKey& key, Waiting& group) {
    if (!group.readyQueued) {group.readyQueued = true; readyWaiting.push_back(key);}
}

void NetworkRuntime::Impl::DrainReady() {
    size_t budget = 128;
    while (budget && !readyWaiting.empty()) {
        const auto key = readyWaiting.front(); readyWaiting.pop_front();
        auto found = waiting.find(key);
        if (found == waiting.end()) {--budget; continue;}
        auto& group = found->second; group.readyQueued = false;
        while (budget && !group.packets.empty()) {
            --budget;
            const auto& packet = group.packets.front();
            auto result = flows.Lookup(packet.view, packet.address.Timestamp, Clock::now());
            if (result.action != FlowTable::Action::Send) {group.readyGeneration = 0; Request(key); break;}
            auto ready = Take(group); Send(ready, result.route, false);
        }
        if (group.packets.empty()) RemoveWaiting(key);
        else {
            waitingDeadlines.Set(key, group.packets.front().received + std::chrono::seconds(5));
            if (group.readyGeneration) ScheduleReady(key, group);
        }
    }
}

void NetworkRuntime::Impl::Defer(const uint8_t* bytes, size_t size, const WINDIVERT_ADDRESS& address, const PacketView& view) {
    if (pendingPackets >= 1024 || size > 4 * 1024 * 1024 - pendingBytes) {Drop("owner_queue_full"); return;}
    const auto key = FlowKey::From(view.tuple);
    auto [position, created] = waiting.try_emplace(key);
    auto& group = position->second;
    group.packets.push_back({buffers.Copy(bytes, size), address, view, Clock::now()});
    ++pendingPackets; pendingBytes += size; ++deferred;
    if (created) {
        waitingPorts.emplace(PortKey(view.tuple), key);
        waitingDeadlines.Set(key, group.packets.front().received + std::chrono::seconds(5));
    }
    if (group.readyGeneration) ScheduleReady(key, group); else Request(key);
}

void NetworkRuntime::Impl::ExpireWaiting() {
    FlowKey key{};
    const auto now = Clock::now();
    size_t budget = 128;
    size_t packetBudget = 128;
    while (budget-- && packetBudget && waitingDeadlines.PopDue(now, key)) {
        auto found = waiting.find(key);
        if (found == waiting.end()) continue;
        auto& group = found->second;
        while (packetBudget && !group.packets.empty() && now >= group.packets.front().received + std::chrono::seconds(5)) {
            --packetBudget;
            group.request = ++nextRequest; group.outstanding = false;
            auto packet = Take(group);
            if (SyntheticAddress(packet.view.tuple.remoteIp)) {
                Drop("synthetic_resolution_timeout");
                continue;
            }
            auto result = flows.Expire(packet.view, packet.address.Timestamp, now);
            if (!result.owner && diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.TracksPort(packet.view.tuple))
                diagnostics.ObserveUnowned(packet.view.tuple);
            logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {return std::string("pending_timeout reason=") + result.reason + Describe(packet.view, packet.address);});
            if (result.action == FlowTable::Action::Send && !(diagnostics.enabled.load(std::memory_order_relaxed) &&
                diagnostics.TracksPort(packet.view.tuple) && diagnostics.RejectFallback(packet.view.tuple, result.route))) {
                logger->recordWarning(NetworkWarning::PendingPidFallback);
                Send(packet, result.route, false);
            } else Drop(result.reason);
        }
        if (group.packets.empty()) RemoveWaiting(key);
        else {waitingDeadlines.Set(key, group.packets.front().received + std::chrono::seconds(5)); Request(key);}
    }
}

void NetworkRuntime::Impl::ResumeRoutes() {
    if (prepared) return;
    size_t budget = routeWaiting.size();
    while (budget-- && !routeWaiting.empty()) {
        auto item = std::move(routeWaiting.front()); routeWaiting.pop_front();
        const auto found = routes.find(item.route.serverId);
        const bool valid = found != routes.end() && found->second.mtu && found->second.revision == windowsRoutes.Revision();
        if (!valid && Clock::now() < item.expires && config->ById(item.route.serverId)) {
            routeWaiting.push_back(std::move(item)); continue;
        }
        routePendingBytes -= item.packet.bytes->size();
        if (!--routePendingServers[item.route.serverId]) routePendingServers.erase(item.route.serverId);
        if (valid) Send(item.packet, item.route, item.dirty, true); else Drop("interface_route_unavailable");
    }
    routeResumeAt = routeWaiting.empty() ? (Clock::time_point::max)() : routeWaiting.front().expires;
}

void NetworkRuntime::Impl::Send(const Packet& packet, const FlowRoute& route, bool dirty, bool resumed) {
    if (diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.TracksPort(packet.view.tuple) &&
        diagnostics.RejectFallback(packet.view.tuple, route)) { Drop("diagnostic_route_unconfirmed"); return; }
    auto* bytes = packet.bytes->data();
    auto address = packet.address;
    if (route.kind == FlowRoute::Kind::Direct) {
        if (route.translatedIp) TranslateDirect(bytes, packet.view, address, route.translatedIp, false, dirty);
        else if (dirty) WinDivertHelperCalcChecksums(bytes, static_cast<UINT>(packet.view.length), &address, 0);
        reinject.Send(network, bytes, packet.view.length, &address, 1); ++sentDirect; return;
    }
    const auto* server = config->ById(route.serverId);
    if (route.kind != FlowRoute::Kind::Tunnel || !server) {Drop("route_server_unavailable"); return;}
    auto ready = routes.find(route.serverId);
    if (ready == routes.end() || !ready->second.mtu || ready->second.revision != windowsRoutes.Revision() ||
        (!resumed && routePendingServers.count(route.serverId))) {
        if (routeWaiting.size() >= 1024 || packet.bytes->size() > 4 * 1024 * 1024 - routePendingBytes) {
            Drop("interface_route_queue_full"); return;
        }
        routeWaiting.push_back({packet, route, dirty, Clock::now() + std::chrono::seconds(5)});
        routeResumeAt = (std::min)(routeResumeAt, routeWaiting.back().expires);
        routePendingBytes += packet.bytes->size(); ++routePendingServers[route.serverId];
        QueueRouteRefresh(); return;
    }
    if (packet.view.length > 65535) {Drop("tunnel_packet_too_large"); return;}
    auto work = packet.bytes.use_count() == 1 ? packet.bytes : buffers.Copy(bytes, packet.view.length);
    Transmit(work->data(), packet.view, address, route, dirty, *server, ready->second);
}

void NetworkRuntime::Impl::Transmit(uint8_t* work, const PacketView& view, const WINDIVERT_ADDRESS& address, const FlowRoute& route,
    bool dirty, const Server& server, const TunnelRouteCache::Route& ready) {
    if (route.translatedIp) {Write32(work + 16, route.translatedIp); dirty = true;}
    DiagnosticSession::PacketOptions options;
    if (diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.TracksPort(view.tuple))
        options = diagnostics.Options(view.tuple, server.transport->id, work, view.length);
    if (!options.preserveMss) dirty |= ClampMss(work, view, config->mss);
    if (options.dontFragment) {
        if (view.length + 36 > ready.mtu) {
            diagnostics.RejectBeforeSend(options.session);
            return;
        }
        Write16(work + 6, 0x4000);
        dirty = true;
    }
    if (!options.preserveMss && view.tuple.protocol == 6 && view.syn) {
        const auto overhead = uint32_t(36 + view.header + size_t(work[view.header + 12] >> 4) * 4);
        if (ready.mtu > overhead) dirty |= ClampMss(work, view, static_cast<uint16_t>((std::min)(uint32_t(config->mss), ready.mtu - overhead)));
    }
    const auto& transport = server.transport;
    auto state = transport->session->Snapshot();
    if (!state || !state->addresses.count(view.tuple.localIp)) {
        transport->session->RequestAddress(view.tuple.localIp);
        if (sessionWaiting.size() >= 1024 || view.length > 4 * 1024 * 1024 - sessionWaitingBytes) { Drop("session_queue_full"); return; }
        sessionWaiting.push_back({{buffers.Copy(work, view.length), address, view, Clock::now()}, route, dirty}); sessionWaitingBytes += view.length;
        return;
    }
    if (options.probe.run) diagnostics.load.Record(miga::diagnostics::LoadCounters::Selected, options.probe);
    WinDivertHelperCalcChecksums(work, static_cast<UINT>(view.length), nullptr, 0);
    static const auto addresses = [] {
        std::array<WINDIVERT_ADDRESS, 64> values{};
        for (auto& value : values) {value.Outbound = 1; value.IPChecksum = 1; value.UDPChecksum = 1;}
        return values;
    }();
    const auto sendBatch = [&](const uint8_t* data, size_t bytes, size_t count) {
        if (options.session) {
            diagnostics.Submitted(options.session);
            return tunnel.SendObserved(network, data, bytes, addresses.data(), count,
                [this, id = options.session, sequence = options.sequence, probe = options.probe](bool success) {
                    diagnostics.Sent(id, success, sequence);
                    if (probe.run) diagnostics.load.Record(miga::diagnostics::LoadCounters::WireSent, probe, success);
                });
        }
        return tunnel.Send(network, data, bytes, addresses.data(), count);
    };
    if (state) {
        const auto transmit = [&](uint8_t* packet, size_t length) {
            if (!miga::v2::TranslateAddress(packet, length, view.tuple.localIp, state->addresses.at(view.tuple.localIp), true)) return false;
            const size_t maximumPayload = ready.mtu > 28 ? ready.mtu - 28 : 0;
            const auto capacity = (std::max)(length + 8, (std::min)(size_t(256), maximumPayload));
            return datagram.BuildGenerated(capacity, [&](uint8_t* output, size_t available) {
                return miga::v2::EncryptDataInto(state->keys.dataC2S, state->keys.prefixC2S,
                    packet, length, output, available, maximumPayload);
            }, ready.path.source, transport->destination, transport->localPort, state->port, ++packetId,
                ready.mtu, sendBatch, options.dontFragment);
        };
        if (view.length > miga::v2::MaxInner) {
            std::vector<miga::v2::Bytes> fragments; miga::v2::Bytes icmp;
            if (!miga::v2::FragmentInner(work, view.length, fragments, icmp)) {Drop("v2_fragment_invalid"); return;}
            if (!icmp.empty()) {
                auto reply = address; reply.Outbound = 0; reply.IPChecksum = 1;
                reinject.Send(network, icmp.data(), icmp.size(), &reply, 1); return;
            }
            for (auto& fragment : fragments) if (!transmit(fragment.data(), fragment.size())) {Drop("v2_send_failed"); return;}
        } else if (!transmit(work, view.length)) {Drop("v2_send_failed"); return;}
        transport->session->MarkActivity();
    }
    ++sentTunnel;
}

void NetworkRuntime::Impl::DrainSessions() {
    const auto now = Clock::now(); const auto count = (std::min)(size_t(128), sessionWaiting.size());
    for (size_t n = 0; n < count; ++n) {
        auto pending = std::move(sessionWaiting.front()); sessionWaiting.pop_front(); sessionWaitingBytes -= pending.packet.view.length;
        const auto* server = config->ById(pending.route.serverId);
        if (!server || now - pending.packet.received >= std::chrono::seconds(30)) {Drop("session_not_ready"); continue;}
        const auto state = server->transport->session->Snapshot();
        if (!state || !state->addresses.count(pending.packet.view.tuple.localIp)) {
            sessionWaitingBytes += pending.packet.view.length; sessionWaiting.push_back(std::move(pending)); continue;
        }
        Send(pending.packet, pending.route, pending.dirty);
    }
}

void NetworkRuntime::Impl::SendCaptured(uint8_t* bytes, const PacketView& view, const WINDIVERT_ADDRESS& address, const FlowRoute& route) {
    const auto* server = config->ById(route.serverId);
    if (route.kind != FlowRoute::Kind::Tunnel || !server) {Drop("route_server_unavailable"); return;}
    if (view.length > 65535) {Drop("tunnel_packet_too_large"); return;}
    auto ready = routes.find(route.serverId);
    if (ready != routes.end() && ready->second.mtu && ready->second.revision == windowsRoutes.Revision() &&
        !routePendingServers.count(route.serverId)) Transmit(bytes, view, address, route, false, *server, ready->second);
    else Send({buffers.Copy(bytes, view.length), address, view, Clock::now()}, route, false);
}

void NetworkRuntime::Impl::Inbound(uint8_t* bytes, size_t size, WINDIVERT_ADDRESS address, PacketView view) {
    const Server* remote = nullptr;
    if (view.tuple.protocol == 17) {
        const auto found = config->inboundPorts.find(view.tuple.remotePort);
        if (found != config->inboundPorts.end()) {
            const auto& server = config->servers[found->second];
            auto state = server.transport->session->Snapshot();
            if (htonl(view.tuple.localIp) == server.transport->destination &&
                (state && view.tuple.localPort == state->port)) remote = &server;
        }
    }
    if (!remote) {
        if (syntheticDns.Port() && view.tuple.protocol == 17 && view.tuple.remotePort == syntheticDns.Port()) {
            SyntheticResponse(bytes, address, view, 0);
            return;
        }
        if (config->fullRoutingServerId && !Local(view.tuple.localIp)) {
            Drop("full_routing_direct_inbound");
            return;
        }
        if (view.tuple.protocol == 17 && view.tuple.localPort == 53 && config->hasDomainRules) {
            Packet packet{buffers.Copy(bytes, view.length), address, view, Clock::now()};
            if (!classifierCommands.TryPush([this, packet = std::move(packet)]() mutable {
                auto active = published.load(); if (!active) return;
                dns.Response(std::move(packet), 0, *active, Clock::now());
            })) ++dnsObservationsLost;
        }
        if (auto original = flows.Inbound(view, address.Timestamp, 0, Clock::now(), config->dnsResolverEnabled)) {
            TranslateDirect(bytes, view, address, *original, true);
        }
        reinject.Send(network, bytes, size, &address, 1); ++sentDirect; return;
    }
    if (config->fullRoutingServerId && remote->transport->id != config->fullRoutingServerId) {
        Drop("full_routing_wrong_server");
        return;
    }
    const auto length = Read16(bytes + view.header + 4) - 8;
    auto* inner = bytes + view.header + 8;
    if (length < 28) {Drop("invalid_tunnel_payload"); return;}
    const auto decodedState = remote->transport->session->Snapshot();
    {
        const auto& state = decodedState;
        if (!state || !miga::v2::DecryptData(state->keys.dataS2C, state->keys.prefixS2C, inner, length, decryptedV2)) {Drop("v2_invalid_payload"); return;}
        inner = decryptedV2.data();
        if (decryptedV2.size() < 20 || (inner[0] >> 4) != 4) {Drop("v2_invalid_response"); return;}
        const auto virtualIp = miga::v2::Get32(inner + 16);
        const auto original = std::find_if(state->addresses.begin(), state->addresses.end(), [&](const auto& item) { return item.second == virtualIp; });
        if (original == state->addresses.end() || !miga::v2::TranslateAddress(inner, decryptedV2.size(), virtualIp, original->first, false)) {Drop("v2_unknown_address"); return;}
    }
    size_t innerLength = decryptedV2.size();
    if (Read16(inner + 6) & 0x3fff) {
        const auto& state = decodedState;
        if (!state) {Drop("v2_session_unavailable"); return;}
        miga::v2::Bytes identity; miga::v2::Put64(identity, uint64_t(remote->transport->id));
        identity.insert(identity.end(), state->session.begin(), state->session.end()); miga::v2::Put64(identity, state->generation);
        const std::string context(reinterpret_cast<const char*>(identity.data()), identity.size());
        const auto result = innerReassembler.Add(inner, innerLength, innerReassembled, context);
        if (result == miga::v2::Ipv4Reassembler::Result::Waiting) return;
        if (result == miga::v2::Ipv4Reassembler::Result::Rejected) {Drop("v2_fragment_invalid"); return;}
        inner = innerReassembled.data(); innerLength = innerReassembled.size();
    }
    PacketView decoded;
    if (!decoded.Read(inner, innerLength)) {Drop("invalid_inner_packet"); return;}
    if (syntheticDns.Port() && decoded.tuple.protocol == 17 && decoded.tuple.remotePort == syntheticDns.Port()) {
        SyntheticResponse(inner, address, decoded, remote->transport->id);
        return;
    }
    const auto serverId = remote->transport->id;
    const auto now = Clock::now();
    const bool legacyDnsResponse = !config->fullRoutingServerId && decoded.tuple.protocol == 17 && decoded.tuple.localPort == 53;
    const auto original = legacyDnsResponse ? flows.Reverse(decoded.IncomingTuple(), serverId, address.Timestamp, now)
        : flows.Inbound(decoded, address.Timestamp, serverId, now, true);
    if (original) {
        Write32(inner + 12, *original); decoded.tuple.localIp = *original;
    }
    if (!(decoded.tuple.protocol == 6 && (decoded.tcp.flags & 2) && diagnostics.enabled.load(std::memory_order_relaxed) &&
        diagnostics.TracksPort(decoded.IncomingTuple()) &&
        diagnostics.Options(decoded.IncomingTuple(), remote->transport->id).preserveMss)) {
        uint16_t maximum = config->mss;
        if (decodedState && decoded.tuple.protocol == 6 && decoded.syn) {
            const auto route = routes.find(remote->transport->id);
            const auto overhead = uint32_t(36 + decoded.header + size_t(inner[decoded.header + 12] >> 4) * 4);
            if (route != routes.end() && route->second.mtu > overhead)
                maximum = static_cast<uint16_t>((std::min)(uint32_t(maximum), route->second.mtu - overhead));
        }
        ClampMss(inner, decoded, maximum);
    }
    if (legacyDnsResponse) {
        Packet packet{buffers.Copy(inner, decoded.length), address, decoded, Clock::now()};
            if (!classifierCommands.TryPush([this, packet = std::move(packet), serverId]() mutable {
            auto active = published.load();
            if (!active || active->fullRoutingServerId || !active->ById(serverId)) return;
            auto response = dns.Response(std::move(packet), serverId, *active, Clock::now());
            if (response) networkCommands.Push([this, packet = std::move(*response), serverId]() mutable {
                if (config->fullRoutingServerId || !config->ById(serverId)) return;
                flows.Inbound(packet.view, packet.address.Timestamp, serverId, Clock::now());
                Send(packet, {}, true);
            });
        })) Drop("dns_queue_full");
        return;
    }
    WinDivertHelperCalcChecksums(inner, static_cast<UINT>(decoded.length), &address, 0);
    miga::diagnostics::Probe loadProbe;
    if (diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.TracksPort(decoded.IncomingTuple()) &&
        diagnostics.load.enabled.load(std::memory_order_relaxed) && miga::diagnostics::ReadProbePacket(inner, decoded.length, loadProbe)) {
        diagnostics.load.Record(miga::diagnostics::LoadCounters::ClientReceived, loadProbe);
        reinject.SendObserved(network, inner, decoded.length, &address, 1, [this, loadProbe](bool success) {
            diagnostics.load.Record(miga::diagnostics::LoadCounters::Reinject, loadProbe, success);
        });
    } else reinject.Send(network, inner, decoded.length, &address, 1);
    ++sentDirect;
}

void NetworkRuntime::Impl::PacketReceived(uint8_t* bytes, size_t size, WINDIVERT_ADDRESS address) {
    ++captured;
    if (size >= 20 && (bytes[0] >> 4) == 4 && (Read16(bytes + 6) & 0x3fff) && (bytes[9] == 6 || bytes[9] == 17)) {
        const auto result = reassembler.Add(bytes, size, reassembledV2);
        if (result == miga::v2::Ipv4Reassembler::Result::Rejected) {Drop("ipv4_fragment_invalid"); return;}
        if (result == miga::v2::Ipv4Reassembler::Result::Waiting) return;
        bytes = reassembledV2.data(); size = reassembledV2.size();
        if (config->dnsResolverEnabled) address.TCPChecksum = address.UDPChecksum = 0;
    }
    PacketView view;
    if (!view.Read(bytes, size)) {
        if (address.Outbound && size >= 20 && (bytes[0] >> 4) == 4 && SyntheticAddress(Read32(bytes + 16)))
            Drop("synthetic_invalid_packet");
        else if (config->fullRoutingServerId) Drop("full_routing_invalid_packet");
        else reinject.Send(network, bytes, size, &address, 1);
        return;
    }
    logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {return "packet_received" + Describe(view, address);});
    if (view.tuple.protocol == 17 && (view.tuple.remotePort == BootstrapDnsPort || view.tuple.localPort == BootstrapDnsPort)) {
        const auto tuple = address.Outbound && view.tuple.remotePort == BootstrapDnsPort ? view.tuple : view.IncomingTuple();
        const auto active = bootstrapDnsTuple.load(std::memory_order_acquire);
        if (active && tuple.remotePort == BootstrapDnsPort && BootstrapDnsKey(tuple) == active) {
            reinject.Send(network, bytes, view.length, &address, 1);
            if (address.Outbound) ++sentDirect;
            return;
        }
    }
    if (view.tuple.protocol == 17 && !(address.Outbound && SyntheticAddress(view.tuple.remoteIp))) {
        const auto tuple = address.Outbound ? view.tuple : view.IncomingTuple();
        if (diagnostics.DirectProbeMatches(tuple)) {
            reinject.Send(network, bytes, size, &address, 1);
            if (address.Outbound) ++sentDirect;
            return;
        }
        const auto matches = [&](const auto& session) {
            return session && session->IsControlTuple(tuple.remoteIp, tuple.remotePort, tuple.localPort, address.Outbound != 0);
        };
        for (const auto& server : config->servers) {
            if (matches(server.transport->session)) {
                reinject.Send(network, bytes, size, &address, 1);
                return;
            }
        }
        if (const auto sessions = preparingSessions.load()) {
            for (const auto& candidate : *sessions) {
                if (matches(candidate.lock())) {
                    reinject.Send(network, bytes, size, &address, 1);
                    return;
                }
            }
        }
    }
    if (!address.Outbound) {Inbound(bytes, size, address, view); return;}
    Outbound(bytes, address, view, true);
}

void NetworkRuntime::Impl::SyntheticResponse(uint8_t* bytes, const WINDIVERT_ADDRESS& address, const PacketView& view,
    size_t server) {
    if (!config->dnsResolverEnabled) return;
    auto current = config;
    Packet packet{buffers.Copy(bytes, view.length), address, view, Clock::now()};
    if (!classifierCommands.TryPush([this, packet = std::move(packet), current, server] {
        const auto active = published.load();
        if (active != current) return;
        SyntheticDnsResolver::Outputs output;
        uint32_t wakeAddress = 0;
        syntheticDns.Response(packet, server, *current, buffers, Clock::now(), output, wakeAddress);
        if (output.empty() && !wakeAddress) return;
        networkCommands.Push([this, current, output = std::move(output), wakeAddress] {
            if (prepared || config != current) return;
            for (const auto& item : output) Send(item.packet, item.route, true);
            if (wakeAddress) RetrySynthetic(wakeAddress);
        });
    })) Drop("synthetic_dns_queue_full");
}

void NetworkRuntime::Impl::RetrySynthetic(uint32_t ip) {
    for (auto& [key, group] : waiting)
        if (key.dstIp == ip && !group.readyGeneration) Request(key);
}

void NetworkRuntime::Impl::Outbound(uint8_t* bytes, WINDIVERT_ADDRESS address, const PacketView& view, bool allowSyntheticDns) {
    const bool synthetic = SyntheticAddress(view.tuple.remoteIp);
    if (synthetic && !config->dnsResolverEnabled) {Drop("synthetic_dns_disabled"); return;}
    if (allowSyntheticDns && config->dnsResolverEnabled && !synthetic && view.tuple.protocol == 17 && view.tuple.remotePort == 53) {
        auto current = config;
        Packet packet{buffers.Copy(bytes, view.length), address, view, Clock::now()};
        if (!classifierCommands.TryPush([this, packet = std::move(packet), current] {
            const auto active = published.load();
            if (active != current) return;
            SyntheticDnsResolver::Outputs output;
            const auto now = Clock::now();
            const auto owner = directory.Find(packet.view.tuple, packet.address.Timestamp, false, now);
            const auto* server = owner ? current->Process(owner->owner->process->Name()) : nullptr;
            const auto handled = syntheticDns.Query(packet, *current, buffers, now, output,
                server ? server->transport->id : 0);
            if (handled && output.empty()) return;
            networkCommands.Push([this, packet, current, handled, output = std::move(output)] {
                if (prepared || config != current) return;
                if (!handled) Outbound(packet.bytes->data(), packet.address, packet.view, false);
                else for (const auto& item : output) Send(item.packet, item.route, true);
            });
        })) Drop("synthetic_dns_queue_full");
        return;
    }
    if (diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.TracksPort(view.tuple))
        diagnostics.ObserveProbe(view.tuple, bytes, view.length);
    if (Local(view.tuple.remoteIp)) {
        if (diagnostics.enabled.load(std::memory_order_relaxed) && diagnostics.TracksPort(view.tuple) &&
            diagnostics.RejectFallback(view.tuple, {})) { Drop("diagnostic_destination_local"); return; }
        const bool privateDns = view.tuple.protocol == 17 && view.tuple.remotePort == 53 &&
            PrivateIpv4(view.tuple.remoteIp) &&
            (config->fullRoutingServerId || config->hasDomainRules || !config->processes.empty());
        if (!privateDns) {
            reinject.Send(network, bytes, view.length, &address, 1); ++sentDirect; return;
        }
        if (config->fullRoutingServerId) {
            DnsMessage message;
            if (!message.Read(bytes, view) || message.response) {
                reinject.Send(network, bytes, view.length, &address, 1); ++sentDirect; return;
            }
        }
    }
    if (config->fullRoutingServerId && !synthetic) {
        const FlowRoute route{FlowRoute::Kind::Tunnel, config->fullRoutingServerId, 0};
        if (diagnostics.enabled.load(std::memory_order_relaxed)) {
            const auto owner = directory.Find(view.tuple, address.Timestamp, view.syn, Clock::now());
            if (owner && diagnostics.Selected(owner->owner->process))
                diagnostics.Observe(view.tuple, owner->owner->process, route, "full_routing");
            if (diagnostics.TracksPort(view.tuple) && diagnostics.RejectFallback(view.tuple, route)) {
                Drop("diagnostic_route_unconfirmed");
                return;
            }
        }
        SendCaptured(bytes, view, address, route);
        return;
    }
    auto result = flows.Lookup(view, address.Timestamp, Clock::now());
    logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {
        return std::string("route_lookup reason=") + result.reason + Describe(view, address) +
            " generation=" + std::to_string(result.generation) + " server_id=" + std::to_string(result.route.serverId);
    });
    if (result.action == FlowTable::Action::Send && diagnostics.enabled.load(std::memory_order_relaxed)) {
        if (result.owner && diagnostics.Selected(result.owner->owner->process))
            diagnostics.Observe(view.tuple, result.owner->owner->process, result.route, result.reason);
        if ((!result.owner || diagnostics.Selected(result.owner->owner->process)) &&
            diagnostics.TracksPort(view.tuple) && diagnostics.RejectFallback(view.tuple, result.route)) {
            Drop("diagnostic_route_unconfirmed"); return;
        }
    }
    const auto pending = waiting.find(FlowKey::From(view.tuple));
    const bool ordered = pending != waiting.end() && pending->second.readyGeneration == result.generation && result.generation;
    if (result.action == FlowTable::Action::Drop) {Drop(result.reason); return;}
    if (result.action == FlowTable::Action::Send && !ordered &&
        (synthetic || !(view.tuple.protocol == 17 && view.tuple.remotePort == 53))) {
        if (synthetic && !result.route.translatedIp) {Drop("synthetic_route_unavailable"); return;}
        if (result.route.kind == FlowRoute::Kind::Direct) {
            if (result.route.translatedIp) {
                TranslateDirect(bytes, view, address, result.route.translatedIp, false);
            }
            reinject.Send(network, bytes, view.length, &address, 1); ++sentDirect;
        } else SendCaptured(bytes, view, address, result.route);
        return;
    }
    Defer(bytes, view.length, address, view);
}

bool NetworkRuntime::Impl::Issue(Receive& receive) {
    receive.api = &api;
    receive.handle = network;
    if (!receive.operation.hEvent) return false;
    ResetEvent(receive.operation.hEvent);
    receive.addressLength = static_cast<UINT>(sizeof(receive.addresses));
    receive.length = 0; receive.ready = receive.pending = false;
    if (api.receive(network, receive.data.data(), static_cast<UINT>(receive.data.size()), &receive.length,
        0, receive.addresses.data(), &receive.addressLength, &receive.operation)) receive.ready = true;
    else if (GetLastError() == ERROR_IO_PENDING) receive.pending = true;
    else {ReceiveError("network_receive_failed"); return false;}
    return true;
}

void NetworkRuntime::Impl::ApplyPrepared() {
    if (!prepared) return;
    tunnel.Reap(); reinject.Reap();
    if (tunnel.Busy() || reinject.Busy()) return;
    if (!prepared->config->dnsResolverEnabled) {
        auto& next = *prepared->config;
        next.dnsResolverReservedThrough = (std::max)(next.dnsResolverReservedThrough, syntheticDns.LastAllocated());
        next.dnsResolverReserveRange = next.dnsResolverReservedThrough != 0;
    }
    const bool routingChanged = config->fullRoutingServerId != prepared->config->fullRoutingServerId ||
        config->dnsResolverReserveRange != prepared->config->dnsResolverReserveRange ||
        config->dnsResolverEnabled != prepared->config->dnsResolverEnabled;
    config = std::move(prepared->config);
    ApplyRoutes(*config, std::move(prepared->routes));
    if (routingChanged) {
        flows.Clear();
        waiting.clear(); waitingPorts.clear(); waitingDeadlines.Clear(); pendingPackets = pendingBytes = 0;
        readyWaiting.clear(); classificationRetries.clear();
        routeWaiting.clear(); routePendingServers.clear(); routePendingBytes = 0;
        routeResumeAt = (Clock::time_point::max)();
        sessionWaiting.clear(); sessionWaitingBytes = 0;
    }
    restartRules.emplace(); restartRules->reserve(config->servers.size());
    restartFullRoutingProfileId.clear();
    for (const auto& server : config->servers) {
        restartRules->push_back(server.rules);
        if (server.transport->id == config->fullRoutingServerId) restartFullRoutingProfileId = server.rules.profileId;
    }
    restartMss = config->mss; restartLogLevel = config->logLevel;
    restartDnsResolverEnabled = config->dnsResolverEnabled;
    published.store(config);
    if (auto sessions = preparingSessions.load()) {
        const auto active = [&](const auto& candidate) {
            const auto session = candidate.lock();
            return !session || std::any_of(config->servers.begin(), config->servers.end(), [&](const auto& server) {
                return server.transport->session == session;
            });
        };
        if (std::all_of(sessions->begin(), sessions->end(), active))
            preparingSessions.compare_exchange_strong(sessions, {});
    }
    std::unordered_set<size_t> ids;
    for (const auto& server : config->servers) ids.insert(server.transport->id);
    flows.Servers(ids);
    logger->setLevel(config->logLevel);
    if (prepared->completion) prepared->completion->set_value(true);
    prepared.reset();
    ResumeRoutes();
    for (auto& entry : waiting) {entry.second.outstanding = false; Request(entry.first);}
    logger->log(LOGGER_LEVEL_INFO, "runtime_config_applied version=" + std::to_string(config->version));
}

void NetworkRuntime::Impl::NetworkLoop() {
    std::array<Receive, 2> receive;
    size_t index = 0;
    if (!Issue(receive[index])) {Halt(); return;}
    while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) {
        tunnel.Reap(); reinject.Reap();
        std::function<void()> command;
        for (size_t i = 0; i < 32 && networkCommands.Pop(command); ++i) {command(); command = {};}
        ApplyPrepared();
        if (!prepared) {
            const auto retryCount = (std::min)(classificationRetries.size(), size_t(32));
            for (size_t i = 0; i < retryCount; ++i) {
                const auto key = classificationRetries.front(); classificationRetries.pop_front();
                auto found = waiting.find(key); if (found != waiting.end()) found->second.retryQueued = false;
                Request(key);
            }
            DrainReady(); ExpireWaiting(); DrainSessions();
            if (Clock::now() >= routeResumeAt) ResumeRoutes();
        }
        auto& current = receive[index];
        if (current.pending && WaitForSingleObject(current.operation.hEvent, 0) == WAIT_OBJECT_0) {
            DWORD bytes = 0;
            if (!api.result(network, &current.operation, &bytes, FALSE)) {ReceiveError("network_receive_failed"); break;}
            current.length = bytes; current.pending = false; current.ready = true;
        }
        if (current.ready && !prepared) {
            const auto filled = index;
            index ^= 1;
            if (!Issue(receive[index])) break;
            auto& batch = receive[filled];
            batch.ready = false;
            const auto begin = Clock::now();
            reinject.BeginBatch(); tunnel.BeginBatch();
            size_t offset = 0;
            if (batch.addressLength > sizeof(batch.addresses) || batch.addressLength % sizeof(WINDIVERT_ADDRESS)) {
                Error("network_batch_invalid", ERROR_INVALID_DATA); break;
            }
            for (size_t i = 0; i < batch.addressLength / sizeof(WINDIVERT_ADDRESS); ++i) {
                const auto length = Ipv4BatchPacketLength(batch.data.data(), batch.length, offset);
                if (!length) {Error("network_batch_invalid", ERROR_INVALID_DATA); break;}
                PacketReceived(batch.data.data() + offset, length, batch.addresses[i]); offset += length;
            }
            tunnel.EndBatch(); reinject.EndBatch();
            logger->recordDelay(NetworkWarning::BatchProcessing, begin);
            continue;
        }
        const auto now = Clock::now();
        const bool busy = tunnel.Busy() || reinject.Busy() || prepared.has_value();
        const auto due = prepared ? now + std::chrono::milliseconds(10) :
            (std::min)(waitingDeadlines.Next(now + std::chrono::hours(24)), routeResumeAt);
        auto wait = static_cast<DWORD>((std::min)(int64_t(busy ? 10 : INFINITE - 1),
            (std::max)(int64_t(0), std::chrono::duration_cast<std::chrono::milliseconds>(due - now).count())));
        if (!sessionWaiting.empty()) wait = (std::min)(wait, DWORD(20));
        if (!readyWaiting.empty() && !prepared) wait = 0;
        if (!classificationRetries.empty() && !prepared) wait = (std::min)(wait, DWORD(1));
        HANDLE events[]{stop, receive[index].operation.hEvent, networkCommands.Event()};
        if (receive[index].ready) WaitForSingleObject(stop, wait);
        else WaitForMultipleObjects(3, events, FALSE, wait);
    }
    Halt();
    for (auto& item : receive) if (item.pending) {
        api.cancel(network, &item.operation); DWORD bytes = 0; api.result(network, &item.operation, &bytes, TRUE); item.pending = false;
    }
    tunnel.RequestStop(); reinject.RequestStop(); tunnel.Drain(); reinject.Drain();
}

bool NetworkRuntime::Impl::Start() {
    if (running.load() && WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) return true;
    if (!stop) return false;
    Stop();
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    winsock = true;
    captured.store(0); sentDirect.store(0); sentTunnel.store(0); deferred.store(0); dropped.store(0);
    dnsObservationsLost = 0; lastSummary = Clock::now();
    ResetEvent(stop);
    networkCommands.Reset(); classifierCommands.Reset(); windowsCommands.Reset(); socketCommands.Reset();
    if (windowsRoutes.Start() != NO_ERROR || !reinject.Reset() || !tunnel.Reset()) return false;
    const auto dnsEnabled = restartRules ? restartDnsResolverEnabled : initial->GetDnsResolverEnabled();
    const auto dnsGuard = syntheticDns.Preflight(dnsEnabled);
    if (!dnsGuard) {
        Error("synthetic_dns_init_failed", ERROR_NOT_READY);
        Stop();
        return false;
    }
    config = Prepare(restartRules ? *restartRules : initial->GetServers(),
        restartRules ? restartMss : initial->GetTunnelMaxMss(),
        restartRules ? restartLogLevel : initial->GetLogLevel(),
        restartRules ? restartFullRoutingProfileId : initial->GetFullRoutingProfileId(),
        dnsEnabled, *dnsGuard, {}, routes);
    if (!config) return false;
    published.store(config);
    socket = api.open("protocol == 6 or protocol == 17", WINDIVERT_LAYER_SOCKET, 0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (socket == INVALID_HANDLE_VALUE) {Error("socket_open_failed", GetLastError()); return false;}
    ConfigureProbes();
    socketThread = std::thread([this] {try {SocketLoop();} catch (...) {Error("socket_thread_failed", ERROR_NOT_ENOUGH_MEMORY); Halt();}});
    SeedSockets();
    if (WaitForSingleObject(stop, 0) != WAIT_TIMEOUT) return false;
    network = api.open("ip and (tcp or (udp.SrcPort != 67 and udp.DstPort != 67 and udp.SrcPort != 68 and udp.DstPort != 68))",
        WINDIVERT_LAYER_NETWORK, 0, 0);
    if (network == INVALID_HANDLE_VALUE) {Error("network_open_failed", GetLastError()); api.close(socket); socket = INVALID_HANDLE_VALUE; return false;}
    reinject.SetErrorHandler([this](DWORD code) {Error("reinject_send_failed", code);});
    tunnel.SetErrorHandler([this](DWORD code) {Error("tunnel_send_failed", code);});
    running.store(true);
    classifierThread = std::thread([this] {Worker(classifierCommands, &Impl::DnsWait);});
    windowsThread = std::thread([this] {Worker(windowsCommands);});
    maintenanceThread = std::thread([this] {try {Maintenance();} catch (...) {Error("maintenance_thread_failed", ERROR_NOT_ENOUGH_MEMORY); Halt();}});
    networkThread = std::thread([this] {
        try {NetworkLoop();} catch (...) {
            Error("network_thread_failed", ERROR_NOT_ENOUGH_MEMORY); Halt();
            tunnel.RequestStop(); reinject.RequestStop(); tunnel.Drain(); reinject.Drain();
        }
    });
    profiles.Start([this](const std::string& profile) {
        const auto active = published.load();
        if (active) for (const auto& server : active->servers)
            if (server.rules.profileId == profile && server.transport->session)
                return server.transport->session->Status();
        return std::string();
    }, [this](const std::string& profile) {
        const auto active = published.load();
        if (active) for (const auto& server : active->servers) {
            if (server.rules.profileId != profile || !server.transport->session) continue;
            const auto bytes = server.transport->session->OpenDiagnostics();
            if (bytes.size() != 66) return std::string();
            const auto address = ntohl(server.transport->destination);
            const auto host = std::to_string(address >> 24) + "." + std::to_string((address >> 16) & 255) + "." +
                std::to_string((address >> 8) & 255) + "." + std::to_string(address & 255);
            return DiagnosticSession::Json{{"ok", true}, {"host", host},
                {"port", miga::v2::Get16(bytes.data())},
                {"fingerprint", miga::v2::Base64(bytes.data() + 2, 32)},
                {"ticket", miga::v2::Base64(bytes.data() + 34, 32)}}.dump();
        }
        return std::string();
    });
    diagnostics.Start([this](DWORD pid, const DiagnosticSession::Json& request) {
        using Json = DiagnosticSession::Json;
        const auto target = request.value("target_pid", pid);
        if (target != pid && request.value("mode", "tunnel") != "rules")
            return Json{{"ok", false}, {"error", "external_process_requires_rules_mode"}};
        auto owner = processes.Get(target, LoadWindowsProcessIdentity);
        if (!owner->isAlive()) return Json{{"ok", false}, {"error", "process_unavailable"}};
        const auto profileValue = request.find("profile_id");
        const auto profile = profileValue != request.end() && profileValue->is_string() ? profileValue->get<std::string>() : std::string();
        const auto force = request.value("mode", "tunnel") == "tunnel";
        auto active = published.load();
        const Server* selected = nullptr;
        if (active) for (const auto& item : active->servers) {
            if (profile.empty() || item.rules.profileId != profile) continue;
            if (selected) return Json{{"ok", false}, {"error", "ambiguous_server"}};
            selected = &item;
        }
        if (selected && selected->transport->session && selected->transport->session->Status() == "ready") {
            diagnostics.Configure(owner, selected->transport->id, force);
            return Json{{"ok", true}, {"pid", owner->pid}, {"server_id", selected->transport->id}, {"mode", force ? "tunnel" : "rules"}};
        }
        diagnostics.Configure(owner, 0, false);
        return Json{{"ok", true}, {"pid", owner->pid}, {"local_only", true}, {"mode", "rules"}};
    });
    logger->log(LOGGER_LEVEL_INFO, "network_runtime_started");
    return true;
}

void NetworkRuntime::Impl::Stop() {
    const bool active = running.load() || network != INVALID_HANDLE_VALUE || socket != INVALID_HANDLE_VALUE;
    running.store(false);
    profiles.Stop();
    SetEvent(stop);
    networkCommands.Close(); classifierCommands.Close(); windowsCommands.Close(); socketCommands.Close();
    if (network != INVALID_HANDLE_VALUE) api.shutdown(network, WINDIVERT_SHUTDOWN_RECV);
    if (socket != INVALID_HANDLE_VALUE) api.shutdown(socket, WINDIVERT_SHUTDOWN_RECV);
    for (auto* thread : {&networkThread, &socketThread, &classifierThread, &windowsThread, &maintenanceThread})
        if (thread->joinable()) thread->join();
    diagnostics.Stop();
    if (active) {lastSummary = Clock::now() - std::chrono::seconds(5); Summary();}
    windowsRoutes.Stop();
    if (network != INVALID_HANDLE_VALUE) api.close(network);
    if (socket != INVALID_HANDLE_VALUE) api.close(socket);
    network = socket = INVALID_HANDLE_VALUE;
    networkCommands.Reset(); classifierCommands.Reset(); windowsCommands.Reset(); socketCommands.Reset();
    waiting.clear(); waitingPorts.clear(); waitingDeadlines.Clear(); pendingPackets = pendingBytes = 0;
    readyWaiting.clear(); classificationRetries.clear(); routePendingServers.clear(); routeRefreshPending.store(false); processes.Clear();
    routeResumeAt = (Clock::time_point::max)();
    sessionWaiting.clear(); sessionWaitingBytes = 0; reassembler.Clear(); innerReassembler.Clear();
    dropSamples.clear();
    flows.Clear(); directory.Clear(); dns.Clear(); routes.clear(); routeCache.clear(); routeWaiting.clear(); routePendingBytes = 0; prepared.reset(); config.reset();
    published.store({});
    preparingSessions.store({});
    syntheticDns.Stop();
    if (winsock) {WSACleanup(); winsock = false;}
    if (active) logger->log(LOGGER_LEVEL_INFO, "network_runtime_stopped");
}

bool NetworkRuntime::Impl::Reload(const std::string& path) {
    if (!running.load()) return false;
    auto completion = std::make_shared<std::promise<bool>>();
    auto future = completion->get_future();
    if (!classifierCommands.TryPush([this, path, completion] {
        ConfigManager next(logger);
        if (!next.Load(path)) {completion->set_value(false); return;}
        auto servers = next.GetServers(); const auto mss = next.GetTunnelMaxMss(); const auto level = next.GetLogLevel();
        auto previous = published.load();
        auto fullProfileId = next.GetFullRoutingProfileId();
        const auto resolverEnabled = next.GetDnsResolverEnabled();
        const auto dnsGuard = syntheticDns.Preflight(resolverEnabled);
        if (!dnsGuard) {
            Error("synthetic_dns_init_failed", ERROR_NOT_READY);
            completion->set_value(false);
            return;
        }
        if (!windowsCommands.Push([this, servers = std::move(servers), mss, level, fullProfileId = std::move(fullProfileId), resolverEnabled, dnsGuard, previous, completion] {
            Prepared next;
            next.config = Prepare(servers, mss, level, fullProfileId, resolverEnabled, *dnsGuard, previous, next.routes); next.completion = completion;
            if (!next.config) {completion->set_value(false); return;}
            if (!networkCommands.Push([this, next = std::move(next)]() mutable {
                if (prepared) {next.completion->set_value(false); return;}
                prepared.emplace(std::move(next));
            })) completion->set_value(false);
        })) completion->set_value(false);
    })) return false;
    completion.reset();
    try {return future.get();} catch (...) {return false;}
}
