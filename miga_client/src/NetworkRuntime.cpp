#include "NetworkRuntimeImpl.h"

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

NetworkRuntime::Impl::Impl(ConfigManager* source, Logger* output) : initial(source), logger(output) {}

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
    for (const auto& tuple : existingTcp) flows.Seed(tuple, timestamp.QuadPart, Clock::now());
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

std::shared_ptr<Configuration> NetworkRuntime::Impl::Prepare(const std::vector<ServerConfig>& servers, uint16_t mss, int level,
    const std::shared_ptr<const Configuration>& previous, std::unordered_map<size_t, TunnelRouteCache::Route>& ready) {
    auto result = std::make_shared<Configuration>();
    result->version = ++nextConfiguration; result->mss = mss; result->logLevel = level;
    std::unordered_set<size_t> reused;
    for (const auto& rules : servers) {
        std::shared_ptr<Transport> transport;
        if (previous) for (const auto& old : previous->servers)
            if (!reused.count(old.transport->id) && old.rules.SameTransport(rules)) { transport = old.transport; break; }
        if (!transport) {
            transport = std::make_shared<Transport>();
            transport->id = ++nextServer;
            if (!transport->transform.Initialize(rules.xorKeyBase64, rules.swapKeyBase64)) return {};
            in_addr address{};
            if (inet_pton(AF_INET, rules.serverIP.c_str(), &address) != 1) {
                addrinfo hint{}; hint.ai_family = AF_INET; hint.ai_socktype = SOCK_DGRAM;
                addrinfo* resolved = nullptr;
                if (getaddrinfo(rules.serverIP.c_str(), nullptr, &hint, &resolved) != 0) return {};
                address = reinterpret_cast<sockaddr_in*>(resolved->ai_addr)->sin_addr;
                freeaddrinfo(resolved);
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
        ready.emplace(transport->id, route);
        reused.insert(transport->id);
        result->servers.push_back({rules, std::move(transport)});
    }
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
        if (config && config->version == version) { routes = std::move(updates); ResumeRoutes(); }
    });
    routeRefreshPending.store(false);
}

void NetworkRuntime::Impl::QueueRouteRefresh() {
    if (!routeRefreshPending.exchange(true) && !windowsCommands.TryPush([this] {RefreshRoutes();}))
        routeRefreshPending.store(false);
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
                logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {
                    return "socket_event type=" + std::to_string(address.Event) + Describe(tuple) +
                        " pid=" + std::to_string(address.Socket.ProcessId) + " endpoint_id=" + std::to_string(address.Socket.EndpointId) +
                        " parent_endpoint_id=" + std::to_string(address.Socket.ParentEndpointId) +
                        " event_timestamp_qpc=" + std::to_string(address.Timestamp);
                });
                if (address.Event == WINDIVERT_EVENT_SOCKET_CLOSE)
                    directory.Close(tuple, address.Socket.EndpointId, address.Socket.ProcessId, address.Timestamp, Clock::now());
                else if (address.Event == WINDIVERT_EVENT_SOCKET_BIND || address.Event == WINDIVERT_EVENT_SOCKET_CONNECT ||
                    address.Event == WINDIVERT_EVENT_SOCKET_ACCEPT) {
                    auto identity = processes.Get(address.Socket.ProcessId, LoadWindowsProcessIdentity);
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
                RouteDecision stale; stale.request = request; stale.configVersion = version; Classified(key, stale, false, {});
            });
            return;
        }
        const auto now = Clock::now();
        auto owner = directory.Find(packet.view.tuple, packet.address.Timestamp, packet.view.syn, now);
        RouteDecision decision;
        decision.request = request; decision.configVersion = current->version;
        decision.owner = owner;
        std::vector<DnsClassifier::Output> dnsOutput;
        bool dnsQuery = false;
        if (owner) {
            const auto pid = owner->owner->process->pid;
            if (pid != 4 && pid != ownPid) {
                const auto name = owner->owner->process->Name();
                dnsQuery = packet.view.tuple.protocol == 17 && packet.view.tuple.remotePort == 53;
                if (dnsQuery) dnsOutput = dns.Query(packet, *current, name, buffers, now);
                else if (!(packet.view.tuple.protocol == 6 && !packet.view.syn)) {
                    if (const auto* server = dns.Select(*current, name, packet.view.tuple.remoteIp, now))
                        decision.route = {FlowRoute::Kind::Tunnel, server->transport->id,
                            dns.Translate(packet.view.tuple.remoteIp, server->transport->id, now)};
                }
            }
        }
        networkCommands.Push([this, key, decision, dnsQuery, dnsOutput = std::move(dnsOutput)]() mutable {
            Classified(key, decision, dnsQuery, std::move(dnsOutput));
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

void NetworkRuntime::Impl::Classified(const FlowKey& key, const RouteDecision& decision, bool dnsQuery, std::vector<DnsClassifier::Output> output) {
    auto found = waiting.find(key);
    if (found == waiting.end() || found->second.request != decision.request) return;
    auto& group = found->second; group.outstanding = false;
    if (prepared) return;
    if (decision.configVersion != config->version) {Request(key); return;}
    const auto& first = group.packets.front();
    auto latest = directory.Find(first.view.tuple, first.address.Timestamp, first.view.syn, Clock::now());
    if (!decision.owner || !latest || latest->owner != decision.owner->owner) {
        if (latest) Request(key);
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
            return "route_created" + Describe(first.view, first.address) +
                " pid=" + std::to_string(decision.owner->owner->process->pid) +
                " endpoint_id=" + std::to_string(decision.owner->owner->endpointId) +
                " generation=" + std::to_string(group.readyGeneration) + " server_id=" + std::to_string(decision.route.serverId) +
                " owner_timestamp_qpc=" + std::to_string(decision.owner->owner->timestamp);
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
            auto result = flows.Expire(packet.view, packet.address.Timestamp, now);
            logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {return std::string("pending_timeout reason=") + result.reason + Describe(packet.view, packet.address);});
            if (result.action == FlowTable::Action::Send) {
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
        const bool valid = found != routes.end() && found->second.source && found->second.revision == windowsRoutes.Revision();
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
    auto* bytes = packet.bytes->data();
    auto address = packet.address;
    if (route.kind == FlowRoute::Kind::Direct) {
        if (dirty) WinDivertHelperCalcChecksums(bytes, static_cast<UINT>(packet.view.length), &address, 0);
        reinject.Send(network, bytes, packet.view.length, &address, 1); ++sentDirect; return;
    }
    const auto* server = config->ById(route.serverId);
    if (route.kind != FlowRoute::Kind::Tunnel || !server) {Drop("route_server_unavailable"); return;}
    auto ready = routes.find(route.serverId);
    if (ready == routes.end() || !ready->second.source || ready->second.revision != windowsRoutes.Revision() ||
        (!resumed && routePendingServers.count(route.serverId))) {
        if (routeWaiting.size() >= 1024 || packet.bytes->size() > 4 * 1024 * 1024 - routePendingBytes) {
            Drop("interface_route_queue_full"); return;
        }
        routeWaiting.push_back({packet, route, dirty, Clock::now() + std::chrono::seconds(5)});
        routeResumeAt = (std::min)(routeResumeAt, routeWaiting.back().expires);
        routePendingBytes += packet.bytes->size(); ++routePendingServers[route.serverId];
        QueueRouteRefresh(); return;
    }
    if (packet.view.length > 65507) {Drop("tunnel_packet_too_large"); return;}
    auto work = packet.bytes.use_count() == 1 ? packet.bytes : buffers.Copy(bytes, packet.view.length);
    Transmit(work->data(), packet.view, address, route, dirty, *server, ready->second);
}

void NetworkRuntime::Impl::Transmit(uint8_t* work, const PacketView& view, const WINDIVERT_ADDRESS& address, const FlowRoute& route,
    bool dirty, const Server& server, const TunnelRouteCache::Route& ready) {
    if (route.translatedIp) {Write32(work + 16, route.translatedIp); dirty = true;}
    dirty |= ClampMss(work, view, config->mss);
    dirty |= !address.IPChecksum || (view.tuple.protocol == 6 ? !address.TCPChecksum : !address.UDPChecksum);
    if (dirty) WinDivertHelperCalcChecksums(work, static_cast<UINT>(view.length), nullptr, 0);
    const auto& transport = server.transport;
    const auto port = std::uniform_int_distribution<uint16_t>(server.rules.portStart, server.rules.portEnd)(rng);
    transport->transform.Encrypt(work, view.length, port);
    static const auto addresses = [] {
        std::array<WINDIVERT_ADDRESS, 64> values{};
        for (auto& value : values) {value.Outbound = 1; value.IPChecksum = 1; value.UDPChecksum = 1;}
        return values;
    }();
    datagram.Build(work, view.length, ready.source, transport->destination,
        transport->localPort, port, ++packetId, ready.mtu,
        [&](const uint8_t* data, size_t size, size_t count) {return tunnel.Send(network, data, size, addresses.data(), count);});
    ++sentTunnel;
}

void NetworkRuntime::Impl::SendCaptured(uint8_t* bytes, const PacketView& view, const WINDIVERT_ADDRESS& address, const FlowRoute& route) {
    const auto* server = config->ById(route.serverId);
    if (route.kind != FlowRoute::Kind::Tunnel || !server) {Drop("route_server_unavailable"); return;}
    if (view.length > 65507) {Drop("tunnel_packet_too_large"); return;}
    auto ready = routes.find(route.serverId);
    if (ready != routes.end() && ready->second.source && ready->second.revision == windowsRoutes.Revision() &&
        !routePendingServers.count(route.serverId)) Transmit(bytes, view, address, route, false, *server, ready->second);
    else Send({buffers.Copy(bytes, view.length), address, view, Clock::now()}, route, false);
}

void NetworkRuntime::Impl::Inbound(uint8_t* bytes, size_t size, WINDIVERT_ADDRESS address, PacketView view) {
    const Server* remote = nullptr;
    if (view.tuple.protocol == 17) {
        const auto found = config->inboundPorts.find(view.tuple.remotePort);
        if (found != config->inboundPorts.end()) {
            const auto& server = config->servers[found->second];
            if (htonl(view.tuple.localIp) == server.transport->destination && view.tuple.localPort >= server.rules.portStart &&
                view.tuple.localPort <= server.rules.portEnd) remote = &server;
        }
    }
    if (!remote) {
        if (view.tuple.protocol == 17 && view.tuple.localPort == 53 && config->hasDomainRules) {
            Packet packet{buffers.Copy(bytes, view.length), address, view, Clock::now()};
            if (!classifierCommands.TryPush([this, packet = std::move(packet)]() mutable {
                auto active = published.load(); if (!active) return;
                dns.Response(std::move(packet), 0, *active, Clock::now());
            })) ++dnsObservationsLost;
        }
        flows.Inbound(view, address.Timestamp, 0, Clock::now());
        reinject.Send(network, bytes, size, &address, 1); ++sentDirect; return;
    }
    const auto length = Read16(bytes + view.header + 4) - 8;
    auto* inner = bytes + view.header + 8;
    if (length < 28) {Drop("invalid_tunnel_payload"); return;}
    remote->transport->transform.Decrypt(inner, length, view.tuple.localPort);
    PacketView decoded;
    if (!decoded.Read(inner, length)) {Drop("invalid_inner_packet"); return;}
    if (auto original = flows.Reverse(decoded.IncomingTuple(), remote->transport->id, address.Timestamp, Clock::now())) {
        Write32(inner + 12, *original); decoded.tuple.localIp = *original;
    }
    ClampMss(inner, decoded, config->mss);
    const auto serverId = remote->transport->id;
    if (decoded.tuple.protocol == 17 && decoded.tuple.localPort == 53) {
        Packet packet{buffers.Copy(inner, decoded.length), address, decoded, Clock::now()};
            if (!classifierCommands.TryPush([this, packet = std::move(packet), serverId]() mutable {
            auto active = published.load(); if (!active || !active->ById(serverId)) return;
            auto response = dns.Response(std::move(packet), serverId, *active, Clock::now());
            if (response) networkCommands.Push([this, packet = std::move(*response), serverId]() mutable {
                if (!config->ById(serverId)) return;
                flows.Inbound(packet.view, packet.address.Timestamp, serverId, Clock::now());
                Send(packet, {}, true);
            });
        })) Drop("dns_queue_full");
        return;
    }
    flows.Inbound(decoded, address.Timestamp, serverId, Clock::now());
    WinDivertHelperCalcChecksums(inner, static_cast<UINT>(decoded.length), &address, 0);
    reinject.Send(network, inner, decoded.length, &address, 1); ++sentDirect;
}

void NetworkRuntime::Impl::PacketReceived(uint8_t* bytes, size_t size, WINDIVERT_ADDRESS address) {
    ++captured;
    PacketView view;
    if (!view.Read(bytes, size)) {reinject.Send(network, bytes, size, &address, 1); return;}
    logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {return "packet_received" + Describe(view, address);});
    if (!address.Outbound) {Inbound(bytes, size, address, view); return;}
    if (Local(view.tuple.remoteIp)) {reinject.Send(network, bytes, size, &address, 1); ++sentDirect; return;}
    auto result = flows.Lookup(view, address.Timestamp, Clock::now());
    logger->logLazy(LOGGER_LEVEL_DEBUG, [&] {
        return std::string("route_lookup reason=") + result.reason + Describe(view, address) +
            " generation=" + std::to_string(result.generation) + " server_id=" + std::to_string(result.route.serverId);
    });
    const auto pending = waiting.find(FlowKey::From(view.tuple));
    const bool ordered = pending != waiting.end() && pending->second.readyGeneration == result.generation && result.generation;
    if (result.action == FlowTable::Action::Drop) {Drop(result.reason); return;}
    if (result.action == FlowTable::Action::Send && !ordered &&
        !(view.tuple.protocol == 17 && view.tuple.remotePort == 53)) {
        if (result.route.kind == FlowRoute::Kind::Direct) {
            reinject.Send(network, bytes, size, &address, 1); ++sentDirect;
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
    config = std::move(prepared->config); routes = std::move(prepared->routes);
    restartRules.emplace(); restartRules->reserve(config->servers.size());
    for (const auto& server : config->servers) restartRules->push_back(server.rules);
    restartMss = config->mss; restartLogLevel = config->logLevel;
    published.store(config);
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
            DrainReady(); ExpireWaiting();
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
    config = Prepare(restartRules ? *restartRules : initial->GetServers(),
        restartRules ? restartMss : initial->GetTunnelMaxMss(),
        restartRules ? restartLogLevel : initial->GetLogLevel(), {}, routes);
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
    classifierThread = std::thread([this] {Worker(classifierCommands);});
    windowsThread = std::thread([this] {Worker(windowsCommands);});
    maintenanceThread = std::thread([this] {try {Maintenance();} catch (...) {Error("maintenance_thread_failed", ERROR_NOT_ENOUGH_MEMORY); Halt();}});
    networkThread = std::thread([this] {
        try {NetworkLoop();} catch (...) {
            Error("network_thread_failed", ERROR_NOT_ENOUGH_MEMORY); Halt();
            tunnel.RequestStop(); reinject.RequestStop(); tunnel.Drain(); reinject.Drain();
        }
    });
    logger->log(LOGGER_LEVEL_INFO, "network_runtime_started");
    return true;
}

void NetworkRuntime::Impl::Stop() {
    const bool active = running.load() || network != INVALID_HANDLE_VALUE || socket != INVALID_HANDLE_VALUE;
    running.store(false);
    SetEvent(stop);
    networkCommands.Close(); classifierCommands.Close(); windowsCommands.Close(); socketCommands.Close();
    if (network != INVALID_HANDLE_VALUE) api.shutdown(network, WINDIVERT_SHUTDOWN_RECV);
    if (socket != INVALID_HANDLE_VALUE) api.shutdown(socket, WINDIVERT_SHUTDOWN_RECV);
    for (auto* thread : {&networkThread, &socketThread, &classifierThread, &windowsThread, &maintenanceThread})
        if (thread->joinable()) thread->join();
    if (active) {lastSummary = Clock::now() - std::chrono::seconds(5); Summary();}
    windowsRoutes.Stop();
    if (network != INVALID_HANDLE_VALUE) api.close(network);
    if (socket != INVALID_HANDLE_VALUE) api.close(socket);
    network = socket = INVALID_HANDLE_VALUE;
    networkCommands.Reset(); classifierCommands.Reset(); windowsCommands.Reset(); socketCommands.Reset();
    waiting.clear(); waitingPorts.clear(); waitingDeadlines.Clear(); pendingPackets = pendingBytes = 0;
    readyWaiting.clear(); classificationRetries.clear(); routePendingServers.clear(); routeRefreshPending.store(false); processes.Clear();
    routeResumeAt = (Clock::time_point::max)();
    dropSamples.clear();
    flows.Clear(); directory.Clear(); dns.Clear(); routes.clear(); routeCache.clear(); routeWaiting.clear(); routePendingBytes = 0; prepared.reset(); config.reset();
    published.store({});
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
        if (!windowsCommands.Push([this, servers = std::move(servers), mss, level, previous, completion] {
            Prepared next;
            next.config = Prepare(servers, mss, level, previous, next.routes); next.completion = completion;
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
