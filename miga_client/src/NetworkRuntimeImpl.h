#pragma once

#include "NetworkRuntime.h"
#include "DiagnosticSession.h"
#include "ProtocolProfiles.h"
#include "ProtocolV2Packets.h"
#include "runtime/FlowTable.h"
#include "runtime/DnsClassifier.h"
#include "runtime/SyntheticDnsResolver.h"
#include "runtime/RuntimeMailbox.h"
#include "AsyncTunnelSender.h"
#include "TunnelDatagram.h"
#include "WindowsProcessIdentity.h"
#include "Ipv4Batch.h"
#include "runtime/WindowsSnapshot.h"
#include <future>
#include <thread>
#include <string_view>

using namespace miga::runtime;

struct NetworkRuntime::Impl {
    struct DriverApi {
        decltype(&WinDivertRecvEx) receive = &WinDivertRecvEx;
        decltype(&GetOverlappedResult) result = &GetOverlappedResult;
        decltype(&CancelIoEx) cancel = &CancelIoEx;
        decltype(&WinDivertOpen) open = &WinDivertOpen;
        decltype(&WinDivertClose) close = &WinDivertClose;
        decltype(&WinDivertShutdown) shutdown = &WinDivertShutdown;
    } api;
    struct Receive {
        std::vector<uint8_t> data = std::vector<uint8_t>(256 * 1024);
        std::array<WINDIVERT_ADDRESS, 64> addresses{};
        OVERLAPPED operation{};
        UINT length = 0, addressLength = 0;
        bool pending = false, ready = false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        DriverApi* api = nullptr;
        Receive();
        ~Receive();
    };
    struct Waiting {
        std::deque<Packet> packets;
        uint64_t request = 0;
        bool outstanding = false;
        uint64_t readyGeneration = 0;
        bool readyQueued = false;
        bool retryQueued = false;
    };
    struct Prepared {
        std::shared_ptr<Configuration> config;
        std::unordered_map<size_t, TunnelRouteCache::Route> routes;
        std::shared_ptr<std::promise<bool>> completion;
    };
    DiagnosticSession diagnostics;
    ProtocolProfiles profiles;
    struct SessionWaiting { Packet packet; FlowRoute route; bool dirty; };
    std::deque<SessionWaiting> sessionWaiting;
    size_t sessionWaitingBytes = 0;
    miga::v2::Bytes decryptedV2, reassembledV2;
    miga::v2::Ipv4Reassembler reassembler, innerReassembler;
    miga::v2::Bytes innerReassembled;
    void DrainSessions();
    ConfigManager* initial;
    Logger* logger;
    std::atomic<bool> running{false};
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE network = INVALID_HANDLE_VALUE, socket = INVALID_HANDLE_VALUE;
    std::thread networkThread, socketThread, classifierThread, windowsThread, maintenanceThread;
    Mailbox<std::function<void()>, 2048> networkCommands;
    Mailbox<std::function<void()>, 1024> classifierCommands;
    Mailbox<std::function<void()>, 128> windowsCommands, socketCommands;
    SocketDirectory directory;
    FlowTable flows{directory};
    ProcessIdentityCache processes;
    PacketBufferPool buffers;
    AsyncTunnelSender reinject, tunnel;
    TunnelDatagram datagram;
    TunnelRouteCache windowsRoutes;
    std::atomic<std::shared_ptr<const Configuration>> published;
    std::shared_ptr<Configuration> config;
    std::optional<Prepared> prepared;
    std::optional<std::vector<ServerConfig>> restartRules;
    uint16_t restartMss = 1400;
    std::string restartFullRoutingProfileId;
    bool restartDnsResolverEnabled = false;
    std::atomic<std::shared_ptr<const std::vector<std::weak_ptr<miga::v2::ProtocolV2Session>>>> preparingSessions;
    std::atomic<uint64_t> bootstrapDnsTuple{0};
    int restartLogLevel = LOGGER_LEVEL_WARNING;
    DnsClassifier dns;
    SyntheticDnsResolver syntheticDns;
    std::unordered_map<size_t, TunnelRouteCache::Route> routes, routeCache;
    std::unordered_map<FlowKey, Waiting, FlowKeyHash> waiting;
    std::unordered_multimap<uint32_t, FlowKey> waitingPorts;
    DeadlineIndex<FlowKey, FlowKeyHash> waitingDeadlines;
    size_t pendingPackets = 0, pendingBytes = 0;
    struct RouteWait { Packet packet; FlowRoute route; bool dirty; Clock::time_point expires; };
    std::deque<RouteWait> routeWaiting;
    Clock::time_point routeResumeAt = (Clock::time_point::max)();
    size_t routePendingBytes = 0;
    std::unordered_map<size_t, size_t> routePendingServers;
    std::deque<FlowKey> readyWaiting;
    std::deque<FlowKey> classificationRetries;
    std::atomic<bool> routeRefreshPending{false};
    uint64_t nextRequest = 0, nextConfiguration = 0;
    size_t nextServer = 0;
    uint16_t packetId = 0;
    bool winsock = false;
    DWORD ownPid = GetCurrentProcessId();
    std::atomic<uint64_t> captured{0}, sentDirect{0}, sentTunnel{0}, deferred{0}, dropped{0};
    struct DropSample {uint64_t count = 0; std::chrono::system_clock::time_point first;};
    std::unordered_map<std::string_view, DropSample> dropSamples;
    uint64_t dnsObservationsLost = 0;
    Clock::time_point lastSummary = Clock::now();
    Impl(ConfigManager* source, Logger* output);
    ~Impl();

    void Error(const char* event, DWORD code);
    void ReceiveError(const char* event);
    static std::string Ip(uint32_t ip);
    static std::string Describe(const SocketTuple& tuple);
    static std::string Describe(const PacketView& packet, const WINDIVERT_ADDRESS& address);
    void Halt();
    void SeedSockets();
    void ConfigureProbes();
    void Drop(const char* reason);
    static uint64_t BootstrapDnsKey(const SocketTuple& tuple);
    static std::optional<uint32_t> BootstrapHosts(std::string_view contents, std::string_view name);
    std::optional<uint32_t> ResolveBootstrapHostname(std::string_view name);
    std::shared_ptr<Configuration> Prepare(const std::vector<ServerConfig>& servers, uint16_t mss, int level,
        const std::string& fullRoutingProfileId, bool dnsResolverEnabled, uint32_t dnsResolverReservedThrough,
        const std::shared_ptr<const Configuration>& previous, std::unordered_map<size_t, TunnelRouteCache::Route>& ready);
    DWORD DnsWait();
    void Worker(auto& mailbox, DWORD (Impl::*nextWait)() = nullptr) {
        HANDLE events[]{stop, mailbox.Event()};
        while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) {
            std::function<void()> action;
            size_t budget = 32;
            while (budget-- && mailbox.Pop(action)) {
                try { action(); } catch (...) { Error("runtime_task_failed", ERROR_NOT_ENOUGH_MEMORY); }
                action = {};
                if (WaitForSingleObject(stop, 0) != WAIT_TIMEOUT) return;
            }
            DWORD timeout = INFINITE;
            if (nextWait) {
                try { timeout = (this->*nextWait)(); }
                catch (...) { Error("runtime_task_failed", ERROR_NOT_ENOUGH_MEMORY); timeout = 100; }
            }
            WaitForMultipleObjects(2, events, FALSE, timeout);
        }
    }
    void RefreshRoutes();
    void ApplyRoutes(const Configuration& current, std::unordered_map<size_t, TunnelRouteCache::Route> updates);
    void QueueRouteRefresh();
    void Maintenance();
    void Summary();
    void SocketLoop();
    void RetryPort(uint32_t port);
    void Request(const FlowKey& key);
    void RemoveWaiting(const FlowKey& key);
    Packet Take(Waiting& group);
    void Classified(const FlowKey& key, const RouteDecision& decision, bool dnsQuery,
        std::vector<DnsClassifier::Output> output, const std::string& processName);
    void ScheduleReady(const FlowKey& key, Waiting& group);
    void DrainReady();
    void Defer(const uint8_t* bytes, size_t size, const WINDIVERT_ADDRESS& address, const PacketView& view);
    void ExpireWaiting();
    void ResumeRoutes();
    void Send(const Packet& packet, const FlowRoute& route, bool dirty, bool resumed = false);
    void Transmit(uint8_t* work, const PacketView& view, const WINDIVERT_ADDRESS& address, const FlowRoute& route,
        bool dirty, const Server& server, const TunnelRouteCache::Route& ready);
    void SendCaptured(uint8_t* bytes, const PacketView& view, const WINDIVERT_ADDRESS& address, const FlowRoute& route);
    void Inbound(uint8_t* bytes, size_t size, WINDIVERT_ADDRESS address, PacketView view);
    void PacketReceived(uint8_t* bytes, size_t size, WINDIVERT_ADDRESS address);
    void Outbound(uint8_t* bytes, WINDIVERT_ADDRESS address, const PacketView& view, bool allowSyntheticDns);
    void SyntheticResponse(uint8_t* bytes, const WINDIVERT_ADDRESS& address, const PacketView& view, size_t server);
    void RetrySynthetic(uint32_t ip);
    bool SyntheticAddress(uint32_t ip) const {
        return SyntheticDnsResolver::Contains(*config, ip);
    }
    bool Issue(Receive& receive);
    void ApplyPrepared();
    void NetworkLoop();
    bool Start();
    void Stop();
    bool Reload(const std::string& path);
};
