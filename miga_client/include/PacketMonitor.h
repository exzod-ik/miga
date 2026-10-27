#pragma once

#include <windivert.h>
#include <memory>
#include <mutex>
#include <array>
#include "BoundedQueue.h"
#include "EventQueueDelay.h"
#include "Ipv4Batch.h"
#include "RoutingState.h"
#include "PendingPackets.h"
#include "PacketWarning.h"
#include <future>
#include <shared_mutex>
#include <random>
#include "ConfigManager.h"
#include "Logger.h"
#include "Encryption.h"
#include "UdpPacketAssembler.h"

// Queue of pending packets (port -> list of packets)
struct PendingPacket {
    std::vector<uint8_t> packetData;
    const char* ownerLookup = "not_recorded";
    WINDIVERT_ADDRESS addr;
    std::chrono::steady_clock::time_point timestamp;
};

class PacketMonitor {
    friend struct PacketMonitorTests;
private:
    // runtime state of a single redirect server
    struct ServerContext {
        size_t configIndex = 0;
        size_t id = 0;
        ServerConfig transport;
        uint16_t localPort = 0;
        SOCKET udpSocket = INVALID_SOCKET;
        sockaddr_in serverAddr;
        std::unique_ptr<UdpPacketAssembler> assembler;
        Encryption encryption;
    };

    // global DNS query correspondence: dns query id -> server index
    std::unordered_map<uint16_t, size_t> m_ActualDns;
    std::unordered_map<uint16_t, size_t> m_AuxiliaryDns;
    // aux dns query id -> original dns query id
    std::unordered_map<uint16_t, uint16_t> m_ActualToAuxiliary;
    // dynamic ip correspondence: original ip -> (query id, server) -> translated ip
    // key: (uint64_t)original_ip << 32 | serverIndex
    std::unordered_map<uint64_t, uint32_t> m_DynamicIpMap;
    // aux translated ip -> original ip for reverse rewriting (inbound):
    // key: (uint64_t)translated_ip << 32 | serverIndex
    std::unordered_map<uint64_t, uint32_t> m_DynamicIpReverse;
    std::unordered_map<uint16_t, std::unordered_map<size_t, uint32_t>> m_PendingDynamicIp;
    // actual dns query id -> ip received from the actual server (may be 0 until received)
    std::unordered_map<uint16_t, uint32_t> m_ActualIpByQuery;
    // timestamps for cleanup: query id -> creation time
    std::unordered_map<uint16_t, std::chrono::steady_clock::time_point> m_DnsTimestamp;
    std::shared_mutex m_DnsMutex;

public:
    PacketMonitor(ConfigManager* config, Logger* logger);
    ~PacketMonitor();

    bool Start();
    void Stop();
    bool ReloadConfig(const std::string& path);
    bool IsRunning() const { return m_Running.load(); }

private:
    RoutingState m_Routing;
    PendingPackets<PendingPacket> m_Pending;
    std::vector<uint8_t> m_OutgoingPacket;
    ProcessIdentityCache m_ProcessNames;
    size_t m_NextServerId = 1;
    std::array<PacketWarningSample, 32> m_WarningSamples{};
    size_t m_WarningSampleCount = 0;
    size_t m_OmittedWarnings = 0;
    std::mt19937 m_rng;
    std::mutex m_RngMutex;

    std::vector<ServerContext> m_Servers;
    uint32_t m_ourPid;

    ConfigManager* m_Config;
    Logger* m_Logger;

    // WinDivert
    HANDLE m_Socket;
    HANDLE m_Network;

    std::thread m_SocketThread;
    std::thread m_EventProcessThread;
    std::thread m_NetworkThread;


    struct NetworkBatch {
        std::vector<uint8_t> data = std::vector<uint8_t>(256 * 1024);
        std::chrono::steady_clock::time_point receivedAt;
        std::array<WINDIVERT_ADDRESS, 64> addresses;

        UINT length = 0;
        UINT addressLength = 0;
    };
    struct WorkItem {
        std::chrono::steady_clock::time_point queuedAt;
        std::unique_ptr<NetworkBatch> batch;
        WINDIVERT_ADDRESS socket{};
        std::shared_ptr<const SocketOwner> owner;
        std::string reloadPath;
        std::shared_ptr<std::promise<bool>> reload;
    };
    BoundedQueue<WorkItem, 256> m_Work;
    EventQueueDelay m_EventQueueDelay;
    static constexpr size_t NetworkBufferCount = 34;
    BoundedQueue<std::unique_ptr<NetworkBatch>, NetworkBufferCount> m_FreeNetworkBatches;

    std::atomic<bool> m_Running;
    std::mutex m_StopMutex;
    std::condition_variable m_StopCondition;


    bool InitUdpSocket(const std::vector<ServerConfig>& servers);
    void CloseUdpSockets();


    bool OpenSocketHandle();
    bool OpenNetworkHandle();

    void SocketThread();
    void EventProcessThread();
    void NetworkThread();
    void ProcessNetworkPacket(uint8_t* packet, UINT packetLen, WINDIVERT_ADDRESS addr);
    void ProcessSocketEvent(const WorkItem& item);
    bool ResolvePacket(const uint8_t* packet, UINT length, const WINDIVERT_ADDRESS& addr, bool deadline,
        std::chrono::steady_clock::time_point receivedAt);
    void DrainPending(uint32_t key = 0);
    void MaintainState();
    void RecordPacketWarning(const uint8_t* packet, UINT length, const char* reason,
        std::chrono::steady_clock::time_point receivedAt, bool dropped, int64_t packetTimestampQpc);
    void SendRoute(const uint8_t* packet, UINT length, const WINDIVERT_ADDRESS& addr, const FlowRoute& route);
    void ClearDnsState();
    void SeedExistingSockets();
    bool SendUdpPacketToMstcp(const UdpPacketInfo* pkt, WINDIVERT_ADDRESS* pAddr, ServerContext& server);

    void ProcessPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, const std::shared_ptr<const SocketOwner>& owner);
    void RedirectPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, ServerContext& server,
        uint32_t newDstIp = 0, uint16_t dnsQueryIdOverride = 0);

    // DNS parsing helpers
    bool ExtractDomainFromDNSQuery(const uint8_t* payload, size_t len, std::string& domain);
    bool ExtractFirstARecord(const uint8_t* payload, size_t len, uint32_t& ipOut);
    void ProcessDNSResponse(const uint8_t* payload, size_t len, size_t serverIndex);
    bool IsDNSQuery(const uint8_t* payload, size_t len);
    bool IsDNSResponse(const uint8_t* payload, size_t len);
    void AddIPsFromDNSResponse(const uint8_t* payload, size_t len);

    // global DNS correspondence helpers
    uint16_t GenerateUniqueQueryId();
    bool HandleDNSResponse(const uint8_t* payload, size_t len, size_t serverIndex, uint16_t queryId);
    bool LookupIpTranslation(uint32_t originalIp, size_t serverIndex, uint32_t& translatedIp);
    bool LookupIpReverse(uint32_t translatedIp, size_t serverIndex, uint32_t& originalIp);
    void CleanupDnsState();

    ProcessOwner GetProcessByPid(DWORD pid);

    ServerContext* FindServerContext(const ServerConfig* config);
    const ServerConfig* FindServerByProcessRule(const std::string& processName) const;
    void RedirectDNSQuery(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr,
        ServerContext* actual, uint16_t queryId, const std::string& reason);
    const ServerConfig* CheckRules(const std::string& processName, UINT32 destIp);
};
