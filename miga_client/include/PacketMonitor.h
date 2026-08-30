#pragma once

#include <windivert.h>
#include <memory>
#include <shared_mutex>
#include <random>
#include "ConfigManager.h"
#include "Logger.h"
#include "Encryption.h"
#include "UdpPacketAssembler.h"

// entry for pid-port cache
struct CacheEntry {
    uint32_t pid;
    std::chrono::steady_clock::time_point lastSeen;
};

// Queue of pending packets (port -> list of packets)
struct PendingPacket {
    std::vector<uint8_t> packetData;
    WINDIVERT_ADDRESS addr;
    std::chrono::steady_clock::time_point timestamp;
};

// key identifying a single tcp/udp flow (host byte order)
struct FlowKey {
    uint8_t proto;
    uint32_t srcIp;
    uint16_t srcPort;
    uint32_t dstIp;
    uint16_t dstPort;

    bool operator==(const FlowKey& o) const {
        return proto == o.proto && srcIp == o.srcIp && srcPort == o.srcPort &&
            dstIp == o.dstIp && dstPort == o.dstPort;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        size_t h = std::hash<uint8_t>()(k.proto);
        h ^= std::hash<uint32_t>()(k.srcIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>()(k.srcPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>()(k.dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>()(k.dstPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// a flow we decided to tunnel: continuation packets keep being redirected
// even if the volatile per-port pid cache entry is lost mid-connection
struct RedirectedFlow {
    size_t serverIndex;
    uint32_t translatedDstIp; // 0 if identity
    std::chrono::steady_clock::time_point lastSeen;
};

class PacketMonitor {
private:
    // runtime state of a single redirect server
    struct ServerContext {
        size_t configIndex;          // index in ConfigManager::GetServers()
        SOCKET udpSocket;
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
    // pending aux ip (original ip not yet known): (query_id << 32) | serverIndex -> translated ip
    std::unordered_map<uint64_t, uint32_t> m_PendingDynamicIp;
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
    bool IsRunning() const { return m_Running.load(); }

private:
    std::unordered_map<uint16_t, CacheEntry> tcpCache;
    std::unordered_map<uint16_t, CacheEntry> udpCache;
    std::shared_mutex cacheMutex;

    std::unordered_map<uint16_t, std::vector<PendingPacket>> pendingTCP;
    std::unordered_map<uint16_t, std::vector<PendingPacket>> pendingUDP;
    std::shared_mutex pendingMutex;

    // flows already tunneled: flow key -> target server (kept alive while active)
    std::unordered_map<FlowKey, RedirectedFlow, FlowKeyHash> m_RedirectedFlows;
    std::shared_mutex m_FlowMutex;

    std::mt19937 m_rng;

    std::vector<ServerContext> m_Servers;
    uint32_t m_ourPid;

    ConfigManager* m_Config;
    Logger* m_Logger;

    // WinDivert
    HANDLE m_Socket;
    HANDLE m_Network;

    std::thread m_SocketThread;
    std::thread m_NetworkThread;
    std::thread m_CleanupThread;

    std::atomic<bool> m_Running;

    bool InitWinDivert();
    bool InitUdpSocket();
    void CloseUdpSockets();
    void CleanupWinDivert();

    bool OpenSocketHandle();
    bool OpenNetworkHandle();

    void UpdateCache(uint16_t port, uint32_t pid, bool isTCP);

    void SocketThread();
    void NetworkThread();
    void CacheCleanupThread();

    bool SendUdpPacketToMstcp(const UdpPacketInfo* pkt, WINDIVERT_ADDRESS* pAddr, ServerContext& server);

    void ProcessPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, uint32_t pid);
    void RedirectPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, ServerContext& server,
        uint32_t newDstIp = 0, uint16_t dnsQueryIdOverride = 0);

    // helpers for tunneled-flow tracking
    void RememberRedirectedFlow(const FlowKey& key, size_t serverIndex, uint32_t translatedDstIp);
    bool FindRedirectedFlow(const FlowKey& key, size_t& serverIndex, uint32_t& translatedDstIp);

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

    std::string GetProcessNameByPid(DWORD pid);

    ServerContext* FindServerContext(const ServerConfig* config);
    const ServerConfig* FindServerByProcessRule(const std::string& processName) const;
    void RedirectDNSQuery(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr,
        ServerContext* actual, uint16_t queryId, const std::string& reason);
    const ServerConfig* CheckRules(const std::string& processName, UINT32 destIp);
};