#pragma once

#include <windivert.h>
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

class PacketMonitor {
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

    std::mt19937 m_rng;
    std::uniform_int_distribution<uint16_t> m_portDist;

    SOCKET m_udpSocket;
    sockaddr_in m_serverAddr;
    UdpPacketAssembler m_assembler;
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

    Encryption m_Encryption;

    bool InitWinDivert();
    bool InitUdpSocket();
    void CleanupWinDivert();

    bool OpenSocketHandle();
    bool OpenNetworkHandle();

    void UpdateCache(uint16_t port, uint32_t pid, bool isTCP);

    void SocketThread();
    void NetworkThread();
    void CacheCleanupThread();

    bool SendUdpPacketToMstcp(const UdpPacketInfo* pkt, WINDIVERT_ADDRESS* pAddr);

    void ProcessPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, uint32_t pid);
    void RedirectPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr);

    // DNS parsing helpers
    bool ExtractDomainFromDNSQuery(const uint8_t* payload, size_t len, std::string& domain);
    void ProcessDNSResponse(const uint8_t* payload, size_t len);
    bool IsDNSQuery(const uint8_t* payload, size_t len);
    bool IsDNSResponse(const uint8_t* payload, size_t len);
    void AddIPsFromDNSResponse(const uint8_t* payload, size_t len);

    std::string GetProcessNameByPid(DWORD pid);
    bool CheckRules(const std::string& processName, UINT32 destIp);
};