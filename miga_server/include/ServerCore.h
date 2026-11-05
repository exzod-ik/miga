#pragma once

#include "Logger.h"
#include "Encryption.h"
#include <thread>
#include <atomic>
#include <vector>
#include <tuple>
#include <unordered_map>
#include <mutex>
#include <random>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <memory>
#include <deque>
#include "TcpConnectionState.h"
#include "PortPool.h"
#include "ConnectionKey.h"
#include "InterfaceIpCache.h"

#define SRC_PORT_START 1000
#define SRC_PORT_END 65535
struct ServerConfig {
    uint16_t client_port_start = 10000;
    uint16_t client_port_end = 15000;
    std::string xorKeyBase64;
    std::string swapKeyBase64;
    std::string interface = "";
    int log_level = LOGGER_LEVEL_NONE;
    uint32_t dns_server = 0x08080808; // 8.8.8.8
};

struct ClientInfo {
    uint32_t client_ip;
    uint16_t client_udp_port;
    uint16_t local_udp_port;
    uint32_t original_src_ip;
    uint16_t original_src_port;
    uint32_t original_dst_ip;
    uint32_t remote_ip;
    uint16_t remote_port;
    TcpConnectionState tcpState;
    std::chrono::steady_clock::time_point last_used;
};

struct PortInfo {
    uint16_t port; // chosen_src_port
};

class ServerCore {
    friend struct ServerPacketPathTest;
private:
    int m_socket;
    int m_tunfd;

    Logger m_logger;
    Encryption m_encryption;
    std::thread m_processPacketsThread;
    std::thread m_processTunThread;
    std::thread m_cleanupThread;
    std::thread m_firewallThread;
    std::atomic<bool> m_running;
    ServerConfig m_config;

    std::mt19937 m_rng;
    PortPool m_tcpPorts{SRC_PORT_START, SRC_PORT_END};
    PortPool m_udpPorts{SRC_PORT_START, SRC_PORT_END};

    std::vector<std::unique_ptr<ClientInfo>> m_tcpRoutes{65536};
    std::vector<std::unique_ptr<ClientInfo>> m_udpRoutes{65536};
    std::deque<uint32_t> m_cleanupKeys;
    std::mutex m_tableMutex;

    // orig src ip, orig src port, orig dst ip, orig dst port, orig proto
    std::unordered_map<ConnectionKey, PortInfo, ConnectionKeyHash> m_connPortMap;
    std::mutex m_connMutex;

    bool InitSocket();
    bool CreateTUN(const char* dev_name);
    void ProcessPackets();
    void ProcessTUN();
    void HandleClientPacket(uint8_t* packet, size_t length);
    void ProcessClientUdpPacket(uint8_t* origIpPacket, size_t origIpLen, uint32_t client_ip, uint16_t client_udp_port, uint16_t local_udp_port);
    bool ValidateInnerIpPacket(const uint8_t* packet, size_t len, struct iphdr*& outIp, size_t& outIpHeaderLen);
    void HandleInternetPacket(uint8_t* ipPacket, size_t ipLen);
    InterfaceIpCache m_interfaceIp;
    void SendPacket(const uint8_t* packet, size_t len);
    void CleanupLoop();
    bool EnsureFirewallRules();
    void FirewallWatchdogLoop();

public:
    ServerCore();
    ~ServerCore();

    bool Initialize(const std::string& configPath);
    void Start();
    void Stop();
};
