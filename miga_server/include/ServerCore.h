#pragma once

#include "Logger.h"
#include "Encryption.h"
#include <thread>
#include <atomic>
#include <vector>
#include <map>
#include <mutex>
#include <random>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "UdpPacketAssembler.h"

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
    std::chrono::steady_clock::time_point last_used;
};

struct PortInfo {
    uint16_t port; // chosen_src_port
    std::chrono::steady_clock::time_point last_used;
};

class ServerCore {
private:
    int m_socket;
    int m_tunfd;
    std::vector<uint8_t> m_recvBuffer;
    Logger m_logger;
    Encryption m_encryption;
    std::thread m_processPacketsThread;
    std::thread m_processTunThread;
    std::thread m_cleanupThread;
    std::atomic<bool> m_running;
    ServerConfig m_config;
    UdpPacketAssembler m_assembler;

    std::mt19937 m_rng;
    std::uniform_int_distribution<uint16_t> m_portDist;

    std::map<std::tuple<uint16_t, uint8_t>, ClientInfo> m_forwardTable;
    std::mutex m_tableMutex;

    // orig src ip, orig src port, orig dst ip, orig dst port, orig proto
    std::map<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t, uint8_t>, PortInfo> m_connPortMap;
    std::mutex m_connMutex;

    bool InitSocket();
    bool CreateTUN(const char* dev_name);
    void ProcessPackets();
    void ProcessTUN();
    void HandleClientPacket(const uint8_t* ipPacket, size_t ipLen, uint16_t dstPort);
    void ProcessClientUdpPacket(UdpPacketInfo* pkt);
    bool ValidateInnerIpPacket(const uint8_t* packet, size_t len, struct iphdr*& outIp, size_t& outIpHeaderLen);
    void HandleInternetPacket(const uint8_t* ipPacket, size_t ipLen, uint16_t dstPort);
    uint32_t GetInterfaceIP();
    void SendPacket(const uint8_t* packet, size_t len);
    void CleanupLoop();

public:
    ServerCore();
    ~ServerCore();

    bool Initialize(const std::string& configPath);
    void Start();
    void Stop();
};