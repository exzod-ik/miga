#include <ws2tcpip.h>
#include <psapi.h>
#include "PacketMonitor.h"

using namespace std;

#pragma comment(lib, "WinDivert.lib")

// check tcp flags for debuging by flags value
string tcpFlags(uint16_t flags) {
    const uint8_t FIN = 0x01;
    const uint8_t SYN = 0x02;
    const uint8_t RST = 0x04;
    const uint8_t PSH = 0x08;
    const uint8_t ACK = 0x10;
    const uint8_t URG = 0x20;
    const uint8_t ECE = 0x40;
    const uint8_t CWR = 0x80;

    vector<string> active_flags;

    if (flags & FIN) active_flags.push_back("FIN");
    if (flags & SYN) active_flags.push_back("SYN");
    if (flags & RST) active_flags.push_back("RST");
    if (flags & PSH) active_flags.push_back("PSH");
    if (flags & ACK) active_flags.push_back("ACK");
    if (flags & URG) active_flags.push_back("URG");
    if (flags & ECE) active_flags.push_back("ECE");
    if (flags & CWR) active_flags.push_back("CWR");

    if (active_flags.empty()) {
        return "NONE";
    }

    string result;
    for (size_t i = 0; i < active_flags.size(); ++i) {
        if (i != 0) result += '-';
        result += active_flags[i];
    }
    return result;
}

// check tcp flags for debuging by windivert header
string tcpFlagsWinDivert(WINDIVERT_TCPHDR* tcpHdr) {

    vector<string> active_flags;

    if (tcpHdr->Fin) active_flags.push_back("FIN");
    if (tcpHdr->Syn) active_flags.push_back("SYN");
    if (tcpHdr->Rst) active_flags.push_back("RST");
    if (tcpHdr->Psh) active_flags.push_back("PSH");
    if (tcpHdr->Ack) active_flags.push_back("ACK");
    if (tcpHdr->Urg) active_flags.push_back("URG");

    if (active_flags.empty()) {
        return "NONE";
    }

    string result;
    for (size_t i = 0; i < active_flags.size(); ++i) {
        if (i != 0) result += '-';
        result += active_flags[i];
    }
    return result;
}

bool iequals(const string& a, const string& b) {
    return equal(a.begin(), a.end(), b.begin(), b.end(),
        [](char ca, char cb) {
            return tolower(static_cast<unsigned char>(ca)) ==
                tolower(static_cast<unsigned char>(cb));
        });
}

string IpToString(UINT32 ip) {
    stringstream ss;
    ss << ((ip >> 0) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "." << ((ip >> 24) & 0xFF);
    return ss.str();
}

// check for local net
bool IsLocalIPv4(uint32_t ipHost) {
    // loopback (127.0.0.0/8)
    if ((ipHost & 0xFF000000) == 0x7F000000)
        return true;

    // private ranges:
    // 10.0.0.0/8
    if ((ipHost & 0xFF000000) == 0x0A000000)
        return true;
    // 172.16.0.0/12
    if ((ipHost & 0xFFF00000) == 0xAC100000)
        return true;
    // 192.168.0.0/16
    if ((ipHost & 0xFFFF0000) == 0xC0A80000)
        return true;

    // link-local (169.254.0.0/16)
    if ((ipHost & 0xFFFF0000) == 0xA9FE0000)
        return true;

    // multicast (224.0.0.0/4)
    if ((ipHost & 0xF0000000) == 0xE0000000)
        return true;

    // broadcast (255.255.255.255)
    if (ipHost == 0xFFFFFFFF)
        return true;

    return false;
}

// open windivert socket layer to get process of packets
bool PacketMonitor::OpenSocketHandle() {
    m_Socket = WinDivertOpen("protocol == 6 or protocol == 17", WINDIVERT_LAYER_SOCKET, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (m_Socket == INVALID_HANDLE_VALUE) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to open Socket layer: " + to_string(GetLastError()));
        return false;
    }
    if (!WinDivertSetParam(m_Socket, WINDIVERT_PARAM_QUEUE_TIME, 50)) {
        m_Logger->log(LOGGER_LEVEL_INFO, "Failed to set queue time for Socket layer");
    }
    return true;
}

// open windivert network layer to snif packets
bool PacketMonitor::OpenNetworkHandle() {
    const char* filter = "ip and (tcp or udp)"; // the filter must be different from the socket layer, otherwise the winddivert freezes
    m_Network = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (m_Network == INVALID_HANDLE_VALUE) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to open Network layer: " + to_string(GetLastError()));
        return false;
    }
    if (!WinDivertSetParam(m_Network, WINDIVERT_PARAM_QUEUE_TIME, 50)) {
        m_Logger->log(LOGGER_LEVEL_INFO, "Failed to set queue time for Network layer");
    }
    return true;
}

// updating cache of process's ports. If can found process of the port - update last time enabled.
void PacketMonitor::UpdateCache(uint16_t port, uint32_t pid, bool isTCP) {
    unique_lock lock(cacheMutex);
    auto& cache = isTCP ? tcpCache : udpCache;
    auto it = cache.find(port);
    if (it != cache.end() && it->second.pid == pid) {
        it->second.lastSeen = chrono::steady_clock::now();
    }
    else if (it != cache.end() && pid == 4) { // SYSTEM overide
        if (m_Logger->isEnabled())
            m_Logger->log(LOGGER_LEVEL_DEBUG, "UpdateCache: ignoring SYSTEM event for port " + to_string(port) + " (already owned by PID " + to_string(it->second.pid) + ")");
        return;
    }
    else {
        cache[port] = { pid, chrono::steady_clock::now() };
    }
}

// thread to listen socket layer
void PacketMonitor::SocketThread() {
    WINDIVERT_ADDRESS addr;
    UINT packetLen;

    while (m_Running.load()) {
        if (!WinDivertRecv(m_Socket, NULL, 0, &packetLen, &addr)) {
            if (GetLastError() == ERROR_OPERATION_ABORTED) break;
            continue;
        }

        switch (addr.Event) {
        // received bind (for udp) or connect (for tcp) event
        case WINDIVERT_EVENT_SOCKET_BIND:
        case WINDIVERT_EVENT_SOCKET_CONNECT:
        {
            uint32_t pid = addr.Socket.ProcessId;
            uint16_t localPort = addr.Socket.LocalPort;
            uint8_t protocol = addr.Socket.Protocol;

            bool isTCP = (protocol == IPPROTO_TCP);
            if (addr.Socket.ProcessId != 4 && m_Logger->isEnabled()) { // pid 4 - SYSTEM - ignoring
                string eventType;
                switch (addr.Event) {
                case WINDIVERT_EVENT_SOCKET_BIND:
                    eventType = "BIND";
                    break;
                case WINDIVERT_EVENT_SOCKET_CONNECT:
                    eventType = "CONNECT";
                    break;
                default:
                    eventType = "UNKNOWN";
                }
                m_Logger->log(LOGGER_LEVEL_DEBUG, "SocketThread " + eventType + " event received: process=" + GetProcessNameByPid(addr.Socket.ProcessId) + ", proto=" + (isTCP ? "TCP" : "UDP") + " local=" + IpToString(*addr.Socket.LocalAddr) + ":" + to_string(localPort));
            }

            UpdateCache(localPort, pid, isTCP);

            // check if there are any pending packets for this port
            unique_lock pendingLock(pendingMutex);
            auto& pendingMap = isTCP ? pendingTCP : pendingUDP;
            auto it = pendingMap.find(localPort);
            if (it != pendingMap.end()) {
                for (const auto& pkt : it->second) {
                    ProcessPacket(pkt.packetData.data(), pkt.packetData.size(), pkt.addr, pid);
                }
                pendingMap.erase(it);
            }
            break;
        }

        // received close tcp connection - clear cache
        case WINDIVERT_EVENT_SOCKET_CLOSE:
        {
            uint16_t localPort = addr.Socket.LocalPort;
            uint8_t protocol = addr.Socket.Protocol;
            bool isTCP = (protocol == IPPROTO_TCP);
            unique_lock lock(cacheMutex);
            auto& cache = isTCP ? tcpCache : udpCache;
            cache.erase(localPort);
            break;
        }
        }
    }
}

// thread to listen network layer
void PacketMonitor::NetworkThread() {

#define NETWORK_BUFFER_SIZE 0xFFFF

    vector<uint8_t> buffer(NETWORK_BUFFER_SIZE);
    WINDIVERT_ADDRESS addr;
    UINT packetLen;

    while (m_Running.load()) {
        if (!WinDivertRecv(m_Network, buffer.data(), buffer.size(), &packetLen, &addr)) {
            if (GetLastError() == ERROR_OPERATION_ABORTED) break;
            continue;
        }

        WINDIVERT_IPHDR* ipHdr = nullptr;
        WINDIVERT_IPV6HDR* ipv6Hdr = nullptr;
        uint8_t protocol = 0;
        WINDIVERT_TCPHDR* tcpHdr = nullptr;
        WINDIVERT_UDPHDR* udpHdr = nullptr;
        void* payload = nullptr;
        uint32_t payloadLen = 0;

        if (!WinDivertHelperParsePacket(buffer.data(), packetLen,
            &ipHdr, &ipv6Hdr, &protocol,
            nullptr, nullptr,
            &tcpHdr, &udpHdr,
            &payload, &payloadLen,
            nullptr, nullptr)) {
            WinDivertSend(m_Network, buffer.data(), packetLen, nullptr, &addr);
            continue;
        }

        // ipv6 not support right now
        if (!ipHdr) {
            WinDivertSend(m_Network, buffer.data(), packetLen, nullptr, &addr);
            continue;
        }

        bool isTCP = (protocol == IPPROTO_TCP);
        bool isUDP = (protocol == IPPROTO_UDP);
        bool outbound = (addr.Outbound != 0);

        uint16_t localPort = 0;
        if (isTCP && tcpHdr) {
            localPort = outbound ? ntohs(tcpHdr->SrcPort) : ntohs(tcpHdr->DstPort);
        }
        else if (isUDP && udpHdr) {
            localPort = outbound ? ntohs(udpHdr->SrcPort) : ntohs(udpHdr->DstPort);
        }
        else {
            // not support anything else protocol
            WinDivertSend(m_Network, buffer.data(), packetLen, nullptr, &addr);
            continue;
        }

        if (m_Logger->isEnabled()) {
            string localAddr, remoteAddr, tcpFlagsInfo;
            uint16_t remotePort = 0;
            if (outbound) {
                localAddr = IpToString(ipHdr->SrcAddr);
                remoteAddr = IpToString(ipHdr->DstAddr);
                remotePort = isTCP ? ntohs(tcpHdr->DstPort) : ntohs(udpHdr->DstPort);
            }
            else {
                remoteAddr = IpToString(ipHdr->SrcAddr);
                localAddr = IpToString(ipHdr->DstAddr);
                remotePort = isTCP ? ntohs(tcpHdr->SrcPort) : ntohs(udpHdr->SrcPort);
            }

            if (isTCP && tcpHdr) {
                tcpFlagsInfo = tcpFlagsWinDivert(tcpHdr);
            }

            m_Logger->log(LOGGER_LEVEL_DEBUG, "NetworkThread event: " + string(isTCP ? "TCP" : isUDP ? "UDP" : "?") +
                " " + localAddr + ":" + to_string(localPort) + (outbound ? " -> " : " <- ")
                + remoteAddr + ":" + to_string(remotePort) + (isTCP ? " flags=" + tcpFlagsInfo : ""));
        }

        if (outbound) {
            uint32_t destIpHost = ntohl(ipHdr->DstAddr);
            if (IsLocalIPv4(destIpHost)) { // ignoring local and intranet packets
                if (m_Logger->isEnabled()) {
                    m_Logger->log(LOGGER_LEVEL_DEBUG, "Skipping local destination: " + IpToString(destIpHost));
                }
                WinDivertSend(m_Network, buffer.data(), packetLen, nullptr, &addr);
                continue;
            }

            // search pid by port and proto in cache
            uint32_t pid = 0;
            {
                unique_lock lock(cacheMutex);
                auto& cache = isTCP ? tcpCache : udpCache;
                auto it = cache.find(localPort);
                if (it != cache.end()) {
                    pid = it->second.pid;
                    it->second.lastSeen = chrono::steady_clock::now();
                }
            }

            if (m_Logger->isEnabled())
                m_Logger->log(LOGGER_LEVEL_DEBUG, "Looking for port " + to_string(localPort) + " in cache (isTCP=" + (isTCP ? "true" : "false") + ")");

            if (pid != 0) { // pid was found
                ProcessPacket(buffer.data(), packetLen, addr, pid);
            }
            else {
                m_Logger->log(LOGGER_LEVEL_DEBUG, "PID not found");
                // put packet to cache until socket event is occurs
                unique_lock lock(pendingMutex);
                auto& pendingMap = isTCP ? pendingTCP : pendingUDP;
                PendingPacket pkt;
                pkt.packetData.assign(buffer.data(), buffer.data() + packetLen);
                pkt.addr = addr;
                pkt.timestamp = chrono::steady_clock::now();
                pendingMap[localPort].push_back(move(pkt));
            }
        }
        else { // inbound
            if (!ipHdr) { // ignoring ipv6
                WinDivertSend(m_Network, buffer.data(), packetLen, nullptr, &addr);
                continue;
            }
            if (ipHdr->SrcAddr == m_serverAddr.sin_addr.s_addr && protocol == IPPROTO_UDP) {
                // ip-packet from miga server - adding fragment to udp assembler
                m_Logger->log(LOGGER_LEVEL_DEBUG, "Received packet from server.");
                if (m_assembler.AddIpPacket(reinterpret_cast<const uint8_t*>(buffer.data()), packetLen)) {
                    // we have at least 1 ready-made udp package - process it and release
                    UdpPacketInfo* pkt;
                    while ((pkt = m_assembler.GetCompleteUdpPacket()) != nullptr) {
                        SendUdpPacketToMstcp(pkt, &addr);
                        m_assembler.ReleaseUdpPacket(pkt);
                    }
                }
            }
            else // some inbound packet not fron server - ignoring
                WinDivertSend(m_Network, buffer.data(), packetLen, NULL, &addr);
        }
    }
}

// place the assembled udp-packet into tcp/ip stack
bool PacketMonitor::SendUdpPacketToMstcp(const UdpPacketInfo* pkt, WINDIVERT_ADDRESS* pAddr) {
    if (!pkt || !pAddr) return false;

    m_Logger->log(LOGGER_LEVEL_DEBUG, "Processing a full udp packet...");

    // decrypt payload - original tranmitted packet
    m_Encryption.Decrypt(pkt->payload, pkt->payloadSize, htons(pkt->srcPort));

    // recalc checksums (server don't do it)
    IP_HEADER* ip = reinterpret_cast<IP_HEADER*>(pkt->payload);
    WinDivertHelperCalcChecksums(pkt->payload, pkt->payloadSize, pAddr, 0);

    uint8_t* ipPayload = reinterpret_cast<uint8_t*>(ip + 1);

    if (m_Logger->isEnabled()) {
        string proto, flags;
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;
        string srcIp = IpToString(ip->src_ip);
        string dstIp = IpToString(ip->dst_ip);

        switch (ip->protocol) {
        case IPPROTO_UDP:
        {
            proto = "UDP";
            UDP_HEADER* udp = reinterpret_cast<UDP_HEADER*>(ipPayload);
            srcPort = ntohs(udp->src_port);
            dstPort = ntohs(udp->dst_port);
            flags = "";
        }
        break;
        case IPPROTO_TCP:
        {
            proto = "TCP";
            TCP_HEADER* tcp = reinterpret_cast<TCP_HEADER*>(ipPayload);
            srcPort = ntohs(tcp->src_port);
            dstPort = ntohs(tcp->dst_port);
            flags = " flags=" + tcpFlags(tcp->flags);

        }
        break;
        default:
            proto = "Unknown";
            srcPort = 0;
            dstPort = 0;
            flags = "";
        }
        m_Logger->log(LOGGER_LEVEL_INFO, "RECEIVED: " + proto + " " + srcIp + ":" + to_string(srcPort) + " -> " + dstIp + ":" + to_string(dstPort) + flags + " size=" + to_string(pkt->payloadSize));
    }

    UINT sended = 0;
    return WinDivertSend(m_Network, pkt->payload, pkt->payloadSize, &sended, pAddr);
}

// thread for clearing expired cache
void PacketMonitor::CacheCleanupThread() {
    const auto TTL_TCP = chrono::minutes(124); // time to life tcp port cache - RFC 5382
    const auto TTL_UDP = chrono::minutes(20);
    const auto PACKET_TTL = chrono::seconds(5); // time to life packet in queue

    while (m_Running.load()) {
        this_thread::sleep_for(chrono::seconds(5));
        auto now = chrono::steady_clock::now();

        unique_lock lock(cacheMutex);

        // Clean TCP cache
        for (auto it = tcpCache.begin(); it != tcpCache.end();) {
            if ((now - it->second.lastSeen) > TTL_TCP) {
                if (m_Logger->isEnabled())
                    m_Logger->log(LOGGER_LEVEL_DEBUG, "PID " + to_string(it->second.pid) + " was removed from TCP cache.");
                it = tcpCache.erase(it);
            }
            else {
                ++it;
            }
        }

        // Clean UDP cache
        for (auto it = udpCache.begin(); it != udpCache.end();) {
            if ((now - it->second.lastSeen) > TTL_UDP) {
                if (m_Logger->isEnabled())
                    m_Logger->log(LOGGER_LEVEL_DEBUG, "PID " + to_string(it->second.pid) + " was removed from UDP cache.");
                it = udpCache.erase(it);
            }
            else {
                ++it;
            }
        }

        // Clean packet queue
        unique_lock lockTTL(pendingMutex);
        auto cleanPendingQueue = [&](auto& pendingMap) {
            for (auto it = pendingMap.begin(); it != pendingMap.end();) {
                bool isStale = false;
                for (const auto& pkt : it->second) {
                    if ((now - pkt.timestamp) > PACKET_TTL) {
                        isStale = true;
                        break;
                    }
                }
                if (isStale) {
                    for (const auto& pkt : it->second) {
                        WinDivertSend(m_Network, pkt.packetData.data(), (UINT)pkt.packetData.size(), nullptr, &pkt.addr);
                    }
                    it = pendingMap.erase(it);
                }
                else {
                    ++it;
                }
            }
            };
        cleanPendingQueue(pendingTCP);
        cleanPendingQueue(pendingUDP);
    }
}

PacketMonitor::PacketMonitor(ConfigManager* config, Logger* logger)
    : m_Config(config)
    , m_Logger(logger)
    , m_Running(false)
    , m_Socket(INVALID_HANDLE_VALUE)
    , m_Network(INVALID_HANDLE_VALUE)
    , m_udpSocket(INVALID_SOCKET)
    , m_Encryption()
    , m_ourPid(GetCurrentProcessId()) {

    if (!m_Config || !m_Logger) {
        throw invalid_argument("ConfigManager and Logger must not be null");
    }
}

PacketMonitor::~PacketMonitor() {
    Stop();
}

bool PacketMonitor::Start() {
    if (m_Running.load()) {
        return false;
    }

    m_Running.store(true);

    random_device rd;
    m_rng.seed(rd());
    m_portDist = uniform_int_distribution<uint16_t>(m_Config->GetPortStart(), m_Config->GetPortEnd());

    if (!m_Encryption.Initialize(m_Config->GetXorKeyBase64(), m_Config->GetSwapKeyBase64())) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to initialize Encryption");
        Stop();
        return false;
    }

    if (!InitUdpSocket()) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to initialize UDP socket");
        Stop();
        return false;
    }

    if (!InitWinDivert()) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to initialize WinDivert");
        Stop();
        return false;
    }

    m_SocketThread = thread(&PacketMonitor::SocketThread, this);
    m_NetworkThread = thread(&PacketMonitor::NetworkThread, this);
    m_CleanupThread = thread(&PacketMonitor::CacheCleanupThread, this);

    m_Logger->log(LOGGER_LEVEL_INFO, "PacketMonitor started successfully");
    return true;
}

void PacketMonitor::Stop() {
    if (!m_Running.load()) {
        return;
    }

    m_Running.store(false);

    if (m_udpSocket != INVALID_SOCKET) {
        closesocket(m_udpSocket);
        m_udpSocket = INVALID_SOCKET;
    }

    if (m_Socket != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(m_Socket, WINDIVERT_SHUTDOWN_RECV);
        WinDivertClose(m_Socket);
        m_Socket = INVALID_HANDLE_VALUE;
    }
    if (m_Network != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(m_Network, WINDIVERT_SHUTDOWN_RECV);
        WinDivertClose(m_Network);
        m_Network = INVALID_HANDLE_VALUE;
    }

    // wait for threads shutdown
    if (m_SocketThread.joinable()) m_SocketThread.join();
    if (m_NetworkThread.joinable()) m_NetworkThread.join();
    if (m_CleanupThread.joinable()) m_CleanupThread.join();

    m_Logger->log(LOGGER_LEVEL_INFO, "PacketMonitor stopped");
}

bool PacketMonitor::InitWinDivert() {
    if (!OpenSocketHandle()) return false;
    if (!OpenNetworkHandle()) return false;

    m_Logger->log(LOGGER_LEVEL_INFO, "WinDivert initialized");
    return true;
}

// initilize udp socket to send datagrams to server
bool PacketMonitor::InitUdpSocket() {
    if (m_udpSocket != INVALID_SOCKET) {
        return true;
    }

    WSADATA wsaData;
    static bool wsaInitialized = false;

    if (!wsaInitialized) {
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "WSAStartup failed: " + to_string(result));
            return false;
        }
        wsaInitialized = true;
    }

    m_udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_udpSocket == INVALID_SOCKET) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to create UDP socket, error: " + to_string(WSAGetLastError()));
        return false;
    }

    const string& serverHost = m_Config->GetServerIP();
    if (serverHost.empty()) {
        m_Logger->log(LOGGER_LEVEL_ERROR, "Server IP not configured");
        closesocket(m_udpSocket);
        m_udpSocket = INVALID_SOCKET;
        return false;
    }

    m_serverAddr.sin_family = AF_INET;
    struct in_addr addr;
    if (inet_pton(AF_INET, serverHost.c_str(), &addr) == 1) {
        m_serverAddr.sin_addr.s_addr = addr.s_addr;
    }

    if (m_serverAddr.sin_addr.s_addr == INADDR_NONE) {
        struct addrinfo hints, * result = nullptr;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        int ret = getaddrinfo(serverHost.c_str(), nullptr, &hints, &result);
        if (ret != 0) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to resolve server address: " + serverHost);
            closesocket(m_udpSocket);
            m_udpSocket = INVALID_SOCKET;
            return false;
        }

        sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(result->ai_addr);
        memcpy(&m_serverAddr, addr, sizeof(sockaddr_in));
        freeaddrinfo(result);
    }

    return true;
}

void PacketMonitor::CleanupWinDivert() {
}

// process received outbound packet
void PacketMonitor::ProcessPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, uint32_t pid) {
    if (pid == 4 || pid == m_ourPid) { // SYSTEM or own
        WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
        return;
    }

    const IP_HEADER* iph = reinterpret_cast<const IP_HEADER*>(packet);
    string processName = GetProcessNameByPid(pid);
    uint32_t destIpHost = ntohl(iph->dst_ip);
    bool shouldRedirect = CheckRules(processName, destIpHost);

    if (shouldRedirect && m_Logger->isEnabled()) {
        string proto, flags;
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;
        if (iph->protocol == IPPROTO_UDP) {
            proto = "UDP";
            const UDP_HEADER* udph = reinterpret_cast<const UDP_HEADER*>(packet + sizeof(IP_HEADER));
            srcPort = htons(udph->src_port);
            dstPort = htons(udph->dst_port);
            flags = "";
        }
        else if (iph->protocol == IPPROTO_TCP) {
            proto = "TCP";
            const TCP_HEADER* tcph = reinterpret_cast<const TCP_HEADER*>(packet + sizeof(IP_HEADER));
            srcPort = htons(tcph->src_port);
            dstPort = htons(tcph->dst_port);
            flags = " flags=" + tcpFlags(tcph->flags);
        }
        else {
            proto = to_string(iph->protocol);
        }

        m_Logger->log(LOGGER_LEVEL_INFO, "REDIRECT: " + proto + " " + IpToString(iph->src_ip) + ":" + to_string(srcPort) + " -> " + IpToString(iph->dst_ip) + ":" + to_string(dstPort) + flags + " PID=" + processName + " size=" + to_string(packetLen));
    }

    if (shouldRedirect) { // rules check passed
        RedirectPacket(packet, packetLen, addr);
    }
    else { // ignoring
        WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
    }
}

// redirecting ip packet to server
void PacketMonitor::RedirectPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr) {

    const IP_HEADER* ipHeader = reinterpret_cast<const IP_HEADER*>(packet);

    if (m_Logger->isEnabled()) {
        uint16_t originalDstPort = 0;
        uint16_t originalSrcPort = 0;
        uint8_t protocol = ipHeader->protocol;
        WORD ipHeaderLen = (ipHeader->ver_hlen & 0x0F) * 4;

        if (protocol == IPPROTO_TCP) {
            TCP_HEADER* tcpHeader = (TCP_HEADER*)((BYTE*)ipHeader + ipHeaderLen);
            originalDstPort = tcpHeader->dst_port;
            originalSrcPort = tcpHeader->src_port;
        }
        else if (protocol == IPPROTO_UDP) {
            UDP_HEADER* udpHeader = (UDP_HEADER*)((BYTE*)ipHeader + ipHeaderLen);
            originalDstPort = udpHeader->dst_port;
            originalSrcPort = udpHeader->src_port;
        }

        m_Logger->log(LOGGER_LEVEL_DEBUG, "Redirect packet from " + IpToString(ipHeader->src_ip) + ":" + to_string(htons(originalSrcPort)) + " to " + IpToString(ipHeader->dst_ip) + ":" + to_string(htons(originalDstPort)));
    }

    // select a random udp port based on the packet checksum
    uint16_t serverPort = m_portDist(m_rng);

    // copy and encrypt packet
    vector<uint8_t> outgoingPacket(packetLen);
    memcpy(outgoingPacket.data(), packet, packetLen);
    m_Encryption.Encrypt(outgoingPacket.data(), outgoingPacket.size(), serverPort);

    m_serverAddr.sin_port = htons(serverPort);
    int sent = sendto(m_udpSocket,
        (const char*)outgoingPacket.data(),
        static_cast<int>(outgoingPacket.size()),
        0,
        (sockaddr*)&m_serverAddr,
        sizeof(m_serverAddr));

    if (sent == SOCKET_ERROR) {
        if (m_Logger->isEnabled())
            m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to send packet to server, error: " + to_string(WSAGetLastError()));
        return;
    }
}

// getting process name by pid
string PacketMonitor::GetProcessNameByPid(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        return "unknown";
    }

    char path[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
        CloseHandle(hProcess);
        string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        return (pos == string::npos) ? fullPath : fullPath.substr(pos + 1);
    }

    CloseHandle(hProcess);
    return "unknown";
}

// checking rules for packet
bool PacketMonitor::CheckRules(const string& processName, UINT32 destIp) {
    const vector<string>& processRules = m_Config->GetProcessRules();
    for (const auto& rule : processRules) {
        if (iequals(processName, rule)) {
            return true;
        }
    }

    if (m_Config->GetIPRule().matches(destIp)) {
        return true;
    }

    return false;
}