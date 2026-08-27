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

// read name from DNS (RFC 1035)
static size_t ReadDNSName(const uint8_t* data, size_t dataLen, size_t offset, std::string& outName) {
    outName.clear();
    bool jumped = false;
    size_t originalOffset = offset;
    size_t maxJumps = 10;

    while (maxJumps-- > 0) {
        if (offset >= dataLen) return 0;
        uint8_t len = data[offset];
        if (len == 0) {
            offset++;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= dataLen) return 0;
            uint16_t ptr = ((len & 0x3F) << 8) | data[offset + 1];
            if (!jumped) {
                originalOffset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }
        offset++;
        if (offset + len > dataLen) return 0;
        if (!outName.empty()) outName += '.';
        outName.append(reinterpret_cast<const char*>(data + offset), len);
        offset += len;
    }
    if (jumped) {
        return originalOffset;
    }
    else {
        return offset;
    }
}

// extract QNAME from dns query
static bool ExtractQName(const uint8_t* dnsHeader, size_t len, std::string& qname) {
    if (len < 12) return false;
    uint16_t qdcount = ntohs(*(uint16_t*)(dnsHeader + 4));
    if (qdcount == 0) return false;
    size_t offset = 12;
    if (!ReadDNSName(dnsHeader, len, offset, qname)) return false;
    return true;
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
                    m_Logger->log(LOGGER_LEVEL_DEBUG, "Skipping local destination: " + IpToString(ntohl(destIpHost)));
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
            ServerContext* server = nullptr;
            for (auto& ctx : m_Servers) {
                if (ipHdr->SrcAddr == ctx.serverAddr.sin_addr.s_addr) {
                    server = &ctx;
                    break;
                }
            }

            if (server != nullptr && protocol == IPPROTO_UDP) {
                // ip-packet from one of miga servers - adding fragment to its udp assembler
                m_Logger->log(LOGGER_LEVEL_DEBUG, "Received packet from server #" + to_string(server->configIndex) + ".");
                if (server->assembler->AddIpPacket(reinterpret_cast<const uint8_t*>(buffer.data()), packetLen)) {
                    // we have at least 1 ready-made udp package - process it and release
                    UdpPacketInfo* pkt;
                    while ((pkt = server->assembler->GetCompleteUdpPacket()) != nullptr) {
                        SendUdpPacketToMstcp(pkt, &addr, *server);
                        server->assembler->ReleaseUdpPacket(pkt);
                    }
                }
            }
            else // some inbound packet not fron any server - ignoring
                WinDivertSend(m_Network, buffer.data(), packetLen, NULL, &addr);
        }
    }
}

// place the assembled udp-packet into tcp/ip stack
bool PacketMonitor::SendUdpPacketToMstcp(const UdpPacketInfo* pkt, WINDIVERT_ADDRESS* pAddr, ServerContext& server) {
    if (!pkt || !pAddr) return false;

    m_Logger->log(LOGGER_LEVEL_DEBUG, "Processing a full udp packet...");

    // decrypt payload - original tranmitted packet
    server.encryption.Decrypt(pkt->payload, pkt->payloadSize, htons(pkt->srcPort));

    // recalc checksums (server don't do it)
    IP_HEADER* ip = reinterpret_cast<IP_HEADER*>(pkt->payload);
    WinDivertHelperCalcChecksums(pkt->payload, pkt->payloadSize, pAddr, 0);

    // check for dns response
    if (ip->protocol == IPPROTO_UDP) {
        const UDP_HEADER* udp = reinterpret_cast<const UDP_HEADER*>(ip + 1);
        uint16_t srcPort = ntohs(udp->src_port);
        if (srcPort == 53) {
            const uint8_t* dnsPayload = reinterpret_cast<const uint8_t*>(udp + 1);
            size_t dnsLen = pkt->payloadSize - (sizeof(IP_HEADER) + sizeof(UDP_HEADER));
            if (dnsLen > 0) {
                uint16_t queryId = ntohs(*reinterpret_cast<const uint16_t*>(dnsPayload));
                // 3.x handle dns response - decide whether to inject into stack
                bool inject = HandleDNSResponse(dnsPayload, dnsLen, server.configIndex, queryId);
                if (!inject) {
                    m_Logger->log(LOGGER_LEVEL_DEBUG, "Auxiliary DNS response dropped (qid=" + to_string(queryId) + ")");
                    return false;
                }
            }
            else {
                ProcessDNSResponse(dnsPayload, dnsLen, server.configIndex);
            }
        }
    }

    // reverse-translate source ip on inbound packets from servers
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        uint32_t srcIpHost = ntohl(ip->src_ip);
        uint32_t originalIp = 0;
        if (LookupIpReverse(srcIpHost, server.configIndex, originalIp)) {
            m_Logger->log(LOGGER_LEVEL_DEBUG, "Reverse translating src " + IpToString(srcIpHost) + " -> " + IpToString(originalIp));
            ip->src_ip = htonl(originalIp);
            WinDivertHelperCalcChecksums(pkt->payload, pkt->payloadSize, pAddr, 0);
        }
    }

    if (m_Logger->isEnabled()) {
        uint8_t* ipPayload = reinterpret_cast<uint8_t*>(ip + 1);

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

        CleanupDnsState();
    }
}

PacketMonitor::PacketMonitor(ConfigManager* config, Logger* logger)
    : m_Config(config)
    , m_Logger(logger)
    , m_Running(false)
    , m_Socket(INVALID_HANDLE_VALUE)
    , m_Network(INVALID_HANDLE_VALUE)
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

    CloseUdpSockets();

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

// initilize udp socket to send datagrams to each configured server
bool PacketMonitor::InitUdpSocket() {
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

    const vector<ServerConfig>& servers = m_Config->GetServers();
    m_Servers.clear();
    m_Servers.resize(servers.size());

    for (size_t i = 0; i < servers.size(); ++i) {
        const ServerConfig& cfg = servers[i];

        ServerContext& ctx = m_Servers[i];
        ctx.configIndex = i;
        ctx.udpSocket = INVALID_SOCKET;
        memset(&ctx.serverAddr, 0, sizeof(ctx.serverAddr));
        ctx.assembler = make_unique<UdpPacketAssembler>();

        if (!ctx.encryption.Initialize(cfg.xorKeyBase64, cfg.swapKeyBase64)) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to initialize Encryption for server #" + to_string(i));
            CloseUdpSockets();
            return false;
        }

        ctx.udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
        if (ctx.udpSocket == INVALID_SOCKET) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to create UDP socket for server #" + to_string(i) + ", error: " + to_string(WSAGetLastError()));
            CloseUdpSockets();
            return false;
        }

        if (cfg.serverIP.empty()) {
            m_Logger->log(LOGGER_LEVEL_ERROR, "Server IP not configured for server #" + to_string(i));
            CloseUdpSockets();
            return false;
        }

        ctx.serverAddr.sin_family = AF_INET;
        struct in_addr addr;
        if (inet_pton(AF_INET, cfg.serverIP.c_str(), &addr) == 1) {
            ctx.serverAddr.sin_addr.s_addr = addr.s_addr;
        }

        if (ctx.serverAddr.sin_addr.s_addr == INADDR_NONE) {
            struct addrinfo hints, * result = nullptr;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;

            int ret = getaddrinfo(cfg.serverIP.c_str(), nullptr, &hints, &result);
            if (ret != 0) {
                m_Logger->log(LOGGER_LEVEL_ERROR, "Failed to resolve server address: " + cfg.serverIP);
                closesocket(ctx.udpSocket);
                CloseUdpSockets();
                return false;
            }

            sockaddr_in* resolved = reinterpret_cast<sockaddr_in*>(result->ai_addr);
            memcpy(&ctx.serverAddr, resolved, sizeof(sockaddr_in));
            freeaddrinfo(result);
        }

        m_Logger->log(LOGGER_LEVEL_INFO, "UDP socket initialized for server #" + to_string(i) + ": " +
            cfg.serverIP + " ports " + to_string(cfg.portStart) + "-" + to_string(cfg.portEnd));
    }

    return true;
}

void PacketMonitor::CloseUdpSockets() {
    for (auto& server : m_Servers) {
        if (server.udpSocket != INVALID_SOCKET) {
            closesocket(server.udpSocket);
            server.udpSocket = INVALID_SOCKET;
        }
    }
    m_Servers.clear();
}

PacketMonitor::ServerContext* PacketMonitor::FindServerContext(const ServerConfig* config) {
    for (auto& server : m_Servers) {
        if (&m_Config->GetServers()[server.configIndex] == config) {
            return &server;
        }
    }
    return nullptr;
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

    if (iph->protocol == IPPROTO_UDP) {
        const UDP_HEADER* udph = reinterpret_cast<const UDP_HEADER*>(packet + sizeof(IP_HEADER));
        uint16_t dstPort = ntohs(udph->dst_port);
        if (addr.Outbound && dstPort == 53) { // outbound DNS query
            const uint8_t* udpPayload = packet + sizeof(IP_HEADER) + sizeof(UDP_HEADER);
            size_t udpPayloadLen = packetLen - (sizeof(IP_HEADER) + sizeof(UDP_HEADER));
            if (udpPayloadLen > 0) {
                string domain;
                if (ExtractDomainFromDNSQuery(udpPayload, udpPayloadLen, domain) && !domain.empty()) {
                    const ServerConfig* dnsServer = m_Config->FindServerByDomain(domain);
                    if (dnsServer != nullptr) {
                        ServerContext* dnsCtx = FindServerContext(dnsServer);
                        if (dnsCtx != nullptr) {
                            uint16_t queryId = ntohs(*reinterpret_cast<const uint16_t*>(udpPayload));

                            // 1.1.1.4 save actual query: original id -> found server
                            {
                                unique_lock lock(m_DnsMutex);
                                m_ActualDns[queryId] = dnsCtx->configIndex;
                                m_ActualIpByQuery[queryId] = 0;
                                m_DnsTimestamp[queryId] = chrono::steady_clock::now();
                            }

                            // 1.1.1.3 send query to actual server with original id
                            m_Logger->log(LOGGER_LEVEL_INFO, "Redirecting DNS query for domain: " + domain +
                                " to actual server #" + to_string(dnsCtx->configIndex) + " (qid=" + to_string(queryId) + ")");
                            RedirectPacket(packet, packetLen, addr, *dnsCtx);

                            // 1.1.1.1/1.1.1.2/1.1.1.5 send query to all other servers with generated ids
                            for (auto& other : m_Servers) {
                                if (other.configIndex == dnsCtx->configIndex)
                                    continue;

                                uint16_t auxId;
                                {
                                    unique_lock lock(m_DnsMutex);
                                    auxId = GenerateUniqueQueryId();
                                    m_AuxiliaryDns[auxId] = other.configIndex;
                                    m_ActualToAuxiliary[auxId] = queryId;
                                    m_DnsTimestamp[auxId] = chrono::steady_clock::now();
                                }

                                m_Logger->log(LOGGER_LEVEL_DEBUG, "Sending aux DNS query for domain: " + domain +
                                    " to server #" + to_string(other.configIndex) + " (aux qid=" + to_string(auxId) + ")");
                                RedirectPacket(packet, packetLen, addr, other, 0, auxId);
                            }
                            return;
                        }
                        WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
                    }
                    else {
                        m_Logger->log(LOGGER_LEVEL_DEBUG, "DNS query not redirected (domain not in list): " + domain);
                        WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
                    }
                    return;
                }
            }
        }
    }

    string processName = GetProcessNameByPid(pid);
    uint32_t destIpHost = ntohl(iph->dst_ip);
    const ServerConfig* targetServer = CheckRules(processName, destIpHost);
    bool shouldRedirect = (targetServer != nullptr);

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
        ServerContext* targetCtx = FindServerContext(targetServer);
        if (targetCtx != nullptr) {
            // 2.2 look up destination in dynamic ip correspondence by original ip and server
            uint32_t translatedIp = 0;
            if (LookupIpTranslation(destIpHost, targetCtx->configIndex, translatedIp)) {
                m_Logger->log(LOGGER_LEVEL_DEBUG, "Translating dst " + IpToString(destIpHost) + " -> " + IpToString(translatedIp) +
                    " for server #" + to_string(targetCtx->configIndex));
                RedirectPacket(packet, packetLen, addr, *targetCtx, translatedIp);
            }
            else {
                RedirectPacket(packet, packetLen, addr, *targetCtx);
            }
            return;
        }
    }
    // ignoring
    WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
}

// redirecting ip packet to server
void PacketMonitor::RedirectPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, ServerContext& server, uint32_t newDstIp, uint16_t dnsQueryIdOverride) {

    // copy and encrypt packet
    vector<uint8_t> outgoingPacket(packetLen);
    memcpy(outgoingPacket.data(), packet, packetLen);

    IP_HEADER* ipHeader = reinterpret_cast<IP_HEADER*>(outgoingPacket.data());

    if (newDstIp != 0) {
        ipHeader->dst_ip = htonl(newDstIp);
    }

    if (dnsQueryIdOverride != 0 && ipHeader->protocol == IPPROTO_UDP) {
        const UDP_HEADER* udpHeader = reinterpret_cast<const UDP_HEADER*>(outgoingPacket.data() + sizeof(IP_HEADER));
        uint8_t* udpPayload = outgoingPacket.data() + sizeof(IP_HEADER) + sizeof(UDP_HEADER);
        if (udpPayload + 2 <= outgoingPacket.data() + packetLen) {
            uint16_t* pQueryId = reinterpret_cast<uint16_t*>(udpPayload);
            *pQueryId = htons(dnsQueryIdOverride);
        }
    }

    // recalc checksums after any ip/payload rewrite
    if (newDstIp != 0 || dnsQueryIdOverride != 0) {
        WinDivertHelperCalcChecksums(outgoingPacket.data(), outgoingPacket.size(), NULL, 0);
    }

    const ServerConfig& cfg = m_Config->GetServers()[server.configIndex];

    // select a random udp port based on the packet checksum
    uint16_t serverPort = uniform_int_distribution<uint16_t>(cfg.portStart, cfg.portEnd)(m_rng);

    server.encryption.Encrypt(outgoingPacket.data(), outgoingPacket.size(), serverPort);

    server.serverAddr.sin_port = htons(serverPort);
    int sent = sendto(server.udpSocket,
        (const char*)outgoingPacket.data(),
        static_cast<int>(outgoingPacket.size()),
        0,
        (sockaddr*)&server.serverAddr,
        sizeof(server.serverAddr));

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

// checking rules for packet, returns first matching server or nullptr
const ServerConfig* PacketMonitor::CheckRules(const string& processName, UINT32 destIp) {
    for (const auto& server : m_Config->GetServers()) {
        for (const auto& rule : server.processRules) {
            if (iequals(processName, rule)) {
                return &server;
            }
        }
    }

    for (const auto& server : m_Config->GetServers()) {
        if (server.staticIPRule.matches(destIp)) {
            return &server;
        }
    }

    for (const auto& server : m_Config->GetServers()) {
        if (server.dynamicIPRule.matches(destIp)) {
            return &server;
        }
    }

    return nullptr;
}

bool PacketMonitor::ExtractDomainFromDNSQuery(const uint8_t* payload, size_t len, std::string& domain) {
    if (len < 12) return false;
    // is it query (QR=0)
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    if ((flags & 0x8000) != 0) return false;
    return ExtractQName(payload, len, domain);
}

bool PacketMonitor::IsDNSQuery(const uint8_t* payload, size_t len) {
    if (len < 12) return false;
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    return (flags & 0x8000) == 0; // QR=0
}

bool PacketMonitor::IsDNSResponse(const uint8_t* payload, size_t len) {
    if (len < 12) return false;
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    return (flags & 0x8000) != 0; // QR=1
}

uint16_t PacketMonitor::GenerateUniqueQueryId() {
    uint16_t candidate;
    const int MAX_ATTEMPTS = 100;
    for (int i = 0; i < MAX_ATTEMPTS; ++i) {
        candidate = static_cast<uint16_t>(uniform_int_distribution<int>(1, 0xFFFF)(m_rng));
        if (m_ActualDns.count(candidate) == 0 && m_AuxiliaryDns.count(candidate) == 0)
            return candidate;
    }
    return candidate;
}

bool PacketMonitor::ExtractFirstARecord(const uint8_t* payload, size_t len, uint32_t& ipOut) {
    if (len < 12) return false;
    uint16_t flags = ntohs(*(uint16_t*)(payload + 2));
    if ((flags & 0x8000) == 0) return false; // not a response

    uint16_t qdcount = ntohs(*(uint16_t*)(payload + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(payload + 6));
    if (ancount == 0) return false;

    size_t offset = 12;
    for (int i = 0; i < qdcount; ++i) {
        std::string dummy;
        size_t bytes = ReadDNSName(payload, len, offset, dummy);
        if (bytes == 0) return false;
        offset = bytes;
        if (offset + 4 > len) return false;
        offset += 4;
    }

    for (int i = 0; i < ancount; ++i) {
        std::string name;
        size_t bytes = ReadDNSName(payload, len, offset, name);
        if (bytes == 0) return false;
        offset = bytes;
        if (offset + 10 > len) return false;
        uint16_t type = ntohs(*(uint16_t*)(payload + offset));
        uint16_t rdlength = ntohs(*(uint16_t*)(payload + offset + 8));
        offset += 10;
        if (offset + rdlength > len) return false;
        if (type == 1 && rdlength == 4) { // A record
            uint32_t ip = 0;
            memcpy(&ip, payload + offset, 4);
            ipOut = ntohl(ip);
            return true;
        }
        offset += rdlength;
    }
    return false;
}

bool PacketMonitor::LookupIpTranslation(uint32_t originalIp, size_t serverIndex, uint32_t& translatedIp) {
    shared_lock lock(m_DnsMutex);
    uint64_t key = ((uint64_t)originalIp << 32) | (uint64_t)(serverIndex & 0xFFFFFFFF);
    auto it = m_DynamicIpMap.find(key);
    if (it == m_DynamicIpMap.end()) return false;
    translatedIp = it->second;
    return true;
}

bool PacketMonitor::LookupIpReverse(uint32_t translatedIp, size_t serverIndex, uint32_t& originalIp) {
    shared_lock lock(m_DnsMutex);
    uint64_t key = ((uint64_t)translatedIp << 32) | (uint64_t)(serverIndex & 0xFFFFFFFF);
    auto it = m_DynamicIpReverse.find(key);
    if (it == m_DynamicIpReverse.end()) return false;
    originalIp = it->second;
    return true;
}

// 3. handle dns response: 3.3 actual response -> return true (inject), 3.4 aux response -> return false (drop)
bool PacketMonitor::HandleDNSResponse(const uint8_t* payload, size_t len, size_t serverIndex, uint16_t queryId) {
    if (!IsDNSResponse(payload, len)) return false;

    uint32_t ip = 0;
    ExtractFirstARecord(payload, len, ip);

    unique_lock lock(m_DnsMutex);

    // 3.2 lookup query id in actual dns correspondence
    auto itActual = m_ActualDns.find(queryId);
    if (itActual != m_ActualDns.end()) {
        // 3.3.1 save received ip as IP / queryId / server / IP
        m_ActualIpByQuery[queryId] = ip;
        m_DnsTimestamp[queryId] = chrono::steady_clock::now();
        if (ip != 0) {
            uint64_t key = ((uint64_t)ip << 32) | (uint64_t)(serverIndex & 0xFFFFFFFF);
            m_DynamicIpMap[key] = ip;          // identity mapping for the actual server
            m_DynamicIpReverse[key] = ip;      // reverse identity (no rewrite needed)
        }

        // 3.3.2 fill in previously received aux entries whose original ip was unknown
        for (auto it = m_PendingDynamicIp.begin(); it != m_PendingDynamicIp.end();) {
            uint64_t pendingQid = it->first >> 32;
            if (pendingQid == queryId && ip != 0) {
                size_t srv = static_cast<size_t>(it->first & 0xFFFFFFFF);
                uint32_t auxIp = it->second;
                uint64_t fwdKey = ((uint64_t)ip << 32) | (uint64_t)(srv & 0xFFFFFFFF);
                uint64_t revKey = ((uint64_t)auxIp << 32) | (uint64_t)(srv & 0xFFFFFFFF);
                m_DynamicIpMap[fwdKey] = auxIp;
                m_DynamicIpReverse[revKey] = ip;
                it = m_PendingDynamicIp.erase(it);
                if (m_Logger->isEnabled())
                    m_Logger->log(LOGGER_LEVEL_DEBUG, "Filled dynamic IP: " + IpToString(ip) + " -> " + IpToString(auxIp));
            }
            else {
                ++it;
            }
        }

        // keep adding resolved ips to the actual server's dynamic rule set
        ProcessDNSResponse(payload, len, serverIndex);
        return true; // 3.3.3 send packet to stack
    }

    // 3.4 lookup query id in auxiliary dns correspondence
    auto itAux = m_AuxiliaryDns.find(queryId);
    if (itAux != m_AuxiliaryDns.end()) {
        // 3.4.2.1 find original query id
        auto itMap = m_ActualToAuxiliary.find(queryId);
        if (itMap == m_ActualToAuxiliary.end())
            return false;
        uint16_t origQid = itMap->second;

        // 3.4.2.2 find ip of the original response (may be 0 if not yet arrived)
        uint32_t origIp = 0;
        auto itIp = m_ActualIpByQuery.find(origQid);
        if (itIp != m_ActualIpByQuery.end())
            origIp = itIp->second;

        // 3.4.2.3 save as: original response ip / original query id / server / aux ip
        if (origIp != 0) {
            uint64_t fwdKey = ((uint64_t)origIp << 32) | (uint64_t)(serverIndex & 0xFFFFFFFF);
            uint64_t revKey = ((uint64_t)ip << 32) | (uint64_t)(serverIndex & 0xFFFFFFFF);
            m_DynamicIpMap[fwdKey] = ip;
            m_DynamicIpReverse[revKey] = origIp;
            if (m_Logger->isEnabled())
                m_Logger->log(LOGGER_LEVEL_DEBUG, "Aux dynamic IP: " + IpToString(origIp) + " -> " + IpToString(ip) +
                    " for server #" + to_string(serverIndex));
        }
        else {
            // original response ip not yet known - keep pending by original query id
            uint64_t pKey = ((uint64_t)origQid << 32) | (uint64_t)(serverIndex & 0xFFFFFFFF);
            m_PendingDynamicIp[pKey] = ip;
            if (m_Logger->isEnabled())
                m_Logger->log(LOGGER_LEVEL_DEBUG, "Pending dynamic IP (waiting original): " + IpToString(ip) +
                    " for server #" + to_string(serverIndex));
        }
        return false; // 3.4.2.4 do not send packet to stack
    }

    // not tracked by our correspondence - treat as a regular dns response
    ProcessDNSResponse(payload, len, serverIndex);
    return true;
}

void PacketMonitor::CleanupDnsState() {
    auto now = chrono::steady_clock::now();
    const auto DNS_TTL = chrono::seconds(30);

    unique_lock lock(m_DnsMutex);

    for (auto it = m_DnsTimestamp.begin(); it != m_DnsTimestamp.end();) {
        if ((now - it->second) > DNS_TTL) {
            uint16_t qid = it->first;
            m_ActualDns.erase(qid);
            m_AuxiliaryDns.erase(qid);
            m_ActualToAuxiliary.erase(qid);
            m_ActualIpByQuery.erase(qid);
            for (auto p = m_PendingDynamicIp.begin(); p != m_PendingDynamicIp.end();) {
                if ((p->first >> 32) == qid)
                    p = m_PendingDynamicIp.erase(p);
                else
                    ++p;
            }
            it = m_DnsTimestamp.erase(it);
            if (m_Logger->isEnabled())
                m_Logger->log(LOGGER_LEVEL_DEBUG, "DNS state cleaned for qid=" + to_string(qid));
        }
        else {
            ++it;
        }
    }
}

void PacketMonitor::ProcessDNSResponse(const uint8_t* payload, size_t len, size_t serverIndex) {
    if (!IsDNSResponse(payload, len)) return;
    if (len < 12) return;

    uint16_t ancount = ntohs(*(uint16_t*)(payload + 6));
    if (ancount == 0) return;

    size_t offset = 12;
    // pass query section
    uint16_t qdcount = ntohs(*(uint16_t*)(payload + 4));
    for (int i = 0; i < qdcount; ++i) {
        std::string dummy;
        size_t bytes = ReadDNSName(payload, len, offset, dummy);
        if (bytes == 0) return;
        offset = bytes;
        if (offset + 4 > len) return;
        offset += 4;
    }

    for (int i = 0; i < ancount; ++i) {
        std::string name;
        size_t bytes = ReadDNSName(payload, len, offset, name);
        if (bytes == 0) return;
        offset = bytes;
        if (offset + 10 > len) return;
        uint16_t type = ntohs(*(uint16_t*)(payload + offset));
        uint16_t class_ = ntohs(*(uint16_t*)(payload + offset + 2));
        uint32_t ttl = ntohl(*(uint32_t*)(payload + offset + 4));
        uint16_t rdlength = ntohs(*(uint16_t*)(payload + offset + 8));
        offset += 10;
        if (offset + rdlength > len) return;
        if (type == 1 && rdlength == 4) { // A record
            uint32_t ip = 0;
            memcpy(&ip, payload + offset, 4);
            uint32_t ipHost = ntohl(ip);
            m_Config->AddDynamicIP(serverIndex, ipHost);
            if (m_Logger->isEnabled())
                m_Logger->log(LOGGER_LEVEL_DEBUG, "DNS response added dynamic IP: " + IpToString(ipHost) + " TTL=" + std::to_string(ttl));
        }
        offset += rdlength;
    }
}