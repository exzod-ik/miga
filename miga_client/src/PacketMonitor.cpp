#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "PacketMonitor.h"
#include "WindowsProcessIdentity.h"
#include "PacketWarning.h"

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

// clamp the tcp MSS option in place, returns true if the packet was modified
bool ClampTcpMss(uint8_t* packet, size_t packetLen, uint16_t maxMss) {
    if (packetLen < sizeof(IP_HEADER)) return false;
    IP_HEADER* ip = reinterpret_cast<IP_HEADER*>(packet);
    if (ip->protocol != IPPROTO_TCP) return false;

    uint8_t ipHdrLen = (ip->ver_hlen & 0x0F) * 4;
    if (ipHdrLen < sizeof(IP_HEADER) || (size_t)(ipHdrLen + sizeof(TCP_HEADER)) > packetLen) return false;

    TCP_HEADER* tcp = reinterpret_cast<TCP_HEADER*>(packet + ipHdrLen);
    uint8_t tcpHdrLen = (tcp->data_offset & 0x0F) * 4;
    if (tcpHdrLen < sizeof(TCP_HEADER) || (size_t)(ipHdrLen + tcpHdrLen) > packetLen) return false;

    uint8_t* options = reinterpret_cast<uint8_t*>(tcp) + sizeof(TCP_HEADER);
    size_t optsLen = tcpHdrLen - sizeof(TCP_HEADER);
    size_t off = 0;
    while (off < optsLen) {
        uint8_t kind = options[off];
        if (kind == 0) break;                  // end of options list
        if (kind == 1) {                       // NOP
            off += 1;
            continue;
        }
        if (off + 1 >= optsLen) break;
        uint8_t len = options[off + 1];
        if (len < 2 || off + len > optsLen) break;
        if (kind == 2 && len == 4) {           // MSS option
            uint16_t* mssField = reinterpret_cast<uint16_t*>(options + off + 2);
            uint16_t currentMss = ntohs(*mssField);
            if (currentMss > maxMss) {
                *mssField = htons(maxMss);
                return true;
            }
            return false;
        }
        off += len;
    }
    return false;
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
        m_Logger->logLazy(LOGGER_LEVEL_ERROR, [&] { return "windivert_open_failed layer=SOCKET win32_error=" + to_string(GetLastError()); });
        return false;
    }
    return true;
}

// open windivert network layer to snif packets
bool PacketMonitor::OpenNetworkHandle() {
    const char* filter = "ip and (tcp or (udp.SrcPort != 67 and udp.DstPort != 67 and udp.SrcPort != 68 and udp.DstPort != 68))"; // the filter must be different from the socket layer, otherwise the winddivert freezes
    m_Network = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (m_Network == INVALID_HANDLE_VALUE) {
        m_Logger->logLazy(LOGGER_LEVEL_ERROR, [&] { return "windivert_open_failed layer=NETWORK win32_error=" + to_string(GetLastError()); });
        return false;
    }
    return true;
}

void PacketMonitor::SocketThread() {
    while (m_Running.load()) {
        WorkItem item;
        UINT packetLength = 0;
        if (!WinDivertRecv(m_Socket, nullptr, 0, &packetLength, &item.socket)) {
            if (!m_Running.load() || GetLastError() == ERROR_OPERATION_ABORTED || GetLastError() == ERROR_NO_DATA)
                break;
            continue;
        }
        const auto& addr = item.socket;
        if (addr.IPv6 || (addr.Socket.Protocol != IPPROTO_TCP && addr.Socket.Protocol != IPPROTO_UDP)) continue;
        if (addr.Event == WINDIVERT_EVENT_SOCKET_BIND || addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT ||
            addr.Event == WINDIVERT_EVENT_SOCKET_ACCEPT) {
            auto process = GetProcessByPid(addr.Socket.ProcessId);
            process->Name();
            item.owner = make_shared<const SocketOwner>(
                SocketOwner{ process, addr.Socket.EndpointId, addr.Timestamp });
        }
        else if (addr.Event != WINDIVERT_EVENT_SOCKET_CLOSE) continue;
        if (!m_Work.Push(move(item), &item.queuedAt)) break;
    }
}

void PacketMonitor::ProcessSocketEvent(const WorkItem& item) {
    const auto& addr = item.socket;
    if (item.owner) {
        const SocketTuple tuple{ addr.Socket.Protocol, addr.Socket.LocalAddr[0], addr.Socket.LocalPort,
            addr.Socket.RemoteAddr[0], addr.Socket.RemotePort };
        m_Routing.Observe(tuple, item.owner, chrono::steady_clock::now());
    }
    else if (addr.Event == WINDIVERT_EVENT_SOCKET_CLOSE) {
        m_Routing.Close(addr.Socket.Protocol, addr.Socket.LocalPort, addr.Socket.EndpointId,
            addr.Timestamp, chrono::steady_clock::now());
        m_Routing.CloseSnapshot({ addr.Socket.Protocol, addr.Socket.LocalAddr[0], addr.Socket.LocalPort,
            addr.Socket.RemoteAddr[0], addr.Socket.RemotePort }, addr.Socket.ProcessId,
            addr.Timestamp, chrono::steady_clock::now());
    }
    DrainPending((uint32_t(addr.Socket.Protocol) << 16) | addr.Socket.LocalPort);
}

void PacketMonitor::NetworkThread() {
    while (m_Running.load()) {
        unique_ptr<NetworkBatch> batch;
        const auto waitStarted = chrono::steady_clock::now();
        if (!m_FreeNetworkBatches.Pop(batch)) break;
        m_Logger->recordDelay(NetworkWarning::ReceiveBufferWait, waitStarted);
        if (!m_Running.load()) break;
        batch->addressLength = static_cast<UINT>(sizeof(batch->addresses));
        if (!WinDivertRecvEx(m_Network, batch->data.data(), static_cast<UINT>(batch->data.size()),
            &batch->length, 0, batch->addresses.data(), &batch->addressLength, nullptr)) {
            const auto error = GetLastError();
            if (!m_Running.load() || error == ERROR_OPERATION_ABORTED || error == ERROR_NO_DATA) break;
            m_Logger->logLazy(LOGGER_LEVEL_ERROR, [&] { return "network_receive_failed win32_error=" + to_string(error); });
            if (!m_FreeNetworkBatches.Push(move(batch))) break;
            unique_lock lock(m_StopMutex);
            if (m_StopCondition.wait_for(lock, chrono::milliseconds(100), [&] { return !m_Running.load(); })) break;
            continue;
        }
        batch->receivedAt = chrono::steady_clock::now();
        WorkItem item;
        item.batch = move(batch);
        const auto queueStarted = chrono::steady_clock::now();
        if (!m_Work.Push(move(item), &item.queuedAt)) break;
        m_Logger->recordDelay(NetworkWarning::ReceiveEventQueueWait, queueStarted);
    }
}

void PacketMonitor::EventProcessThread() {
    auto maintenance = chrono::steady_clock::now() + chrono::seconds(5);
    while (m_Running.load()) {
        WorkItem item;
        size_t queueDepth = 0;
        const auto result = m_Work.PopUntil(item, m_Pending.Deadline(maintenance), &queueDepth);
        if (result == decltype(m_Work)::WaitResult::Closed || !m_Running.load()) break;
        if (result == decltype(m_Work)::WaitResult::Item) {
            if (m_Logger->isEnabled(LOGGER_LEVEL_WARNING))
                m_EventQueueDelay.Record(item.reload ? EventQueueDelay::Type::Control :
                    item.batch ? EventQueueDelay::Type::Network : EventQueueDelay::Type::Socket,
                    chrono::steady_clock::now() - item.queuedAt, queueDepth);
            if (item.reload) {
                try {
                    if (!m_Config->Load(item.reloadPath, true,
                        [&](const vector<ServerConfig>& servers) { return InitUdpSocket(servers); })) item.reload->set_value(false);
                    else {

                        m_Logger->enable(m_Config->GetLogLevel(), false);
                        item.reload->set_value(true);
                    }
                }
                catch (...) { item.reload->set_exception(current_exception()); }
            }
            else if (!item.batch) ProcessSocketEvent(item);
            else {
                auto& batch = item.batch;
                m_Logger->recordDelay(NetworkWarning::BatchAge, batch->receivedAt);
                const auto started = chrono::steady_clock::now();
                const UINT count = batch->addressLength / sizeof(WINDIVERT_ADDRESS);
                UINT offset = 0;
                bool valid = batch->addressLength != 0 &&
                    batch->addressLength % sizeof(WINDIVERT_ADDRESS) == 0 &&
                    count <= batch->addresses.size() && batch->length <= batch->data.size();
                for (UINT i = 0; valid && i < count && m_Running.load(); ++i) {
                    const auto length = static_cast<UINT>(
                        Ipv4BatchPacketLength(batch->data.data(), batch->length, offset));
                    if (length == 0) { valid = false; break; }
                    ProcessNetworkPacket(batch->data.data() + offset, length, batch->addresses[i]);
                    offset += length;
                }
                if (m_Running.load() && (!valid || offset != batch->length))
                    m_Logger->log(LOGGER_LEVEL_ERROR, "network_batch_invalid");
                m_Logger->recordDelay(NetworkWarning::BatchProcessing, started);
                if (!m_FreeNetworkBatches.Push(move(batch))) break;
            }
        }
        const auto now = chrono::steady_clock::now();
        if (now >= m_Pending.Deadline(maintenance)) DrainPending();
        if (now >= maintenance) {
            MaintainState();
            maintenance = now + chrono::seconds(5);
        }
    }
}
void PacketMonitor::ProcessNetworkPacket(uint8_t* packet, UINT packetLen, WINDIVERT_ADDRESS addr) {
    WINDIVERT_IPHDR* ipHdr = nullptr;
    WINDIVERT_IPV6HDR* ipv6Hdr = nullptr;
    uint8_t protocol = 0;
    WINDIVERT_TCPHDR* tcpHdr = nullptr;
    WINDIVERT_UDPHDR* udpHdr = nullptr;
    void* payload = nullptr;
    uint32_t payloadLen = 0;

    if (!WinDivertHelperParsePacket(packet, packetLen,
        &ipHdr, &ipv6Hdr, &protocol,
        nullptr, nullptr,
        &tcpHdr, &udpHdr,
        &payload, &payloadLen,
        nullptr, nullptr)) {
        WinDivertSend(m_Network, packet, packetLen, nullptr, &addr);
        return;
    }

    // ipv6 not support right now
    if (!ipHdr) {
        WinDivertSend(m_Network, packet, packetLen, nullptr, &addr);
        return;
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
        WinDivertSend(m_Network, packet, packetLen, nullptr, &addr);
        return;
    }

    if (m_Logger->isEnabled(LOGGER_LEVEL_DEBUG)) {
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

        m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "packet_captured protocol=" + string(isTCP ? "TCP" : isUDP ? "UDP" : "unknown") +
            " direction=" + (outbound ? "outbound" : "inbound") +
            " local=" + localAddr + ":" + to_string(localPort) +
            " remote=" + remoteAddr + ":" + to_string(remotePort) +
            (isTCP ? " tcp_flags_text=" + LogValue(tcpFlagsInfo) : ""); });
    }

    if (outbound) {
        uint32_t destIpHost = ntohl(ipHdr->DstAddr);
        if (IsLocalIPv4(destIpHost)) { // ignoring local and intranet packets
            if (m_Logger->isEnabled(LOGGER_LEVEL_DEBUG)) {
                m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "packet_bypass reason=local_destination dst_ip=" + IpToString(ntohl(destIpHost)); });
            }
            WinDivertSend(m_Network, packet, packetLen, nullptr, &addr);
            return;
        }

        if (isUDP) {
            for (const auto& server : m_Servers) {
                if (localPort == server.localPort && ipHdr->DstAddr == server.serverAddr.sin_addr.s_addr &&
                    ntohs(udpHdr->DstPort) >= server.transport.portStart &&
                    ntohs(udpHdr->DstPort) <= server.transport.portEnd) {
                    WinDivertSend(m_Network, packet, packetLen, nullptr, &addr);
                    return;
                }
            }
        }
        const auto now = chrono::steady_clock::now();
        if (!ResolvePacket(packet, packetLen, addr, false, now)) {
            PendingPacket pending;
            pending.packetData.assign(packet, packet + packetLen);
            pending.addr = addr;
            pending.timestamp = now;
            if (!m_Pending.Push(move(pending), now, (uint32_t(ipHdr->Protocol) << 16) | localPort))
                RecordPacketWarning(packet, packetLen, "owner_queue_full", now, true, addr.Timestamp);
        }
    }    else { // inbound
        if (!ipHdr) { // ignoring ipv6
            WinDivertSend(m_Network, packet, packetLen, nullptr, &addr);
            return;
        }
        ServerContext* server = nullptr;
        for (auto& ctx : m_Servers) {
            if (isUDP && ipHdr->SrcAddr == ctx.serverAddr.sin_addr.s_addr &&
                ntohs(udpHdr->DstPort) == ctx.localPort &&
                ntohs(udpHdr->SrcPort) >= ctx.transport.portStart &&
                ntohs(udpHdr->SrcPort) <= ctx.transport.portEnd) {
                server = &ctx;
                break;
            }
        }

        if (server != nullptr && protocol == IPPROTO_UDP) {
            // ip-packet from one of miga servers - adding fragment to its udp assembler
            m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "tunnel_packet_received server_index=" + to_string(server->configIndex); });
            if (server->assembler->AddIpPacket(reinterpret_cast<const uint8_t*>(packet), packetLen)) {
                // we have at least 1 ready-made udp package - process it and release
                UdpPacketInfo* pkt;
                while ((pkt = server->assembler->GetCompleteUdpPacket()) != nullptr) {
                    SendUdpPacketToMstcp(pkt, &addr, *server);
                    server->assembler->ReleaseUdpPacket(pkt);
                }
            }
        }
        else {
            SocketTuple incoming;
            bool syn = false;
            if (ReadSocketPacket(packet, packetLen, incoming, syn)) {
                std::swap(incoming.localIp, incoming.remoteIp);
                std::swap(incoming.localPort, incoming.remotePort);
                m_Routing.ObserveInbound(incoming, addr.Timestamp, chrono::steady_clock::now());
            }
            WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
        }
    }
}

// place the assembled udp-packet into tcp/ip stack
bool PacketMonitor::SendUdpPacketToMstcp(const UdpPacketInfo* pkt, WINDIVERT_ADDRESS* pAddr, ServerContext& server) {
    if (!pkt || !pAddr || !pkt->payload || pkt->payloadSize < 28 || pkt->payloadSize > 65535) return false;

    m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "tunnel_packet_processing_started"; });

    // decrypt payload - original tranmitted packet
    server.encryption.Decrypt(pkt->payload, pkt->payloadSize, htons(pkt->srcPort));
    SocketTuple decoded;
    bool syn = false;
    if (!ReadSocketPacket(pkt->payload, pkt->payloadSize, decoded, syn)) return false;
    const auto innerLength = static_cast<UINT>((UINT(pkt->payload[2]) << 8) | pkt->payload[3]);
    const auto ipLength = size_t(pkt->payload[0] & 15) * 4;

    // clamp the mss in the remote's syn-ack so this host also sends small segments
    IP_HEADER* ip = reinterpret_cast<IP_HEADER*>(pkt->payload);
    if (pkt->payloadSize >= sizeof(IP_HEADER) && ip->protocol == IPPROTO_TCP &&
        (size_t)((ip->ver_hlen & 0x0F) * 4 + sizeof(TCP_HEADER)) <= pkt->payloadSize) {
        TCP_HEADER* tcp = reinterpret_cast<TCP_HEADER*>(pkt->payload + (ip->ver_hlen & 0x0F) * 4);
        if ((tcp->flags & 0x02) != 0 && (tcp->flags & 0x10) != 0) { // SYN-ACK
            ClampTcpMss(pkt->payload, pkt->payloadSize, m_Config->GetTunnelMaxMss());
        }
    }

    // recalc checksums (server don't do it)
    WinDivertHelperCalcChecksums(pkt->payload, innerLength, pAddr, 0);

    // check for dns response
    if (ip->protocol == IPPROTO_UDP) {
        const UDP_HEADER* udp = reinterpret_cast<const UDP_HEADER*>(pkt->payload + ipLength);
        uint16_t srcPort = ntohs(udp->src_port);
        if (srcPort == 53) {
            const uint8_t* dnsPayload = reinterpret_cast<const uint8_t*>(udp + 1);
            size_t dnsLen = ntohs(udp->length) - sizeof(UDP_HEADER);
            if (dnsLen >= 12) {
                uint16_t queryId = ntohs(*reinterpret_cast<const uint16_t*>(dnsPayload));
                // 3.x handle dns response - decide whether to inject into stack
                bool inject = HandleDNSResponse(dnsPayload, dnsLen, server.configIndex, queryId);
                if (!inject) {
                    m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_response_suppressed reason=auxiliary query_id=" + to_string(queryId); });
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
            m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_address_translated direction=reverse src_ip=" + IpToString(srcIpHost) + " translated_ip=" + IpToString(originalIp); });
            ip->src_ip = htonl(originalIp);
            WinDivertHelperCalcChecksums(pkt->payload, innerLength, pAddr, 0);
        }
    }

    if (m_Logger->isEnabled(LOGGER_LEVEL_DEBUG)) {
        uint8_t* ipPayload = pkt->payload + ipLength;

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
            flags = " tcp_flags_text=" + LogValue(tcpFlags(tcp->flags));

        }
        break;
        default:
            proto = "Unknown";
            srcPort = 0;
            dstPort = 0;
            flags = "";
        }
        m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "packet_received protocol=" + proto + " src=" + srcIp + ":" + to_string(srcPort) + " dst=" + dstIp + ":" + to_string(dstPort) + flags + " size=" + to_string(pkt->payloadSize); });
    }

    decoded = { decoded.protocol, ntohl(ip->dst_ip), decoded.remotePort,
        ntohl(ip->src_ip), decoded.localPort };
    m_Routing.ObserveInbound(decoded, pAddr->Timestamp, chrono::steady_clock::now(), server.id);
    UINT sended = 0;
    return WinDivertSend(m_Network, pkt->payload, innerLength, &sended, pAddr);
}

bool PacketMonitor::ResolvePacket(const uint8_t* packet, UINT length, const WINDIVERT_ADDRESS& addr,
    bool deadline, chrono::steady_clock::time_point receivedAt) {
    SocketTuple tuple;
    bool syn = false;
    if (!ReadSocketPacket(packet, length, tuple, syn)) {
        RecordPacketWarning(packet, length, "invalid_packet", receivedAt, true, addr.Timestamp);
        return true;
    }
    const auto now = chrono::steady_clock::now();
    const auto decision = deadline ? m_Routing.Expire(tuple, addr.Timestamp, syn, now) :
        m_Routing.Resolve(tuple, addr.Timestamp, syn, now);
    switch (decision.action) {
    case RoutingState::Action::AwaitOwner:
        return false;
    case RoutingState::Action::SelectRoute:
        ProcessPacket(packet, length, addr, decision.owner);
        return true;
    case RoutingState::Action::Send:
        if (!decision.owner && string_view(decision.reason) == "owner_deadline_direct")
            RecordPacketWarning(packet, length, decision.reason, receivedAt, false, addr.Timestamp);
        SendRoute(packet, length, addr, decision.route);
        return true;
    case RoutingState::Action::Drop:
        RecordPacketWarning(packet, length, decision.reason, receivedAt, true, addr.Timestamp);
        return true;
    }
    return true;
}

void PacketMonitor::SendRoute(const uint8_t* packet, UINT length, const WINDIVERT_ADDRESS& addr,
    const FlowRoute& route) {
    if (route.kind == FlowRoute::Kind::Direct) {
        WinDivertSend(m_Network, packet, length, nullptr, &addr);
        return;
    }
    for (auto& server : m_Servers) {
        if (server.id == route.serverId && route.kind == FlowRoute::Kind::Tunnel) {
            RedirectPacket(packet, length, addr, server, route.translatedIp);
            return;
        }
    }
    RecordPacketWarning(packet, length, "route_server_unavailable", chrono::steady_clock::now(), true, addr.Timestamp);
}

void PacketMonitor::DrainPending(uint32_t key) {
    const auto now = chrono::steady_clock::now();
    const auto resolve = [&](PendingPacket& packet, bool expired) {
        return ResolvePacket(packet.packetData.data(), static_cast<UINT>(packet.packetData.size()),
            packet.addr, expired, packet.timestamp);
    };
    if (key != 0) m_Pending.DrainMatching(key, now, resolve);
    else m_Pending.DrainExpired(now, resolve);
}

void PacketMonitor::RecordPacketWarning(const uint8_t* packet, UINT length, const char* reason,
    chrono::steady_clock::time_point receivedAt, bool dropped, int64_t packetTimestampQpc) {
    m_Logger->recordWarning(dropped ? NetworkWarning::RoutingDrop : NetworkWarning::PendingPidFallback);
    if (!m_Logger->isEnabled(LOGGER_LEVEL_WARNING)) return;
    if (m_WarningSampleCount == m_WarningSamples.size()) { ++m_OmittedWarnings; return; }
    auto& sample = m_WarningSamples[m_WarningSampleCount++];
    sample.packetTimestampQpc = packetTimestampQpc;
    sample.size = length;
    sample.captured = (std::min)(size_t(length), sample.header.size());
    memcpy(sample.header.data(), packet, sample.captured);
    sample.ownerLookup = reason;
    sample.ageMs = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - receivedAt).count();
}

void PacketMonitor::MaintainState() {
    m_Routing.Cleanup(chrono::steady_clock::now());
    m_ProcessNames.Cleanup();
    CleanupDnsState();
    for (size_t i = 0; i < m_WarningSampleCount; ++i)
        m_Logger->logLazy(LOGGER_LEVEL_WARNING, [&] {
            return "routing_packet " + FormatPacketWarning(m_WarningSamples[i]);
        });
    if (m_OmittedWarnings)
        m_Logger->logLazy(LOGGER_LEVEL_WARNING, [&] {
            return "routing_packet omitted=" + to_string(m_OmittedWarnings);
        });
    m_WarningSampleCount = m_OmittedWarnings = 0;
    for (auto& server : m_Servers)
        m_Logger->recordWarning(NetworkWarning::IncompleteFragments, 0, server.assembler->TakeExpiredIncompleteCount());
    m_EventQueueDelay.Flush([&](const string& message) {
        m_Logger->log(LOGGER_LEVEL_WARNING, message);
    });
    m_Logger->flushWarnings();
}

bool PacketMonitor::ReloadConfig(const string& path) {
    if (!m_Running.load()) return false;
    WorkItem item;
    item.reloadPath = path;
    item.reload = make_shared<promise<bool>>();
    auto result = item.reload->get_future();
    if (!m_Work.Push(move(item), &item.queuedAt)) return false;
    try { return result.get(); }
    catch (const exception&) { return false; }
}

void PacketMonitor::ClearDnsState() {
    m_ActualDns.clear();
    m_AuxiliaryDns.clear();
    m_ActualToAuxiliary.clear();
    m_DynamicIpMap.clear();
    m_DynamicIpReverse.clear();
    m_PendingDynamicIp.clear();
    m_ActualIpByQuery.clear();
    m_DnsTimestamp.clear();
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
    m_Routing.SetEvictionHandler([this](const SocketOwnerTable::Eviction& entry) {
        m_Logger->logLazy(LOGGER_LEVEL_ERROR, [&] { return entry.Describe(); });
    });
    m_Routing.SetOwnerChangeHandler([this](const SocketOwnerTable::Change& change) {
        if (change.state.owner->process->pid == m_ourPid) return;
        m_Logger->logLazy(LOGGER_LEVEL_INFO, [&] { return change.Describe(); });
    });
}

PacketMonitor::~PacketMonitor() {
    Stop();
}

void PacketMonitor::SeedExistingSockets() {
    LARGE_INTEGER captured;
    QueryPerformanceCounter(&captured);
    uint64_t id = 0;
    const auto seed = [&](const SocketTuple& tuple, DWORD pid) {
        auto process = GetProcessByPid(pid);
        if (!process->isAlive()) return;
        process->Name();
        auto owner = make_shared<const SocketOwner>(SocketOwner{ process, ++id, captured.QuadPart, true });
        const auto now = chrono::steady_clock::now();
        m_Routing.Observe(tuple, owner, now);
        if (tuple.protocol == IPPROTO_TCP) m_Routing.Commit(tuple, captured.QuadPart, owner, {}, now);
    };
    vector<uint8_t> buffer;
    DWORD size = 0;
    DWORD error = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    for (int attempt = 0; error == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt) {
        buffer.resize(size);
        error = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    if (error == NO_ERROR && !buffer.empty()) {
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwOwningPid == 0) continue;
            seed({ IPPROTO_TCP, ntohl(row.dwLocalAddr), ntohs(static_cast<u_short>(row.dwLocalPort)),
                ntohl(row.dwRemoteAddr), ntohs(static_cast<u_short>(row.dwRemotePort)) }, row.dwOwningPid);
        }
    }
    else m_Logger->log(LOGGER_LEVEL_WARNING, "socket_snapshot_failed protocol=TCP win32_error=" + to_string(error));
    buffer.clear();
    size = 0;
    error = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    for (int attempt = 0; error == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt) {
        buffer.resize(size);
        error = GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    }
    if (error == NO_ERROR && !buffer.empty()) {
        auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            seed({ IPPROTO_UDP, ntohl(row.dwLocalAddr), ntohs(static_cast<u_short>(row.dwLocalPort)), 0, 0 },
                row.dwOwningPid);
        }
    }
    else m_Logger->log(LOGGER_LEVEL_WARNING, "socket_snapshot_failed protocol=UDP win32_error=" + to_string(error));
}

bool PacketMonitor::Start() {
    if (m_Running.load()) {
        return false;
    }

    m_Running.store(true);

    random_device rd;
    m_rng.seed(rd());

    if (!InitUdpSocket(m_Config->GetServers())) {
        m_Logger->logLazy(LOGGER_LEVEL_ERROR, [&] { return "transport_init_failed protocol=UDP"; });
        Stop();
        return false;
    }

    if (!OpenSocketHandle()) {
        m_Logger->logLazy(LOGGER_LEVEL_ERROR, [&] { return "windivert_init_failed"; });
        Stop();
        return false;
    }

    m_Work.Reset();
    m_FreeNetworkBatches.Reset();
    for (size_t i = 0; i < NetworkBufferCount; ++i)
        m_FreeNetworkBatches.Push(make_unique<NetworkBatch>());

    m_SocketThread = thread(&PacketMonitor::SocketThread, this);
    SeedExistingSockets();
    if (!OpenNetworkHandle()) { Stop(); return false; }
    m_EventProcessThread = thread(&PacketMonitor::EventProcessThread, this);
    m_NetworkThread = thread(&PacketMonitor::NetworkThread, this);


    m_Logger->logLazy(LOGGER_LEVEL_INFO, [&] { return "packet_monitor_started"; });
    return true;
}

void PacketMonitor::Stop() {
    if (!m_Running.load()) {
        return;
    }

    {
        lock_guard lock(m_StopMutex);
        m_Running.store(false);
    }
    m_StopCondition.notify_all();
    m_Work.Close();
    m_FreeNetworkBatches.Close();

    if (m_Socket != INVALID_HANDLE_VALUE)
        WinDivertShutdown(m_Socket, WINDIVERT_SHUTDOWN_RECV);
    if (m_Network != INVALID_HANDLE_VALUE)
        WinDivertShutdown(m_Network, WINDIVERT_SHUTDOWN_RECV);

    if (m_NetworkThread.joinable()) m_NetworkThread.join();
    if (m_SocketThread.joinable()) m_SocketThread.join();
    if (m_EventProcessThread.joinable()) m_EventProcessThread.join();


    CloseUdpSockets();
    if (m_Socket != INVALID_HANDLE_VALUE) {
        WinDivertClose(m_Socket);
        m_Socket = INVALID_HANDLE_VALUE;
    }
    if (m_Network != INVALID_HANDLE_VALUE) {
        WinDivertClose(m_Network);
        m_Network = INVALID_HANDLE_VALUE;
    }
    m_Work.Reset();
    m_FreeNetworkBatches.Reset();

    m_Routing.Clear();
    ClearDnsState();
    m_Pending.Clear();
    m_EventQueueDelay.Clear();

    m_ProcessNames.Clear();

    m_Logger->logLazy(LOGGER_LEVEL_INFO, [&] { return "packet_monitor_stopped"; });
}


// initilize udp socket to send datagrams to each configured server
bool PacketMonitor::InitUdpSocket(const vector<ServerConfig>& servers) {
    static const int winsock = [] { WSADATA data; return WSAStartup(MAKEWORD(2, 2), &data); }();
    if (winsock != 0) return false;
    vector<ServerContext> next(servers.size());
    vector<size_t> reuse(servers.size(), m_Servers.size());
    vector<size_t> oldToNew(m_Servers.size(), servers.size());
    const auto cancel = [&] {
        for (auto& server : next)
            if (server.udpSocket != INVALID_SOCKET) closesocket(server.udpSocket);
        return false;
    };
    for (size_t i = 0; i < servers.size(); ++i) {
        for (size_t j = 0; j < m_Servers.size(); ++j) {
            if (oldToNew[j] == servers.size() && servers[i].SameTransport(m_Servers[j].transport)) {
                reuse[i] = j;
                oldToNew[j] = i;
                break;
            }
        }
        if (reuse[i] != m_Servers.size()) continue;
        auto& context = next[i];
        context.configIndex = i;
        context.id = m_NextServerId++;
        context.transport.serverIP = servers[i].serverIP;
        context.transport.portStart = servers[i].portStart;
        context.transport.portEnd = servers[i].portEnd;
        context.transport.xorKeyBase64 = servers[i].xorKeyBase64;
        context.transport.swapKeyBase64 = servers[i].swapKeyBase64;
        context.assembler = make_unique<UdpPacketAssembler>();
        if (!context.encryption.Initialize(servers[i].xorKeyBase64, servers[i].swapKeyBase64)) return cancel();
        context.serverAddr = {};
        context.serverAddr.sin_family = AF_INET;
        if (inet_pton(AF_INET, servers[i].serverIP.c_str(), &context.serverAddr.sin_addr) != 1) {
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            addrinfo* address = nullptr;
            if (getaddrinfo(servers[i].serverIP.c_str(), nullptr, &hints, &address) != 0) return cancel();
            context.serverAddr = *reinterpret_cast<sockaddr_in*>(address->ai_addr);
            freeaddrinfo(address);
        }
        context.udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
        if (context.udpSocket == INVALID_SOCKET) return cancel();
        BOOL exclusive = TRUE;
        if (setsockopt(context.udpSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) != 0) return cancel();
        sockaddr_in local{};
        local.sin_family = AF_INET;
        if (::bind(context.udpSocket, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) return cancel();
        int length = sizeof(local);
        if (getsockname(context.udpSocket, reinterpret_cast<sockaddr*>(&local), &length) != 0) return cancel();
        context.localPort = ntohs(local.sin_port);
    }
    const auto remapValues = [&](auto& map) {
        for (auto it = map.begin(); it != map.end();) {
            if (it->second >= oldToNew.size() || oldToNew[it->second] == servers.size()) it = map.erase(it);
            else { it->second = oldToNew[it->second]; ++it; }
        }
    };
    const auto remapKeys = [&](auto& map) {
        std::decay_t<decltype(map)> updated;
        for (const auto& item : map) {
            const auto old = static_cast<uint32_t>(item.first);
            if (old < oldToNew.size() && oldToNew[old] != servers.size())
                updated.emplace((item.first & 0xFFFFFFFF00000000ull) | oldToNew[old], item.second);
        }
        map = move(updated);
    };
    remapValues(m_ActualDns);
    remapValues(m_AuxiliaryDns);
    remapKeys(m_DynamicIpMap);
    remapKeys(m_DynamicIpReverse);
    for (auto& query : m_PendingDynamicIp) {
        unordered_map<size_t, uint32_t> updated;
        for (const auto& item : query.second)
            if (item.first < oldToNew.size() && oldToNew[item.first] != servers.size())
                updated.emplace(oldToNew[item.first], item.second);
        query.second = move(updated);
    }
    unordered_set<size_t> ids;
    for (size_t i = 0; i < next.size(); ++i) {
        if (reuse[i] != m_Servers.size()) {
            next[i] = move(m_Servers[reuse[i]]);
            m_Servers[reuse[i]].udpSocket = INVALID_SOCKET;
            next[i].configIndex = i;
        }
        ids.insert(next[i].id);
    }
    for (auto& old : m_Servers)
        if (old.udpSocket != INVALID_SOCKET) closesocket(old.udpSocket);
    m_Servers = move(next);
    m_Routing.RetainServers(ids);
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


// process received outbound packet
void PacketMonitor::ProcessPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr,
    const shared_ptr<const SocketOwner>& owner) {
    const auto& process = owner->process;
    SocketTuple tuple;
    bool syn = false;
    if (!ReadSocketPacket(packet, packetLen, tuple, syn)) return;
    const auto commit = [&](FlowRoute route) {
        if (!m_Routing.Commit(tuple, addr.Timestamp, owner, route, chrono::steady_clock::now())) {
            RecordPacketWarning(packet, packetLen, "flow_capacity_or_stale_generation",
                chrono::steady_clock::now(), true, addr.Timestamp);
            return;
        }
        SendRoute(packet, packetLen, addr, route);
    };
    const auto pid = process->pid;
    if (pid == 4 || pid == m_ourPid) { // SYSTEM or own
        WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
        return;
    }

    const IP_HEADER* iph = reinterpret_cast<const IP_HEADER*>(packet);

    if (iph->protocol == IPPROTO_UDP) {
        const UDP_HEADER* udph = reinterpret_cast<const UDP_HEADER*>(packet + ((packet[0] & 15) * 4));
        uint16_t dstPort = ntohs(udph->dst_port);
        if (addr.Outbound && dstPort == 53) { // outbound DNS query
            const uint8_t* udpPayload = packet + ((packet[0] & 15) * 4) + sizeof(UDP_HEADER);
            size_t udpPayloadLen = packetLen - ((packet[0] & 15) * 4 + sizeof(UDP_HEADER));
            if (udpPayloadLen > 0) {
                string domain;
                if (ExtractDomainFromDNSQuery(udpPayload, udpPayloadLen, domain) && !domain.empty()) {
                    uint16_t queryId = ntohs(*reinterpret_cast<const uint16_t*>(udpPayload));

                    // 1. process rules take priority over domain rules
                    string processName = process->Name();
                    const ServerConfig* procServer = FindServerByProcessRule(processName);
                    if (procServer != nullptr) {
                        ServerContext* procCtx = FindServerContext(procServer);
                        if (procCtx != nullptr) {
                            RedirectDNSQuery(packet, packetLen, addr, procCtx, queryId, "process: " + processName);
                            return;
                        }
                    }

                    // 2. domain rules
                    const ServerConfig* dnsServer = m_Config->FindServerByDomain(domain);
                    if (dnsServer != nullptr) {
                        ServerContext* dnsCtx = FindServerContext(dnsServer);
                        if (dnsCtx != nullptr) {
                            RedirectDNSQuery(packet, packetLen, addr, dnsCtx, queryId, "domain: " + domain);
                            return;
                        }
                        WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
                    }
                    else {
                        m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_query_bypass reason=no_matching_rule domain=" + LogValue(domain); });
                        WinDivertSend(m_Network, packet, packetLen, NULL, &addr);
                    }
                    return;
                }
            }
        }
    }

    if (tuple.protocol == IPPROTO_TCP && !syn) {
        commit({});
        return;
    }
    const auto* target = CheckRules(process->Name(), tuple.remoteIp);
    auto* server = target ? FindServerContext(target) : nullptr;
    if (!server) {
        commit({});
        return;
    }
    uint32_t translated = 0;
    LookupIpTranslation(tuple.remoteIp, server->configIndex, translated);
    commit({ FlowRoute::Kind::Tunnel, server->id, translated });
}
// redirecting ip packet to server
void PacketMonitor::RedirectPacket(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr, ServerContext& server, uint32_t newDstIp, uint16_t dnsQueryIdOverride) {

    // copy and encrypt packet
    if (packetLen > 1472)
        m_Logger->recordWarning(NetworkWarning::LargeTunnelPacket, static_cast<uint64_t>(packetLen) + 28);
    auto& outgoingPacket = m_OutgoingPacket;
    outgoingPacket.assign(packet, packet + packetLen);

    IP_HEADER* ipHeader = reinterpret_cast<IP_HEADER*>(outgoingPacket.data());

    if (newDstIp != 0) {
        ipHeader->dst_ip = htonl(newDstIp);
    }

    if (dnsQueryIdOverride != 0 && ipHeader->protocol == IPPROTO_UDP) {

        uint8_t* udpPayload = outgoingPacket.data() + ((outgoingPacket[0] & 15) * 4) + sizeof(UDP_HEADER);
        if (udpPayload + 2 <= outgoingPacket.data() + packetLen) {
            uint16_t* pQueryId = reinterpret_cast<uint16_t*>(udpPayload);
            *pQueryId = htons(dnsQueryIdOverride);
        }
    }

    // clamp the advertised mss so tunneled connections never exceed the safe payload size
    bool mssClamped = false;
    if (ipHeader->protocol == IPPROTO_TCP) {
        const TCP_HEADER* tcp = reinterpret_cast<const TCP_HEADER*>(outgoingPacket.data() + (ipHeader->ver_hlen & 0x0F) * 4);
        if ((tcp->flags & 0x02) != 0) { // SYN
            mssClamped = ClampTcpMss(outgoingPacket.data(), outgoingPacket.size(), m_Config->GetTunnelMaxMss());
        }
    }

    // recalc checksums after any ip/payload rewrite
    if (newDstIp != 0 || dnsQueryIdOverride != 0 || mssClamped) {
        WinDivertHelperCalcChecksums(outgoingPacket.data(), static_cast<UINT>(outgoingPacket.size()), NULL, 0);
    }

    const ServerConfig& cfg = server.transport;

    // select a random udp port based on the packet checksum
    uint16_t serverPort;
    {
        lock_guard<mutex> lock(m_RngMutex);
        serverPort = uniform_int_distribution<uint16_t>(cfg.portStart, cfg.portEnd)(m_rng);
    }

    server.encryption.Encrypt(outgoingPacket.data(), outgoingPacket.size(), serverPort);

    sockaddr_in serverAddr = server.serverAddr;
    serverAddr.sin_port = htons(serverPort);
    int sent = sendto(server.udpSocket,
        (const char*)outgoingPacket.data(),
        static_cast<int>(outgoingPacket.size()),
        0,
        (sockaddr*)&serverAddr,
        sizeof(serverAddr));

    if (sent == SOCKET_ERROR) {
        if (m_Logger->isEnabled(LOGGER_LEVEL_ERROR))
            m_Logger->logLazy(LOGGER_LEVEL_ERROR, [&] { return "tunnel_send_failed direction=to_server wsa_error=" + to_string(WSAGetLastError()); });
        return;
    }
}

// getting process name by pid
ProcessOwner PacketMonitor::GetProcessByPid(DWORD pid) {
    return m_ProcessNames.Get(pid, LoadWindowsProcessIdentity);
}

// checking rules for packet, returns first matching server or nullptr
const ServerConfig* PacketMonitor::CheckRules(const string& processName, UINT32 destIp) {
    const ServerConfig* processServer = FindServerByProcessRule(processName);
    if (processServer != nullptr) {
        return processServer;
    }

    for (const auto& server : m_Config->GetServers()) {
        if (server.staticIPRule.matches(destIp)) {
            return &server;
        }
    }

    return m_Config->FindServerByDynamicIP(destIp);
}

const ServerConfig* PacketMonitor::FindServerByProcessRule(const string& processName) const {
    return m_Config->FindServerByProcess(processName);
}

// redirect a dns query: send it to the "actual" server with the original query id and
// send generated-id copies to every other server (aux) to build the ip correspondence
void PacketMonitor::RedirectDNSQuery(const uint8_t* packet, UINT packetLen, const WINDIVERT_ADDRESS& addr,
    ServerContext* actual, uint16_t queryId, const string& reason) {
    {
        unique_lock lock(m_DnsMutex);
        m_ActualDns[queryId] = actual->configIndex;
        m_ActualIpByQuery[queryId] = 0;
        m_DnsTimestamp[queryId] = chrono::steady_clock::now();
    }

    m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_query_redirected role=primary reason=" + LogValue(reason) +
        " server_index=" + to_string(actual->configIndex) + " query_id=" + to_string(queryId); });
    RedirectPacket(packet, packetLen, addr, *actual);

    for (auto& other : m_Servers) {
        if (other.configIndex == actual->configIndex)
            continue;

        uint16_t auxId;
        {
            unique_lock lock(m_DnsMutex);
            auxId = GenerateUniqueQueryId();
            m_AuxiliaryDns[auxId] = other.configIndex;
            m_ActualToAuxiliary[auxId] = queryId;
            m_DnsTimestamp[auxId] = chrono::steady_clock::now();
        }

        m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_query_redirected role=auxiliary reason=" + LogValue(reason) +
            " server_index=" + to_string(other.configIndex) + " query_id=" + to_string(auxId); });
        RedirectPacket(packet, packetLen, addr, other, 0, auxId);
    }
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
        {
            lock_guard<mutex> lock(m_RngMutex);
            candidate = static_cast<uint16_t>(uniform_int_distribution<int>(1, 0xFFFF)(m_rng));
        }
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
        auto pending = m_PendingDynamicIp.find(queryId);
        if (pending != m_PendingDynamicIp.end() && ip != 0) {
            for (const auto& [srv, auxIp] : pending->second) {
                uint64_t fwdKey = ((uint64_t)ip << 32) | (uint64_t)(srv & 0xFFFFFFFF);
                uint64_t revKey = ((uint64_t)auxIp << 32) | (uint64_t)(srv & 0xFFFFFFFF);
                m_DynamicIpMap[fwdKey] = auxIp;
                m_DynamicIpReverse[revKey] = ip;
            }
            m_PendingDynamicIp.erase(pending);
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
            if (m_Logger->isEnabled(LOGGER_LEVEL_DEBUG))
                m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_address_mapping_added original_ip=" + IpToString(origIp) + " translated_ip=" + IpToString(ip) +
                    " server_index=" + to_string(serverIndex); });
        }
        else {
            // original response ip not yet known - keep pending by original query id
            m_PendingDynamicIp[origQid][serverIndex] = ip;
            if (m_Logger->isEnabled(LOGGER_LEVEL_DEBUG))
                m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_address_mapping_pending reason=awaiting_original translated_ip=" + IpToString(ip) +
                    " server_index=" + to_string(serverIndex); });
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
            m_PendingDynamicIp.erase(qid);
            it = m_DnsTimestamp.erase(it);
            if (m_Logger->isEnabled(LOGGER_LEVEL_DEBUG))
                m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_state_expired query_id=" + to_string(qid); });
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
            if (m_Logger->isEnabled(LOGGER_LEVEL_DEBUG))
                m_Logger->logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_dynamic_ip_added ip=" + IpToString(ipHost) + " ttl_seconds=" + std::to_string(ttl); });
        }
        offset += rdlength;
    }
}
