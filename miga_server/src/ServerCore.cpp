#include "ServerCore.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>
#include <fcntl.h>
#include <errno.h>
#include <sstream>
#include <ifaddrs.h>
#include <chrono>
#include <thread>
#include <poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>


using json = nlohmann::json;
using namespace std;

string IpToString(uint32_t ip) {
    stringstream ss;
    ss << ((ip >> 0) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "." << ((ip >> 24) & 0xFF);
    return ss.str();
}

// check tcp flags for debuging from tcp header
string tcpFlags(tcphdr* tcp) {
    vector<string> active_flags;

    if (tcp->fin) active_flags.push_back("FIN");
    if (tcp->syn) active_flags.push_back("SYN");
    if (tcp->rst) active_flags.push_back("RST");
    if (tcp->psh) active_flags.push_back("PSH");
    if (tcp->ack) active_flags.push_back("ACK");
    if (tcp->urg) active_flags.push_back("URG");
    if (tcp->ece) active_flags.push_back("ECE");
    if (tcp->cwr) active_flags.push_back("CWR");

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

// calculate internet checksum
static uint16_t in_cksum(uint16_t* addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t* w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = static_cast<uint16_t>(~sum);
    return answer;
}

// calculate tcp checksum
uint16_t tcp_checksum(const struct iphdr* ip, const struct tcphdr* tcp) {
    uint16_t tcp_len = ntohs(ip->tot_len) - ip->ihl * 4;
    // Псевдозаголовок
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } pseudo;
    pseudo.saddr = ip->saddr;
    pseudo.daddr = ip->daddr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(tcp_len);

    vector<uint8_t> buf(sizeof(pseudo) + tcp_len);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), tcp, tcp_len);

    return in_cksum((uint16_t*)buf.data(), buf.size());
}

// calculate udp checksum
uint16_t udp_checksum(const struct iphdr* ip, const struct udphdr* udp) {
    uint16_t udp_len = ntohs(udp->len);
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo;
    pseudo.saddr = ip->saddr;
    pseudo.daddr = ip->daddr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.udp_len = udp->len;

    vector<uint8_t> buf(sizeof(pseudo) + udp_len);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), udp, udp_len);

    return in_cksum((uint16_t*)buf.data(), buf.size());
}

ServerCore::ServerCore()
    : m_socket(-1)
    , m_recvBuffer(65536)
    , m_logger()
    , m_running(false) {
    m_config.log_level = LOGGER_LEVEL_NONE;
}

ServerCore::~ServerCore() {
    Stop();
    if (m_socket >= 0) close(m_socket);
}

// get ip of interface
uint32_t ServerCore::GetInterfaceIP() {
    struct ifaddrs* ifaddr, * ifa;
    uint32_t ip = 0;
    if (getifaddrs(&ifaddr) == -1) return 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            if (m_config.interface.empty() || strcmp(ifa->ifa_name, m_config.interface.c_str()) == 0) {
                ip = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return ip;
}

// send unpacked ip packet to tun
void ServerCore::SendPacket(const uint8_t* packet, size_t len) {
    ssize_t n = write(m_tunfd, packet, len);
    if (n < 0) {
        m_logger.log(LOGGER_LEVEL_ERROR, "SendPacket error: " + string(strerror(errno)));
        return;
    }
    if ((size_t)n != len) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Partial write to tun");
        return;
    }
    return;
}

// initialize raw udp socket to snif inbound packets from clients
bool ServerCore::InitSocket() {

    m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (m_socket < 0) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Failed to create RAW socket (need root)");
        return false;
    }
    int one = 1;
    if (setsockopt(m_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Failed to set sockopt IP_HDRINCL");
        return false;
    }

    m_logger.log(LOGGER_LEVEL_INFO, "RAW socket created");
    return true;
}

// create tun to receive and send packets to target server
bool ServerCore::CreateTUN(const char* dev_name) {
    struct ifreq ifr;

    // Открываем клон-устройство TUN
    if ((m_tunfd = open("/dev/net/tun", O_RDWR)) < 0) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Error while creating tun: can't open /dev/net/tun");
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN — IP-packets without Ethernet-header
    // IFF_NO_PI — don't add addditional info

    if (*dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    if (ioctl(m_tunfd, TUNSETIFF, (void*)&ifr) < 0) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Error while creating tun: ioctl TUNSETIFF");
        close(m_tunfd);
        return false;
    }
    
    string msg = "TUN interface created: ";
    msg += ifr.ifr_name;
    m_logger.log(LOGGER_LEVEL_INFO, msg);

    int flags = fcntl(m_tunfd, F_GETFL, 0);
    fcntl(m_tunfd, F_SETFL, flags | O_NONBLOCK);

    //enable ip-forward
    const char* ip_forward_path = "/proc/sys/net/ipv4/ip_forward";
    ifstream ifs(ip_forward_path);
    if (ifs.is_open()) {
        string value;
        getline(ifs, value);
        ifs.close();
        if (value != "1") {
            ofstream ofs(ip_forward_path);
            if (ofs.is_open()) {
                ofs << "1";
                ofs.close();
            }
            else {
                m_logger.log(LOGGER_LEVEL_ERROR, "Failed to enable IP forwarding");
                close(m_tunfd);
                return false;
            }
        }
    }

    // some system commands
    system(("ip addr add 10.0.0.1/24 dev " + string(dev_name)).c_str());
    system(("ip link set " + string(dev_name) + " up").c_str());

    return true;
}

// procces packet from client
void ServerCore::HandleClientPacket(const uint8_t* ipPacket, size_t ipLen, uint16_t dstPort) {

    if (dstPort < m_config.client_port_start || dstPort > m_config.client_port_end) {
        return;
    }

    struct iphdr* ip = (struct iphdr*)ipPacket;
    if (ip->protocol != IPPROTO_UDP) {
        return;
    }

    // add ip-packet to udp assembler
    if (m_assembler.AddIpPacket(ipPacket, ipLen)) {
        // we have at least 1 ready-made udp package - process it and release
        UdpPacketInfo* pkt;
        while ((pkt = m_assembler.GetCompleteUdpPacket()) != nullptr) {
            ProcessClientUdpPacket(pkt);
            m_assembler.ReleaseUdpPacket(pkt);
        }
    }
}

// process udp packet from client
void ServerCore::ProcessClientUdpPacket(UdpPacketInfo* pkt) {
    uint8_t* udpPayload = pkt->payload;
    size_t payloadLen = pkt->payloadSize;

    vector<uint8_t> decrypted(udpPayload, udpPayload + payloadLen);
    m_encryption.Decrypt(decrypted.data(), decrypted.size(), htons(pkt->dstPort));

    const uint8_t* origIpPacket = decrypted.data();
    size_t origIpLen = decrypted.size();

    struct iphdr* origIp = nullptr;
    size_t origIpHeaderLen = 0;
    if (!ValidateInnerIpPacket(origIpPacket, origIpLen, origIp, origIpHeaderLen)) {
        return;
    }

    uint32_t original_dst_ip = origIp->daddr;
    uint16_t original_dst_port = 0;
    uint32_t original_src_ip = origIp->saddr;
    uint16_t original_src_port = 0;
    string proto, flags = "";

    if (origIp->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(origIpPacket + origIpHeaderLen);
        original_src_port = ntohs(tcp->source);
        original_dst_port = ntohs(tcp->dest);
        proto = "TCP";
        if (m_logger.isEnabled()) {
            flags = " flags=" + tcpFlags(tcp);
        }
    }
    else if (origIp->protocol == IPPROTO_UDP) {
        struct udphdr* udpInner = (struct udphdr*)(origIpPacket + origIpHeaderLen);
        original_src_port = ntohs(udpInner->source);
        original_dst_port = ntohs(udpInner->dest);
        proto = "UDP";
    }

    bool dnsRedirect = false;
    uint32_t saved_dst_ip = original_dst_ip;

    if (m_config.dns_server && origIp->protocol == IPPROTO_UDP && original_dst_port == 53) {
        dnsRedirect = true;
        original_dst_ip = m_config.dns_server;
        if (m_logger.isEnabled()) {
            m_logger.log(LOGGER_LEVEL_INFO, "DNS redirect: " + IpToString(saved_dst_ip) + " -> " + IpToString(m_config.dns_server));
        }
    }

    uint32_t client_ip = pkt->srcIp;
    uint16_t client_udp_port = ntohs(pkt->srcPort);
    uint16_t local_udp_port = ntohs(pkt->dstPort);
    auto connKey = make_tuple(original_src_ip, original_src_port, original_dst_ip, original_dst_port, origIp->protocol);

    uint16_t chosen_src_port = 0;
    bool isNewConnection = false;

    if (origIp->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(origIpPacket + origIpHeaderLen);
        isNewConnection = (tcp->syn && !tcp->ack);
    }
    else if (origIp->protocol == IPPROTO_UDP) {
        isNewConnection = true;
    }

    {
        lock_guard<mutex> lock(m_connMutex);
        auto it = m_connPortMap.find(connKey);
        if (it != m_connPortMap.end()) {
            chosen_src_port = it->second.port;
            it->second.last_used = chrono::steady_clock::now();
            if (m_logger.isEnabled())
                m_logger.log(LOGGER_LEVEL_DEBUG, "  Using existing port=" + to_string(chosen_src_port));
        }
        else if (isNewConnection) {
            bool port_found = false;
            for (int attempt = 0; attempt < 10; ++attempt) {
                chosen_src_port = m_portDist(m_rng);
                auto key = make_tuple(chosen_src_port, origIp->protocol);
                lock_guard<mutex> lock_table(m_tableMutex);
                if (m_forwardTable.find(key) == m_forwardTable.end()) {
                    port_found = true;
                    break;
                }
            }
            if (!port_found) {
                m_logger.log(LOGGER_LEVEL_ERROR, "No free source port for destination " + IpToString(original_dst_ip));
                return;
            }
            PortInfo info;
            info.port = chosen_src_port;
            info.last_used = chrono::steady_clock::now();
            m_connPortMap[connKey] = info;
            if (m_logger.isEnabled())
                m_logger.log(LOGGER_LEVEL_DEBUG, "  Generated new port=" + to_string(chosen_src_port));
        }
        else {
            if (origIp->protocol == IPPROTO_TCP) {
                m_logger.log(LOGGER_LEVEL_INFO, "  Ignoring non-SYN TCP packet for unknown connection");
            }
            else {
                m_logger.log(LOGGER_LEVEL_INFO, "  Ignoring UDP packet for unknown connection (should not happen)");
            }
            return;
        }
    }

    if (m_logger.isEnabled()) {
        m_logger.log(LOGGER_LEVEL_INFO, "CLIENT->SERVER: " + proto + " " + IpToString(origIp->saddr) + ":" + to_string(original_src_port) +
            " to " + IpToString(origIp->daddr) + ":" + to_string(original_dst_port) + " (fwd_srv_port=" + to_string(chosen_src_port) + ")" + flags);
    }

    vector<uint8_t> outPacket(origIpLen);
    memcpy(outPacket.data(), origIpPacket, origIpLen);
    struct iphdr* outIp = (struct iphdr*)outPacket.data();

    outIp->daddr = original_dst_ip;

    uint32_t server_ip = inet_addr("10.0.0.2");
    outIp->saddr = server_ip;
    outIp->check = 0;
    outIp->check = in_cksum((uint16_t*)outIp, outIp->ihl * 4);

    if (outIp->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(outPacket.data() + outIp->ihl * 4);
        tcp->source = htons(chosen_src_port);
        tcp->check = 0;
        tcp->check = tcp_checksum(outIp, tcp);
    }
    else if (outIp->protocol == IPPROTO_UDP) {
        struct udphdr* udpOut = (struct udphdr*)(outPacket.data() + outIp->ihl * 4);
        udpOut->source = htons(chosen_src_port);
        udpOut->check = 0;
        udpOut->check = udp_checksum(outIp, udpOut);
    }

    SendPacket(outPacket.data(), outPacket.size());

    ClientInfo info;
    info.local_udp_port = local_udp_port;
    info.client_ip = client_ip;
    info.client_udp_port = client_udp_port;
    info.original_src_ip = original_src_ip;
    info.original_src_port = original_src_port;
    info.original_dst_ip = saved_dst_ip;
    info.last_used = chrono::steady_clock::now();

    auto key = make_tuple(chosen_src_port, origIp->protocol);
    {
        lock_guard<mutex> lock(m_tableMutex);
        m_forwardTable[key] = info;
        if (m_logger.isEnabled()) {
            stringstream ss;
            ss << "Adding forward entry: original_dst_ip=" << inet_ntoa(*(in_addr*)&original_dst_ip)
                << " chosen_src_port=" << chosen_src_port;
            m_logger.log(LOGGER_LEVEL_DEBUG, ss.str());
        }
    }
}

bool ServerCore::ValidateInnerIpPacket(const uint8_t* packet, size_t len, struct iphdr*& outIp, size_t& outIpHeaderLen) {
    if (len < sizeof(struct iphdr)) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Inner IP packet too short for IP header");
        return false;
    }

    struct iphdr* ip = (struct iphdr*)packet;

    // ip version
    if (ip->version != 4) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Inner IP packet has invalid version (must be 4)");
        return false;
    }

    // header length
    uint8_t ihl = ip->ihl;
    if (ihl < 5 || ihl > 15) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Inner IP packet has invalid header length: " + to_string(ihl));
        return false;
    }

    size_t ipHeaderLen = ihl * 4;
    if (len < ipHeaderLen) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Inner IP packet too short for claimed header length");
        return false;
    }

    // packet length
    uint16_t totalLen = ntohs(ip->tot_len);
    if (totalLen < ipHeaderLen) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Inner IP total length less than header length");
        return false;
    }
    if (totalLen > len) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Inner IP packet larger than available data");
        return false;
    }

    // protocol
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Inner IP packet has unsupported protocol: " + to_string(ip->protocol));
        return false;
    }

    // transport header
    size_t transportOffset = ipHeaderLen;
    if (ip->protocol == IPPROTO_TCP) {
        if (totalLen < transportOffset + sizeof(struct tcphdr)) {
            m_logger.log(LOGGER_LEVEL_ERROR, "Inner TCP packet too short for TCP header");
            return false;
        }
        struct tcphdr* tcp = (struct tcphdr*)(packet + transportOffset);
        uint8_t tcpHeaderLen = tcp->doff * 4;
        if (tcpHeaderLen < sizeof(struct tcphdr)) {
            m_logger.log(LOGGER_LEVEL_ERROR, "Inner TCP header length too small");
            return false;
        }
        if (transportOffset + tcpHeaderLen > totalLen) {
            m_logger.log(LOGGER_LEVEL_ERROR, "Inner TCP packet truncated");
            return false;
        }
    }
    else if (ip->protocol == IPPROTO_UDP) {
        if (totalLen < transportOffset + sizeof(struct udphdr)) {
            m_logger.log(LOGGER_LEVEL_ERROR, "Inner UDP packet too short for UDP header");
            return false;
        }
        struct udphdr* udp = (struct udphdr*)(packet + transportOffset);
        uint16_t udpLen = ntohs(udp->len);
        if (udpLen < sizeof(struct udphdr)) {
            m_logger.log(LOGGER_LEVEL_ERROR, "Inner UDP length field too small");
            return false;
        }
        if (transportOffset + udpLen > totalLen) {
            m_logger.log(LOGGER_LEVEL_ERROR, "Inner UDP packet truncated");
            return false;
        }
    }

    outIp = ip;
    outIpHeaderLen = ipHeaderLen;
    return true;
}

void ServerCore::HandleInternetPacket(const uint8_t* ipPacket, size_t ipLen, uint16_t dstPort) {
    if (m_logger.isEnabled())
        m_logger.log(LOGGER_LEVEL_DEBUG, "HandleInternetPacket called, dstPort=" + to_string(dstPort));

    if (dstPort < SRC_PORT_START || dstPort > SRC_PORT_END) return;

    struct iphdr* ip = (struct iphdr*)ipPacket;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return;

    size_t ipHeaderLen = ip->ihl * 4;
    if (ipLen < ipHeaderLen) return;

    uint16_t srcPort = 0;
    if (ip->protocol == IPPROTO_TCP) {
        if (ipLen < ipHeaderLen + sizeof(struct tcphdr)) return;
        struct tcphdr* tcp = (struct tcphdr*)(ipPacket + ipHeaderLen);
        srcPort = ntohs(tcp->source);
    }
    else if (ip->protocol == IPPROTO_UDP) {
        if (ipLen < ipHeaderLen + sizeof(struct udphdr)) return;
        struct udphdr* udp = (struct udphdr*)(ipPacket + ipHeaderLen);
        srcPort = ntohs(udp->source);
    }

    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip_str, INET_ADDRSTRLEN);

    auto key = make_tuple(dstPort, ip->protocol);
    ClientInfo info;
    bool found = false;
    {
        lock_guard<mutex> lock(m_tableMutex);
        auto it = m_forwardTable.find(key);
        if (it != m_forwardTable.end()) {
            info = it->second;
            found = true;
            it->second.last_used = chrono::steady_clock::now();
        }
    }

    if (m_logger.isEnabled()) {
        stringstream ss;
        ss << "Looking for key: src_ip=" << src_ip_str << " dst_port=" << dstPort;
        m_logger.log(LOGGER_LEVEL_DEBUG, ss.str());
    }

    if (!found) {
        m_logger.log(LOGGER_LEVEL_INFO, "No client found for packet");
        return;
    }

    if (m_logger.isEnabled()) {
        stringstream ss2;
        ss2 << "Found client for " << src_ip_str << ":" << srcPort
            << " -> " << dst_ip_str << ":" << dstPort
            << " client=" << inet_ntoa(*(in_addr*)&info.client_ip) << ":" << info.client_udp_port
            << " original client = " << inet_ntoa(*(in_addr*)&info.original_src_ip) << ":" << info.original_src_port;
        m_logger.log(LOGGER_LEVEL_DEBUG, ss2.str());
    }

    bool shouldRemove = false;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(ipPacket + ipHeaderLen);
        if (tcp->fin || tcp->rst) {
            shouldRemove = true;
        }
    }

    vector<uint8_t> outPacket(ipLen);
    memcpy(outPacket.data(), ipPacket, ipLen);
    struct iphdr* outIp = (struct iphdr*)outPacket.data();
    outIp->daddr = info.original_src_ip;
    outIp->saddr = info.original_dst_ip;

    if (outIp->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(outPacket.data() + outIp->ihl * 4);
        tcp->dest = htons(info.original_src_port);
    }
    else if (outIp->protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(outPacket.data() + outIp->ihl * 4);
        udp->dest = htons(info.original_src_port);
    }

    if (m_logger.isEnabled()) {
        string proto, flags = "";
        uint16_t logSrcPort = 0, logDestPort = 0;
        if (outIp->protocol == IPPROTO_TCP) {
            struct tcphdr* tcp = (struct tcphdr*)(outPacket.data() + outIp->ihl * 4);
            logSrcPort = ntohs(tcp->source);
            logDestPort = ntohs(tcp->dest);
            proto = "TCP";
            flags = " flags=" + tcpFlags(tcp);
        }
        else if (outIp->protocol == IPPROTO_UDP) {
            struct udphdr* udp = (struct udphdr*)(outPacket.data() + outIp->ihl * 4);
            logSrcPort = ntohs(udp->source);
            logDestPort = ntohs(udp->dest);
            proto = "UDP";
        }

        m_logger.log(LOGGER_LEVEL_INFO, "SERVER->CLIENT: " + proto + " " + IpToString(outIp->saddr) + ":" + to_string(logSrcPort) +
            " to " + IpToString(outIp->daddr) + ":" + to_string(logDestPort) + " (fwd_srv_port=" + to_string(dstPort) + ")" + flags);
    }

    vector<uint8_t> responsePacket(outPacket.size());
    memcpy(responsePacket.data(), outPacket.data(), outPacket.size());

    m_encryption.Encrypt(responsePacket.data(), responsePacket.size(), info.local_udp_port);

    struct iphdr udpIp;
    memset(&udpIp, 0, sizeof(udpIp));
    udpIp.version = 4;
    udpIp.ihl = 5;
    udpIp.tot_len = htons(static_cast<uint16_t>(sizeof(udpIp) + sizeof(struct udphdr) + responsePacket.size()));
    udpIp.id = htons(static_cast<uint16_t>(rand() & 0xFFFF));
    udpIp.ttl = 64;
    udpIp.protocol = IPPROTO_UDP;
    udpIp.saddr = GetInterfaceIP();
    udpIp.daddr = info.client_ip;
    udpIp.check = 0;
    udpIp.check = in_cksum((uint16_t*)&udpIp, static_cast<int>(sizeof(udpIp)));

    struct udphdr udpHeader;
    udpHeader.source = htons(info.local_udp_port);
    udpHeader.dest = htons(info.client_udp_port);
    udpHeader.len = htons(static_cast<uint16_t>(sizeof(udphdr) + responsePacket.size()));
    udpHeader.check = 0;

    vector<uint8_t> udpPacket(sizeof(udpIp) + sizeof(udpHeader) + responsePacket.size());
    memcpy(udpPacket.data(), &udpIp, sizeof(udpIp));
    memcpy(udpPacket.data() + sizeof(udpIp), &udpHeader, sizeof(udpHeader));
    memcpy(udpPacket.data() + sizeof(udpIp) + sizeof(udpHeader), responsePacket.data(), responsePacket.size());

    struct sockaddr_in dummy;
    memset(&dummy, 0, sizeof(dummy));
    dummy.sin_family = AF_INET;  // или любой другой
    dummy.sin_addr.s_addr = udpIp.daddr;
    dummy.sin_port = udpHeader.dest;
    ssize_t sent = sendto(m_socket, udpPacket.data(), udpPacket.size(), 0,
        (struct sockaddr*)&dummy, sizeof(dummy));

    if (m_logger.isEnabled()) {
        if (sent < 0) {
            m_logger.log(LOGGER_LEVEL_ERROR, "Failed to send to client: " + string(strerror(errno)));
        }
        else {
            stringstream ss3;
            ss3 << "Sent response to client " << inet_ntoa(*(in_addr*)&info.client_ip) << ":" << info.client_udp_port << " (" << sent << " bytes)";
            m_logger.log(LOGGER_LEVEL_DEBUG, ss3.str());
        }
    }

    if (shouldRemove) {
        lock_guard<mutex> lockForward(m_tableMutex);
        auto itForward = m_forwardTable.find(key);
        if (itForward != m_forwardTable.end()) {
            m_forwardTable.erase(itForward);
        }
        lock_guard<mutex> lockConn(m_connMutex);
        auto connKey = make_tuple(info.original_src_ip, info.original_src_port, ip->saddr, srcPort, ip->protocol);
        m_connPortMap.erase(connKey);
        m_logger.log(LOGGER_LEVEL_INFO, "Removed connection mapping for FIN/RST");
    }
}

// cleaning thread
void ServerCore::CleanupLoop() {
    const auto tcp_timeout = chrono::minutes(124); //  RFC 5382
    const auto udp_timeout = chrono::minutes(20);
    while (m_running) {
        this_thread::sleep_for(chrono::seconds(1));
        auto now = chrono::steady_clock::now();
        {
            lock_guard<mutex> lock(m_connMutex);
            for (auto it = m_connPortMap.begin(); it != m_connPortMap.end(); ) {
                auto timeout = (get<4>(it->first) == IPPROTO_TCP) ? tcp_timeout : udp_timeout;
                if (now - it->second.last_used > timeout) {
                    it = m_connPortMap.erase(it);
                }
                else {
                    ++it;
                }
            }
        }

        {
            lock_guard<mutex> lock(m_tableMutex);
            for (auto it = m_forwardTable.begin(); it != m_forwardTable.end(); ) {
                auto timeout = (get<1>(it->first) == IPPROTO_TCP) ? tcp_timeout : udp_timeout;
                if (now - it->second.last_used > timeout) {
                    it = m_forwardTable.erase(it);
                }
                else {
                    ++it;
                }
            }
        }
    }
}

// client packet sniffing thread
void ServerCore::ProcessPackets() {
    m_logger.log(LOGGER_LEVEL_INFO, "Packet processing thread started");

    int flags = fcntl(m_socket, F_GETFL, 0);
    fcntl(m_socket, F_SETFL, flags | O_NONBLOCK);

    struct pollfd pfd;
    pfd.fd = m_socket;
    pfd.events = POLLIN;

    while (m_running) {
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            m_logger.log(LOGGER_LEVEL_ERROR, "poll error: " + string(strerror(errno)));
            break;
        }
        if (ret == 0) continue;

        if (pfd.revents & POLLIN) {
            struct sockaddr_in fromAddr;
            socklen_t addrLen = sizeof(fromAddr);
            ssize_t received = recvfrom(m_socket, m_recvBuffer.data(), m_recvBuffer.size(), 0,
                (struct sockaddr*)&fromAddr, &addrLen);
            if (received < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && m_logger.isEnabled()) {
                    m_logger.log(LOGGER_LEVEL_ERROR, "recvfrom error: " + string(strerror(errno)));
                }
                continue;
            }

            const uint8_t* ipPacket = m_recvBuffer.data();
            size_t ipLen = received;
            struct iphdr* ip = (struct iphdr*)ipPacket;

            uint32_t server_ip = inet_addr("10.0.0.2");
            if (ip->daddr == server_ip || ip->saddr == server_ip)
                continue; // inbound packet from target server - process in other place

            size_t ipHeaderLen = ip->ihl * 4;
            if (ipLen < ipHeaderLen + sizeof(struct udphdr)) continue;
            uint16_t dstPort = 0;
            struct udphdr* udp = (struct udphdr*)(ipPacket + ipHeaderLen);
            if (ipLen >= ipHeaderLen + sizeof(struct udphdr)) {
                dstPort = ntohs(udp->dest);
            }
            if (dstPort >= m_config.client_port_start && dstPort <= m_config.client_port_end) {
                if (m_logger.isEnabled()) {
                    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);
                    m_logger.log(LOGGER_LEVEL_DEBUG, "Client packet from " + string(src_ip) + ":" + to_string(ntohs(udp->source)) +
                        " to " + string(dst_ip) + ":" + to_string(dstPort));
                }
                HandleClientPacket(ipPacket, ipLen, dstPort);
            }
        }
    }

    m_logger.log(LOGGER_LEVEL_INFO, "Packet processing thread stopped");
}

// target servers packet sniffing thread
void ServerCore::ProcessTUN() {
    m_logger.log(LOGGER_LEVEL_INFO, "Tun processing thread started");

    struct pollfd pfd;
    pfd.fd = m_tunfd;
    pfd.events = POLLIN;

    uint8_t buffer[65536];
    while (m_running) {
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            m_logger.log(LOGGER_LEVEL_ERROR, "poll error: " + string(strerror(errno)));
            break;
        }
        if (ret == 0) continue;

        if (pfd.revents & POLLIN) {
            ssize_t ipLen = read(m_tunfd, buffer, sizeof(buffer));
            if (ipLen < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                m_logger.log(LOGGER_LEVEL_ERROR, "Error while reading from TUN");
                break;
            }
            if (ipLen == 0) {
                m_logger.log(LOGGER_LEVEL_INFO, "TUN device closed");
                break;
            }

            struct iphdr* iph = (struct iphdr*)buffer;
            if (m_logger.isEnabled()) {
                stringstream ss;
                ss << "Received " << ipLen << " bytes, "
                    << "src: " << inet_ntoa(*(struct in_addr*)&iph->saddr)
                    << " dst: " << inet_ntoa(*(struct in_addr*)&iph->daddr)
                    << " proto: " << (int)iph->protocol;
                m_logger.log(LOGGER_LEVEL_DEBUG, ss.str());
            }

            size_t ipHeaderLen = iph->ihl * 4;
            if (ipLen < ipHeaderLen + sizeof(struct udphdr)) continue;
            uint16_t dstPort = 0;
            if (iph->protocol == IPPROTO_UDP) {
                m_logger.log(LOGGER_LEVEL_DEBUG, "Tun UDP received");
                struct udphdr* udp = (struct udphdr*)(buffer + ipHeaderLen);
                dstPort = ntohs(udp->dest);
            }
            else if (iph->protocol == IPPROTO_TCP) {
                m_logger.log(LOGGER_LEVEL_DEBUG, "Tun TCP received");
                struct tcphdr* tcp = (struct tcphdr*)(buffer + ipHeaderLen);
                dstPort = ntohs(tcp->dest);
            }
            HandleInternetPacket(buffer, ipLen, dstPort);
        }
    }

    m_logger.log(LOGGER_LEVEL_INFO, "Tun processing thread stopped");
}

bool ServerCore::Initialize(const string& configPath) {
    try {
        ifstream configFile(configPath);
        if (!configFile.is_open()) {
            cerr << "Failed to open config file: " << configPath << endl;
            return false;
        }
        json config;
        configFile >> config;

        if (config.contains("log_level")) {
            string levelStr = config["log_level"];
            if (levelStr == "error") {
                m_config.log_level = LOGGER_LEVEL_ERROR;
            }
            else if (levelStr == "info") {
                m_config.log_level = LOGGER_LEVEL_INFO;
            }
            else if (levelStr == "debug") {
                m_config.log_level = LOGGER_LEVEL_DEBUG;
            }
            else {
                m_config.log_level = LOGGER_LEVEL_NONE;   // по умолчанию
            }
            m_logger.log(LOGGER_LEVEL_INFO, "Log level: " + levelStr);
        }
        else {
            m_config.log_level = LOGGER_LEVEL_NONE;   // значение по умолчанию
        }

        m_logger.enable(m_config.log_level, (isatty(STDOUT_FILENO) != 0));

        m_logger.log(LOGGER_LEVEL_INFO, "Initializing server...");
        if (config.contains("client_ports")) {
            m_config.client_port_start = config["client_ports"]["start"];
            m_config.client_port_end = config["client_ports"]["end"];
            m_logger.log(LOGGER_LEVEL_INFO, "Client port range: " + to_string(m_config.client_port_start) + "-" + to_string(m_config.client_port_end));
        }
        else {
            m_config.client_port_start = 10000;
            m_config.client_port_end = 15000;
        }

        if (config.contains("encryption")) {
            m_config.xorKeyBase64 = config["encryption"]["xor_key"];
            m_config.swapKeyBase64 = config["encryption"]["swap_key"];
            m_logger.log(LOGGER_LEVEL_INFO, "Encryption keys loaded");
            if (!m_encryption.Initialize(m_config.xorKeyBase64, m_config.swapKeyBase64)) {
                m_logger.log(LOGGER_LEVEL_ERROR, "Failed to initialize encryption");
                return false;
            }
        }
        else {
            m_logger.log(LOGGER_LEVEL_ERROR, "Missing encryption section");
            return false;
        }

        if (config.contains("interface")) {
            m_config.interface = config["interface"];
        }
        else {
            m_config.interface = "";
        }

        if (config.contains("dns_server")) {
            string dns = config["dns_server"];
            m_config.dns_server = inet_addr(dns.c_str());
            m_logger.log(LOGGER_LEVEL_INFO, "DNS redirect enabled: " + dns);
        }
        else {
            m_config.dns_server = 0;
            m_logger.log(LOGGER_LEVEL_INFO, "DNS redirect disabled (no dns_server in config)");
        }
    }
    catch (const exception& e) {
        m_logger.log(LOGGER_LEVEL_ERROR, "Config parse error: " + string(e.what()));
        return false;
    }

    random_device rd;
    m_rng.seed(rd());
    m_portDist = uniform_int_distribution<uint16_t>(SRC_PORT_START, SRC_PORT_END);

    if (!InitSocket()) return false;
    if (!CreateTUN("tun_miga")) return false;

    m_logger.log(LOGGER_LEVEL_INFO, "Server initialized successfully");
    return true;
}

void ServerCore::Start() {
    if (m_running) return;
    m_running = true;
    system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP"); // drop icmp "Port unreachable"
    m_processPacketsThread = thread(&ServerCore::ProcessPackets, this);
    m_processTunThread = thread(&ServerCore::ProcessTUN, this);
    m_cleanupThread = thread(&ServerCore::CleanupLoop, this);
    m_logger.log(LOGGER_LEVEL_INFO, "Server started");
}

void ServerCore::Stop() {
    if (m_running) {
        m_running = false;
        system("iptables -D OUTPUT -p icmp --icmp-type destination-unreachable -j DROP");
        if (m_processPacketsThread.joinable()) m_processPacketsThread.join();
        if (m_processTunThread.joinable()) m_processTunThread.join();
        if (m_cleanupThread.joinable()) m_cleanupThread.join();
        m_logger.log(LOGGER_LEVEL_INFO, "Server stopped");
    }
}