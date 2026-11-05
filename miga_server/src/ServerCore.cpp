#include "ServerCore.h"
#include "InternetChecksum.h"
#include "TunnelIngress.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>
#include <fcntl.h>
#include <errno.h>
#include <sstream>
#include <chrono>
#include <thread>
#include <poll.h>
#include <array>
#include <linux/filter.h>
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

    InternetChecksum checksum;
    checksum.Add(&pseudo, sizeof(pseudo));
    checksum.Add(tcp, tcp_len);
    return checksum.Value();
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

    InternetChecksum checksum;
    checksum.Add(&pseudo, sizeof(pseudo));
    checksum.Add(udp, udp_len);
    const uint16_t value = checksum.Value();
    return value ? value : 0xffff;
}

ServerCore::ServerCore()
    : m_socket(-1)
    , m_tunfd(-1)
    , m_logger()
    , m_running(false) {
    m_config.log_level = LOGGER_LEVEL_NONE;
}

ServerCore::~ServerCore() {
    Stop();
    if (m_socket >= 0) close(m_socket);
    if (m_tunfd >= 0) close(m_tunfd);
}

// send unpacked ip packet to tun
void ServerCore::SendPacket(const uint8_t* packet, size_t len) {
    ssize_t n = write(m_tunfd, packet, len);
    if (n < 0) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "tun_write_failed" + LogErrno(errno); });
        return;
    }
    if ((size_t)n != len) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "tun_write_failed reason=partial_write expected_bytes=" + to_string(len) + " written_bytes=" + to_string(n); });
        return;
    }
    return;
}

// initialize raw udp socket to snif inbound packets from clients
bool ServerCore::InitSocket() {

    m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (m_socket < 0) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "socket_create_failed type=RAW protocol=UDP required_privilege=root_or_cap_net_raw" + LogErrno(errno); });
        return false;
    }
    const int discovery = IP_PMTUDISC_DONT;
    if (setsockopt(m_socket, IPPROTO_IP, IP_MTU_DISCOVER, &discovery, sizeof(discovery)) < 0) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "socket_option_failed option=IP_MTU_DISCOVER" + LogErrno(errno); });
        return false;
    }
    sock_filter instructions[] = {
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, m_config.client_port_start, 0, 2),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, m_config.client_port_end, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
        BPF_STMT(BPF_RET | BPF_K, 0)
    };
    sock_fprog filter{static_cast<unsigned short>(std::size(instructions)), instructions};
    if (setsockopt(m_socket, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
        m_logger.logLazy(LOGGER_LEVEL_WARNING, [&] { return "socket_filter_unavailable" + LogErrno(errno); });

    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "socket_created type=RAW protocol=UDP"; });
    return true;
}

// create tun to receive and send packets to target server
bool ServerCore::CreateTUN(const char* dev_name) {
    struct ifreq ifr;

    // Открываем клон-устройство TUN
    if ((m_tunfd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC)) < 0) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "tun_create_failed operation=open path=/dev/net/tun" + LogErrno(errno); });
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN — IP-packets without Ethernet-header
    // IFF_NO_PI — don't add addditional info

    if (*dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    if (ioctl(m_tunfd, TUNSETIFF, (void*)&ifr) < 0) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "tun_create_failed operation=ioctl request=TUNSETIFF" + LogErrno(errno); });
        close(m_tunfd);
        m_tunfd = -1;
        return false;
    }
    
    string msg = "tun_created interface=";
    msg += LogValue(ifr.ifr_name);
    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return msg; });

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
                m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "ip_forwarding_enable_failed"; });
                close(m_tunfd);
                m_tunfd = -1;
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
void ServerCore::HandleClientPacket(uint8_t* packet, size_t length) {
    TunnelIngress datagram;
    if (!TunnelIngress::Parse(packet, length, m_config.client_port_start, m_config.client_port_end, datagram)) return;
    m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return "tunnel_packet_received src=" + IpToString(datagram.clientAddress) +
        ":" + to_string(datagram.clientPort) + " dst_port=" + to_string(datagram.serverPort); });
    const auto started = chrono::steady_clock::now();
    ProcessClientUdpPacket(datagram.payload, datagram.length, datagram.clientAddress, datagram.clientPort, datagram.serverPort);
    m_logger.recordDelay(NetworkWarning::ClientPacketProcessing, started);
}

void ServerCore::ProcessClientUdpPacket(uint8_t* origIpPacket, size_t origIpLen,
    uint32_t client_ip, uint16_t client_udp_port, uint16_t local_udp_port) {
    m_encryption.Decrypt(origIpPacket, origIpLen, local_udp_port);
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
    TcpSegment tcpSegment;

    if (origIp->protocol == IPPROTO_TCP) {
        if (!TcpSegment::Parse(origIpPacket, origIpLen, tcpSegment)) return;
        struct tcphdr* tcp = (struct tcphdr*)(origIpPacket + origIpHeaderLen);
        original_src_port = ntohs(tcp->source);
        original_dst_port = ntohs(tcp->dest);
        proto = "TCP";
        if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG)) {
            flags = " tcp_flags_text=" + LogValue(tcpFlags(tcp));
        }
    }
    else if (origIp->protocol == IPPROTO_UDP) {
        struct udphdr* udpInner = (struct udphdr*)(origIpPacket + origIpHeaderLen);
        original_src_port = ntohs(udpInner->source);
        original_dst_port = ntohs(udpInner->dest);
        proto = "UDP";
    }

    uint32_t saved_dst_ip = original_dst_ip;

    if (m_config.dns_server && origIp->protocol == IPPROTO_UDP && original_dst_port == 53) {
        original_dst_ip = m_config.dns_server;
        if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG)) {
            m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return "dns_query_redirected original_ip=" + IpToString(saved_dst_ip) + " server_ip=" + IpToString(m_config.dns_server); });
        }
    }

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
        lock_guard<mutex> lock_table(m_tableMutex);
        const auto now = chrono::steady_clock::now();
        auto it = m_connPortMap.find(connKey);
        auto& routes = origIp->protocol == IPPROTO_TCP ? m_tcpRoutes : m_udpRoutes;
        ClientInfo* replaced = nullptr;
        if (it != m_connPortMap.end() && origIp->protocol == IPPROTO_TCP &&
            routes[it->second.port]->tcpState.IsNewConnection(tcpSegment))
            replaced = routes[it->second.port].get();
        if (it != m_connPortMap.end() && !replaced) {
            chosen_src_port = it->second.port;
            if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG))
                m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return "source_port_selected reused=1 port=" + to_string(chosen_src_port); });
        }
        else if (isNewConnection) {
            auto& ports = origIp->protocol == IPPROTO_TCP ? m_tcpPorts : m_udpPorts;
            auto port = ports.Acquire(m_rng);
            if (!port) {
                m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "source_port_exhausted dst_ip=" + IpToString(original_dst_ip); });
                return;
            }
            chosen_src_port = *port;
            if (replaced) {
                replaced->tcpState.Retire();
                replaced->last_used = now;
            }
            routes[chosen_src_port] = make_unique<ClientInfo>();
            auto& route = *routes[chosen_src_port];
            route.original_src_ip = original_src_ip;
            route.original_src_port = original_src_port;
            route.remote_ip = original_dst_ip;
            route.remote_port = original_dst_port;
            m_cleanupKeys.push_back((uint32_t(origIp->protocol) << 16) | chosen_src_port);
            PortInfo info;
            info.port = chosen_src_port;
            m_connPortMap[connKey] = info;
            if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG))
                m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return "source_port_selected reused=0 port=" + to_string(chosen_src_port); });
        }
        else {
            if (origIp->protocol == IPPROTO_TCP) {
                m_logger.logLazy(LOGGER_LEVEL_WARNING, [&] { return "server_packet_drop protocol=TCP reason=unknown_connection_non_syn"; });
            }
            else {
                m_logger.logLazy(LOGGER_LEVEL_WARNING, [&] { return "server_packet_drop protocol=UDP reason=unknown_connection"; });
            }
            return;
        }
        auto& info = *routes[chosen_src_port];
        info.local_udp_port = local_udp_port;
        info.client_ip = client_ip;
        info.client_udp_port = client_udp_port;
        info.original_dst_ip = saved_dst_ip;
        info.last_used = now;
        if (origIp->protocol == IPPROTO_TCP)
            info.tcpState.Observe(tcpSegment, true);
    }

    if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG)) {
        m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return "packet_forwarded direction=client_to_server protocol=" + proto + " src=" + IpToString(origIp->saddr) + ":" + to_string(original_src_port) +
            " dst=" + IpToString(origIp->daddr) + ":" + to_string(original_dst_port) + " forwarded_port=" + to_string(chosen_src_port) + flags; });
    }

    auto* outIp = origIp;
    outIp->daddr = original_dst_ip;

    outIp->saddr = htonl(0x0a000002);
    outIp->check = 0;
    outIp->check = in_cksum((uint16_t*)outIp, outIp->ihl * 4);

    if (outIp->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(origIpPacket + origIpHeaderLen);
        tcp->source = htons(chosen_src_port);
        tcp->check = 0;
        tcp->check = tcp_checksum(outIp, tcp);
    }
    else if (outIp->protocol == IPPROTO_UDP) {
        struct udphdr* udpOut = (struct udphdr*)(origIpPacket + origIpHeaderLen);
        udpOut->source = htons(chosen_src_port);
        udpOut->check = 0;
        udpOut->check = udp_checksum(outIp, udpOut);
    }

    SendPacket(origIpPacket, ntohs(outIp->tot_len));
}

bool ServerCore::ValidateInnerIpPacket(const uint8_t* packet, size_t len, struct iphdr*& outIp, size_t& outIpHeaderLen) {
    if (len < sizeof(struct iphdr)) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid reason=ip_header_truncated"; });
        return false;
    }

    struct iphdr* ip = (struct iphdr*)packet;

    // ip version
    if (ip->version != 4) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid reason=ip_version expected=4"; });
        return false;
    }

    // header length
    uint8_t ihl = ip->ihl;
    if (ihl < 5 || ihl > 15) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid reason=ip_header_length header_length=" + to_string(ihl); });
        return false;
    }

    size_t ipHeaderLen = ihl * 4;
    if (len < ipHeaderLen) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid reason=claimed_ip_header_truncated"; });
        return false;
    }

    // packet length
    uint16_t totalLen = ntohs(ip->tot_len);
    if (totalLen < ipHeaderLen) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid reason=ip_total_length_below_header"; });
        return false;
    }
    if (totalLen > len) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid reason=ip_total_length_exceeds_buffer"; });
        return false;
    }

    if (ntohs(ip->frag_off) & 0x3fff) return false;

    // protocol
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid reason=unsupported_protocol protocol=" + to_string(ip->protocol); });
        return false;
    }

    // transport header
    size_t transportOffset = ipHeaderLen;
    if (ip->protocol == IPPROTO_TCP) {
        if (totalLen < transportOffset + sizeof(struct tcphdr)) {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid protocol=TCP reason=header_truncated"; });
            return false;
        }
        struct tcphdr* tcp = (struct tcphdr*)(packet + transportOffset);
        uint8_t tcpHeaderLen = tcp->doff * 4;
        if (tcpHeaderLen < sizeof(struct tcphdr)) {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid protocol=TCP reason=header_length"; });
            return false;
        }
        if (transportOffset + tcpHeaderLen > totalLen) {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid protocol=TCP reason=packet_truncated"; });
            return false;
        }
    }
    else if (ip->protocol == IPPROTO_UDP) {
        if (totalLen < transportOffset + sizeof(struct udphdr)) {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid protocol=UDP reason=header_truncated"; });
            return false;
        }
        struct udphdr* udp = (struct udphdr*)(packet + transportOffset);
        uint16_t udpLen = ntohs(udp->len);
        if (udpLen < sizeof(struct udphdr)) {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid protocol=UDP reason=length_below_header"; });
            return false;
        }
        if (transportOffset + udpLen > totalLen) {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "inner_packet_invalid protocol=UDP reason=packet_truncated"; });
            return false;
        }
    }

    outIp = ip;
    outIpHeaderLen = ipHeaderLen;
    return true;
}

void ServerCore::HandleInternetPacket(uint8_t* innerPacket, size_t ipLen) {
    iphdr* ip = nullptr;
    size_t ipHeaderLen = 0;
    if (!ValidateInnerIpPacket(innerPacket, ipLen, ip, ipHeaderLen)) return;
    ipLen = ntohs(ip->tot_len);
    if (ipLen > 65507) {
        m_logger.recordWarning(NetworkWarning::LargeTunnelPacket, ipLen);
        return;
    }
    TcpSegment tcpSegment;
    if (ip->protocol == IPPROTO_TCP && !TcpSegment::Parse(innerPacket, ipLen, tcpSegment)) return;
    uint16_t ports[2];
    memcpy(ports, innerPacket + ipHeaderLen, sizeof(ports));
    const uint16_t srcPort = ntohs(ports[0]);
    const uint16_t dstPort = ntohs(ports[1]);
    if (dstPort < SRC_PORT_START) return;
    ClientInfo info{};
    bool found = false;
    {
        lock_guard<mutex> lock(m_tableMutex);
        auto& route = (ip->protocol == IPPROTO_TCP ? m_tcpRoutes : m_udpRoutes)[dstPort];
        if (route) {
            if (ip->protocol == IPPROTO_TCP) {
                if (ip->saddr != route->remote_ip || srcPort != route->remote_port) return;
                route->tcpState.Observe(tcpSegment, false);
            }
            route->last_used = chrono::steady_clock::now();
            info = *route;
            found = true;
        }
    }

    if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG)) {
        stringstream ss;
        ss << "reverse_route_lookup src_ip=" << IpToString(ip->saddr) << " dst_port=" << dstPort;
        m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return ss.str(); });
    }

    if (!found) {
        m_logger.logLazy(LOGGER_LEVEL_WARNING, [&] { return "server_packet_drop reason=reverse_route_missing"; });
        return;
    }

    if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG)) {
        stringstream ss2;
        ss2 << "reverse_route_found src=" << IpToString(ip->saddr) << ":" << srcPort
            << " dst=" << IpToString(ip->daddr) << ":" << dstPort
            << " client=" << inet_ntoa(*(in_addr*)&info.client_ip) << ":" << info.client_udp_port
            << " original_client=" << inet_ntoa(*(in_addr*)&info.original_src_ip) << ":" << info.original_src_port;
        m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return ss2.str(); });
    }

    auto* outIp = ip;
    outIp->daddr = info.original_src_ip;
    outIp->saddr = info.original_dst_ip;

    if (outIp->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(innerPacket + outIp->ihl * 4);
        tcp->dest = htons(info.original_src_port);
    }
    else if (outIp->protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(innerPacket + outIp->ihl * 4);
        udp->dest = htons(info.original_src_port);
    }

    if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG)) {
        string proto, flags = "";
        uint16_t logSrcPort = 0, logDestPort = 0;
        if (outIp->protocol == IPPROTO_TCP) {
            struct tcphdr* tcp = (struct tcphdr*)(innerPacket + outIp->ihl * 4);
            logSrcPort = ntohs(tcp->source);
            logDestPort = ntohs(tcp->dest);
            proto = "TCP";
            flags = " tcp_flags_text=" + LogValue(tcpFlags(tcp));
        }
        else if (outIp->protocol == IPPROTO_UDP) {
            struct udphdr* udp = (struct udphdr*)(innerPacket + outIp->ihl * 4);
            logSrcPort = ntohs(udp->source);
            logDestPort = ntohs(udp->dest);
            proto = "UDP";
        }

        m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return "packet_forwarded direction=server_to_client protocol=" + proto + " src=" + IpToString(outIp->saddr) + ":" + to_string(logSrcPort) +
            " dst=" + IpToString(outIp->daddr) + ":" + to_string(logDestPort) + " forwarded_port=" + to_string(dstPort) + flags; });
    }

    m_encryption.Encrypt(innerPacket, ipLen, info.local_udp_port);

    udphdr udpHeader{};
    udpHeader.source = htons(info.local_udp_port);
    udpHeader.dest = htons(info.client_udp_port);
    udpHeader.len = htons(static_cast<uint16_t>(sizeof(udphdr) + ipLen));
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = info.client_ip;
    iovec parts[] = {{&udpHeader, sizeof(udpHeader)}, {innerPacket, ipLen}};
    msghdr message{};
    message.msg_name = &destination;
    message.msg_namelen = sizeof(destination);
    message.msg_iov = parts;
    message.msg_iovlen = std::size(parts);
    alignas(cmsghdr) unsigned char control[CMSG_SPACE(sizeof(in_pktinfo))]{};
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_IP;
    header->cmsg_type = IP_PKTINFO;
    header->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
    in_pktinfo source{};
    source.ipi_spec_dst.s_addr = m_interfaceIp.Get();
    memcpy(CMSG_DATA(header), &source, sizeof(source));
    ssize_t sent;
    do {
        sent = sendmsg(m_socket, &message, MSG_DONTWAIT);
    } while (sent < 0 && errno == EINTR);

    if (m_logger.isEnabled(LOGGER_LEVEL_ERROR)) {
        if (sent < 0) {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "tunnel_send_failed direction=to_client" + LogErrno(errno); });
        }
        else if (m_logger.isEnabled(LOGGER_LEVEL_DEBUG)) {
            stringstream ss3;
            ss3 << "tunnel_packet_sent client=" << inet_ntoa(*(in_addr*)&info.client_ip) << ":" << info.client_udp_port << " size=" << sent;
            m_logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { return ss3.str(); });
        }
    }
}

// cleaning thread
void ServerCore::CleanupLoop() {
    const auto udp_timeout = chrono::minutes(20);
    auto lastWarningReport = chrono::steady_clock::now();
    while (m_running) {
        this_thread::sleep_for(chrono::seconds(1));
        auto now = chrono::steady_clock::now();
        if (now - lastWarningReport >= chrono::seconds(5)) {
            m_logger.flushWarnings();
            lastWarningReport = now;
        }
        size_t remaining;
        {
            lock_guard<mutex> lock(m_connMutex);
            remaining = m_cleanupKeys.size();
        }
        while (remaining && m_running) {
            lock_guard<mutex> lock(m_connMutex);
            lock_guard<mutex> lockTable(m_tableMutex);
            const size_t count = min<size_t>(remaining, 128);
            remaining -= count;
            for (size_t i = 0; i < count; ++i) {
                const auto key = m_cleanupKeys.front();
                m_cleanupKeys.pop_front();
                const auto port = static_cast<uint16_t>(key);
                const auto protocol = static_cast<uint8_t>(key >> 16);
                auto& route = (protocol == IPPROTO_TCP ? m_tcpRoutes : m_udpRoutes)[port];
                auto timeout = protocol == IPPROTO_TCP ? route->tcpState.IdleTimeout() : udp_timeout;
                if (now - route->last_used <= timeout) {
                    m_cleanupKeys.push_back(key);
                    continue;
                }
                auto connection = m_connPortMap.find(make_tuple(route->original_src_ip, route->original_src_port,
                    route->remote_ip, route->remote_port, protocol));
                if (connection != m_connPortMap.end() && connection->second.port == port)
                    m_connPortMap.erase(connection);
                (protocol == IPPROTO_TCP ? m_tcpPorts : m_udpPorts).Release(port);
                route.reset();
            }
        }
    }
}

// make sure required iptables rules are present
bool ServerCore::EnsureFirewallRules() {
    string check = "iptables -w -C POSTROUTING -t nat -s 10.0.0.0/24 ! -o tun_miga -j MASQUERADE 2>/dev/null";
    if (system(check.c_str()) == 0) {
        return true;
    }

    string add = "iptables -w -A POSTROUTING -t nat -s 10.0.0.0/24 ! -o tun_miga -j MASQUERADE";
    if (system(add.c_str()) != 0) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "nat_rule_restore_failed interface=tun_miga rule=MASQUERADE"; });
        return false;
    }

    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "nat_rule_restored interface=tun_miga rule=MASQUERADE reason=missing"; });
    return true;
}

// firewall watchdog thread
void ServerCore::FirewallWatchdogLoop() {
    while (m_running) {
        this_thread::sleep_for(chrono::seconds(3));
        EnsureFirewallRules();
    }
}

// client packet sniffing thread
void ServerCore::ProcessPackets() {
    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "worker_started worker=client_packets"; });

    constexpr size_t batch = 16;
    vector<array<uint8_t, 65536>> buffers(batch);
    array<mmsghdr, batch> messages{};
    array<iovec, batch> parts{};
    for (size_t i = 0; i < batch; ++i) {
        parts[i] = {buffers[i].data(), buffers[i].size()};
        messages[i].msg_hdr.msg_iov = &parts[i];
        messages[i].msg_hdr.msg_iovlen = 1;
    }

    struct pollfd pfd;
    pfd.fd = m_socket;
    pfd.events = POLLIN;

    while (m_running) {
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "io_failed operation=poll" + LogErrno(errno); });
            break;
        }
        if (ret == 0) continue;

        if (pfd.revents & POLLIN) {
            int count = recvmmsg(m_socket, messages.data(), batch, MSG_DONTWAIT, nullptr);
            if (count < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                    m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "io_failed operation=recvmmsg" + LogErrno(errno); });
                continue;
            }
            for (int i = 0; i < count; ++i)
                HandleClientPacket(buffers[i].data(), messages[i].msg_len);
        }
    }

    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "worker_stopped worker=client_packets"; });
}

// target servers packet sniffing thread
void ServerCore::ProcessTUN() {
    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "worker_started worker=tun_packets"; });

    struct pollfd pfd;
    pfd.fd = m_tunfd;
    pfd.events = POLLIN;

    uint8_t buffer[65536];
    while (m_running) {
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "io_failed operation=poll" + LogErrno(errno); });
            break;
        }
        if (ret == 0) continue;

        if (!(pfd.revents & POLLIN)) continue;
        for (size_t i = 0; i < 16 && m_running; ++i) {
            ssize_t ipLen = read(m_tunfd, buffer, sizeof(buffer));
            if (ipLen < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "tun_read_failed" + LogErrno(errno); });
                return;
            }
            if (ipLen == 0) {
                m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "tun_closed"; });
                return;
            }

            const auto processingStarted = chrono::steady_clock::now();
            HandleInternetPacket(buffer, ipLen);
            m_logger.recordDelay(NetworkWarning::InternetPacketProcessing, processingStarted);
        }
    }

    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "worker_stopped worker=tun_packets"; });
}

bool ServerCore::Initialize(const string& configPath) {
    try {
        ifstream configFile(configPath);
        if (!configFile.is_open()) {
            cerr << "config_open_failed path=" << LogValue(configPath) << endl;
            return false;
        }
        json config;
        configFile >> config;

        if (config.contains("log_level")) {
            string levelStr = config["log_level"];
            if (levelStr == "error") {
                m_config.log_level = LOGGER_LEVEL_ERROR;
            }
            else if (levelStr == "warning") {
                m_config.log_level = LOGGER_LEVEL_WARNING;
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
            m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "log_level_selected level=" + LogValue(levelStr); });
        }
        else {
            m_config.log_level = LOGGER_LEVEL_NONE;   // значение по умолчанию
        }

        m_logger.enable(m_config.log_level, (isatty(STDOUT_FILENO) != 0));

        m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "server_initializing"; });
        if (config.contains("client_ports")) {
            m_config.client_port_start = config["client_ports"]["start"];
            m_config.client_port_end = config["client_ports"]["end"];
            m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "client_ports_configured range=" + to_string(m_config.client_port_start) + "-" + to_string(m_config.client_port_end); });
        }
        else {
            m_config.client_port_start = 10000;
            m_config.client_port_end = 15000;
        }

        if (config.contains("encryption")) {
            m_config.xorKeyBase64 = config["encryption"]["xor_key"];
            m_config.swapKeyBase64 = config["encryption"]["swap_key"];
            m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "transform_keys_loaded"; });
            if (!m_encryption.Initialize(m_config.xorKeyBase64, m_config.swapKeyBase64)) {
                m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "transform_init_failed"; });
                return false;
            }
        }
        else {
            m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "config_invalid reason=missing_section section=encryption"; });
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
            m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "dns_redirect_configured enabled=1 server=" + LogValue(dns); });
        }
        else {
            m_config.dns_server = 0;
            m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "dns_redirect_configured enabled=0 reason=missing_dns_server"; });
        }
    }
    catch (const exception& e) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "config_parse_failed error=" + LogValue(e.what()); });
        return false;
    }

    random_device rd;
    m_rng.seed(rd());

    if (!InitSocket()) return false;
    if (!CreateTUN("tun_miga")) return false;

    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "server_initialized"; });
    return true;
}

void ServerCore::Start() {
    if (m_running) return;
    if (!m_interfaceIp.Start(m_config.interface)) {
        m_logger.logLazy(LOGGER_LEVEL_ERROR, [&] { return "interface_monitor_start_failed"; });
        return;
    }
    m_running = true;
    system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP"); // drop icmp "Port unreachable"
    EnsureFirewallRules();
    m_processPacketsThread = thread(&ServerCore::ProcessPackets, this);
    m_processTunThread = thread(&ServerCore::ProcessTUN, this);
    m_cleanupThread = thread(&ServerCore::CleanupLoop, this);
    m_firewallThread = thread(&ServerCore::FirewallWatchdogLoop, this);
    m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "server_started"; });
}

void ServerCore::Stop() {
    if (m_running) {
        m_running = false;
        m_interfaceIp.Stop();
        system("iptables -D OUTPUT -p icmp --icmp-type destination-unreachable -j DROP");
        if (m_processPacketsThread.joinable()) m_processPacketsThread.join();
        if (m_processTunThread.joinable()) m_processTunThread.join();
        if (m_cleanupThread.joinable()) m_cleanupThread.join();
        if (m_firewallThread.joinable()) m_firewallThread.join();
        m_logger.logLazy(LOGGER_LEVEL_INFO, [&] { return "server_stopped"; });
    }
}