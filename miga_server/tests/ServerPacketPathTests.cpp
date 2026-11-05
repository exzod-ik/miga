#include "ServerCore.h"
#include <cassert>
#include <fcntl.h>
#ifdef NDEBUG
#error ServerPacketPathTests requires assertions enabled
#endif
#include <cstring>
#include <iostream>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

struct ServerPacketPathTest {
    ServerCore core;
    int tunPeer = -1;
    int client = -1;
    int listener = -1;
    sockaddr_in serverAddress{};
    Encryption transform;

    static int BindLoopback(sockaddr_in& address) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        assert(fd >= 0);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        assert(bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        socklen_t length = sizeof(address);
        assert(getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        const int discovery = IP_PMTUDISC_DONT;
        assert(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &discovery, sizeof(discovery)) == 0);
        return fd;
    }

    static size_t Receive(int fd, uint8_t* data, size_t capacity) {
        pollfd descriptor{fd, POLLIN, 0};
        assert(poll(&descriptor, 1, 2000) == 1);
        auto received = recv(fd, data, capacity, 0);
        assert(received >= 0);
        return static_cast<size_t>(received);
    }

    void Open() {
        listener = BindLoopback(serverAddress);
        sockaddr_in clientAddress{};
        client = BindLoopback(clientAddress);
        core.m_config.client_port_start = core.m_config.client_port_end = ntohs(serverAddress.sin_port);
        assert(core.InitSocket());
        int pair[2];
        assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
        core.m_tunfd = pair[0];
        assert(fcntl(core.m_tunfd, F_SETFL, O_NONBLOCK) == 0);
        tunPeer = pair[1];
        auto xorKey = Encryption::GenerateXorKeyBase64();
        auto swapKey = Encryption::GenerateSwapKeyBase64();
        assert(transform.Initialize(xorKey, swapKey));
        assert(core.m_encryption.Initialize(xorKey, swapKey));
    }

    void StartWorkers() {
        core.m_running = true;
        core.m_processPacketsThread = std::thread(&ServerCore::ProcessPackets, &core);
        core.m_processTunThread = std::thread(&ServerCore::ProcessTUN, &core);
        core.m_cleanupThread = std::thread(&ServerCore::CleanupLoop, &core);
    }

    void StopWorkers() {
        core.m_running = false;
        core.m_processPacketsThread.join();
        core.m_processTunThread.join();
        core.m_cleanupThread.join();
    }

    void RoundTrip(uint8_t protocol) {
        std::vector<uint8_t> inner(4096, 0x93);
        auto* ip = reinterpret_cast<iphdr*>(inner.data());
        *ip = {};
        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = htons(static_cast<uint16_t>(inner.size()));
        ip->protocol = protocol;
        ip->saddr = htonl(0xc0000201);
        ip->daddr = htonl(0xc6336402);
        if (protocol == IPPROTO_TCP) {
            auto* tcp = reinterpret_cast<tcphdr*>(inner.data() + 20);
            *tcp = {};
            tcp->source = htons(31234);
            tcp->dest = htons(443);
            tcp->doff = 5;
            tcp->syn = 1;
        } else {
            auto* udp = reinterpret_cast<udphdr*>(inner.data() + 20);
            *udp = {};
            udp->source = htons(31234);
            udp->dest = htons(53);
            udp->len = htons(static_cast<uint16_t>(inner.size() - 20));
        }
        transform.Encrypt(inner.data(), inner.size(), ntohs(serverAddress.sin_port));
        assert(sendto(client, nullptr, 0, 0, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == 0);
        assert(sendto(client, inner.data(), inner.size(), 0,
            reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == static_cast<ssize_t>(inner.size()));
        alignas(iphdr) uint8_t buffer[65536];
        auto length = Receive(tunPeer, buffer, sizeof(buffer));
        assert(length == inner.size());
        auto* forwarded = reinterpret_cast<iphdr*>(buffer);
        assert(forwarded->saddr == htonl(0x0a000002));
        assert(forwarded->daddr == (protocol == IPPROTO_TCP ? htonl(0xc6336402) : core.m_config.dns_server));
        std::swap(forwarded->saddr, forwarded->daddr);
        uint16_t ports[2];
        memcpy(ports, buffer + 20, sizeof(ports));
        assert(ntohs(ports[0]) >= SRC_PORT_START);
        std::swap(ports[0], ports[1]);
        memcpy(buffer + 20, ports, sizeof(ports));
        if (protocol == IPPROTO_TCP) reinterpret_cast<tcphdr*>(buffer + 20)->ack = 1;
        assert(send(tunPeer, buffer, length, 0) == static_cast<ssize_t>(length));
        sockaddr_in source{};
        socklen_t sourceLength = sizeof(source);
        pollfd fd{client, POLLIN, 0};
        assert(poll(&fd, 1, 2000) == 1);
        auto received = recvfrom(client, buffer, sizeof(buffer), 0,
            reinterpret_cast<sockaddr*>(&source), &sourceLength);
        assert(received == static_cast<ssize_t>(inner.size()));
        assert(source.sin_addr.s_addr == serverAddress.sin_addr.s_addr && source.sin_port == serverAddress.sin_port);
        transform.Decrypt(buffer, length, ntohs(source.sin_port));
        assert(forwarded->daddr == htonl(0xc0000201) && forwarded->saddr == htonl(0xc6336402));
        memcpy(ports, buffer + 20, sizeof(ports));
        assert(ntohs(ports[0]) == (protocol == IPPROTO_TCP ? 443 : 53) && ntohs(ports[1]) == 31234);
        for (size_t i = protocol == IPPROTO_TCP ? 40 : 28; i < length; ++i) assert(buffer[i] == 0x93);
    }

    void CheckCleanup() {
        {
            std::lock_guard<std::mutex> lock(core.m_tableMutex);
            for (auto& route : core.m_udpRoutes)
                if (route) route->last_used -= std::chrono::minutes(21);
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
        do {
            {
                std::lock_guard<std::mutex> lock(core.m_connMutex);
                if (core.m_cleanupKeys.size() == 1) {
                    assert(core.m_connPortMap.size() == 1 && (core.m_cleanupKeys.front() >> 16) == IPPROTO_TCP);
                    return;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } while (std::chrono::steady_clock::now() < deadline);
        assert(false);
    }

    ~ServerPacketPathTest() {
        close(listener);
        close(client);
        close(tunPeer);
    }
};

int main() {
    ServerPacketPathTest fixture;
    fixture.Open();
    fixture.StartWorkers();
    fixture.RoundTrip(IPPROTO_TCP);
    fixture.RoundTrip(IPPROTO_UDP);
    fixture.CheckCleanup();
    fixture.StopWorkers();
    fixture.StartWorkers();
    fixture.RoundTrip(IPPROTO_UDP);
    fixture.StopWorkers();
    std::cout << "Server TCP/UDP tunnel round trips passed\n";
}
