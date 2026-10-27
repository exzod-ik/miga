#pragma once

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

class InterfaceIpCache {
public:
    ~InterfaceIpCache() { Stop(); }

    bool Start(const std::string& interfaceName) {
        if (thread_.joinable()) return true;
        interfaceName_ = interfaceName;
        wakeFd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (wakeFd_ < 0) return false;
        netlinkFd_ = OpenEvents();
        const bool refreshed = Refresh();
        try {
            thread_ = std::thread(&InterfaceIpCache::Watch, this, refreshed);
        }
        catch (...) {
            if (netlinkFd_ >= 0) close(netlinkFd_);
            close(wakeFd_);
            netlinkFd_ = wakeFd_ = -1;
            throw;
        }
        return true;
    }

    void Stop() {
        if (!thread_.joinable()) return;
        const uint64_t signal = 1;
        while (write(wakeFd_, &signal, sizeof(signal)) < 0 && errno == EINTR) {}
        thread_.join();
        if (netlinkFd_ >= 0) close(netlinkFd_);
        close(wakeFd_);
        netlinkFd_ = wakeFd_ = -1;
    }

    uint32_t Get() const { return address_.load(std::memory_order_relaxed); }

private:
    static int OpenEvents() {
        const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) return -1;
        sockaddr_nl address{};
        address.nl_family = AF_NETLINK;
        address.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
        if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            close(fd);
            return -1;
        }
        return fd;
    }

    bool Refresh() {
        ifaddrs* interfaces = nullptr;
        if (getifaddrs(&interfaces) < 0) {
            address_.store(0, std::memory_order_relaxed);
            return false;
        }
        uint32_t address = 0;
        for (auto* entry = interfaces; entry; entry = entry->ifa_next) {
            if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET ||
                (entry->ifa_flags & IFF_LOOPBACK)) continue;
            if (interfaceName_.empty() || interfaceName_ == entry->ifa_name) {
                address = reinterpret_cast<sockaddr_in*>(entry->ifa_addr)->sin_addr.s_addr;
                break;
            }
        }
        freeifaddrs(interfaces);
        address_.store(address, std::memory_order_relaxed);
        return true;
    }

    void Watch(bool refreshed) {
        for (;;) {
            pollfd descriptors[2] = { { wakeFd_, POLLIN, 0 }, { netlinkFd_, POLLIN, 0 } };
            const int result = poll(descriptors, 2, netlinkFd_ >= 0 && refreshed ? -1 : 5000);
            if (result < 0 && errno == EINTR) continue;
            if (descriptors[0].revents != 0) return;
            if (result < 0 || (descriptors[1].revents & (POLLHUP | POLLNVAL))) {
                if (netlinkFd_ >= 0) close(netlinkFd_);
                netlinkFd_ = -1;
                refreshed = Refresh();
                continue;
            }
            if (result == 0) {
                if (netlinkFd_ < 0) netlinkFd_ = OpenEvents();
                refreshed = Refresh();
                continue;
            }
            if (descriptors[1].revents & (POLLIN | POLLERR)) {
                for (int i = 0; i < 64; ++i) {
                    char buffer[8192];
                    const auto length = recv(netlinkFd_, buffer, sizeof(buffer), MSG_DONTWAIT);
                    if (length >= 0) continue;
                    if (errno == EINTR || errno == ENOBUFS) continue;
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        close(netlinkFd_);
                        netlinkFd_ = -1;
                    }
                    break;
                }
                refreshed = Refresh();
            }
        }
    }

    std::atomic<uint32_t> address_{0};
    std::string interfaceName_;
    int netlinkFd_ = -1;
    int wakeFd_ = -1;
    std::thread thread_;
};
