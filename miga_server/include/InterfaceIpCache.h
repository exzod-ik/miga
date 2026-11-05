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
    ~InterfaceIpCache();

    bool Start(const std::string& interfaceName);

    void Stop();

    uint32_t Get() const;

private:
    static int OpenEvents();

    bool Refresh();

    void Watch(bool refreshed);

    std::atomic<uint32_t> address_{0};
    std::string interfaceName_;
    int netlinkFd_ = -1;
    int wakeFd_ = -1;
    std::thread thread_;
};
