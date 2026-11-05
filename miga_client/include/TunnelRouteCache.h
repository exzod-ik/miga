#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <initializer_list>
#include <iphlpapi.h>
#include <atomic>
#include <chrono>

class TunnelRouteCache {
public:
    struct Route {
        uint32_t source = 0;
        uint32_t mtu = 0;
        uint64_t revision = 0;
        std::chrono::steady_clock::time_point checked{};
    };
    uint64_t Revision() const;
    ~TunnelRouteCache();
    DWORD Start();
    void Stop();
    DWORD Resolve(uint32_t destination, Route& route) const;
private:
    std::atomic<uint64_t> revision_{1};
    HANDLE routeNotification_ = nullptr;
    HANDLE addressNotification_ = nullptr;
    HANDLE interfaceNotification_ = nullptr;
    static VOID CALLBACK RouteChanged(PVOID context, PMIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE);
    static VOID CALLBACK AddressChanged(PVOID context, PMIB_UNICASTIPADDRESS_ROW, MIB_NOTIFICATION_TYPE);
    static VOID CALLBACK InterfaceChanged(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE);
};
