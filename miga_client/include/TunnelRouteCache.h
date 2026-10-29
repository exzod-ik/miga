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
    ~TunnelRouteCache() { Stop(); }
    DWORD Start() {
        Stop();
        auto code = NotifyRouteChange2(AF_INET, RouteChanged, this, FALSE, &routeNotification_);
        if (code == NO_ERROR) code = NotifyUnicastIpAddressChange(AF_INET, AddressChanged, this, FALSE, &addressNotification_);
        if (code == NO_ERROR) code = NotifyIpInterfaceChange(AF_INET, InterfaceChanged, this, FALSE, &interfaceNotification_);
        if (code != NO_ERROR) Stop();
        ++revision_;
        return code;
    }
    void Stop() {
        for (auto* handle : { &routeNotification_, &addressNotification_, &interfaceNotification_ }) {
            if (*handle) CancelMibChangeNotify2(*handle);
            *handle = nullptr;
        }
    }
    DWORD Resolve(uint32_t destination, Route& route) const {
        const auto revision = revision_.load();
        const auto now = std::chrono::steady_clock::now();
        if (route.source && route.revision == revision && now - route.checked < std::chrono::seconds(5)) return NO_ERROR;
        SOCKADDR_INET target{};
        target.Ipv4.sin_family = AF_INET;
        target.Ipv4.sin_addr.s_addr = destination;
        SOCKADDR_INET source{};
        MIB_IPFORWARD_ROW2 best{};
        auto code = GetBestRoute2(nullptr, 0, nullptr, &target, 0, &best, &source);
        if (code != NO_ERROR) { route = {}; return code; }
        MIB_IPINTERFACE_ROW network{};
        InitializeIpInterfaceEntry(&network);
        network.Family = AF_INET;
        network.InterfaceLuid = best.InterfaceLuid;
        code = GetIpInterfaceEntry(&network);
        if (code != NO_ERROR) { route = {}; return code; }
        if (source.Ipv4.sin_addr.s_addr == 0 || network.NlMtu < 68) { route = {}; return ERROR_BAD_NETPATH; }
        route = { source.Ipv4.sin_addr.s_addr, network.NlMtu, revision, now };
        return NO_ERROR;
    }
private:
    std::atomic<uint64_t> revision_{1};
    HANDLE routeNotification_ = nullptr;
    HANDLE addressNotification_ = nullptr;
    HANDLE interfaceNotification_ = nullptr;
    static VOID CALLBACK RouteChanged(PVOID context, PMIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE) {
        ++static_cast<TunnelRouteCache*>(context)->revision_;
    }
    static VOID CALLBACK AddressChanged(PVOID context, PMIB_UNICASTIPADDRESS_ROW, MIB_NOTIFICATION_TYPE) {
        ++static_cast<TunnelRouteCache*>(context)->revision_;
    }
    static VOID CALLBACK InterfaceChanged(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE) {
        ++static_cast<TunnelRouteCache*>(context)->revision_;
    }
};
