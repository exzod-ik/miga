#include <winsock2.h>
#include "AsyncTunnelSender.h"
#include "TunnelDatagram.h"
#include "TunnelRouteCache.h"
#include <iostream>
#include <thread>
#include <map>
#include <stdexcept>

static void Check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Pending {
    const uint8_t* data;
    UINT size;
    const WINDIVERT_ADDRESS* address;
    std::vector<uint8_t> expected;
    WINDIVERT_ADDRESS expectedAddress{};
    bool cancelled = false;
};
static std::map<OVERLAPPED*, Pending> pending;
static int mode = 0;
static DWORD completionError = 0;
extern "C" BOOL WinDivertSendEx(HANDLE, const VOID* data, UINT size, UINT* sent, UINT64,
    const WINDIVERT_ADDRESS* address, UINT addressSize, LPOVERLAPPED operation) {
    Check(addressSize == sizeof(WINDIVERT_ADDRESS), "async address count");
    if (mode == 1) { *sent = size; return TRUE; }
    if (mode == 2) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    const auto* bytes = static_cast<const uint8_t*>(data);
    Check(!pending.count(operation), "overlapped reused before completion");
    pending.emplace(operation, Pending{bytes, size, address, {bytes, bytes + size}, *address});
    SetLastError(ERROR_IO_PENDING);
    return FALSE;
}
static BOOL WINAPI Result(HANDLE, LPOVERLAPPED operation, LPDWORD sent, BOOL wait) {
    auto it = pending.find(operation);
    Check(it != pending.end(), "known completion");
    if (WaitForSingleObject(operation->hEvent, wait ? INFINITE : 0) != WAIT_OBJECT_0) {
        SetLastError(ERROR_IO_INCOMPLETE); return FALSE;
    }
    Check(std::equal(it->second.expected.begin(), it->second.expected.end(), it->second.data), "buffer alive and unchanged");
    Check(std::memcmp(it->second.address, &it->second.expectedAddress, sizeof(WINDIVERT_ADDRESS)) == 0,
        "direction, interface, checksum flags and timestamp alive and unchanged");
    *sent = it->second.size;
    const bool cancelled = it->second.cancelled;
    pending.erase(it);
    if (cancelled || completionError) { SetLastError(cancelled ? ERROR_OPERATION_ABORTED : completionError); return FALSE; }
    return TRUE;
}
static BOOL WINAPI Cancel(HANDLE, LPOVERLAPPED operation) {
    auto& item = pending.at(operation);
    item.cancelled = true;
    SetEvent(operation->hEvent);
    return TRUE;
}
static uint16_t Read16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
static void DatagramTests() {
    TunnelDatagram builder;
    const uint32_t source = htonl(0xc0000201), destination = htonl(0xcb007101);
    for (size_t size : {size_t(1), size_t(29), size_t(1400), size_t(1472), size_t(4000), size_t(65507)}) {
        for (uint32_t mtu : {68u, 576u, 1500u, 65535u}) {
            std::vector<uint8_t> payload(size);
            for (size_t i = 0; i < size; ++i) payload[i] = static_cast<uint8_t>(i);
            std::vector<uint8_t> udp;
            size_t fragmentCount = 0;
            Check(builder.Build(payload.data(), payload.size(), source, destination, 40000, 54321, 65535, mtu,
                [&](const uint8_t* batch, size_t length, size_t count) {
                    Check(count > 0 && count <= 64, "fragment batch bounded");
                    size_t offset = 0;
                    for (size_t i = 0; i < count; ++i) {
                        Check(offset + 20 <= length, "fragment header bounds");
                        auto* ip = batch + offset;
                        const auto total = Read16(ip + 2);
                        Check(total <= mtu && total >= 20 && offset + total <= length, "fragment lengths");
                        InternetChecksum checksum; checksum.Add(ip, 20);
                        Check(checksum.Value() == 0, "fragment IP checksum");
                        Check(Read16(ip + 4) == 65535, "fragment identification");
                        Check((Read16(ip + 6) & 0x1fff) * 8 == udp.size(), "fragment offset");
                        const bool more = (Read16(ip + 6) & 0x2000) != 0;
                        Check(!more || (total - 20) % 8 == 0, "fragment alignment");
                        udp.insert(udp.end(), ip + 20, ip + total);
                        Check(more == (udp.size() < payload.size() + 8), "last fragment flag");
                        offset += total;
                        ++fragmentCount;
                    }
                    Check(offset == length, "batch trailing bytes");
                    return true;
                }), "datagram built");
            Check(fragmentCount > 0 && udp.size() == size + 8, "reassembled length");
            Check(Read16(udp.data()) == 40000 && Read16(udp.data() + 2) == 54321, "ports and nonce byte order");
            Check(Read16(udp.data() + 4) == udp.size(), "UDP length");
            Check(std::equal(payload.begin(), payload.end(), udp.begin() + 8), "payload preserved");
            InternetChecksum checksum;
            checksum.Add(&source, 4); checksum.Add(&destination, 4);
            const uint8_t pseudo[] = {0, 17, udp[4], udp[5]};
            checksum.Add(pseudo, 4); checksum.Add(udp.data(), udp.size());
            Check(checksum.Value() == 0, "UDP pseudo-header checksum");
        }
    }
    uint8_t payload = 1;
    auto reject = [](const uint8_t*, size_t, size_t) -> bool { throw std::runtime_error("invalid datagram submitted"); };
    Check(!builder.Build(&payload, 0, source, destination, 1, 2, 0, 1500, reject), "empty rejected");
    Check(!builder.Build(&payload, 65508, source, destination, 1, 2, 0, 1500, reject), "oversize rejected");
    Check(!builder.Build(nullptr, 1, source, destination, 1, 2, 0, 1500, reject), "null rejected");
    Check(!builder.Build(&payload, 1, source, destination, 1, 2, 0, 67, reject), "invalid MTU rejected");
    size_t calls = 0;
    Check(!builder.Build(&payload, 1, source, destination, 1, 2, 0, 1500,
        [&](const uint8_t*, size_t, size_t) { ++calls; return false; }), "send failure propagated");
    Check(calls == 1, "no retry duplicates");
}
static void AsyncTests() {
    AsyncTunnelSender sender;
    sender.SetApi({&WinDivertSendEx, &Result, &Cancel});
    std::vector<DWORD> errors;
    sender.SetErrorHandler([&](DWORD code) { errors.push_back(code); });
    const HANDLE handle = reinterpret_cast<HANDLE>(1);
    std::vector<uint8_t> data(100, 42);
    WINDIVERT_ADDRESS address{}; address.Outbound = 1;
    for (int i = 0; i < 32; ++i) {
        address.Outbound = i % 2;
        address.IPv6 = i % 3 == 0;
        address.IPChecksum = i % 2;
        address.TCPChecksum = i % 3 == 0;
        address.UDPChecksum = i % 3 == 1;
        address.Timestamp = 1000 + i;
        address.Network.IfIdx = 10 + i;
        address.Network.SubIfIdx = 20 + i;
        Check(sender.Send(handle, data.data(), data.size(), &address, 1), "pending submission");
    }
    data.assign(200, 99);
    address.Outbound = 0;
    sender.Reap();
    Check(pending.size() == 32, "pending retained");
    for (auto& item : pending) SetEvent(item.first->hEvent);
    sender.Drain();
    Check(pending.empty() && errors.empty(), "completion drains owned buffers");
    address.Outbound = 1;
    mode = 1;
    Check(sender.Send(handle, data.data(), data.size(), &address, 1), "immediate completion");
    mode = 2;
    Check(!sender.Send(handle, data.data(), data.size(), &address, 1), "immediate error");
    Check(errors.back() == ERROR_INVALID_DATA, "immediate error recorded");
    mode = 0;
    for (int i = 0; i < 32; ++i) Check(sender.Send(handle, data.data(), data.size(), &address, 1), "fill pool");
    std::thread stop([&] { Sleep(30); sender.RequestStop(); });
    Check(!sender.Send(handle, data.data(), data.size(), &address, 1), "pool wait interrupted by stop");
    stop.join();
    sender.Drain();
    Check(pending.empty() && errors.size() == 1, "cancel all pending without shutdown errors");
    Check(sender.Reset(), "restart sender");
    Check(sender.Send(handle, data.data(), data.size(), &address, 1), "submit after restart");
    completionError = ERROR_NETWORK_UNREACHABLE;
    for (auto& item : pending) SetEvent(item.first->hEvent);
    sender.Reap();
    Check(errors.back() == completionError && pending.empty(), "asynchronous error recorded");
    completionError = 0;
}
int main() {
    try {
        DatagramTests();
        AsyncTests();
        TunnelRouteCache routes;
        Check(routes.Start() == NO_ERROR, "route notifications subscribe");
        TunnelRouteCache::Route route;
        Check(routes.Resolve(htonl(INADDR_LOOPBACK), route) == NO_ERROR && route.source == htonl(INADDR_LOOPBACK), "source route lookup");
        routes.Stop();
        Check(routes.Start() == NO_ERROR, "route notification restart");
        std::cout << "Tunnel send tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
