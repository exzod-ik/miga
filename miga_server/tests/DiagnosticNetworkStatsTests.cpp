#include "DiagnosticNetworkStats.h"
#include <arpa/inet.h>
#include <cassert>
#include <iostream>

int main() {
    using Json = DiagnosticNetworkStats::Json;
    Json before = {{"boot", "boot-a"}, {"interface", "eth0"}, {"ifindex", 2}, {"socket_inode", 42}, {"time_ms", 100},
        {"counters", {{"driver/pkts rx OOB/0", uint64_t(9007199254740993ULL)}, {"socket/drops", 8}, {"softnet/cpu0/dropped", 2}}}};
    auto after = before;
    after["time_ms"] = 1100;
    after["counters"]["driver/pkts rx OOB/0"] = uint64_t(9007199254740998ULL);
    after["counters"]["socket/drops"] = 8;
    after["counters"]["softnet/cpu0/dropped"] = 5;
    auto diff = DiagnosticNetworkStats::Difference(before, after);
    assert(diff["delta"]["driver/pkts rx OOB/0"] == 5);
    assert(diff["delta"]["socket/drops"] == 0);
    assert(diff["delta"]["softnet/cpu0/dropped"] == 3);
    assert(diff["elapsed_ms"] == 1000);
    after["counters"]["socket/drops"] = 0;
    assert(DiagnosticNetworkStats::Difference(before, after)["delta"]["socket/drops"].is_null());
    after["socket_inode"] = 43;
    assert(DiagnosticNetworkStats::Difference(before, after)["delta"]["socket/drops"].is_null());
    after["ifindex"] = 3;
    diff = DiagnosticNetworkStats::Difference(before, after);
    assert(diff["delta"]["driver/pkts rx OOB/0"].is_null());
    assert(diff["delta"]["softnet/cpu0/dropped"] == 3);
    after["boot"] = "boot-b";
    assert(DiagnosticNetworkStats::Difference(before, after)["delta"]["softnet/cpu0/dropped"].is_null());
    after["counters"].erase("softnet/cpu0/dropped");
    assert(DiagnosticNetworkStats::Difference(before, after)["delta"]["softnet/cpu0/dropped"].is_null());
    auto live = DiagnosticNetworkStats::Capture(-1, inet_addr("127.0.0.1"));
    assert(live["interface"] == "lo");
    assert(live["counters"].contains("interface/rx_packets"));
    assert(!live["counters"].contains("socket/drops"));
    assert(DiagnosticNetworkStats::Capture(-1, 0)["interface"] == "");
    std::cout << "DiagnosticNetworkStats tests passed\n";
}
