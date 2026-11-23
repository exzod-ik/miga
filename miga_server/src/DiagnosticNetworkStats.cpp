#include "DiagnosticNetworkStats.h"
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace {
using Json = DiagnosticNetworkStats::Json;
std::string Read(const std::string& path) {
    std::ifstream file(path);
    std::string value;
    std::getline(file, value);
    return value;
}
void Counter(Json& counters, const std::string& key, const std::string& path) {
    std::ifstream file(path);
    uint64_t value;
    if (file >> value) counters[key] = value;
}
bool Ethtool(int socket, const std::string& name, void* data) {
    ifreq request{};
    if (name.size() >= IFNAMSIZ) return false;
    std::memcpy(request.ifr_name, name.c_str(), name.size() + 1);
    request.ifr_data = static_cast<char*>(data);
    return ioctl(socket, SIOCETHTOOL, &request) == 0;
}
void Driver(Json& result, int socket, const std::string& name) {
    ethtool_ringparam ring{}; ring.cmd = ETHTOOL_GRINGPARAM;
    if (Ethtool(socket, name, &ring)) result["ring"] = {{"rx", ring.rx_pending}, {"rx_max", ring.rx_max_pending}};
    else result["unavailable"].push_back("rx_ring");
    ethtool_drvinfo info{}; info.cmd = ETHTOOL_GDRVINFO;
    if (!Ethtool(socket, name, &info) || info.n_stats == 0 || info.n_stats > 4096) {
        result["unavailable"].push_back("driver_counters"); return;
    }
    result["driver"] = std::string(info.driver, strnlen(info.driver, sizeof(info.driver)));
    std::vector<uint64_t> names((sizeof(ethtool_gstrings) + size_t(info.n_stats) * ETH_GSTRING_LEN + 7) / 8);
    std::vector<uint64_t> values((sizeof(ethtool_stats) + size_t(info.n_stats) * sizeof(uint64_t) + 7) / 8);
    auto* strings = reinterpret_cast<ethtool_gstrings*>(names.data());
    auto* stats = reinterpret_cast<ethtool_stats*>(values.data());
    strings->cmd = ETHTOOL_GSTRINGS; strings->string_set = ETH_SS_STATS; strings->len = info.n_stats;
    stats->cmd = ETHTOOL_GSTATS; stats->n_stats = info.n_stats;
    if (!Ethtool(socket, name, strings) || !Ethtool(socket, name, stats) || strings->len != info.n_stats || stats->n_stats != info.n_stats) {
        result["unavailable"].push_back("driver_counters"); return;
    }
    std::unordered_map<std::string, unsigned> occurrences;
    for (uint32_t i = 0; i < info.n_stats; ++i) {
        const auto* bytes = reinterpret_cast<const char*>(strings->data + size_t(i) * ETH_GSTRING_LEN);
        std::string label(bytes, strnlen(bytes, ETH_GSTRING_LEN));
        std::string lower = label;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {return char(std::tolower(c));});
        if (lower.find("rx") == std::string::npos) continue;
        bool selected = false;
        for (const auto* term : {"oob", "drop", "discard", "miss", "err", "no_buf", "no_buffer", "out_of_buf", "alloc_fail", "alloc fail"})
            selected |= lower.find(term) != std::string::npos;
        if (!selected) continue;
        const auto occurrence = occurrences[label]++;
        result["counters"]["driver/" + label + "/" + std::to_string(occurrence)] = stats->data[i];
    }
}
}

DiagnosticNetworkStats::Json DiagnosticNetworkStats::Capture(int udpSocket, uint32_t address) {
    Json result = {{"counters", Json::object()}, {"unavailable", Json::array()},
        {"time_ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()},
        {"boot", Read("/proc/sys/kernel/random/boot_id")}};
    std::string name;
    ifaddrs* interfaces = nullptr;
    if (address && getifaddrs(&interfaces) == 0) {
        for (auto* entry = interfaces; entry; entry = entry->ifa_next)
            if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET &&
                reinterpret_cast<sockaddr_in*>(entry->ifa_addr)->sin_addr.s_addr == address) {name = entry->ifa_name; break;}
        freeifaddrs(interfaces);
    }
    result["interface"] = name;
    if (!name.empty()) {
        result["ifindex"] = if_nametoindex(name.c_str());
        for (const auto* counter : {"rx_packets", "rx_bytes", "rx_dropped", "rx_errors", "rx_missed_errors", "rx_fifo_errors", "tx_packets", "tx_bytes", "tx_dropped", "tx_errors"})
            Counter(result["counters"], std::string("interface/") + counter, "/sys/class/net/" + name + "/statistics/" + counter);
        const int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (control >= 0) {Driver(result, control, name); close(control);}
        else result["unavailable"].push_back("ethtool_socket");
    } else result["unavailable"].push_back("interface");
    std::ifstream softnet("/proc/net/softnet_stat");
    std::string line;
    unsigned cpu = 0;
    while (std::getline(softnet, line)) {
        std::istringstream fields(line);
        uint64_t processed, dropped, squeezed;
        if (!(fields >> std::hex >> processed >> dropped >> squeezed)) continue;
        const auto prefix = "softnet/cpu" + std::to_string(cpu++) + "/";
        result["counters"][prefix + "dropped"] = dropped;
        result["counters"][prefix + "time_squeeze"] = squeezed;
    }
    if (!cpu) result["unavailable"].push_back("softnet");
    int buffer = 0; socklen_t length = sizeof(buffer);
    if (udpSocket >= 0 && getsockopt(udpSocket, SOL_SOCKET, SO_RCVBUF, &buffer, &length) == 0) result["socket_rcvbuf"] = buffer;
    struct stat identity{};
    bool found = false;
    if (udpSocket >= 0 && fstat(udpSocket, &identity) == 0) {
        result["socket_inode"] = uint64_t(identity.st_ino);
        std::ifstream sockets("/proc/net/udp");
        std::getline(sockets, line);
        while (std::getline(sockets, line)) {
            std::istringstream fields(line);
            std::vector<std::string> columns;
            std::string field;
            while (fields >> field) columns.push_back(field);
            if (columns.size() < 13 || columns[9] != std::to_string(identity.st_ino)) continue;
            std::istringstream value(columns.back()); uint64_t drops;
            if (value >> drops) {result["counters"]["socket/drops"] = drops; found = true;}
        }
    }
    if (!found) result["unavailable"].push_back("socket_drops");
    return result;
}

DiagnosticNetworkStats::Json DiagnosticNetworkStats::Difference(const Json& before, const Json& after) {
    Json result = after;
    result["delta"] = Json::object();
    result["invalid"] = Json::array();
    const bool boot = !before.value("boot", "").empty() && before.value("boot", "") == after.value("boot", "");
    const bool iface = boot && before.value("interface", "") == after.value("interface", "") && before.value("ifindex", 0u) == after.value("ifindex", 0u);
    const bool socket = boot && before.value("socket_inode", uint64_t(0)) != 0 && before.value("socket_inode", uint64_t(0)) == after.value("socket_inode", uint64_t(0));
    result["elapsed_ms"] = after.value("time_ms", int64_t(0)) - before.value("time_ms", int64_t(0));
    const auto previous = before.value("counters", Json::object());
    auto keys = previous;
    keys.update(after.value("counters", Json::object()));
    for (const auto& entry : keys.items()) {
        const auto& key = entry.key();
        const bool identity = key.rfind("socket/", 0) == 0 ? socket : key.rfind("softnet/", 0) == 0 ? boot : iface;
        if (!identity || !previous.contains(key) || !after.at("counters").contains(key) || after.at("counters").at(key).get<uint64_t>() < previous.at(key).get<uint64_t>()) {
            result["delta"][key] = nullptr; result["invalid"].push_back(key);
        } else result["delta"][key] = after.at("counters").at(key).get<uint64_t>() - previous.at(key).get<uint64_t>();
    }
    return result;
}
