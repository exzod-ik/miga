#include "V2Server.h"
#include "ClientStore.h"
#include "DiagnosticControl.h"
#include "InterfaceIpCache.h"
#include "Logger.h"
#include "ProtocolV2.h"
#include "ProtocolV2Packets.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <linux/if_tun.h>
#include <map>
#include <net/if.h>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <set>
#include <signal.h>
#include <spawn.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace miga::v2
{
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
namespace
{
constexpr int ClientPageSize = 64;
constexpr size_t AdminResponseLimit = 128 * 1024;

std::string TextIp(uint32_t host)
{
    in_addr address{htonl(host)};
    char text[INET_ADDRSTRLEN]{};
    return inet_ntop(AF_INET, &address, text, sizeof(text)) ? text : "";
}
int Command(std::vector<std::string> arguments, std::string *output)
{
    static Clock::time_point blockedUntil{};
    if (arguments.empty() || Clock::now() < blockedUntil)
        return -1;
    if (arguments[0] == "iptables")
    {
        const auto wait = std::find(arguments.begin(), arguments.end(), "-w");
        if (wait != arguments.end() && (wait + 1 == arguments.end() || (wait + 1)->front() == '-'))
            arguments.insert(wait + 1, "5");
    }
    std::vector<char *> argv;
    for (auto &argument : arguments)
        argv.push_back(argument.data());
    argv.push_back(nullptr);
    int descriptors[2]{-1, -1};
    if (output && pipe2(descriptors, O_CLOEXEC) != 0)
        return -1;
    if (output)
    {
        output->clear();
        fcntl(descriptors[0], F_SETFL, O_NONBLOCK);
    }
    const int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null < 0)
    {
        if (output)
        {
            close(descriptors[0]);
            close(descriptors[1]);
        }
        return -1;
    }
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_init(&actions);
    posix_spawnattr_init(&attributes);
    posix_spawn_file_actions_adddup2(&actions, null, STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, null, STDERR_FILENO);
    posix_spawn_file_actions_adddup2(&actions, output ? descriptors[1] : null, STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, null);
    if (output)
    {
        posix_spawn_file_actions_addclose(&actions, descriptors[0]);
        posix_spawn_file_actions_addclose(&actions, descriptors[1]);
    }
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attributes, 0);
    pid_t process = -1;
    const int spawned = posix_spawnp(&process, argv[0], &actions, &attributes, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    close(null);
    if (output)
        close(descriptors[1]);
    if (spawned != 0)
    {
        if (output)
            close(descriptors[0]);
        blockedUntil = Clock::now() + std::chrono::seconds(30);
        return -1;
    }
    const auto deadline = Clock::now() + std::chrono::seconds(5);
    bool failed = false, complete = false;
    int status = 0;
    std::array<char, 4096> buffer;
    while (!failed)
    {
        if (output)
            for (;;)
            {
                const auto count = read(descriptors[0], buffer.data(), buffer.size());
                if (count < 0 && errno == EINTR)
                    continue;
                if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    failed = true;
                if (count <= 0)
                    break;
                if (output->size() + static_cast<size_t>(count) > 4 * 1024 * 1024)
                {
                    failed = true;
                    break;
                }
                output->append(buffer.data(), static_cast<size_t>(count));
            }
        const auto waited = waitpid(process, &status, WNOHANG);
        if (waited == process)
        {
            complete = true;
            break;
        }
        if (waited < 0 && errno != EINTR)
        {
            failed = true;
            break;
        }
        if (Clock::now() >= deadline)
        {
            failed = true;
            break;
        }
        pollfd descriptor{output ? descriptors[0] : -1, POLLIN, 0};
        poll(&descriptor, 1, 20);
    }
    if (!complete)
    {
        kill(-process, SIGKILL);
        while (waitpid(process, &status, 0) < 0)
            if (errno != EINTR)
                break;
    }
    if (complete && output)
        for (;;)
        {
            const auto count = read(descriptors[0], buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
                break;
            if (output->size() + static_cast<size_t>(count) > 4 * 1024 * 1024)
            {
                failed = true;
                break;
            }
            output->append(buffer.data(), static_cast<size_t>(count));
        }
    if (output)
        close(descriptors[0]);
    if (failed)
    {
        blockedUntil = Clock::now() + std::chrono::seconds(30);
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
bool RunCommand(const std::vector<std::string> &arguments)
{
    return Command(arguments, nullptr) == 0;
}
bool Capture(const std::vector<std::string> &arguments, std::string &output)
{
    return Command(arguments, &output) == 0;
}
bool RuleTokens(const std::string &line, std::vector<std::string> &arguments)
{
    arguments.clear();
    std::string token;
    char quote = 0;
    bool escaped = false, started = false;
    for (const char value : line)
    {
        if (escaped)
        {
            token += value;
            escaped = false;
            started = true;
            continue;
        }
        if (value == '\\' && quote != '\'')
        {
            escaped = true;
            continue;
        }
        if (quote)
        {
            if (value == quote)
                quote = 0;
            else
                token += value;
            started = true;
            continue;
        }
        if (value == '\'' || value == '"')
        {
            quote = value;
            started = true;
            continue;
        }
        if (value == ' ' || value == '\t')
        {
            if (started)
            {
                arguments.push_back(token);
                token.clear();
                started = false;
            }
        }
        else
        {
            token += value;
            started = true;
        }
    }
    if (quote || escaped)
        return false;
    if (started)
        arguments.push_back(token);
    return true;
}
bool RemoveHooks(const std::string &table, const std::string &parent, const std::string &target)
{
    std::string rules;
    if (!Capture({"iptables", "-w", "-t", table, "-S", parent}, rules))
        return false;
    std::istringstream lines(rules);
    std::string line;
    while (std::getline(lines, line))
    {
        std::vector<std::string> arguments;
        if (!RuleTokens(line, arguments))
            return false;
        if (arguments.size() < 4 || arguments[0] != "-A" || arguments[1] != parent)
            continue;
        bool own = false;
        for (size_t i = 2; i + 1 < arguments.size(); ++i)
            if (arguments[i] == "-j" && arguments[i + 1] == target)
                own = true;
        if (!own)
            continue;
        arguments[0] = "-D";
        arguments.insert(arguments.begin(), {"iptables", "-w", "-t", table});
        if (!RunCommand(arguments))
            return false;
    }
    return true;
}
bool RemovePortRule(uint16_t port, const std::string &target)
{
    if (RunCommand({"iptables", "-w", "-D", "MIGA_V2_UDP", "-p", "udp", "--dport", std::to_string(port), "-j", target}))
        return true;
    std::string rules;
    if (!Capture({"iptables", "-w", "-S", "MIGA_V2_UDP"}, rules))
        return false;
    std::istringstream lines(rules);
    std::string line;
    while (std::getline(lines, line))
    {
        std::vector<std::string> arguments;
        if (!RuleTokens(line, arguments))
            return false;
        bool matchingPort = false, matchingTarget = false;
        for (size_t i = 0; i + 1 < arguments.size(); ++i)
        {
            if (arguments[i] == "--dport" && arguments[i + 1] == std::to_string(port))
                matchingPort = true;
            if (arguments[i] == "-j" && arguments[i + 1] == target)
                matchingTarget = true;
        }
        if (matchingPort && matchingTarget)
            return false;
    }
    return true;
}
bool SecureDirectory(const std::string &path)
{
    struct stat info{};
    if (lstat(path.c_str(), &info) == 0)
        return S_ISDIR(info.st_mode) && info.st_uid == geteuid() && (info.st_mode & 0077) == 0;
    return errno == ENOENT && mkdir(path.c_str(), 0700) == 0;
}
bool SecureRead(const std::string &path, Bytes &bytes, size_t expected)
{
    int file = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0)
        return false;
    struct stat info{};
    bool valid = fstat(file, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
                 (info.st_mode & 0077) == 0 && info.st_size == static_cast<off_t>(expected);
    bytes.resize(expected);
    size_t offset = 0;
    while (valid && offset < expected)
    {
        const auto count = read(file, bytes.data() + offset, expected - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
        {
            valid = false;
            break;
        }
        offset += static_cast<size_t>(count);
    }
    close(file);
    return valid;
}
bool LoadIdentity(const std::string &directory, Key &privateKey, Key &publicKey, Key &shared)
{
    Bytes bytes;
    const std::string path = directory + "/identity";
    struct stat info{};
    if (lstat(path.c_str(), &info) == 0)
    {
        if (!SecureRead(path, bytes, 96))
            return false;
        std::copy_n(bytes.begin(), 32, privateKey.begin());
        std::copy_n(bytes.begin() + 32, 32, publicKey.begin());
        std::copy_n(bytes.begin() + 64, 32, shared.begin());
        return true;
    }
    if (errno != ENOENT || !NoiseHandshake::GenerateKeypair(privateKey, publicKey))
        return false;
    Random(shared.data(), shared.size());
    bytes.insert(bytes.end(), privateKey.begin(), privateKey.end());
    bytes.insert(bytes.end(), publicKey.begin(), publicKey.end());
    bytes.insert(bytes.end(), shared.begin(), shared.end());
    const std::string temporary = directory + "/identity.new";
    const int file = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0)
        return false;
    const bool written =
        write(file, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()) && fsync(file) == 0;
    const bool closed = close(file) == 0;
    if (!written || !closed || link(temporary.c_str(), path.c_str()) != 0)
    {
        unlink(temporary.c_str());
        return false;
    }
    unlink(temporary.c_str());
    const int parent = open(directory.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    const bool durable = parent >= 0 && fsync(parent) == 0;
    if (parent >= 0)
        close(parent);
    return durable;
}
bool SamePeer(const sockaddr_in &a, const sockaddr_in &b)
{
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}
bool Equal(const Key &a, const Key &b)
{
    uint32_t result = 0;
    for (size_t i = 0; i < a.size(); ++i)
        result |= a[i] ^ b[i];
    return result == 0;
}
int BindPort(uint16_t port, int receiveBytes = 256 * 1024, uint32_t address = INADDR_ANY)
{
    const int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (descriptor < 0)
        return -1;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = address;
    const int discovery = IP_PMTUDISC_DONT;
    const int buffer = receiveBytes / 2;
    int actual = 0;
    socklen_t optionLength = sizeof(actual);
    if (setsockopt(descriptor, IPPROTO_IP, IP_MTU_DISCOVER, &discovery, sizeof(discovery)) != 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)) != 0 ||
        getsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &actual, &optionLength) != 0 ||
        (actual < receiveBytes && setsockopt(descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &buffer, sizeof(buffer)) != 0) ||
        getsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &actual, &optionLength) != 0 ||
        bind(descriptor, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0)
    {
        const int error = errno;
        close(descriptor);
        errno = error;
        return -1;
    }
    if (actual < receiveBytes) {
        close(descriptor);
        errno = ENOBUFS;
        return -1;
    }
    return descriptor;
}
constexpr char UdpPingRequest[] = "MIGAPNG1";
constexpr char UdpPingReply[] = "MIGAPNG2";
constexpr size_t UdpPingHeaderSize = sizeof(UdpPingRequest) - 1;
constexpr size_t UdpPingSize = UdpPingHeaderSize + 16;

bool Send(int descriptor, const sockaddr_in &peer, const Bytes &bytes)
{
    return !bytes.empty() &&
           sendto(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL, reinterpret_cast<const sockaddr *>(&peer),
                  sizeof(peer)) == static_cast<ssize_t>(bytes.size());
}
}
struct Bucket
{
    double tokens = 0;
    Clock::time_point updated{};
    bool Take(double rate, double capacity, Clock::time_point now)
    {
        if (updated == Clock::time_point{})
            tokens = capacity;
        else
            tokens = std::min(capacity, tokens + std::chrono::duration<double>(now - updated).count() * rate);
        updated = now;
        if (tokens < 1)
            return false;
        tokens -= 1;
        return true;
    }
};

class V2Server::Impl
{
  public:
    struct Socket
    {
        int fd = -1;
        uint16_t port = 0;
        uint32_t diagnosticIdentity = 0;
        Key challenge{};
        SessionKeys keys{};
        ReplayWindow replay;
        uint64_t outputCounter = 0;
        Clock::time_point created = Clock::now();
        sockaddr_in peer{};
        bool bound = false;
        std::atomic<int64_t> received{0};
        std::atomic<uint64_t> accepted{0};
        std::atomic<bool> enabled{false};
        std::atomic<uint32_t> inFlight{0};
        ~Socket()
        {
            if (fd >= 0)
                close(fd);
        }
    };
    struct Session
    {
        Id id{}, client{};
        Key handshake{};
        std::shared_ptr<Socket> active, pending;
        std::map<uint32_t, uint32_t> addresses;
        Clock::time_point activity = Clock::now();
        struct Cached
        {
            Bytes input, output;
            sockaddr_in peer{};
            Clock::time_point until{};
        };
        std::map<Id, Cached> replies;
        sockaddr_in controlPeer{};
        int controlFd = -1;
        uint64_t generation = 0;
        uint32_t diagnosticIdentity = 0;
    };
    struct Quarantine
    {
        std::shared_ptr<Socket> socket;
        Clock::time_point until;
        bool dropped = false;
    };
    struct AddressQuarantine
    {
        uint32_t address;
        Clock::time_point until;
        bool cleaned;
    };
    struct FirstReply
    {
        Bytes fingerprint, response;
        sockaddr_in peer{};
        Clock::time_point until;
    };
    Json settings;
    ClientStore store;
    Key privateKey{}, publicKey{}, shared{}, envelope{}, schedule{};
    uint16_t portStart = 10000, portEnd = 15000;
    uint32_t maxSessions = 64, subnet = 0;
    uint32_t listenAddress = INADDR_ANY;
    std::string directory, host, interface, cidr, adminPath;
    int tun = -1, admin = -1;
    DiagnosticControl diagnostics;
    uint16_t diagnosticFirewallPort = 0;
    InterfaceIpCache interfaceIp;
    std::map<uint16_t, int> controls;
    bool pingPortCarriesControl = false;
    Bucket pingBucket;
    std::map<Id, std::unique_ptr<Session>> sessions;
    std::unordered_map<uint32_t, Session *> destinations;
    std::set<uint32_t> allocated;
    std::vector<Quarantine> quarantine;
    std::vector<AddressQuarantine> retiredAddresses;
    std::map<std::pair<Id, Id>, FirstReply> firstReplies;
    std::map<Id, Bucket> clientBuckets;
    std::unordered_map<uint32_t, Bucket> ipBuckets;
    Bucket globalBucket;
    Clock::time_point nextMaintenance{};
    bool firewall = false;
    Logger logger;
    std::atomic<uint64_t> udpSendErrors{0}, udpReceiveErrors{0}, tunWriteErrors{0}, tunReadErrors{0};
    std::atomic<int> lastUdpSendError{0}, lastUdpReceiveError{0}, lastTunWriteError{0}, lastTunReadError{0};
    struct DataRoute
    {
        std::shared_ptr<Socket> socket;
        uint32_t client;
    };
    struct DataSnapshot
    {
        std::vector<std::shared_ptr<Socket>> sockets;
        std::unordered_map<uint32_t, DataRoute> routes;
    };
    bool dataSnapshotDirty = false;
    std::shared_ptr<const DataSnapshot> dataSnapshot = std::make_shared<DataSnapshot>();
    std::atomic<bool> dataRunning{false};
    std::thread dataWorker;
    std::string configPath;

    ~Impl()
    {
        dataRunning = false;
        if (dataWorker.joinable())
            dataWorker.join();
        std::atomic_store(&dataSnapshot, std::shared_ptr<const DataSnapshot>(std::make_shared<DataSnapshot>()));
        diagnostics.Stop();
        if (diagnosticFirewallPort) {
            const auto port = std::to_string(diagnosticFirewallPort);
            const bool unhooked = RunCommand({"iptables", "-w", "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", "MIGA_V2_UDP"});
            const bool removed = RunCommand({"iptables", "-w", "-D", "MIGA_V2_UDP", "-p", "tcp", "--dport", port, "-j", "ACCEPT"});
            if (!unhooked || !removed)
                logger.log(LOGGER_LEVEL_WARNING, "diagnostics_firewall_remove_failed");
        }
        interfaceIp.Stop();
        for (auto &entry : sessions)
            Close(*entry.second);
        for (auto &entry : controls)
        {
            close(entry.second);
            Allow(entry.first, false);
        }
        for (auto &entry : quarantine)
        {
            Drop(entry.socket->port, true);
            Allow(entry.socket->port, false);
        }
        if (admin >= 0)
        {
            close(admin);
            unlink(adminPath.c_str());
        }
        if (tun >= 0)
            close(tun);
    }
    bool Allow(uint16_t port, bool add)
    {
        if (!firewall)
            return false;
        const std::string value = std::to_string(port);
        if (add)
        {
            if (RunCommand({"iptables", "-w", "-C", "MIGA_V2_UDP", "-p", "udp", "--dport", value, "-j", "ACCEPT"}))
                return true;
            return RunCommand(
                {"iptables", "-w", "-I", "MIGA_V2_UDP", "1", "-p", "udp", "--dport", value, "-j", "ACCEPT"});
        }
        return RemovePortRule(port, "ACCEPT");
    }
    bool Drop(uint16_t port, bool add)
    {
        const std::string value = std::to_string(port);
        if (add && RunCommand({"iptables", "-w", "-C", "MIGA_V2_UDP", "-p", "udp", "--dport", value, "-j", "DROP"}))
            return true;
        if (!add)
            return RemovePortRule(port, "DROP");
        return RunCommand({"iptables", "-w", "-I", "MIGA_V2_UDP", "-p", "udp", "--dport", value, "-j", "DROP"});
    }
    bool SetupFirewall()
    {
        for (const auto *chain : {"MIGA_V2_UDP", "MIGA_V2_FORWARD"})
        {
            RunCommand({"iptables", "-w", "-N", chain});
            if (!RunCommand({"iptables", "-w", "-F", chain}))
                return false;
        }
        for (const auto *chain : {"MIGA_V2_NAT", "MIGA_V2_DNS"})
        {
            RunCommand({"iptables", "-w", "-t", "nat", "-N", chain});
            if (!RunCommand({"iptables", "-w", "-t", "nat", "-F", chain}))
                return false;
        }
        if (!RemoveHooks("filter", "INPUT", "MIGA_V2_UDP") || !RemoveHooks("filter", "FORWARD", "MIGA_V2_FORWARD") ||
            !RemoveHooks("nat", "POSTROUTING", "MIGA_V2_NAT") || !RemoveHooks("nat", "PREROUTING", "MIGA_V2_DNS"))
            return false;
        if (!RunCommand({"iptables", "-w", "-I", "INPUT", "1", "-p", "udp", "-j", "MIGA_V2_UDP"}) ||
            !RunCommand({"iptables", "-w", "-A", "MIGA_V2_UDP", "-p", "udp", "--dport",
                         std::to_string(portStart) + ":" + std::to_string(portEnd), "-j", "DROP"}) ||
            !RunCommand({"iptables", "-w", "-t", "nat", "-A", "POSTROUTING", "-j", "MIGA_V2_NAT"}) ||
            !RunCommand({"iptables", "-w", "-t", "nat", "-A", "MIGA_V2_NAT", "-s", cidr, "-o", interface, "-j",
                         "MASQUERADE"}) ||
            !RunCommand({"iptables", "-w", "-t", "nat", "-A", "PREROUTING", "-j", "MIGA_V2_DNS"}) ||
            !RunCommand({"iptables", "-w", "-A", "MIGA_V2_FORWARD", "-i", "tun_miga", "-s", cidr, "-o", interface, "-j",
                         "ACCEPT"}) ||
            !RunCommand({"iptables", "-w", "-A", "MIGA_V2_FORWARD", "-i", interface, "-d", cidr, "-o", "tun_miga", "-m",
                         "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}) ||
            !RunCommand({"iptables", "-w", "-I", "FORWARD", "1", "-j", "MIGA_V2_FORWARD"}))
            return false;
        const std::string dns = settings.value("dns_server", std::string());
        if (!dns.empty())
        {
            in_addr server{};
            if (inet_pton(AF_INET, dns.c_str(), &server) != 1 ||
                !RunCommand({"iptables", "-w", "-t", "nat", "-A", "MIGA_V2_DNS", "-i", "tun_miga", "-s", cidr, "-p",
                             "udp", "--dport", "53", "-j", "DNAT", "--to-destination", dns}))
                return false;
        }
        else
        {
            for (const auto *subnet : {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
                if (!RunCommand({"iptables", "-w", "-t", "nat", "-A", "MIGA_V2_DNS", "-i", "tun_miga", "-s", cidr,
                                 "-d", subnet, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "8.8.8.8"}))
                    return false;
        }
        const auto diagnosticSettings = settings.value("diagnostics", Json::object());
        const auto diagnosticPort = diagnosticSettings.is_object() ? diagnosticSettings.value("port", 47900) : 47900;
        if (diagnosticPort < 0 || diagnosticPort > 65535) return false;
        if (diagnosticPort > 0) {
            if (!RunCommand({"iptables", "-w", "-A", "MIGA_V2_UDP", "-p", "tcp", "--dport", std::to_string(diagnosticPort), "-j", "ACCEPT"})) return false;
            diagnosticFirewallPort = static_cast<uint16_t>(diagnosticPort);
            if (!RunCommand({"iptables", "-w", "-I", "INPUT", "1", "-p", "tcp", "--dport", std::to_string(diagnosticPort), "-j", "MIGA_V2_UDP"})) return false;
        }
        firewall = true;
        return true;
    }
    bool Conntrack(uint32_t address)
    {
        RunCommand({"conntrack", "-D", "-s", TextIp(address)});
        RunCommand({"conntrack", "-D", "-d", TextIp(address)});
        std::string source, destination;
        return Capture({"conntrack", "-L", "-s", TextIp(address)}, source) && source.empty() &&
               Capture({"conntrack", "-L", "-d", TextIp(address)}, destination) && destination.empty();
    }
    uint32_t Address(Session &session, uint32_t local)
    {
        const auto known = session.addresses.find(local);
        if (known != session.addresses.end())
            return known->second;
        if (local == 0 || session.addresses.size() >= 16 || allocated.size() >= static_cast<size_t>(maxSessions) * 16)
            return 0;
        for (uint32_t offset = 2; offset < 65535; ++offset)
        {
            const auto address = subnet + offset;
            if (allocated.count(address) == 0)
            {
                if (!store.ReserveAddress(address))
                    return 0;
                allocated.insert(address);
                session.addresses[local] = address;
                destinations[address] = &session;
                if (session.active && session.active->bound)
                    dataSnapshotDirty = true;
                return address;
            }
        }
        return 0;
    }
    void Retire(std::shared_ptr<Socket> &socket)
    {
        if (!socket)
            return;
        socket->enabled.store(false);
        while (socket->inFlight.load())
            std::this_thread::yield();
        quarantine.push_back({socket, Clock::now() + std::chrono::minutes(2)});
        socket.reset();
    }
    void Close(Session &session)
    {
        if (session.diagnosticIdentity) diagnostics.Revoke(session.diagnosticIdentity);
        if (session.active && session.active->bound)
            dataSnapshotDirty = true;
        Retire(session.active);
        Retire(session.pending);
        for (const auto &address : session.addresses)
        {
            destinations.erase(address.second);
            retiredAddresses.push_back(
                {address.second, Clock::now() + std::chrono::minutes(2), Conntrack(address.second)});
        }
        session.addresses.clear();
    }
    std::shared_ptr<Socket> Reserve()
    {
        size_t pending = 0, sockets = quarantine.size();
        for (const auto &session : sessions)
        {
            if (session.second->pending)
            {
                ++pending;
                ++sockets;
            }
            if (session.second->active)
                ++sockets;
        }
        if (sockets >= 1024)
            return {};
        if (pending >= static_cast<size_t>(maxSessions) * 2)
            return {};
        uint32_t random = 0;
        Random(reinterpret_cast<uint8_t *>(&random), sizeof(random));
        for (uint32_t attempt = 0; attempt < 64512; ++attempt)
        {
            const uint16_t port = static_cast<uint16_t>(1024 + (random + attempt) % 64512);
            if (port >= portStart && port <= portEnd)
                continue;
            const int fd = BindPort(port, 8 * 1024 * 1024, listenAddress);
            if (fd < 0) {
                const int error = errno;
                if (error == EADDRINUSE) continue;
                logger.logLazy(LOGGER_LEVEL_WARNING, [&] {
                    return "session_socket_failed target_receive_bytes=8388608 errno=" + std::to_string(error);
                });
                return {};
            }
            if (!store.ReservePort(port))
            {
                close(fd);
                continue;
            }
            if (!Allow(port, true))
            {
                store.ReleasePort(port);
                close(fd);
                return {};
            }
            auto socket = std::make_shared<Socket>();
            socket->fd = fd;
            socket->port = port;
            Random(socket->challenge.data(), socket->challenge.size());
            return socket;
        }
        return {};
    }
    bool Initialize(const std::string &path);
    void Maintain();
    void Control(int fd, const sockaddr_in &peer, const uint8_t *data, size_t length);
    void HelloRequest(int fd, const sockaddr_in &peer, const Message &message);
    void SessionControl(int fd, const sockaddr_in &peer, const uint8_t *data, size_t length, Socket *binding = nullptr);
    void Data(Session &session, Socket &socket, const sockaddr_in &peer, const uint8_t *data, size_t length);
    Json AdminCommand(const Json &command);
    void PollAdmin();
    void Run(const std::atomic<bool> &running);
    void Publish();
    void DataLoop();
    bool SendDataToClient(Socket &socket, const Bytes &bytes)
    {
        if (Send(socket.fd, socket.peer, bytes))
            return true;
        lastUdpSendError.store(errno, std::memory_order_relaxed);
        udpSendErrors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    bool WriteTun(const uint8_t *packet, size_t length)
    {
        const auto written = write(tun, packet, length);
        if (written == static_cast<ssize_t>(length))
            return true;
        lastTunWriteError.store(written < 0 ? errno : EIO, std::memory_order_relaxed);
        tunWriteErrors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
};

V2Server::V2Server() : impl_(std::make_unique<Impl>())
{
}
V2Server::~V2Server() = default;
bool V2Server::Initialize(const std::string &path)
{
    return impl_->Initialize(path);
}
void V2Server::Run(const std::atomic<bool> &running)
{
    impl_->Run(running);
}

bool V2Server::Impl::Initialize(const std::string &path)
{
    try
    {
        if (!miga::v2::Initialize())
            return false;
        configPath = path;
        std::ifstream input(path);
        if (!input || !(input >> settings) || settings.value("protocol", 0) != 2)
            return false;
        const auto level = settings.value("log_level", std::string("info"));
        logger.enable(level == "debug"     ? LOGGER_LEVEL_DEBUG
                      : level == "info"    ? LOGGER_LEVEL_INFO
                      : level == "warning" ? LOGGER_LEVEL_WARNING
                      : level == "error"   ? LOGGER_LEVEL_ERROR
                                           : LOGGER_LEVEL_NONE,
                      isatty(STDOUT_FILENO) != 0);
        directory = settings.value("state_directory", std::string("/var/lib/miga"));
        host = settings.at("host").get<std::string>();
        in_addr listenAddressParsed{};
        if (inet_pton(AF_INET, host.c_str(), &listenAddressParsed) == 1)
            listenAddress = listenAddressParsed.s_addr;
        else
        {
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            addrinfo *resolved = nullptr;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &resolved) != 0 || resolved == nullptr)
                return false;
            listenAddress = reinterpret_cast<const sockaddr_in *>(resolved->ai_addr)->sin_addr.s_addr;
            freeaddrinfo(resolved);
        }
        interface = settings.at("interface").get<std::string>();
        cidr = settings.at("virtual_subnet").get<std::string>();
        maxSessions = settings.value("max_sessions", 64u);
        const auto ports = settings.value("control_ports", Json::array({10000, 15000}));
        if (!ports.is_array() || ports.size() != 2 || !ports[0].is_number_integer() || !ports[1].is_number_integer())
            return false;
        const auto start = ports[0].get<int64_t>(), end = ports[1].get<int64_t>();
        if (start < 1024 || end > 65535 || start > end || maxSessions == 0 || maxSessions > 512 ||
            maxSessions * 8 > 64512 - (end - start + 1))
            return false;
        portStart = static_cast<uint16_t>(start);
        portEnd = static_cast<uint16_t>(end);
        const auto slash = cidr.find('/');
        in_addr base{};
        if (slash == std::string::npos || cidr.substr(slash) != "/16" ||
            inet_pton(AF_INET, cidr.substr(0, slash).c_str(), &base) != 1)
            return false;
        subnet = ntohl(base.s_addr);
        if ((subnet & 65535) != 0 || !((subnet >> 24) == 10 || (subnet >> 20) == 0xac1 || (subnet >> 16) == 0xc0a8))
            return false;
        if (interface.empty() || interface.size() >= IFNAMSIZ ||
            interface.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") !=
                std::string::npos)
            return false;
        for (const auto *table : {"/proc/net/udp", "/proc/net/udp6"})
        {
            std::ifstream sockets(table);
            std::string line;
            if (!sockets || !std::getline(sockets, line))
                return false;
            while (std::getline(sockets, line))
            {
                std::istringstream fields(line);
                std::string index, local;
                if (!(fields >> index >> local))
                    return false;
                const auto colon = local.find_last_of(':');
                if (colon == std::string::npos)
                    return false;
                const auto port = std::stoul(local.substr(colon + 1), nullptr, 16);
                if (port >= portStart && port <= portEnd)
                    return false;
            }
        }
        std::string routes;
        if (!Capture({"ip", "-j", "-4", "route", "show", "table", "all"}, routes))
            return false;
        for (const auto &route : Json::parse(routes))
        {
            const auto destination = route.value("dst", std::string("default"));
            if (destination == "default" || route.value("dev", std::string()) == "tun_miga")
                continue;
            const auto delimiter = destination.find('/');
            in_addr address{};
            if (inet_pton(AF_INET, destination.substr(0, delimiter).c_str(), &address) != 1)
                return false;
            const unsigned bits = delimiter == std::string::npos
                                      ? 32
                                      : static_cast<unsigned>(std::stoul(destination.substr(delimiter + 1)));
            if (bits > 32)
                return false;
            const uint32_t mask = bits == 0 ? 0 : 0xffffffffu << (32 - bits);
            const auto low = ntohl(address.s_addr) & mask;
            const auto high = low | ~mask;
            if (low <= subnet + 65535 && high >= subnet)
                return false;
        }
        if (!SecureDirectory(directory) || !LoadIdentity(directory, privateKey, publicKey, shared) ||
            !store.Open(directory + "/clients.sqlite3"))
            return false;
        envelope = EnvelopeKey(shared);
        schedule = ScheduleKey(shared);
        tun = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (tun < 0)
            return false;
        ifreq request{};
        request.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strcpy(request.ifr_name, "tun_miga");
        if (ioctl(tun, TUNSETIFF, &request) != 0 ||
            !RunCommand({"ip", "addr", "replace", TextIp(subnet + 1) + "/16", "dev", "tun_miga"}) ||
            !RunCommand({"ip", "link", "set", "dev", "tun_miga", "mtu", "65535", "up"}) || !SetupFirewall())
            return false;
        std::vector<uint32_t> oldAddresses;
        std::vector<uint16_t> oldPorts;
        if (!store.ReservedAddresses(oldAddresses) || !store.ReservedPorts(oldPorts) || oldPorts.size() > 1024)
            return false;
        for (const auto address : oldAddresses)
        {
            if (address <= subnet + 1 || address >= subnet + 65535)
                return false;
            allocated.insert(address);
            retiredAddresses.push_back({address, Clock::now() + std::chrono::minutes(2), Conntrack(address)});
        }
        for (const auto port : oldPorts)
        {
            if (port < 1024 || (port >= portStart && port <= portEnd))
                return false;
            const int fd = BindPort(port, 256 * 1024, listenAddress);
            if (fd < 0 || !Drop(port, true))
            {
                if (fd >= 0)
                    close(fd);
                return false;
            }
            Allow(port, false);
            auto socket = std::make_shared<Socket>();
            socket->fd = fd;
            socket->port = port;
            quarantine.push_back({socket, Clock::now() + std::chrono::minutes(2), true});
        }
        if (!interfaceIp.Start(interface) || !diagnostics.Configure(settings.value("diagnostics", Json())))
            return false;
        diagnostics.SetNetworkSource([this](uint32_t identity) -> std::shared_ptr<const int> {
            const auto snapshot = std::atomic_load(&dataSnapshot);
            for (const auto &socket : snapshot->sockets)
                if (socket->diagnosticIdentity == identity && socket->enabled.load())
                    return std::shared_ptr<const int>(socket, &socket->fd);
            return {};
        }, [this] { return interfaceIp.Get(); });
        diagnostics.load.firewall = [this](uint16_t port, bool add) {
            return RunCommand({"iptables", "-w", add ? "-I" : "-D", "MIGA_V2_UDP", "-i", "tun_miga",
                "-p", "udp", "--dport", std::to_string(port), "-j", "ACCEPT"});
        };
        if (!diagnostics.Start())
            return false;
        adminPath = directory + "/admin.sock";
        admin = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        sockaddr_un local{};
        local.sun_family = AF_UNIX;
        if (admin < 0 || adminPath.size() >= sizeof(local.sun_path))
            return false;
        std::strcpy(local.sun_path, adminPath.c_str());
        struct stat existing{};
        if (lstat(adminPath.c_str(), &existing) == 0)
        {
            if (!S_ISSOCK(existing.st_mode) || existing.st_uid != geteuid())
                return false;
            const int probe = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
            const bool inUse = probe >= 0 && connect(probe, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0;
            if (probe >= 0)
                close(probe);
            if (inUse || unlink(adminPath.c_str()) != 0)
                return false;
        }
        const auto oldMask = umask(0077);
        const bool bound = bind(admin, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0;
        umask(oldMask);
        if (!bound || chmod(adminPath.c_str(), 0600) != 0 || listen(admin, 8) != 0)
            return false;
        Maintain();
        return std::any_of(controls.begin(), controls.end(), [this](const auto &entry) {
            return entry.first != portStart || pingPortCarriesControl;
        });
    }
    catch (...)
    {
        return false;
    }
}

void V2Server::Impl::Maintain()
{
    const auto now = Clock::now();
    const auto utc = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t day = utc / 86400;
    std::set<uint16_t> required{DailyPort(schedule, day, portStart, portEnd)};
    if (utc % 86400 < 300 && day > 0)
        required.insert(DailyPort(schedule, day - 1, portStart, portEnd));
    if (utc % 86400 >= 86100)
        required.insert(DailyPort(schedule, day + 1, portStart, portEnd));
    pingPortCarriesControl = required.count(portStart) != 0;
    required.insert(portStart);
    for (const auto port : required)
        if (controls.count(port) == 0)
        {
            const int fd = BindPort(port, 256 * 1024, listenAddress);
            if (fd >= 0)
            {
                if (Allow(port, true))
                    controls.emplace(port, fd);
                else
                    close(fd);
            }
        }
    for (auto it = controls.begin(); it != controls.end();)
    {
        if (required.count(it->first) == 0)
        {
            Allow(it->first, false);
            close(it->second);
            it = controls.erase(it);
        }
        else
            ++it;
    }
    std::map<Id, bool> revoked;
    for (const auto &session : sessions)
        if (revoked.count(session.second->client) == 0)
        {
            bool value = false;
            if (store.IsRevoked(session.second->client, value))
                revoked[session.second->client] = value;
        }
    for (auto it = sessions.begin(); it != sessions.end();)
    {
        auto &session = *it->second;
        for (auto cached = session.replies.begin(); cached != session.replies.end();)
        {
            if (cached->second.until != Clock::time_point{} && now >= cached->second.until)
                cached = session.replies.erase(cached);
            else
                ++cached;
        }
        if (session.active)
        {
            const auto ticks = session.active->received.load(std::memory_order_relaxed);
            if (ticks)
                session.activity = std::max(session.activity, Clock::time_point(Clock::duration(ticks)));
        }
        if (session.pending && now - session.pending->created >= std::chrono::seconds(30))
            Retire(session.pending);
        if ((!session.active && !session.pending) || now - session.activity >= std::chrono::minutes(5) ||
            (revoked.count(session.client) != 0 && revoked[session.client]))
        {
            Close(session);
            it = sessions.erase(it);
        }
        else
            ++it;
    }
    for (auto it = quarantine.begin(); it != quarantine.end();)
    {
        if (!it->dropped)
            it->dropped = Drop(it->socket->port, true) && Allow(it->socket->port, false);
        if (it->dropped && now >= it->until && it->socket.use_count() == 1 && Drop(it->socket->port, false) &&
            store.ReleasePort(it->socket->port))
            it = quarantine.erase(it);
        else
            ++it;
    }
    for (auto it = retiredAddresses.begin(); it != retiredAddresses.end();)
    {
        if (!it->cleaned)
        {
            it->cleaned = Conntrack(it->address);
            if (it->cleaned)
                it->until = now + std::chrono::minutes(2);
        }
        if (it->cleaned && now >= it->until && Conntrack(it->address) && store.ReleaseAddress(it->address))
        {
            allocated.erase(it->address);
            it = retiredAddresses.erase(it);
        }
        else
            ++it;
    }
    for (auto it = firstReplies.begin(); it != firstReplies.end();)
    {
        if (now >= it->second.until)
            it = firstReplies.erase(it);
        else
            ++it;
    }
    for (auto it = ipBuckets.begin(); it != ipBuckets.end();)
    {
        if (now - it->second.updated > std::chrono::minutes(10))
            it = ipBuckets.erase(it);
        else
            ++it;
    }
    for (auto it = clientBuckets.begin(); it != clientBuckets.end();)
    {
        if (now - it->second.updated > std::chrono::minutes(10))
            it = clientBuckets.erase(it);
        else
            ++it;
    }
    const auto sends = udpSendErrors.exchange(0, std::memory_order_relaxed);
    const auto receives = udpReceiveErrors.exchange(0, std::memory_order_relaxed);
    const auto writes = tunWriteErrors.exchange(0, std::memory_order_relaxed);
    const auto reads = tunReadErrors.exchange(0, std::memory_order_relaxed);
    if (sends || receives || writes || reads)
        logger.logLazy(LOGGER_LEVEL_WARNING, [&] {
            return "runtime_io_error udp_send_errors=" + std::to_string(sends) +
                   " udp_receive_errors=" + std::to_string(receives) + " tun_write_errors=" + std::to_string(writes) +
                   " tun_read_errors=" + std::to_string(reads) +
                   " udp_send_errno=" + std::to_string(lastUdpSendError.load(std::memory_order_relaxed)) +
                   " udp_receive_errno=" + std::to_string(lastUdpReceiveError.load(std::memory_order_relaxed)) +
                   " tun_write_errno=" + std::to_string(lastTunWriteError.load(std::memory_order_relaxed)) +
                   " tun_read_errno=" + std::to_string(lastTunReadError.load(std::memory_order_relaxed));
        });
    nextMaintenance = now + std::chrono::seconds(1);
    Publish();
}

void V2Server::Impl::Publish()
{
    if (!dataSnapshotDirty)
        return;
    auto snapshot = std::make_shared<DataSnapshot>();
    for (const auto &entry : sessions)
    {
        const auto &session = *entry.second;
        if (!session.active || !session.active->bound)
            continue;
        snapshot->sockets.push_back(session.active);
        for (const auto &address : session.addresses)
            snapshot->routes.emplace(address.second, DataRoute{session.active, session.active->peer.sin_addr.s_addr});
    }
    std::atomic_store(&dataSnapshot, std::shared_ptr<const DataSnapshot>(snapshot));
    dataSnapshotDirty = false;
}

void V2Server::Impl::HelloRequest(int fd, const sockaddr_in &peer, const Message &message)
{
    Hello hello;
    if (!DecodeHello(message.body, hello))
        return;
    const auto now = Clock::now();
    ClientRecord client;
    if (!store.Get(hello.client, client) || client.revoked)
        return;
    const auto proof = HelloProof(client.secret, hello.client, hello.time, message.request, publicKey, hello.noise);
    if (!Equal(proof, hello.proof))
        return;
    const auto utc = static_cast<int64_t>(std::time(nullptr));
    if (hello.time > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        static_cast<int64_t>(hello.time) < utc - 120 || static_cast<int64_t>(hello.time) > utc + 120)
        return;
    const auto digest = Hmac(envelope, message.body.data(), message.body.size());
    Bytes fingerprint(digest.begin(), digest.end());
    const auto known = firstReplies.find({hello.client, message.request});
    if (known != firstReplies.end())
    {
        if (SamePeer(known->second.peer, peer) && known->second.fingerprint == fingerprint)
            Send(fd, peer, known->second.response);
        return;
    }
    if (clientBuckets.count(hello.client) == 0 && clientBuckets.size() >= 65536)
        return;
    if (!globalBucket.Take(std::min(maxSessions, 100u), std::min(maxSessions, 100u), now) ||
        !clientBuckets[hello.client].Take(1, 4, now))
        return;
    if (store.Admit(hello.client, message.request, fingerprint, peer.sin_addr.s_addr, ntohs(peer.sin_port),
                    static_cast<int64_t>(hello.time), utc, maxSessions) != Admission::Accepted)
        return;
    size_t count = 0;
    for (const auto &session : sessions)
        if (session.second->client == hello.client)
            ++count;
    if (sessions.size() >= maxSessions || (client.maxConnections && count >= client.maxConnections))
        return;
    NoiseHandshake noise;
    Bytes payload;
    if (!noise.Start(false, publicKey, &privateKey) || !noise.Read(hello.noise, payload) || payload.empty() ||
        payload[0] == 0 || payload[0] > 16 || payload.size() != 1 + static_cast<size_t>(payload[0]) * 4)
        return;
    auto session = std::make_unique<Session>();
    Random(session->id.data(), session->id.size());
    if (sessions.count(session->id))
        return;
    session->client = hello.client;
    session->controlPeer = peer;
    session->controlFd = fd;
    session->pending = Reserve();
    if (!session->pending)
        return;
    bool valid = true;
    for (size_t i = 0; i < payload[0]; ++i)
        if (!Address(*session, Get32(payload.data() + 1 + i * 4)))
            valid = false;
    OpenReply parameters;
    parameters.session = session->id;
    Random(parameters.secret.data(), parameters.secret.size());
    parameters.challenge = session->pending->challenge;
    parameters.port = session->pending->port;
    for (const auto &address : session->addresses)
        parameters.addresses.push_back(address);
    Message response;
    response.operation = Operation::HelloReply;
    response.request = message.request;
    if (!valid || !noise.Write(EncodeOpenReply(parameters), response.body) || !noise.Complete() ||
        !noise.Hash(session->handshake))
    {
        Close(*session);
        return;
    }
    session->pending->keys = DeriveSession(parameters.secret, session->handshake, session->client, session->id);
    Bytes output = Seal(envelope, EncodeMessage(response));
    if (output.empty() || firstReplies.size() >= static_cast<size_t>(maxSessions) * 1024)
    {
        Close(*session);
        return;
    }
    firstReplies.emplace(std::make_pair(hello.client, message.request),
                         FirstReply{fingerprint, output, peer, now + std::chrono::minutes(10)});
    sessions.emplace(session->id, std::move(session));
    Send(fd, peer, output);
}

void V2Server::Impl::Control(int fd, const sockaddr_in &peer, const uint8_t *data, size_t length)
{
    if (length > MaxControl || length < 40)
        return;
    const auto now = Clock::now();
    if (ipBuckets.count(peer.sin_addr.s_addr) == 0 && ipBuckets.size() >= 4096)
        return;
    if (!ipBuckets[peer.sin_addr.s_addr].Take(10, 20, now))
        return;
    Bytes outer;
    if (!Unseal(envelope, data, length, outer))
        return;
    Message message;
    if (DecodeMessage(outer, message) && message.operation == Operation::Hello)
    {
        HelloRequest(fd, peer, message);
        return;
    }
    SessionControl(fd, peer, data, length);
}

void V2Server::Impl::SessionControl(int fd, const sockaddr_in &peer, const uint8_t *data, size_t length,
                                    Socket *binding)
{
    Bytes outer;
    if (!Unseal(envelope, data, length, outer) || outer.size() < 18)
        return;
    Id id{};
    std::copy_n(outer.begin(), 16, id.begin());
    const auto found = sessions.find(id);
    if (found == sessions.end())
        return;
    auto &session = *found->second;
    Message message;
    uint64_t counter = 0;
    Id verified{};
    std::shared_ptr<Socket> socket;
    if (binding)
    {
        if (!session.pending || session.pending.get() != binding ||
            !UnsealControl(envelope, binding->keys.controlC2S, data, length, verified, counter, message))
            return;
        socket = session.pending;
    }
    else
    {
        if (session.active &&
            UnsealControl(envelope, session.active->keys.controlC2S, data, length, verified, counter, message))
            socket = session.active;
        else if (session.pending &&
                 UnsealControl(envelope, session.pending->keys.controlC2S, data, length, verified, counter, message))
            socket = session.pending;
        else
            return;
    }
    if (verified != session.id || (binding && message.operation != Operation::Bind))
        return;
    const auto input = EncodeMessage(message);
    const auto cached = session.replies.find(message.request);
    if (cached != session.replies.end())
    {
        if (cached->second.input == input && SamePeer(cached->second.peer, peer))
        {
            if (message.operation == Operation::Bind)
            {
                const auto daily = controls.find(
                    DailyPort(schedule, static_cast<uint64_t>(std::time(nullptr)) / 86400, portStart, portEnd));
                if (daily != controls.end())
                    Send(daily->second, session.controlPeer, cached->second.output);
            }
            else
                Send(fd, peer, cached->second.output);
        }
        return;
    }
    if (!socket->replay.Accept(counter) || session.replies.size() >= 1024)
        return;
    Message response;
    response.operation = Operation::Error;
    response.request = message.request;
    bool closing = false;
    int responseFd = fd;
    sockaddr_in responsePeer = peer;
    switch (message.operation)
    {
    case Operation::Bind: {
        if (!binding || message.body.size() != 32 ||
            !std::equal(message.body.begin(), message.body.end(), socket->challenge.begin()))
            return;
        const auto daily = controls.find(
            DailyPort(schedule, static_cast<uint64_t>(std::time(nullptr)) / 86400, portStart, portEnd));
        if (daily == controls.end())
            return;
        socket->peer = peer;
        socket->bound = true;
        Retire(session.active);
        session.active = session.pending;
        session.pending.reset();
        if (!session.diagnosticIdentity && !session.addresses.empty()) session.diagnosticIdentity = session.addresses.begin()->second;
        session.active->diagnosticIdentity = session.diagnosticIdentity;
        session.active->enabled.store(true);
        ++session.generation;
        response.operation = Operation::Ready;
        responsePeer = session.controlPeer;
        responseFd = daily->second;
        dataSnapshotDirty = true;
        break;
    }
    case Operation::DiagnosticOpen:
        if (!message.body.empty() || !session.active || socket != session.active) return;
        response.body = diagnostics.Authorize(session.active->diagnosticIdentity);
        response.operation = Operation::DiagnosticReply;
        break;
    case Operation::Status:
        if (!message.body.empty())
            return;
        session.controlPeer = peer;
        session.controlFd = fd;
        response.operation = session.active ? Operation::Ready : Operation::Status;
        break;
    case Operation::AddAddress:
        if (message.body.size() != 4)
            return;
        if (const auto address = Address(session, Get32(message.body.data())))
        {
            response.operation = Operation::AddressReply;
            response.body = message.body;
            Put32(response.body, address);
        }
        break;
    case Operation::Resume: {
        if (!session.active || socket != session.active || message.body.size() < 33 || message.body[32] > 16 ||
            message.body.size() != 33 + size_t(message.body[32]) * 4 ||
            !std::equal(message.body.begin(), message.body.begin() + 32, socket->keys.resume.begin()))
            return;
        if (session.pending)
            return;
        session.pending = Reserve();
        if (!session.pending)
            break;
        OpenReply parameters;
        parameters.session = session.id;
        parameters.port = session.pending->port;
        parameters.challenge = session.pending->challenge;
        Random(parameters.secret.data(), parameters.secret.size());
        for (size_t i = 0; i < message.body[32]; ++i)
        {
            if (!Address(session, Get32(message.body.data() + 33 + i * 4)))
            {
                Retire(session.pending);
                Publish();
                return;
            }
        }
        for (const auto &address : session.addresses)
            parameters.addresses.push_back(address);
        session.pending->keys = DeriveSession(parameters.secret, session.handshake, session.client, session.id);
        session.controlPeer = peer;
        session.controlFd = fd;
        response.operation = Operation::OpenReply;
        response.body = EncodeOpenReply(parameters);
        break;
    }
    case Operation::Close:
        if (!message.body.empty())
            return;
        response.operation = Operation::Close;
        closing = true;
        break;
    default:
        return;
    }
    if (response.operation == Operation::Ready && session.active)
    {
        Put64(response.body, session.active->accepted.load(std::memory_order_relaxed));
        Put64(response.body, session.generation | DataProbeCapability);
    }
    const auto output = SealControl(envelope, socket->keys.controlS2C, session.id, ++socket->outputCounter, response);
    session.replies.emplace(message.request,
                            Session::Cached{input, output, peer, Clock::now() + std::chrono::seconds(120)});
    session.activity = Clock::now();
    if (!closing)
        Publish();
    Send(responseFd, responsePeer, output);
    if (closing)
    {
        Close(session);
        sessions.erase(found);
        Publish();
    }
}

void V2Server::Impl::DataLoop()
{
    std::array<uint8_t, 65536> buffer{};
    std::array<std::array<uint8_t, 65536>, 16> receiveBuffers{};
    std::array<mmsghdr, 16> messages{};
    std::array<iovec, 16> parts{};
    std::array<sockaddr_in, 16> peers{};
    struct InFlight
    {
        Socket &socket;
        bool active;
        explicit InFlight(Socket &value) : socket(value), active(false)
        {
            socket.inFlight.fetch_add(1);
            active = socket.enabled.load();
        }
        ~InFlight()
        {
            socket.inFlight.fetch_sub(1);
        }
    };
    Bytes plaintext, encrypted;
    std::vector<Bytes> fragments;
    Bytes icmp;
    plaintext.reserve(65536);
    encrypted.reserve(65536);
    std::shared_ptr<const DataSnapshot> snapshot;
    std::vector<pollfd> descriptors;
    while (dataRunning.load(std::memory_order_relaxed))
    {
        const auto current = std::atomic_load(&dataSnapshot);
        if (snapshot != current)
        {
            snapshot = current;
            descriptors.clear();
            descriptors.push_back({tun, POLLIN, 0});
            for (const auto &socket : snapshot->sockets)
                descriptors.push_back({socket->fd, POLLIN, 0});
        }
        const int ready = poll(descriptors.data(), descriptors.size(), 50);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            continue;
        for (size_t index = 0; index < descriptors.size(); ++index)
        {
            if (!(descriptors[index].revents & POLLIN))
                continue;
            size_t received = 16;
            if (index != 0)
            {
                for (size_t i = 0; i < messages.size(); ++i)
                {
                    parts[i] = {receiveBuffers[i].data(), receiveBuffers[i].size()};
                    messages[i] = {};
                    messages[i].msg_hdr.msg_name = &peers[i];
                    messages[i].msg_hdr.msg_namelen = sizeof(peers[i]);
                    messages[i].msg_hdr.msg_iov = &parts[i];
                    messages[i].msg_hdr.msg_iovlen = 1;
                }
                const int count = recvmmsg(descriptors[index].fd, messages.data(),
                                           static_cast<unsigned>(messages.size()), MSG_DONTWAIT, nullptr);
                if (count <= 0)
                {
                    if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    {
                        lastUdpReceiveError.store(errno, std::memory_order_relaxed);
                        udpReceiveErrors.fetch_add(1, std::memory_order_relaxed);
                    }
                    continue;
                }
                received = static_cast<size_t>(count);
            }
            for (size_t batch = 0; batch < received; ++batch)
            {
                if (index == 0)
                {
                    const auto length = read(tun, buffer.data(), buffer.size());
                    if (length <= 0)
                    {
                        if (length < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        {
                            lastTunReadError.store(errno, std::memory_order_relaxed);
                            tunReadErrors.fetch_add(1, std::memory_order_relaxed);
                        }
                        break;
                    }
                    if (static_cast<size_t>(length) > MaxInner)
                    {
                        if (!FragmentInner(buffer.data(), static_cast<size_t>(length), fragments, icmp))
                            continue;
                        if (!icmp.empty())
                        {
                            WriteTun(icmp.data(), icmp.size());
                            continue;
                        }
                        for (const auto &fragment : fragments)
                        {
                            const auto route = snapshot->routes.find(Get32(fragment.data() + 16));
                            if (route == snapshot->routes.end())
                                continue;
                            auto &socket = *route->second.socket;
                            InFlight operation(socket);
                            if (!operation.active)
                                continue;
                            if (EncryptData(socket.keys.dataS2C, socket.keys.prefixS2C, fragment.data(),
                                            fragment.size(), encrypted))
                                SendDataToClient(socket, encrypted);
                        }
                        continue;
                    }
                    size_t actual = 0;
                    bool keepalive = false;
                    if (!ValidateInner(buffer.data(), static_cast<size_t>(length), actual, keepalive) || keepalive ||
                        actual != static_cast<size_t>(length))
                        continue;
                    const auto route = snapshot->routes.find(Get32(buffer.data() + 16));
                    if (route == snapshot->routes.end())
                        continue;
                    diagnostics.Inbound(buffer.data(), actual);
                    auto &socket = *route->second.socket;
                    InFlight operation(socket);
                    if (!operation.active)
                        continue;
                    diagnostics.LoadPacket(miga::diagnostics::LoadCounters::TunRead, buffer.data(), actual, socket.diagnosticIdentity);
                    const bool sent = EncryptData(socket.keys.dataS2C, socket.keys.prefixS2C, buffer.data(), actual, encrypted) && SendDataToClient(socket, encrypted);
                    diagnostics.LoadPacket(miga::diagnostics::LoadCounters::WireSent, buffer.data(), actual, socket.diagnosticIdentity, sent);
                }
                else
                {
                    auto &socket = *snapshot->sockets[index - 1];
                    InFlight operation(socket);
                    if (!operation.active || (messages[batch].msg_hdr.msg_flags & MSG_TRUNC))
                        continue;
                    const auto &peer = peers[batch];
                    const auto length = messages[batch].msg_len;
                    if (!SamePeer(socket.peer, peer) || !DecryptData(socket.keys.dataC2S, socket.keys.prefixC2S,
                                                                     receiveBuffers[batch].data(), length, plaintext))
                        continue;
                    size_t actual = 0;
                    bool keepalive = false;
                    if (!ValidateInner(plaintext.data(), plaintext.size(), actual, keepalive))
                        continue;
                    if (keepalive)
                    {
                        socket.received.store(Clock::now().time_since_epoch().count(), std::memory_order_relaxed);
                        Id token{};
                        if (ReadDataProbe(socket.keys.dataC2S, plaintext, false, token))
                        {
                            if (EncryptDataProbe(socket.keys.dataS2C, socket.keys.prefixS2C, token, true, encrypted))
                                SendDataToClient(socket, encrypted);
                        }
                        else
                            socket.accepted.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    const auto address = snapshot->routes.find(Get32(plaintext.data() + 12));
                    if (address == snapshot->routes.end() || address->second.socket.get() != &socket)
                        continue;
                    socket.received.store(Clock::now().time_since_epoch().count(), std::memory_order_relaxed);
                    socket.accepted.fetch_add(1, std::memory_order_relaxed);
                    if (diagnostics.Echo(plaintext.data(), actual, socket.diagnosticIdentity,
                                         [&](uint8_t *packet, size_t size) {
                                             return EncryptData(socket.keys.dataS2C, socket.keys.prefixS2C, packet,
                                                                size, encrypted) &&
                                                    SendDataToClient(socket, encrypted);
                                         }))
                        continue;
                    diagnostics.LoadPacket(miga::diagnostics::LoadCounters::ServerReceived, plaintext.data(), actual, socket.diagnosticIdentity);
                    const auto watch = diagnostics.Outbound(plaintext.data(), actual, socket.diagnosticIdentity);
                    const auto header = size_t(plaintext[0] & 15) * 4;
                    if (watch && !(Get16(plaintext.data() + 6) & 0x1fff))
                        diagnostics.TunMapped(watch, Get16(plaintext.data() + header));
                    const bool written = WriteTun(plaintext.data(), actual);
                    diagnostics.TunWritten(watch, written, plaintext.data(), actual);
                    diagnostics.LoadPacket(miga::diagnostics::LoadCounters::TunWritten, plaintext.data(), actual, socket.diagnosticIdentity, written);
                }
            }
        }
    }
}

Json V2Server::Impl::AdminCommand(const Json &command)
{
    const auto scope = command.at("scope").get<std::string>();
    const auto operation = command.at("operation").get<std::string>();
    if (scope == "settings")
    {
        if (operation == "get")
            return Json{{"max_sessions", maxSessions}};
        if (operation != "set")
            return Json{{"error", "unknown_operation"}};
        const auto limit = command.at("max_sessions").get<uint32_t>();
        if (!limit || limit > 512 || std::min(limit * 8, 1024u) > 64512u - (uint32_t(portEnd) - portStart + 1))
            return Json{{"error", "invalid_limit"}};
        Json updated;
        {
            std::ifstream input(configPath);
            if (!input || !(input >> updated))
                return Json{{"error", "config_read_failed"}};
        }
        updated["max_sessions"] = limit;
        const auto bytes = updated.dump(2) + "\n";
        const std::string temporary = configPath + ".v2.new";
        const int file = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (file < 0)
            return Json{{"error", "config_write_failed"}};
        const bool written =
            write(file, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()) && fsync(file) == 0;
        const bool closed = close(file) == 0;
        if (!written || !closed || rename(temporary.c_str(), configPath.c_str()) != 0)
        {
            unlink(temporary.c_str());
            return Json{{"error", "config_write_failed"}};
        }
        const auto slash = configPath.find_last_of('/');
        const auto parentPath = slash == std::string::npos ? "." : configPath.substr(0, slash);
        const int parent = open(parentPath.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        const bool durable = parent >= 0 && fsync(parent) == 0;
        if (parent >= 0)
            close(parent);
        if (!durable)
            return Json{{"error", "config_sync_failed"}};
        settings = std::move(updated);
        maxSessions = limit;
        return Json{{"max_sessions", maxSessions}};
    }
    if (scope != "client")
        return Json{{"error", "unknown_scope"}};
    if (operation == "list")
    {
        Id after{};
        const bool hasCursor = command.contains("after");
        if (hasCursor)
        {
            Bytes bytes;
            if (!Unbase64(command.at("after").get<std::string>(), bytes) || bytes.size() != after.size())
                return Json{{"error", "invalid_cursor"}};
            std::copy(bytes.begin(), bytes.end(), after.begin());
        }
        std::vector<ClientRecord> records;
        if (!store.ListActive(hasCursor ? &after : nullptr, ClientPageSize + 1, records))
            return Json{{"error", "database_unavailable"}};
        const bool hasMore = records.size() > ClientPageSize;
        if (hasMore)
            records.pop_back();
        std::map<Id, size_t> counts;
        for (const auto &session : sessions)
            ++counts[session.second->client];
        Json rows = Json::array();
        for (const auto &record : records)
        {
            const auto count = counts.find(record.id);
            rows.push_back(Json{{"id", Base64(record.id.data(), record.id.size())},
                                {"name", record.name},
                                {"limit", record.maxConnections},
                                {"sessions", count == counts.end() ? 0 : count->second}});
        }
        Json next = nullptr;
        if (hasMore)
        {
            const auto &id = records.back().id;
            next = Base64(id.data(), id.size());
        }
        return Json{{"clients", std::move(rows)}, {"next", std::move(next)}};
    }
    if (operation == "add")
    {
        ClientRecord record;
        record.name = command.at("name").get<std::string>();
        record.maxConnections = command.at("limit").get<uint32_t>();
        Random(record.id.data(), record.id.size());
        Random(record.secret.data(), record.secret.size());
        if (!store.Add(record))
            return Json{{"error", "client_add_failed"}};
        Invitation invitation;
        invitation.host = host;
        invitation.portStart = portStart;
        invitation.portEnd = portEnd;
        invitation.serverKey = publicKey;
        invitation.serverSecret = shared;
        invitation.clientId = record.id;
        invitation.clientSecret = record.secret;
        return Json{{"id", Base64(record.id.data(), record.id.size())}, {"invitation", FormatInvitation(invitation)}};
    }
    Bytes bytes;
    if (!Unbase64(command.at("id").get<std::string>(), bytes) || bytes.size() != 16)
        return Json{{"error", "invalid_id"}};
    Id id{};
    std::copy_n(bytes.begin(), 16, id.begin());
    ClientRecord existing;
    if (!store.Get(id, existing) || existing.revoked)
        return Json{{"error", "client_not_found"}};
    if (operation == "update")
    {
        if (!store.Update(id, command.at("name").get<std::string>(), command.at("limit").get<uint32_t>()))
            return Json{{"error", "client_update_failed"}};
        return Json{{"ok", true}};
    }
    if (operation != "revoke" && operation != "disconnect")
        return Json{{"error", "unknown_operation"}};
    if (operation == "revoke" && !store.Revoke(id))
        return Json{{"error", "client_revoke_failed"}};
    for (auto it = sessions.begin(); it != sessions.end();)
    {
        if (it->second->client == id)
        {
            Close(*it->second);
            it = sessions.erase(it);
        }
        else
            ++it;
    }
    Publish();
    return Json{{"ok", true}};
}

void V2Server::Impl::PollAdmin()
{
    for (size_t batch = 0; batch < 8; ++batch)
    {
        const int connection = accept4(admin, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (connection < 0)
            break;
        ucred credentials{};
        socklen_t size = sizeof(credentials);
        if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 || credentials.uid != geteuid())
        {
            close(connection);
            continue;
        }
        pollfd pending{connection, POLLIN, 0};
        if (poll(&pending, 1, 500) <= 0)
        {
            close(connection);
            continue;
        }
        std::array<char, 4097> data{};
        const auto count = recv(connection, data.data(), data.size(), 0);
        if (count > 0 && count <= 4096)
        {
            Json response;
            try
            {
                response = AdminCommand(Json::parse(data.data(), data.data() + count));
            }
            catch (...)
            {
                response = Json{{"error", "invalid_request"}};
            }
            const auto text = response.dump();
            const auto sent = send(connection, text.data(), text.size(), MSG_NOSIGNAL);
            if (sent != static_cast<ssize_t>(text.size()))
            {
                const int error = sent < 0 ? errno : EIO;
                logger.log(LOGGER_LEVEL_WARNING, "admin_response_send_failed errno=" + std::to_string(error));
            }
        }
        close(connection);
    }
}

void V2Server::Impl::Run(const std::atomic<bool> &running)
{
    dataRunning = true;
    dataWorker = std::thread([this] { DataLoop(); });
    std::array<uint8_t, 65536> buffer{};
    while (running.load(std::memory_order_relaxed))
    {
        std::vector<pollfd> descriptors;
        descriptors.push_back({admin, POLLIN, 0});
        std::vector<std::shared_ptr<Socket>> pending;
        for (const auto &entry : controls)
            descriptors.push_back({entry.second, POLLIN, 0});
        const size_t controlEnd = descriptors.size();
        const auto pingListener = controls.find(portStart);
        const int pingFd = pingListener != controls.end() ? pingListener->second : -1;
        for (const auto &entry : sessions)
            if (entry.second->pending)
            {
                pending.push_back(entry.second->pending);
                descriptors.push_back({entry.second->pending->fd, POLLIN, 0});
            }
        if (poll(descriptors.data(), descriptors.size(), 100) > 0)
        {
            if (descriptors[0].revents & POLLIN)
                PollAdmin();
            for (size_t i = 1; i < descriptors.size(); ++i)
            {
                if (!(descriptors[i].revents & POLLIN))
                    continue;
                for (size_t batch = 0; batch < 16; ++batch)
                {
                    sockaddr_in peer{};
                    socklen_t peerLength = sizeof(peer);
                    const auto length = recvfrom(descriptors[i].fd, buffer.data(), buffer.size(), MSG_DONTWAIT,
                                                 reinterpret_cast<sockaddr *>(&peer), &peerLength);
                    if (length < 0)
                        break;
                    if (i < controlEnd)
                    {
                        const int fd = descriptors[i].fd;
                        if (fd == pingFd && static_cast<size_t>(length) == UdpPingSize &&
                            std::memcmp(buffer.data(), UdpPingRequest, UdpPingHeaderSize) == 0)
                        {
                            if (pingBucket.Take(20, 40, Clock::now()))
                            {
                                std::memcpy(buffer.data(), UdpPingReply, UdpPingHeaderSize);
                                sendto(fd, buffer.data(), UdpPingSize, MSG_NOSIGNAL,
                                       reinterpret_cast<const sockaddr *>(&peer), sizeof(peer));
                            }
                        }
                        else if (fd != pingFd || pingPortCarriesControl)
                            Control(fd, peer, buffer.data(), static_cast<size_t>(length));
                    }
                    else
                    {
                        SessionControl(descriptors[i].fd, peer, buffer.data(), static_cast<size_t>(length),
                                       pending[i - controlEnd].get());
                        if (pending[i - controlEnd]->bound)
                            break;
                    }
                }
            }
        }
        if (Clock::now() >= nextMaintenance)
            Maintain();
    }
    dataRunning = false;
    if (dataWorker.joinable())
        dataWorker.join();
}

int V2Server::Admin(int argc, char **argv, const std::string &path)
{
    try
    {
        if (argc < 3 || !miga::v2::Initialize())
            return 1;
        Json command{{"scope", argv[1]}, {"operation", argv[2]}};
        const bool clientList = command.at("scope") == "client" && command.at("operation") == "list";
        bool singlePage = false;
        for (int index = 3; index < argc; ++index)
        {
            const std::string option = argv[index];
            if (option == "--json")
                continue;
            if (option == "--page" && clientList)
            {
                singlePage = true;
                continue;
            }
            if (option == "--config")
            {
                ++index;
                continue;
            }
            if (index + 1 >= argc)
                return 1;
            const std::string value = argv[++index];
            if (option == "--after" && clientList)
            {
                command["after"] = value;
                singlePage = true;
            }
            else if (option == "--id")
                command["id"] = value;
            else if (option == "--name")
                command["name"] = value;
            else if (option == "--limit" || option == "--max-sessions")
            {
                size_t end = 0;
                const auto number = std::stoull(value, &end);
                if (end != value.size() || value.empty() || value[0] == '-' ||
                    number > std::numeric_limits<uint32_t>::max())
                    return 1;
                command[option == "--limit" ? "limit" : "max_sessions"] = number;
            }
            else
                return 1;
        }
        Json config;
        {
            std::ifstream input(path);
            if (!input || !(input >> config) || config.value("protocol", 0) != 2)
                return 1;
        }
        const auto directory = config.value("state_directory", std::string("/var/lib/miga"));
        const std::string socketPath = directory + "/admin.sock";
        sockaddr_un peer{};
        peer.sun_family = AF_UNIX;
        if (socketPath.size() >= sizeof(peer.sun_path))
            return 1;
        std::strcpy(peer.sun_path, socketPath.c_str());
        std::unique_ptr<Impl> offline;
        bool online = false;
        const auto request = [&]() -> Json {
            if (!offline)
            {
                const int connection = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
                if (connection >= 0 && connect(connection, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)) == 0)
                {
                    online = true;
                    const auto text = command.dump();
                    const auto sent = send(connection, text.data(), text.size(), MSG_NOSIGNAL);
                    pollfd ready{connection, POLLIN, 0};
                    std::vector<char> result(AdminResponseLimit);
                    ssize_t length = -1;
                    if (sent == static_cast<ssize_t>(text.size()) && poll(&ready, 1, 30000) > 0)
                        length = recv(connection, result.data(), result.size(), MSG_TRUNC);
                    close(connection);
                    if (length <= 0 || static_cast<size_t>(length) > result.size())
                        return Json{{"error", "admin_response_unavailable"}};
                    return Json::parse(result.data(), result.data() + length);
                }
                if (connection >= 0)
                    close(connection);
                if (online)
                    return Json{{"error", "admin_connection_lost"}};
                offline = std::make_unique<Impl>();
                offline->configPath = path;
                offline->settings = config;
                offline->directory = directory;
                offline->host = config.at("host").get<std::string>();
                offline->maxSessions = config.value("max_sessions", 64u);
                const auto ports = config.value("control_ports", Json::array({10000, 15000}));
                offline->portStart = ports.at(0).get<uint16_t>();
                offline->portEnd = ports.at(1).get<uint16_t>();
                if (!SecureDirectory(directory) ||
                    !LoadIdentity(directory, offline->privateKey, offline->publicKey, offline->shared) ||
                    !offline->store.Open(directory + "/clients.sqlite3"))
                    return Json{{"error", "admin_state_unavailable"}};
            }
            return offline->AdminCommand(command);
        };
        auto response = request();
        if (clientList && !(response.is_object() && response.contains("error")))
        {
            if (singlePage && response.is_array())
            {
                if (command.contains("after"))
                    response = Json{{"error", "pagination_unavailable"}};
                else
                    response = Json{{"clients", std::move(response)}, {"next", nullptr}};
            }
            else if (!singlePage && response.is_object())
            {
                std::multimap<std::string, Json> rows;
                std::set<std::string> cursors;
                for (;;)
                {
                    for (auto &row : response.at("clients"))
                        rows.emplace(row.at("name").get<std::string>(), std::move(row));
                    const auto &next = response.at("next");
                    if (next.is_null())
                    {
                        response = Json::array();
                        for (auto &entry : rows)
                            response.push_back(std::move(entry.second));
                        break;
                    }
                    const auto cursor = next.get<std::string>();
                    if (!cursors.insert(cursor).second)
                    {
                        response = Json{{"error", "invalid_cursor"}};
                        break;
                    }
                    command["after"] = cursor;
                    response = request();
                    if (response.is_object() && response.contains("error"))
                        break;
                }
            }
        }
        std::cout << response.dump() << std::endl;
        return response.is_object() && response.contains("error") ? 1 : 0;
    }
    catch (...)
    {
        std::cerr << "admin_command_failed" << std::endl;
        return 1;
    }
}

}
