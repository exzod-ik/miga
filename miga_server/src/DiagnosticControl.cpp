#include "DiagnosticControl.h"
#include "DiagnosticNetworkStats.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <cstring>
#include <csignal>
#include <iostream>

namespace {
uint16_t U16(const uint8_t* p) {return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);}
uint32_t U32(const uint8_t* p) {uint32_t value; std::memcpy(&value, p, 4); return value;}
bool Header(const uint8_t* p, size_t n, size_t& ihl) {
    if (n < 20 || p[0] >> 4 != 4) return false;
    ihl = (p[0] & 15) * 4;
    if (ihl < 20 || n < ihl + 8 || U16(p + 2) < ihl + 8 || U16(p + 2) > n || (U16(p + 6) & 0x3fff) || (p[9] != 6 && p[9] != 17)) return false;
    return p[9] != 17 || (U16(p + ihl + 4) >= 8 && ihl + U16(p + ihl + 4) == U16(p + 2));
}
std::string Resolve(const char* name) {
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(name, nullptr, &hints, &result)) return {};
    char text[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr, text, sizeof(text));
    freeaddrinfo(result); return text;
}
}

bool DiagnosticControl::HasPort(const PortIndex& index, uint8_t protocol, uint16_t port) {
    return (index[protocol == 17 ? 1 : 0][port / 64].load(std::memory_order_relaxed) & (uint64_t(1) << (port % 64))) != 0;
}
void DiagnosticControl::IndexPort(PortIndex& index, uint8_t protocol, uint16_t port) {
    index[protocol == 17 ? 1 : 0][port / 64].fetch_or(uint64_t(1) << (port % 64), std::memory_order_relaxed);
}
DiagnosticControl::~DiagnosticControl() {Stop();}
void DiagnosticControl::SetNetworkSource(std::function<std::shared_ptr<const int>(uint32_t)> socket,
                                         std::function<uint32_t()> address) {
    networkSocket_ = std::move(socket);
    networkAddress_ = std::move(address);
}
DiagnosticControl::Json DiagnosticControl::CaptureNetwork() {
    uint32_t client;
    {
        std::lock_guard lock(mutex_);
        client = client_;
    }
    auto socket = client && networkSocket_ ? networkSocket_(client) : nullptr;
    return DiagnosticNetworkStats::Capture(socket ? *socket : -1, networkAddress_ ? networkAddress_() : 0);
}
bool DiagnosticControl::Configure(const Json& settings) {
    settings_ = settings.is_object() ? settings : Json::object();
    const auto port = settings_.value("port", 47900);
    return port >= 0 && port <= 65535;
}
bool DiagnosticControl::Start() {
    Stop(); stopping_.store(false);
    thread_ = std::thread([this] {try {Serve();} catch (...) {active.store(false);}});
    return true;
}
miga::v2::Bytes DiagnosticControl::Authorize(uint32_t identity) {
    std::lock_guard lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    for (auto it = grants_.begin(); it != grants_.end();) {
        if (it->second.expires <= now) it = grants_.erase(it); else ++it;
    }
    if (!identity || !port_ || stopping_.load() || active.load() || grants_.size() >= 64) return {};
    Grant grant{};
    if (RAND_bytes(grant.ticket.data(), 32) != 1) return {};
    grant.expires = now + std::chrono::seconds(30);
    grants_[identity] = grant;
    miga::v2::Bytes result;
    miga::v2::Put16(result, port_);
    result.insert(result.end(), fingerprint_.begin(), fingerprint_.end());
    result.insert(result.end(), grant.ticket.begin(), grant.ticket.end());
    return result;
}
void DiagnosticControl::Revoke(uint32_t identity) {
    std::lock_guard lock(mutex_);
    grants_.erase(identity);
    if (loadClient_.load() == identity) { loadClient_.store(0); load.Stop(); }
    if (client_ == identity) {
        active.store(false);
        if (connection_ >= 0) shutdown(connection_, SHUT_RDWR);
        client_ = 0;
    }
}
void DiagnosticControl::Stop() {
    stopping_.store(true); active.store(false);
    {
        std::lock_guard lock(mutex_);
        if (connection_ >= 0) shutdown(connection_, SHUT_RDWR);
        if (listener_ >= 0) shutdown(listener_, SHUT_RDWR);
    }
    if (thread_.joinable()) thread_.join();
    std::lock_guard lock(mutex_); loadClient_.store(0); load.Stop();
}

DiagnosticControl::Json DiagnosticControl::Command(const Json& request) {
    auto command = request.value("command", "");
    if (command == "load_prepare") {
        std::lock_guard lock(mutex_);
        if (!active.load() || !client_) return {{"ok", false}, {"error", "session_required"}};
        loadClient_.store(0);
        auto result = load.Prepare(request, networkAddress_ ? networkAddress_() : 0);
        loadClient_.store(client_); return result;
    }
    if (command == "load_start") { std::lock_guard lock(mutex_); return load.StartSending(); }
    if (command == "load_stats") { std::lock_guard lock(mutex_); return load.Stats(); }
    if (command == "load_stop") { std::lock_guard lock(mutex_); loadClient_.store(0); load.Stop(); return {{"ok", true}}; }
    if (command == "ping") return {{"ok", true}, {"protocol", 1}};
    if (command == "begin") {
        if (active.load()) return {{"ok", false}, {"error", "session_already_started"}};
        networkBefore_ = CaptureNetwork();
        auto tcp = Resolve("www.cloudflare.com"); auto stun = Resolve("stun.cloudflare.com");
        std::lock_guard lock(mutex_);
        if (stopping_.load() || !client_) return {{"ok", false}, {"error", "stopping"}};
        if (RAND_bytes(token_.data(), static_cast<int>(token_.size())) != 1) return {{"ok", false}, {"error", "random_unavailable"}};
        static const char hex[] = "0123456789abcdef";
        std::string token;
        for (auto byte : token_) {token += hex[byte >> 4]; token += hex[byte & 15];}
        ++session_;
        for (auto* index : {&outboundPorts_, &inboundPorts_}) for (auto& protocol : *index) for (auto& word : protocol) word.store(0, std::memory_order_relaxed);
        watches_.clear(); echo_ = {{"received", 0}, {"replied", 0}, {"sequences", Json::array()}}; active.store(true);
        return {{"ok", true}, {"token", token}, {"echo_ip", "198.18.0.1"}, {"echo_port", 47901},
            {"tcp_host", "www.cloudflare.com"}, {"tcp_ip", tcp}, {"tcp_port", 443},
            {"stun_host", "stun.cloudflare.com"}, {"stun_ip", stun}, {"stun_port", 3478}};
    }
    if (command == "end") {active.store(false); return {{"ok", true}};}
    if (command == "network_stats") {
        if (!active.load()) return {{"ok", false}, {"error", "session_required"}};
        auto after = CaptureNetwork();
        if (!active.load()) return {{"ok", false}, {"error", "session_required"}};
        return {{"ok", true}, {"network", DiagnosticNetworkStats::Difference(networkBefore_, after)}};
    }
    std::lock_guard lock(mutex_);
    if (!active.load()) return {{"ok", false}, {"error", "session_required"}};
    if (command == "watch") {
        if (watches_.size() >= 128) return {{"ok", false}, {"error", "watch_capacity"}};
        in_addr ip{}; const auto text = request.at("remote_ip").get<std::string>();
        if (inet_pton(AF_INET, text.c_str(), &ip) != 1) return {{"ok", false}, {"error", "invalid_ipv4"}};
        const auto protocol = request.at("protocol").get<int>();
        const auto local = request.at("local_port").get<int>(), remote = request.at("remote_port").get<int>();
        if ((protocol != 6 && protocol != 17) || local < 1 || local > 65535 || remote < 1 || remote > 65535) return {{"ok", false}};
        std::vector<uint8_t> transaction;
        const auto hex = request.value("transaction_id", "");
        if (!hex.empty()) {
            if (protocol != 17 || hex.size() != 24) return {{"ok", false}, {"error", "invalid_transaction"}};
            for (size_t i = 0; i < hex.size(); i += 2) {
                const auto digit = [](char c) {return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;};
                const auto a = digit(hex[i]), b = digit(hex[i + 1]);
                if (a < 0 || b < 0) return {{"ok", false}, {"error", "invalid_transaction"}};
                transaction.push_back(uint8_t(a * 16 + b));
            }
        }
        const auto id = ++nextWatch_;
        watches_.push_back({id, uint8_t(protocol), uint16_t(local), uint16_t(remote), 0, ip.s_addr, 0, std::move(transaction),
            {{"watch_id", id}, {"local_port", local}, {"protocol", protocol}, {"transaction_id", hex}, {"received", 0}, {"tun_written", 0}, {"tun_response", 0}}, false, {}, {}});
        watches_.back().sequence16 = protocol == 17 && request.value("sequence16", false);
        IndexPort(outboundPorts_, uint8_t(protocol), uint16_t(local));
        return {{"ok", true}, {"watch_id", id}};
    }
    if (command == "stats") {
        Json watches = Json::array();
        for (const auto& watch : watches_) {
            auto stats = watch.stats;
            if (watch.sequence16) {stats["received_sequences"] = watch.receivedSequences; stats["written_sequences"] = watch.writtenSequences;}
            watches.push_back(std::move(stats));
        }
        return {{"ok", true}, {"echo", echo_}, {"watches", watches}};
    }
    return {{"ok", false}, {"error", "invalid_command"}};
}

void DiagnosticControl::Serve() {
    sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked, SIGPIPE); pthread_sigmask(SIG_BLOCK, &blocked, nullptr);
    auto* context = SSL_CTX_new(TLS_server_method());
    if (!context) {std::cerr << "diagnostics_control_unavailable reason=tls_context\n"; return;}
    auto* keyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* key = nullptr;
    X509* certificate = X509_new();
    bool valid = keyContext && certificate && EVP_PKEY_keygen_init(keyContext) == 1 &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyContext, NID_X9_62_prime256v1) == 1 &&
        EVP_PKEY_keygen(keyContext, &key) == 1;
    if (valid) {
        X509_set_version(certificate, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
        X509_gmtime_adj(X509_getm_notBefore(certificate), -60);
        X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000);
        X509_set_pubkey(certificate, key);
        auto* name = X509_get_subject_name(certificate);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("MIGA diagnostics"), -1, -1, 0);
        X509_set_issuer_name(certificate, name);
        valid = X509_sign(certificate, key, EVP_sha256()) > 0 &&
            SSL_CTX_use_certificate(context, certificate) == 1 && SSL_CTX_use_PrivateKey(context, key) == 1;
        unsigned int size = 0;
        std::lock_guard lock(mutex_);
        valid = valid && X509_digest(certificate, EVP_sha256(), fingerprint_.data(), &size) == 1 && size == 32;
    }
    EVP_PKEY_CTX_free(keyContext); EVP_PKEY_free(key); X509_free(certificate);
    SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(context, SSL_OP_NO_TICKET);
    if (!valid) {SSL_CTX_free(context); return;}
    auto listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) {SSL_CTX_free(context); return;}
    {
        std::lock_guard lock(mutex_); listener_ = listener;
    }
    int yes = 1; setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(settings_.value("port", uint16_t(47900)));
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && listen(listener, 4) == 0) {
        {
            socklen_t size = sizeof(address);
            if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) == 0) {
                std::lock_guard lock(mutex_); port_ = ntohs(address.sin_port);
            }
        }
        while (!stopping_.load()) {
            pollfd event{listener, POLLIN, 0}; if (poll(&event, 1, 500) <= 0) continue;
            sockaddr_in peer{}; socklen_t length = sizeof(peer);
            auto socket = accept4(listener, reinterpret_cast<sockaddr*>(&peer), &length, SOCK_CLOEXEC);
            if (socket < 0) continue;
            timeval timeout{10, 0}; setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            {std::lock_guard lock(mutex_); connection_ = socket; client_ = 0;}
            auto* tls = SSL_new(context); SSL_set_fd(tls, socket);
            if (SSL_accept(tls) == 1 && SSL_get_verify_result(tls) == X509_V_OK) {
                timeout.tv_sec = 10; setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                bool authorized = false;
                auto expires = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                std::string line; char byte;
                while (!stopping_.load()) {
                    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(expires - std::chrono::steady_clock::now()).count();
                    if (remaining <= 0) break;
                    timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(remaining);
                    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    if (SSL_read(tls, &byte, 1) != 1) break;
                    if (byte != '\n') {if (line.size() >= 8192) break; line += byte; continue;}
                    Json response;
                    if (!authorized) {
                        try {
                            const auto request = Json::parse(line);
                            miga::v2::Bytes ticket;
                            if (request.value("command", "") != "authorize" ||
                                !miga::v2::Unbase64(request.value("ticket", ""), ticket) || ticket.size() != 32) break;
                            std::lock_guard lock(mutex_);
                            for (auto it = grants_.begin(); it != grants_.end(); ++it) {
                                if (it->second.expires > std::chrono::steady_clock::now() &&
                                    CRYPTO_memcmp(ticket.data(), it->second.ticket.data(), 32) == 0) {
                                    client_ = it->first;
                                    grants_.erase(it);
                                    authorized = true;
                                    expires = std::chrono::steady_clock::now() + std::chrono::minutes(120);
                                    break;
                                }
                            }
                            OPENSSL_cleanse(ticket.data(), ticket.size());
                        } catch (...) {break;}
                        if (!authorized) break;
                        timeout.tv_sec = 300;
                        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                        response = {{"ok", true}};
                    } else {
                        {
                            std::lock_guard lock(mutex_);
                            if (!client_ || std::chrono::steady_clock::now() >= expires) break;
                        }
                        try {response = Command(Json::parse(line));} catch (...) {response = {{"ok", false}, {"error", "invalid_request"}};}
                    }
                    line.clear(); auto text = response.dump() + "\n"; size_t offset = 0;
                    while (offset < text.size()) {auto n = SSL_write(tls, text.data() + offset, int(text.size() - offset)); if (n <= 0) break; offset += static_cast<size_t>(n);}
                    if (offset != text.size()) break;
                }
            }
            active.store(false);
            { std::lock_guard lock(mutex_); loadClient_.store(0); load.Stop(); }
            SSL_free(tls);
            {std::lock_guard lock(mutex_); connection_ = -1; client_ = 0; close(socket); watches_.clear();}
        }
    }
    {std::lock_guard lock(mutex_); listener_ = -1; port_ = 0; grants_.clear(); close(listener);}
    SSL_CTX_free(context);
}

bool DiagnosticControl::Echo(uint8_t* p, size_t n, uint32_t client, const Reply& reply) {
    if (!active.load(std::memory_order_relaxed)) return false;
    size_t ihl;
    if (!Header(p, n, ihl) || p[9] != 17 || U32(p + 16) != htonl(0xc6120001) || U16(p + ihl + 2) != 47901) return false;
    std::unique_lock lock(mutex_);
    if (!active.load() || client != client_ || n < ihl + 28 || n > 1600 || std::memcmp(p + ihl + 8, token_.data(), token_.size())) return true;
    echo_["received"] = echo_["received"].get<uint64_t>() + 1;
    if (echo_["sequences"].size() < 256) echo_["sequences"].push_back({{"sequence", ntohl(U32(p + ihl + 24))}, {"ip_size", U16(p + 2)}, {"received", true}, {"replied", false}});
    uint8_t swap[4]; std::memcpy(swap, p + 12, 4); std::memcpy(p + 12, p + 16, 4); std::memcpy(p + 16, swap, 4);
    std::swap(p[ihl], p[ihl + 2]); std::swap(p[ihl + 1], p[ihl + 3]);
    const auto size = ihl + 28; p[2] = uint8_t(size >> 8); p[3] = uint8_t(size);
    p[ihl + 4] = 0; p[ihl + 5] = 28; p[ihl + 6] = p[ihl + 7] = 0;
    const auto session = session_;
    const auto sequence = ntohl(U32(p + ihl + 24));
    lock.unlock();
    const auto sent = reply(p, size);
    lock.lock();
    if (session == session_ && sent) {
        echo_["replied"] = echo_["replied"].get<uint64_t>() + 1;
        for (auto& item : echo_["sequences"]) if (item["sequence"] == sequence) item["replied"] = true;
    }
    return true;
}
namespace {
uint32_t ProbeSequence(const uint8_t* p, size_t n) {
    if (!p || n < 30 || (p[0] >> 4) != 4 || p[9] != 17 || (p[6] & 0x3f) || p[7]) return 0;
    const size_t h = (p[0] & 15) * 4;
    if (h < 20 || n != h + 10 || ((unsigned(p[2]) << 8) | p[3]) != n || p[h + 4] || p[h + 5] != 10) return 0;
    return ((uint32_t(p[h + 8]) << 8) | p[h + 9]) + 1;
}
}

uint64_t DiagnosticControl::Outbound(const uint8_t* p, size_t n, uint32_t client) {
    if (!active.load(std::memory_order_relaxed)) return 0;
    size_t ihl; if (!Header(p, n, ihl) || !HasPort(outboundPorts_, p[9], U16(p + ihl))) return 0;
    std::lock_guard lock(mutex_); if (!active.load() || client != client_) return 0;
    for (auto it = watches_.rbegin(); it != watches_.rend(); ++it) {
        auto& w = *it;
        if (p[9] != w.protocol || U32(p + 16) != w.ip || U16(p + ihl) != w.local || U16(p + ihl + 2) != w.remote) continue;
        if (!w.transaction.empty() && (n < ihl + 28 || U16(p + ihl + 8) != 1 || U32(p + ihl + 12) != htonl(0x2112a442) ||
            std::memcmp(p + ihl + 16, w.transaction.data(), 12))) continue;
        if (w.protocol == 6) {
            if (n < ihl + 20) continue;
            const auto sequence = ntohl(U32(p + ihl + 4));
            if ((p[ihl + 13] & 0x12) == 2) {
                if (w.stats["received"].get<uint64_t>() && w.sequence != sequence) continue;
                w.sequence = sequence;
            }
        }
        if (w.source && w.source != U32(p + 12)) continue;
        w.source = U32(p + 12);
        w.stats["received"] = w.stats["received"].get<uint64_t>() + 1;
        if (w.sequence16) {const auto seq = ProbeSequence(p, n); if (seq) w.receivedSequences.insert(uint16_t(seq - 1));}
        w.stats["last_ip_size"] = U16(p + 2);
        w.stats["inner_df"] = (U16(p + 6) & 0x4000) != 0;
        return w.id;
    }
    return 0;
}
void DiagnosticControl::TunMapped(uint64_t id, uint16_t translated) {
    if (!active.load(std::memory_order_relaxed)) return;
    std::lock_guard lock(mutex_);
    uint8_t protocol = 0;
    for (auto& w : watches_) if (w.id == id) {w.translated = translated; protocol = w.protocol;}
    for (auto& w : watches_) if (w.id != id && w.protocol == protocol && w.translated == translated) w.translated = 0;
    if (protocol) IndexPort(inboundPorts_, protocol, translated);
}
void DiagnosticControl::TunWritten(uint64_t id, bool success, const uint8_t* packet, size_t length) {
    if (!active.load(std::memory_order_relaxed)) return;
    std::lock_guard lock(mutex_);
    for (auto& w : watches_) if (w.id == id && success)
        {
            w.stats["tun_written"] = w.stats["tun_written"].get<uint64_t>() + 1;
            if (w.sequence16) {const auto seq = ProbeSequence(packet, length); if (seq) w.writtenSequences.insert(uint16_t(seq - 1));}
        }
}
void DiagnosticControl::Inbound(const uint8_t* p, size_t n) {
    if (!active.load(std::memory_order_relaxed)) return;
    size_t ihl; if (!Header(p, n, ihl) || !HasPort(inboundPorts_, p[9], U16(p + ihl + 2))) return;
    std::lock_guard lock(mutex_);
    for (auto& w : watches_) {
        if (!w.translated || !w.source || U32(p + 16) != w.source || p[9] != w.protocol || U32(p + 12) != w.ip || U16(p + ihl) != w.remote || U16(p + ihl + 2) != w.translated) continue;
        if (!w.transaction.empty() && (n < ihl + 28 || U16(p + ihl + 8) != 0x0101 || U32(p + ihl + 12) != htonl(0x2112a442) ||
            std::memcmp(p + ihl + 16, w.transaction.data(), 12))) continue;
        if (w.protocol == 6 && (n < ihl + 20 || !(p[ihl + 13] & 0x10) || int32_t(ntohl(U32(p + ihl + 8)) - w.sequence - 1) < 0)) continue;
        w.stats["tun_response"] = w.stats["tun_response"].get<uint64_t>() + 1;
    }
}

void DiagnosticControl::LoadPacket(miga::diagnostics::LoadCounters::Stage stage, const uint8_t* packet, size_t size, uint32_t client, bool success) {
    if (!load.enabled.load(std::memory_order_relaxed) || client != loadClient_.load(std::memory_order_relaxed)) return;
    if (stage == miga::diagnostics::LoadCounters::ServerReceived) load.Observe(packet, size);
    load.counters.Packet(stage, packet, size, success);
}
