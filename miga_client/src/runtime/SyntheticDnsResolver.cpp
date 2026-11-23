#include "runtime/SyntheticDnsResolver.h"
#include "LogFormat.h"
#include <iphlpapi.h>

namespace miga::runtime {
namespace {
constexpr auto retryDelay = std::chrono::seconds(2);
constexpr auto queryLifetime = std::chrono::seconds(4);
constexpr size_t upstreamUdpSize = 1232;
constexpr size_t maxQueries = 2048;
constexpr size_t maxListeners = 512;
constexpr size_t maxCachedAnswers = 2048;

bool Public(uint32_t address) {
    return address >= 0x01000000 && address < 0xe0000000 && !Local(address) &&
        !SyntheticDnsStore::Contains(address) && (address & 0xffc00000) != 0x64400000;
}

std::span<const uint8_t> Payload(const Packet& packet) {
    const auto offset = packet.view.header;
    const auto* bytes = packet.bytes->data();
    if (packet.view.tuple.protocol != 17 || offset + 8 > packet.view.length) return {};
    const auto length = Read16(bytes + offset + 4);
    if (length < 8 || offset + length > packet.view.length) return {};
    return {bytes + offset + 8, size_t(length) - 8};
}

Packet MakePacket(const WINDIVERT_ADDRESS& address, const SocketTuple& tuple, bool outbound,
    std::span<const uint8_t> payload, PacketBufferPool& buffers, Clock::time_point now) {
    std::vector<uint8_t> bytes(28 + payload.size());
    bytes[0] = 0x45;
    bytes[8] = 64;
    bytes[9] = 17;
    Write16(bytes.data() + 2, static_cast<uint16_t>(bytes.size()));
    Write32(bytes.data() + 12, tuple.localIp);
    Write32(bytes.data() + 16, tuple.remoteIp);
    Write16(bytes.data() + 20, tuple.localPort);
    Write16(bytes.data() + 22, tuple.remotePort);
    Write16(bytes.data() + 24, static_cast<uint16_t>(bytes.size() - 20));
    std::copy(payload.begin(), payload.end(), bytes.begin() + 28);
    Packet packet{buffers.Copy(bytes.data(), bytes.size()), address, {}, now};
    packet.address.Outbound = outbound;
    packet.address.Loopback = (tuple.localIp >> 24) == 127 && (tuple.remoteIp >> 24) == 127;
    packet.view.Read(bytes.data(), bytes.size());
    return packet;
}

uint32_t ReadSystemUpstream() {
    ULONG length = 0;
    if (GetNetworkParams(nullptr, &length) != ERROR_BUFFER_OVERFLOW || !length) return 0;
    std::vector<uint8_t> buffer(length);
    auto* info = reinterpret_cast<FIXED_INFO*>(buffer.data());
    if (GetNetworkParams(info, &length) != NO_ERROR) return 0;
    for (const auto* item = &info->DnsServerList; item; item = item->Next) {
        IN_ADDR address{};
        if (inet_pton(AF_INET, item->IpAddress.String, &address) != 1) continue;
        const auto ip = ntohl(address.s_addr);
        if (ip && (ip >> 24) != 127 && !SyntheticDnsStore::Contains(ip)) return ip;
    }
    return 0;
}

bool Qualified(const std::string& name) {
    return name.find('.') != std::string::npos && !name.ends_with(".local") &&
        !name.ends_with(".localhost") && !name.ends_with(".home.arpa");
}
}

size_t SyntheticDnsResolver::KeyHash::operator()(const Key& key) const {
    return std::hash<std::string>{}(key.name) ^ (key.server * 0x9e3779b9) ^
        (size_t(key.upstream) * 0x85ebca6b) ^ (size_t(key.source) * 0xc2b2ae35);
}

SyntheticDnsResolver::~SyntheticDnsResolver() { Stop(); }

void SyntheticDnsResolver::Start() {
    if (Port()) return;
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ != INVALID_SOCKET) {
        BOOL exclusive = TRUE;
        sockaddr_in local{};
        local.sin_family = AF_INET;
        int length = sizeof(local);
        if (setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<char*>(&exclusive), sizeof(exclusive)) == 0 &&
            bind(socket_, reinterpret_cast<const sockaddr*>(&local), length) == 0 &&
            getsockname(socket_, reinterpret_cast<sockaddr*>(&local), &length) == 0) {
            port_ = ntohs(local.sin_port);
        } else {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }
}

void SyntheticDnsResolver::Stop() {
    if (socket_ != INVALID_SOCKET) closesocket(socket_);
    socket_ = INVALID_SOCKET;
    port_ = 0;
    listeners_ = 0;
    defaultUpstream_ = 0;
    version_ = 0;
    store_.Clear();
    queries_.clear();
    deadlines_.Clear();
    pending_.clear();
    cache_.clear();
    upstreams_.clear();
}

std::optional<uint32_t> SyntheticDnsResolver::Preflight(bool enabled) {
    if (!enabled) return store_.LastAllocated();
    Start();
    return Port() ? std::optional<uint32_t>{0xc613ffff} : std::nullopt;
}

bool SyntheticDnsResolver::Configure(const Configuration& config) {
    const bool enabled = config.dnsResolverEnabled && !config.fullRoutingServerId && Port();
    if (version_ != config.version) {
        version_ = config.version;
        queries_.clear();
        deadlines_.Clear();
        pending_.clear();
        cache_.clear();
        upstreams_.clear();
        listeners_ = 0;
        defaultUpstream_ = enabled ? ReadSystemUpstream() : 0;
    }
    return enabled;
}

void SyntheticDnsResolver::Cleanup(Clock::time_point now, const Configuration& config,
    PacketBufferPool& buffers, Outputs& outputs) {
    if (!Configure(config)) return;
    uint16_t id = 0;
    while (deadlines_.PopDue(now, id)) {
        const auto found = queries_.find(id);
        if (found == queries_.end()) continue;
        const auto& state = found->second;
        if (now < state.expires) {
            deadlines_.Set(id, state.expires);
            QueueQuery(state, buffers, now, outputs);
            continue;
        }
        for (const auto& listener : state.listeners) FailClient(listener, buffers, outputs);
        listeners_ -= state.listeners.size();
        pending_.erase(state.key);
        queries_.erase(found);
    }
}

bool SyntheticDnsResolver::StartQuery(const Key& key, const Packet& origin, PacketBufferPool& buffers,
    Clock::time_point now, Outputs& outputs, uint32_t wakeAddress, const Packet* listener) {
    if (!key.upstream || !key.source) return false;
    if (const auto pending = pending_.find(key); pending != pending_.end()) {
        auto& state = queries_.at(pending->second);
        if (wakeAddress) state.wakeAddress = wakeAddress;
        if (listener) {state.listeners.push_back(*listener); ++listeners_;}
        return true;
    }
    if (queries_.size() >= maxQueries) return false;
    uint16_t id = 0;
    for (size_t attempt = 0; attempt < 16; ++attempt) {
        miga::v2::Random(reinterpret_cast<uint8_t*>(&id), sizeof(id));
        if (!queries_.contains(id)) break;
    }
    if (queries_.contains(id)) return false;
    auto wire = BuildSyntheticDnsQuery(key.name, 1, id, upstreamUdpSize);
    if (wire.empty()) return false;
    const SocketTuple tuple{17, key.source, Port(), key.upstream, 53};
    QueryState state{key, tuple, origin.address, std::move(wire), now + queryLifetime, wakeAddress};
    if (listener) {state.listeners.push_back(*listener); ++listeners_;}
    const auto position = queries_.emplace(id, std::move(state)).first;
    pending_.emplace(key, id);
    deadlines_.Set(id, now + retryDelay);
    cache_.erase(key);
    QueueQuery(position->second, buffers, now, outputs);
    return true;
}

void SyntheticDnsResolver::QueueQuery(const QueryState& state, PacketBufferPool& buffers,
    Clock::time_point now, Outputs& outputs) {
    const auto server = state.key.server;
    const FlowRoute route = server ? FlowRoute{FlowRoute::Kind::Tunnel, server, 0} : FlowRoute{};
    outputs.push_back({MakePacket(state.address, state.tuple, true, state.wire, buffers, now), route});
}

const SyntheticDnsResolver::Answer* SyntheticDnsResolver::Resolve(const Key& key, const Packet& origin,
    PacketBufferPool& buffers, Clock::time_point now, Outputs& outputs, uint32_t wakeAddress) {
    if (const auto answer = cache_.find(key); answer != cache_.end()) return &answer->second;
    StartQuery(key, origin, buffers, now, outputs, wakeAddress);
    return nullptr;
}

void SyntheticDnsResolver::Reply(const Packet& query, std::span<const uint8_t> wire,
    PacketBufferPool& buffers, Outputs& outputs) {
    if (wire.empty()) return;
    const auto& tuple = query.view.tuple;
    outputs.push_back({MakePacket(query.address, {17, tuple.remoteIp, 53, tuple.localIp, tuple.localPort},
        false, wire, buffers, Clock::now()), {}});
}

void SyntheticDnsResolver::FailClient(const Packet& query, PacketBufferPool& buffers, Outputs& outputs) {
    const auto question = ParseSyntheticDnsQuestion(Payload(query));
    if (question) Reply(query, BuildSyntheticDnsAnswer(*question, {}, 2), buffers, outputs);
}

void SyntheticDnsResolver::AnswerClient(const Packet& query, const Answer& answer, PacketBufferPool& buffers, Outputs& outputs) {
    const auto question = ParseSyntheticDnsQuestion(Payload(query));
    if (!question) return;
    if (answer.responseCode != 0 && answer.responseCode != 3) {
        FailClient(query, buffers, outputs);
        return;
    }
    const auto address = store_.FindOrAllocate(question->name);
    Reply(query, BuildSyntheticDnsAnswer(*question, address, address ? 0 : 2, answer.ttl), buffers, outputs);
}

bool SyntheticDnsResolver::Query(const Packet& packet, const Configuration& config, PacketBufferPool& buffers,
    Clock::time_point now, Outputs& outputs, size_t replyServer) {
    const auto question = ParseSyntheticDnsQuestion(Payload(packet));
    if (!question || question->requiresPassthrough || !(question->flags & 0x0100) || question->type != 1 ||
        packet.address.Loopback || (packet.view.tuple.remoteIp >> 24) == 127) return false;
    const auto normalized = NormalizeSyntheticDnsName(question->name);
    if (!normalized || !Qualified(*normalized)) return false;
    if (!Configure(config) || listeners_ >= maxListeners) {
        FailClient(packet, buffers, outputs);
        return true;
    }
    const auto upstream = packet.view.tuple.remoteIp;
    if (upstreams_.size() >= 64 && !upstreams_.contains(packet.view.tuple.localIp)) upstreams_.clear();
    upstreams_[packet.view.tuple.localIp] = upstream;
    Cleanup(now, config, buffers, outputs);
    Key key{*normalized, replyServer, upstream, packet.view.tuple.localIp};
    if (!StartQuery(key, packet, buffers, now, outputs, 0, &packet))
        FailClient(packet, buffers, outputs);
    if (replyServer) {
        key.server = 0;
        StartQuery(key, packet, buffers, now, outputs);
    }
    for (const auto& server : config.servers) {
        key.server = server.transport->id;
        if (key.server != replyServer) StartQuery(key, packet, buffers, now, outputs);
    }
    return true;
}

void SyntheticDnsResolver::Route(const Packet& packet, const Configuration& config, const std::string& process,
    PacketBufferPool& buffers, Clock::time_point now, RouteDecision& decision, Outputs& outputs, std::optional<size_t> serverOverride) {
    decision.route = {FlowRoute::Kind::Unavailable};
    decision.reason = "synthetic_address_unavailable";
    if (!Configure(config)) return;
    if (packet.view.tuple.protocol == 6 && !packet.view.syn) return;
    const auto ip = packet.view.tuple.remoteIp;
    const auto name = store_.Lookup(ip);
    if (!name) return;
    const auto configured = upstreams_.find(packet.view.tuple.localIp);
    const auto upstream = configured == upstreams_.end() ? defaultUpstream_ : configured->second;
    const Server* server = nullptr;
    if (serverOverride && *serverOverride) {
        server = config.ById(*serverOverride);
        if (!server) return;
    }
    if (!server && !serverOverride) server = config.Process(process);
    if (!server && !serverOverride) {
        const auto* domain = config.Domain(*name);
        for (const auto& candidate : config.servers) {
            if (candidate.rules.staticIPRule.ipRanges.empty()) continue;
            const auto* direct = Resolve({*name, 0, upstream, packet.view.tuple.localIp}, packet, buffers, now, outputs, ip);
            if (!direct) {decision.resolutionPending = true; return;}
            if (std::any_of(direct->addresses.begin(), direct->addresses.end(), [&](uint32_t address) {
                return Public(address) && candidate.rules.staticIPRule.matches(address);
            })) {server = &candidate; break;}
        }
        if (!server) server = domain;
    }
    const auto id = server ? server->transport->id : 0;
    const auto* answer = Resolve({*name, id, upstream, packet.view.tuple.localIp}, packet, buffers, now, outputs, ip);
    if (!answer) {decision.resolutionPending = true; return;}
    if (answer->addresses.empty()) return;
    decision.route = {id ? FlowRoute::Kind::Tunnel : FlowRoute::Kind::Direct, id, answer->addresses.front()};
    decision.reason = "synthetic_address_resolved";
}

void SyntheticDnsResolver::Response(const Packet& packet, size_t server, const Configuration& config,
    PacketBufferPool& buffers, Clock::time_point now, Outputs& outputs, uint32_t& wakeAddress) {
    if (!Configure(config)) return;
    const auto wire = Payload(packet);
    if (wire.size() < 12 || wire.size() > upstreamUdpSize || (Read16(wire.data() + 2) & 0xf800) != 0x8000) return;
    const auto found = queries_.find(Read16(wire.data()));
    if (found == queries_.end()) return;
    auto& state = found->second;
    if (state.expires <= now || state.key.server != server || !Exact(state.tuple, packet.view.IncomingTuple())) return;
    const auto message = ReadSyntheticDnsResponse(wire);
    if (!message || message->name != state.key.name) return;
    Answer answer;
    answer.responseCode = message->truncated ? 2 : message->responseCode;
    answer.ttl = message->negativeTtl;
    if (!answer.responseCode) {
        for (const auto& [address, ttl] : message->addresses) {
            if (!Public(address) && (server || !PrivateIpv4(address))) continue;
            answer.ttl = answer.addresses.empty() ? ttl : (std::min)(answer.ttl, ttl);
            answer.addresses.push_back(address);
        }
    }
    if (answer.responseCode == 3 && logger_)
        logger_->log(LOGGER_LEVEL_WARNING, "synthetic_dns_nxdomain name=" + LogValue(message->name) +
            " server_id=" + std::to_string(server));
    for (const auto& listener : state.listeners) AnswerClient(listener, answer, buffers, outputs);
    wakeAddress = state.wakeAddress;
    if (cache_.size() >= maxCachedAnswers) cache_.erase(cache_.begin());
    cache_.insert_or_assign(state.key, std::move(answer));
    listeners_ -= state.listeners.size();
    pending_.erase(state.key);
    deadlines_.Erase(found->first);
    queries_.erase(found);
}
}
