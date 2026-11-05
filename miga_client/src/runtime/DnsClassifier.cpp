#include "runtime/DnsClassifier.h"

namespace miga::runtime {
bool DnsMessage::Name(const uint8_t* data, size_t size, size_t& offset, std::string& result) {
    size_t cursor = offset, consumed = 0;
    bool jumped = false;
    result.clear();
    for (size_t steps = 0; steps < 128 && cursor < size; ++steps) {
        const auto length = data[cursor++];
        if ((length & 0xc0) == 0xc0) {
            if (cursor >= size) return false;
            const size_t target = (size_t(length & 63) << 8) | data[cursor++];
            if (!jumped) consumed = cursor;
            jumped = true; cursor = target; continue;
        }
        if (length & 0xc0) return false;
        if (!length) { offset = jumped ? consumed : cursor; return true; }
        if (cursor + length > size || result.size() + length + 1 > 255) return false;
        if (!result.empty()) result.push_back('.');
        for (size_t i = 0; i < length; ++i)
            result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(data[cursor++]))));
    }
    return false;
}

bool DnsMessage::Read(const Packet& packet) {
    if (packet.view.tuple.protocol != 17) return false;
    const auto* udp = packet.bytes->data() + packet.view.header;
    const auto length = Read16(udp + 4);
    if (length < 20 || packet.view.header + length > packet.view.length) return false;
    const auto* data = udp + 8;
    const size_t size = length - 8;
    if (Read16(data + 4) != 1) return false;
    id = Read16(data); response = (data[2] & 0x80) != 0;
    size_t offset = 12;
    if (!Name(data, size, offset, question) || offset + 4 > size || Read16(data + offset + 2) != 1) return false;
    type = Read16(data + offset); offset += 4;
    const auto answers = Read16(data + 6);
    for (size_t i = 0; i < answers; ++i) {
        std::string name;
        if (!Name(data, size, offset, name) || offset + 10 > size) return false;
        const auto answerType = Read16(data + offset), answerClass = Read16(data + offset + 2);
        const auto ttl = Read32(data + offset + 4);
        const auto bytes = Read16(data + offset + 8);
        offset += 10;
        if (offset + bytes > size) return false;
        if (answerType == 1 && answerClass == 1 && bytes == 4 && (type == 1 || type == 255))
            addresses.emplace_back(Read32(data + offset), ttl);
        offset += bytes;
    }
    return true;
}

DnsClassifier::DnsClassifier() { ResetIds(); }

uint64_t DnsClassifier::TakeOverflows() {const auto count = overflows_; overflows_ = 0; return count;}

void DnsClassifier::Reconfigure(const Configuration& config) {
    if (version_ == config.version) return;
    version_ = config.version;
    decltype(dynamic_) updated;
    for (const auto& item : dynamic_) if (const auto* server = config.Domain(item.second.question)) {
        const MappingKey key{item.first.ip, server->transport->id};
        auto found = updated.find(key);
        if (found == updated.end() || found->second.expires < item.second.expires) updated[key] = item.second;
    }
    dynamic_.swap(updated); dynamicDeadlines_.Clear();
    for (const auto& item : dynamic_) dynamicDeadlines_.Set(item.first, item.second.expires);
    for (auto it = translations_.begin(); it != translations_.end();) {
        if (!config.ById(it->first.server)) {translationDeadlines_.Erase(it->first); it = translations_.erase(it);}
        else ++it;
    }
}

const Server* DnsClassifier::Select(const Configuration& config, const std::string& process, uint32_t ip, Clock::time_point now) {
    Reconfigure(config);
    if (const auto* server = config.Process(process)) return server;
    for (const auto& server : config.servers) if (server.rules.staticIPRule.matches(ip)) return &server;
    for (const auto& server : config.servers) {
        auto found = dynamic_.find({ip, server.transport->id});
        if (found != dynamic_.end() && found->second.expires > now) {
            const auto* domain = config.Domain(found->second.question);
            if (domain && domain->transport->id == server.transport->id) return &server;
        }
    }
    return nullptr;
}

uint32_t DnsClassifier::Translate(uint32_t ip, size_t server, Clock::time_point now) const {
    auto found = translations_.find({ip, server});
    return found != translations_.end() && found->second.expires > now ? found->second.ip : 0;
}

std::vector<DnsClassifier::Output> DnsClassifier::Query(const Packet& packet, const Configuration& config, const std::string& process,
    PacketBufferPool& pool, Clock::time_point now) {
    Reconfigure(config);
    DnsMessage message;
    const auto* primary = config.Process(process);
    if (!message.Read(packet) || message.response) {
        const auto* target = Select(config, process, packet.view.tuple.remoteIp, now);
        return {{packet, target ? FlowRoute{FlowRoute::Kind::Tunnel, target->transport->id, 0} : FlowRoute{}}};
    }
    if (!primary) primary = config.Domain(message.question);
    if (!primary) return {{packet, {}}};
    auto group = std::make_shared<Group>();
    group->original = message.id; group->question = message.question; group->tuple = packet.view.tuple;
    group->expires = now + std::chrono::seconds(30);
    group->primary = primary->transport->id;
    std::vector<Output> result;
    const auto append = [&](const Server& server) {
        const auto id = Allocate(now);
        if (!id) return;
        auto copy = packet;
        copy.bytes = pool.Copy(packet.bytes->data(), packet.view.length);
        Write16(copy.bytes->data() + copy.view.header + 8, *id);
        queries_[*id] = {group, server.transport->id};
        queryDeadlines_.Set(*id, group->expires);
        result.push_back({std::move(copy), {FlowRoute::Kind::Tunnel, server.transport->id, 0}});
    };
    append(*primary);
    if (result.empty()) return {};
    for (const auto& server : config.servers) if (server.transport->id != primary->transport->id) append(server);
    return result;
}

std::optional<Packet> DnsClassifier::Response(Packet packet, size_t serverId, const Configuration& config, Clock::time_point now) {
    Reconfigure(config);
    DnsMessage message;
    if (!message.Read(packet) || !message.response) return packet;
    auto found = queries_.find(message.id);
    if (serverId && found != queries_.end()) {
        auto& query = found->second;
        auto& group = *query.group;
        const auto reversed = packet.view.IncomingTuple();
        if (group.expires <= now || query.server != serverId || !Exact(group.tuple, reversed) ||
            message.question != group.question) return {};
        group.answers[serverId] = {message.addresses, now};
        const auto actual = group.answers.find(group.primary);
        if (actual != group.answers.end()) {
            for (const auto& answer : group.answers) {
                if (!config.ById(answer.first) || answer.second.addresses.empty()) continue;
                for (size_t i = 0; i < actual->second.addresses.size(); ++i) {
                    const auto original = actual->second.addresses[i];
                    const auto translated = answer.second.addresses[i % answer.second.addresses.size()];
                    const MappingKey key{original.first, answer.first};
                    const auto expires = (std::min)(actual->second.received + std::chrono::seconds(original.second),
                        answer.second.received + std::chrono::seconds(translated.second));
                    if (translations_.size() < 65536 || translations_.count(key)) {
                        translations_[key] = {translated.first, expires};
                        translationDeadlines_.Set(key, expires);
                    } else ++overflows_;
                }
            }
        }
        if (serverId != group.primary) return {};
        Write16(packet.bytes->data() + packet.view.header + 8, group.original);
    }
    if (const auto* domain = config.Domain(message.question)) {
        for (const auto& address : message.addresses) {
            const MappingKey key{address.first, domain->transport->id};
            const auto expires = now + std::chrono::seconds(address.second);
            if (dynamic_.size() < 65536 || dynamic_.count(key)) {
                dynamic_[key] = {expires, message.question};
                dynamicDeadlines_.Set(key, expires);
            } else ++overflows_;
        }
    }
    return packet;
}

void DnsClassifier::Cleanup(Clock::time_point now) {
    uint16_t query = 0;
    for (size_t i = 0; i < 128 && queryDeadlines_.PopDue(now, query); ++i)
        if (queries_.erase(query)) freeIds_.push_back(query);
    MappingKey key{};
    for (size_t i = 0; i < 128 && translationDeadlines_.PopDue(now, key); ++i) translations_.erase(key);
    for (size_t i = 0; i < 128 && dynamicDeadlines_.PopDue(now, key); ++i) dynamic_.erase(key);
}

void DnsClassifier::Clear() {
    queries_.clear(); dynamic_.clear(); translations_.clear();
    queryDeadlines_.Clear(); translationDeadlines_.Clear(); dynamicDeadlines_.Clear();
    ResetIds(); overflows_ = 0; version_ = 0;
}

bool DnsClassifier::MappingKey::operator==(const MappingKey& other) const { return ip == other.ip && server == other.server; }

size_t DnsClassifier::MappingHash::operator()(const MappingKey& key) const { return size_t(key.ip) ^ (key.server * 0x9e3779b9); }

std::optional<uint16_t> DnsClassifier::Allocate(Clock::time_point now) {
    if (queries_.size() >= 8192) Cleanup(now);
    if (queries_.size() >= 8192 || freeIds_.empty()) {++overflows_; return {};}
    const auto id = freeIds_.front(); freeIds_.pop_front(); return id;
}

void DnsClassifier::ResetIds() {freeIds_.clear(); for (uint32_t i = 0; i < 65536; ++i) freeIds_.push_back(static_cast<uint16_t>(i));}

}
