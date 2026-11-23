#include "ProtocolV2.h"
#include "nlohmann/json.hpp"
#include <sodium.h>
#include <noise/protocol.h>
#include <algorithm>
#include <cstring>
#include <set>
#include <limits>

namespace miga::v2 {
namespace {
template <size_t N> void Append(Bytes &out, const std::array<uint8_t, N> &value) {
    out.insert(out.end(), value.begin(), value.end());
}
template <size_t N> bool Field(const nlohmann::json &object, const char *name, std::array<uint8_t, N> &value) {
    if (!object.contains(name) || !object[name].is_string())
        return false;
    Bytes bytes;
    if (!Unbase64(object[name].get<std::string>(), bytes) || bytes.size() != N)
        return false;
    std::copy(bytes.begin(), bytes.end(), value.begin());
    return true;
}
Key ExpandKey(const Key &secret, const std::string &label, const Bytes &context) {
    const auto bytes = Hkdf(secret, label, context, 32);
    Key key{};
    std::copy(bytes.begin(), bytes.end(), key.begin());
    return key;
}
void AdjustChecksum(uint8_t *checksum, uint32_t from, uint32_t to) {
    uint32_t sum = uint16_t(~Get16(checksum));
    sum += uint16_t(~uint16_t(from >> 16));
    sum += uint16_t(to >> 16);
    sum += uint16_t(~uint16_t(from));
    sum += uint16_t(to);
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    const auto value = uint16_t(~sum);
    checksum[0] = uint8_t(value >> 8);
    checksum[1] = uint8_t(value);
}
}
Invitation::~Invitation() {
    sodium_memzero(serverSecret.data(), serverSecret.size());
    sodium_memzero(clientSecret.data(), clientSecret.size());
}
SessionKeys::~SessionKeys() {
    sodium_memzero(dataC2S.data(), dataC2S.size());
    sodium_memzero(dataS2C.data(), dataS2C.size());
    sodium_memzero(controlC2S.data(), controlC2S.size());
    sodium_memzero(controlS2C.data(), controlS2C.size());
    sodium_memzero(resume.data(), resume.size());
}
OpenReply::~OpenReply() {
    sodium_memzero(secret.data(), secret.size());
}
bool Initialize() {
    return sodium_init() >= 0;
}
void Random(uint8_t *output, size_t length) {
    randombytes_buf(output, length);
}
void Put16(Bytes &b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}
void Put32(Bytes &b, uint32_t v) {
    for (int i = 3; i >= 0; --i)
        b.push_back(uint8_t(v >> (i * 8)));
}
void Put64(Bytes &b, uint64_t v) {
    for (int i = 7; i >= 0; --i)
        b.push_back(uint8_t(v >> (i * 8)));
}
uint16_t Get16(const uint8_t *b) {
    return uint16_t(uint16_t(b[0]) << 8 | b[1]);
}
uint32_t Get32(const uint8_t *b) {
    return uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3];
}
uint64_t Get64(const uint8_t *b) {
    return uint64_t(Get32(b)) << 32 | Get32(b + 4);
}
std::string Base64(const uint8_t *data, size_t length) {
    std::string result(sodium_base64_ENCODED_LEN(length, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    sodium_bin2base64(result.data(), result.size(), data, length, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    result.resize(std::strlen(result.c_str()));
    return result;
}
bool Unbase64(const std::string &value, Bytes &result) {
    if (value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != std::string::npos)
        return false;
    result.resize(value.size());
    size_t size = 0;
    const char *end = nullptr;
    if (sodium_base642bin(result.data(), result.size(), value.data(), value.size(), nullptr, &size, &end,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
        end != value.data() + value.size())
        return false;
    result.resize(size);
    return Base64(result.data(), result.size()) == value;
}
bool ParseInvitation(const std::string &text, Invitation &invitation) {
    if (text.size() > 4096 || text.compare(0, 6, "miga2:") != 0)
        return false;
    Bytes bytes;
    if (!Unbase64(text.substr(6), bytes))
        return false;
    try {
        bool duplicate = false;
        std::vector<std::set<std::string>> objects;
        auto callback = [&](int, nlohmann::json::parse_event_t event, nlohmann::json &parsed) {
            if (event == nlohmann::json::parse_event_t::object_start)
                objects.emplace_back();
            else if (event == nlohmann::json::parse_event_t::key && !objects.empty())
                duplicate |= !objects.back().insert(parsed.get<std::string>()).second;
            else if (event == nlohmann::json::parse_event_t::object_end && !objects.empty())
                objects.pop_back();
            return true;
        };
        const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), callback);
        if (duplicate || !j.is_object() || j.size() != 7)
            return false;
        for (const auto* name : {"v", "host", "ports", "server_key", "server_secret", "client_id", "client_secret"})
            if (!j.contains(name))
                return false;
        if (!j["v"].is_number_integer() || j["v"] != 2 || !j["host"].is_string())
            return false;
        Invitation next;
        next.host = j["host"].get<std::string>();
        if (next.host.empty() || next.host.size() > 253 || next.host.front() == '.' || next.host.back() == '.' ||
            next.host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.") != std::string::npos)
            return false;
        size_t label = 0;
        while (label < next.host.size()) {
            const auto dot = next.host.find('.', label);
            const auto end = dot == std::string::npos ? next.host.size() : dot;
            if (end == label || end - label > 63 || next.host[label] == '-' || next.host[end - 1] == '-')
                return false;
            label = end + 1;
        }
        if (!j["ports"].is_array() || j["ports"].size() != 2 || !j["ports"][0].is_number_integer() || !j["ports"][1].is_number_integer())
            return false;
        const auto start = j["ports"][0].get<int64_t>(), end = j["ports"][1].get<int64_t>();
        if (start < 1024 || end > 65535 || start > end)
            return false;
        next.portStart = uint16_t(start);
        next.portEnd = uint16_t(end);
        if (!Field(j, "server_key", next.serverKey) || !Field(j, "server_secret", next.serverSecret) ||
            !Field(j, "client_id", next.clientId) || !Field(j, "client_secret", next.clientSecret))
            return false;
        invitation = std::move(next);
        return true;
    } catch (...) {
        return false;
    }
}
std::string FormatInvitation(const Invitation &i) {
    nlohmann::json j = {{"v", 2},
                        {"host", i.host},
                        {"ports", {i.portStart, i.portEnd}},
                        {"server_key", Base64(i.serverKey.data(), 32)},
                        {"server_secret", Base64(i.serverSecret.data(), 32)},
                        {"client_id", Base64(i.clientId.data(), 16)},
                        {"client_secret", Base64(i.clientSecret.data(), 32)}};
    const auto text = j.dump();
    return "miga2:" + Base64(reinterpret_cast<const uint8_t *>(text.data()), text.size());
}
Key Hmac(const Key &key, const uint8_t *data, size_t length) {
    Key out{};
    crypto_auth_hmacsha256(out.data(), data, length, key.data());
    return out;
}
Bytes Hkdf(const Key &secret, const std::string &label, const Bytes &context, size_t length) {
    if (length > 255 * 32)
        return {};
    const Key salt{};
    auto extracted = Hmac(salt, secret.data(), secret.size());
    Bytes info(label.begin(), label.end());
    info.push_back(0);
    info.insert(info.end(), context.begin(), context.end());
    Bytes previous, output;
    for (unsigned counter = 1; output.size() < length; ++counter) {
        Bytes input = previous;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(uint8_t(counter));
        const auto block = Hmac(extracted, input.data(), input.size());
        previous.assign(block.begin(), block.end());
        const auto amount = std::min(length - output.size(), previous.size());
        output.insert(output.end(), previous.begin(), previous.begin() + amount);
    }
    sodium_memzero(extracted.data(), extracted.size());
    return output;
}
Key ScheduleKey(const Key &secret) {
    return ExpandKey(secret, "miga-v2/schedule", {});
}
Key EnvelopeKey(const Key &secret) {
    return ExpandKey(secret, "miga-v2/envelope", {});
}
uint16_t DailyPort(const Key &key, uint64_t day, uint16_t start, uint16_t end) {
    if (start > end)
        return 0;
    Bytes bytes;
    Put64(bytes, day);
    const auto hash = Hmac(key, bytes.data(), bytes.size());
    return uint16_t(start + Get64(hash.data()) % (uint32_t(end) - start + 1));
}
SessionKeys DeriveSession(const Key &secret, const Key &hash, const Id &client, const Id &session) {
    Bytes context;
    Append(context, hash);
    Append(context, client);
    Append(context, session);
    SessionKeys keys;
    keys.dataC2S = ExpandKey(secret, "miga-v2/data/c2s", context);
    keys.dataS2C = ExpandKey(secret, "miga-v2/data/s2c", context);
    keys.controlC2S = ExpandKey(secret, "miga-v2/control/c2s", context);
    keys.controlS2C = ExpandKey(secret, "miga-v2/control/s2c", context);
    keys.resume = ExpandKey(secret, "miga-v2/resume", context);
    auto prefix = Hkdf(secret, "miga-v2/prefix/c2s", context, 4);
    std::copy(prefix.begin(), prefix.end(), keys.prefixC2S.begin());
    prefix = Hkdf(secret, "miga-v2/prefix/s2c", context, 4);
    std::copy(prefix.begin(), prefix.end(), keys.prefixS2C.begin());
    return keys;
}
Bytes EncodeMessage(const Message &message) {
    if (message.body.size() > MaxControl - 22)
        return {};
    Bytes out;
    Put16(out, 2);
    Put16(out, uint16_t(message.operation));
    Append(out, message.request);
    Put16(out, uint16_t(message.body.size()));
    out.insert(out.end(), message.body.begin(), message.body.end());
    return out;
}
bool DecodeMessage(const Bytes &bytes, Message &message) {
    if (bytes.size() < 22 || bytes.size() > MaxControl || Get16(bytes.data()) != 2 || Get16(bytes.data() + 2) < 1 ||
        Get16(bytes.data() + 2) > 14)
        return false;
    const auto length = Get16(bytes.data() + 20);
    if (length > bytes.size() - 22)
        return false;
    message.operation = Operation(Get16(bytes.data() + 2));
    std::copy_n(bytes.data() + 4, 16, message.request.begin());
    message.body.assign(bytes.begin() + 22, bytes.begin() + 22 + length);
    return true;
}
Bytes Seal(const Key &key, const Bytes &plaintext, size_t minimum, size_t maximum) {
    const auto needed = plaintext.size() + 40;
    if (needed > MaxControl || minimum > maximum || maximum > MaxControl)
        return {};
    size_t size = needed;
    if (needed <= maximum) {
        const auto low = std::max(needed, minimum);
        size = low + randombytes_uniform(uint32_t(maximum - low + 1));
    }
    Bytes padded(size - 40);
    Random(padded.data(), padded.size());
    std::copy(plaintext.begin(), plaintext.end(), padded.begin());
    Bytes output(size);
    Random(output.data(), 24);
    unsigned long long length = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(output.data() + 24, &length, padded.data(), padded.size(), nullptr, 0, nullptr,
                                                   output.data(), key.data()) != 0)
        return {};
    return output;
}
bool Unseal(const Key &key, const uint8_t *data, size_t length, Bytes &plaintext) {
    if (!data || length < 40 || length > MaxControl)
        return false;
    plaintext.resize(length - 40);
    unsigned long long size = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext.data(), &size, nullptr, data + 24, length - 24, nullptr, 0, data,
                                                   key.data()) != 0) {
        plaintext.clear();
        return false;
    }
    plaintext.resize(size);
    return true;
}
Bytes EncodeHello(const Hello &hello) {
    if (hello.noise.size() > 1000)
        return {};
    Bytes b;
    Append(b, hello.client);
    Put64(b, hello.time);
    Put16(b, uint16_t(hello.noise.size()));
    b.insert(b.end(), hello.noise.begin(), hello.noise.end());
    Append(b, hello.proof);
    return b;
}
bool DecodeHello(const Bytes &b, Hello &h) {
    if (b.size() < 58)
        return false;
    const auto n = Get16(b.data() + 24);
    if (size_t(n) != b.size() - 58)
        return false;
    std::copy_n(b.data(), 16, h.client.begin());
    h.time = Get64(b.data() + 16);
    h.noise.assign(b.begin() + 26, b.begin() + 26 + n);
    std::copy_n(b.data() + 26 + n, 32, h.proof.begin());
    return true;
}
Key HelloProof(const Key &key, const Id &client, uint64_t time, const Id &request, const Key &server, const Bytes &noise) {
    Bytes b;
    Put16(b, 2);
    Put16(b, 16);
    Append(b, client);
    Put16(b, 8);
    Put64(b, time);
    Put16(b, 16);
    Append(b, request);
    Put16(b, 32);
    Append(b, server);
    Put16(b, uint16_t(noise.size()));
    b.insert(b.end(), noise.begin(), noise.end());
    return Hmac(key, b.data(), b.size());
}
Bytes EncodeOpenReply(const OpenReply &r) {
    if (r.addresses.size() > 16)
        return {};
    Bytes b;
    Append(b, r.session);
    Append(b, r.secret);
    Append(b, r.challenge);
    Put16(b, r.port);
    b.push_back(uint8_t(r.addresses.size()));
    for (auto a : r.addresses) {
        Put32(b, a.first);
        Put32(b, a.second);
    }
    return b;
}
bool DecodeOpenReply(const Bytes &b, OpenReply &r) {
    if (b.size() < 83 || b[82] > 16 || b.size() != 83 + size_t(b[82]) * 8)
        return false;
    std::copy_n(b.data(), 16, r.session.begin());
    std::copy_n(b.data() + 16, 32, r.secret.begin());
    std::copy_n(b.data() + 48, 32, r.challenge.begin());
    r.port = Get16(b.data() + 80);
    r.addresses.clear();
    if (r.port < 1024)
        return false;
    for (size_t n = 83; n < b.size(); n += 8)
        r.addresses.emplace_back(Get32(b.data() + n), Get32(b.data() + n + 4));
    return true;
}
Bytes SealControl(const Key &envelope, const Key &key, const Id &session, uint64_t counter, const Message &message) {
    Bytes inner;
    Put64(inner, counter);
    const auto encoded = EncodeMessage(message);
    if (encoded.empty())
        return {};
    inner.insert(inner.end(), encoded.begin(), encoded.end());
    auto sealed = Seal(key, inner, inner.size() + 40, inner.size() + 40);
    if (sealed.empty())
        return {};
    Bytes out;
    Append(out, session);
    Put16(out, uint16_t(sealed.size()));
    out.insert(out.end(), sealed.begin(), sealed.end());
    return Seal(envelope, out);
}
bool UnsealControl(const Key &envelope, const Key &key, const uint8_t *data, size_t length, Id &session, uint64_t &counter,
                   Message &message) {
    Bytes outer;
    if (!Unseal(envelope, data, length, outer) || outer.size() < 58)
        return false;
    std::copy_n(outer.data(), 16, session.begin());
    const auto size = Get16(outer.data() + 16);
    if (size < 70 || size > outer.size() - 18)
        return false;
    Bytes inner;
    if (!Unseal(key, outer.data() + 18, size, inner) || inner.size() < 30)
        return false;
    counter = Get64(inner.data());
    return DecodeMessage(Bytes(inner.begin() + 8, inner.end()), message);
}

bool ReplayWindow::Accept(uint64_t counter) {
    if (!counter)
        return false;
    if (counter > highest) {
        const auto shift = counter - highest;
        bitmap = shift >= 64 ? 1 : (bitmap << shift) | 1;
        highest = counter;
        return true;
    }
    const auto distance = highest - counter;
    if (distance >= 64 || (bitmap & (uint64_t(1) << distance)))
        return false;
    bitmap |= uint64_t(1) << distance;
    return true;
}
bool ValidateInner(const uint8_t *p, size_t available, size_t &length, bool &keepalive) {
    keepalive = false;
    length = 0;
    if (!p || !available)
        return false;
    if ((p[0] >> 4) != 4) {
        keepalive = true;
        length = available;
        return true;
    }
    if (available < 20)
        return false;
    const auto header = size_t(p[0] & 15) * 4;
    if (header < 20 || header > available)
        return false;
    length = Get16(p + 2);
    if (length < header || length > available || length > MaxInner)
        return false;
    if (p[9] != 6 && p[9] != 17)
        return false;
    const auto fragment = Get16(p + 6);
    if ((fragment & 0x8000) || ((fragment & 0x4000) && (fragment & 0x3fff)))
        return false;
    if ((fragment & 0x2000) && ((length - header) % 8 || length == header))
        return false;
    if (!(fragment & 0x1fff)) {
        if (p[9] == 6 &&
            (length - header < 20 || size_t(p[header + 12] >> 4) * 4 < 20 || size_t(p[header + 12] >> 4) * 4 > length - header))
            return false;
        if (p[9] == 17 &&
            (length - header < 8 || Get16(p + header + 4) < 8 || (!(fragment & 0x2000) && Get16(p + header + 4) != length - header)))
            return false;
    }
    return true;
}
size_t EncryptDataInto(const Key &key, const Prefix &prefix, const uint8_t *packet, size_t length, uint8_t *output, size_t capacity, size_t maximumPayload) {
    size_t actual;
    bool keepalive;
    if (!output || length > MaxInner || !ValidateInner(packet, length, actual, keepalive) || actual != length)
        return 0;
    size_t padded = length;
    const auto ceiling = std::min(size_t(256), maximumPayload);
    if (length + 8 < ceiling) {
        const auto low = std::min(ceiling, std::max(size_t(96), length + 8));
        padded = low + randombytes_uniform(uint32_t(ceiling - low + 1)) - 8;
    }
    if (capacity < padded + 8)
        return 0;
    Random(output, 8);
    std::array<uint8_t, 12> nonce{};
    std::copy(prefix.begin(), prefix.end(), nonce.begin());
    std::copy_n(output, 8, nonce.data() + 4);
    if (crypto_stream_chacha20_ietf_xor_ic(output + 8, packet, length, nonce.data(), 0, key.data()) != 0)
        return 0;
    if (padded > length) {
        std::array<uint8_t, 256> padding{};
        const auto offset = length % 64;
        const auto paddingLength = padded - length;
        Random(padding.data() + offset, paddingLength);
        if (crypto_stream_chacha20_ietf_xor_ic(padding.data(), padding.data(), offset + paddingLength,
                nonce.data(), static_cast<uint32_t>(length / 64), key.data()) != 0)
            return 0;
        std::copy_n(padding.data() + offset, paddingLength, output + 8 + length);
    }
    return padded + 8;
}
bool EncryptData(const Key &key, const Prefix &prefix, const uint8_t *packet, size_t length, Bytes &output, size_t maximumPayload) {
    if (length > MaxInner) {
        output.clear();
        return false;
    }
    output.resize(std::max(length + 8, std::min(size_t(256), maximumPayload)));
    const auto written = EncryptDataInto(key, prefix, packet, length, output.data(), output.size(), maximumPayload);
    output.resize(written);
    return written != 0;
}
bool EncryptKeepalive(const Key &key, const Prefix &prefix, Bytes &output, size_t maximumPayload) {
    const auto ceiling = std::min(size_t(256), maximumPayload);
    if (ceiling < 9)
        return false;
    const auto low = std::min(size_t(96), ceiling);
    const auto size = low + randombytes_uniform(uint32_t(ceiling - low + 1));
    Bytes plaintext(size - 8);
    Random(plaintext.data(), plaintext.size());
    plaintext[0] = uint8_t((plaintext[0] & 15) | 0x60);
    return EncryptData(key, prefix, plaintext.data(), plaintext.size(), output, size);
}
bool EncryptDataProbe(const Key& key, const Prefix& prefix, const Id& token, bool reply, Bytes& output) {
    Bytes plaintext{static_cast<uint8_t>(reply ? 0x72 : 0x71)};
    plaintext.insert(plaintext.end(), token.begin(), token.end());
    const auto tag = Hmac(key, plaintext.data(), plaintext.size());
    plaintext.insert(plaintext.end(), tag.begin(), tag.end());
    return EncryptData(key, prefix, plaintext.data(), plaintext.size(), output, plaintext.size() + 8);
}
bool ReadDataProbe(const Key& key, const Bytes& plaintext, bool reply, Id& token) {
    const size_t header = 1 + token.size();
    if (plaintext.size() != header + Key{}.size() || plaintext[0] != (reply ? 0x72 : 0x71))
        return false;
    const auto tag = Hmac(key, plaintext.data(), header);
    if (sodium_memcmp(tag.data(), plaintext.data() + header, tag.size()) != 0)
        return false;
    std::copy_n(plaintext.data() + 1, token.size(), token.begin());
    return true;
}
bool DecryptData(const Key &key, const Prefix &prefix, const uint8_t *packet, size_t length, Bytes &output) {
    output.clear();
    if (!packet || length < 9 || length > 65507)
        return false;
    std::array<uint8_t, 12> nonce{};
    std::copy(prefix.begin(), prefix.end(), nonce.begin());
    std::copy_n(packet, 8, nonce.data() + 4);
    output.resize(length - 8);
    if (crypto_stream_chacha20_ietf_xor_ic(output.data(), packet + 8, length - 8, nonce.data(), 0, key.data()) != 0)
        return false;
    size_t actual;
    bool keepalive;
    if (!ValidateInner(output.data(), output.size(), actual, keepalive)) {
        output.clear();
        return false;
    }
    output.resize(actual);
    return true;
}
bool TranslateAddress(uint8_t *packet, size_t length, uint32_t oldAddress, uint32_t newAddress, bool source) {
    size_t actual;
    bool keepalive;
    if (!ValidateInner(packet, length, actual, keepalive) || keepalive)
        return false;
    auto *address = packet + (source ? 12 : 16);
    if (Get32(address) != oldAddress)
        return false;
    AdjustChecksum(packet + 10, oldAddress, newAddress);
    const auto header = size_t(packet[0] & 15) * 4;
    if (!(Get16(packet + 6) & 0x1fff)) {
        auto *checksum = packet + header + (packet[9] == 6 ? 16 : 6);
        if (packet[9] == 6 || Get16(checksum)) {
            AdjustChecksum(checksum, oldAddress, newAddress);
            if (packet[9] == 17 && Get16(checksum) == 0) {
                checksum[0] = 255;
                checksum[1] = 255;
            }
        }
    }
    address[0] = uint8_t(newAddress >> 24);
    address[1] = uint8_t(newAddress >> 16);
    address[2] = uint8_t(newAddress >> 8);
    address[3] = uint8_t(newAddress);
    return true;
}
NoiseHandshake::NoiseHandshake() = default;
NoiseHandshake::~NoiseHandshake() {
    if (state_)
        noise_handshakestate_free(static_cast<NoiseHandshakeState *>(state_));
}
bool NoiseHandshake::Start(bool initiator, const Key &server, const Key *secret) {
    if (state_)
        return false;
    NoiseHandshakeState *state = nullptr;
    if (noise_handshakestate_new_by_name(&state, "Noise_NK_25519_ChaChaPoly_BLAKE2s",
                                         initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER) != NOISE_ERROR_NONE)
        return false;
    state_ = state;
    if (initiator) {
        if (noise_dhstate_set_public_key(noise_handshakestate_get_remote_public_key_dh(state), server.data(), 32) != NOISE_ERROR_NONE)
            return false;
    } else if (!secret || noise_dhstate_set_keypair(noise_handshakestate_get_local_keypair_dh(state), secret->data(), 32, server.data(),
                                                    32) != NOISE_ERROR_NONE)
        return false;
    return noise_handshakestate_start(state) == NOISE_ERROR_NONE;
}
bool NoiseHandshake::Write(const Bytes &payload, Bytes &message) {
    if (!state_)
        return false;
    message.resize(MaxControl);
    NoiseBuffer out, in;
    noise_buffer_set_output(out, message.data(), message.size());
    noise_buffer_set_input(in, const_cast<uint8_t *>(payload.data()), payload.size());
    if (noise_handshakestate_write_message(static_cast<NoiseHandshakeState *>(state_), &out, payload.empty() ? nullptr : &in) !=
        NOISE_ERROR_NONE)
        return false;
    message.resize(out.size);
    return true;
}
bool NoiseHandshake::Read(const Bytes &message, Bytes &payload) {
    if (!state_)
        return false;
    Bytes copy = message;
    payload.resize(MaxControl);
    NoiseBuffer in, out;
    noise_buffer_set_input(in, copy.data(), copy.size());
    noise_buffer_set_output(out, payload.data(), payload.size());
    if (noise_handshakestate_read_message(static_cast<NoiseHandshakeState *>(state_), &in, &out) != NOISE_ERROR_NONE)
        return false;
    payload.resize(out.size);
    return true;
}
bool NoiseHandshake::Complete() const {
    return state_ && noise_handshakestate_get_action(static_cast<NoiseHandshakeState *>(state_)) == NOISE_ACTION_SPLIT;
}
bool NoiseHandshake::Hash(Key &hash) const {
    return Complete() && noise_handshakestate_get_handshake_hash(static_cast<NoiseHandshakeState *>(state_), hash.data(), hash.size()) ==
                             NOISE_ERROR_NONE;
}
bool NoiseHandshake::GenerateKeypair(Key &secret, Key &publicKey) {
    Random(secret.data(), secret.size());
    return crypto_scalarmult_curve25519_base(publicKey.data(), secret.data()) == 0;
}
}
