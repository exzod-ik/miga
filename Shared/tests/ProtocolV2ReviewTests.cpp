#include "ProtocolV2.h"
#include "ProtocolV2Packets.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <limits>
#include <cstring>
using namespace miga::v2;
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template<class T> std::string Hex(const T& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out; out.reserve(bytes.size() * 2);
    for (auto value : bytes) { out.push_back(digits[value >> 4]); out.push_back(digits[value & 15]); }
    return out;
}
void Set16(Bytes& b, size_t offset, uint16_t value) { b[offset] = uint8_t(value >> 8); b[offset + 1] = uint8_t(value); }
uint16_t Sum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2) sum += uint32_t(data[i]) * 256 + (i + 1 < length ? data[i + 1] : 0);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return uint16_t(~sum);
}
Bytes Udp() {
    Bytes p(29); p[0] = 0x45; p[8] = 64; p[9] = 17;
    Set16(p, 2, uint16_t(p.size()));
    p[12] = 192; p[13] = 0; p[14] = 2; p[15] = 1;
    p[16] = 198; p[17] = 51; p[18] = 100; p[19] = 2;
    Set16(p, 20, 12345); Set16(p, 22, 443); Set16(p, 24, 9); p[28] = 99;
    Bytes pseudo(p.begin() + 12, p.begin() + 20); pseudo.push_back(0); pseudo.push_back(17); Put16(pseudo, 9);
    pseudo.insert(pseudo.end(), p.begin() + 20, p.end());
    auto checksum = Sum(pseudo.data(), pseudo.size()); Set16(p, 26, checksum ? checksum : 65535);
    Set16(p, 10, Sum(p.data(), 20)); return p;
}
void Invitations() {
    Invitation value; value.host = "vpn.example.org";
    for (size_t n = 0; n < 32; ++n) { value.serverSecret[n] = uint8_t(n); value.serverKey[n] = uint8_t(n + 1); value.clientSecret[n] = uint8_t(n + 2); }
    Invitation decoded;
    const auto invitation = FormatInvitation(value);
    Require(ParseInvitation(invitation, decoded), "valid seven-field invitation rejected");
    Require(decoded.host == value.host && decoded.clientSecret == value.clientSecret, "invitation content changed");
    Bytes json; Require(Unbase64(invitation.substr(6), json), "base64 decode");
    std::string duplicate(json.begin(), json.end()); duplicate.insert(1, "\"v\":2,");
    const auto duplicateEncoded = "miga2:" + Base64(reinterpret_cast<const uint8_t*>(duplicate.data()), duplicate.size());
    Require(!ParseInvitation(duplicateEncoded, decoded), "duplicate JSON field accepted");
    std::string missingVersion(json.begin(), json.end());
    const auto versionAt = missingVersion.find("\"v\":2");
    Require(versionAt != std::string::npos, "invitation version fixture");
    missingVersion.replace(versionAt, 5, "\"unknown\":2");
    const auto missingEncoded = "miga2:" + Base64(reinterpret_cast<const uint8_t*>(missingVersion.data()), missingVersion.size());
    Require(!ParseInvitation(missingEncoded, decoded), "unknown replacement field accepted");
    Require(!ParseInvitation(invitation + "=", decoded), "noncanonical Base64 accepted");
    Require(!ParseInvitation(std::string(4097, 'a'), decoded), "oversize invitation accepted");
}
void Cryptography() {
    Key key{}; for (size_t i = 0; i < key.size(); ++i) key[i] = uint8_t(i);
    Require(DailyPort(key, 0, 10000, 15000) == 13110, "daily HMAC vector day0");
    Require(DailyPort(key, 1, 10000, 15000) == 11920, "daily HMAC vector day1");
    Require(DailyPort(key, 20771, 10000, 15000) == 11824, "daily HMAC vector day20771");
    Require(DailyPort(key, uint64_t(4294967296), 10000, 15000) == 13451, "daily HMAC vector uint64");
    Require(ScheduleKey(key) != EnvelopeKey(key), "HKDF role separation");
    Require(Hex(ScheduleKey(key)) == "9368eafdf404209d72f445ca5f72f3b77c330f0270c2c9e51a560adb739cc929", "HKDF schedule vector");
    Require(Hex(EnvelopeKey(key)) == "b2d31079967986b2f770220741883107ad3b8d58a16b8d110692b01c848473bd", "HKDF envelope vector");
    Require(Hex(Hkdf(key, "review", {1, 2, 3}, 65)) == "cbe1dca73388e8903f73c921b64fd62cdfdfe8a55644be7a17700f62fb60175c35c9a102658f0896953e470a9760b04e0502298b80fccb213079a633d92315d415", "HKDF multiblock vector");
    Require(Hex(HelloProof(key, Id{}, 1700000000, Id{}, key, {7, 8, 9})) == "1df8d054c3f9373eccf7e3febd6e3624f05b7db95b121a1c34a5fcb4c925f294", "personal HMAC vector");
    Id client{}, session{}; Key hash{}; auto a = DeriveSession(key, hash, client, session); session[0] = 1; auto b = DeriveSession(key, hash, client, session);
    Require(a.dataC2S != a.dataS2C && a.controlC2S != a.dataC2S && a.dataC2S != b.dataC2S, "session key separation");
    Require(Hex(a.dataC2S) == "e7a936228c9615f9ebdd74fc5cc1ab3e99bb060531e688d60f3c8f2560bfc8d1", "session key context vector");
    Require(Hex(a.prefixS2C) == "0b5b1669", "session nonce prefix vector");
    Message request; request.operation = Operation::Status; request.body = {1, 2, 3}; Random(request.request.data(), request.request.size());
    const auto sealed = SealControl(EnvelopeKey(key), a.controlC2S, session, 1, request);
    Id received{}; uint64_t counter = 0; Message parsed;
    Require(!sealed.empty() && UnsealControl(EnvelopeKey(key), a.controlC2S, sealed.data(), sealed.size(), received, counter, parsed), "control roundtrip");
    Require(received == session && counter == 1 && parsed.body == request.body && parsed.request == request.request, "control content");
    auto changed = sealed; changed.back() ^= 1;
    Require(!UnsealControl(EnvelopeKey(key), a.controlC2S, changed.data(), changed.size(), received, counter, parsed), "tampered control accepted");
    for (size_t length = 0; length < 40; ++length) Require(!UnsealControl(EnvelopeKey(key), a.controlC2S, sealed.data(), length, received, counter, parsed), "short control accepted");
    Key secret{}, publicKey{}; Require(NoiseHandshake::GenerateKeypair(secret, publicKey), "Noise keys");
    NoiseHandshake initiator, responder;
    Require(initiator.Start(true, publicKey) && responder.Start(false, publicKey, &secret), "Noise start");
    Bytes first, second, payload;
    Require(initiator.Write({}, first), "Noise first write"); Require(responder.Read(first, payload), "Noise first read");
    Require(responder.Write({7, 8, 9}, second) && initiator.Read(second, payload), "Noise response");
    Require(payload == Bytes({7, 8, 9}), "Noise payload");
    Key left{}, right{}; Require(initiator.Hash(left) && responder.Hash(right) && left == right, "Noise transcript hash");
    NoiseHandshake badClient, badServer; Require(badClient.Start(true, publicKey) && badServer.Start(false, publicKey, &secret), "Noise tamper start");
    Require(badClient.Write({}, first) && badServer.Read(first, payload) && badServer.Write({7}, second), "Noise tamper exchange");
    second.back() ^= 1; Require(!badClient.Read(second, payload), "Noise tamper accepted");
}
void TcpPackets() {
    Bytes packet(45); packet[0] = 0x45; packet[8] = 64; packet[9] = 6;
    Set16(packet, 2, uint16_t(packet.size()));
    packet[12] = 192; packet[14] = 2; packet[15] = 1;
    packet[16] = 198; packet[17] = 51; packet[18] = 100; packet[19] = 2;
    Set16(packet, 20, 12345); Set16(packet, 22, 443); packet[32] = 0x60; packet[33] = 2;
    packet[40] = 2; packet[41] = 4; Set16(packet, 42, 1400); packet[44] = 99;
    const auto tcpSum = [](const Bytes& bytes) {
        Bytes pseudo(bytes.begin() + 12, bytes.begin() + 20); pseudo.push_back(0); pseudo.push_back(6);
        Put16(pseudo, uint16_t(bytes.size() - 20)); pseudo.insert(pseudo.end(), bytes.begin() + 20, bytes.end());
        return Sum(pseudo.data(), pseudo.size());
    };
    Set16(packet, 36, tcpSum(packet)); Set16(packet, 10, Sum(packet.data(), 20));
    for (bool source : {true, false}) {
        auto translated = packet;
        const auto originalAddress = Get32(packet.data() + (source ? 12 : 16));
        Require(TranslateAddress(translated.data(), translated.size(), originalAddress, 0x0a400002, source), "TCP address translation");
        Require(Sum(translated.data(), 20) == 0 && tcpSum(translated) == 0, "TCP translated checksums");
        Bytes encrypted, decrypted;
        Require(EncryptData(Key{}, Prefix{}, translated.data(), translated.size(), encrypted), "TCP encryption");
        Require(DecryptData(Key{}, Prefix{}, encrypted.data(), encrypted.size(), decrypted) && decrypted == translated, "TCP decrypt/options");
        Require(TranslateAddress(decrypted.data(), decrypted.size(), 0x0a400002, originalAddress, source) && decrypted == packet, "TCP reverse translation");
    }
}
void Replay() {
    ReplayWindow window;
    Require(!window.Accept(0) && window.Accept(1) && !window.Accept(1), "control replay duplicate");
    Require(window.Accept(65) && window.Accept(2) && !window.Accept(1) && !window.Accept(2), "control replay boundary");
    Require(window.Accept(std::numeric_limits<uint64_t>::max()), "control replay high counter");
    Require(!window.Accept(65) && !window.Accept(0), "control replay wrap");
}
void Packets() {
    const auto original = Udp(); Key key{}; Prefix prefix{}; Bytes encrypted, plain;
    auto contradictory = original; contradictory.resize(36); Set16(contradictory, 2, 36); Set16(contradictory, 24, 16); Set16(contradictory, 6, 0x6000);
    size_t contradictoryLength = 0; bool contradictoryKeepalive = false;
    Require(!ValidateInner(contradictory.data(), contradictory.size(), contradictoryLength, contradictoryKeepalive), "DF/MF contradictory data accepted");
    for (unsigned i = 0; i < 128; ++i) {
        Require(EncryptData(key, prefix, original.data(), original.size(), encrypted), "data encryption");
        Require(encrypted.size() >= 96 && encrypted.size() <= 256, "padding range");
        Require(DecryptData(key, prefix, encrypted.data(), encrypted.size(), plain) && plain == original, "data roundtrip");
        Require(EncryptData(key, prefix, original.data(), original.size(), encrypted, 100) && encrypted.size() <= 100, "padding exceeds MTU");
        Require(EncryptKeepalive(key, prefix, encrypted), "keepalive encryption");
        Require(encrypted.size() >= 96 && encrypted.size() <= 256, "keepalive size");
        Require(DecryptData(key, prefix, encrypted.data(), encrypted.size(), plain) && plain[0] >> 4 != 4, "keepalive format");
    }
    for (const size_t size : {size_t(63), size_t(64), size_t(65), size_t(127), size_t(128), size_t(129), size_t(247), size_t(248), size_t(249), MaxInner}) {
        auto packet = original; packet.resize(size, 0x7c); Set16(packet, 2, uint16_t(size)); Set16(packet, 24, uint16_t(size - 20));
        Bytes output(std::max(size + 8, size_t(256)) + 2, 0xa5);
        const auto count = EncryptDataInto(key, prefix, packet.data(), packet.size(), output.data() + 1, output.size() - 2);
        Require(count >= size + 8 && output.front() == 0xa5 && output.back() == 0xa5, "stream block output bounds");
        Require(DecryptData(key, prefix, output.data() + 1, count, plain) && plain == packet, "stream block boundary roundtrip");
    }
    Bytes direct(258, 0xa5);
    const auto written = EncryptDataInto(key, prefix, original.data(), original.size(), direct.data() + 1, 256);
    Require(written >= 96 && written <= 256 && direct.front() == 0xa5 && direct.back() == 0xa5, "direct encryption bounds");
    Require(DecryptData(key, prefix, direct.data() + 1, written, plain) && plain == original, "direct encryption roundtrip");
    direct.assign(258, 0xa5);
    Require(!EncryptDataInto(key, prefix, original.data(), original.size(), direct.data() + 1, 8), "short output accepted");
    Require(std::all_of(direct.begin(), direct.end(), [](uint8_t value) { return value == 0xa5; }), "short output modified");
    auto translated = original;
    Require(TranslateAddress(translated.data(), translated.size(), 0xc0000201, 0x0ac80002, true), "source translation");
    Require(Sum(translated.data(), 20) == 0, "translated IP checksum");
    Bytes pseudo(translated.begin() + 12, translated.begin() + 20); pseudo.push_back(0); pseudo.push_back(17); Put16(pseudo, 9); pseudo.insert(pseudo.end(), translated.begin() + 20, translated.end());
    Require(Sum(pseudo.data(), pseudo.size()) == 0, "translated UDP checksum");
    Require(TranslateAddress(translated.data(), translated.size(), 0x0ac80002, 0xc0000201, true) && translated == original, "reverse translation");
    translated = original; Set16(translated, 26, 0); Require(TranslateAddress(translated.data(), translated.size(), 0xc0000201, 0x0ac80002, true) && Get16(translated.data() + 26) == 0, "zero UDP checksum changed");
    auto bad = original; bad[0] = 0x4f; size_t length = 0; bool keepalive = false;
    Require(!ValidateInner(bad.data(), bad.size(), length, keepalive), "truncated IP options");
    bad = original; Set16(bad, 24, 8); Require(!ValidateInner(bad.data(), bad.size(), length, keepalive), "inconsistent UDP length");
    bad = original; Set16(bad, 6, 0x2000); Require(!ValidateInner(bad.data(), bad.size(), length, keepalive), "unaligned fragment accepted");
    Bytes oversized(MaxInner + 1, 0); oversized[0] = 0x60;
    Require(!EncryptData(key, prefix, oversized.data(), oversized.size(), encrypted), "oversized keepalive accepted");
}
void Fragments() {
    auto packet = Udp(); packet.resize(65535);
    for (size_t i = 29; i < packet.size(); ++i) packet[i] = uint8_t(i);
    Set16(packet, 2, uint16_t(packet.size())); Set16(packet, 24, uint16_t(packet.size() - 20)); Set16(packet, 26, 0);
    Set16(packet, 10, 0); Set16(packet, 10, Sum(packet.data(), 20));
    std::vector<Bytes> fragments; Bytes icmp, complete;
    Require(FragmentInner(packet.data(), packet.size(), fragments, icmp) && fragments.size() == 2 && icmp.empty(), "max IPv4 fragmentation");
    for (const auto& fragment : fragments) Require(fragment.size() <= MaxInner && Sum(fragment.data(), 20) == 0, "fragment size/checksum");
    Ipv4Reassembler assembler;
    Require(assembler.Add(fragments[1].data(), fragments[1].size(), complete) == Ipv4Reassembler::Result::Waiting, "out of order final fragment");
    Require(assembler.Add(fragments[0].data(), fragments[0].size(), complete) == Ipv4Reassembler::Result::Complete && complete == packet, "fragment reassembly");
    Require(assembler.Add(fragments[0].data(), fragments[0].size(), complete) == Ipv4Reassembler::Result::Waiting, "overlap start");
    Require(assembler.Add(fragments[0].data(), fragments[0].size(), complete) == Ipv4Reassembler::Result::Rejected, "duplicate fragment accepted");
    Require(assembler.Add(fragments[1].data(), fragments[1].size(), complete) == Ipv4Reassembler::Result::Rejected, "overlap tombstone lost");
    assembler.Clear();
    auto other = packet; other.back() ^= 0x5a;
    std::vector<Bytes> otherFragments;
    Require(FragmentInner(other.data(), other.size(), otherFragments, icmp), "second session fragments");
    const std::string firstSession("server\0session1", 15), secondSession("server\0session2", 15);
    Require(assembler.Add(fragments[0].data(), fragments[0].size(), complete, firstSession) == Ipv4Reassembler::Result::Waiting, "first namespace initial");
    Require(assembler.Add(otherFragments[1].data(), otherFragments[1].size(), complete, secondSession) == Ipv4Reassembler::Result::Waiting, "cross-session fragment collision");
    Require(assembler.Add(fragments[1].data(), fragments[1].size(), complete, firstSession) == Ipv4Reassembler::Result::Complete && complete == packet, "first namespace completion");
    Require(assembler.Add(otherFragments[0].data(), otherFragments[0].size(), complete, secondSession) == Ipv4Reassembler::Result::Complete && complete == other, "second namespace completion");
    assembler.Clear();
    Set16(packet, 6, 0x4000);
    Require(FragmentInner(packet.data(), packet.size(), fragments, icmp) && fragments.empty() && !icmp.empty(), "DF ICMP missing");
    Require(icmp[20] == 3 && icmp[21] == 4 && Get16(icmp.data() + 26) == MaxInner && Sum(icmp.data(), 20) == 0 && Sum(icmp.data() + 20, icmp.size() - 20) == 0, "DF ICMP fields/checksum");
    auto reserved = Udp(); Set16(reserved, 6, 0x8000);
    Require(assembler.Add(reserved.data(), reserved.size(), complete) == Ipv4Reassembler::Result::Rejected, "reserved IP flag accepted");
    Require(!FragmentInner(reserved.data(), reserved.size(), fragments, icmp), "reserved fragment flag accepted");
    Set16(reserved, 6, 0x6000);
    Require(!FragmentInner(reserved.data(), reserved.size(), fragments, icmp), "contradictory DF/MF accepted");
    packet = Udp(); packet.insert(packet.begin() + 20, {0x82, 4, 0, 0, 0x02, 4, 0, 0}); packet[0] = 0x47; packet.resize(65535);
    Set16(packet, 2, 65535); Set16(packet, 32, uint16_t(packet.size() - 28)); Set16(packet, 34, 0); Set16(packet, 10, 0); Set16(packet, 10, Sum(packet.data(), 28));
    Require(FragmentInner(packet.data(), packet.size(), fragments, icmp) && fragments.size() == 2, "IP option fragmentation");
    Require((fragments[0][0] & 15) == 7 && (fragments[1][0] & 15) == 6 && fragments[1][20] == 0x82, "copy-bit IP options");
    Require(assembler.Add(fragments[0].data(), fragments[0].size(), complete) == Ipv4Reassembler::Result::Waiting, "option initial fragment");
    Require(assembler.Add(fragments[1].data(), fragments[1].size(), complete) == Ipv4Reassembler::Result::Complete && complete == packet, "option fragment roundtrip");
}

}
int main() {
    try { Require(Initialize(), "sodium init"); Invitations(); Cryptography(); Replay(); Packets(); TcpPackets(); Fragments(); std::cout << "Protocol v2 independent review tests passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
