#include "DiagnosticControl.h"
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/ssl.h>
#include <unistd.h>
#include <chrono>
#include <csignal>

struct DiagnosticControlTests {
    static std::vector<uint8_t> Packet(uint16_t local, uint16_t remote, uint32_t source, uint32_t destination, bool response, uint8_t transaction) {
        std::vector<uint8_t> packet(48);
        packet[0] = 0x45; packet[3] = 48; packet[9] = 17;
        std::memcpy(packet.data() + 12, &source, 4); std::memcpy(packet.data() + 16, &destination, 4);
        packet[20] = uint8_t(local >> 8); packet[21] = uint8_t(local);
        packet[22] = uint8_t(remote >> 8); packet[23] = uint8_t(remote); packet[25] = 28;
        packet[28] = response ? 1 : 0; packet[29] = 1;
        packet[32] = 0x21; packet[33] = 0x12; packet[34] = 0xa4; packet[35] = 0x42;
        std::fill(packet.begin() + 36, packet.end(), transaction);
        return packet;
    }

    static void Run() {
        DiagnosticControl control;
        assert(control.Configure({{"port", 0}})); control.Stop(); control.Stop();
        const auto client = inet_addr("203.0.113.1"), remote = inet_addr("192.0.2.2");
        auto request = Packet(42000, 3478, inet_addr("192.0.2.1"), remote, false, 1);
        assert(control.Outbound(request.data(), request.size(), client) == 0);
        control.client_ = client; control.active.store(true);
        control.echo_ = {{"received", 0}, {"replied", 0}, {"sequences", DiagnosticControl::Json::array()}};
        auto watched = control.Command({{"command", "watch"}, {"protocol", 17}, {"local_port", 42000}, {"remote_port", 3478}, {"remote_ip", "192.0.2.2"}, {"transaction_id", "010101010101010101010101"}});
        assert(watched["ok"] == true);
        assert(control.Outbound(request.data(), 19, client) == 0);
        assert(control.Outbound(request.data(), request.size(), inet_addr("203.0.113.2")) == 0);
        request[36] = 2; assert(control.Outbound(request.data(), request.size(), client) == 0); request[36] = 1;
        const auto id = control.Outbound(request.data(), request.size(), client); assert(id != 0);
        control.TunMapped(id, 12345);
        auto response = Packet(3478, 12345, remote, inet_addr("192.0.2.1"), true, 1);
        response[36] = 2; control.Inbound(response.data(), response.size());
        assert(control.Command({{"command", "stats"}})["watches"][0]["tun_response"] == 0);
        response[36] = 1;
        const auto otherVirtual = inet_addr("192.0.2.9");
        std::memcpy(response.data() + 16, &otherVirtual, 4);
        control.Inbound(response.data(), response.size());
        assert(control.Command({{"command", "stats"}})["watches"][0]["tun_response"] == 0);
        const auto ownVirtual = inet_addr("192.0.2.1");
        std::memcpy(response.data() + 16, &ownVirtual, 4);
        control.Inbound(response.data(), response.size());
        control.TunWritten(id, true);
        auto stats = control.Command({{"command", "stats"}})["watches"][0];
        assert(stats["received"] == 1 && stats["tun_written"] == 1 && stats["tun_response"] == 1);
        auto sequenceWatch = control.Command({{"command", "watch"}, {"protocol", 17}, {"local_port", 42002}, {"remote_port", 35652}, {"remote_ip", "192.0.2.2"}, {"sequence16", true}})["watch_id"].get<uint64_t>();
        auto small = Packet(42002, 35652, inet_addr("192.0.2.1"), remote, false, 0);
        small.resize(30); small[3] = 30; small[25] = 10; small[28] = 0; small[29] = 0;
        for (int repeat = 0; repeat < 2; ++repeat) {
            assert(control.Outbound(small.data(), small.size(), client) == sequenceWatch);
            control.TunWritten(sequenceWatch, true, small.data(), small.size());
        }
        small[28] = 255; small[29] = 255;
        assert(control.Outbound(small.data(), small.size(), client) == sequenceWatch);
        control.TunWritten(sequenceWatch, false, small.data(), small.size());
        auto unique = control.Command({{"command", "stats"}})["watches"][1];
        assert(unique["received"] == 3 && unique["tun_written"] == 2);
        assert(unique["received_sequences"].size() == 2 && unique["written_sequences"].size() == 1);
        assert(unique["written_sequences"][0] == 0);
        small[0] = 0x4f;
        control.TunWritten(sequenceWatch, true, small.data(), small.size());
        assert(control.Command({{"command", "stats"}})["watches"][1]["written_sequences"].size() == 1);
        auto echo = Packet(42001, 47901, inet_addr("192.0.2.1"), inet_addr("198.18.0.1"), false, 0);
        std::fill(echo.begin() + 28, echo.end(), 0); echo[47] = 7;
        bool replied = false;
        assert(control.Echo(echo.data(), echo.size(), client, [&](uint8_t* bytes, size_t length) {
            replied = true; assert(length == 48 && bytes[47] == 7);
            assert(std::memcmp(bytes + 16, request.data() + 12, 4) == 0);
            return true;
        }));
        assert(replied);
        auto echoStats = control.Command({{"command", "stats"}})["echo"];
        assert(echoStats["received"] == 1 && echoStats["replied"] == 1);
        assert(echoStats["sequences"][0]["sequence"] == 7);
        assert(control.Command({{"command", "watch"}, {"protocol", 6}, {"local_port", 43000}, {"remote_port", 443}, {"remote_ip", "192.0.2.2"}})["ok"] == true);
        auto tcp = Packet(43000, 443, inet_addr("192.0.2.1"), remote, false, 0);
        tcp.resize(40); tcp[3] = 40; tcp[9] = 6; tcp[32] = 0x50; tcp[33] = 2;
        std::fill(tcp.begin() + 24, tcp.begin() + 28, 0xff); tcp[27] = 0xfe;
        const auto tcpId = control.Outbound(tcp.data(), tcp.size(), client); assert(tcpId);
        control.TunMapped(tcpId, 12345); control.TunWritten(tcpId, true);
        auto tcpResponse = tcp;
        std::memcpy(tcpResponse.data() + 12, &remote, 4);
        std::memcpy(tcpResponse.data() + 16, &ownVirtual, 4);
        tcpResponse[20] = 1; tcpResponse[21] = 0xbb; tcpResponse[22] = 0x30; tcpResponse[23] = 0x39;
        std::fill(tcpResponse.begin() + 28, tcpResponse.begin() + 32, 0xff); tcpResponse[31] = 0xfd; tcpResponse[33] = 0x12;
        control.Inbound(tcpResponse.data(), tcpResponse.size());
        assert(control.Command({{"command", "stats"}})["watches"][2]["tun_response"] == 0);
        tcpResponse[31] = 0xff; control.Inbound(tcpResponse.data(), tcpResponse.size());
        assert(control.Command({{"command", "stats"}})["watches"][2]["tun_response"] == 1);
        control.Inbound(response.data(), response.size());
        assert(control.Command({{"command", "stats"}})["watches"][0]["tun_response"] == 2);
        control.Command({{"command", "end"}});
        assert(control.Outbound(request.data(), request.size(), client) == 0);
    }

    using Json = DiagnosticControl::Json;
    static void Network() {
        const int receiver = socket(AF_INET, SOCK_DGRAM, 0);
        const int sender = socket(AF_INET, SOCK_DGRAM, 0);
        assert(receiver >= 0 && sender >= 0);
        const int buffer = 4096;
        assert(setsockopt(receiver, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)) == 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        assert(bind(receiver, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        socklen_t length = sizeof(address);
        assert(getsockname(receiver, reinterpret_cast<sockaddr*>(&address), &length) == 0);

        DiagnosticControl control;
        control.SetNetworkSource([&](uint32_t identity) -> std::shared_ptr<const int> {
            assert(identity == 42);
            return std::make_shared<const int>(receiver);
        }, [] { return htonl(INADDR_LOOPBACK); });
        control.client_ = 42;
        control.networkBefore_ = control.CaptureNetwork();
        control.active.store(true);
        const Json command = {{"command", "network_stats"}};
        assert(control.Command(command)["network"]["delta"]["socket/drops"] == 0);
        std::array<uint8_t, 512> payload{};
        for (int i = 0; i < 128; ++i) {
            assert(sendto(sender, payload.data(), payload.size(), 0,
                          reinterpret_cast<sockaddr*>(&address), sizeof(address)) ==
                   static_cast<ssize_t>(payload.size()));
        }
        assert(control.Command(command)["network"]["delta"]["socket/drops"].get<uint64_t>() > 0);
        close(sender);
        close(receiver);
    }

    static void Tls() {
        DiagnosticControl control;
        assert(control.Configure({{"port", 0}}));
        assert(control.Start());
        miga::v2::Bytes grant;
        for (int attempt = 0; attempt < 100 && grant.empty(); ++attempt) {
            grant = control.Authorize(42);
            if (grant.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        assert(grant.size() == 66);
        const auto port = miga::v2::Get16(grant.data());
        auto* context = SSL_CTX_new(TLS_client_method()); assert(context);
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
        auto exchange = [&](const miga::v2::Bytes& parameters, bool accepted, bool revoke) {
            auto socket = ::socket(AF_INET, SOCK_STREAM, 0); assert(socket >= 0);
            timeval timeout{3, 0}; setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
            assert(connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
            auto* tls = SSL_new(context); assert(tls); SSL_set_fd(tls, socket);
            assert(SSL_connect(tls) == 1);
            auto* certificate = SSL_get1_peer_certificate(tls);
            std::array<uint8_t, 32> digest{}; unsigned int size = 0;
            assert(certificate && X509_digest(certificate, EVP_sha256(), digest.data(), &size) == 1 && size == 32);
            assert(std::equal(digest.begin(), digest.end(), parameters.begin() + 2));
            X509_free(certificate);
            const auto ticket = miga::v2::Base64(parameters.data() + 34, 32);
            auto request = Json{{"command", "authorize"}, {"ticket", ticket}}.dump() + "\n";
            assert(SSL_write(tls, request.data(), static_cast<int>(request.size())) > 0);
            char buffer[256]{}; auto count = SSL_read(tls, buffer, sizeof(buffer));
            if (accepted) {
                assert(count > 0 && Json::parse(std::string(buffer, count))["ok"] == true);
                if (revoke) control.Revoke(42);
                request = "{\"command\":\"ping\"}\n";
                const auto written = SSL_write(tls, request.data(), static_cast<int>(request.size()));
                count = written > 0 ? SSL_read(tls, buffer, sizeof(buffer)) : -1;
                if (revoke) assert(count <= 0);
                else assert(count > 0 && Json::parse(std::string(buffer, count))["ok"] == true);
            } else assert(count <= 0);
            SSL_free(tls); close(socket);
        };
        auto invalid = grant; invalid[34] ^= 1;
        exchange(invalid, false, false);
        exchange(grant, true, false);
        exchange(grant, false, false);
        auto revoked = control.Authorize(42); assert(revoked.size() == 66);
        control.Revoke(42); exchange(revoked, false, false);
        auto expired = control.Authorize(42); assert(expired.size() == 66);
        {std::lock_guard lock(control.mutex_); control.grants_.at(42).expires = std::chrono::steady_clock::now();}
        exchange(expired, false, false);
        auto current = control.Authorize(42); assert(current.size() == 66);
        exchange(current, true, true);
        SSL_CTX_free(context);
        control.Stop(); control.Stop();
    }

};

int main() {
    std::signal(SIGPIPE, SIG_IGN);
    DiagnosticControlTests::Run();
    DiagnosticControlTests::Network();
    DiagnosticControlTests::Tls();
    std::cout << "diagnostic control tests passed\n";
}
