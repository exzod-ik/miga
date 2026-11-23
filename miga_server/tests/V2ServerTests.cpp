#include "../src/V2Server.cpp"
#include <cassert>
#include <cstdlib>

namespace miga::v2
{
struct V2ServerTests
{
    struct Client
    {
        int control = -1, data = -1;
        sockaddr_in server{};
        Invitation invitation;
        Id request{};
        OpenReply parameters;
        Key hash{};
        SessionKeys keys;
        uint64_t counter = 0;
        Bytes hello;
        NoiseHandshake noise;
        Client(const Invitation &value, uint16_t port) : invitation(value)
        {
            control = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            data = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            sockaddr_in local{};
            local.sin_family = AF_INET;
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            assert(control >= 0 && data >= 0 &&
                   bind(control, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0 &&
                   bind(data, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0);
            server.sin_family = AF_INET;
            server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            server.sin_port = htons(port);
        }
        ~Client()
        {
            close(control);
            close(data);
        }
        bool Receive(Bytes &response, int milliseconds = 1000)
        {
            pollfd pending{control, POLLIN, 0};
            if (poll(&pending, 1, milliseconds) <= 0)
                return false;
            response.resize(65536);
            const auto count = recv(control, response.data(), response.size(), 0);
            if (count <= 0)
                return false;
            response.resize(static_cast<size_t>(count));
            return true;
        }
        bool Start(bool validSecret = true)
        {
            assert(noise.Start(true, invitation.serverKey));
            Bytes addresses{1};
            Put32(addresses, 0xc0a80102);
            Hello value;
            value.client = invitation.clientId;
            value.time = static_cast<uint64_t>(std::time(nullptr));
            assert(noise.Write(addresses, value.noise));
            Random(request.data(), request.size());
            value.proof = HelloProof(invitation.clientSecret, value.client, value.time, request, invitation.serverKey,
                                     value.noise);
            if (!validSecret)
                value.proof[0] ^= 1;
            Message message;
            message.operation = Operation::Hello;
            message.request = request;
            message.body = EncodeHello(value);
            hello = Seal(EnvelopeKey(invitation.serverSecret), EncodeMessage(message));
            return Send(control, server, hello);
        }
        bool Complete()
        {
            Bytes response, plaintext, payload;
            Message message;
            if (!Receive(response) ||
                !Unseal(EnvelopeKey(invitation.serverSecret), response.data(), response.size(), plaintext) ||
                !DecodeMessage(plaintext, message) || message.operation != Operation::HelloReply ||
                message.request != request || !noise.Read(message.body, payload) || !noise.Complete() ||
                !noise.Hash(hash) || !DecodeOpenReply(payload, parameters))
                return false;
            keys = DeriveSession(parameters.secret, hash, invitation.clientId, parameters.session);
            return true;
        }
        Bytes Control(Operation operation, const Bytes &body, Id *id = nullptr)
        {
            Message message;
            message.operation = operation;
            message.body = body;
            Random(message.request.data(), message.request.size());
            if (id)
                message.request = *id;
            return SealControl(EnvelopeKey(invitation.serverSecret), keys.controlC2S, parameters.session, ++counter,
                               message);
        }
        bool Reply(Operation expected, Message &message)
        {
            Bytes response;
            Id session{};
            uint64_t value = 0;
            return Receive(response) &&
                   UnsealControl(EnvelopeKey(invitation.serverSecret), keys.controlS2C, response.data(),
                                 response.size(), session, value, message) &&
                   session == parameters.session && message.operation == expected;
        }
        bool Bind(bool loseReady = false)
        {
            sockaddr_in destination = server;
            destination.sin_port = htons(parameters.port);
            const auto message =
                Control(Operation::Bind, Bytes(parameters.challenge.begin(), parameters.challenge.end()));
            if (!Send(data, destination, message))
                return false;
            if (loseReady)
            {
                Bytes lost;
                return Receive(lost);
            }
            Message ready;
            return Reply(Operation::Ready, ready) && ready.body.size() == 16 && Get64(ready.body.data() + 8) >= 1;
        }
        bool SendData(uint32_t source, int descriptor = -1)
        {
            Bytes packet(28, 0);
            packet[0] = 0x45;
            packet[3] = 28;
            packet[8] = 64;
            packet[9] = 17;
            packet[12] = uint8_t(source >> 24);
            packet[13] = uint8_t(source >> 16);
            packet[14] = uint8_t(source >> 8);
            packet[15] = uint8_t(source);
            packet[16] = 8;
            packet[17] = 8;
            packet[18] = 8;
            packet[19] = 8;
            packet[20] = 0x12;
            packet[21] = 0x34;
            packet[23] = 53;
            packet[25] = 8;
            Bytes encrypted;
            if (!EncryptData(keys.dataC2S, keys.prefixC2S, packet.data(), packet.size(), encrypted))
                return false;
            sockaddr_in destination = server;
            destination.sin_port = htons(parameters.port);
            return Send(descriptor < 0 ? data : descriptor, destination, encrypted);
        }
        bool ReceiveData(uint32_t destination)
        {
            pollfd ready{data, POLLIN, 0};
            if (poll(&ready, 1, 1000) <= 0)
                return false;
            std::array<uint8_t, 65536> buffer{};
            const auto size = recv(data, buffer.data(), buffer.size(), 0);
            Bytes plaintext;
            return size > 0 &&
                   DecryptData(keys.dataS2C, keys.prefixS2C, buffer.data(), static_cast<size_t>(size), plaintext) &&
                   plaintext.size() == 28 && Get32(plaintext.data() + 16) == destination;
        }
    };

    static void Run()
    {
        assert(miga::v2::Initialize());
        char temporary[] = "/tmp/miga-v2-runtime-XXXXXX";
        const auto *directory = mkdtemp(temporary);
        assert(directory);
        const std::string path = directory;
        const auto priorPath = std::getenv("PATH");
        const std::string original = priorPath ? priorPath : "";
        for (const auto *name : {"iptables", "conntrack"})
        {
            const auto command = path + "/" + name;
            std::ofstream file(command);
            file << "#!/bin/sh\nexit 0\n";
            file.close();
            assert(chmod(command.c_str(), 0700) == 0);
        }
        assert(setenv("PATH", (path + ":" + original).c_str(), 1) == 0);
        int tun[2];
        assert(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, tun) == 0);
        ClientRecord record;
        Random(record.id.data(), record.id.size());
        Random(record.secret.data(), record.secret.size());
        record.name = "isolated";
        record.maxConnections = 1;
        ClientRecord secondRecord;
        Random(secondRecord.id.data(), secondRecord.id.size());
        Random(secondRecord.secret.data(), secondRecord.secret.size());
        secondRecord.name = "second";
        secondRecord.maxConnections = 0;
        Invitation invitation;
        invitation.host = "127.0.0.1";
        invitation.clientId = record.id;
        invitation.clientSecret = record.secret;
        Key privateKey;
        assert(NoiseHandshake::GenerateKeypair(privateKey, invitation.serverKey));
        Random(invitation.serverSecret.data(), invitation.serverSecret.size());
        uint16_t controlPort = 0;
        sockaddr_in originalPeer{};
        Bytes replay;
        {
            V2Server server;
            auto &impl = *server.impl_;
            impl.directory = path;
            impl.firewall = true;
            impl.subnet = 0x0a400000;
            impl.tun = tun[0];
            impl.maxSessions = 2;
            assert(impl.diagnostics.Configure({{"port", 0}}) && impl.diagnostics.Start());
            for (int i = 0; i < 100 && impl.diagnostics.Authorize(1).empty(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            impl.diagnostics.Revoke(1);
            impl.publicKey = invitation.serverKey;
            impl.privateKey = privateKey;
            impl.shared = invitation.serverSecret;
            impl.envelope = EnvelopeKey(impl.shared);
            impl.schedule = ScheduleKey(impl.shared);
            assert(impl.store.Open(path + "/clients.sqlite3") && impl.store.Add(record) &&
                   impl.store.Add(secondRecord));
            controlPort = DailyPort(impl.schedule, static_cast<uint64_t>(std::time(nullptr)) / 86400, 10000, 15000);
            const int listener = BindPort(controlPort);
            assert(listener >= 0);
            impl.controls[controlPort] = listener;
            impl.Maintain();
            assert(impl.controls.count(impl.portStart) == 1);
            std::atomic<bool> running{true};
            std::thread thread([&] { impl.Run(running); });

            Client pinger(Invitation{}, impl.portStart);
            Bytes request(24, 0);
            std::memcpy(request.data(), "MIGAPNG1", 8);
            Random(request.data() + 8, 16);
            Bytes reply;
            assert(Send(pinger.control, pinger.server, request) && pinger.Receive(reply));
            assert(reply.size() == request.size() && std::memcmp(reply.data(), "MIGAPNG2", 8) == 0 &&
                   std::equal(reply.begin() + 8, reply.end(), request.begin() + 8));
            assert(Send(pinger.control, pinger.server, reply) && !pinger.Receive(reply, 100));
            request.pop_back();
            assert(Send(pinger.control, pinger.server, request) && !pinger.Receive(reply, 100));

            Client wrong(invitation, controlPort);
            assert(wrong.Start(false));
            Bytes response;
            assert(!wrong.Receive(response, 150));
            Client client(invitation, controlPort);
            assert(client.Start() && client.Complete());
            replay = client.hello;
            socklen_t originalPeerLength = sizeof(originalPeer);
            assert(getsockname(client.control, reinterpret_cast<sockaddr *>(&originalPeer), &originalPeerLength) == 0);
            assert(client.parameters.addresses.size() == 1 && client.parameters.addresses[0].first == 0xc0a80102);
            assert(client.Bind(true));
            const auto recoverReady = client.Control(Operation::Status, {});
            assert(Send(client.control, client.server, recoverReady));
            Message recovered;
            assert(client.Reply(Operation::Ready, recovered) && recovered.body.size() == 16);
            assert(Get64(recovered.body.data() + 8) & DataProbeCapability);
            Id probeToken{};
            Random(probeToken.data(), probeToken.size());
            Bytes probe;
            assert(EncryptDataProbe(client.keys.dataC2S, client.keys.prefixC2S, probeToken, false, probe));
            auto dataPeer = client.server;
            dataPeer.sin_port = htons(client.parameters.port);
            assert(Send(client.data, dataPeer, probe));
            pollfd probeReady{client.data, POLLIN, 0};
            assert(poll(&probeReady, 1, 1000) == 1);
            std::array<uint8_t, 256> probeReply{};
            sockaddr_in replyPeer{};
            socklen_t replyPeerLength = sizeof(replyPeer);
            const auto probeSize = recvfrom(client.data, probeReply.data(), probeReply.size(), 0,
                reinterpret_cast<sockaddr*>(&replyPeer), &replyPeerLength);
            assert(probeSize > 0 && SamePeer(dataPeer, replyPeer));
            Bytes probePlaintext;
            Id receivedToken{};
            assert(DecryptData(client.keys.dataS2C, client.keys.prefixS2C, probeReply.data(), probeSize, probePlaintext));
            assert(ReadDataProbe(client.keys.dataS2C, probePlaintext, true, receivedToken) && receivedToken == probeToken);
            probePlaintext.back() ^= 1;
            assert(!ReadDataProbe(client.keys.dataS2C, probePlaintext, true, receivedToken));
            const auto diagnosticRequest = client.Control(Operation::DiagnosticOpen, {});
            assert(Send(client.control, client.server, diagnosticRequest));
            Message diagnosticReply;
            assert(client.Reply(Operation::DiagnosticReply, diagnosticReply) && diagnosticReply.body.size() == 66);
            assert(Get16(diagnosticReply.body.data()) != 0);
            const auto diagnosticParameters = diagnosticReply.body;
            assert(Send(client.control, client.server, diagnosticRequest));
            assert(client.Reply(Operation::DiagnosticReply, diagnosticReply) && diagnosticReply.body == diagnosticParameters);
            const auto snapshot = std::atomic_load(&impl.dataSnapshot);
            assert(snapshot->sockets.size() == 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(1100));
            assert(std::atomic_load(&impl.dataSnapshot) == snapshot);
            int receiveBuffer = 0;
            socklen_t receiveLength = sizeof(receiveBuffer);
            assert(getsockopt(snapshot->sockets[0]->fd, SOL_SOCKET, SO_RCVBUF, &receiveBuffer, &receiveLength) == 0);
            assert(receiveBuffer >= 8 * 1024 * 1024);
            std::cout << "session_receive_buffer_bytes=" << receiveBuffer << std::endl;
            assert(Send(client.control, client.server, replay));
            assert(client.Receive(response));
            Client limited(invitation, controlPort);
            assert(limited.Start());
            assert(!limited.Receive(response, 150));
            const uint32_t virtualIp = client.parameters.addresses[0].second;
            {
                std::lock_guard lock(impl.diagnostics.mutex_);
                impl.diagnostics.client_ = snapshot->sockets[0]->diagnosticIdentity;
            }
            impl.diagnostics.active.store(true);
            assert(impl.diagnostics.Command({{"command", "watch"}, {"protocol", 17}, {"local_port", 0x1234},
                {"remote_port", 53}, {"remote_ip", "8.8.8.8"}})["ok"] == true);
            assert(client.SendData(virtualIp));
            pollfd ready{tun[1], POLLIN, 0};
            assert(poll(&ready, 1, 1000) > 0);
            std::array<uint8_t, 65536> inner{};
            assert(recv(tun[1], inner.data(), inner.size(), 0) == 28 && Get32(inner.data() + 12) == virtualIp);
            assert(client.SendData(virtualIp + 100));
            assert(poll(&ready, 1, 150) == 0);
            assert(client.SendData(virtualIp, client.control));
            assert(poll(&ready, 1, 150) == 0);
            Invitation secondInvitation = invitation;
            secondInvitation.clientId = secondRecord.id;
            secondInvitation.clientSecret = secondRecord.secret;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            Client other(secondInvitation, controlPort);
            assert(other.Start() && other.Complete() && other.Bind());
            const auto otherVirtual = other.parameters.addresses[0].second;
            assert(otherVirtual != virtualIp);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            Client full(secondInvitation, controlPort);
            assert(full.Start() && !full.Receive(response, 150));
            assert(other.SendData(virtualIp));
            assert(poll(&ready, 1, 150) == 0);
            assert(other.SendData(otherVirtual));
            assert(poll(&ready, 1, 1000) > 0);
            assert(recv(tun[1], inner.data(), inner.size(), 0) == 28 && Get32(inner.data() + 12) == otherVirtual);
            auto respond = [&](uint32_t destination) {
                Bytes packet(28, 0);
                packet[0] = 0x45;
                packet[3] = 28;
                packet[8] = 64;
                packet[9] = 17;
                packet[12] = 8;
                packet[13] = 8;
                packet[14] = 8;
                packet[15] = 8;
                packet[16] = uint8_t(destination >> 24);
                packet[17] = uint8_t(destination >> 16);
                packet[18] = uint8_t(destination >> 8);
                packet[19] = uint8_t(destination);
                packet[21] = 53;
                packet[22] = 0x12;
                packet[23] = 0x34;
                packet[25] = 8;
                return send(tun[1], packet.data(), packet.size(), 0) == static_cast<ssize_t>(packet.size());
            };
            assert(respond(virtualIp) && client.ReceiveData(virtualIp));
            {
                const auto watched = impl.diagnostics.Command({{"command", "stats"}})["watches"][0];
                assert(watched["received"] == 1 && watched["tun_written"] == 1 && watched["tun_response"] == 1);
            }
            pollfd wrongOwner{other.data, POLLIN, 0};
            assert(poll(&wrongOwner, 1, 150) == 0);
            assert(respond(otherVirtual) && other.ReceiveData(otherVirtual));
            wrongOwner.fd = client.data;
            assert(poll(&wrongOwner, 1, 150) == 0);
            Bytes add;
            Put32(add, 0xc0a80103);
            const auto addRequest = client.Control(Operation::AddAddress, add);
            assert(Send(client.control, client.server, addRequest));
            Message mapped;
            assert(client.Reply(Operation::AddressReply, mapped) && mapped.body.size() == 8 &&
                   Get32(mapped.body.data()) == 0xc0a80103);
            const auto secondAddress = Get32(mapped.body.data() + 4);
            assert(Send(client.control, client.server, addRequest));
            assert(client.Reply(Operation::AddressReply, mapped) && Get32(mapped.body.data() + 4) == secondAddress);
            const auto status = client.Control(Operation::Status, {});
            assert(Send(client.control, client.server, status));
            Message health;
            assert(client.Reply(Operation::Ready, health) && health.body.size() == 16 &&
                   Get64(health.body.data()) == 1);
            Bytes resume(client.keys.resume.begin(), client.keys.resume.end());
            resume.push_back(0);
            const auto restore = client.Control(Operation::Resume, resume);
            assert(Send(client.control, client.server, restore));
            Message resumed;
            assert(client.Reply(Operation::OpenReply, resumed));
            OpenReply replacement;
            assert(DecodeOpenReply(resumed.body, replacement) && replacement.addresses.size() == 2 &&
                   replacement.port != client.parameters.port);
            const auto oldPort = client.parameters.port;
            client.parameters = replacement;
            client.keys = DeriveSession(replacement.secret, client.hash, invitation.clientId, replacement.session);
            client.counter = 0;
            assert(client.Bind() && client.SendData(virtualIp));
            assert(poll(&ready, 1, 1000) > 0);
            assert(recv(tun[1], inner.data(), inner.size(), 0) == 28);
            sockaddr_in old = client.server;
            old.sin_port = htons(oldPort);
            assert(Send(client.data, old, replay));
            assert(poll(&ready, 1, 150) == 0);
            running = false;
            thread.join();
            assert(impl.AdminCommand(
                           Json{{"scope", "client"}, {"operation", "disconnect"}, {"id", Base64(record.id.data(), 16)}})
                       .value("ok", false));
            assert(impl.sessions.size() == 1);
            assert(std::atomic_load(&impl.dataSnapshot)->routes.count(virtualIp) == 0);
        }
        close(tun[1]);
        {
            ClientStore store;
            assert(store.Open(path + "/clients.sqlite3"));
            std::vector<uint32_t> addresses;
            std::vector<uint16_t> ports;
            assert(store.ReservedAddresses(addresses) && addresses.size() == 3 && store.ReservedPorts(ports) &&
                   ports.size() == 3);
        }
        int restartedTun[2];
        assert(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, restartedTun) == 0);
        {
            V2Server server;
            auto &impl = *server.impl_;
            impl.directory = path;
            impl.firewall = true;
            impl.subnet = 0x0a400000;
            impl.tun = restartedTun[0];
            impl.maxSessions = 2;
            assert(impl.diagnostics.Configure({{"port", 0}}) && impl.diagnostics.Start());
            for (int i = 0; i < 100 && impl.diagnostics.Authorize(1).empty(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            impl.diagnostics.Revoke(1);
            impl.publicKey = invitation.serverKey;
            impl.privateKey = privateKey;
            impl.shared = invitation.serverSecret;
            impl.envelope = EnvelopeKey(impl.shared);
            impl.schedule = ScheduleKey(impl.shared);
            assert(impl.store.Open(path + "/clients.sqlite3"));
            std::vector<uint32_t> reserved;
            assert(impl.store.ReservedAddresses(reserved));
            for (const auto address : reserved)
                impl.allocated.insert(address);
            const int listener = BindPort(controlPort);
            assert(listener >= 0);
            impl.controls[controlPort] = listener;
            impl.Maintain();
            const int recorded = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            assert(recorded >= 0);
            assert(bind(recorded, reinterpret_cast<sockaddr *>(&originalPeer), sizeof(originalPeer)) == 0);
            sockaddr_in serverPeer{};
            serverPeer.sin_family = AF_INET;
            serverPeer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            serverPeer.sin_port = htons(controlPort);
            std::atomic<bool> running{true};
            std::thread thread([&] { impl.Run(running); });
            assert(Send(recorded, serverPeer, replay));
            pollfd answer{recorded, POLLIN, 0};
            assert(poll(&answer, 1, 150) == 0);
            Client fresh(invitation, controlPort);
            assert(fresh.Start() && fresh.Complete() && fresh.Bind());
            assert(fresh.parameters.addresses[0].second >= 0x0a400005);
            running = false;
            thread.join();
            close(recorded);
            assert(impl.AdminCommand(
                           Json{{"scope", "client"}, {"operation", "revoke"}, {"id", Base64(record.id.data(), 16)}})
                       .value("ok", false));
            assert(impl.sessions.empty());
            const auto revoked = std::atomic_load(&impl.dataSnapshot);
            assert(revoked->sockets.empty() && revoked->routes.empty());
            impl.Maintain();
            assert(std::atomic_load(&impl.dataSnapshot) == revoked);
            const auto before = impl.firstReplies.size();
            impl.Control(listener, serverPeer, fresh.hello.data(), fresh.hello.size());
            assert(impl.firstReplies.size() == before && impl.sessions.empty());

            ClientRecord entry;
            entry.name = std::string(256, '\x01');
            for (unsigned i = 0; i < 150; ++i)
            {
                entry.id.back() = static_cast<uint8_t>(i);
                assert(impl.store.Add(entry));
            }
            assert(impl.store.Revoke(entry.id));
            Json list{{"scope", "client"}, {"operation", "list"}};
            std::set<std::string> listed;
            size_t pages = 0;
            for (;;)
            {
                const auto page = impl.AdminCommand(list);
                assert(page.dump().size() < AdminResponseLimit && page["clients"].size() <= ClientPageSize);
                for (const auto &row : page["clients"])
                    assert(listed.insert(row.at("id").get<std::string>()).second && row["sessions"] == 0);
                ++pages;
                if (page["next"].is_null())
                    break;
                assert(pages < 3);
                list["after"] = page["next"];
            }
            assert(pages == 3 && listed.size() == 150);
            assert(listed.count(Base64(record.id.data(), record.id.size())) == 0);
            assert(listed.count(Base64(entry.id.data(), entry.id.size())) == 0);
            list["after"] = "invalid";
            assert(impl.AdminCommand(list)["error"] == "invalid_cursor");

            impl.adminPath = path + "/admin.sock";
            impl.admin = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            sockaddr_un endpoint{};
            endpoint.sun_family = AF_UNIX;
            assert(impl.admin >= 0 && impl.adminPath.size() < sizeof(endpoint.sun_path));
            std::strcpy(endpoint.sun_path, impl.adminPath.c_str());
            assert(bind(impl.admin, reinterpret_cast<const sockaddr *>(&endpoint), sizeof(endpoint)) == 0);
            assert(listen(impl.admin, 8) == 0);
            const auto configPath = path + "/test-config.json";
            std::ofstream(configPath) << Json{{"protocol", 2}, {"state_directory", path}};
            impl.logger.setLevel(LOGGER_LEVEL_NONE);
            running = true;
            std::thread adminThread([&] { impl.Run(running); });
            const auto listCommand = [&](bool singlePage) {
                std::array<std::string, 5> arguments{"miga-server", "client", "list", "--json", "--page"};
                std::array<char *, 5> raw{};
                for (size_t i = 0; i < arguments.size(); ++i)
                    raw[i] = arguments[i].data();
                std::ostringstream response;
                auto *output = std::cout.rdbuf(response.rdbuf());
                const auto status = V2Server::Admin(singlePage ? 5 : 4, raw.data(), configPath);
                std::cout.rdbuf(output);
                assert(status == 0);
                return Json::parse(response.str());
            };
            const auto all = listCommand(false);
            assert(all.is_array() && all.size() == listed.size() && all.dump().size() > 200 * 1024);
            const auto first = listCommand(true);
            assert(first.at("clients").size() == ClientPageSize && first.at("next").is_string());
            running = false;
            adminThread.join();
            assert(unlink(configPath.c_str()) == 0);
        }
        close(restartedTun[1]);
        assert(setenv("PATH", original.c_str(), 1) == 0);
        for (const auto *name : {"iptables", "conntrack", "clients.sqlite3"})
            assert(unlink((path + "/" + name).c_str()) == 0);
        assert(rmdir(path.c_str()) == 0);
        const auto commandStarted = Clock::now();
        assert(!RunCommand({"sh", "-c", "sleep 20"}));
        const auto elapsed = std::chrono::duration<double>(Clock::now() - commandStarted).count();
        assert(elapsed >= 4.5 && elapsed < 7);
        std::string blocked;
        const auto retryStarted = Clock::now();
        assert(!Capture({"sh", "-c", "printf unexpected"}, blocked));
        assert(Clock::now() - retryStarted < std::chrono::milliseconds(100));
        std::cout << "v2_server_isolated_tests_passed" << std::endl;
    }
};
}

int main()
{
    miga::v2::V2ServerTests::Run();
}
