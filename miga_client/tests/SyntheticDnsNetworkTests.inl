    static void SyntheticDnsNetworkTests(Logger& logger, ConfigManager& source) {
        auto runtime = Fixture(logger, source);
        runtime->config->dnsResolverEnabled = true;
        runtime->config->dnsResolverReserveRange = true;
        runtime->config->servers[0].rules.processRules.clear();
        runtime->config->servers[1].rules.processRules.clear();
        runtime->config->Index();
        const auto resolver = uint32_t(0xc0a80001);
        const auto shared = uint32_t(0xcb007125);
        const auto directName = "example.com";
        const auto tunnelName = "example.net";

        WSADATA winsock{};
        assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
        SyntheticDnsResolverTestAccess::StartResolver(runtime->syntheticDns);
        const auto port = runtime->syntheticDns.Port();
        assert(port != 0);
        const auto readPacket = [](Packet& packet) {
            auto& bytes = *packet.bytes;
            Write16(bytes.data() + 2, static_cast<uint16_t>(bytes.size()));
            if (bytes[9] == 17) Write16(bytes.data() + 24, static_cast<uint16_t>(bytes.size() - 20));
            assert(packet.view.Read(bytes.data(), bytes.size()));
        };
        const auto dns = [&](std::span<const uint8_t> wire, const SocketTuple& tuple, bool outbound) {
            auto packet = MakePacket(false, tuple.localPort, tuple.remotePort);
            auto& bytes = *packet.bytes;
            bytes.resize(28);
            bytes.insert(bytes.end(), wire.begin(), wire.end());
            Write32(bytes.data() + 12, tuple.localIp);
            Write32(bytes.data() + 16, tuple.remoteIp);
            packet.address.Outbound = outbound;
            readPacket(packet);
            return packet;
        };
        const auto answer = [&](const std::vector<uint8_t>& query, uint32_t address, uint32_t ttl = 60) {
            const auto question = ParseSyntheticDnsQuestion(std::span<const uint8_t>(query).subspan(28));
            assert(question);
            const auto wire = BuildSyntheticDnsAnswer(*question, address, 0, ttl);
            return dns(wire, {17, Read32(query.data() + 16), 53, Read32(query.data() + 12),
                Read16(query.data() + 20)}, false);
        };
        const auto unwrap = [&](const std::vector<uint8_t>& outer, size_t serverId) {
            const auto& transport = runtime->config->ById(serverId)->transport;
            assert(Read32(outer.data() + 16) == ntohl(transport->destination));
            const auto state = transport->session->Snapshot();
            miga::v2::Bytes result;
            assert(miga::v2::DecryptData(state->keys.dataC2S, state->keys.prefixC2S,
                outer.data() + 28, outer.size() - 28, result));
            return result;
        };
        const auto fromServer = [&](Packet response, size_t serverId) {
            const auto& transport = runtime->config->ById(serverId)->transport;
            const auto state = transport->session->Snapshot();
            miga::v2::Bytes encrypted;
            const auto localIp = state->addresses.begin()->first;
            assert(miga::v2::EncryptData(state->keys.dataS2C, state->keys.prefixS2C,
                response.bytes->data(), response.bytes->size(), encrypted));
            TunnelDatagram wrapper;
            assert(wrapper.Build(encrypted.data(), encrypted.size(), transport->destination, htonl(localIp),
                state->port, transport->localPort, 1, 1500, [&](const uint8_t* data, size_t length, size_t count) {
                    assert(count == 1);
                    response.bytes = std::make_shared<std::vector<uint8_t>>(data, data + length);
                    Receive(*runtime, response);
                    return true;
                }));
            Pump(*runtime);
        };
        const auto receive = [&](Packet packet) {Receive(*runtime, packet); Pump(*runtime);};
        const auto observe = [&](const Packet& packet, uint64_t endpoint, const char* name) {
            runtime->directory.Observe(packet.view.tuple,
                std::make_shared<const SocketOwner>(SocketOwner{Identity(1200, name), endpoint, 100}), Clock::now());
        };
        const auto dnsAddress = [&](uint16_t id, uint16_t port = 53000, uint32_t ttl = 60) {
            const auto& result = submissions.back();
            PacketView view;
            DnsMessage message;
            assert(Read16(result.data() + 28) == id);
            assert(Read32(result.data() + 12) == resolver && Read16(result.data() + 22) == port);
            assert(view.Read(result.data(), result.size()) && message.Read(result.data(), view));
            assert(message.addresses.size() == 1 && message.addresses.front().second == ttl);
            const auto address = message.addresses.front().first;
            assert(SyntheticDnsStore::Contains(address));
            return address;
        };
        const auto learn = [&](const char* name, uint16_t id) {
            const auto wire = BuildSyntheticDnsQuery(name, 1, id);
            auto query = dns(wire, {17, 0xc0000201, 53000, resolver, 53}, true);
            if (id == 1000) observe(query, 100, "unrelated.exe");
            const auto before = submissions.size();
            receive(query);
            assert(submissions.size() == before + 3);
            const auto directQuery = submissions[before];
            const auto firstQuery = unwrap(submissions[before + 1], 1);
            const auto secondQuery = unwrap(submissions[before + 2], 2);
            receive(query);
            assert(submissions.size() == before + 3);
            fromServer(answer(secondQuery, shared), 2);
            receive(answer(directQuery, shared));
            assert(submissions.size() == before + 5);
            fromServer(answer(firstQuery, shared), 1);
            assert(submissions.size() == before + 5);
            return dnsAddress(id);
        };

        const auto directIp = learn(directName, 1000);
        auto before = submissions.size();
        const auto repeated = BuildSyntheticDnsQuery(directName, 1, 1002);
        receive(dns(repeated, {17, 0xc0000201, 53000, resolver, 53}, true));
        assert(submissions.size() == before + 3);
        receive(answer(submissions[before], shared));
        assert(submissions.size() == before + 4 && dnsAddress(1002) == directIp);

        auto direct = MakePacket(true, 53200);
        Write32(direct.bytes->data() + 16, directIp);
        readPacket(direct);
        observe(direct, 101, "unrelated.exe");
        before = submissions.size();
        receive(direct);
        assert(submissions.size() == before + 1);
        assert(Read32(submissions.back().data() + 16) == shared);
        const auto tcpReply = [&](uint16_t destinationPort, uint32_t localIp) {
            auto packet = MakePacket(true, 443, destinationPort);
            Write32(packet.bytes->data() + 12, shared);
            Write32(packet.bytes->data() + 16, localIp);
            (*packet.bytes)[33] = 0x12;
            packet.address.Outbound = 0;
            packet.address.Timestamp = 210;
            readPacket(packet);
            return packet;
        };
        auto directReply = tcpReply(53200, direct.view.tuple.localIp);
        assert(WinDivertHelperCalcChecksums(directReply.bytes->data(), static_cast<UINT>(directReply.bytes->size()), &directReply.address, 0));
        assert(directReply.address.IPChecksum && directReply.address.TCPChecksum);
        auto expectedReply = *directReply.bytes;
        Write32(expectedReply.data() + 12, directIp);
        assert(WinDivertHelperCalcChecksums(expectedReply.data(), static_cast<UINT>(expectedReply.size()), nullptr, 0));
        receive(directReply);
        assert(submissions.back() == expectedReply);
        assert(submissions.size() == before + 2);
        assert(Read32(submissions.back().data() + 12) == directIp);

        auto split = std::make_shared<Configuration>(*runtime->config);
        ++split->version;
        split->servers[0].rules.processRules = {"chrome.exe"};
        split->servers[1].rules.processRules = {"late.exe"};
        split->Index();
        runtime->config = split;
        runtime->published.store(split);
        before = submissions.size();
        auto tunnelDns = dns(BuildSyntheticDnsQuery(tunnelName, 1, 1001), {17, 0xc0000201, 53001, resolver, 53}, true);
        observe(tunnelDns, 110, "chrome.exe");
        receive(tunnelDns);
        assert(submissions.size() == before + 3);
        const auto firstQuery = unwrap(submissions[before], 1);
        const auto directQuery = submissions[before + 1];
        const auto lateQuery = unwrap(submissions[before + 2], 2);
        fromServer(answer(firstQuery, shared), 2);
        receive(answer(directQuery, 0xcb007180, 20));
        assert(submissions.size() == before + 3);
        fromServer(answer(firstQuery, shared, 120), 1);
        assert(submissions.size() == before + 4);
        const auto tunnelIp = dnsAddress(1001, 53001, 120);
        assert(directIp != tunnelIp);

        auto tunnel = MakePacket(true, 53201);
        Write32(tunnel.bytes->data() + 16, tunnelIp);
        readPacket(tunnel);
        observe(tunnel, 102, "chrome.exe");
        before = submissions.size();
        receive(tunnel);
        assert(submissions.size() == before + 1);
        const auto outgoing = unwrap(submissions.back(), 1);
        assert(Read32(outgoing.data() + 16) == shared && Read16(outgoing.data() + 20) == 53201);
        fromServer(tcpReply(53201, Read32(outgoing.data() + 12)), 1);
        assert(submissions.size() == before + 2);
        assert(Read32(submissions.back().data() + 12) == tunnelIp);
        receive(tunnel);
        assert(submissions.size() == before + 3);
        assert(Read32(unwrap(submissions.back(), 1).data() + 16) == shared);

        auto directSameName = MakePacket(true, 53206);
        Write32(directSameName.bytes->data() + 16, tunnelIp);
        readPacket(directSameName);
        observe(directSameName, 106, "unrelated.exe");
        receive(directSameName);
        assert(submissions.size() == before + 4 && Read32(submissions.back().data() + 16) == 0xcb007180);
        auto late = MakePacket(true, 53207);
        Write32(late.bytes->data() + 16, tunnelIp);
        readPacket(late);
        observe(late, 107, "late.exe");
        receive(late);
        assert(submissions.size() == before + 4);
        fromServer(answer(lateQuery, 0xcb007155), 2);
        assert(submissions.size() == before + 5 && Read32(unwrap(submissions.back(), 2).data() + 16) == 0xcb007155);

        const auto checkUdpChecksums = [](const std::vector<uint8_t>& datagram) {
            assert(datagram[9] == 17 && Read16(datagram.data() + 10) && Read16(datagram.data() + 26));
            auto recalculated = datagram;
            Write16(recalculated.data() + 10, 0);
            Write16(recalculated.data() + 26, 0);
            assert(WinDivertHelperCalcChecksums(recalculated.data(), static_cast<UINT>(recalculated.size()), nullptr, 0));
            assert(recalculated == datagram);
        };
        auto udp = MakePacket(false, 53205, 443);
        Write32(udp.bytes->data() + 16, tunnelIp);
        readPacket(udp);
        observe(udp, 105, "chrome.exe");
        before = submissions.size();
        receive(udp);
        assert(submissions.size() == before + 1);
        const auto outgoingUdp = unwrap(submissions.back(), 1);
        assert(Read32(outgoingUdp.data() + 16) == shared);
        checkUdpChecksums(outgoingUdp);

        auto udpReply = MakePacket(false, 443, 53205);
        Write32(udpReply.bytes->data() + 12, shared);
        Write32(udpReply.bytes->data() + 16, Read32(outgoingUdp.data() + 12));
        udpReply.address.Outbound = 0;
        udpReply.address.Timestamp = 210;
        readPacket(udpReply);
        fromServer(udpReply, 1);
        assert(submissions.size() == before + 2);
        assert(Read32(submissions.back().data() + 12) == tunnelIp);
        checkUdpChecksums(submissions.back());

        auto unknown = MakePacket(true, 53202);
        Write32(unknown.bytes->data() + 16, 0xc613ffff);
        readPacket(unknown);
        observe(unknown, 103, "unrelated.exe");
        before = submissions.size();
        receive(unknown);
        assert(submissions.size() == before);

        const auto missing = BuildSyntheticDnsQuery("missing.example", 1, 1004);
        receive(dns(missing, {17, 0xc0000201, 53000, resolver, 53}, true));
        assert(submissions.size() == before + 3);
        const auto missingDirect = submissions[before];
        const auto missingQuestion = ParseSyntheticDnsQuestion(std::span<const uint8_t>(missingDirect).subspan(28));
        assert(missingQuestion);
        const auto negative = BuildSyntheticDnsAnswer(*missingQuestion, {}, 3);
        receive(dns(negative, {17, resolver, 53, 0xc0000201, port}, false));
        assert(submissions.size() == before + 4);
        const auto missingIp = dnsAddress(1004, 53000, 0);
        auto missingFlow = MakePacket(true, 53208);
        Write32(missingFlow.bytes->data() + 16, missingIp);
        readPacket(missingFlow);
        observe(missingFlow, 111, "unrelated.exe");
        receive(missingFlow);
        assert(submissions.size() == before + 4);

        const auto timeout = BuildSyntheticDnsQuery("timeout.example", 1, 1005);
        receive(dns(timeout, {17, 0xc0000201, 53000, resolver, 53}, true));
        assert(submissions.size() == before + 7);
        const auto firstTimeoutQuery = submissions[before + 4];
        SyntheticDnsResolver::Outputs retries;
        const auto retryTime = Clock::now() + std::chrono::milliseconds(2100);
        runtime->syntheticDns.Cleanup(retryTime, *runtime->config, runtime->buffers, retries);
        const auto retried = std::find_if(retries.begin(), retries.end(), [&](const auto& item) {
            return item.route.kind == FlowRoute::Kind::Direct &&
                std::equal(item.packet.bytes->begin() + 28, item.packet.bytes->end(),
                    firstTimeoutQuery.begin() + 28, firstTimeoutQuery.end());
        });
        assert(retried != retries.end() && retried->packet.address.Outbound);
        assert(Read16(retried->packet.bytes->data() + 20) == port);
        retries.clear();
        runtime->syntheticDns.Cleanup(retryTime + std::chrono::milliseconds(500), *runtime->config, runtime->buffers, retries);
        assert(retries.empty());
        SyntheticDnsResolver::Outputs expired;
        runtime->syntheticDns.Cleanup(Clock::now() + std::chrono::seconds(4), *runtime->config, runtime->buffers, expired);
        assert(expired.size() == 1);
        const auto& failure = *expired.front().packet.bytes;
        assert(Read16(failure.data() + 28) == 1005 && (failure[31] & 15) == 2);

        before = submissions.size();
        auto full = std::make_shared<Configuration>(*runtime->config);
        ++full->version;
        full->fullRoutingServerId = 2;
        full->dnsResolverEnabled = false;
        runtime->config = full;
        runtime->published.store(full);
        receive(dns(BuildSyntheticDnsQuery(tunnelName, 1, 1003), {17, 0xc0000201, 53000, resolver, 53}, true));
        assert(submissions.size() == before + 1);
        const auto fullQuery = unwrap(submissions.back(), 2);
        assert(Read16(fullQuery.data() + 20) == 53000);
        assert(Read16(fullQuery.data() + 28) == 1003);

        runtime->Stop();
        assert(runtime->syntheticDns.Port() == 0);
        WSACleanup();
    }
