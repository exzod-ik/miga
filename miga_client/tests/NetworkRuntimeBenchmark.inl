    static inline size_t benchmarkSubmitted = 0;

    static BOOL BenchmarkSend(HANDLE, const VOID*, UINT length, UINT* sent, UINT64,
        const WINDIVERT_ADDRESS*, UINT addressLength, OVERLAPPED*) {
        benchmarkSubmitted += addressLength / sizeof(WINDIVERT_ADDRESS);
        if (sent) *sent = length;
        return TRUE;
    }

    static void Benchmark(bool tcp, bool tunnelled, bool inbound, bool resolverEnabled, size_t packetSize, bool validChecksums) {
        Logger logger;
        logger.enable(LOGGER_LEVEL_NONE, false);
        ConfigManager source(&logger);
        auto runtime = Fixture(logger, source);
        runtime->config->dnsResolverEnabled = resolverEnabled;
        runtime->config->dnsResolverReserveRange = resolverEnabled;
        auto packet = MakePacket(tcp, 5011);
        const uint32_t realIp = packet.view.tuple.remoteIp;
        const uint32_t localIp = packet.view.tuple.localIp;
        if (resolverEnabled) {
            Write32(packet.bytes->data() + 16, 0xc6120002);
            assert(packet.view.Read(packet.bytes->data(), packet.bytes->size()));
        }
        auto owner = runtime->directory.Observe(packet.view.tuple, std::make_shared<const SocketOwner>(
            SocketOwner{Identity(200, tunnelled ? "chrome.exe" : "direct.exe"), 30, 100}), Clock::now());
        const FlowRoute route{tunnelled ? FlowRoute::Kind::Tunnel : FlowRoute::Kind::Direct,
            tunnelled ? size_t{1} : size_t{0}, resolverEnabled ? realIp : 0};
        assert(runtime->flows.Commit(packet.view, packet.address.Timestamp, {route, owner}, Clock::now()));
        if (tcp) (*packet.bytes)[33] = 16;
        auto input = *packet.bytes;
        input.resize(packetSize);
        Write16(input.data() + 2, static_cast<uint16_t>(input.size()));
        if (!tcp) Write16(input.data() + 24, static_cast<uint16_t>(input.size() - 20));
        if (inbound) {
            packet.address.Outbound = 0;
            Write32(input.data() + 12, realIp);
            Write32(input.data() + 16, tunnelled ? 0x0a420001 : localIp);
            Write16(input.data() + 20, 443);
            Write16(input.data() + 22, 5011);
            if (tunnelled) {
                const auto session = runtime->config->servers[0].transport->session->Snapshot();
                miga::v2::Bytes payload;
                assert(miga::v2::EncryptData(session->keys.dataS2C, session->keys.prefixS2C, input.data(), input.size(), payload));
                TunnelDatagram wrapper;
                assert(wrapper.Build(payload.data(), payload.size(), htonl(0xc6336401), htonl(localIp), 20001, 60001, 1, 1500,
                    [&](const uint8_t* data, size_t length, size_t count) {
                        assert(count == 1);
                        input.assign(data, data + length);
                        return true;
                    }));
            }
        }
        if (validChecksums)
            assert(WinDivertHelperCalcChecksums(input.data(), static_cast<UINT>(input.size()), &packet.address, 0));
        AsyncTunnelSender::Api fast;
        fast.send = BenchmarkSend;
        runtime->reinject.SetApi(fast);
        runtime->tunnel.SetApi(fast);
        std::vector<double> samples;
        std::vector<uint8_t> work(input.size());
        constexpr size_t groups = 768, batch = 64;
        benchmarkSubmitted = 0;
        for (size_t i = 0; i < groups; ++i) {
            const auto start = Clock::now();
            runtime->tunnel.BeginBatch();
            runtime->reinject.BeginBatch();
            for (size_t n = 0; n < batch; ++n) {
                memcpy(work.data(), input.data(), input.size());
                runtime->PacketReceived(work.data(), work.size(), packet.address);
            }
            runtime->tunnel.EndBatch();
            runtime->reinject.EndBatch();
            if (i >= 64) samples.push_back(std::chrono::duration<double, std::nano>(Clock::now() - start).count() / batch);
        }
        assert(benchmarkSubmitted == groups * batch);
        std::sort(samples.begin(), samples.end());
        std::cout << (tcp ? "TCP " : "UDP ") << (tunnelled ? "tunnel" : "direct") << (inbound ? " inbound" : " outbound")
            << " bytes=" << packetSize << " resolver=" << resolverEnabled << " batch_p50_ns_per_packet=" << samples[samples.size()/2]
            << " batch_p95_ns_per_packet=" << samples[samples.size()*95/100] << "\n";
    }
