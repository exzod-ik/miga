#pragma once

#include <nlohmann/json.hpp>
#include <atomic>
#include <thread>
#include <mutex>
#include <array>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>
#include <unordered_set>
#include <map>
#include <chrono>
#include "ProtocolV2.h"
#include "DiagnosticLoadSocket.h"

namespace miga::v2 { struct V2ServerTests; }

class DiagnosticControl {
    friend struct DiagnosticControlTests;
    friend struct miga::v2::V2ServerTests;
public:
    using Json = nlohmann::json;
    using Reply = std::function<bool(uint8_t*, size_t)>;
    ~DiagnosticControl();
    bool Configure(const Json& settings);
    bool Start();
    void SetNetworkSource(std::function<std::shared_ptr<const int>(uint32_t)> socket,
                          std::function<uint32_t()> address);
    void Stop();
    miga::v2::Bytes Authorize(uint32_t identity);
    void Revoke(uint32_t identity);
    bool Echo(uint8_t* packet, size_t length, uint32_t client, const Reply& reply);
    uint64_t Outbound(const uint8_t* packet, size_t length, uint32_t client);
    void TunMapped(uint64_t watch, uint16_t translated);
    void TunWritten(uint64_t watch, bool success, const uint8_t* packet = nullptr, size_t length = 0);
    void Inbound(const uint8_t* packet, size_t length);
    std::atomic<bool> active{false};
    DiagnosticLoadSocket load;
    void LoadPacket(miga::diagnostics::LoadCounters::Stage stage, const uint8_t* packet, size_t size, uint32_t client, bool success = true);
private:
    using PortIndex = std::array<std::array<std::atomic<uint64_t>, 1024>, 2>;
    PortIndex outboundPorts_{}, inboundPorts_{};
    static bool HasPort(const PortIndex& index, uint8_t protocol, uint16_t port);
    static void IndexPort(PortIndex& index, uint8_t protocol, uint16_t port);
    Json settings_;
    std::atomic<bool> stopping_{false};
    std::thread thread_;
    std::mutex mutex_;
    int listener_ = -1, connection_ = -1;
    uint32_t client_ = 0;
    std::atomic<uint32_t> loadClient_{0};
    struct Grant { miga::v2::Key ticket; std::chrono::steady_clock::time_point expires; };
    std::map<uint32_t, Grant> grants_;
    miga::v2::Key fingerprint_{};
    uint16_t port_ = 0;
    std::array<uint8_t, 16> token_{};
    struct Watch {uint64_t id; uint8_t protocol; uint16_t local, remote, translated = 0; uint32_t ip; uint32_t sequence = 0; std::vector<uint8_t> transaction; Json stats; bool sequence16 = false; std::unordered_set<uint16_t> receivedSequences, writtenSequences; uint32_t source = 0;};
    uint64_t nextWatch_ = 0, session_ = 0;
    std::vector<Watch> watches_;
    Json echo_;
    std::function<std::shared_ptr<const int>(uint32_t)> networkSocket_;
    std::function<uint32_t()> networkAddress_;
    Json networkBefore_;
    Json CaptureNetwork();
    void Serve();
    Json Command(const Json& command);
};
