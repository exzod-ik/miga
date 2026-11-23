#pragma once
#include "DiagnosticLoad.h"
#include <functional>
#include <thread>
#include <netinet/in.h>

class DiagnosticLoadSocket {
public:
    using Json = nlohmann::json;
    std::atomic<bool> enabled{false};
    miga::diagnostics::LoadCounters counters;
    std::function<bool(uint16_t, bool)> firewall;
    ~DiagnosticLoadSocket();
    Json Prepare(const Json& request, uint32_t address);
    Json StartSending();
    Json Stats();
    void Stop();
    void Observe(const uint8_t* packet, size_t length);
private:
    std::mutex mutex_;
    std::thread thread_;
    std::atomic<bool> stopping_{false}, sending_{false};
    std::atomic<uint64_t> socketDrops_{0}, sendLate_{0};
    int socket_ = -1, receiveBuffer_ = 0;
    uint16_t port_ = 0, clientPort_ = 0;
    uint32_t address_ = 0;
    sockaddr_in peer_{};
    bool peerReady_ = false, firewallAdded_ = false;
    miga::diagnostics::Probe identity_;
    int rate_ = 0, seconds_ = 0, bytes_ = 0;
    void Run();
};
