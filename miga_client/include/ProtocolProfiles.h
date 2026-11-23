#pragma once
#include "ProtocolV2.h"
#include <atomic>
#include <thread>
#include <functional>

class ProtocolProfiles {
public:
    ~ProtocolProfiles();
    using Status = std::function<std::string(const std::string&)>;
    using Diagnostic = std::function<std::string(const std::string&)>;
    void Start(Status status = {}, Diagnostic diagnostic = {});
    void Stop();
    static bool Load(const std::string& id, miga::v2::Invitation& invitation);
private:
    std::atomic<bool> stopping_{true};
    std::thread thread_;
    Status status_;
    Diagnostic diagnostic_;
    void Serve();
    static bool Save(const std::string& text, std::string& id);
};
