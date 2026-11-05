#pragma once

#include <memory>
#include <string>

class ConfigManager;
class Logger;

class NetworkRuntime {
public:
    NetworkRuntime(ConfigManager* configuration, Logger* logger);
    ~NetworkRuntime();
    bool Start();
    void Stop();
    bool ReloadConfig(const std::string& path);
    bool IsRunning() const;
private:
    friend struct NetworkRuntimeTests;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
