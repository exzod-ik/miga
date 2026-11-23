#pragma once

#include <atomic>
#include <memory>
#include <string>

namespace miga::v2
{

class V2Server
{
    friend struct V2ServerTests;

  public:
    V2Server();
    ~V2Server();
    bool Initialize(const std::string &configPath);
    void Run(const std::atomic<bool> &running);
    static int Admin(int argc, char **argv, const std::string &configPath);

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}
