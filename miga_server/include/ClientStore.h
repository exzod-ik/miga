#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;

namespace miga::v2
{

using ClientId = std::array<uint8_t, 16>;
using AccessSecret = std::array<uint8_t, 32>;

struct ClientRecord
{
    ClientId id{};
    AccessSecret secret{};
    std::string name;
    uint32_t maxConnections = 1;
    bool revoked = false;
};

enum class Admission
{
    Accepted,
    Duplicate,
    Rejected,
    Unavailable
};

class ClientStore
{
  public:
    ClientStore() = default;
    ~ClientStore();
    ClientStore(const ClientStore &) = delete;
    ClientStore &operator=(const ClientStore &) = delete;
    bool Open(const std::string &path);
    bool Add(const ClientRecord &record);
    bool Get(const ClientId &id, ClientRecord &record);
    bool IsRevoked(const ClientId &id, bool &revoked);
    bool List(std::vector<ClientRecord> &records);
    bool ListActive(const ClientId *after, int limit, std::vector<ClientRecord> &records);
    bool Update(const ClientId &id, const std::string &name, uint32_t maxConnections);
    bool Revoke(const ClientId &id);
    Admission Admit(const ClientId &client, const ClientId &request, const std::vector<uint8_t> &fingerprint,
                    uint32_t address, uint16_t port, int64_t requestTime, int64_t now, uint32_t maxSessions);
    bool Purge(int64_t now);
    bool ReserveAddress(uint32_t address);
    bool ReleaseAddress(uint32_t address);
    bool ReservedAddresses(std::vector<uint32_t> &addresses);
    bool ReservePort(uint16_t port);
    bool ReleasePort(uint16_t port);
    bool ReservedPorts(std::vector<uint16_t> &ports);

  private:
    sqlite3 *db_ = nullptr;
    int64_t lastWall_ = 0;
    bool Execute(const char *sql);
};

}
