#include "ClientStore.h"
#include <cstring>
#include <limits>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

namespace miga::v2
{
namespace
{
class Statement
{
  public:
    sqlite3_stmt *value = nullptr;
    Statement(sqlite3 *db, const char *sql)
    {
        if (sqlite3_prepare_v2(db, sql, -1, &value, nullptr) != SQLITE_OK)
            value = nullptr;
    }
    ~Statement()
    {
        sqlite3_finalize(value);
    }
};
bool Bind(sqlite3_stmt *statement, int index, const ClientId &value)
{
    return sqlite3_bind_blob(statement, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) ==
           SQLITE_OK;
}
bool Read(sqlite3_stmt *statement, ClientRecord &record)
{
    if (sqlite3_column_bytes(statement, 0) != 16 || sqlite3_column_bytes(statement, 1) != 32)
        return false;
    std::memcpy(record.id.data(), sqlite3_column_blob(statement, 0), 16);
    std::memcpy(record.secret.data(), sqlite3_column_blob(statement, 1), 32);
    const auto *name = sqlite3_column_text(statement, 2);
    if (!name)
        return false;
    record.name.assign(reinterpret_cast<const char *>(name), static_cast<size_t>(sqlite3_column_bytes(statement, 2)));
    const auto limit = sqlite3_column_int64(statement, 3);
    if (limit < 0 || limit > std::numeric_limits<uint32_t>::max())
        return false;
    record.maxConnections = static_cast<uint32_t>(limit);
    record.revoked = sqlite3_column_int(statement, 4) != 0;
    return true;
}
}

ClientStore::~ClientStore()
{
    if (db_)
        sqlite3_close(db_);
}

bool ClientStore::Execute(const char *sql)
{
    return sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool ClientStore::Open(const std::string &path)
{
    if (db_)
        return false;
    struct stat existing{};
    if (lstat(path.c_str(), &existing) == 0 && (!S_ISREG(existing.st_mode) || (existing.st_mode & 0077) != 0))
        return false;
    const auto oldMask = umask(0077);
    const int result = sqlite3_open_v2(path.c_str(), &db_,
                                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    umask(oldMask);
    if (result != SQLITE_OK || chmod(path.c_str(), 0600) != 0)
        return false;
    sqlite3_busy_timeout(db_, 5000);
    if (!Execute("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;"
                 "CREATE TABLE IF NOT EXISTS clients(id BLOB PRIMARY KEY CHECK(length(id)=16),secret BLOB NOT NULL "
                 "CHECK(length(secret)=32),name TEXT NOT NULL,max_connections INTEGER NOT NULL "
                 "CHECK(max_connections>=0),revoked INTEGER NOT NULL DEFAULT 0);"
                 "CREATE TABLE IF NOT EXISTS requests(client BLOB NOT NULL,request BLOB NOT NULL,fingerprint BLOB NOT "
                 "NULL,address INTEGER NOT NULL,port INTEGER NOT NULL,accepted INTEGER NOT NULL,PRIMARY "
                 "KEY(client,request));"
                 "CREATE INDEX IF NOT EXISTS requests_age ON requests(accepted);"
                 "CREATE TABLE IF NOT EXISTS clock(id INTEGER PRIMARY KEY CHECK(id=1),high_water INTEGER NOT NULL);"
                 "CREATE TABLE IF NOT EXISTS addresses(value INTEGER PRIMARY KEY);"
                 "CREATE TABLE IF NOT EXISTS ports(value INTEGER PRIMARY KEY);"))
        return false;
    Statement clock(db_, "SELECT high_water FROM clock WHERE id=1");
    if (!clock.value)
        return false;
    if (sqlite3_step(clock.value) == SQLITE_ROW)
        lastWall_ = sqlite3_column_int64(clock.value, 0);
    return true;
}

bool ClientStore::Add(const ClientRecord &record)
{
    if (record.name.empty() || record.name.size() > 256 || record.name.find('\0') != std::string::npos)
        return false;
    Statement query(db_, "INSERT INTO clients(id,secret,name,max_connections,revoked) VALUES(?,?,?,?,0)");
    return query.value && Bind(query.value, 1, record.id) &&
           sqlite3_bind_blob(query.value, 2, record.secret.data(), 32, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(query.value, 3, record.name.data(), static_cast<int>(record.name.size()),
                             SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int64(query.value, 4, record.maxConnections) == SQLITE_OK &&
           sqlite3_step(query.value) == SQLITE_DONE;
}

bool ClientStore::Get(const ClientId &id, ClientRecord &record)
{
    Statement query(db_, "SELECT id,secret,name,max_connections,revoked FROM clients WHERE id=?");
    return query.value && Bind(query.value, 1, id) && sqlite3_step(query.value) == SQLITE_ROW &&
           Read(query.value, record);
}
bool ClientStore::IsRevoked(const ClientId &id, bool &revoked)
{
    Statement query(db_, "SELECT revoked FROM clients WHERE id=?");
    if (!query.value || !Bind(query.value, 1, id))
        return false;
    const int status = sqlite3_step(query.value);
    if (status == SQLITE_DONE)
    {
        revoked = true;
        return true;
    }
    if (status != SQLITE_ROW)
        return false;
    revoked = sqlite3_column_int(query.value, 0) != 0;
    return true;
}

bool ClientStore::List(std::vector<ClientRecord> &records)
{
    records.clear();
    Statement query(db_, "SELECT id,secret,name,max_connections,revoked FROM clients ORDER BY name,id");
    if (!query.value)
        return false;
    int status;
    while ((status = sqlite3_step(query.value)) == SQLITE_ROW)
    {
        ClientRecord record;
        if (!Read(query.value, record))
            return false;
        records.push_back(std::move(record));
    }
    return status == SQLITE_DONE;
}

bool ClientStore::ListActive(const ClientId *after, int limit, std::vector<ClientRecord> &records)
{
    records.clear();
    Statement query(db_, after
        ? "SELECT id,secret,name,max_connections,revoked FROM clients WHERE revoked=0 AND id>?2 ORDER BY id LIMIT ?1"
        : "SELECT id,secret,name,max_connections,revoked FROM clients WHERE revoked=0 ORDER BY id LIMIT ?1");
    if (!query.value || sqlite3_bind_int(query.value, 1, limit) != SQLITE_OK || (after && !Bind(query.value, 2, *after)))
        return false;
    int status;
    while ((status = sqlite3_step(query.value)) == SQLITE_ROW)
    {
        ClientRecord record;
        if (!Read(query.value, record))
            return false;
        records.push_back(std::move(record));
    }
    return status == SQLITE_DONE;
}

bool ClientStore::Update(const ClientId &id, const std::string &name, uint32_t maxConnections)
{
    if (name.empty() || name.size() > 256 || name.find('\0') != std::string::npos)
        return false;
    Statement query(db_, "UPDATE clients SET name=?,max_connections=? WHERE id=? AND revoked=0");
    return query.value &&
           sqlite3_bind_text(query.value, 1, name.data(), static_cast<int>(name.size()), SQLITE_TRANSIENT) ==
               SQLITE_OK &&
           sqlite3_bind_int64(query.value, 2, maxConnections) == SQLITE_OK && Bind(query.value, 3, id) &&
           sqlite3_step(query.value) == SQLITE_DONE && sqlite3_changes(db_) == 1;
}

bool ClientStore::Revoke(const ClientId &id)
{
    Statement query(db_, "UPDATE clients SET revoked=1 WHERE id=?");
    return query.value && Bind(query.value, 1, id) && sqlite3_step(query.value) == SQLITE_DONE &&
           sqlite3_changes(db_) == 1;
}

bool ClientStore::Purge(int64_t now)
{
    if (now < lastWall_)
        return false;
    Statement query(db_, "DELETE FROM requests WHERE accepted<?");
    return query.value && sqlite3_bind_int64(query.value, 1, now - 600) == SQLITE_OK &&
           sqlite3_step(query.value) == SQLITE_DONE;
}

Admission ClientStore::Admit(const ClientId &client, const ClientId &request, const std::vector<uint8_t> &fingerprint,
                             uint32_t address, uint16_t port, int64_t requestTime, int64_t now, uint32_t maxSessions)
{
    if (!db_ || maxSessions == 0 || fingerprint.size() != 32)
        return Admission::Unavailable;
    if (now < lastWall_ || requestTime < now - 120 || requestTime > now + 120)
        return Admission::Rejected;
    if (!Execute("BEGIN IMMEDIATE"))
        return Admission::Unavailable;
    auto finish = [&](Admission result, bool commit) {
        if (!Execute(commit ? "COMMIT" : "ROLLBACK"))
            return Admission::Unavailable;
        return result;
    };
    ClientRecord record;
    if (!Get(client, record) || record.revoked)
        return finish(Admission::Rejected, false);
    Statement known(db_, "SELECT fingerprint,address,port,accepted FROM requests WHERE client=? AND request=?");
    if (!known.value || !Bind(known.value, 1, client) || !Bind(known.value, 2, request))
        return finish(Admission::Unavailable, false);
    const int status = sqlite3_step(known.value);
    if (status == SQLITE_ROW)
    {
        const bool same = sqlite3_column_bytes(known.value, 0) == 32 &&
                          std::memcmp(sqlite3_column_blob(known.value, 0), fingerprint.data(), 32) == 0 &&
                          sqlite3_column_int64(known.value, 1) == address &&
                          sqlite3_column_int(known.value, 2) == port &&
                          sqlite3_column_int64(known.value, 3) >= now - 600;
        return finish(same ? Admission::Duplicate : Admission::Rejected, false);
    }
    if (status != SQLITE_DONE || !Purge(now))
        return finish(Admission::Unavailable, false);
    Statement count(db_, "SELECT COUNT(*) FROM requests");
    if (!count.value || sqlite3_step(count.value) != SQLITE_ROW ||
        sqlite3_column_int64(count.value, 0) >= static_cast<int64_t>(maxSessions) * 1024)
        return finish(Admission::Unavailable, false);
    Statement insert(db_, "INSERT INTO requests(client,request,fingerprint,address,port,accepted) VALUES(?,?,?,?,?,?)");
    if (!insert.value || !Bind(insert.value, 1, client) || !Bind(insert.value, 2, request) ||
        sqlite3_bind_blob(insert.value, 3, fingerprint.data(), 32, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(insert.value, 4, address) != SQLITE_OK ||
        sqlite3_bind_int(insert.value, 5, port) != SQLITE_OK || sqlite3_bind_int64(insert.value, 6, now) != SQLITE_OK ||
        sqlite3_step(insert.value) != SQLITE_DONE)
        return finish(Admission::Unavailable, false);
    Statement clock(db_, "INSERT INTO clock(id,high_water) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET "
                         "high_water=MAX(high_water,excluded.high_water)");
    if (!clock.value || sqlite3_bind_int64(clock.value, 1, now) != SQLITE_OK ||
        sqlite3_step(clock.value) != SQLITE_DONE)
        return finish(Admission::Unavailable, false);
    const auto result = finish(Admission::Accepted, true);
    if (result == Admission::Accepted)
        lastWall_ = now;
    return result;
}

bool ClientStore::ReserveAddress(uint32_t address)
{
    Statement query(db_, "INSERT INTO addresses(value) VALUES(?)");
    return query.value && sqlite3_bind_int64(query.value, 1, address) == SQLITE_OK &&
           sqlite3_step(query.value) == SQLITE_DONE;
}
bool ClientStore::ReleaseAddress(uint32_t address)
{
    Statement query(db_, "DELETE FROM addresses WHERE value=?");
    return query.value && sqlite3_bind_int64(query.value, 1, address) == SQLITE_OK &&
           sqlite3_step(query.value) == SQLITE_DONE;
}
bool ClientStore::ReservedAddresses(std::vector<uint32_t> &addresses)
{
    addresses.clear();
    Statement query(db_, "SELECT value FROM addresses");
    if (!query.value)
        return false;
    int status;
    while ((status = sqlite3_step(query.value)) == SQLITE_ROW)
        addresses.push_back(static_cast<uint32_t>(sqlite3_column_int64(query.value, 0)));
    return status == SQLITE_DONE;
}
bool ClientStore::ReservePort(uint16_t port)
{
    Statement query(db_, "INSERT INTO ports(value) VALUES(?)");
    return query.value && sqlite3_bind_int(query.value, 1, port) == SQLITE_OK &&
           sqlite3_step(query.value) == SQLITE_DONE;
}
bool ClientStore::ReleasePort(uint16_t port)
{
    Statement query(db_, "DELETE FROM ports WHERE value=?");
    return query.value && sqlite3_bind_int(query.value, 1, port) == SQLITE_OK &&
           sqlite3_step(query.value) == SQLITE_DONE;
}
bool ClientStore::ReservedPorts(std::vector<uint16_t> &ports)
{
    ports.clear();
    Statement query(db_, "SELECT value FROM ports");
    if (!query.value)
        return false;
    int status;
    while ((status = sqlite3_step(query.value)) == SQLITE_ROW)
        ports.push_back(static_cast<uint16_t>(sqlite3_column_int(query.value, 0)));
    return status == SQLITE_DONE;
}

}
