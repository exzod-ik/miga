#include "ClientStore.h"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

using namespace miga::v2;

int main()
{
    char temporary[] = "/tmp/miga-v2-store-XXXXXX";
    const auto *directory = mkdtemp(temporary);
    assert(directory);
    const std::string path = std::string(directory) + "/clients.sqlite3";
    ClientRecord record;
    record.id[0] = 1;
    record.secret[0] = 2;
    record.name = "test client";
    record.maxConnections = 0;
    ClientId request{};
    request[0] = 3;
    std::vector<uint8_t> fingerprint(32, 4);
    {
        ClientStore store;
        assert(store.Open(path));
        assert(store.Add(record));
        assert(!store.Add(record));
        ClientRecord loaded;
        assert(store.Get(record.id, loaded));
        assert(loaded.secret == record.secret && loaded.maxConnections == 0 && loaded.name == record.name);
        assert(store.Admit(record.id, request, fingerprint, 1, 2000, 1000, 1000, 1) == Admission::Accepted);
        assert(store.Admit(record.id, request, fingerprint, 1, 2000, 1000, 1000, 1) == Admission::Duplicate);
        assert(store.Admit(record.id, request, fingerprint, 2, 2000, 1000, 1000, 1) == Admission::Rejected);
        fingerprint[0] ^= 1;
        assert(store.Admit(record.id, request, fingerprint, 1, 2000, 1000, 1000, 1) == Admission::Rejected);
        fingerprint[0] ^= 1;
        ClientId future{};
        future[0] = 4;
        assert(store.Admit(record.id, future, fingerprint, 1, 2000, 1121, 1000, 1) == Admission::Rejected);
        assert(store.Admit(record.id, future, fingerprint, 1, 2000, 1000, 999, 1) == Admission::Rejected);
        assert(store.ReserveAddress(0x0a400002));
        assert(!store.ReserveAddress(0x0a400002));
        assert(store.ReservePort(20000));
        assert(!store.ReservePort(20000));
        assert(store.Update(record.id, "renamed", 3));
    }
    {
        ClientStore store;
        assert(store.Open(path));
        assert(store.Admit(record.id, request, fingerprint, 1, 2000, 1000, 1000, 1) == Admission::Duplicate);
        ClientId different{};
        different[0] = 5;
        assert(store.Admit(record.id, different, fingerprint, 1, 2000, 1000, 900, 1) == Admission::Rejected);
        std::vector<uint32_t> addresses;
        std::vector<uint16_t> ports;
        assert(store.ReservedAddresses(addresses) && addresses == std::vector<uint32_t>{0x0a400002});
        assert(store.ReservedPorts(ports) && ports == std::vector<uint16_t>{20000});
        assert(store.ReleaseAddress(addresses[0]) && store.ReleasePort(ports[0]));
        assert(store.Revoke(record.id));
        assert(store.Admit(record.id, different, fingerprint, 1, 2000, 1000, 1000, 1) == Admission::Rejected);
        assert(!store.Update(record.id, "revoked", 1));
        std::vector<ClientRecord> clients;
        assert(store.List(clients) && clients.size() == 1 && clients[0].revoked);
    }
    struct stat permissions{};
    assert(stat(path.c_str(), &permissions) == 0 && (permissions.st_mode & 0077) == 0);
    assert(unlink(path.c_str()) == 0);
    const std::string capacityPath = std::string(directory) + "/capacity.sqlite3";
    {
        ClientStore store;
        assert(store.Open(capacityPath));
        assert(store.Add(record));
        for (uint32_t value = 0; value < 1024; ++value)
        {
            request[0] = static_cast<uint8_t>(value >> 8);
            request[1] = static_cast<uint8_t>(value);
            assert(store.Admit(record.id, request, fingerprint, 1, 2000, 2000, 2000, 1) == Admission::Accepted);
        }
        request[2] = 1;
        assert(store.Admit(record.id, request, fingerprint, 1, 2000, 2000, 2000, 1) == Admission::Unavailable);
        assert(store.Admit(record.id, request, fingerprint, 1, 2000, 2601, 2601, 1) == Admission::Accepted);
    }
    assert(unlink(capacityPath.c_str()) == 0);
    assert(rmdir(directory) == 0);
    std::cout << "client_store_tests_passed" << std::endl;
}
