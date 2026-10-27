#include "InterfaceIpCache.h"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <dirent.h>
#include <iostream>
#include <vector>

static size_t DescriptorCount() {
    DIR* directory = opendir("/proc/self/fd");
    assert(directory);
    size_t count = 0;
    while (readdir(directory)) ++count;
    closedir(directory);
    return count;
}

int main() {
    const auto before = DescriptorCount();
    InterfaceIpCache cache;
    assert(cache.Start("miga-no-such-interface"));
    assert(cache.Get() == 0);
    cache.Stop();
    cache.Stop();
    assert(cache.Start("lo"));
    assert(cache.Get() == 0);
    cache.Stop();

    ifaddrs* interfaces = nullptr;
    assert(getifaddrs(&interfaces) == 0);
    std::vector<uint32_t> addresses{ 0 };
    for (auto* entry = interfaces; entry; entry = entry->ifa_next) {
        if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET && !(entry->ifa_flags & IFF_LOOPBACK))
            addresses.push_back(reinterpret_cast<sockaddr_in*>(entry->ifa_addr)->sin_addr.s_addr);
    }
    freeifaddrs(interfaces);
    assert(cache.Start(""));
    assert(std::find(addresses.begin(), addresses.end(), cache.Get()) != addresses.end());
    std::atomic<bool> reading{ true };
    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i)
        readers.emplace_back([&] { while (reading.load()) cache.Get(); });
    cache.Stop();
    reading = false;
    for (auto& reader : readers) reader.join();

    for (int i = 0; i < 20; ++i) {
        assert(cache.Start(""));
        const auto started = std::chrono::steady_clock::now();
        cache.Stop();
        assert(std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
    }
    assert(DescriptorCount() == before);
    std::cout << "Interface IP cache tests passed\n";
}
