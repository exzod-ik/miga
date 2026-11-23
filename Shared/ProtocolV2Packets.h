#pragma once
#include "ProtocolV2.h"
#include <chrono>
#include <unordered_map>
#include <list>

namespace miga::v2 {
bool FragmentInner(const uint8_t* packet, size_t length, std::vector<Bytes>& fragments, Bytes& icmp);
class Ipv4Reassembler {
public:
    enum class Result { Complete, Waiting, Rejected };
    Result Add(const uint8_t* packet, size_t length, Bytes& complete, const std::string& context = {});
    void Clear();
private:
    using Expiry = std::list<std::pair<std::string, std::chrono::steady_clock::time_point>>;
    struct Entry {
        Bytes header, payload, present;
        Expiry::iterator expiry;
        size_t end = 0, received = 0;
        bool hasEnd = false, invalid = false;
        std::chrono::steady_clock::time_point created;
    };
    std::unordered_map<std::string, Entry> entries_;
    Expiry expiry_;
    size_t bytes_ = 0;
};
}
