#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

class InternetChecksum {
public:
    void Add(const void* buffer, size_t length);

    uint16_t Value() const;

private:
    uint64_t sum_ = 0;
    uint8_t byte_ = 0;
    bool pending_ = false;
};
