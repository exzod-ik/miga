#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

class InternetChecksum {
public:
    void Add(const void* buffer, size_t length) {
        auto* data = static_cast<const uint8_t*>(buffer);
        if (pending_ && length != 0) {
            sum_ += (static_cast<uint16_t>(byte_) << 8) | *data++;
            --length;
            pending_ = false;
        }
        while (length >= 2) {
            sum_ += (static_cast<uint16_t>(data[0]) << 8) | data[1];
            data += 2;
            length -= 2;
        }
        if (length != 0) {
            byte_ = *data;
            pending_ = true;
        }
        while (sum_ >> 16) sum_ = (sum_ & 0xFFFF) + (sum_ >> 16);
    }

    uint16_t Value() const {
        auto sum = sum_ + (pending_ ? static_cast<uint16_t>(byte_) << 8 : 0);
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        const uint16_t value = static_cast<uint16_t>(~sum);
        const uint8_t bytes[] = { static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value) };
        uint16_t result;
        std::memcpy(&result, bytes, sizeof(result));
        return result;
    }

private:
    uint64_t sum_ = 0;
    uint8_t byte_ = 0;
    bool pending_ = false;
};
