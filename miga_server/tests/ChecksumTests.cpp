#include "InternetChecksum.h"
#include <cassert>
#include <iostream>
#include <random>
#include <vector>

static uint16_t Reference(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    while (length > 1) {
        uint16_t word;
        std::memcpy(&word, data, 2);
        sum += word;
        data += 2;
        length -= 2;
    }
    if (length) {
        uint16_t word = 0;
        std::memcpy(&word, data, 1);
        sum += word;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    return static_cast<uint16_t>(~sum);
}

int main() {
    std::mt19937 random(42);
    std::vector<uint8_t> data(65548);
    for (auto& byte : data) byte = static_cast<uint8_t>(random());
    for (size_t length = 0; length <= 65547; ++length) {
        const auto expected = Reference(data.data(), length);
        InternetChecksum checksum;
        const auto split = length < 12 ? length : 12;
        checksum.Add(data.data(), split);
        checksum.Add(data.data() + split, length - split);
        assert(checksum.Value() == expected);
        if (length < 256) {
            for (size_t offset = 0; offset <= length; ++offset) {
                InternetChecksum fragmented;
                fragmented.Add(data.data() + 1, offset);
                fragmented.Add(nullptr, 0);
                fragmented.Add(data.data() + 1 + offset, length - offset);
                assert(fragmented.Value() == Reference(data.data() + 1, length));
            }
        }
    }
    std::fill(data.begin(), data.end(), uint8_t{255});
    InternetChecksum carries;
    carries.Add(data.data(), data.size());
    assert(carries.Value() == Reference(data.data(), data.size()));
    const uint8_t known[] = {0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7};
    InternetChecksum checksum;
    checksum.Add(known, sizeof(known));
    auto value = checksum.Value();
    uint8_t bytes[2];
    std::memcpy(bytes, &value, 2);
    assert(bytes[0] == 0x22 && bytes[1] == 0x0D);
    std::cout << "Checksum tests passed\n";
}
