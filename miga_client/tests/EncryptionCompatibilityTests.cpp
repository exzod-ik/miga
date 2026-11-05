#include "Encryption.h"
#include <algorithm>
#include <cassert>
#include <iostream>

int main() {
    Encryption transform;
    std::string xorKey;
    for (int i = 0; i < 42; ++i) xorKey += "AQID";
    xorKey += "AQI=";
    assert(transform.Initialize(xorKey, "AQIDBAUGBwg="));
    transform.Decrypt(nullptr, 0, 12345);
    const auto verify = [&](size_t size, uint16_t nonce) {
        std::vector<uint8_t> original(size);
        for (size_t i = 0; i < size; ++i) original[i] = static_cast<uint8_t>(i * 37);
        auto expected = original;
        for (size_t i = 0; i < size; ++i) expected[i] ^= static_cast<uint8_t>((i % 128) % 3 + 1);
        uint64_t key = 0x0807060504030201ULL;
        for (size_t i = 0; i < 4; ++i) key ^= uint64_t(nonce) << (16 * i);
        for (size_t i = 0; i + 1 < size; ++i)
            if ((key >> (i % 64)) & 1) std::swap(expected[i], expected[i + 1]);
        auto actual = original;
        transform.Encrypt(actual.data(), actual.size(), nonce);
        assert(actual == expected);
        transform.Decrypt(actual.data(), actual.size(), nonce);
        assert(actual == original);
    };
    for (uint32_t port = 0; port <= 65535; ++port) verify(257, static_cast<uint16_t>(port));
    for (size_t size : {size_t(1), size_t(2), size_t(127), size_t(128), size_t(129), size_t(1500), size_t(65507)})
        for (uint16_t port : {uint16_t(0), uint16_t(1), uint16_t(255), uint16_t(32768), uint16_t(65535)}) verify(size, port);
    std::cout << "Encryption wire compatibility tests passed\n";
}
