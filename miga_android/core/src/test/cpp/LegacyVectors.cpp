#include "Encryption.h"
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

static std::string Base64(const std::vector<uint8_t>& data) {
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    int value = 0, bits = -6;
    for (uint8_t byte : data) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 0) {
            output.push_back(alphabet[(value >> bits) & 63]);
            bits -= 6;
        }
    }
    if (bits > -6) output.push_back(alphabet[((value << 8) >> (bits + 8)) & 63]);
    while (output.size() % 4) output.push_back('=');
    return output;
}

int main() {
    std::vector<uint8_t> xorKey(128), swapKey(8);
    for (size_t i = 0; i < xorKey.size(); ++i) xorKey[i] = static_cast<uint8_t>(i * 37 + 11);
    for (size_t i = 0; i < swapKey.size(); ++i) swapKey[i] = static_cast<uint8_t>(i * 29 + 3);
    Encryption encryption;
    if (!encryption.Initialize(Base64(xorKey), Base64(swapKey))) return 1;
    for (int length : {1, 2, 63, 64, 65, 128, 129}) {
        for (uint16_t port : {uint16_t(1), uint16_t(0x1234), uint16_t(65535)}) {
            std::vector<uint8_t> packet(length);
            for (int i = 0; i < length; ++i) packet[i] = static_cast<uint8_t>(i * 13 + 7);
            encryption.Encrypt(packet.data(), packet.size(), port);
            std::cout << length << ',' << port << ',';
            for (auto byte : packet) std::cout << std::hex << std::setfill('0') << std::setw(2) << int(byte);
            std::cout << std::dec << '\n';
        }
    }
}
