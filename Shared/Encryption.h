#pragma once

#include <vector>
#include <string>
#include <cstdint>

class Encryption {
private:
    std::vector<uint8_t> m_xorKey;
    std::vector<uint8_t> m_swapKey;

    uint64_t m_swapBits = 0;

    static const size_t XOR_KEY_SIZE = 128;
    static const size_t SWAP_KEY_SIZE = 8;

    void XorTransform(uint8_t* data, size_t length);
    void SwapTransform(uint8_t* data, size_t length, uint16_t nonce);
    void ReverseSwapTransform(uint8_t* data, size_t length, uint16_t nonce);

public:
    Encryption();
    ~Encryption();

    bool Initialize(const std::string& xorKeyBase64, const std::string& swapKeyBase64);
    void Encrypt(uint8_t* data, size_t length, uint16_t nonce);
    void Decrypt(uint8_t* data, size_t length, uint16_t nonce);
    bool IsInitialized() const;

    static std::string GenerateXorKeyBase64();
    static std::string GenerateSwapKeyBase64();
};