#include "Encryption.h"
#include <vector>
#include <string>
#include <random>
#include <cstdint>
#include <algorithm>
#include <stdexcept>

using namespace std;

static const string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static string Base64Encode(const vector<uint8_t>& data) {
    std::string result;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (result.size() % 4) {
        result.push_back('=');
    }
    return result;
}

vector<uint8_t> Base64Decode(const string& base64) {
    vector<uint8_t> result;
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : base64) {
        if (c == '=') {
            if (valb == -2) {
                result.push_back((val >> 2) & 0xFF);
            }
            break;
        }
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return result;
}

Encryption::Encryption() {
}

Encryption::~Encryption() {
}

bool Encryption::Initialize(const string& xorKeyBase64, const string& swapKeyBase64) {
    try {
        m_xorKey = Base64Decode(xorKeyBase64);
        m_swapKey = Base64Decode(swapKeyBase64);

        if (m_xorKey.size() != XOR_KEY_SIZE) {
            m_xorKey.resize(XOR_KEY_SIZE, 0);
        }

        if (m_swapKey.size() != SWAP_KEY_SIZE) {
            m_swapKey.resize(SWAP_KEY_SIZE, 0);
        }

        m_swapBits = 0;
        for (size_t i = 0; i < SWAP_KEY_SIZE; ++i)
            m_swapBits |= uint64_t(m_swapKey[i]) << (8 * i);
        return true;
    }
    catch (...) {
        return false;
    }
}

// apply xor key to data
void Encryption::XorTransform(uint8_t* data, size_t length) {
    if (m_xorKey.size() != XOR_KEY_SIZE) {
        throw runtime_error("XorTransform: xor key empty");
    }

    while (length >= XOR_KEY_SIZE) {
        for (size_t i = 0; i < XOR_KEY_SIZE; ++i) data[i] ^= m_xorKey[i];
        data += XOR_KEY_SIZE;
        length -= XOR_KEY_SIZE;
    }
    for (size_t i = 0; i < length; ++i) data[i] ^= m_xorKey[i];
}

// apply swap key to encrypt data
void Encryption::SwapTransform(uint8_t* data, size_t length, uint16_t nonce) {
    if (m_swapKey.empty()) {
        throw runtime_error("SwapTransform: swap key empty");
    }

    if (length < 2) {
        return;
    }

    const uint64_t keyBits = m_swapBits ^ (uint64_t(nonce) * 0x0001000100010001ULL);
    size_t keyBitPos = 0;

    for (size_t i = 0; i < length - 1; i++) {
        bool shouldSwap = (keyBits >> (keyBitPos % 64)) & 1;
        if (shouldSwap) {
            swap(data[i], data[i + 1]);
        }
        keyBitPos++;
    }
}

// apply swap key to decrypt data
void Encryption::ReverseSwapTransform(uint8_t* data, size_t length, uint16_t nonce) {
    const uint64_t key = m_swapBits ^ (uint64_t(nonce) * 0x0001000100010001ULL);

    // go from the end to the beginning, using the same key bits
    for (size_t i = length - 1; i > 0; i--) {
        // check the i-th bit of the key (shift by (i-1) % 64)
        bool shouldSwap = (key >> ((i - 1) % 64)) & 1;
        if (shouldSwap) {
            swap(data[i - 1], data[i]);
        }
    }
}

void Encryption::Encrypt(uint8_t* data, size_t length, uint16_t nonce) {
    if (!data) {
        throw runtime_error("Encrypt: null data pointer");
    }
    if (length == 0) {
        throw runtime_error("Encrypt: zero length");
    }
    if (m_xorKey.empty()) {
        throw runtime_error("Encrypt: xor key not initialized");
    }
    if (m_swapKey.empty()) {
        throw runtime_error("Encrypt: swap key not initialized");
    }

    XorTransform(data, length);
    SwapTransform(data, length, nonce);
}

void Encryption::Decrypt(uint8_t* data, size_t length, uint16_t nonce) {
    if (length == 0) return;
    if (!data || !IsInitialized()) throw runtime_error("Decrypt: invalid input or uninitialized keys");
    ReverseSwapTransform(data, length, nonce);
    XorTransform(data, length);
}

string Encryption::GenerateXorKeyBase64() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<unsigned int> dist(0, 255);
    vector<uint8_t> key(XOR_KEY_SIZE);
    for (auto& b : key) {
        b = static_cast<uint8_t>(dist(gen));
    }
    return Base64Encode(key);
}

string Encryption::GenerateSwapKeyBase64() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<unsigned int> dist(0, 255);
    vector<uint8_t> key(SWAP_KEY_SIZE);
    for (auto& b : key) {
        b = static_cast<uint8_t>(dist(gen));
    }
    return Base64Encode(key);
}

bool Encryption::IsInitialized() const { return !m_xorKey.empty() && !m_swapKey.empty(); }
