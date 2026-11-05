#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

struct TunnelIngress {
    uint8_t* payload;
    size_t length;
    uint32_t clientAddress;
    uint16_t clientPort;
    uint16_t serverPort;

    static bool Parse(uint8_t* packet, size_t size, uint16_t first, uint16_t last, TunnelIngress& result);
};
