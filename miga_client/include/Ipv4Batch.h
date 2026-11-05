#pragma once

#include <cstddef>
#include <cstdint>

size_t Ipv4BatchPacketLength(const uint8_t* data, size_t size, size_t offset);
