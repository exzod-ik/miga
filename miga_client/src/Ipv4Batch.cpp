#include "Ipv4Batch.h"

size_t Ipv4BatchPacketLength(const uint8_t* data, size_t size, size_t offset) {
    if (!data || offset > size || size - offset < 20) return 0;
    const auto* packet = data + offset;
    if ((packet[0] >> 4) != 4) return 0;
    const size_t length = (size_t(packet[2]) << 8) | packet[3];
    const size_t headerLength = (packet[0] & 15) * 4;
    if (headerLength < 20 || length < headerLength || length > size - offset) return 0;
    return length;
}
