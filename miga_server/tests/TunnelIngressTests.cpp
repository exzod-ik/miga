#include "TunnelIngress.h"
#include <array>
#include <cassert>
#include <iostream>

int main() {
    std::array<uint8_t, 80> packet{};
    packet[0] = 0x46;
    packet[3] = 64;
    packet[6] = 0x40;
    packet[9] = 17;
    packet[24] = 0xab;
    packet[25] = 0xcd;
    packet[26] = 0x13;
    packet[27] = 0x89;
    packet[29] = 40;
    TunnelIngress datagram{};
    const auto parse = [&](size_t size = 80) {
        return TunnelIngress::Parse(packet.data(), size, 5001, 5002, datagram);
    };
    assert(parse() && datagram.payload == packet.data() + 32 && datagram.length == 32);
    assert(datagram.clientPort == 0xabcd && datagram.serverPort == 5001);
    for (size_t i = 0; i < 64; ++i) assert(!parse(i));
    packet[27] = 0x8a;
    assert(parse() && datagram.serverPort == 5002);
    packet[27] = 0x8b;
    assert(!parse());
    packet[27] = 0x89;
    for (uint8_t length = 0; length < 28; ++length) {
        packet[29] = length;
        assert(!parse());
    }
    packet[29] = 41;
    assert(!parse());
    packet[29] = 40;
    packet[6] = 0x20;
    assert(!parse());
    packet[6] = 0;
    packet[7] = 1;
    assert(!parse());
    packet[7] = 0;
    packet[0] = 0x44;
    assert(!parse());
    packet[0] = 0x66;
    assert(!parse());
    packet[0] = 0x46;
    packet[9] = 6;
    assert(!parse());
    packet[9] = 17;
    packet[12] = 10;
    packet[15] = 2;
    assert(!parse());
    std::cout << "Tunnel ingress tests passed\n";
}
