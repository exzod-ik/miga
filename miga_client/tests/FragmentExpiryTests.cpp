#include <winsock2.h>
#include "UdpPacketAssembler.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

void Require(bool value, const char* message) {
    if (!value) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

std::vector<uint8_t> Fragment(uint16_t id, bool first) {
    std::vector<uint8_t> packet(first ? 36 : 28, 0);
    packet[0] = 0x45;
    packet[3] = static_cast<uint8_t>(packet.size());
    packet[4] = static_cast<uint8_t>(id >> 8);
    packet[5] = static_cast<uint8_t>(id);
    packet[6] = first ? 0x20 : 0;
    packet[7] = first ? 0 : 2;
    packet[9] = 17;
    packet[12] = 192;
    packet[16] = 198;
    if (first) {
        packet[21] = 10;
        packet[23] = 20;
        packet[25] = 24;
    }
    return packet;
}

int main() {
    UdpPacketAssembler assembler(20);
    Require(!assembler.AddIpPacket(nullptr, 0), "null packet");
    auto first = Fragment(1, true);
    auto last = Fragment(1, false);
    Require(!assembler.AddIpPacket(first.data(), first.size()), "incomplete fragment");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assembler.CleanupExpired();
    Require(!assembler.AddIpPacket(last.data(), last.size()), "expired first fragment cannot complete datagram");
    Require(assembler.TakeExpiredIncompleteCount() == 1, "expired incomplete datagram counted");
    Require(assembler.TakeExpiredIncompleteCount() == 0, "expiry counter drained");
    Require(assembler.AddIpPacket(first.data(), first.size()), "out-of-order fragments complete after expiration");
    auto* result = assembler.GetCompleteUdpPacket();
    Require(result && result->payloadSize == 16, "assembled payload length");
    assembler.ReleaseUdpPacket(result);
    Require(!assembler.AddIpPacket(first.data(), first.size()), "completed entry still suppresses immediate duplicate");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    Require(!assembler.AddIpPacket(first.data(), first.size()), "same ID can start again after expiry");
    Require(assembler.TakeExpiredIncompleteCount() == 0, "completed datagram expiry is not loss");
    Require(assembler.AddIpPacket(last.data(), last.size()), "reused ID completes");
    result = assembler.GetCompleteUdpPacket();
    Require(result != nullptr, "reused ID produces packet");
    assembler.ReleaseUdpPacket(result);
    for (uint16_t id = 2; id < 1000; ++id) {
        auto packet = Fragment(id, true);
        assembler.AddIpPacket(packet.data(), packet.size());
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    first = Fragment(1000, true);
    last = Fragment(1000, false);
    Require(!assembler.AddIpPacket(first.data(), first.size()), "cleanup of many expired entries");
    Require(assembler.AddIpPacket(last.data(), last.size()), "expiry list remains valid after mass cleanup");
    result = assembler.GetCompleteUdpPacket();
    Require(result != nullptr, "mass cleanup completion");
    assembler.ReleaseUdpPacket(result);
    std::cout << "Fragment expiry tests passed\n";
}
