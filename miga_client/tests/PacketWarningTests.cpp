#include "PacketWarning.h"
#include <cassert>
#include <iostream>

int main() {
    PacketWarningSample sample;
    assert(FormatPacketWarning(sample).find("reason=invalid_ipv4") == 0);
    sample.captured = 64;
    sample.size = 1200;
    sample.ageMs = 6500;
    sample.packetTimestampQpc = 123456789;
    auto& p = sample.header;
    p[0] = 0x4f;
    p[2] = 4;
    p[3] = 176;
    p[9] = 17;
    p[12] = 192; p[13] = 0; p[14] = 2; p[15] = 1;
    p[16] = 198; p[17] = 51; p[18] = 100; p[19] = 2;
    p[60] = 0x12; p[61] = 0x34; p[62] = 0xab; p[63] = 0xcd;
    assert(FormatPacketWarning(sample) == "protocol=UDP src=192.0.2.1:4660 dst=198.51.100.2:43981 size=1200 age_ms=6500 packet_timestamp_qpc=123456789 owner_lookup=not_recorded");
    p[9] = 6;
    assert(FormatPacketWarning(sample).find("protocol=TCP") == 0);
    sample.captured = 80;
    p[73] = 0x14;
    assert(FormatPacketWarning(sample).find("tcp_flags=0x14") != std::string::npos);
    p[7] = 1;
    assert(FormatPacketWarning(sample).find("src=192.0.2.1:unknown dst=198.51.100.2:unknown") != std::string::npos);
    p[7] = 0;
    sample.captured = 62;
    assert(FormatPacketWarning(sample).find(":unknown") != std::string::npos);
    sample.captured = 81;
    assert(FormatPacketWarning(sample).find("reason=invalid_ipv4") == 0);
    sample.captured = 64;
    sample.size = 50;
    assert(FormatPacketWarning(sample).find("reason=invalid_ipv4") == 0);
    std::cout << "Packet warning tests passed\n";
}