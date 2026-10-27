#include "TcpConnectionState.h"
#include <cstdlib>
#include <iostream>
#include <vector>

void Require(bool value, const char* message) {
    if (!value) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

TcpSegment Segment(uint32_t sequence, uint32_t acknowledgment = 0, uint32_t payload = 0,
    bool fin = false, bool ack = false, bool syn = false, bool rst = false) {
    return {sequence, acknowledgment, payload, syn, fin, ack, rst};
}

void TestClose(bool clientFirst) {
    TcpConnectionState state;
    state.Observe(Segment(100, 0, 0, false, false, true), true);
    state.Observe(Segment(500, 101, 0, false, true, true), false);
    state.Observe(Segment(101, 501, 0, false, true), true);
    state.Observe(Segment(1000, 0, 20, true), clientFirst);
    Require(!state.IsClosed(), "one FIN must not close the connection");
    Require(state.IdleTimeout() == std::chrono::minutes(124), "half-close keeps established timeout");
    state.Observe(Segment(2000, 1020, 0, false, true), !clientFirst);
    Require(!state.IsClosed(), "ACK of data without FIN is insufficient");
    state.Observe(Segment(2000, 1021, 200, false, true), !clientFirst);
    Require(state.IdleTimeout() == std::chrono::minutes(124), "opposite direction can continue sending data");
    state.Observe(Segment(2200, 1021, 10, true, true), !clientFirst);
    Require(!state.IsClosed(), "second FIN needs its own ACK");
    Require(state.IdleTimeout() == std::chrono::minutes(4), "both FINs use closing timeout");
    state.Observe(Segment(1021, 2210, 0, false, true), clientFirst);
    Require(!state.IsClosed(), "second ACK must cover FIN sequence number");
    state.Observe(Segment(1021, 2211, 0, false, true), clientFirst);
    Require(state.IsClosed(), "both FINs acknowledged");
    state.Observe(Segment(1000, 0, 20, true), clientFirst);
    state.Observe(Segment(2200, 1021, 10, true, true), !clientFirst);
    Require(state.IsClosed(), "duplicate FINs do not reopen the connection");
    Require(state.IdleTimeout() == std::chrono::minutes(4), "closed mapping retained for retransmission");
    Require(!state.IsNewConnection(Segment(100, 0, 0, false, false, true)), "duplicate SYN is not a new connection");
    Require(state.IsNewConnection(Segment(9000, 0, 0, false, false, true)), "new SYN sequence replaces closing connection");
}

void TestSimultaneousCloseAndWrap() {
    TcpConnectionState state;
    state.Observe(Segment(0xFFFFFFFEu, 0, 1, true), true);
    state.Observe(Segment(20, 0xFFFFFFFFu, 0, true, true), false);
    state.Observe(Segment(0, 21, 0, false, true), true);
    Require(!state.IsClosed(), "ACK before wrapped FIN end is insufficient");
    state.Observe(Segment(21, 0, 0, false, true), false);
    Require(state.IsClosed(), "ACK zero acknowledges wrapped FIN");
    state.Observe(Segment(21, 0xFFFFFFF0u, 0, false, true), false);
    Require(state.IsClosed(), "old reordered ACK cannot undo close");
}

void TestReorderedAckAndReset() {
    TcpConnectionState state;
    state.Observe(Segment(70, 501, 0, false, true), true);
    state.Observe(Segment(500, 71, 0, false, true), false);
    state.Observe(Segment(70, 0, 0, true), true);
    state.Observe(Segment(500, 0, 0, true), false);
    Require(state.IsClosed(), "ACKs seen before delayed FINs must be retained");
    for (bool fromClient : {false, true}) {
        TcpConnectionState reset;
        reset.Observe(Segment(10, 0, 0, false, false, true), true);
        reset.Observe(Segment(20, 0, 0, false, false, false, true), fromClient);
        Require(reset.IdleTimeout() == std::chrono::minutes(4), "RST retains route briefly in both directions");
        Require(reset.IsNewConnection(Segment(11, 0, 0, false, false, true)), "new SYN after reset");
        Require(reset.IsNewConnection(Segment(10, 0, 0, false, false, true)), "SYN retry after reset starts fresh");
    }
    TcpConnectionState active;
    active.Observe(Segment(10, 0, 0, false, false, true), true);
    Require(!active.IsNewConnection(Segment(11, 0, 0, false, false, true)), "active connection is not replaced by unexpected SYN");
    active.Retire();
    Require(active.IdleTimeout() == std::chrono::minutes(4), "retired mapping cannot retain port for 124 minutes");
    TcpConnectionState fresh;
    Require(fresh.IdleTimeout() == std::chrono::minutes(124) && !fresh.IsClosed(), "new flow starts without old FIN state");
    fresh.Observe(Segment(100, 0, 5, true, false, true), true);
    fresh.Observe(Segment(500, 106, 0, true, true), false);
    fresh.Observe(Segment(107, 501, 0, false, true), true);
    Require(!fresh.IsClosed(), "SYN and FIN both consume sequence space");
    fresh.Observe(Segment(501, 107, 0, false, true), false);
    Require(fresh.IsClosed(), "ACK covers SYN, data and FIN");
}

void TestPacketParsing() {
    std::vector<uint8_t> packet(60, 0);
    packet[0] = 0x46;
    packet[3] = 57;
    packet[9] = 6;
    packet[28] = 0xFF;
    packet[29] = 0xFF;
    packet[30] = 0xFF;
    packet[31] = 0xFE;
    packet[35] = 42;
    packet[36] = 0x70;
    packet[37] = 0x11;
    TcpSegment segment;
    Require(TcpSegment::Parse(packet.data(), packet.size(), segment), "parse IPv4 and TCP options");
    Require(segment.sequence == 0xFFFFFFFEu && segment.acknowledgment == 42 &&
        segment.payloadSize == 5 && segment.fin && segment.ack && !segment.syn && !segment.rst,
        "parse flags, byte order and IP total length instead of buffer size");
    for (size_t length = 0; length < 57; ++length)
        Require(!TcpSegment::Parse(packet.data(), length, segment), "reject truncated packet");
    Require(!TcpSegment::Parse(nullptr, 100, segment), "reject null packet");
    packet[36] = 0x40;
    Require(!TcpSegment::Parse(packet.data(), packet.size(), segment), "reject short TCP header");
    packet[36] = 0xF0;
    Require(!TcpSegment::Parse(packet.data(), packet.size(), segment), "reject oversized TCP header");
    packet[36] = 0x70;
    packet[6] = 0x20;
    Require(!TcpSegment::Parse(packet.data(), packet.size(), segment), "reject first IP fragment");
    packet[6] = 0;
    packet[7] = 1;
    Require(!TcpSegment::Parse(packet.data(), packet.size(), segment), "reject non-first IP fragment");
    packet[7] = 0;
    packet[6] = 0x40;
    Require(TcpSegment::Parse(packet.data(), packet.size(), segment), "DF flag is allowed");
    packet[0] = 0x44;
    Require(!TcpSegment::Parse(packet.data(), packet.size(), segment), "reject invalid IHL");
    packet[0] = 0x66;
    Require(!TcpSegment::Parse(packet.data(), packet.size(), segment), "reject IPv6");
    packet[0] = 0x46;
    packet[9] = 17;
    Require(!TcpSegment::Parse(packet.data(), packet.size(), segment), "reject UDP in TCP state parser");
}

int main() {
    TestClose(true);
    TestClose(false);
    TestSimultaneousCloseAndWrap();
    TestReorderedAckAndReset();
    TestPacketParsing();
    std::cout << "TCP connection state tests passed\n";
}
