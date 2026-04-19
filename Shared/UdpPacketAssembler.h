#pragma once

#include <queue>
#include <unordered_map>
#include <mutex>

struct UdpPacketInfo {
    uint32_t srcIp;
    uint32_t dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t* payload;
    size_t   payloadSize;
};

class UdpPacketAssembler {
public:
    explicit UdpPacketAssembler(uint32_t timeoutMs = 30000);

    bool AddIpPacket(const uint8_t* packet, size_t len);
    UdpPacketInfo* GetCompleteUdpPacket();
    void ReleaseUdpPacket(UdpPacketInfo* pkt);

private:
    struct FragmentedPacket {
        std::vector<uint8_t> firstFragment;
        std::unordered_map<uint16_t, std::vector<uint8_t>> fragmentsMap;
        size_t totalDataSize;
        size_t receivedSize;
        uint8_t ipHdrLen;
        uint16_t ipId;
        uint8_t protocol;
        uint32_t srcIp;
        uint32_t dstIp;
        std::chrono::steady_clock::time_point lastUpdate;
        bool completed; 

        FragmentedPacket();
    };

    bool AddFragment(const uint8_t* ipData, uint16_t ipTotalLen, uint8_t ipHdrLen, uint16_t flags_offset, bool moreFragments);
    UdpPacketInfo* CreateUdpPacketInfo(uint32_t srcIp, uint32_t dstIp, uint16_t srcPort, uint16_t dstPort, const uint8_t* payload, size_t payloadSize);

    void CleanupTimeoutFragments();

    std::unordered_map<uint64_t, FragmentedPacket> fragments_;
    std::queue<UdpPacketInfo*> completedPackets_;
    std::mutex mtx_;
    uint32_t timeoutMs_;
};