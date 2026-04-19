#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <cstring>
#include "NetworkStructures.h"
#include "UdpPacketAssembler.h"

using namespace std;

UdpPacketAssembler::FragmentedPacket::FragmentedPacket()
    : totalDataSize(0)
    , receivedSize(0)
    , ipHdrLen(0)
    , ipId(0)
    , protocol(0)
    , srcIp(0)
    , dstIp(0)
    , lastUpdate(chrono::steady_clock::now())
    , completed(false)
{
}

UdpPacketAssembler::UdpPacketAssembler(uint32_t timeoutMs)
    : timeoutMs_(timeoutMs)
{
}

// adding packet
bool UdpPacketAssembler::AddIpPacket(const uint8_t* packet, size_t len) {
    lock_guard<mutex> lock(mtx_);

    const IP_HEADER* ip = reinterpret_cast<const IP_HEADER*>(packet);
    uint16_t ipTotalLen = ntohs(ip->total_len);
    if (ipTotalLen > len)
        return false;

    uint8_t ipHdrLen = (ip->ver_hlen & 0x0F) * 4;
    if (ipHdrLen < sizeof(IP_HEADER) || ipHdrLen > ipTotalLen)
        return false;

    // packet is fragmented?
    uint16_t flags_offset = ntohs(ip->flags_offset);
    bool isFragment = (flags_offset & 0x1FFF) != 0;
    bool moreFragments = (flags_offset & 0x2000) != 0;

    // is it udp?
    if (ip->protocol != 17 && !isFragment) {
        return false;
    }

    bool result = false;

    if (isFragment || moreFragments) {
        // add fragment to assemble full udp packet
        if (AddFragment(packet, ipTotalLen, ipHdrLen, flags_offset, moreFragments)) {
            result = true; // udp packet assembled
        }
    }
    else {
        if (ip->protocol == 17) {
            if (ipTotalLen >= ipHdrLen + sizeof(UDP_HEADER)) {
                const uint8_t* udpData = packet + ipHdrLen;
                const UDP_HEADER* udp = reinterpret_cast<const UDP_HEADER*>(udpData);
                uint16_t udpLen = ntohs(udp->length);
                if (udpLen >= sizeof(UDP_HEADER) && ipTotalLen >= ipHdrLen + udpLen) {
                    UdpPacketInfo* info = CreateUdpPacketInfo(
                        ip->src_ip, ip->dst_ip,
                        udp->src_port, udp->dst_port,
                        udpData + sizeof(UDP_HEADER), udpLen - sizeof(UDP_HEADER));
                    if (info) {
                        completedPackets_.push(info);
                        result = true;
                    }
                }
            }
        }
    }

    CleanupTimeoutFragments();

    return result;
}

UdpPacketInfo* UdpPacketAssembler::GetCompleteUdpPacket() {
    lock_guard<mutex> lock(mtx_);
    if (completedPackets_.empty())
        return nullptr;
    UdpPacketInfo* pkt = completedPackets_.front();
    completedPackets_.pop();
    return pkt;
}

void UdpPacketAssembler::ReleaseUdpPacket(UdpPacketInfo* pkt) {
    if (pkt) {
        delete[] pkt->payload;
        delete pkt;
    }
}

// adding fragment of udp packet to cache
bool UdpPacketAssembler::AddFragment(const uint8_t* ipData, uint16_t ipTotalLen,
    uint8_t ipHdrLen, uint16_t flags_offset, bool moreFragments) {
    const IP_HEADER* ip = reinterpret_cast<const IP_HEADER*>(ipData);
    uint16_t fragmentOffset = (flags_offset & 0x1FFF) * 8;
    uint16_t fragmentDataLen = ipTotalLen - ipHdrLen;

    uint64_t key = (static_cast<uint64_t>(ip->src_ip) << 32) ^
        (static_cast<uint64_t>(ip->dst_ip) << 16) ^
        (static_cast<uint64_t>(ip->id) << 8) ^
        (static_cast<uint64_t>(ip->protocol));

    auto it = fragments_.find(key);
    if (it == fragments_.end()) {
        FragmentedPacket fp;
        fp.ipHdrLen = ipHdrLen;
        fp.ipId = ip->id;
        fp.protocol = ip->protocol;
        fp.srcIp = ip->src_ip;
        fp.dstIp = ip->dst_ip;
        fp.lastUpdate = chrono::steady_clock::now();

        if (fragmentOffset == 0) {
            fp.firstFragment.assign(ipData, ipData + ipTotalLen);
        }

        if (fragmentOffset == 0 && !moreFragments) {
            fp.totalDataSize = fragmentDataLen;
            fp.fragmentsMap[fragmentOffset] = vector<uint8_t>(ipData + ipHdrLen, ipData + ipTotalLen);
            fp.receivedSize = fragmentDataLen;
            fp.completed = true;
        }
        else {
            vector<uint8_t> data(ipData + ipHdrLen, ipData + ipTotalLen);
            fp.fragmentsMap[fragmentOffset] = move(data);
            fp.receivedSize = fragmentDataLen;
        }

        fragments_.emplace(key, move(fp));
        it = fragments_.find(key);
    }

    FragmentedPacket& fp = it->second;
    fp.lastUpdate = chrono::steady_clock::now();

    if (fp.completed)
        return false;

    if (fragmentOffset == 0 && fp.firstFragment.empty()) {
        fp.firstFragment.assign(ipData, ipData + ipTotalLen);
        fp.ipHdrLen = ipHdrLen;
    }

    vector<uint8_t> data(ipData + ipHdrLen, ipData + ipTotalLen);
    auto insertResult = fp.fragmentsMap.emplace(fragmentOffset, move(data));
    if (insertResult.second)
        fp.receivedSize += fragmentDataLen;
    else
        insertResult.first->second = move(data);
    if (!moreFragments) { // it's last fragment
        fp.totalDataSize = fragmentOffset + fragmentDataLen;
    }

    // if udp packet assembled
    if (fp.totalDataSize > 0 && fp.receivedSize >= fp.totalDataSize) {
        vector<uint8_t> fullData(fp.totalDataSize);
        for (const auto& entry : fp.fragmentsMap) {
            uint16_t offset = entry.first;
            const auto& fragData = entry.second;
            if (offset + fragData.size() <= fp.totalDataSize) {
                memcpy(fullData.data() + offset, fragData.data(), fragData.size());
            }
        }

        if (!fp.firstFragment.empty()) {
            const IP_HEADER* firstIp = reinterpret_cast<const IP_HEADER*>(fp.firstFragment.data());
            uint8_t firstIpHdrLen = (firstIp->ver_hlen & 0x0F) * 4;
            size_t ipPacketSize = firstIpHdrLen + fp.totalDataSize;

            vector<uint8_t> fullIpPacket(ipPacketSize);
            memcpy(fullIpPacket.data(), fp.firstFragment.data(), firstIpHdrLen);
            memcpy(fullIpPacket.data() + firstIpHdrLen, fullData.data(), fp.totalDataSize);

            if (fp.protocol == 17 && ipPacketSize >= firstIpHdrLen + sizeof(UDP_HEADER)) {
                const uint8_t* udpData = fullIpPacket.data() + firstIpHdrLen;
                const UDP_HEADER* udp = reinterpret_cast<const UDP_HEADER*>(udpData);
                uint16_t udpLen = ntohs(udp->length);
                if (udpLen >= sizeof(UDP_HEADER) && ipPacketSize >= firstIpHdrLen + udpLen) {
                    UdpPacketInfo* info = CreateUdpPacketInfo(
                        fp.srcIp, fp.dstIp,
                        udp->src_port, udp->dst_port,
                        udpData + sizeof(UDP_HEADER), udpLen - sizeof(UDP_HEADER));
                    if (info) {
                        completedPackets_.push(info);
                        fp.completed = true;
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

UdpPacketInfo* UdpPacketAssembler::CreateUdpPacketInfo(uint32_t srcIp, uint32_t dstIp,
    uint16_t srcPort, uint16_t dstPort, const uint8_t* payload, size_t payloadSize) {
    UdpPacketInfo* info = new UdpPacketInfo;
    info->srcIp = srcIp;
    info->dstIp = dstIp;
    info->srcPort = srcPort;
    info->dstPort = dstPort;
    info->payloadSize = payloadSize;
    if (payloadSize > 0) {
        info->payload = new uint8_t[payloadSize];
        memcpy(info->payload, payload, payloadSize);
    }
    else {
        info->payload = nullptr;
    }
    return info;
}

void UdpPacketAssembler::CleanupTimeoutFragments() {
    auto now = chrono::steady_clock::now();
    for (auto it = fragments_.begin(); it != fragments_.end(); ) {
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - it->second.lastUpdate).count();
        if (elapsed > static_cast<int64_t>(timeoutMs_)) {
            it = fragments_.erase(it);
        }
        else {
            ++it;
        }
    }
}