#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>
#include "../../Shared/InternetChecksum.h"

class TunnelDatagram {
public:
    template<class Send>
    bool Build(const uint8_t* payload, size_t length, uint32_t source, uint32_t destination,
        uint16_t sourcePort, uint16_t destinationPort, uint16_t id, uint32_t mtu, Send send) {
        if (!payload || length == 0 || length > 65507 || mtu < 68 || source == 0 || destination == 0) return false;
        datagram_.assign(28 + length, 0);
        auto* ip = datagram_.data();
        ip[0] = 0x45;
        Write16(ip + 2, static_cast<uint16_t>(datagram_.size()));
        Write16(ip + 4, id);
        ip[8] = 64;
        ip[9] = 17;
        std::memcpy(ip + 12, &source, 4);
        std::memcpy(ip + 16, &destination, 4);
        Write16(ip + 20, sourcePort);
        Write16(ip + 22, destinationPort);
        Write16(ip + 24, static_cast<uint16_t>(8 + length));
        std::memcpy(ip + 28, payload, length);
        InternetChecksum udp;
        udp.Add(ip + 12, 8);
        const uint8_t pseudo[] = { 0, 17, ip[24], ip[25] };
        udp.Add(pseudo, sizeof(pseudo));
        udp.Add(ip + 20, 8 + length);
        auto checksum = udp.Value();
        if (checksum == 0) checksum = 0xffff;
        std::memcpy(ip + 26, &checksum, 2);
        if (datagram_.size() <= mtu) {
            InternetChecksum header;
            header.Add(ip, 20);
            checksum = header.Value();
            std::memcpy(ip + 10, &checksum, 2);
            return send(datagram_.data(), datagram_.size(), 1);
        }
        const size_t fragmentSize = (std::min)(size_t(mtu), size_t(65535)) - 20;
        size_t offset = 0;
        batch_.clear();
        size_t count = 0;
        while (offset < 8 + length) {
            const auto remaining = 8 + length - offset;
            const auto size = remaining > fragmentSize ? fragmentSize & ~size_t(7) : remaining;
            const auto start = batch_.size();
            batch_.resize(start + 20 + size);
            auto* fragment = batch_.data() + start;
            std::memcpy(fragment, ip, 20);
            Write16(fragment + 2, static_cast<uint16_t>(20 + size));
            Write16(fragment + 6, static_cast<uint16_t>((offset / 8) | (size < remaining ? 0x2000 : 0)));
            InternetChecksum header;
            header.Add(fragment, 20);
            checksum = header.Value();
            std::memcpy(fragment + 10, &checksum, 2);
            std::memcpy(fragment + 20, ip + 20 + offset, size);
            offset += size;
            ++count;
            if (count == 64 || offset == 8 + length) {
                if (!send(batch_.data(), batch_.size(), count)) return false;
                batch_.clear();
                count = 0;
            }
        }
        return true;
    }
private:
    std::vector<uint8_t> datagram_;
    std::vector<uint8_t> batch_;
    static void Write16(uint8_t* bytes, uint16_t value) {
        bytes[0] = static_cast<uint8_t>(value >> 8);
        bytes[1] = static_cast<uint8_t>(value);
    }
};
