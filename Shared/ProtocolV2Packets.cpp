#include "ProtocolV2Packets.h"
#include "InternetChecksum.h"
#include <algorithm>
#include <cstring>

namespace miga::v2 {
namespace {
void Set16(uint8_t* p, uint16_t value) {p[0] = uint8_t(value >> 8); p[1] = uint8_t(value);}
void Checksum(uint8_t* p, size_t length, size_t position) {
    p[position] = p[position + 1] = 0;
    InternetChecksum checksum;
    checksum.Add(p, length);
    const auto value = checksum.Value();
    std::memcpy(p + position, &value, 2);
}
Bytes CopyOptions(const uint8_t* packet, size_t header) {
    Bytes out(packet, packet + 20);
    for (size_t at = 20; at < header;) {
        const auto option = packet[at];
        if (!option) break;
        if (option == 1) {++at; continue;}
        if (at + 2 > header || packet[at + 1] < 2 || packet[at + 1] > header - at) return {};
        const auto size = packet[at + 1];
        if (option & 0x80) out.insert(out.end(), packet + at, packet + at + size);
        at += size;
    }
    while (out.size() % 4) out.push_back(0);
    out[0] = uint8_t(0x40 | out.size() / 4);
    return out;
}
}
bool FragmentInner(const uint8_t* p, size_t length, std::vector<Bytes>& fragments, Bytes& icmp) {
    fragments.clear();
    icmp.clear();
    if (!p || length < 20 || length > 65535 || (p[0] >> 4) != 4 || Get16(p + 2) != length) return false;
    const size_t header = size_t(p[0] & 15) * 4;
    if (header < 20 || header > length || (p[9] != 6 && p[9] != 17)) return false;
    const auto flags = Get16(p + 6);
    if ((flags & 0x8000) || ((flags & 0x4000) && (flags & 0x3fff))) return false;
    if (length <= MaxInner) { fragments.emplace_back(p, p + length); return true; }
    if (flags & 0x4000) {
        const auto source = Get32(p + 12), destination = Get32(p + 16);
        const bool forbidden = !source || (source >> 24) == 127 || (source >> 28) >= 14 || source == 0xffffffff || (destination >> 28) >= 14 || destination == 0xffffffff || (flags & 0x1fff);
        if (forbidden) return false;
        const auto quote = std::min(length, header + 8);
        icmp.assign(28 + quote, uint8_t(0));
        icmp[0] = 0x45; Set16(icmp.data() + 2, uint16_t(icmp.size())); icmp[8] = 64; icmp[9] = 1;
        std::copy_n(p + 16, 4, icmp.data() + 12); std::copy_n(p + 12, 4, icmp.data() + 16);
        icmp[20] = 3; icmp[21] = 4; Set16(icmp.data() + 26, uint16_t(MaxInner)); std::copy_n(p, quote, icmp.data() + 28);
        Checksum(icmp.data(), 20, 10);
        Checksum(icmp.data() + 20, icmp.size() - 20, 2);
        return true;
    }
    auto copied = CopyOptions(p, header);
    if (copied.empty()) return false;
    size_t at = 0;
    const auto payload = length - header;
    while (at < payload) {
        const auto& base = at == 0 ? Bytes(p, p + header) : copied;
        const auto remaining = payload - at;
        const auto capacity = MaxInner - base.size();
        const auto size = remaining > capacity ? capacity & ~size_t(7) : remaining;
        Bytes fragment = base;
        fragment.insert(fragment.end(), p + header + at, p + header + at + size);
        const auto offset = size_t(flags & 0x1fff) * 8 + at; if (offset / 8 > 8191) {fragments.clear(); return false;}
        Set16(fragment.data() + 2, uint16_t(fragment.size())); Set16(fragment.data() + 6, uint16_t(offset / 8 | (at + size < payload || (flags & 0x2000) ? 0x2000 : 0)));
        Checksum(fragment.data(), base.size(), 10);
        fragments.push_back(std::move(fragment));
        at += size;
    }
    return true;
}
Ipv4Reassembler::Result Ipv4Reassembler::Add(const uint8_t* p, size_t length, Bytes& complete, const std::string& context) {
    complete.clear();
    if (context.size() > 64) return Result::Rejected;
    if (!p || length < 20 || length > 65535 || (p[0] >> 4) != 4 || Get16(p + 2) != length) return Result::Rejected;
    const size_t header = size_t(p[0] & 15) * 4;
    if (header < 20 || header > length) return Result::Rejected;
    const auto fragment = Get16(p + 6);
    if (fragment & 0x8000) return Result::Rejected;
    if (!(fragment & 0x3fff)) {
        complete.assign(p, p + length);
        return Result::Complete;
    }
    if ((fragment & 0xc000) || (p[9] != 6 && p[9] != 17)) return Result::Rejected;
    const auto start = size_t(fragment & 0x1fff) * 8, size = length - header;
    if (!size || ((fragment & 0x2000) && size % 8) || start + size > 65515) return Result::Rejected;
    const auto now = std::chrono::steady_clock::now();
    size_t budget = 128;
    while (budget-- && !expiry_.empty() && now - expiry_.front().second > std::chrono::seconds(30)) {
        const auto expired = std::move(expiry_.front());
        expiry_.pop_front();
        const auto found = entries_.find(expired.first);
        if (found != entries_.end() && found->second.created == expired.second) {
            bytes_ -= found->second.payload.size() * 2 + found->second.header.size();
            entries_.erase(found);
        }
    }
    std::string key(1, char(context.size()));
    key += context;
    key.append(reinterpret_cast<const char*>(p + 12), 8);
    key.push_back(char(p[9]));
    key.append(reinterpret_cast<const char*>(p + 4), 2);
    auto found = entries_.find(key);
    if (found == entries_.end()) {
        if (entries_.size() >= 1024 || bytes_ >= 4 * 1024 * 1024) return Result::Rejected;
        found = entries_.emplace(key, Entry{}).first;
        found->second.created = now;
        expiry_.emplace_back(key, now);
        found->second.expiry = std::prev(expiry_.end());
    }
    auto& entry = found->second;
    if (entry.invalid) return Result::Rejected;
    const auto end = start + size;
    const auto growth = end > entry.payload.size() ? (end - entry.payload.size()) * 2 : 0;
    const auto headerGrowth = !start && entry.header.empty() ? header : 0;
    if (growth + headerGrowth > 4 * 1024 * 1024 - bytes_) {entry.invalid = true; return Result::Rejected;}
    if (entry.hasEnd && end > entry.end) {entry.invalid = true; return Result::Rejected;}
    if (!(fragment & 0x2000)) {
        if ((entry.hasEnd && entry.end != end) || end < entry.payload.size()) {
            entry.invalid = true;
            return Result::Rejected;
        }
        entry.end = end;
        entry.hasEnd = true;
    }
    entry.payload.resize(std::max(entry.payload.size(), end));
    entry.present.resize(entry.payload.size());
    bytes_ += growth;
    if (std::find(entry.present.begin() + start, entry.present.begin() + end, uint8_t(1)) != entry.present.begin() + end) {entry.invalid = true; return Result::Rejected;}
    if (!start) {
        if (!entry.header.empty()) {entry.invalid = true; return Result::Rejected;}
        entry.header.assign(p, p + header);
        bytes_ += header;
    }
    std::copy_n(p + header, size, entry.payload.data() + start);
    std::fill(entry.present.begin() + start, entry.present.begin() + end, uint8_t(1));
    entry.received += size;
    if (!entry.hasEnd || entry.header.empty() || entry.received != entry.end) return Result::Waiting;
    if (entry.end + entry.header.size() > 65535) {entry.invalid = true; return Result::Rejected;}
    complete = entry.header;
    complete.insert(complete.end(), entry.payload.begin(), entry.payload.begin() + entry.end);
    Set16(complete.data() + 2, uint16_t(complete.size()));
    Set16(complete.data() + 6, 0);
    Checksum(complete.data(), entry.header.size(), 10);
    bytes_ -= entry.payload.size() * 2 + entry.header.size();
    expiry_.erase(entry.expiry);
    entries_.erase(found);
    return Result::Complete;
}
void Ipv4Reassembler::Clear() {entries_.clear(); expiry_.clear(); bytes_ = 0;}
}
