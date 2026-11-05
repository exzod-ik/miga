#include "runtime/WindowsSnapshot.h"

namespace miga::runtime {
DWORD WindowsSnapshot::Read(bool udp) {
    entries.clear();
    DWORD size = 0;
    std::vector<uint8_t> buffer;
    auto read = [&] {
        return udp ? GetExtendedUdpTable(buffer.empty() ? nullptr : buffer.data(), &size, FALSE,
            AF_INET, UDP_TABLE_OWNER_PID, 0) : GetExtendedTcpTable(buffer.empty() ? nullptr : buffer.data(),
            &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    };
    DWORD error = read();
    for (int attempt = 0; error == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt) {
        if (size > 16 * 1024 * 1024) return ERROR_NOT_ENOUGH_MEMORY;
        buffer.resize(size); error = read();
    }
    if (error != NO_ERROR) return error;
    if (buffer.size() < sizeof(DWORD)) return ERROR_INVALID_DATA;
    if (udp) {
        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        if (table->dwNumEntries > (buffer.size() - offsetof(MIB_UDPTABLE_OWNER_PID, table)) / sizeof(MIB_UDPROW_OWNER_PID))
            return ERROR_INVALID_DATA;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            entries.push_back({{17, ntohl(row.dwLocalAddr), ntohs(static_cast<u_short>(row.dwLocalPort)), 0, 0}, row.dwOwningPid});
        }
    } else {
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        if (table->dwNumEntries > (buffer.size() - offsetof(MIB_TCPTABLE_OWNER_PID, table)) / sizeof(MIB_TCPROW_OWNER_PID))
            return ERROR_INVALID_DATA;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwState == MIB_TCP_STATE_CLOSED ||
                row.dwState == MIB_TCP_STATE_TIME_WAIT || row.dwState == MIB_TCP_STATE_DELETE_TCB || !row.dwOwningPid) continue;
            entries.push_back({{6, ntohl(row.dwLocalAddr), ntohs(static_cast<u_short>(row.dwLocalPort)),
                ntohl(row.dwRemoteAddr), ntohs(static_cast<u_short>(row.dwRemotePort))}, row.dwOwningPid});
        }
    }
    return NO_ERROR;
}

WindowsSnapshot::Index WindowsSnapshot::MakeIndex() const {
    Index result; result.reserve(entries.size());
    for (const auto& item : entries) result.emplace(FlowKey::From(item.tuple), item.pid);
    return result;
}

bool WindowsSnapshot::Contains(const Index& index, const SocketTuple& tuple, const ProcessOwner& process) {
    if (!process || !process->isAlive()) return false;
    if (!tuple.localIp) {
        for (const auto& item : index) {
            const SocketTuple candidate{item.first.proto, item.first.srcIp, item.first.srcPort, item.first.dstIp, item.first.dstPort};
            if (item.second == process->pid && Matches(tuple, candidate)) return true;
        }
        return false;
    }
    const auto range = index.equal_range(FlowKey::From(tuple));
    for (auto it = range.first; it != range.second; ++it) if (it->second == process->pid) return true;
    return false;
}

}
