#pragma once

#include "RuntimeTypes.h"
#include <iphlpapi.h>

namespace miga::runtime {
struct WindowsSnapshot {
    struct Entry { SocketTuple tuple; DWORD pid; };
    std::vector<Entry> entries;
    DWORD Read(bool udp);
    using Index = std::unordered_multimap<FlowKey, DWORD, FlowKeyHash>;
    Index MakeIndex() const;
    static bool Contains(const Index& index, const SocketTuple& tuple, const ProcessOwner& process);
};
}
