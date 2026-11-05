#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <tuple>

using ConnectionKey = std::tuple<uint32_t, uint16_t, uint32_t, uint16_t, uint8_t>;

struct ConnectionKeyHash {
    size_t operator()(const ConnectionKey& key) const;
};
