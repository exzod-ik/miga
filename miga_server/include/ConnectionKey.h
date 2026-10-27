#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <tuple>

using ConnectionKey = std::tuple<uint32_t, uint16_t, uint32_t, uint16_t, uint8_t>;

struct ConnectionKeyHash {
    size_t operator()(const ConnectionKey& key) const {
        size_t hash = 0;
        std::apply([&](auto... value) {
            ((hash ^= std::hash<decltype(value)>{}(value) + 0x9e3779b9u + (hash << 6) + (hash >> 2)), ...);
        }, key);
        return hash;
    }
};
