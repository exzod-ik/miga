#include "ConnectionKey.h"

size_t ConnectionKeyHash::operator()(const ConnectionKey& key) const {
    size_t hash = 0;
    std::apply([&](auto... value) {
        ((hash ^= std::hash<decltype(value)>{}(value) + 0x9e3779b9u + (hash << 6) + (hash >> 2)), ...);
    }, key);
    return hash;
}
