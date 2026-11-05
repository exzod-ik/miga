#pragma once

#include <cstdint>
#include <array>
#include <memory>
#include <mutex>
#include <vector>

class PacketBufferPool {
    struct State {
        std::mutex mutex;
        std::array<std::vector<std::unique_ptr<std::vector<uint8_t>>>, 6> buffers;
        State();
    };
    std::shared_ptr<State> state_ = std::make_shared<State>();
public:
    std::shared_ptr<std::vector<uint8_t>> Copy(const uint8_t* data, size_t size);
};
