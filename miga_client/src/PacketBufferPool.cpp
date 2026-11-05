#include "PacketBufferPool.h"

PacketBufferPool::State::State() {
    for (size_t i = 0; i < buffers.size(); ++i) buffers[i].reserve(i == 0 ? 2048 : 32);
}

std::shared_ptr<std::vector<uint8_t>> PacketBufferPool::Copy(const uint8_t* data, size_t size) {
    std::unique_ptr<std::vector<uint8_t>> buffer;
    size_t bucket = 0;
    size_t capacity = 2048;
    while (capacity < size && bucket < 5) { capacity *= 2; ++bucket; }
    {
        std::lock_guard lock(state_->mutex);
        auto& free = state_->buffers[bucket];
        if (!free.empty()) { buffer = std::move(free.back()); free.pop_back(); }
    }
    if (!buffer) {
        buffer = std::make_unique<std::vector<uint8_t>>();
        buffer->reserve(capacity);
    }
    buffer->assign(data, data + size);
    return {buffer.release(), [state = state_, bucket, capacity](std::vector<uint8_t>* value) {
        std::unique_ptr<std::vector<uint8_t>> released(value);
        released->clear();
        std::lock_guard lock(state->mutex);
        auto& free = state->buffers[bucket];
        if (free.size() < (bucket == 0 ? 2048u : 32u) && released->capacity() <= capacity)
            free.push_back(std::move(released));
    }};
}
