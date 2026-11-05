#include "AsyncTunnelSender.h"

AsyncTunnelSender::AsyncTunnelSender() : stop_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}

AsyncTunnelSender::~AsyncTunnelSender() {
    RequestStop();
    Drain();
    for (auto& slot : slots_) if (slot.operation.hEvent) CloseHandle(slot.operation.hEvent);
    if (stop_) CloseHandle(stop_);
}

void AsyncTunnelSender::SetApi(Api api) { api_ = api; }

void AsyncTunnelSender::SetErrorHandler(ErrorHandler handler) { error_ = std::move(handler); }

bool AsyncTunnelSender::Reset() {
    batching_ = false;
    batchData_.clear();
    batchCount_ = 0;
    batchData_.reserve(256 * 1024);
    for (auto& slot : slots_) slot.data.reserve(256 * 1024);
    return stop_ && ResetEvent(stop_);
}

void AsyncTunnelSender::RequestStop() { if (stop_) SetEvent(stop_); }

bool AsyncTunnelSender::Send(HANDLE handle, const uint8_t* data, size_t size, const WINDIVERT_ADDRESS* addresses, size_t count) {
    if (!stop_ || WaitForSingleObject(stop_, 0) != WAIT_TIMEOUT) return false;
    if (size == 0 || size > 256 * 1024 || count == 0 || count > 64) return Fail(ERROR_INVALID_PARAMETER);
    if (batching_) {
        if (batchCount_ && (batchHandle_ != handle || batchCount_ + count > 64 ||
            batchData_.size() + size > 256 * 1024)) Flush();
        batchHandle_ = handle;
        batchData_.insert(batchData_.end(), data, data + size);
        std::copy_n(addresses, count, batchAddresses_.begin() + batchCount_);
        batchCount_ += count;
        if (batchCount_ == 64) return Flush();
        return true;
    }
    return Submit(handle, data, size, addresses, count, nullptr);
}

void AsyncTunnelSender::BeginBatch() { batching_ = true; }

bool AsyncTunnelSender::EndBatch() { batching_ = false; return Flush(); }

uint64_t AsyncTunnelSender::TakeOverflows() { return overflows_.exchange(0); }

void AsyncTunnelSender::Reap() { for (auto& slot : slots_) Complete(slot, false); }

bool AsyncTunnelSender::Busy() const {
    for (const auto& slot : slots_) if (slot.pending) return true;
    return false;
}

void AsyncTunnelSender::Drain() {
    EndBatch();
    for (auto& slot : slots_) Complete(slot, true);
}

bool AsyncTunnelSender::Submit(HANDLE handle, const uint8_t* data, size_t size, const WINDIVERT_ADDRESS* addresses,
    size_t count, std::vector<uint8_t>* owned) {
    if (!stop_ || WaitForSingleObject(stop_, 0) != WAIT_TIMEOUT) return false;
    size_t available = slots_.size();
    for (size_t i = 0; i < slots_.size(); ++i) {
        const auto index = (next_ + i) % slots_.size();
        Complete(slots_[index], false);
        if (!slots_[index].pending) { available = index; break; }
    }
    if (available == slots_.size()) { ++overflows_; return false; }
    auto& slot = slots_[available];
    if (WaitForSingleObject(stop_, 0) != WAIT_TIMEOUT) return false;
    if (!slot.operation.hEvent) slot.operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!slot.operation.hEvent) return Fail(GetLastError());
    const auto event = slot.operation.hEvent;
    slot.operation = {};
    slot.operation.hEvent = event;
    ResetEvent(event);
    if (owned) slot.data.swap(*owned);
    else slot.data.assign(data, data + size);
    std::copy_n(addresses, count, slot.addresses.begin());
    slot.handle = handle;
    slot.sent = 0;
    slot.submitted = 0;
    next_ = (available + 1) % slots_.size();
    if (api_.send(handle, slot.data.data(), static_cast<UINT>(size), &slot.submitted, 0,
        slot.addresses.data(), static_cast<UINT>(count * sizeof(WINDIVERT_ADDRESS)), &slot.operation)) {
        return slot.submitted == size || Fail(ERROR_WRITE_FAULT);
    }
    const DWORD code = GetLastError();
    if (code != ERROR_IO_PENDING) return Fail(code);
    slot.pending = true;
    return true;
}

bool AsyncTunnelSender::Flush() {
    if (batchCount_ == 0) return true;
    const auto result = Submit(batchHandle_, batchData_.data(), batchData_.size(),
        batchAddresses_.data(), batchCount_, &batchData_);
    batchCount_ = 0;
    batchData_.clear();
    return result;
}

bool AsyncTunnelSender::Fail(DWORD code) { if (error_) error_(code); return false; }

void AsyncTunnelSender::Complete(Slot& slot, bool wait) {
    if (!slot.pending) return;
    if (!wait && WaitForSingleObject(slot.operation.hEvent, 0) == WAIT_TIMEOUT) return;
    if (wait) {
        HANDLE events[] = { slot.operation.hEvent, stop_ };
        const auto result = WaitForMultipleObjects(2, events, FALSE, INFINITE);
        if (result != WAIT_OBJECT_0) api_.cancel(slot.handle, &slot.operation);
    }
    if (!api_.result(slot.handle, &slot.operation, &slot.sent, wait ? TRUE : FALSE)) {
        const DWORD code = GetLastError();
        if (code == ERROR_IO_INCOMPLETE) return;
        if (code != ERROR_OPERATION_ABORTED) Fail(code);
    } else if (slot.sent != slot.data.size()) Fail(ERROR_WRITE_FAULT);
    slot.pending = false;
}
