#pragma once

#include <winsock2.h>
#include <windivert.h>
#include <array>
#include <algorithm>
#include <vector>
#include <functional>

class AsyncTunnelSender {
public:
    struct Api {
        decltype(&WinDivertSendEx) send = &WinDivertSendEx;
        decltype(&GetOverlappedResult) result = &GetOverlappedResult;
        decltype(&CancelIoEx) cancel = &CancelIoEx;
    };
    using ErrorHandler = std::function<void(DWORD)>;
    AsyncTunnelSender() : stop_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}
    ~AsyncTunnelSender() {
        RequestStop();
        Drain();
        for (auto& slot : slots_) if (slot.operation.hEvent) CloseHandle(slot.operation.hEvent);
        if (stop_) CloseHandle(stop_);
    }
    AsyncTunnelSender(const AsyncTunnelSender&) = delete;
    AsyncTunnelSender& operator=(const AsyncTunnelSender&) = delete;
    void SetApi(Api api) { api_ = api; }
    void SetErrorHandler(ErrorHandler handler) { error_ = std::move(handler); }
    bool Reset() { return stop_ && ResetEvent(stop_); }
    void RequestStop() { if (stop_) SetEvent(stop_); }
    bool Send(HANDLE handle, const uint8_t* data, size_t size, const WINDIVERT_ADDRESS* addresses, size_t count) {
        if (!stop_ || WaitForSingleObject(stop_, 0) != WAIT_TIMEOUT) return false;
        if (size == 0 || size > 256 * 1024 || count == 0 || count > 64) return Fail(ERROR_INVALID_PARAMETER);
        auto& slot = slots_[next_];
        Complete(slot, true);
        if (WaitForSingleObject(stop_, 0) != WAIT_TIMEOUT) return false;
        if (!slot.operation.hEvent) slot.operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!slot.operation.hEvent) return Fail(GetLastError());
        const auto event = slot.operation.hEvent;
        slot.operation = {};
        slot.operation.hEvent = event;
        ResetEvent(event);
        slot.data.assign(data, data + size);
        std::copy_n(addresses, count, slot.addresses.begin());
        slot.handle = handle;
        slot.sent = 0;
        slot.submitted = 0;
        next_ = (next_ + 1) % slots_.size();
        if (api_.send(handle, slot.data.data(), static_cast<UINT>(size), &slot.submitted, 0,
            slot.addresses.data(), static_cast<UINT>(count * sizeof(WINDIVERT_ADDRESS)), &slot.operation)) {
            return slot.submitted == size || Fail(ERROR_WRITE_FAULT);
        }
        const DWORD code = GetLastError();
        if (code != ERROR_IO_PENDING) return Fail(code);
        slot.pending = true;
        return true;
    }
    void Reap() { for (auto& slot : slots_) Complete(slot, false); }
    void Drain() { for (auto& slot : slots_) Complete(slot, true); }
private:
    struct Slot {
        OVERLAPPED operation{};
        std::vector<uint8_t> data;
        std::array<WINDIVERT_ADDRESS, 64> addresses{};
        HANDLE handle = INVALID_HANDLE_VALUE;
        DWORD sent = 0;
        UINT submitted = 0;
        bool pending = false;
    };
    std::array<Slot, 32> slots_;
    size_t next_ = 0;
    HANDLE stop_;
    Api api_;
    ErrorHandler error_;
    bool Fail(DWORD code) { if (error_) error_(code); return false; }
    void Complete(Slot& slot, bool wait) {
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
};
