#pragma once

#include <winsock2.h>
#include <windivert.h>
#include <array>
#include <algorithm>
#include <vector>
#include <functional>
#include <atomic>

class AsyncTunnelSender {
public:
    struct Api {
        decltype(&WinDivertSendEx) send = &WinDivertSendEx;
        decltype(&GetOverlappedResult) result = &GetOverlappedResult;
        decltype(&CancelIoEx) cancel = &CancelIoEx;
    };
    using ErrorHandler = std::function<void(DWORD)>;
    AsyncTunnelSender();
    ~AsyncTunnelSender();
    AsyncTunnelSender(const AsyncTunnelSender&) = delete;
    AsyncTunnelSender& operator=(const AsyncTunnelSender&) = delete;
    void SetApi(Api api);
    void SetErrorHandler(ErrorHandler handler);
    bool Reset();
    void RequestStop();
    bool Send(HANDLE handle, const uint8_t* data, size_t size, const WINDIVERT_ADDRESS* addresses, size_t count);
    void BeginBatch();
    bool EndBatch();
    uint64_t TakeOverflows();
    void Reap();
    bool Busy() const;
    void Drain();
private:
    bool Submit(HANDLE handle, const uint8_t* data, size_t size, const WINDIVERT_ADDRESS* addresses,
        size_t count, std::vector<uint8_t>* owned);
    bool Flush();
    bool batching_ = false;
    std::vector<uint8_t> batchData_;
    std::array<WINDIVERT_ADDRESS, 64> batchAddresses_{};
    size_t batchCount_ = 0;
    HANDLE batchHandle_ = INVALID_HANDLE_VALUE;
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
    std::atomic<uint64_t> overflows_{0};
    HANDLE stop_;
    Api api_;
    ErrorHandler error_;
    bool Fail(DWORD code);
    void Complete(Slot& slot, bool wait);
};
