#include <windows.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <string>

namespace {
std::wstring isolatedName;
std::atomic<HANDLE> serverPipe{INVALID_HANDLE_VALUE};
HANDLE serverClosed = nullptr;
HANDLE CreateIsolatedPipe(LPCWSTR, DWORD openMode, DWORD pipeMode, DWORD instances, DWORD outputSize,
                          DWORD inputSize, DWORD timeout, LPSECURITY_ATTRIBUTES security) {
    assert(security && security->lpSecurityDescriptor);
    HANDLE pipe = CreateNamedPipeW(isolatedName.c_str(), openMode, pipeMode, instances, outputSize, inputSize, timeout, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) std::cerr << "pipe create error=" << GetLastError() << std::endl;
    serverPipe.store(pipe);
    return pipe;
}
BOOL CloseIsolatedHandle(HANDLE handle) {
    const bool matches = handle == serverPipe.load();
    const auto result = CloseHandle(handle);
    if (matches) SetEvent(serverClosed);
    return result;
}
}
#define CreateNamedPipeW CreateIsolatedPipe
#define CloseHandle CloseIsolatedHandle
#include "../src/ProtocolProfiles.cpp"
#undef CloseHandle
#undef CreateNamedPipeW

namespace {
HANDLE Connect() {
    const auto deadline = GetTickCount64() + 2000;
    while (GetTickCount64() < deadline) {
        auto pipe = CreateFileW(isolatedName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) return pipe;
        Sleep(1);
    }
    assert(false);
    return INVALID_HANDLE_VALUE;
}
void Send(HANDLE pipe, const std::string& request) {
    DWORD written = 0;
    assert(WriteFile(pipe, request.data(), static_cast<DWORD>(request.size()), &written, nullptr));
    assert(written == request.size());
}
void StopBounded(ProtocolProfiles& profiles) {
    const auto start = GetTickCount64();
    profiles.Stop();
    assert(GetTickCount64() - start < 1000);
}
}
int main() {
    isolatedName = L"\\\\.\\pipe\\MigaProfiles-regression-" + std::to_wstring(GetCurrentProcessId());
    serverClosed = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    assert(serverClosed);
    assert(miga::v2::Initialize());
    ProtocolProfiles profiles;
    profiles.Start([](const std::string&) { return "ready"; });
    for (int attempt = 0; attempt < 30; ++attempt) {
        HANDLE pipe = Connect();
        Send(pipe, "{\"operation\":\"status\",\"profile_id\":\"00000000000000000000000000000000\"}\n");
        assert(WaitForSingleObject(serverClosed, 2000) == WAIT_OBJECT_0);
        char data[512]{};
        DWORD count = 0;
        assert(ReadFile(pipe, data, sizeof(data), &count, nullptr));
        assert(std::string(data, count) == "{\"ok\":true,\"state\":\"ready\"}\n");
        CloseHandle(pipe);
    }
    HANDLE disconnected = Connect();
    CloseHandle(disconnected);
    assert(WaitForSingleObject(serverClosed, 2000) == WAIT_OBJECT_0);
    HANDLE idle = Connect();
    StopBounded(profiles);
    CloseHandle(idle);
    profiles.Start();
    StopBounded(profiles);
    CloseHandle(serverClosed);
    std::cout << "Profile pipe delayed reads, repeated listeners, disconnected peer and bounded stop passed\n";
}