#include "WindowsProcessIdentity.h"

ProcessOwner LoadWindowsProcessIdentity(uint32_t processId) {
    std::shared_ptr<void> handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
        FALSE, processId), [](void* value) { if (value) CloseHandle(value); });
    auto alive = [handle] { return handle && WaitForSingleObject(handle.get(), 0) == WAIT_TIMEOUT; };
    auto readName = [handle]() -> std::string {
        if (!handle) return "unknown";
        char path[32768];
        DWORD length = static_cast<DWORD>(sizeof(path));
        if (!QueryFullProcessImageNameA(handle.get(), 0, path, &length)) return "unknown";
        std::string fullPath(path, length);
        const auto pos = fullPath.find_last_of("\\/");
        return pos == std::string::npos ? fullPath : fullPath.substr(pos + 1);
    };
    return std::make_shared<const ProcessIdentity>(processId, std::move(alive), std::move(readName));
}
