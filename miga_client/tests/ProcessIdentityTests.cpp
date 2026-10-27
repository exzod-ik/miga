#include "WindowsProcessIdentity.h"
#include "BoundedQueue.h"
#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

int main(int argc, char**) {
    if (argc > 1) return 0;

    ProcessIdentityCache cache;
    std::atomic<bool> oldAlive{ true };
    std::atomic<int> reads{ 0 };
    std::atomic<int> loads{ 0 };
    auto oldProcess = std::make_shared<const ProcessIdentity>(1234,
        [&] { return oldAlive.load(); }, [&] { ++reads; return "old.exe"; });
    auto newProcess = std::make_shared<const ProcessIdentity>(1234,
        [] { return true; }, [] { return "new.exe"; });
    ProcessOwner current = oldProcess;
    auto loader = [&](uint32_t) { ++loads; return current; };
    auto first = cache.Get(1234, loader);
    assert(first->Name() == "old.exe");
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            for (int j = 0; j < 1000; ++j) {
                const auto process = cache.Get(1234, loader);
                assert(process == first);
                assert(process->Name() == "old.exe");
            }
        });
    }
    for (auto& thread : threads) thread.join();
    assert(reads == 1 && loads == 1);

    BoundedQueue<std::shared_ptr<const SocketOwner>, 1> queue;
    auto socket = std::make_shared<const SocketOwner>(SocketOwner{ first, 10, 100 });
    assert(socket->Matches(100) && socket->Matches(200) && !socket->Matches(99));
    assert(queue.Push(std::move(socket)));
    oldAlive = false;
    current = newProcess;
    const auto replacement = cache.Get(1234, loader);
    assert(replacement == newProcess && replacement->Name() == "new.exe");
    std::shared_ptr<const SocketOwner> queued;
    assert(queue.Pop(queued));
    assert(queued->process->Name() == "old.exe");
    assert(queued->endpointId == 10);
    SocketOwner newSocket{ replacement, 11, 300 };
    assert(!newSocket.Matches(200));
    cache.Clear();
    assert(queued->process->Name() == "old.exe");

    int failedLoads = 0;
    auto failure = [&](uint32_t id) {
        ++failedLoads;
        return std::make_shared<const ProcessIdentity>(id, [] { return false; }, [] { return "unknown"; });
    };
    cache.Get(77, failure);
    cache.Get(77, failure);
    assert(failedLoads == 2);

    int retryReads = 0;
    ProcessIdentity retry(78, [] { return true; }, [&]() -> std::string {
        return ++retryReads == 1 ? "unknown" : "recovered.exe";
    });
    assert(retry.Name() == "unknown" && retry.Name() == "unknown");
    assert(retryReads == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    assert(retry.Name() == "recovered.exe");

    auto uniqueLoader = [](uint32_t id) {
        return std::make_shared<const ProcessIdentity>(id, [] { return true; }, [] { return "bounded.exe"; });
    };
    std::weak_ptr<const ProcessIdentity> evicted = cache.Get(1, uniqueLoader);
    for (uint32_t id = 2; id <= 1025; ++id) cache.Get(id, uniqueLoader);
    assert(evicted.expired());
    cache.Clear();
    std::atomic<bool> cleanupAlive{ true };
    std::weak_ptr<const ProcessIdentity> cleaned = cache.Get(1, [&](uint32_t id) {
        return std::make_shared<const ProcessIdentity>(id, [&] { return cleanupAlive.load(); }, [] { return "cleanup.exe"; });
    });
    cleanupAlive = false;
    cache.Cleanup();
    assert(cleaned.expired());

    char executable[32768];
    const auto length = GetModuleFileNameA(nullptr, executable, static_cast<DWORD>(sizeof(executable)));
    assert(length != 0 && length < sizeof(executable));
    std::string command = "\"" + std::string(executable, length) + "\" --child";
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    assert(CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &child));
    auto childIdentity = cache.Get(child.dwProcessId, LoadWindowsProcessIdentity);
    assert(childIdentity->isAlive());
    const auto childName = childIdentity->Name();
    assert(childName == "process-identity-tests.exe");
    assert(ResumeThread(child.hThread) != static_cast<DWORD>(-1));
    assert(WaitForSingleObject(child.hProcess, 10000) == WAIT_OBJECT_0);
    assert(!childIdentity->isAlive());
    cache.Cleanup();
    assert(childIdentity->Name() == childName);
    childIdentity.reset();
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);

    DWORD before = 0, after = 0;
    assert(GetProcessHandleCount(GetCurrentProcess(), &before));
    for (int i = 0; i < 100; ++i) {
        auto own = LoadWindowsProcessIdentity(GetCurrentProcessId());
        assert(own->isAlive() && own->Name() == childName);
    }
    assert(GetProcessHandleCount(GetCurrentProcess(), &after));
    assert(after == before);
    std::cout << "Process identity tests passed\n";
}
