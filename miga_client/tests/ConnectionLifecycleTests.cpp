#include "TcpSocketMaintenance.h"
#include <iostream>
#include <stdexcept>
#include <future>

static void Check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

int main() {
    try {
        using Table = SocketOwnerTable;
        using Status = Table::ProbeResult;
        const auto now = Table::Clock::now();
        auto process = std::make_shared<const ProcessIdentity>(10, [] { return true; }, [] { return "fixture.exe"; });
        auto owner = std::make_shared<const SocketOwner>(SocketOwner{process, 1, 100});
        SocketTuple tuple{6, 0xc0000201, 5000, 0xc6336401, 443};
        const auto later = now + std::chrono::minutes(124);
        std::vector<Table::Probe> probes;
        RoutingState routing;
        routing.SetProbeHandler([&](const Table::Probe& probe) { probes.push_back(probe); return true; });
        routing.Observe(tuple, owner, now);
        routing.Commit(tuple, 120, owner, {FlowRoute::Kind::Tunnel, 7, 0}, now);
        routing.Cleanup(later);
        Check(probes.size() == 1 && routing.Size() == 1, "idle TCP remains routable during background check");
        routing.ApplyProbe(probes.back(), Status::Present, later);
        Check(routing.Resolve(tuple, 140, false, later).route.serverId == 7, "confirmed socket preserves route");
        routing.ApplyProbe(probes.back(), Status::Absent, later);
        Check(routing.Resolve(tuple, 150, false, later).owner == owner, "activity invalidates stale absence");
        routing.RetainServers({});
        Check(routing.Resolve(tuple, 160, false, later).action == RoutingState::Action::Drop,
            "confirmed socket cannot revive removed transport");

        Table table;
        table.SetProbeHandler([&](const Table::Probe& probe) { probes.push_back(probe); return true; });
        table.Update(tuple, owner, now);
        table.Cleanup(later);
        auto request = probes.back();
        table.ApplyProbe(request, Status::Unknown, later);
        Check(table.Size() == 1, "snapshot failure is not socket disappearance");
        table.Cleanup(later + std::chrono::seconds(30));
        request = probes.back();
        table.ApplyProbe(request, Status::Absent, later + std::chrono::seconds(30));
        Check(table.Size() == 0, "confirmed absence retires idle socket");
        table.Update(tuple, owner, later);
        table.ApplyProbe(request, Status::Absent, later);
        Check(table.Size() == 1, "old request cannot delete recreated entry");
        const auto oldProbeCount = probes.size();
        table.Cleanup(later + std::chrono::minutes(124));
        Check(probes.size() == oldProbeCount + 1, "next lifetime eventually checked");
        request = probes.back();
        table.Cleanup(later + std::chrono::minutes(124) + std::chrono::seconds(30));
        table.ApplyProbe(request, Status::Absent, later + std::chrono::minutes(124) + std::chrono::seconds(30));
        Check(table.Size() == 1, "superseded probe cannot delete current candidate");
        request = probes.back();
        table.Close(6, 5000, 1, 200, later + std::chrono::minutes(124));
        table.ApplyProbe(request, Status::Present, later + std::chrono::minutes(124));
        table.Cleanup(later + std::chrono::minutes(124) + std::chrono::seconds(30));
        Check(table.Size() == 0, "confirmation cannot resurrect CLOSE");

        Table bounded;
        for (uint16_t port = 1000; port < 1300; ++port) {
            auto key = tuple; key.localPort = port;
            bounded.Update(key, owner, now);
        }
        bounded.Cleanup(later, 17);
        Check(bounded.Size() == 283, "cleanup budget bounds due work");
        Check(bounded.NextDeadline(later + std::chrono::seconds(1)) <= later, "remaining due work stays scheduled");
        while (bounded.Size()) bounded.Cleanup(later, 17);

        DeadlineIndex<int> deadlines;
        deadlines.Set(1, now); deadlines.Set(1, later);
        int key = 0;
        Check(deadlines.Size() == 1 && !deadlines.PopDue(now, key), "one deadline per entry");
        Check(deadlines.PopDue(later, key) && key == 1, "rescheduled deadline");
        deadlines.Set(1, later); deadlines.Erase(1);
        Check(deadlines.Size() == 0, "erased entry leaves no timer");

        TcpSocketMaintenance::Snapshot snapshot;
        snapshot.emplace(FlowKey::From(tuple), 10);
        request = {1, tuple, owner, now};
        Check(TcpSocketMaintenance::Check(request, snapshot) == Status::Present, "exact tuple and process");
        auto other = request; other.tuple.remotePort++;
        Check(TcpSocketMaintenance::Check(other, snapshot) == Status::Absent, "different remote peer rejected");
        auto dead = std::make_shared<const ProcessIdentity>(10, [] { return false; }, [] { return "old.exe"; });
        other = request;
        other.owner = std::make_shared<const SocketOwner>(SocketOwner{dead, 1, 100});
        Check(TcpSocketMaintenance::Check(other, snapshot) == Status::Absent, "reused PID cannot confirm old process");

        std::promise<void> entered, release;
        auto gate = release.get_future().share();
        TcpSocketMaintenance service([&](auto& output) {
            entered.set_value(); gate.wait(); output = snapshot; return DWORD(NO_ERROR);
        });
        service.Start();
        const auto submitTimeout = Table::Clock::now() + std::chrono::seconds(2);
        bool submitted = false;
        while (!(submitted = service.Submit(request)) && Table::Clock::now() < submitTimeout) std::this_thread::yield();
        Check(submitted, "submit background check");
        Check(entered.get_future().wait_for(std::chrono::seconds(2)) == std::future_status::ready, "reader runs in background");
        Check(service.Take().empty(), "worker need not wait for snapshot");
        release.set_value();
        std::vector<TcpSocketMaintenance::Result> results;
        const auto timeout = Table::Clock::now() + std::chrono::seconds(2);
        while (results.empty() && Table::Clock::now() < timeout) {
            results = service.Take();
            std::this_thread::yield();
        }
        Check(results.size() == 1 && results[0].status == Status::Present, "background result delivered");
        service.Stop();
        service.Start();
        Check(service.Take().empty(), "restart has no stale result");
        service.Stop();
        std::cout << "Connection lifecycle tests passed\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
