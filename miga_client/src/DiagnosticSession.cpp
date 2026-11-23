#include "DiagnosticSession.h"
#include "WindowsProcessIdentity.h"
#include "runtime/WindowsSnapshot.h"
#include <algorithm>
#include <sddl.h>

namespace {
uint32_t ProbeSequence(const uint8_t* p, size_t n) {
    if (!p || n < 30 || (p[0] >> 4) != 4 || p[9] != 17 || (p[6] & 0x3f) || p[7]) return 0;
    const size_t h = (p[0] & 15) * 4;
    if (h < 20 || n != h + 10 || ((unsigned(p[2]) << 8) | p[3]) != n || p[h + 4] || p[h + 5] != 10) return 0;
    return ((uint32_t(p[h + 8]) << 8) | p[h + 9]) + 1;
}
}


DiagnosticSession::~DiagnosticSession() { Stop(); }

void DiagnosticSession::Start(Begin begin) {
    Stop(); stopping_.store(false);
    thread_ = std::thread([this, begin = std::move(begin)] { Serve(begin); });
}

void DiagnosticSession::Stop() {
    stopping_.store(true);
    if (thread_.joinable()) {
        while (WaitForSingleObject(thread_.native_handle(), 10) == WAIT_TIMEOUT)
            CancelSynchronousIo(thread_.native_handle());
        thread_.join();
    }
    Clear();
}

void DiagnosticSession::Clear() {
    enabled.store(false);
    load.Clear();
    ClearDirectProbe();
    std::lock_guard lock(mutex_);
    for (auto& word : portMask_) word.store(0, std::memory_order_relaxed);
    sequencePort_ = 0; capturedSequences_.clear(); completedSequences_.clear();
    observing_ = false;
    targetPid_.store(0); owner_.reset(); registrations_.clear(); flows_.clear(); server_ = 0; force_ = mss_ = false; probePort_ = 0;
}

bool DiagnosticSession::RegisterDirectProbe(DWORD pid, const Json& request) {
    const auto localIp = request.at("local_ip").get<int64_t>();
    const auto localPort = request.at("local_port").get<int64_t>();
    const auto remoteIp = request.at("remote_ip").get<int64_t>();
    if (localIp <= 0 || localIp > UINT32_MAX || localPort <= 0 || localPort > UINT16_MAX ||
        remoteIp <= 0 || remoteIp > UINT32_MAX) return false;
    auto process = LoadWindowsProcessIdentity(pid);
    if (!process || !process->isAlive()) return false;
    miga::runtime::WindowsSnapshot snapshot;
    if (snapshot.Read(true) != NO_ERROR) return false;
    const auto ownsSocket = std::any_of(snapshot.entries.begin(), snapshot.entries.end(), [&](const auto& entry) {
        return entry.pid == pid && entry.tuple.localPort == localPort &&
            (!entry.tuple.localIp || entry.tuple.localIp == localIp);
    });
    if (!ownsSocket) return false;
    std::lock_guard lock(mutex_);
    if (directProbeOwner_) return false;
    directProbeOwner_ = std::move(process);
    directProbeTuple_ = {17, static_cast<uint32_t>(localIp), static_cast<uint16_t>(localPort),
        static_cast<uint32_t>(remoteIp), 3478};
    directProbePort_.store(directProbeTuple_.localPort, std::memory_order_release);
    return true;
}

void DiagnosticSession::ClearDirectProbe() {
    std::lock_guard lock(mutex_);
    directProbePort_.store(0, std::memory_order_release);
    directProbeOwner_.reset();
    directProbeTuple_ = {};
}

bool DiagnosticSession::DirectProbeMatches(const SocketTuple& tuple) {
    const auto port = directProbePort_.load(std::memory_order_acquire);
    if (!port || tuple.protocol != 17 || tuple.localPort != port) return false;
    std::lock_guard lock(mutex_);
    return FlowKey::From(tuple) == FlowKey::From(directProbeTuple_) &&
        directProbeOwner_ && directProbeOwner_->isAlive();
}

void DiagnosticSession::MarkPort(uint8_t protocol, uint16_t port) {
    const auto key = (unsigned(protocol == 17) << 16) | port;
    portMask_[key / 64].fetch_or(uint64_t(1) << (key % 64), std::memory_order_relaxed);
}

void DiagnosticSession::Configure(ProcessOwner owner, size_t server, bool force) {
    std::lock_guard lock(mutex_);
    owner_ = std::move(owner); server_ = server; force_ = force;
    targetPid_.store(owner_->pid);
    ++session_;
    observing_ = false;
    captured_ = unowned_ = submitted_ = completed_ = rejected_ = preSendRejected_ = 0;
    sequencePort_ = 0; capturedSequences_.clear(); completedSequences_.clear();
    stats_ = {{"flows", Json::array()}};
    enabled.store(true);
}

bool DiagnosticSession::Route(const ProcessOwner& owner, FlowRoute& route) {
    if (!Selected(owner)) return false;
    std::lock_guard lock(mutex_);
    if (!owner_ || owner != owner_ || !owner_->isAlive()) return false;
    if (force_) route = {FlowRoute::Kind::Tunnel, server_, 0};
    return force_;
}

DiagnosticSession::PacketOptions DiagnosticSession::Options(const SocketTuple& tuple, size_t server, const uint8_t* packet, size_t length) {
    std::lock_guard lock(mutex_);
    auto flow = flows_.find(FlowKey::From(tuple));
    if (flow == flows_.end() || flow->second != server) return {};
    PacketOptions result{session_, mss_ && tuple.protocol == 17 && probePort_ == tuple.localPort, mss_ && tuple.protocol == 6,
        sequencePort_ && tuple.localPort == sequencePort_ && tuple.protocol == 17 ? ProbeSequence(packet, length) : 0, {}};
    if (load.enabled.load(std::memory_order_relaxed)) miga::diagnostics::ReadProbePacket(packet, length, result.probe);
    return result;
}

bool DiagnosticSession::RejectFallback(const SocketTuple& tuple, const FlowRoute& route) {
    std::lock_guard lock(mutex_);
    return force_ && (route.kind != FlowRoute::Kind::Tunnel || route.serverId != server_) &&
        IsRegistered(tuple);
}

bool DiagnosticSession::IsRegistered(const SocketTuple& tuple) const {
    return registrations_.count((uint32_t(tuple.protocol) << 16) | tuple.localPort) != 0;
}

bool DiagnosticSession::MatchesObservation(const SocketTuple& tuple) const {
    return observing_ && (!observationTuple_.localPort || (tuple.protocol == observationTuple_.protocol &&
        tuple.localPort == observationTuple_.localPort && tuple.remotePort == observationTuple_.remotePort &&
        tuple.remoteIp == observationTuple_.remoteIp));
}

DiagnosticSession::Json DiagnosticSession::BeginObservation(const SocketTuple& tuple) {
    std::lock_guard lock(mutex_);
    observing_ = !tuple.localPort || (IsRegistered(tuple) && tuple.remotePort && tuple.remoteIp);
    observationTuple_ = tuple;
    observationCaptured_ = observationUnowned_ = 0;
    observationFlowIndices_.clear();
    observationFlows_ = Json::array();
    return {{"ok", observing_}};
}

DiagnosticSession::Json DiagnosticSession::EndObservation() {
    std::lock_guard lock(mutex_);
    Json result = {{"ok", observing_}, {"captured", observationCaptured_},
        {"unowned", observationUnowned_}, {"flows", std::move(observationFlows_)}};
    observing_ = false;
    return result;
}

void DiagnosticSession::ObserveUnowned(const SocketTuple& tuple) {
    std::lock_guard lock(mutex_);
    if (IsRegistered(tuple)) ++unowned_;
    if (observationTuple_.localPort && MatchesObservation(tuple)) ++observationUnowned_;
}

void DiagnosticSession::Observe(const SocketTuple& tuple, const ProcessOwner& owner, const FlowRoute& route, const char* reason) {
    std::lock_guard lock(mutex_);
    const auto key = FlowKey::From(tuple);
    if (!owner || owner_ != owner) {
        flows_.erase(key);
        return;
    }
    const char* kind = route.kind == FlowRoute::Kind::Tunnel ? "tunnel" :
        route.kind == FlowRoute::Kind::Direct ? "direct" : "drop";
    auto describe = [&] {
        return Json{{"pid", owner->pid}, {"application", owner->Name()}, {"protocol", tuple.protocol},
            {"local_port", tuple.localPort}, {"remote_ip", tuple.remoteIp}, {"remote_port", tuple.remotePort},
            {"server_id", route.serverId}, {"route", kind}, {"reason", reason}};
    };
    if (MatchesObservation(tuple)) {
        ++observationCaptured_;
        const auto previous = observationFlowIndices_.find(key);
        if (previous != observationFlowIndices_.end()) {
            auto& row = observationFlows_[previous->second];
            if (row["server_id"] != route.serverId || row["route"] != kind || row["reason"] != reason)
                row = describe();
        } else if (observationFlows_.size() < 128) {
            observationFlowIndices_.emplace(key, observationFlows_.size());
            observationFlows_.push_back(describe());
        }
    }
    ++captured_;
    if (flows_.size() >= 1024 && !flows_.count(key)) return;
    auto [flow, inserted] = flows_.insert_or_assign(key, route.serverId);
    if (inserted) MarkPort(tuple.protocol, tuple.localPort);
    auto& rows = stats_["flows"];
    if (inserted && rows.size() < 128) rows.push_back(describe());
}

void DiagnosticSession::ObserveProbe(const SocketTuple& tuple, const uint8_t* packet, size_t length) {
    load.Packet(miga::diagnostics::LoadCounters::Captured, packet, length);
    std::lock_guard lock(mutex_);
    if (!sequencePort_ || tuple.localPort != sequencePort_ || tuple.protocol != 17) return;
    const auto sequence = ProbeSequence(packet, length);
    if (sequence) capturedSequences_.insert(uint16_t(sequence - 1));
}

void DiagnosticSession::Submitted(uint64_t session) {
    std::lock_guard lock(mutex_);
    if (session_ == session && owner_) ++submitted_;
}

void DiagnosticSession::RejectBeforeSend(uint64_t session) {
    std::lock_guard lock(mutex_);
    if (session_ == session && owner_) ++preSendRejected_;
}

void DiagnosticSession::Sent(uint64_t session, bool success, uint32_t sequence) {
    std::lock_guard lock(mutex_);
    if (session_ == session && owner_) {
        if (success) {
            ++completed_;
            if (sequencePort_ && sequence) completedSequences_.insert(uint16_t(sequence - 1));
        }
        else ++rejected_;
    }
}

void DiagnosticSession::Serve(Begin begin) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) return;
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    while (!stopping_.load()) {
        HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\MigaDiagnostics-v1", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &security);
        if (pipe == INVALID_HANDLE_VALUE) break;
        if ((ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) && !stopping_.load()) {
            ULONG pid = 0;
            if (GetNamedPipeClientProcessId(pipe, &pid)) {
                std::string line;
                char byte; DWORD count;
                while (!stopping_.load() && ReadFile(pipe, &byte, 1, &count, nullptr) && count) {
                    if (byte != '\n') { if (line.size() == 8192) break; line.push_back(byte); continue; }
                    Json result;
                    try {
                        auto request = Json::parse(line); line.clear();
                        auto command = request.value("command", "");
                        if (command == "begin" && !enabled.load()) result = begin(pid, request);
                        else if (command == "direct_probe_register")
                            result = {{"ok", RegisterDirectProbe(pid, request)}};
                        else if (command == "direct_probe_end") {
                            ClearDirectProbe(); result = {{"ok", true}};
                        }
                        else if (command == "observe_begin" && enabled.load()) {
                            SocketTuple tuple{};
                            tuple.localPort = request.value("local_port", uint16_t(0));
                            tuple.remotePort = request.value("remote_port", uint16_t(0));
                            tuple.remoteIp = request.value("remote_ip", uint32_t(0));
                            tuple.protocol = request.value("protocol", uint8_t(0));
                            result = BeginObservation(tuple);
                        } else if (command == "observe_end" && enabled.load()) {
                            result = EndObservation();
                        }
                        else if (command == "stats") {
                            std::lock_guard lock(mutex_);
                            result = stats_;
                            result["captured"] = captured_;
                            result["unowned"] = unowned_;
                            result["submitted"] = submitted_;
                            result["completed"] = completed_;
                            result["send_rejected"] = rejected_;
                            result["pre_send_rejected"] = preSendRejected_;
                            result["pending"] = submitted_ - completed_ - rejected_;
                            result["send_counter_unit"] = "outer_send_batches";
                            if (sequencePort_) {
                                result["captured_sequences"] = capturedSequences_;
                                result["completed_sequences"] = completedSequences_;
                            }
                        } else if (command == "load_configure" && enabled.load()) {
                            load.Configure(request); result = {{"ok", true}};
                        } else if (command == "load_stats" && enabled.load()) {
                            result = {{"ok", true}, {"stages", load.Snapshot()}};
                        } else if (command == "load_stop") {
                            load.Clear(); result = {{"ok", true}};
                        } else if (command == "register" && enabled.load()) {
                            const int protocol = request.at("protocol"), port = request.at("local_port");
                            std::lock_guard lock(mutex_);
                            bool ok = (protocol == 6 || protocol == 17) && port > 0 && port <= 65535 && registrations_.size() < 1024;
                            if (ok) {
                                registrations_.insert((uint32_t(protocol) << 16) | uint32_t(port));
                                MarkPort(static_cast<uint8_t>(protocol), static_cast<uint16_t>(port));
                            }
                            result = {{"ok", ok}};
                        }
                        else if (command == "options") {
                            std::lock_guard lock(mutex_); mss_ = request.value("mss", false);
                            probePort_ = request.value("probe_port", uint16_t(0));
                            sequencePort_ = request.value("sequence_port", uint16_t(0)); result = {{"ok", true}};
                        } else if (command == "finish_step") {
                            load.Clear();
                            std::lock_guard lock(mutex_);
                            registrations_.clear();
                            flows_.clear();
                            observing_ = false;
                            mss_ = false;
                            probePort_ = 0;
                            sequencePort_ = 0; capturedSequences_.clear(); completedSequences_.clear();
                            for (auto& word : portMask_) word.store(0, std::memory_order_relaxed);
                            result = {{"ok", true}};
                        } else if (command == "end") {Clear(); result = {{"ok", true}};}
                        else result = {{"ok", false}, {"error", "invalid_command"}};
                    } catch (...) {result = {{"ok", false}, {"error", "invalid_request"}};}
                    auto response = result.dump() + "\n";
                    if (!WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &count, nullptr)) break;
                }
            }
        }
        Clear(); DisconnectNamedPipe(pipe); CloseHandle(pipe);
    }
    LocalFree(descriptor);
}
