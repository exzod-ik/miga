# Linux protocol v2 runtime

The server accepts only `protocol: 2`. Absent or unsupported versions fail startup. Old transport, key generation, raw socket and connection-table implementation have been removed.

The v2 configuration contains `host`, `interface`, `virtual_subnet` (a persisted private /16), `control_ports` (default `[10000,15000]`), `max_sessions` (default 64), `dns_server`, `log_level`, and optional `diagnostics.port`. It contains no invitation secrets. The DNS NAT rules redirect tunneled UDP/53 to `dns_server` when configured. If it is empty, only packets addressed to RFC 1918 resolvers are redirected to `8.8.8.8`. Conntrack restores the original resolver address in replies. The identity file and SQLite database live in `state_directory` (default `/var/lib/miga`), with a 0700 directory and 0600 files. SQLite uses a rollback journal and full synchronous commits. Session keys exist only in memory.

The daemon also listens for availability probes on the first port of the configured `control_ports` range. A request is exactly 24 bytes (`MIGAPNG1` followed by a 16-byte nonce). The reply is the same length, with `MIGAPNG2` followed by the original nonce. The responder uses no session state and applies a global limit of 20 replies per second with a burst of 40. Normal control traffic on that port is enabled only when the daily schedule selects it, including the rotation overlap.

The control owner handles Noise, SQLite, daily listeners, administrative commands, resource allocation, expiry and firewall changes. The data worker reads an immutable snapshot of active sockets and virtual-address routes. It uses a reusable sixteen-datagram `recvmmsg` batch and reusable encryption buffers. It performs no SQLite lookup, Noise exchange, shell invocation or firewall operation. Retirement disables a socket and drains its in-flight operations before slow cleanup; shared ownership retains the descriptor until old snapshots release it.

Each bound socket accepts data only from its authenticated BIND endpoint. The decrypted IPv4 source must belong to that session. TUN responses select the session by destination virtual IPv4. Linux conntrack owns NAT; the MIGA DNS chain applies the configured UDP/53 DNAT and Linux restores the original resolver address in replies. Inner fragments retain their virtual address without reading a transport header in noninitial fragments. Oversized return packets use the shared standard IPv4 fragmentation/DF helper.

Protected READY/STATUS bodies contain accepted bound data/keepalive count and generation, each unsigned 64-bit big-endian. A successful BIND increments the generation and starts the new socket counter at zero. These counters are inside protected control messages and are never added to data packets. Lost READY can be recovered with STATUS. RESUME retains virtual addresses and conntrack, replaces keys and the work socket, and does not reserve an additional logical connection slot.

## Resource bounds

- Configured active-session limit: 1–512; default 64. Reducing it preserves existing sessions.
- Pending work sockets: at most twice the configured session limit.
- All active, pending and quarantined session sockets together: at most 1024, independent of a later limit reduction.
- Each new session data socket requires an actual SO_RCVBUF of at least 8 MiB, checked with getsockopt. The request accounts for Linux doubling; SO_RCVBUFFORCE is used if normal limits prevent it. Failure refuses the session and logs errno. This permits about 512 MiB of queued receive memory at 64 active sessions, up to about 8 GiB at the hard socket limit including retained sockets; it is capacity, not upfront allocation. Control and newly restored quarantine sockets retain a small buffer. Shared receive buffers consume about 1 MiB.
- Virtual addresses: at most 16 per session and `16 × max_sessions` in total; existing allocations survive reductions.
- Accepted first-request history: at most `1024 × max_sessions`, retained for ten minutes in SQLite. Clock rollback below the persisted acceptance high-water mark rejects new handshakes until time catches up.
- Initial response cache: at most the same history limit. Per-session operation response cache: 1024 entries, retained for 120 seconds, longer than the complete 30-second retry interval. Retries preserve the original request ID, contents and protected counter.
- Source-IP rate buckets: 4096; invitation rate buckets: 65536. Idle buckets expire after ten minutes.
- Child network commands: `posix_spawnp`, five-second deadline, process-group termination/reaping on timeout and a thirty-second failure circuit breaker. Captured stdout is limited to 4 MiB. No user value is interpolated into a shell command.

Closed socket descriptors remain bound for two minutes. Their ports and reserved virtual addresses are persisted, so a daemon restart reconstructs quarantine rather than immediately reusing them. Address reuse requires verified-empty conntrack queries, a two-minute delay and a second verified cleanup. Failed cleanup retains quarantine. Resource exhaustion refuses new allocations and preserves active sessions.

Only the MIGA-owned UDP, FORWARD, NAT and DNS chains are reconciled on startup. Their hooks are removed and replaced without changing foreign rules or default policies. Closed control-range ports and quarantined work ports deliberately retain MIGA DROP protection when the daemon stops; the next startup reconciles this owned state. Removing the daemon does not itself remove these protective rules. Real firewall startup, removal and installer rollback require the separately authorized Linux integration check.

Datapath failures increment bounded atomic counters. The control owner emits at most one `runtime_io_error` warning per maintenance interval with UDP send/receive and TUN read/write counts and last errno values. Successful packets do not format INFO/WARNING messages. Diagnostic NIC/RX counters use the configured interface address; per-session socket counters are not aggregated by this interface snapshot.

## Administration

The running daemon exposes an owner-only Unix `SOCK_SEQPACKET` administrative socket. The CLI checks this first; offline client changes use the same protected SQLite database. Administrative JSON output includes an invitation only for an explicit add operation.

```sh
miga-server client list --json
miga-server client list --page --json
miga-server client list --page --after CLIENT_ID --json
miga-server client add --name 'Example client' --limit 1 --json
miga-server client update --id CLIENT_ID --name 'New name' --limit 0
miga-server client disconnect --id CLIENT_ID
miga-server client revoke --id CLIENT_ID
miga-server settings get --json
miga-server settings set --max-sessions 64
```

The default list command returns a JSON array assembled from bounded admin socket pages. With `--page` it returns `clients` and `next`. Pass a non-null `next` as `--after` to continue. Results follow client ID order within the paged traversal.

The personal limit zero removes only that invitation's connection limit. There is no device registration. Online revoke/disconnect retires matching sessions through the control owner. Settings updates preserve other JSON fields and atomically replace/fsync the configuration; active sessions remain connected.

For standalone updates, stage `ServerVersion.inc` beside `update-v2.py` and the candidate ELF. The updater verifies that the candidate reports the version in this file.

The source installer requires an explicit `install.sh --protocol-v2 HOST OUTGOING_INTERFACE`, staged together with `install-v2.sh`, `prepare-dependencies.sh` and the verified `miga_server` ELF. Dependency preparation runs before service changes, bootstraps Python for fresh installations and updates, and installs only missing required tools with apt-get/dnf/yum and bounded commands. Bash/coreutils and running systemd are prerequisites. Apt uses noninteractive, no-remove/no-upgrade and needrestart list-only mode; no full system upgrade is requested. Installed dependencies remain after MIGA rollback. It validates subnet and control-port conflicts, preserves diagnostics settings, verifies existing MIGA socket ownership, and replaces the binary only after preflight. It reuses the persistent VMXNET3 RX-ring helper. An existing unsupported configuration is rejected. The isolated installer integration fixture executes transformed copies of both shell installers and their Python blocks against temporary paths and command adapters; it performs no real installation or systemd/firewall changes. See [upgrade validation](tests/UPGRADE_VALIDATION.md) for coverage and limits.

## Build and verification

From the repository root on Linux:

```sh
python3 dependencies/build-linux.py
```

This verifies the pinned archive hashes and builds static libsodium, the pinned Noise-C revision with its sodium backend, and SQLite into `Build/protocol-v2/linux`. It installs nothing into the operating system. The server project runs this bootstrap before compilation and links those static archives. OpenSSL is required for the diagnostic TLS listener authenticated by single-use v2 tickets.

The isolated tests are described in [tests/README.md](tests/README.md). They use loopback UDP, a Unix datagram socketpair in place of TUN, temporary SQLite files, and local command stubs in place of iptables/conntrack. They bypass privileged `Initialize`; passing them does not establish real TUN/NAT/DNS-DNAT, firewall silence, PMTU delivery, installation/rollback, Amnezia coexistence or production performance.

Session sockets bind the wildcard IPv4 address, and ordinary UDP replies use the kernel route's source-address selection. Multihomed hosts, NAT and policy routing require explicit live verification together with Amnezia coexistence; the isolated loopback fixture does not establish that behavior.

## Diagnostics authorization

DiagnosticOpen=13 has an empty body and requires an active session. DiagnosticReply=14 returns port (2 bytes big-endian), SHA-256 certificate fingerprint (32 bytes), and a single-use random ticket (32 bytes); an empty body means unavailable. Session control protects all parameters. The separate TLS channel pins that certificate and requires authorize with the ticket before accepting commands. Tickets expire after 30 seconds; diagnostic connections after 5 minutes. Session close/revoke cancels access. See DIAGNOSTICS.md for local-only behavior and deployment requirements.

При успешной установке install-v2.sh удаляет оставшиеся от старого ServerCore правила OUTPUT, полностью подавляющие ICMP destination-unreachable (type 3), включая дубликаты. Удаляется только точная прежняя форма без дополнительных условий. Такие же записи удаляются из filter в /etc/iptables/rules.v4 и /etc/sysconfig/iptables с атомарной заменой файла и сохранением владельца/прав; другие правила не меняются. V2 не добавляет это подавление. Действующие политики firewall могут независимо ограничивать ICMP.
