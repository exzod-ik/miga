# Client regression tests

From an x64 Visual Studio Developer Command Prompt:

```bat
miga_client\tests\run-tests.cmd
```

The script builds and runs tests sequentially under Build/tests; tests sharing object filenames must not be built concurrently. No service or WinDivert driver is started. NetworkRuntimeTests substitute receive/send/completion APIs and keep their fixtures and log under Build/tests/runtime. Other configuration/log fixtures also stay under Build/tests.

| Test | Coverage |
| --- | --- |
| RuntimeStateTests | Current SocketDirectory/FlowTable: PID 4 suppression, CLOSE and owner removal, same/different SYN sequence, new EndpointId and wildcard local IP, late ACK, startup direct routes, FIN/RST timers, wrong-server inbound activity, UDP multiple peers/reuse, removed servers, idle probes and stale results. |
| NetworkQueueTests | Current RuntimeMailbox: bounded backpressure, ownership transfer, stop/reset, event wakeup, 10,000 ordered concurrent items, delay accounting; IPv4 batch boundaries, maximum length, IHL and truncated TCP parsing. |
| ProcessIdentityTests | PID reuse, retained process identity across queued work, concurrent name cache, retry after failure, bounded eviction/cleanup and real Windows process handles. |
| RoutingIndexTests | Range normalization against linear lookup, edge addresses, configuration parsing and replacement, failed load preserving prior configuration. |
| NetworkRuntimeTests | Production runtime with substituted WinDivert API: process isolation, owner deadlines, FIFO, tunnel wire round trip and reverse IP, route unavailability/recovery, direct DNS reinjection, DNS replies in both orders, multiple A records, ID collision isolation, TTL, process/static/dynamic priority, server reorder, reload barrier, idle wakeup, cancellation and repeated network-loop stop/start. |
| LoggerTests | Sync/async recording, captured timestamps, escaping, concurrent aggregates, queue overflow and level change without file truncation. |
| PacketBufferPoolTests | Size classes, reuse, source preservation, cross-thread returns and buffers surviving pool destruction. |
| TunnelSendTests | MTU fragmentation, checksums, asynchronous completion/error/cancellation, slot lifetime, batch limits, partial flush and restart. |
| EncryptionCompatibilityTests | Wire compatibility with the reference scalar algorithm for all 65,536 nonce values and boundary sizes. |
| FragmentExpiryTests | Shared server assembler: expiry, reordered fragments, duplicate suppression and ID reuse. UdpPacketAssembler is not compiled into the Windows client. |

Old architecture tests have been removed after migrating relevant regression cases to the current runtime and mailbox. The pre-cleanup source snapshot is in Build/backups/before-legacy-cleanup-20261104-005019.

See [../ARCHITECTURE.md](../ARCHITECTURE.md) for the current thread ownership and limits. Native capture, real startup snapshot races, interface-change notifications, driver fragment reassembly, MSI installation and actual CPU/latency improvement require live verification. Windows test builds do not prove Linux toolchain compatibility.
