# Network queue tests

Run from the repository root in an x64 Visual Studio Developer Command Prompt:

```bat
if not exist Build\tests mkdir Build\tests
cl /nologo /std:c++20 /EHsc /W4 /WX /I miga_client\include miga_client\tests\NetworkQueueTests.cpp /FoBuild\tests\NetworkQueueTests.obj /FeBuild\tests\network-queue-tests.exe
Build\tests\network-queue-tests.exe
```

Tests cover backpressure, FIFO ordering, transfer of buffer ownership, shutdown with empty/full queues, restart without stale packets, concurrent delivery of 10,000 items and IPv4 batch boundaries including truncated headers and maximum-size packets.

NETWORK reception uses batches of up to 64 packets and a shared queue of 256 network/socket/control events. A pool of 34 reusable 256 KiB buffers covers the queued, receiving and processing batches. A full queue blocks reception; it does not discard the received batch. Shutdown cancels queue waits and discards remaining queued batches. The worker processes packets in receive order. The driver queue time is unchanged.

These tests do not load WinDivert or run the service. Live TCP/UDP, DNS, stop/restart and hot reload require separate integration checks.

Additional production-code tests, from the same developer command prompt:

```bat
cl /nologo /std:c++20 /EHsc /W4 /I miga_client\include /I Shared miga_client\tests\RoutingIndexTests.cpp miga_client\src\ConfigManager.cpp Shared\Logger.cpp /FoBuild\tests\ /FeBuild\tests\routing-index-tests.exe /link ws2_32.lib
Build\tests\routing-index-tests.exe
cl /nologo /std:c++17 /EHsc /W4 /I Shared miga_client\tests\FragmentExpiryTests.cpp Shared\UdpPacketAssembler.cpp /FoBuild\tests\ /FeBuild\tests\fragment-expiry-tests.exe /link ws2_32.lib
Build\tests\fragment-expiry-tests.exe
```

Routing tests compare normalized ranges with linear matching, check process case and server priority, concurrent dynamic IP updates, and successful/failed/cold reloads. They create and remove a synthetic fixture under Build/tests. Fragment tests cover expiry, reordered fragments, duplicate suppression and ID reuse after timeout. Existing C4201/C4244 warnings in shared headers and case conversion remain visible.
Process identity tests (Windows, no driver or service required):

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /I miga_client\include miga_client\tests\ProcessIdentityTests.cpp /FoBuild\tests\ProcessIdentityTests.obj /FeBuild\tests\process-identity-tests.exe
Build\tests\process-identity-tests.exe
```

These tests cover repeated and concurrent cache hits, simulated PID reuse, queued owner retention, socket timestamp boundaries, failed lookup retries, bounded eviction, terminated-process cleanup and handle release. A child copy of the test executable verifies actual Windows process exit and executable-name lookup. They do not simulate WinDivert event delivery or live routing.

Logger tests:

```bat
cl /nologo /std:c++17 /EHsc /W4 /WX /I Shared miga_client\tests\LoggerTests.cpp Shared\Logger.cpp /FoBuild\tests\ /FeBuild\tests\logger-tests.exe
Build\tests\logger-tests.exe
```

Checks verify that disabled message factories are not evaluated, selected levels are respected, concurrent messages remain complete, and enabled messages are immediately visible in the file. The test uses and removes an isolated directory under Build/tests. Logging retains immediate flushing; only the redundant second file flush is removed.

Packet WARNING formatting tests:

```bat
cl /nologo /std:c++17 /EHsc /W4 /WX /I miga_client\include miga_client\tests\PacketWarningTests.cpp /FoBuild\tests\PacketWarningTests.obj /FeBuild\tests\packet-warning-tests.exe
Build\tests\packet-warning-tests.exe
```

Covers TCP/UDP protocol labels, network byte order, IPv4 options, unavailable fragment ports and truncated or invalid headers. Routing diagnostics capture at most 32 header samples per reporting cycle on the routing worker; further packets are counted in omitted.

Socket owner lifetime tests:

```bat
cl /nologo /std:c++17 /EHsc /W4 /WX /I miga_client\include miga_client\tests\SocketOwnerTableTests.cpp /FoBuild\tests\SocketOwnerTableTests.obj /FeBuild\tests\socket-owner-tests.exe
Build\tests\socket-owner-tests.exe
```

Covers delayed packets before CLOSE, late TCP continuations, stale CLOSE, exact tuple matching, simultaneous peers on one local port, SYN after CLOSE, port reuse by another process, UDP lifetime boundaries, repeated UDP CONNECT/ACCEPT events across multiple destinations with and without BIND, BIND-to-CONNECT, delayed socket delivery, bounded eviction, expiry, reset, IPv4 options and truncated headers. These tests do not replace live WinDivert TCP/UDP, DNS, service restart or hot reload checks.
Routing state and PacketMonitor integration tests:

~~~bat
cl /nologo /std:c++17 /EHsc /W4 /WX /I miga_client\include miga_client\tests\RoutingStateTests.cpp /FoBuild\tests\RoutingStateTests.obj /FeBuild\tests\routing-state-tests.exe
Build\tests\routing-state-tests.exe
cl /nologo /std:c++20 /EHsc /W3 /DWINDIVERTEXPORT=extern /I miga_client\include /I Shared miga_client\tests\PacketMonitorFlowTests.cpp miga_client\src\PacketMonitor.cpp miga_client\src\ConfigManager.cpp Shared\Encryption.cpp Shared\Logger.cpp Shared\UdpPacketAssembler.cpp /FoBuild\tests\ /FeBuild\tests\packet-monitor-tests.exe /link ws2_32.lib iphlpapi.lib miga_client\windivert\x64\WinDivert.lib
copy /Y miga_client\windivert\x64\WinDivert.dll Build\tests\WinDivert.dll
Build\tests\packet-monitor-tests.exe
~~~

RoutingState tests cover generation changes, committed direct/tunnel routes, late TCP, UDP reuse, removed servers, capacity, deadlines and shutdown wakeups. PacketMonitor integration tests execute production routing, transformation and reinjection code with substituted WinDivertSendEx for both tunnel transmission and reinjection and real loopback UDP sockets. They cover delayed ownership, TCP/UDP in both directions, multiple UDP peers, server reorder, DNS replies in both orders with multiple A records, failed preparation, malformed packets, worker deadline wakeup, hot reload and worker stop/restart. The fixture and log stay under Build/tests/packet-monitor-runtime. No driver or service is started. Loopback access must be allowed by the test environment. Actual WinDivert capture, startup socket snapshot races, installed service restart and gameplay still need live verification.
Queue optimization checks cover protocol/port-specific pending retries, FIFO and byte accounting across both indexes, and deadline processing without visiting younger packets. Cached socket lookup is compared against uncached lookup across TCP/UDP generation changes, future socket timestamps, CLOSE, SYN, expiry, eviction and reset. Integration checks send alternating packet sizes through the reused output buffer, verify the decrypted contents and source preservation, and check allocation reuse. The worker owns the transformation buffer; the async sender copies the outer datagram into a bounded slot that remains alive until completion. The WinDivertSendEx substitute validates outer IP/UDP checksums and relays the UDP payload to the loopback fixture.

SYSTEM ownership regression checks cover PID 4 suppression on an already owned TCP/UDP port, cached lookups, different remote peers, unrelated endpoint CLOSE, ordinary owner replacement, closed-owner grace expiry, idle expiry, empty ports and independent protocols. Integration checks verify that SYSTEM events cannot redirect established TCP/UDP tunnels to direct delivery.

Event queue delay checks cover timestamps taken after producer backpressure, atomic queue depth before removal, timeout/close results, the 100 ms threshold, per-type counts/maxima and flush/reset. WARNING event_queue_delay aggregates NETWORK batches, SOCKET events and CONTROL events approximately every 5 seconds; max_queue_depth_at_pop includes the extracted event. A blocked worker reports accumulated delays only after it resumes processing.

Tunnel encapsulation and asynchronous send tests (Windows, no WinDivert driver or service started):

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /DWINDIVERTEXPORT=extern /I miga_client\include miga_client\tests\TunnelSendTests.cpp /FoBuild\tests\TunnelSendTests.obj /FeBuild\tests\tunnel-send-tests.exe /link ws2_32.lib iphlpapi.lib
Build\tests\tunnel-send-tests.exe
```

Covers outer IPv4/UDP lengths, checksums, source/destination ports, odd payloads, maximum UDP size, MTUs 68/576/1500/65535, fragment offsets and reconstruction, batches of at most 64 fragments, invalid lengths, send failure, immediate/pending/error completions, immutable buffer/address ownership including inbound/outbound direction, IPv6, interface, timestamp and checksum flags, bounded pool backpressure, cancellation while full, draining and restart. Route notifications and loopback source selection use the real IP Helper API. Async completion/cancellation use substituted API functions; actual driver completion, firewall/NAT, route changes, packet ordering, tunnel traffic and latency remain live checks.