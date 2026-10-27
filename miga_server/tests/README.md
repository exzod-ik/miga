# TCP connection state tests

Tests exercise the production TCP state and IPv4/TCP parser without sockets, TUN, configuration files or privileges.

From the repository root on Linux:

```sh
mkdir -p Build/tests
g++ -std=c++17 -Wall -Wextra -Werror -I miga_server/include miga_server/tests/TcpConnectionStateTests.cpp -o Build/tests/tcp-state-tests
./Build/tests/tcp-state-tests
```

From an x64 Visual Studio Developer Command Prompt:

```bat
if not exist Build\tests mkdir Build\tests
cl /nologo /std:c++17 /EHsc /W4 /WX /I miga_server\include miga_server\tests\TcpConnectionStateTests.cpp /FoBuild\tests\TcpConnectionStateTests.obj /FeBuild\tests\tcp-state-tests.exe
Build\tests\tcp-state-tests.exe
```

A single FIN retains the 124-minute idle timeout. Two FINs, a reset or a retired mapping use a 4-minute idle timeout. Traffic in either direction refreshes the idle timer. Both FIN acknowledgments are tracked with wrapping sequence numbers; retransmissions retain their route. A new SYN with a different initial sequence number can get a new port after closing begins, while the old port remains reserved until cleanup.

These tests do not replace Linux server compilation or TCP/UDP integration tests through TUN.

Port pool and connection-key tests:

```bat
cl /nologo /std:c++17 /EHsc /W4 /WX /I miga_server\include miga_server\tests\PortPoolTests.cpp /FoBuild\tests\PortPoolTests.obj /FeBuild\tests\port-pool-tests.exe
Build\tests\port-pool-tests.exe
```

On Linux, compile PortPoolTests.cpp with the same include path and compiler flags used above for TcpConnectionStateTests.cpp. The test exhausts and replenishes the full port range, checks single-free-port allocation, duplicate release, independent TCP/UDP pools and full five-tuple key equality.
Interface IP cache tests (Linux only, no root, TUN or firewall changes):

```sh
g++ -std=c++17 -Wall -Wextra -Werror -pthread -I miga_server/include miga_server/tests/InterfaceIpCacheTests.cpp -o Build/tests/interface-ip-cache-tests
./Build/tests/interface-ip-cache-tests
```

The tests cover initial address lookup, missing and loopback interfaces, concurrent reads, repeated stop/start, waking an idle watcher and descriptor cleanup. Run on a host with stable interface addresses. Live address replacement, interface removal/recreation and netlink overflow/reconnection still require separate Linux integration checks.

The cache subscribes to NETLINK_ROUTE link and IPv4-address notifications before its initial snapshot. Packet handling only reads an atomic IPv4 value. Notifications trigger a fresh getifaddrs snapshot, including after notification loss. A failed subscription is retried every five seconds with periodic snapshots until it recovers. A failed snapshot publishes zero and is retried. Selection remains the configured interface, or the first non-loopback IPv4 when no interface is configured; no address yields zero as before. Stop wakes poll through eventfd and joins the watcher before closing descriptors.

Checksum tests (portable C++17):

```bat
cl /nologo /std:c++17 /EHsc /O2 /W4 /WX /I Shared miga_server\tests\ChecksumTests.cpp /FoBuild\tests\ChecksumTests.obj /FeBuild\tests\checksum-tests.exe
Build\tests\checksum-tests.exe
```

On Linux:

```sh
g++ -std=c++17 -O2 -Wall -Wextra -Werror -I Shared miga_server/tests/ChecksumTests.cpp -o Build/tests/checksum-tests
./Build/tests/checksum-tests
```

Checks cover every size from 0 through 65547 bytes against the previous contiguous-buffer checksum, split pseudoheader/payload, odd split positions, unaligned input, empty fragments, carry folding and a known checksum. These portable tests do not compile ServerCore or validate live TCP/UDP forwarding.
