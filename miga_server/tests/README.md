# TCP connection state tests

Tests exercise the production TCP state and IPv4/TCP parser without sockets, TUN, configuration files or privileges.

From the repository root on Linux:

```sh
mkdir -p Build/tests
g++ -std=c++17 -Wall -Wextra -Werror -I miga_server/include miga_server/tests/TcpConnectionStateTests.cpp miga_server/src/TcpConnectionState.cpp -o Build/tests/tcp-state-tests
./Build/tests/tcp-state-tests
```

From an x64 Visual Studio Developer Command Prompt:

```bat
if not exist Build\tests mkdir Build\tests
cl /nologo /std:c++17 /EHsc /W4 /WX /I miga_server\include miga_server\tests\TcpConnectionStateTests.cpp miga_server\src\TcpConnectionState.cpp /FoBuild\tests\ /FeBuild\tests\tcp-state-tests.exe
Build\tests\tcp-state-tests.exe
```

A single FIN retains the 124-minute idle timeout. Two FINs, a reset or a retired mapping use a 4-minute idle timeout. Traffic in either direction refreshes the idle timer. Both FIN acknowledgments are tracked with wrapping sequence numbers; retransmissions retain their route. A new SYN with a different initial sequence number can get a new port after closing begins, while the old port remains reserved until cleanup.

These tests do not replace Linux server compilation or TCP/UDP integration tests through TUN.

Port pool and connection-key tests:

```bat
cl /nologo /std:c++17 /EHsc /W4 /WX /I miga_server\include miga_server\tests\PortPoolTests.cpp miga_server\src\ConnectionKey.cpp miga_server\src\PortPool.cpp /FoBuild\tests\ /FeBuild\tests\port-pool-tests.exe
Build\tests\port-pool-tests.exe
```

On Linux, compile PortPoolTests.cpp with the same include path and compiler flags used above for TcpConnectionStateTests.cpp. The test exhausts and replenishes the full port range, checks single-free-port allocation, duplicate release, independent TCP/UDP pools and full five-tuple key equality.
Interface IP cache tests (Linux only, no root, TUN or firewall changes):

```sh
g++ -std=c++17 -Wall -Wextra -Werror -pthread -I miga_server/include miga_server/tests/InterfaceIpCacheTests.cpp miga_server/src/InterfaceIpCache.cpp -o Build/tests/interface-ip-cache-tests
./Build/tests/interface-ip-cache-tests
```

The tests cover initial address lookup, missing and loopback interfaces, concurrent reads, repeated stop/start, waking an idle watcher and descriptor cleanup. Run on a host with stable interface addresses. Live address replacement, interface removal/recreation and netlink overflow/reconnection still require separate Linux integration checks.

The cache subscribes to NETLINK_ROUTE link and IPv4-address notifications before its initial snapshot. Packet handling only reads an atomic IPv4 value. Notifications trigger a fresh getifaddrs snapshot, including after notification loss. A failed subscription is retried every five seconds with periodic snapshots until it recovers. A failed snapshot publishes zero and is retried. Selection remains the configured interface, or the first non-loopback IPv4 when no interface is configured; no address yields zero as before. Stop wakes poll through eventfd and joins the watcher before closing descriptors.

Checksum tests (portable C++17):

```bat
cl /nologo /std:c++17 /EHsc /O2 /W4 /WX /I Shared miga_server\tests\ChecksumTests.cpp Shared\InternetChecksum.cpp /FoBuild\tests\ /FeBuild\tests\checksum-tests.exe
Build\tests\checksum-tests.exe
```

On Linux:

```sh
g++ -std=c++17 -O2 -Wall -Wextra -Werror -I Shared miga_server/tests/ChecksumTests.cpp Shared/InternetChecksum.cpp -o Build/tests/checksum-tests
./Build/tests/checksum-tests
```

Checks cover every size from 0 through 65547 bytes against the previous contiguous-buffer checksum, split pseudoheader/payload, odd split positions, unaligned input, empty fragments, carry folding and a known checksum. These portable tests do not compile ServerCore or validate live TCP/UDP forwarding.

Tunnel ingress tests (portable C++17):

```sh
g++ -std=c++17 -Wall -Wextra -Werror -I miga_server/include miga_server/tests/TunnelIngressTests.cpp miga_server/src/TunnelIngress.cpp -o Build/tests/tunnel-ingress-tests
./Build/tests/tunnel-ingress-tests
```

Tests cover IPv4 options, UDP port byte order and configured boundaries, short and empty datagrams, invalid lengths and fragments. Linux reassembles outer fragments before the raw socket filter. Return traffic uses raw UDP with IP_PKTINFO and IP_PMTUDISC_DONT so Linux can fragment according to the route. An end-to-end MTU check requires a Linux route with constrained MTU and a receiving client.

Linux raw packet path regression (requires CAP_NET_RAW; the constrained-MTU namespace also requires namespace/network administration privileges):

```sh
g++ -std=c++17 -O2 -pthread -I miga_server/include -I Shared miga_server/tests/ServerPacketPathTests.cpp miga_server/src/ServerCore.cpp miga_server/src/TunnelIngress.cpp Shared/InternetChecksum.cpp Shared/Encryption.cpp Shared/LogFormat.cpp Shared/LogTime.cpp Shared/Logger.cpp miga_server/src/ConnectionKey.cpp miga_server/src/InterfaceIpCache.cpp miga_server/src/PortPool.cpp miga_server/src/TcpConnectionState.cpp -o Build/tests/server-packet-path
unshare -n sh -ec 'ip link set lo mtu 1280 up; exec Build/tests/server-packet-path'
```

The test uses a private loopback network, a datagram socket pair in place of TUN, and real raw UDP receive/filter/send. It round-trips 4096-byte inner TCP and DNS/UDP packets, including restoration of the original DNS address and the outer source port. It does not install firewall rules or start the daemon.
