# Server tests

Run `python3 miga_server/tests/ServerUpdateMigrationTests.py` for isolated installer configuration, legacy migration, v2 host preservation, active/stopped service behavior, rollback after install/readiness/partial-stop failures, continued restoration after a file failure, and exact legacy NAT cleanup. On Linux, set `MIGA_TEST_SERVER_BINARY` to a built server ELF to use its real `--version` output in the update and migration checks. System commands, systemd, firewall and RX rings are substituted; the tests do not install or deploy anything. `python3 miga_server/tests/InstallerIcmpCleanupTests.py` separately verifies exact legacy ICMP DROP cleanup.

Run `python3 miga_server/tests/ServerInstallerIntegrationTests.py` for the actual shell/Python installer sequence with temporary filesystem paths and command adapters, including RX, binary replacement, sysctl, service start, ICMP cleanup, occupied control ports and subnet exhaustion failures. Package-manager entry points fail closed. Windows needs Git Bash (`MIGA_TEST_BASH` can override its path). Readiness tests execute the production polling functions with substituted sockets/process observations. See [UPGRADE_VALIDATION.md](UPGRADE_VALIDATION.md) for the validation matrix and the unverified real Linux/systemd boundary.

Protocol v2 isolated storage and session tests use the production SQLite store and complete Noise/UDP control runtime. The runtime test substitutes a Unix datagram socketpair for TUN and temporary executable stubs for iptables/conntrack; it does not initialize TUN, install rules or start the daemon service. It covers a wrong personal proof, real NK/BIND, lost READY recovered through STATUS, personal/global limits, two invitations with identical local addresses and ports, virtual-source and endpoint isolation, response ownership, ADD_ADDRESS retries, RESUME at the active-session limit, persisted replay rejection after restart, disconnect/revoke, stable routing snapshots during idle maintenance, client listing across multiple admin socket pages, and bounded child-command timeout. Do not compile tests with NDEBUG, because assertions execute the tested operations.

Run `python3 miga_server/tests/run-v2-tests.py` from a Linux checkout. It builds the pinned dependencies locally, compiles the SQLite store test, the common Windows/Linux wire-vector review, and the private runtime fixture, then executes them with C++17 and `-Wall -Wextra -Werror`. OpenSSL headers/libraries must already be available; set `MIGA_OPENSSL_PREFIX` for a local static installation. See [the runtime notes](../PROTOCOL_V2.md) for resource bounds and unverified live scenarios.

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

Checks cover every size from 0 through 65547 bytes against the previous contiguous-buffer checksum, split pseudoheader/payload, odd split positions, unaligned input, empty fragments, carry folding and a known checksum. These portable tests do not validate live TCP/UDP forwarding.

Diagnostic control tests are included in `python3 miga_server/tests/run-v2-tests.py`. They exercise packet correlation, virtual destination isolation, real loopback TLS with the certificate fingerprint, wrong tickets, one-time use, expiry, revocation before/after authorization, and stop cleanup. No certificate files, root, daemon deployment or firewall changes are required. The runtime fixture verifies DiagnosticOpen over real authenticated v2 control and idempotent replies.

Network counter tests (Linux; no root, daemon changes or firewall):

~~~sh
g++ -std=c++17 -Wall -Wextra -Werror -I miga_server/include -I Shared miga_server/tests/DiagnosticNetworkStatsTests.cpp miga_server/src/DiagnosticNetworkStats.cpp -o Build/tests/diagnostic-network-tests
./Build/tests/diagnostic-network-tests
~~~

Covers exact 64-bit deltas, reset/missing counters, boot/interface/socket replacement and unavailable socket statistics. Includes a read-only loopback snapshot. Report formatting tests: dotnet run --project miga_diagnostics/tests/ServerNetworkReportTests.csproj.

Нагрузочная диагностика: `python3 tests/run-v2-tests.py diagnostic-load diagnostic-control runtime`. DiagnosticLoadTests проверяет ограничения, повреждённые пакеты, старые ступени, уникальные номера/повторы/перестановки, реальный loopback UDP в обе стороны с буфером 8 МиБ и повторную очистку. Firewall подменён; тест не проверяет настоящий TUN/WinDivert и сетевые потери между машинами.

`python3 tests/InstallerIcmpCleanupTests.py` проверяет удаление старого ICMP DROP из установщика: точное совпадение, дубликаты, сохранённые правила, повторный запуск и ошибки iptables. Команды iptables подменены; сетевые правила машины не меняются.

`python3 tests/ServerDependencyTests.py` проверяет общий Bash helper с подменой поиска команд и пакетных менеджеров: все зависимости уже есть, apt/dnf/yum, ошибки и таймауты, неподдерживаемый менеджер, systemd, проверку после установки и порядок подготовки до остановки. На Windows используется Git Bash (или MIGA_TEST_BASH). Реальные пакеты не устанавливаются; apt/systemd и сеть VPS этими тестами не проверяются. `python3 tests/ServerUpdateMigrationTests.py` проверяет миграцию и откат в изолированной файловой системе.
