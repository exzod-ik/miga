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
| NetworkRuntimeTests | Production runtime with substituted WinDivert API: process isolation, owner deadlines, FIFO, tunnel wire round trip and reverse IP, route unavailability/recovery, direct DNS reinjection, private resolver routing in split and full modes, DNS replies in both orders, multiple A records, ID collision isolation, TTL, process/static/dynamic priority, server reorder, reload barrier, idle wakeup, cancellation and repeated network-loop stop/start. |
| LoggerTests | Sync/async recording, captured timestamps, escaping, concurrent aggregates, queue overflow and level change without file truncation. |
| PacketBufferPoolTests | Size classes, reuse, source preservation, cross-thread returns and buffers surviving pool destruction. |
| TunnelSendTests | MTU fragmentation, checksums, asynchronous completion/error/cancellation, slot lifetime, batch limits, partial flush and restart. |

После сборки запустите из корня репозитория `Build\tests\network-runtime-tests.exe --benchmark`. Тест измеряет путь от входа в PacketReceived до синхронной подмены WinDivertSendEx для установленных IPv4-потоков TCP и UDP, отдельно для исходящего и входящего трафика через VPS и напрямую. При включённом резолвере используется готовое соответствие виртуального и реального IP. Размеры IP-пакетов — 40 и 1400 байт, пачка — 64 пакета. После 64 прогревочных пачек выводятся медиана и 95-й процентиль среднего времени на пакет в пачке. По умолчанию флаги валидности контрольных сумм сброшены. Параметр `--benchmark-valid-checksums` измеряет случай, когда суммы уже вычислены до перехвата. Сравнивайте сборки с одинаковой оптимизацией при одинаковой загрузке машины.

Old architecture tests have been removed after migrating relevant regression cases to the current runtime and mailbox. The pre-cleanup source snapshot is in Artifacts/previous-builds/backups/before-legacy-cleanup-20261104-005019.

See [../ARCHITECTURE.md](../ARCHITECTURE.md) for the current thread ownership and limits. Native capture, real startup snapshot races, interface-change notifications, driver fragment reassembly, MSI installation and actual CPU/latency improvement require live verification. Windows test builds do not prove Linux toolchain compatibility.

Миграция Windows: `dotnet run --project "MIGA Agent/tests/InvitationTests.csproj" -c Release` проверяет перенос правил и глобальных настроек, состояния приглашений, повторную загрузку, отклонение повреждённых данных и атомарную запись на изолированных файлах. RoutingIndexTests проверяет отключение транспортов при requires_invitation, отклонение противоречивых состояний и восстановление маршрутов после импорта всех профилей.

Авторизация диагностики: ProtocolV2SessionTests проверяет DiagnosticOpen/DiagnosticReply через настоящий loopback Noise-сеанс. `dotnet run --project miga_diagnostics/tests/LocalDiagnosticsTests.csproj -c Release` проверяет локальные capture/route без авторизации, пропуск серверных проб и отсутствие открытия серверного канала при локальном выборе; используется уникальный тестовый named pipe, рабочая служба и сеть не затрагиваются. Тесты Agent проверяют совпадение, подмену и неверный формат отпечатка TLS.

Profile pipe delivery regression (Windows, isolated unique pipe, no installed service):

    miga_client\tests\run-v2-profile-pipe-tests.cmd

Runs the production profile server loop with a test pipe name and test-user ACL. Checks delayed reads after the server closes its handle, repeated listeners, a disconnected peer, and bounded stop while waiting for a request or connection. It does not load or save real profiles.
