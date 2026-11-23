# Protocol v2 independent review tests

Build the pinned Windows x64 libraries with dependencies/build-windows.ps1, then run from the repository root:

```bat
dependencies\run-review-tests.cmd
```

Tests compile with /W4 /WX and use the actual libsodium and Noise-C implementations. They cover seven-field invitation round trips, duplicate JSON rejection, canonical Base64URL, independently calculated daily HMAC, personal proof and multiblock HKDF/session vectors, key-role/session separation, authenticated control tampering and short frames, Noise NK transcript agreement and tampering, replay-window boundaries, padding/MTU limits, keepalive format, incremental IP/TCP/UDP checksums, TCP options and source/destination translation round trips, malformed or oversized inner packets, maximum-size out-of-order fragmentation, DF/ICMP feedback, IPv4 option copy bits and overlapping-fragment rejection.

The test does not use WinDivert, sockets, TUN, firewall, installed configuration or real keys. It does not establish real-network throughput or DPI resistance. Generated output stays in Build/protocol-v2/review.
