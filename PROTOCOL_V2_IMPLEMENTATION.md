# Protocol v2 implementation

Protocol v2 is the only transport. Old configurations and protocol 1 are rejected. Custom control ranges are restricted to UDP ports 1024–65535, default 10000–15000. The server uses ordinary UDP sockets and Linux conntrack. Windows and Android share ProtocolV2Session and Shared cryptography; Android supplies already protected, network-bound sockets. Building does not install or deploy anything.

## Components

- `Shared/ProtocolV2.h/.cpp`: canonical control encoding, invitation validation, HKDF/HMAC, Noise NK, XChaCha20-Poly1305 control envelopes, independent ChaCha20-IETF data datagrams, directional session keys and IPv4 checksum adjustment.
- `Shared/ProtocolV2Packets.h/.cpp`: Standard inner fragmentation/DF feedback and bounded overlap-rejecting reassembly.
- `miga_client/ProtocolV2Session`: one asynchronous control worker per configured VPS, immutable session snapshots for NETWORK, bounded additional-address requests, idle keepalive and authenticated recovery.
- `miga_client/ProtocolProfiles`: administrative `MigaProfiles-v2` named pipe, machine-scope DPAPI and protected SYSTEM/Administrators-owned profile files under `%ProgramData%/MIGA/profiles`. Configuration contains `protocol: 2` and `profile_id`, never invitation secrets. Existing MIGA/profile directories and profile files are rejected unless their owner SID is LocalSystem or Builtin Administrators; tightening a DACL alone would leave a precreating standard user able to restore access as owner. The Agent verifies the pipe server PID against the running MigaClient service before sending credentials. A bounded status operation reports connecting, ready, recovering or unavailable; READY is required for ready status.
- `miga_server/V2Server`: separate control/session transport, virtual-address routes, ordinary UDP data workers and TUN forwarding. `ClientStore` persists invitation records and accepted-handshake history in SQLite. Server resource bounds, administrative commands and isolated-test details are documented in `miga_server/PROTOCOL_V2.md`.
- Agent: invitation import, local connection names and SSH administrative client/limit controls. Installation requires the explicit v2 action.

## Canonical wire details

All integers below are big-endian. Byte arrays are concatenated without native structure padding. HKDF uses RFC 5869 SHA-256: Extract with a 32-byte zero salt, Expand info is UTF-8 purpose label followed by one zero byte and context. Server-wide labels use an empty context. Session context is `handshake_hash[32] || client_id[16] || session_id[16]`.

The encrypted message header is `version:u16=2 || operation:u16 || request_id[16] || body_length:u16 || body`. The remaining plaintext is random padding. Initial outer XChaCha20-Poly1305 envelopes have `nonce[24] || ciphertext || tag[16]`; total payload is uniform 384вЂ“768 bytes when the content fits. Larger content uses the minimum required size, never above 1200 bytes.

HELLO body is `client_id[16] || unix_time:u64 || noise_length:u16 || noise_message || personal_hmac[32]`. The Noise initiator payload is `address_count:u8 || local_ipv4:u32...`. HMAC input is `version:u16 || client_length:u16=16 || client_id || time_length:u16=8 || unix_time:u64 || request_length:u16=16 || request_id || server_key_length:u16=32 || server_public_key || noise_length:u16 || noise_message`.

HELLO_REPLY contains the Noise responder message. Its authenticated Noise payload is OPEN_REPLY: `session_id[16] || session_secret[32] || bind_challenge[32] || session_port:u16 || address_count:u8 || (local_ipv4:u32 || virtual_ipv4:u32)...`.

Subsequent outer plaintext is `session_id[16] || sealed_length:u16 || sealed_control || padding`. The inner personal XChaCha20-Poly1305 plaintext is `control_counter:u64 || encoded_message`. The explicit encrypted length avoids guessing AEAD boundaries inside random outer padding. Only control has a 64-message replay window.

BIND carries its 32-byte challenge. READY is returned through the control endpoint. STATUS READY includes accepted-data counter and session generation as two u64 fields; these permit a client health hypothesis without treating unauthenticated data as proof of receipt. ADD_ADDRESS carries local IPv4:u32 and ADDRESS_REPLY carries local IPv4:u32 plus virtual IPv4:u32. RESUME carries resume_secret[32], address_count:u8 and local IPv4:u32 values. CLOSE is empty.

Data is `random_nonce[8] || ChaCha20-IETF(inner_ipv4 || random_padding)`, with nonce `direction_prefix[4] || random_nonce[8]` and initial block counter 0. There is no data authentication tag, packet counter, replay window or automatic rekey. Short datagrams use uniform 96вЂ“256-byte padding capped by the path MTU; padding never forces fragmentation. Keepalive plaintext has an IP version other than 4 and never reaches TUN.

The high bit of the 64-bit generation in authenticated Ready messages advertises support for data-path probes. The Ready body remains 16 bytes. The server echoes a probe on the active session UDP socket using the opposite direction key. The encrypted non-IPv4 record contains a request or reply marker (0x71 or 0x72), a 16-byte token and a 32-byte HMAC over the marker and token. Each probe occupies 57 bytes of UDP payload including the 8-byte data nonce. These records do not enter TUN. Android uses this capability after outgoing traffic has gone unanswered and reconnects only that profile after three unanswered probes. A server without the capability keeps the existing recovery behavior.

## Runtime ownership and bounds

NETWORK retains routing, DNS-facing tuple identity, data encryption/decryption and existing asynchronous WinDivert send lifetimes. Control workers never execute Noise, SQLite or synchronous control exchanges on NETWORK. Session snapshots keep data keys, port and up to 16 address mappings immutable. Unchanged profile transports retain sessions across reload; send pools drain before configuration publication.

Selected tunnel packets waiting for a session/address have a separate limit of 1024 packets, 4 MiB and 30 seconds. Expiry drops them; it does not send them directly. IPv4 reassembly has independent limits of 1024 entries, 4 MiB and 30 seconds; overlapping fragments invalidate the assembly. Expiration is ordered and bounded per fragment, with no per-packet scan of all entries.

The client uses random 30вЂ“60-second idle keepalive intervals. Random control health checks compare the authenticated accepted-data counter against local sends; missing progress is a recovery hypothesis, not proof of packet loss. Local route/address changes request protected recovery. Ordinary unauthenticated packets never change the peer endpoint.

## Build and validation

Pinned archives and hashes are in `dependencies/manifest.json`. `dependencies/build-windows.ps1` builds static crypto libraries, and `dependencies/run-review-tests.cmd` runs independent shared wire/crypto/packet tests. Client regression commands remain in `miga_client/tests/run-tests.cmd`; Agent invitation parser tests are under `MIGA Agent/tests`. `miga_client/tests/run-v2-profile-owner-tests.cmd` checks real Win32 owner metadata on isolated workspace files, including rejection after DACL tightening. `miga_client/tests/run-v2-session-tests.cmd` exercises real Noise/control exchanges over isolated loopback UDP, including address addition, recovery, lost READY reconciliation and cancellation; the network-restricted sandbox requires an approved loopback test executable run.

Building and stub/local-process tests do not validate the installed WinDivert driver, real NAT rebinding, production firewall/conntrack, VPS coexistence, installation, upgrade/rollback or DPI behavior. These require separately authorized live validation. Data encryption deliberately lacks integrity and replay protection as agreed in `PROTOCOL_V2_DESIGN.md`.

## Review and performance boundaries

The data path does not enter Noise, SQLite or firewall operations. Session control publishes immutable routing/key snapshots; server data workers use bounded UDP batches (`recvmmsg`, up to 16) and reusable buffers. The server poll set scales with active socket count and is capped at 512. Session, pending-request, address, quarantine, queue and fragment limits bound retained resources; limit failure rejects new work rather than evicting established connections.

Client data encryption writes directly into the reusable outer UDP datagram payload through EncryptDataInto and TunnelDatagram::BuildGenerated. There is no intermediate encrypted full-packet buffer or plaintext staging copy. The existing copy into the AsyncTunnelSender-owned overlapped buffer remains necessary until asynchronous completion. Random padding uses a bounded 256-byte scratch buffer and continues the same ChaCha20 stream position. Wire bytes and padding rules are unchanged.

Each new session data socket requires at least 8 MiB of actual SO_RCVBUF capacity, verified with getsockopt. Linux doubles the requested value; SO_RCVBUFFORCE is attempted when the normal request is capped. Failure to obtain the target refuses session creation and records errno, rather than silently using a smaller buffer. Control and newly reconstructed quarantine sockets retain a small buffer. Capacity is not allocated upfront: 64 active sessions allow about 512 MiB of receive queues, and the hard 1024-socket bound allows up to about 8 GiB if all sockets retain the large setting. Retired snapshots and quarantined sockets also count toward resource bounds.

Secure random generation and atomic shared-pointer snapshot access still have costs. No CPU, latency, throughput or DPI improvement is claimed without measurement. Legacy code inventory is recorded in PROTOCOL_V2_LEGACY_AUDIT.md.

## Diagnostics authorization

DiagnosticOpen=13 has an empty body and requires an active session. DiagnosticReply=14 returns port (2 bytes big-endian), SHA-256 certificate fingerprint (32 bytes), and a single-use random ticket (32 bytes); an empty body means unavailable. Session control protects all parameters. The separate TLS channel pins that certificate and requires authorize with the ticket before accepting commands. Tickets expire after 30 seconds; diagnostic connections after 5 minutes. Session close/revoke cancels access. See DIAGNOSTICS.md for local-only behavior and deployment requirements.
