# Linux 1.2.5 to protocol v2 upgrade validation

Audit date: 2026-11-15. The original Windows/Git Bash fixture audit is retained below. A subsequent real Linux/systemd integration run passed all seven upgrade/rollback scenarios in an isolated container on the authorized build host. Production VPS instances were not accessed. No host service, firewall, route or package installation was changed.

## Real Linux integration

Seven scenarios passed using actual Linux ELF binaries, systemd, TUN, iptables, sysctl, filesystem backup/restore and the production updater. The legacy binary was compiled from Git snapshot `68613ad` with its actual server sources and Shared.vcxitems sources, C++17, `-O0` and pthread. The candidate is the existing current build, version 1.3.0. No production source correction was needed and no MSI was rebuilt for this run. All four tested scripts were copied from the current sources; their bytes also match current MSI staging bdf4f2967ee242b795d1535f453589e2. Source and LF-normalized hashes are recorded in the typed summary. The candidate SHA-256 matches the local ELF used by that package.

| Scenario | Initial state | Result |
| --- | --- | --- |
| Empty legacy interface, default ports/log/DNS | Active, enabled | Upgrade passed; v2 active/enabled |
| Failure after actual v2 service start | Active, enabled | Complete rollback; original 1.2.5 ready |
| Explicit legacy interface | Stopped, disabled | Upgrade passed; stopped/disabled preserved |
| Missing legacy interface | Active, disabled | Upgrade passed; active/disabled preserved |
| Failure after binary replacement | Active, enabled | Complete rollback; original 1.2.5 ready |
| Failure after unit replacement | Active, disabled | Complete rollback; original 1.2.5 ready |
| Failure after unit replacement | Stopped, disabled | Complete rollback; stopped/disabled preserved |

Success assertions checked installed version and candidate SHA-256, migrated defaults, removal of legacy encryption fields, resolved eth0 interface, original config/state backup contents, administrative settings response, live TUN and v2 NAT chains. Rollback assertions compared original binary, config, unit, state sentinel, persistent firewall file and semantic runtime firewall rules. Active rollbacks additionally required stable original process identity, version 1.2.5 and its actual ICMP type-3 rule. Foreign filter/NAT rules and a destination-specific ICMP rule survived every case; the obsolete MIGA ICMP/NAT rules were removed on success. Final stopped rollback left no stale TUN.

Faults were injected only into disposable copies of install-v2.sh, with exit 77 after the indicated real operation. Each case removed its previous unique stage marker, compared the installed binary with the candidate and wrote the marker only after reaching the target operation. Tests asserted those markers as well as complete rollback. System commands were not substituted. The production update-v2.py was unchanged.

Isolation used Docker 20.10.5 and official Debian 11 pinned to `sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9`, systemd 247.3-7+deb11u5 and private PID/mount/network/cgroup namespaces. The runtime container used network=none, SYS_ADMIN and NET_ADMIN, a TUN device, seccomp/AppArmor unconfined, 640 MiB memory, one CPU and 256 PIDs. It was not privileged and had no host network or writable host bind mounts. The sole bind source was staged .deb files, read-only. The private cgroup mount was replaced inside the container namespace. Only the namespaced net.ipv4.ip_forward file was exposed writable; setting it to zero left host forwarding at one. Synthetic eth0/default routing exercised automatic interface lookup without external traffic.

Real apt package installation ran offline from a staged file repository. Removing conntrack inside the container and running the unmodified prepare-dependencies.sh produced `server_dependencies_ready installed=1`; dpkg audit was clean. The candidate executed against Debian 11 runtime libraries without missing dependencies. Initial cached security-package URLs returned 404, so the disposable rootfs used explicitly selected base bullseye packages; host apt metadata and packages were not changed. Setup timeouts and the corrected harness expectation for legacy ICMP type 3 were setup issues, not product defects.

Binary SHA-256:

- Legacy 1.2.5: `53cefb01ecee385e06feb991f40c46275cfb8f14f6fca6ae41b7bd5af1d74942`.
- Candidate 1.3.0: `f1e157cf14509aa262639de96916dcfb78b7554cd0b6898c8d0213fbf59a11ae`.

Local evidence: `Artifacts/linux-upgrade/upgrade-linux-summary.json` contains the seven typed results, reached-stage flags, hashes, isolation limits and cleanup invariants. `Artifacts/linux-upgrade/upgrade-linux-matrix.log`, `Artifacts/linux-upgrade/upgrade-linux-legacy-bootstrap.log` and `Artifacts/linux-upgrade/upgrade-linux-cleanup.log` contain execution outcomes. The reproducible disposable harness remains at `Artifacts/linux-upgrade/upgrade-real-linux.py`. Automatic approval review rejected exporting raw remote journals, including after a sensitive-marker scan; only the typed summary was exported, without config/state/keys or raw logs.

Both test containers, both newly created images and staged dependency/source/binary payloads were removed. Host routes, semantic firewall rules and IPv4 forwarding matched the before-test snapshots both before and after cleanup. Disk free space returned to 4.3 GiB. No host installation, service restart, firewall write or production VPS operation occurred.

## Reproduce

From the repository root:

```powershell
python3 -m unittest discover -s miga_server/tests -p 'Server*Tests.py' -v
dotnet build 'MIGA Agent/MIGA Agent.csproj' --no-restore --configuration Release
git diff --check
```

Python executable used: `C:/Users/exzod/AppData/Local/Python/bin/python3.13.exe`. Shell executable: `C:/Program Files/Git/bin/bash.exe`. Git Bash required execution outside the filesystem sandbox; the fixture itself uses only temporary directories and substituted system commands. Python discovery passed 34 unittest methods: 8 dependency, 21 migration/readiness, 5 installer integration. After adding strict DNS string validation, all 21 migration/readiness methods were repeated and passed. The independent ICMP assertions passed in the preceding audit. The seven installer fault injections are subcases within one method, not seven additional methods.

The installer fixture executes transformed copies of `install-v2.sh`, nested `install.sh --configure-rx-ring`, `prepare-dependencies.sh`, and their actual embedded Python. Absolute Linux paths point into one temporary tree. The staged executable is a version-only fixture; daemon initialization, ip/systemctl/iptables/sysctl/ethtool and installation permissions use adapters. Unknown adapter commands fail. Apt/dnf/yum and timeout functions fail closed. The wrapper uses its production backup/restore/control flow with system adapters. Readiness functions execute separately with substituted socket responses, process observations and time.

## Matrix

| Boundary | Evidence | Result |
| --- | --- | --- |
| Agent selects upgrade for old version, binds action to connected host, quotes host/interface | Source review of ServerTabViewModel | Checked statically |
| SFTP private staging, binary SHA/version, LF scripts, 15-minute command timeout, cleanup | Agent/SshManager source review; Release build | Checked statically; no live SSH |
| Cleanup fails after installation | Cleanup error is reported separately; original installation result retained | Fixed; build checked |
| Missing dependencies, apt/dnf/yum mapping, package failure/timeouts and secret-safe output | 8 dependency methods with manager/failure subcases | Passed; no real package installation |
| Recognize legacy 1.2.5 config and version; reject invalid schema | Migration tests; read-only `68613ad` main/ServerCore/install source | Passed for the supported schema |
| Standard unit, command line, PID executable, no DropIns/stale daemon cache | Pre-stop rejection tests and source review | Passed; enabled/disabled only |
| Snapshot files/state, permissions and RX/service metadata | Wrapper source; fixture backups/restoration | Passed for fixture files; Linux ownership not exercised |
| State backup fails after stop | No installer invocation; old state retained and server restarted | Passed |
| Legacy config conversion, settings retained and keys removed | Actual installer shell/Python fixture | Passed |
| Occupied control ports / no nonoverlapping private /16 | Actual embedded Python rejects; wrapper restores snapshot | Passed |
| Binary replacement, RX configuration, sysctl load, service start, ICMP cleanup fail | Seven actual-installer fault subcases, each asserting its reached stage/reason | Passed |
| Initially active/stopped and disabled server | Actual-installer success fixtures | Passed; original state restored after readiness |
| Existing v2 host and update mode | Migration test | Passed |
| v2 administrative settings response and four stable PID observations | Production ready() with socket/process adapters; PID replacement, invalid JSON, socket error, late death, timeout | Passed; no data-path proof |
| Failure / timeout / interruption after partial changes | Wrapper failure subcases; run() process-group cancellation tests | Passed with subprocess/signal adapters |
| Partial stop failure | Existing wrapper failure subcase | Passed |
| Restore directory copy fails | Current state remains until staged backup copy succeeds | Regression passed |
| Binary/config restore fails | Remaining files restored; failed path emitted; server remains stopped; incomplete reported | Regression passed |
| Legacy restart creates ICMP rule late | Production legacy_ready() waits for rule/stable PID/executable before firewall normalization | Regression passed with process/firewall adapters |
| Runtime foreign firewall rules and broad legacy MASQUERADE | Scoped ownership/restore tests | Passed |
| Concurrent foreign persistent firewall change | File retained, conflict path/reason and incomplete rollback; server stays stopped | Regression passed; requires manual reconciliation |
| Exact legacy NAT/ICMP and persisted duplicates | Actual cleanup plus isolated ownership/idempotence/error tests | Passed |
| Client invitation after migration | Agent migration result explains new miga2 invitations; ManageClients shares SSH; import persists profile/dirty/reloads service | Source review only; no UI/live invitation round trip |
| MSI payload chain | build.ps1, wixproj, Package.wxs reviewed; current Agent republished; fresh staging and actual MSI extraction, 24 hashes compared | Passed; scripts also match repository sources; no config/log/key payload |

## Legacy automatic interface correction

The 1.2.5 sources at HEAD define `ServerConfig.interface = ""`; `UpdateConfigFile` writes that value, while `InterfaceIpCache::Refresh` treats it as automatic selection of the first non-loopback IPv4 interface. The v2 updater incorrectly required a nonempty interface before detecting the legacy protocol. This proves a compatibility defect; the reported VPS configuration has not been read, so the actual stored value remains unverified.

For legacy protocol 1 or absent protocol only, missing/empty interface now triggers `ip -j -4 route get 1.1.1.1` before service stop. This is a local route lookup, without transmitting a packet. Exactly one unicast result with a safe explicit device name is required; loopback/tun devices and missing devices fail before stop. `ip link show dev` verifies existence. Explicit names remain explicit. V2 configurations still require a name. The resolved name is passed to the installer without modifying the original file before backup. Choosing the kernel route to this public IPv4 destination is a migration policy; it is not proof that every policy-routed destination uses that device.

The adjacent legacy load defaults are also preserved: absent client ports mean 10000-15000; absent log level means none; absent DNS or 0.0.0.0 means disabled DNS, represented by an empty string in v2. The v2 server skips the DNS NAT rule for that string. Missing encryption keys still fail as they did in the old loader. Non-string DNS values are rejected. Regression coverage includes empty and missing interfaces through the actual installer fixture, original backup contents, default migration, invalid/ambiguous route results, lookup failure before stop, explicit link failure, and v2 empty-interface rejection.

## Packaged artifact

The rebuilt package is `Build/MigaInstaller.Wix/bin/Release/ru-RU/MIGA-1.3.0-x64.msi`, 105066496 bytes, SHA-256 `CADA3D908FA9D0AE99E35E27060C8605724BFC5FDCC2858A8FFA8241A50B0328`. All 24 extracted files match fresh staging `Build/MigaInstaller.Wix/staging/bdf4f2967ee242b795d1535f453589e2`; all four installer scripts additionally match current repository sources. Executable versions are 1.3.0.0. The unchanged Agent, native client, diagnostics, server and dependency payload were copied only after checking every prior staging hash and previous MSI against the preceding extraction report. No component requiring compilation changed in this correction.

Verification: `Artifacts/previous-builds/Archive/msi-1.3.0-legacy-interface-verify/verification.json`. WiX build with Windows Installer ICE access: `build.log` in that directory; all enabled checks passed without suppression. Existing WiX directory-name canonicalization warning remains. Extraction log: `extraction.log`. Previous MSI (SHA-256 `958FDAB576A1D3641D11FD1F86C34502079BB21F90146C59A57F5AA5FCB99308`) and report: `Artifacts/previous-builds/backups/before-legacy-interface-msi-20261115-144048`. No MSI installation, update, removal, EULA acceptance or server deployment was executed.

## Limits and operation

The real integration run establishes Debian 11 startup/control readiness, systemd upgrade/rollback, real file backup/restore, TUN/NAT setup and preservation of foreign rules. It does not establish end-to-end TCP/UDP/DNS forwarding, packet loss, MTU behavior, real client invitations, online repository installation, dnf/yum behavior, the production target distribution, Agent GUI/SFTP/SSH deployment, other distributions, ACL/SELinux behavior, real vmxnet3 NIC ring changes or another VPN under concurrent traffic. No ready external v2 data-client harness was available; no packet-forwarding claim is made. Stable process/admin observations establish startup/control availability only. The older Windows fixtures alone establish none of these real Linux properties.

SIGKILL, host power loss, filesystem exhaustion, permanently hung kernel calls and unavailable restoration commands can prevent automatic rollback. An SSH disconnect/timeout is not proof that remote rollback completed; inspect the reported backup and service status after reconnecting. Installed dependency packages remain after rollback.

Automatic update supports the standard installed unit, `/etc/miga/config.json`, `/var/lib/miga`, and enabled/disabled states. Custom commands, process arguments, state directories, masked/static/indirect units, DropIns and units requiring daemon-reload are rejected before stop. This intentionally leaves custom installations for manual review.

`server_update_restore_failed path=... reason=...` identifies a failed restoration without printing file contents. A persistent firewall conflict preserves the concurrently changed file and reports `rollback=incomplete`; compare its MIGA-owned lines against the root-only backup. Do not replace another VPN's firewall wholesale. The server stays stopped when any file restoration fails.
