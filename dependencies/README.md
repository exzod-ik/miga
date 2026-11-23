# Protocol v2 dependencies

Pinned sources and archive SHA-256 values are listed in manifest.json. Builds do not download newer versions. Third-party licenses remain in the extracted upstream source trees.

Windows x64 static libraries:

```powershell
.\dependencies\build-windows.ps1
```

The script verifies archive checksums, extracts fresh build sources in a unique Build/.work directory, checks public vendored headers against the verified archives, initializes the Visual Studio x64 toolchain and writes libsodium.lib and noiseprotocol.lib to Build/protocol-v2/lib. The temporary sources, projects and object files are removed after the build. Release libraries use the dynamic CRT (/MD); compiler debug information is embedded in object files (/Z7) to avoid a dependency on a running PDB compiler server.

Noise-C uses its upstream libsodium backend and BLAKE2s implementation. A build-only copy of dhstate.c excludes Curve448 and NewHope dispatch branches: MIGA uses NK with Curve25519, and those unrelated implementations require C extensions unavailable in MSVC. Unsupported DH IDs fail with NOISE_ERROR_UNKNOWN_ID. The pinned archive is not edited. Source pattern checks prevent silently applying the selection to an unexpected version.

Both Windows and Linux integration must use the same wire test vectors. Compilation does not validate live WinDivert, TUN, conntrack, firewall or deployment behavior.

Linux static dependencies are built with `python3 dependencies/build-linux.py` into `Build/protocol-v2/linux`. This includes SQLite 3.54.1 with extension loading disabled, as well as the same sodium/Noise selection used on Windows. The script verifies the pinned archives, checks SQLite's published SHA3-256 as well, and uses a local installation prefix. It requires a C compiler, archive tool and make; it does not install system packages or modify services.
