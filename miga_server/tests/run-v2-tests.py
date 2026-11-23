import os
from pathlib import Path
import subprocess
import sys


root = Path(__file__).resolve().parents[2]
subprocess.run([sys.executable, str(root / "dependencies" / "build-linux.py")], check=True)
prefix = root / "Build" / "protocol-v2" / "linux"
output = root / "Build" / "protocol-v2" / "linux-tests"
output.mkdir(parents=True, exist_ok=True)
compiler = os.environ.get("CXX", "g++")
common = [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
          "-I" + str(root / "miga_server" / "include"), "-I" + str(root / "Shared"), "-I" + str(prefix / "include")]
crypto = [str(prefix / "lib" / name) for name in ("libnoiseprotocol.a", "libsodium.a")]
sqlite = [str(prefix / "lib" / "libsqlite3.a")]
openssl = Path(os.environ.get("MIGA_OPENSSL_PREFIX", str(root / "miga_server" / "Build" / "openssl-lts" / "install")))
if (openssl / "lib" / "libssl.a").exists():
    common += ["-I" + str(openssl / "include")]
    tls = [str(openssl / "lib" / "libssl.a"), str(openssl / "lib" / "libcrypto.a")]
else:
    tls = ["-lssl", "-lcrypto"]


def test(name, sources, libraries):
    if len(sys.argv) > 1 and name not in sys.argv[1:]:
        return
    binary = output / name
    command = common + [str(root / source) for source in sources] + libraries + ["-ldl", "-lm", "-o", str(binary)]
    subprocess.run(command, cwd=root, check=True)
    subprocess.run([str(binary)], cwd=root, timeout=90, check=True)


test("store", ["miga_server/tests/ClientStoreTests.cpp", "miga_server/src/ClientStore.cpp"], sqlite)
shared = ["Shared/DiagnosticLoad.cpp", "Shared/ProtocolV2.cpp", "Shared/ProtocolV2Packets.cpp", "Shared/InternetChecksum.cpp"]
test("client-session", ["miga_client/tests/ProtocolV2SessionTests.cpp", "miga_client/src/ProtocolV2Session.cpp", *shared], crypto)
test("shared-review", ["Shared/tests/ProtocolV2ReviewTests.cpp", *shared], crypto)
test("runtime", ["miga_server/tests/V2ServerTests.cpp", "miga_server/src/ClientStore.cpp",
                 "miga_server/src/DiagnosticLoadSocket.cpp", "miga_server/src/DiagnosticControl.cpp", "miga_server/src/DiagnosticNetworkStats.cpp",
                 "miga_server/src/InterfaceIpCache.cpp", *shared,
                 "Shared/Logger.cpp", "Shared/LogFormat.cpp", "Shared/LogTime.cpp"], crypto + sqlite + tls)
test("diagnostic-control", ["miga_server/tests/DiagnosticControlTests.cpp", "miga_server/src/DiagnosticLoadSocket.cpp", "miga_server/src/DiagnosticControl.cpp",
                           "miga_server/src/DiagnosticNetworkStats.cpp", *shared], crypto + tls)
test("diagnostic-load", ["miga_server/tests/DiagnosticLoadTests.cpp", "miga_server/src/DiagnosticLoadSocket.cpp", "Shared/DiagnosticLoad.cpp"], [])
print("protocol_v2_linux_tests_passed")
