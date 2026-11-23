import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


root = Path(__file__).resolve().parent.parent
dependencies = root / "dependencies"
output = root / "Build" / "protocol-v2" / "linux"
manifest = json.loads((dependencies / "manifest.json").read_text())
output.mkdir(parents=True, exist_ok=True)

make = os.environ.get("MIGA_MAKE") or shutil.which("make")
if not make:
    fallback = root / "miga_server" / "Build" / "build-tools" / "root" / "usr" / "bin" / "make"
    if fallback.exists():
        make = str(fallback)
if not make:
    raise RuntimeError("make is required; no system packages are installed by this script")
compiler = os.environ.get("CC", "cc")
archive_tool = os.environ.get("AR", "ar")
stamp = output / "build-manifest.json"
expected = {"dependencies": manifest, "compiler": compiler, "flags": "O3-fPIC-sodium-backend-v1"}
if stamp.exists() and json.loads(stamp.read_text()) == expected and all((output / "lib" / name).exists() for name in ("libnoiseprotocol.a", "libsodium.a", "libsqlite3.a")):
    print(output)
    raise SystemExit(0)
work_root = root / "Build" / ".work"
if work_root.is_symlink() or work_root.parent.is_symlink():
    raise RuntimeError("Build workspace is a link")
work_root.mkdir(exist_ok=True)
try:
    with tempfile.TemporaryDirectory(prefix="linux-dependencies-", dir=work_root) as run:
        scratch = Path(run)
        for component in manifest.values():
            archive = dependencies / component["archive"]
            if hashlib.sha256(archive.read_bytes()).hexdigest() != component["sha256"]:
                raise RuntimeError("Dependency archive checksum mismatch: " + archive.name)
            if "sha3_256" in component and hashlib.sha3_256(archive.read_bytes()).hexdigest() != component["sha3_256"]:
                raise RuntimeError("Dependency SHA3 checksum mismatch: " + archive.name)
            if archive.suffix == ".zip":
                with zipfile.ZipFile(archive) as source:
                    for member in source.namelist():
                        if not (scratch / "sources" / member).resolve().is_relative_to((scratch / "sources").resolve()):
                            raise RuntimeError("Archive path outside build sources")
                    if not (scratch / "sources" / source.namelist()[0].split("/")[0]).exists():
                        source.extractall(scratch / "sources")
                continue
            with tarfile.open(archive, "r:gz") as source:
                for member in source.getmembers():
                    destination = (scratch / "sources" / member.name).resolve()
                    if not destination.is_relative_to((scratch / "sources").resolve()):
                        raise RuntimeError("Archive path outside build sources")
                if not (scratch / "sources" / source.getmembers()[0].name.split("/")[0]).exists():
                    source.extractall(scratch / "sources")
        prefix = scratch / "install"
        sodium = scratch / "sources" / "libsodium-1.0.22"
        noise = scratch / "sources" / ("noise-c-" + manifest["noise_c"]["revision"])
        environment = os.environ.copy()
        environment["MAKE"] = make
        build = scratch / "build" / "sodium"
        build.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(sodium / "configure"), "--disable-shared", "--enable-static", "--prefix=" + str(prefix)], cwd=build, env=environment, check=True)
        subprocess.run([make, "-j2"], cwd=build, env=environment, check=True)
        subprocess.run([make, "install"], cwd=build, env=environment, check=True)
        generated = scratch / "build" / "noise"
        generated.mkdir(parents=True, exist_ok=True)
        dh = (noise / "src" / "protocol" / "dhstate.c").read_text()
        for algorithm in ("CURVE448", "NEWHOPE"):
            pattern = r"(?m)^    case NOISE_DH_" + algorithm + r":\n        \*state = noise_\w+_new\(\);\n        break;\n"
            dh, count = re.subn(pattern, "", dh)
            if count != 1:
                raise RuntimeError("Unexpected pinned Noise DH implementation: " + algorithm)
        (generated / "dhstate.c").write_text(dh)
        sources = sorted(path for path in (noise / "src" / "protocol").glob("*.c") if path.name not in ("dhstate.c", "rand_os.c"))
        sources += [generated / "dhstate.c"]
        sources += sorted((noise / "src" / "backend" / "sodium").glob("*.c"))
        sources += [noise / name for name in ("src/backend/ref/cipher-aesgcm.c", "src/backend/ref/hash-blake2s.c", "src/crypto/blake2/blake2s.c", "src/crypto/aes/rijndael-alg-fst.c", "src/crypto/ghash/ghash.c")]
        objects = []
        for index, source in enumerate(sources):
            obj = generated / (str(index) + ".o")
            command = [compiler, "-std=c11", "-O3", "-fPIC", "-DUSE_LIBSODIUM=1", "-DSODIUM_STATIC", "-I" + str(noise / "include"), "-I" + str(noise / "src"), "-I" + str(noise / "src" / "protocol"), "-I" + str(prefix / "include"), "-c", str(source), "-o", str(obj)]
            subprocess.run(command, check=True)
            objects.append(str(obj))
        subprocess.run([archive_tool, "rcs", str(prefix / "lib" / "libnoiseprotocol.a"), *objects], check=True)
        shutil.copytree(noise / "include" / "noise", prefix / "include" / "noise", dirs_exist_ok=True)
        sqlite = scratch / "sources" / "sqlite-amalgamation-3540100"
        sqlite_object = scratch / "build" / "sqlite3.o"
        subprocess.run([compiler, "-std=c11", "-O3", "-fPIC", "-DSQLITE_THREADSAFE=1", "-DSQLITE_OMIT_LOAD_EXTENSION=1", "-c", str(sqlite / "sqlite3.c"), "-o", str(sqlite_object)], check=True)
        subprocess.run([archive_tool, "rcs", str(prefix / "lib" / "libsqlite3.a"), str(sqlite_object)], check=True)
        shutil.copyfile(sqlite / "sqlite3.h", prefix / "include" / "sqlite3.h")
        shutil.copytree(prefix / "include", output / "include", dirs_exist_ok=True)
        (output / "lib").mkdir(exist_ok=True)
        for name in ("libnoiseprotocol.a", "libsodium.a", "libsqlite3.a"):
            (prefix / "lib" / name).replace(output / "lib" / name)
        stamp.write_text(json.dumps(expected, sort_keys=True))
finally:
    try:
        work_root.rmdir()
    except OSError:
        pass
print(output)
