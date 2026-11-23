import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--ndk", required=True)
parser.add_argument("--bash", default="C:/Program Files/Git/bin/bash.exe")
parser.add_argument("--abi", action="append")
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
work_root = root / "Build" / ".work"
if any(path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
       for path in (work_root.parent, work_root)):
    raise RuntimeError("Build workspace is a link")
work_root.mkdir(parents=True, exist_ok=True)
ndk = Path(args.ndk).resolve()
bin = ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin"
dependency_manifest = root / "dependencies/manifest.json"
manifest = json.loads(dependency_manifest.read_text())
native_sources = [
    root / "miga_android/app/src/main/cpp/ProtocolV2Jni.cpp",
    root / "miga_client/src/ProtocolV2Session.cpp",
    root / "Shared/ProtocolV2.cpp",
    root / "Shared/ProtocolV2Packets.cpp",
    root / "Shared/InternetChecksum.cpp",
]
inputs = native_sources + [
    Path(__file__).resolve(),
    dependency_manifest,
    root / "miga_client/include/ProtocolV2Session.h",
    root / "Shared/ProtocolV2.h",
    root / "Shared/ProtocolV2Packets.h",
    root / "Shared/InternetChecksum.h",
] + sorted((root / "Shared/nlohmann").rglob("*.hpp"))
def digest_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


with tempfile.TemporaryDirectory(prefix="android-jni-", dir=work_root) as scratch:
    out = Path(scratch)
    for name in ("libsodium", "noise_c"):
        entry = manifest[name]
        archive = root / "dependencies" / entry["archive"]
        inputs.append(archive)
        if digest_file(archive) != entry["sha256"]:
            raise RuntimeError("Dependency checksum mismatch")
        with tarfile.open(archive) as source:
            destination = out / source.getmembers()[0].name.split("/")[0]
            if not destination.exists(): source.extractall(out, filter="data")
    sodium = out / "libsodium-1.0.22"
    noise = out / "noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6"
    abis = {"arm64-v8a": "aarch64-linux-android", "armeabi-v7a": "armv7a-linux-androideabi", "x86": "i686-linux-android", "x86_64": "x86_64-linux-android"}
    def input_digests():
        return {p.relative_to(root).as_posix(): digest_file(p) for p in inputs}

    digests = input_digests()
    for abi in args.abi or abis:
        target = abis[abi]
        build = out / abi
        build.mkdir(exist_ok=True)
        configure = build / "configure.sh"
        script = f"""set -eu
    export PATH="/{bin.drive[0].lower()}{bin.as_posix()[2:]}:$PATH"
    cd '{build.as_posix()}'
    CC='clang.exe --target={target}29' AR=llvm-ar.exe RANLIB=llvm-ranlib.exe STRIP=llvm-strip.exe bash ../libsodium-1.0.22/configure --host={target} --prefix='{build.as_posix()}/install' --disable-shared --enable-static --disable-dependency-tracking CFLAGS='-O2 -fPIC'
    """
        if not (build / "configured").exists():
            configure.write_text(script, newline="\n")
            with (build / "configure.log").open("w") as log:
                subprocess.run([args.bash, str(configure)], cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
            (build / "configured").touch()
        text = (build / "src/libsodium/Makefile").read_text().replace("\\\n", " ")
        variables = dict(re.findall(r"^([A-Za-z0-9_]+) = (.*)$", text, re.M))
        def expand(value):
            for _ in range(20):
                changed = re.sub(r"\$\(([A-Za-z0-9_]+)\)", lambda m: variables.get(m[1], ""), value)
                if changed == value: return value
                value = changed
            raise RuntimeError("Make variable cycle")
        defines = shlex.split(expand(variables["DEFS"]))
        common = [str(bin / "clang.exe"), "--target=" + target + "29", "-O2", "-fPIC", "-DSODIUM_STATIC", "-I" + str(build / "src/libsodium/include"), "-I" + str(build / "src/libsodium/include/sodium"), "-I" + str(sodium / "src/libsodium/include"), "-I" + str(sodium / "src/libsodium/include/sodium")]
        jobs = []
        objects = []
        def compile_command(command, source, obj):
            objects.append(obj)
            stamp = obj.with_suffix(".sha256")
            digest = hashlib.sha256((json.dumps(command) + str(ndk)).encode() + source.read_bytes()).hexdigest()
            if not obj.exists() or not stamp.exists() or stamp.read_text() != digest:
                jobs.append((command, stamp, digest))
        def compile_one(job):
            command, stamp, digest = job
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
            stamp.write_text(digest)
        for variable, value in variables.items():
            if not variable.endswith("_la_SOURCES"): continue
            group = variable[:-8]
            flags = [flag for flag in shlex.split(expand(variables.get(group + "_CPPFLAGS", ""))) if flag.startswith(("-m", "-D"))]
            for name in expand(value).split():
                if not name.endswith((".c", ".S", ".s")): continue
                source = sodium / "src/libsodium" / name
                obj = build / (group + "-" + name.replace("/", "_") + ".o")
                compile_command(common + defines + flags + ["-c", str(source), "-o", str(obj)], source, obj)
        def run(command): subprocess.run(command, check=True, stdout=subprocess.DEVNULL)

        dh = (noise / "src/protocol/dhstate.c").read_text()
        for algorithm in ("CURVE448", "NEWHOPE"):
            dh = re.sub(r"(?m)^    case NOISE_DH_" + algorithm + r":\n        \*state = noise_\w+_new\(\);\n        break;\n", "", dh)
        (build / "dhstate.c").write_text(dh)
        sources = [p for p in (noise / "src/protocol").glob("*.c") if p.name not in ("dhstate.c", "rand_os.c")]
        sources += [build / "dhstate.c"] + list((noise / "src/backend/sodium").glob("*.c"))
        sources += [noise / p for p in ("src/backend/ref/cipher-aesgcm.c", "src/backend/ref/hash-blake2s.c", "src/crypto/blake2/blake2s.c", "src/crypto/aes/rijndael-alg-fst.c", "src/crypto/ghash/ghash.c")]
        for i, source in enumerate(sources):
            obj = build / ("noise-" + str(i) + ".o")
            compile_command(common + ["-include", "sodium.h", "-DUSE_LIBSODIUM=1", "-I" + str(noise / "include"), "-I" + str(noise / "src"), "-I" + str(noise / "src/protocol"), "-c", str(source), "-o", str(obj)], source, obj)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool: list(pool.map(compile_one, jobs))
        print("crypto_compiled", abi, flush=True)
        output = root / "Build/android/jni" / abi / "libmiga-v2.so"
        output.parent.mkdir(parents=True, exist_ok=True)
        command = [str(bin / "clang++.exe"), "--target=" + target + "29", "-std=c++20", "-O2", "-fPIC", "-shared", "-static-libstdc++", "-Wl,--no-undefined", "-Wl,-z,max-page-size=16384", "-DSODIUM_STATIC", "-I" + str(noise / "include"), "-I" + str(sodium / "src/libsodium/include"), "-I" + str(sodium / "src/libsodium/include/sodium"), "-I" + str(build / "src/libsodium/include"), "-I" + str(build / "src/libsodium/include/sodium"), "-I" + str(root / "Shared")]
        command += [str(p) for p in native_sources]
        temporary_output = build / output.name
        command += [str(p) for p in objects] + ["-o", str(temporary_output)]
        run(command)
        if input_digests() != digests:
            raise RuntimeError("JNI inputs changed during the build; rerun build-v2.py")
        binary_digest = digest_file(temporary_output)
        stamp = output.with_suffix(".sha256")
        temporary_stamp = build / stamp.name
        temporary_stamp.write_text(
            f"{binary_digest} libmiga-v2.so\n" +
            "".join(f"{digest} {path}\n" for path, digest in sorted(digests.items())),
            encoding="utf-8",
        )
        temporary_output.replace(output)
        temporary_stamp.replace(stamp)
        print("native_library_built", abi, binary_digest, flush=True)
try:
    work_root.rmdir()
except OSError:
    pass
