param(
    [Parameter(Mandatory = $true)] [string] $NdkPath
)

$ErrorActionPreference = 'Stop'
$requiredNdk = '30.0.16248370'
$requiredCommit = '9a06bc6e7989da54e3d32ff701ef7a7ce4995d3a'
$ndkBuild = Join-Path $NdkPath 'ndk-build.cmd'
$properties = Join-Path $NdkPath 'source.properties'
if (-not (Test-Path -LiteralPath $ndkBuild) -or -not (Test-Path -LiteralPath $properties)) {
    throw "Android NDK r30 ($requiredNdk) is required at NdkPath; no SDK installation or license acceptance is done by this script."
}
$installed = (Get-Content -LiteralPath $properties | Select-String '^Pkg.Revision\s*=').ToString().Split('=')[1].Trim()
if ($installed -ne $requiredNdk) { throw "Expected Android NDK $requiredNdk, found $installed" }

$work = Join-Path $env:TEMP ("miga-hev-native-build-2.17.1-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$source = Join-Path $work 'jni'
& git clone --depth 1 --branch 2.17.1 --recurse-submodules https://github.com/heiher/hev-socks5-tunnel.git $source
if ($LASTEXITCODE -ne 0) { throw 'Could not obtain pinned hev-socks5-tunnel source' }
$actual = (& git -C $source rev-parse HEAD).Trim()
if ($actual -ne $requiredCommit) { throw "Unexpected hev-socks5-tunnel commit: $actual" }

# On Windows, Git may check out symlinks as text files containing their targets.
# Materialize only the symlinks recorded by the pinned source and its submodules.
foreach ($repo in @($source, (Join-Path $source 'src\core'),
                    (Join-Path $source 'third-part\hev-task-system'),
                    (Join-Path $source 'third-part\yaml'))) {
    $repoRoot = [IO.Path]::GetFullPath($repo).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    foreach ($entry in (& git -C $repo ls-files --stage)) {
        if ($entry -notmatch '^120000 [0-9a-f]+ 0\t(.+)$') { continue }
        $link = Join-Path $repo $Matches[1]
        if ((Get-Item -LiteralPath $link).LinkType -eq 'SymbolicLink') { continue }
        $target = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $link) (Get-Content -LiteralPath $link -Raw).Trim()))
        if (-not $target.StartsWith($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $target -PathType Leaf)) {
            throw "Invalid source symlink target: $link"
        }
        Copy-Item -LiteralPath $target -Destination $link -Force
    }
}

& $ndkBuild -C $work
if ($LASTEXITCODE -ne 0) { throw 'hev-socks5-tunnel native build failed' }

$destination = Join-Path $PSScriptRoot 'app\src\main\jniLibs'
foreach ($abi in @('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64')) {
    $library = Join-Path $work "libs\$abi\libhev-socks5-tunnel.so"
    if (-not (Test-Path -LiteralPath $library)) { throw "Native library missing for $abi" }
}
foreach ($abi in @('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64')) {
    $library = Join-Path $work "libs\$abi\libhev-socks5-tunnel.so"
    $abiDirectory = Join-Path $destination $abi
    New-Item -ItemType Directory -Force -Path $abiDirectory | Out-Null
    Copy-Item -LiteralPath $library -Destination (Join-Path $abiDirectory 'libhev-socks5-tunnel.so')
}
Write-Output 'Built and copied four ABI libraries; jniLibs is ignored by Git.'
