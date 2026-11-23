[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$RuntimeVersion,
    [string]$DotNetRoot = (Split-Path (Get-Command dotnet -ErrorAction Stop).Source -Parent)
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($RuntimeVersion -notmatch '^10\.0\.\d+$') { throw 'An explicit .NET 10 patch version is required.' }
if (Test-Path -LiteralPath $Destination) { throw 'Runtime destination must be a new directory.' }
$sources = @{}
foreach ($framework in @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App')) {
    $source = Join-Path $DotNetRoot "shared\$framework\$RuntimeVersion"
    $metadata = @(Get-Content -LiteralPath (Join-Path $source '.version'))
    if ($metadata.Count -lt 2 -or $metadata[1].Trim() -ne $RuntimeVersion) { throw "Unexpected framework version: $framework" }
    if (!(Test-Path -LiteralPath (Join-Path $source "$framework.deps.json"))) { throw "Missing framework dependency manifest: $framework" }
    $sources[$framework] = $source
}
$hostfxr = Join-Path $DotNetRoot "host\fxr\$RuntimeVersion\hostfxr.dll"
$stream = [IO.File]::OpenRead($hostfxr)
try {
    $reader = [IO.BinaryReader]::new($stream)
    $stream.Position = 0x3c
    $offset = $reader.ReadInt32()
    $stream.Position = $offset
    if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Private hostfxr must be Windows x64.' }
} finally { $stream.Dispose() }
New-Item -ItemType Directory -Path $Destination | Out-Null
foreach ($framework in $sources.Keys) {
    $target = Join-Path $Destination "shared\$framework\$RuntimeVersion"
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Get-ChildItem -LiteralPath $sources[$framework] -Force | Copy-Item -Destination $target -Recurse
}
$hostDirectory = Join-Path $Destination "host\fxr\$RuntimeVersion"
New-Item -ItemType Directory -Path $hostDirectory -Force | Out-Null
Copy-Item -LiteralPath $hostfxr -Destination $hostDirectory
foreach ($name in @('LICENSE.txt', 'ThirdPartyNotices.txt')) {
    Copy-Item -LiteralPath (Join-Path $DotNetRoot $name) -Destination $Destination
}
