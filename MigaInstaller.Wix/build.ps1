[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$ProductVersion = '1.3.0',
    [string]$ServerBinary,
    [string]$VisualStudioPath,
    [string]$CrtDirectory,
    [string]$DotNetRoot = (Split-Path (Get-Command dotnet -ErrorAction Stop).Source -Parent),
    [string]$DotNetRuntimeVersion = '10.0.14',
    [switch]$Verify
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
if (!$PSBoundParameters.ContainsKey('DotNetRoot') -and
    !(Test-Path -LiteralPath (Join-Path $DotNetRoot "host\fxr\$DotNetRuntimeVersion\hostfxr.dll"))) {
    $localRuntime = Join-Path $repoRoot "Artifacts\toolchains\dotnet-$DotNetRuntimeVersion"
    if (Test-Path -LiteralPath (Join-Path $localRuntime "host\fxr\$DotNetRuntimeVersion\hostfxr.dll")) {
        $DotNetRoot = $localRuntime
    }
}
if (!$ServerBinary) {
    $ServerBinary = Join-Path $repoRoot 'Build\miga_server\bin\x64\Release\miga_server'
}
if (!(Test-Path -LiteralPath $ServerBinary -PathType Leaf)) {
    throw 'Build the Linux server first, or specify -ServerBinary with its ELF executable.'
}
$serverStream = [IO.File]::OpenRead($ServerBinary)
try {
    $magic = New-Object byte[] 4
    if ($serverStream.Read($magic, 0, 4) -ne 4 -or [BitConverter]::ToString($magic) -ne '7F-45-4C-46') {
        throw 'ServerBinary must be a Linux ELF executable.'
    }
} finally { $serverStream.Dispose() }
if (!$VisualStudioPath) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $VisualStudioPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or !$VisualStudioPath) { throw 'Visual Studio C++ build tools not found.' }
}
$msbuild = Join-Path $VisualStudioPath 'MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!$CrtDirectory) {
    $redistRoot = Join-Path $VisualStudioPath 'VC\Redist\MSVC'
    $redistVersion = Get-ChildItem -LiteralPath $redistRoot -Directory |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    $crt = Get-ChildItem -LiteralPath (Join-Path $redistVersion.FullName 'x64') -Directory -Filter 'Microsoft.VC*.CRT' |
        Select-Object -First 1
    $CrtDirectory = $crt.FullName
}
foreach ($required in @('msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll')) {
    if (!(Test-Path -LiteralPath (Join-Path $CrtDirectory $required))) { throw "Missing CRT file: $required" }
}
. (Join-Path $repoRoot 'build-support.ps1')
$work = New-MigaBuildWorkspace $repoRoot
$previousWork = $env:MigaWorkRoot
$previousOutput = $env:MigaOutputRoot
try {
    $env:MigaWorkRoot = (Join-Path $work 'obj') + '\'
    $env:MigaOutputRoot = (Join-Path $work 'packages') + '\'
    # Fresh staging prevents obsolete files from entering the package. No local configs are copied.
    $payload = Join-Path $work 'payload'
    New-Item -ItemType Directory -Path $payload -Force | Out-Null
    & (Join-Path $PSScriptRoot 'prepare-runtime.ps1') -Destination (Join-Path $payload 'Runtime') -RuntimeVersion $DotNetRuntimeVersion -DotNetRoot $DotNetRoot
    & (Join-Path $repoRoot 'dependencies\build-windows.ps1') -MSBuild $msbuild
    if ($LASTEXITCODE -ne 0) { throw 'Protocol v2 static dependency build failed.' }
    $clientPublishDir = Join-Path $payload 'Client'
    $publishOptions = @('--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'false', '/p:PublishSingleFile=true', '/p:IncludeNativeLibrariesForSelfExtract=true', '/p:EnableCompressionInSingleFile=false', '/p:AppHostDotNetSearch=AppRelative', '/p:AppHostRelativeDotNet=Runtime', "/p:RuntimeFrameworkVersion=$DotNetRuntimeVersion")
    & dotnet publish (Join-Path $repoRoot 'MIGA Agent\MIGA Agent.csproj') @publishOptions /p:PublishReadyToRun=true "/p:SolutionDir=$repoRoot\" --output $clientPublishDir
    if ($LASTEXITCODE -ne 0) { throw 'Client publication failed.' }
    $adminPublishDir = Join-Path $payload 'Admin'
    & dotnet publish (Join-Path $repoRoot 'MIGA Admin\MIGA Admin.csproj') @publishOptions /p:PublishReadyToRun=true --output $adminPublishDir
    if ($LASTEXITCODE -ne 0) { throw 'Admin publication failed.' }
    $diagnosticsPublishDir = Join-Path $payload 'Diagnostics'
    & dotnet publish (Join-Path $repoRoot 'miga_diagnostics\miga_diagnostics.csproj') @publishOptions --output $diagnosticsPublishDir
    if ($LASTEXITCODE -ne 0) { throw 'Diagnostics publication failed.' }
    & $msbuild (Join-Path $repoRoot 'miga_client\miga_client.vcxproj') /t:Build /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 "/p:SolutionDir=$repoRoot\" /m
    if ($LASTEXITCODE -ne 0) { throw 'Client build failed.' }
    $clientOutput = Join-Path $env:MigaOutputRoot 'miga_client\bin\x64\Release'
    Copy-Item -LiteralPath (Join-Path $clientOutput 'miga_client.exe') -Destination $payload
    foreach ($driverFile in @('WinDivert.dll', 'WinDivert64.sys')) {
        Copy-Item -LiteralPath (Join-Path $repoRoot "miga_client\windivert\x64\$driverFile") -Destination $payload
    }
    Get-ChildItem -LiteralPath $CrtDirectory -File -Filter '*.dll' | Copy-Item -Destination $payload
    Copy-Item -LiteralPath $ServerBinary -Destination (Join-Path $payload 'miga_server')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'miga_server\install.sh') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $repoRoot 'miga_server\install-v2.sh') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $repoRoot 'miga_server\update-v2.py') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $repoRoot 'miga_server\ServerVersion.inc') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $repoRoot 'miga_server\prepare-dependencies.sh') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $repoRoot 'dependencies\libsodium-1.0.22\LICENSE') -Destination (Join-Path $payload 'libsodium-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'dependencies\noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6\COPYING') -Destination (Join-Path $payload 'Noise-C-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE.txt') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'OpenSSL-LICENSE.txt') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ZXing-LICENSE.txt') -Destination $payload
    & dotnet build (Join-Path $PSScriptRoot 'MigaInstaller.Wix.wixproj') --configuration Release "/p:ProductVersion=$ProductVersion" "/p:PayloadDir=$payload" "/p:ClientPublishDir=$clientPublishDir" "/p:AdminPublishDir=$adminPublishDir" "/p:DotNetRuntimeVersion=$DotNetRuntimeVersion"
    if ($LASTEXITCODE -ne 0) { throw 'WiX build failed.' }
    $relativePackage = "MigaInstaller.Wix\bin\Release\ru-RU\MIGA-$ProductVersion-x64.msi"
    $package = Join-Path $env:MigaOutputRoot $relativePackage
    if ($Verify) {
        & (Get-Process -Id $PID).Path -NoProfile -File (Join-Path $PSScriptRoot 'tests\VerifyPackage.ps1') -MsiPath $package -PayloadDir $payload -BuildOutputRoot $env:MigaOutputRoot -RuntimeVersion $DotNetRuntimeVersion -ReportDirectory (Join-Path $work 'verification')
        if ($LASTEXITCODE -ne 0) { throw 'MSI payload verification failed.' }
    }
    $finalPackage = Join-Path (Join-Path $repoRoot 'Build') $relativePackage
    New-Item -ItemType Directory -Path (Split-Path $finalPackage -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $package -Destination $finalPackage -Force
    Write-Output $finalPackage
} finally {
    $env:MigaWorkRoot = $previousWork
    $env:MigaOutputRoot = $previousOutput
    Remove-MigaBuildWorkspace $work
}
