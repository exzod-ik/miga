[CmdletBinding()]
param(
    [ValidateSet('Windows','Client','Admin','Diagnostics','Server','Android','Installer')]
    [string]$Target = 'Windows',
    [ValidateSet('Debug','Release')]
    [string]$Configuration = 'Release',
    [string]$ServerOpenSslRoot = $env:MIGA_SERVER_OPENSSL_ROOT
)
$ErrorActionPreference = 'Stop'
if ($Target -eq 'Installer') {
    & (Join-Path $PSScriptRoot 'MigaInstaller.Wix\build.ps1')
    return
}
if ($Target -eq 'Android') {
    if ($Configuration -eq 'Debug') {
        $android = Join-Path $PSScriptRoot 'miga_android'
        & (Join-Path $android 'gradlew.bat') -p $android :core:jar :app:assembleDebug :devicechecks:assembleDebug
        if ($LASTEXITCODE -ne 0) { throw 'Android build failed.' }
    } else {
        & (Join-Path $PSScriptRoot 'miga_android\release.ps1')
    }
    return
}
. (Join-Path $PSScriptRoot 'build-support.ps1')
$vswhere = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$vs) { throw 'Visual Studio C++ build tools not found.' }
$msbuild = Join-Path $vs 'MSBuild\Current\Bin\amd64\MSBuild.exe'
$work = New-MigaBuildWorkspace $PSScriptRoot
$previousWork = $env:MigaWorkRoot
try {
    $env:MigaWorkRoot = $work + '\'
    $managed = switch ($Target) {
        Windows { 'MIGA Agent\MIGA Agent.csproj'; 'MIGA Admin\MIGA Admin.csproj'; 'miga_diagnostics\miga_diagnostics.csproj' }
        Admin { 'MIGA Admin\MIGA Admin.csproj' }
        Diagnostics { 'miga_diagnostics\miga_diagnostics.csproj' }
    }
    foreach ($project in $managed) {
        & dotnet build (Join-Path $PSScriptRoot $project) --configuration $Configuration
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $project" }
    }
    if ($Target -in @('Windows','Client','Server')) {
        $name = if ($Target -eq 'Server') { 'miga_server' } else { 'miga_client' }
        $project = Join-Path $PSScriptRoot "$name\$name.vcxproj"
        $options = @("/p:Configuration=$Configuration", '/p:Platform=x64', '/p:PreferredToolArchitecture=x64')
        if ($Target -eq 'Server') {
            $run = Split-Path $work -Leaf
            $options += "/p:MigaRemoteWorkId=$run"
            if ($ServerOpenSslRoot) {
                $options += "/p:MigaOpenSslIncludeDirectory=$ServerOpenSslRoot/include"
                $options += "/p:MigaOpenSslLibraryDirectory=$ServerOpenSslRoot/lib"
            }
            try {
                & $msbuild $project /t:Build @options /m
                if ($LASTEXITCODE -ne 0) { throw "Build failed: $name" }
            } finally {
                & $msbuild $project /t:RemotePostBuildEvent @options /p:MigaCleanRemoteWork=true
                if ($LASTEXITCODE -ne 0) { Write-Warning "Remote intermediate cleanup failed for build $run." }
            }
        } else {
            & (Join-Path $PSScriptRoot 'dependencies\build-windows.ps1') -MSBuild $msbuild
            & $msbuild $project /t:Build @options /m
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $name" }
        }
    }
} finally {
    $env:MigaWorkRoot = $previousWork
    Remove-MigaBuildWorkspace $work
}
