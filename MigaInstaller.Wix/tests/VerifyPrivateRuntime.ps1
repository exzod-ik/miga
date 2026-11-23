[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RuntimeDirectory,
    [string]$RuntimeVersion = '10.0.14',
    [string]$ReportDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (!$ReportDirectory) { $ReportDirectory = Join-Path $repo ('Build\private-runtime-check-' + [guid]::NewGuid().ToString('N')) }
New-Item -ItemType Directory -Path $ReportDirectory | Out-Null
$project = Join-Path $ReportDirectory 'RuntimeIsolationProbe.csproj'
$source = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType><UseWPF>true</UseWPF><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>'
[IO.File]::WriteAllText($project, $source + "`r`n")
$program = 'Console.WriteLine(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory()); Console.WriteLine(new System.Windows.DependencyObject().GetType().FullName);'
[IO.File]::WriteAllText((Join-Path $ReportDirectory 'Program.cs'), $program + "`r`n")
$output = Join-Path $ReportDirectory app
& dotnet publish $project -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:AppHostDotNetSearch=AppRelative /p:AppHostRelativeDotNet=Runtime "/p:RuntimeFrameworkVersion=$RuntimeVersion" --output $output
if ($LASTEXITCODE -ne 0) { throw 'Runtime isolation probe publication failed.' }
Copy-Item -LiteralPath $RuntimeDirectory -Destination (Join-Path $output Runtime) -Recurse
$saved = @{}
$variables = @('DOTNET_ROOT', 'DOTNET_ROOT_X64', 'DOTNET_HOST_TRACE', 'DOTNET_HOST_TRACEFILE', 'DOTNET_DISABLE_GUI_ERRORS')
foreach ($name in $variables) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:DOTNET_ROOT = Join-Path $ReportDirectory nonexistent
    $env:DOTNET_ROOT_X64 = $env:DOTNET_ROOT
    $env:DOTNET_HOST_TRACE = '1'
    $env:DOTNET_HOST_TRACEFILE = Join-Path $ReportDirectory positive-hosttrace.txt
    $env:DOTNET_DISABLE_GUI_ERRORS = '1'
    $positive = & (Join-Path $output RuntimeIsolationProbe.exe)
    if ($LASTEXITCODE -ne 0 -or $positive[0].TrimEnd('\') -ne (Join-Path $output "Runtime\shared\Microsoft.NETCore.App\$RuntimeVersion")) { throw 'Probe did not use the packaged runtime.' }
    $trace = Get-Content -LiteralPath $env:DOTNET_HOST_TRACEFILE -Raw
    if (!$trace.Contains((Join-Path $output "Runtime\shared\Microsoft.WindowsDesktop.App\$RuntimeVersion\WindowsBase.dll")) -or !$trace.Contains((Join-Path $output "Runtime\host\fxr\$RuntimeVersion\hostfxr.dll"))) { throw 'Private hostfxr/Desktop runtime was not resolved.' }
    $negative = Join-Path $ReportDirectory no-runtime
    New-Item -ItemType Directory -Path $negative | Out-Null
    Copy-Item -LiteralPath (Join-Path $output RuntimeIsolationProbe.exe) -Destination $negative
    $env:DOTNET_HOST_TRACEFILE = Join-Path $ReportDirectory negative-hosttrace.txt
    & (Join-Path $negative RuntimeIsolationProbe.exe) 2> (Join-Path $ReportDirectory negative-stderr.txt)
    $negativeExit = $LASTEXITCODE
    $negativeTrace = Get-Content -LiteralPath $env:DOTNET_HOST_TRACEFILE -Raw
    if ($negativeExit -eq 0 -or !$negativeTrace.Contains('search options: [ app_relative ]')) { throw 'Missing private runtime did not fail with app-relative-only search.' }
    [pscustomobject]@{ private_runtime_success=$true; desktop_framework_resolved=$true; global_dotnet_roots_ignored=$true; missing_runtime_exit=$negativeExit; production_applications_started=$false } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ReportDirectory verification.json) -Encoding utf8
} finally {
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
Write-Output "Private runtime isolation verified: $ReportDirectory"
$global:LASTEXITCODE = 0
