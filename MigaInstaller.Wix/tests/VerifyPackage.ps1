[CmdletBinding()]
param(
    [string]$MsiPath,
    [string]$ReportDirectory,
    [Parameter(Mandatory)][string]$PayloadDir,
    [string]$BuildOutputRoot,
    [string]$RuntimeVersion = '10.0.14'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (!$MsiPath) { $MsiPath = Join-Path $repo 'Build\MigaInstaller.Wix\bin\Release\ru-RU\MIGA-1.3.0-x64.msi' }
if (!$ReportDirectory) { $ReportDirectory = Join-Path $repo 'Artifacts\msi-verification' }
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$wix = Join-Path $env:USERPROFILE '.nuget\packages\wixtoolset.sdk\7.0.0\tools\net472\x64\wix.exe'
$source = Join-Path $ReportDirectory 'package.wxs'
$extracted = Join-Path $ReportDirectory 'files'
& $wix msi decompile $MsiPath -o $source -x $extracted
if ($LASTEXITCODE -ne 0) { throw 'MSI extraction failed.' }
[xml]$xml = Get-Content -LiteralPath $source
$stage = (Resolve-Path -LiteralPath $PayloadDir).ProviderPath
if (!$BuildOutputRoot) { $BuildOutputRoot = Join-Path $repo 'Build' }
$features = @{}
$componentFeatures = @{}
foreach ($feature in $xml.SelectNodes('//*[local-name()="Feature"]')) {
    $features[$feature.Id] = [int]$feature.Level
    foreach ($reference in $feature.SelectNodes('./*[local-name()="ComponentRef"]')) {
        if ($componentFeatures.ContainsKey($reference.Id)) { throw 'Shared file component assigned to multiple features.' }
        $componentFeatures[$reference.Id] = [string]$feature.Id
    }
}
if ($features.Count -ne 3 -or $features.Client -ne 1 -or $features.Admin -ne 2 -or $features.Common -ne 1) { throw 'Unexpected default/optional features.' }
$files = @()
$targetPaths = @{}
function RelativeDirectory([string]$Id) {
    if ($Id -eq 'INSTALLFOLDER') { return '' }
    $node = $xml.SelectSingleNode('//*[local-name()="Directory" and @Id="' + $Id + '"]')
    if (!$node) { throw "Unexpected payload directory: $Id" }
    $parentId = [string]$node.ParentNode.Id
    $prefix = RelativeDirectory $parentId
    if ($prefix) { return Join-Path $prefix ([string]$node.Name) }
    return [string]$node.Name
}
foreach ($file in $xml.SelectNodes('//*[local-name()="File"]')) {
    $name = [string]$file.Name
    $component = $file.ParentNode
    $directory = $component.GetAttribute('Directory')
    if (!$directory) { $directory = [string]$component.ParentNode.Id }
    $relativeDirectory = RelativeDirectory $directory
    $relative = if ($relativeDirectory) { Join-Path $relativeDirectory $name } else { $name }
    if ($targetPaths.ContainsKey($relative)) { throw "Duplicate installed path: $relative" }
    $targetPaths[$relative] = [string]$component.Id
    $runtime = $relative.StartsWith('Runtime\', [StringComparison]::OrdinalIgnoreCase)
    if ($name -match '(?i)\.(log|pdb|p12|pem|key|dpapi)$' -or $name -eq 'MIGA Agent.exe' -or ($name -match '(?i)\.json$' -and (!$runtime -or $name -notin @('Microsoft.NETCore.App.deps.json', 'Microsoft.NETCore.App.runtimeconfig.json', 'Microsoft.WindowsDesktop.App.deps.json', 'Microsoft.WindowsDesktop.App.runtimeconfig.json')))) { throw "Forbidden payload: $relative" }
    $expectedFeature = switch -Regex ($name) {
        '^(MIGA Client\.exe|miga_client\.exe|miga_diagnostics\.exe|WinDivert\.dll|WinDivert64\.sys)$' { 'Client'; break }
        '^(MIGA Admin\.exe|miga_server|install\.sh|install-v2\.sh|update-v2\.py|ServerVersion\.inc|prepare-dependencies\.sh)$' { 'Admin'; break }
        default { 'Common' }
    }
    if ($componentFeatures[[string]$file.ParentNode.Id] -ne $expectedFeature) { throw "Wrong feature: $name" }
    $input = if ($runtime) { Join-Path $stage $relative } else { switch ($name) {
        'MIGA Client.exe' { Join-Path $stage "Client\$name" }
        'MIGA Admin.exe' { Join-Path $stage "Admin\$name" }
        'miga_diagnostics.exe' { Join-Path $stage "Diagnostics\$name" }
        default { Join-Path $stage $name }
    } }
    $output = Join-Path $extracted ("File\" + $file.Id)
    $hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
    if ($hash -ne (Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash) { throw "Payload hash mismatch: $name" }
    $version = $null
    if ($name -in @('MIGA Client.exe','MIGA Admin.exe','miga_client.exe','miga_diagnostics.exe')) {
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($output).FileVersion
        if ($version -ne '1.3.0.0') { throw "Unexpected version: $name $version" }
    }
    $files += [pscustomobject]@{ name=$name; path=$relative; feature=$expectedFeature; sha256=$hash; version=$version }
}
$runtimeFiles = @($files | Where-Object path -Like 'Runtime\*')
if ($runtimeFiles.Count -ne @(Get-ChildItem -LiteralPath (Join-Path $stage Runtime) -Recurse -File -Force).Count -or 'ZXing-LICENSE.txt' -notin $files.name -or 'ServerVersion.inc' -notin $files.name) { throw 'Missing runtime files or package license.' }
foreach ($required in @('Runtime\LICENSE.txt', 'Runtime\ThirdPartyNotices.txt', "Runtime\host\fxr\$runtimeVersion\hostfxr.dll", "Runtime\shared\Microsoft.NETCore.App\$runtimeVersion\coreclr.dll", "Runtime\shared\Microsoft.WindowsDesktop.App\$runtimeVersion\PresentationFramework.dll")) {
    if (!$targetPaths.ContainsKey($required)) { throw "Missing private runtime file: $required" }
}
$shortcuts = @($xml.SelectNodes('//*[local-name()="Shortcut"]'))
if ($shortcuts.Count -ne 4 -or @($shortcuts | Where-Object Name -eq 'MIGA Client').Count -ne 2 -or @($shortcuts | Where-Object Name -eq 'MIGA Admin').Count -ne 2) { throw 'Unexpected shortcuts.' }
$service = $xml.SelectSingleNode('//*[local-name()="ServiceInstall" and @Name="MigaClient"]')
if (!$service -or $componentFeatures[[string]$service.ParentNode.Id] -ne 'Client') { throw 'Service is outside Client.' }
$clientDeps = Get-Content -LiteralPath (Join-Path $BuildOutputRoot 'MIGA Agent\bin\Release\net10.0-windows\win-x64\MIGA Client.deps.json') -Raw
$adminDeps = Get-Content -LiteralPath (Join-Path $BuildOutputRoot 'MIGA Admin\bin\Release\net10.0-windows\win-x64\MIGA Admin.deps.json') -Raw
if ($clientDeps -match 'SSH.NET|Renci.Ssh') { throw 'SSH dependency in Client.' }
if ($adminDeps -match 'System.ServiceProcess.ServiceController|MIGA Client') { throw 'Client service dependency in Admin.' }
$sdkVersion = (& dotnet --version).Trim()
$dotnetRoot = Split-Path (Get-Command dotnet).Source -Parent
$hostModel = [Reflection.Assembly]::LoadFrom((Join-Path $dotnetRoot "sdk\$sdkVersion\Microsoft.NET.HostModel.dll"))
$searchOptions = [Activator]::CreateInstance($hostModel.GetType('Microsoft.NET.HostModel.AppHost.HostWriter+DotNetSearchOptions'))
$searchOptions.Location = [Enum]::Parse($hostModel.GetType('Microsoft.NET.HostModel.AppHost.HostWriter+DotNetSearchOptions+SearchLocation'), 'AppRelative')
$searchOptions.AppRelativeDotNet = 'Runtime'
$searchBytes = $hostModel.GetType('Microsoft.NET.HostModel.AppHost.HostWriter').GetMethod('GetSearchOptionBytes', [Reflection.BindingFlags]'NonPublic,Static').Invoke($null, @($searchOptions))
if (!('MigaBundleSearch' -as [type])) { Add-Type 'using System; public static class MigaBundleSearch { public static int Find(byte[] data, byte[] pattern) => data.AsSpan().IndexOf(pattern); }' }
foreach ($application in @(@('MIGA Client', 'MIGA Agent', 'Client'), @('MIGA Admin', 'MIGA Admin', 'Admin'), @('miga_diagnostics', 'miga_diagnostics', 'Diagnostics'))) {
    $name = $application[0]
    $configuration = Join-Path $BuildOutputRoot ( $application[1] + "\bin\Release\net10.0-windows\win-x64\$name.runtimeconfig.json")
    $bytes = [IO.File]::ReadAllBytes((Join-Path $stage ($application[2] + "\$name.exe")))
    $configBytes = [IO.File]::ReadAllBytes($configuration)
    $options = (Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json).runtimeOptions
    if ($options.PSObject.Properties.Name -contains 'includedFrameworks') { throw "Self-contained runtime still bundled: $name" }
    $frameworks = if ($options.PSObject.Properties.Name -contains 'frameworks') { @($options.frameworks) } else { @($options.framework) }
    foreach ($framework in $frameworks) {
        if ($framework.name -notin @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App') -or [version]$framework.version -gt [version]$runtimeVersion -or ([version]$framework.version).Major -ne 10) { throw "Private runtime cannot satisfy $name" }
    }
    $searchOffset = [MigaBundleSearch]::Find($bytes, $searchBytes)
    if ($searchOffset -lt 0 -or $searchOffset -gt 1048576 -or [MigaBundleSearch]::Find($bytes, $configBytes) -lt 0) { throw "Embedded FDD/private-only config mismatch: $name" }
}
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@([IO.Path]::GetFullPath($MsiPath),0))
function Query([string]$Sql, [int]$Count) {
    $view = $database.OpenView($Sql)
    [void]$view.Execute()
    while ($record = $view.Fetch()) {
        $values = for ($index=1; $index -le $Count; $index++) { $record.GetType().InvokeMember('StringData','GetProperty',$null,$record,$index) }
        ,$values
    }
}
$level = @(Query 'SELECT `Value` FROM `Property` WHERE `Property` = ''INSTALLLEVEL''' 1)
if ($level[0][0] -ne '1') { throw 'INSTALLLEVEL is not 1.' }
$commonFeature = @(Query 'SELECT `Attributes` FROM `Feature` WHERE `Feature` = ''Common''' 1)
if (($commonFeature[0][0] -band 16) -eq 0) { throw 'Common runtime feature can be removed separately.' }
$upgrades = @(Query 'SELECT `VersionMin`,`VersionMax`,`Attributes`,`ActionProperty` FROM `Upgrade`' 4)
$inclusive = @($upgrades | Where-Object { $_[1] -eq '1.3.0' -and ([int]$_[2] -band 512) -ne 0 -and $_[3] -eq 'WIX_UPGRADE_DETECTED' })
if ($inclusive.Count -ne 1) { throw 'Same-version replacement range missing.' }
$sequence = @(Query 'SELECT `Action`,`Sequence` FROM `InstallExecuteSequence`' 2)
$remove = [int](@($sequence | Where-Object { $_[0] -eq 'RemoveExistingProducts' })[0][1])
$initialize = [int](@($sequence | Where-Object { $_[0] -eq 'InstallInitialize' })[0][1])
if ($remove -ne $initialize + 1) { throw 'Unexpected legacy package removal sequence.' }
$result = [pscustomobject]@{
    msi=[IO.Path]::GetFullPath($MsiPath)
    sha256=(Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash
    size=(Get-Item -LiteralPath $MsiPath).Length
    features=$features
    verified_file_count=$files.Count
    files=$files
    shortcut_count=$shortcuts.Count
    client_has_no_ssh_dependency=$true
    admin_has_no_client_service_dependency=$true
    common_runtime_file_count=$runtimeFiles.Count
    unique_installed_paths=$true
    common_runtime_required_for_all_feature_selections=$true
    application_bundles_use_private_runtime_only=$true
    same_version_upgrade_inclusive=$true
    remove_existing_products_sequence=$remove
    client_service_component_guid=[string]$service.ParentNode.Guid
    installation_executed=$false
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ReportDirectory 'verification.json') -Encoding utf8
$result | Select-Object msi,sha256,size,verified_file_count,shortcut_count,same_version_upgrade_inclusive,remove_existing_products_sequence,client_service_component_guid
