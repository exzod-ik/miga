[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$ProductVersion = '1.2.2',
    [string]$ServerBinary,
    [string]$VisualStudioPath,
    [string]$CrtDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$agentPublishDir = Join-Path $repoRoot 'Build\MIGA Agent\publish'
if (!(Test-Path -LiteralPath (Join-Path $agentPublishDir 'MIGA Agent.exe') -PathType Leaf)) {
    throw "Publish MIGA Agent to '$agentPublishDir' before building the installer."
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
$msbuild = Join-Path $VisualStudioPath 'MSBuild\Current\Bin\MSBuild.exe'
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
# Fresh staging prevents obsolete files from entering the package. No local configs are copied.
$payload = Join-Path $repoRoot ('Build\MigaInstaller.Wix\staging\' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $payload -Force | Out-Null
& $msbuild (Join-Path $repoRoot 'miga_client\miga_client.vcxproj') /t:Build /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$repoRoot\" /m
if ($LASTEXITCODE -ne 0) { throw 'Client build failed.' }
# Package the existing GUI publication without building or publishing its project.
Get-ChildItem -LiteralPath $agentPublishDir -File -Recurse |
    Where-Object { $_.Name -ne 'config.json' -and $_.Extension -notin @('.pdb', '.log') } |
    ForEach-Object {
        $relativePath = $_.FullName.Substring($agentPublishDir.Length + 1)
        $destination = Join-Path $payload $relativePath
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $destination
    }
$clientOutput = Join-Path $repoRoot 'Build\miga_client\bin\x64\Release'
Copy-Item -LiteralPath (Join-Path $clientOutput 'miga_client.exe') -Destination $payload
foreach ($driverFile in @('WinDivert.dll', 'WinDivert64.sys')) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "miga_client\windivert\x64\$driverFile") -Destination $payload
}
Get-ChildItem -LiteralPath $CrtDirectory -File -Filter '*.dll' | Copy-Item -Destination $payload
Copy-Item -LiteralPath $ServerBinary -Destination (Join-Path $payload 'miga_server')
Copy-Item -LiteralPath (Join-Path $repoRoot 'miga_server\install.sh') -Destination $payload
Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE.txt') -Destination $payload
# Persist the completed staging path for subsequent builds from Visual Studio.
$payloadProps = Join-Path $repoRoot 'Build\MigaInstaller.Wix\Payload.props'
$propsXml = New-Object System.Xml.XmlDocument
[void]$propsXml.AppendChild($propsXml.CreateElement('Project'))
$group = $propsXml.CreateElement('PropertyGroup')
[void]$propsXml.DocumentElement.AppendChild($group)
$pathProperty = $propsXml.CreateElement('PayloadDir')
$pathProperty.SetAttribute('Condition', "'`$(PayloadDir)' == ''")
$pathProperty.InnerText = $payload
[void]$group.AppendChild($pathProperty)
$propsXml.Save($payloadProps)
& dotnet build (Join-Path $PSScriptRoot 'MigaInstaller.Wix.wixproj') --configuration Release "/p:ProductVersion=$ProductVersion" "/p:PayloadDir=$payload"
if ($LASTEXITCODE -ne 0) { throw 'WiX build failed.' }