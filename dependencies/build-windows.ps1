param([string]$MSBuild = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root 'Build\protocol-v2'
$lib = Join-Path $out 'lib'
. (Join-Path $root 'build-support.ps1')
$work = New-MigaBuildWorkspace $root
try {
    $generated = Join-Path $work 'generated'
    New-Item -ItemType Directory -Force -Path $lib,$generated | Out-Null
    $devcmd = Join-Path ($MSBuild.Substring(0, $MSBuild.IndexOf('\MSBuild\', [StringComparison]::OrdinalIgnoreCase))) 'Common7\Tools\VsDevCmd.bat'
    $environmentScript = Join-Path $generated 'environment.cmd'
    [IO.File]::WriteAllText($environmentScript, "@echo off`r`ncall `"$devcmd`" -arch=x64 -host_arch=x64 >nul`r`nif errorlevel 1 exit /b 1`r`nset`r`n", [Text.Encoding]::ASCII)
    $environment = & $env:ComSpec /d /c $environmentScript
    if ($LASTEXITCODE -ne 0) { throw 'Visual Studio environment initialization failed' }
    foreach ($line in $environment) {
     $separator = $line.IndexOf('=')
     if ($separator -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0, $separator), $line.Substring($separator + 1), 'Process') }
    }
    $expected = @{
     'libsodium-1.0.22.tar.gz' = 'ADBDD8F16149E81AC6078A03ACA6FC03B592B89EF7B5ED83841C086191BE3349'
     'noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6.tar.gz' = 'D95CDD666124E9D1175C0C24024D7CABCD71149A9DBFE0DE3ACA43C562F7AC12'
    }
    foreach ($entry in $expected.GetEnumerator()) {
     if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $entry.Key) -Algorithm SHA256).Hash -ne $entry.Value) { throw ('Dependency archive checksum mismatch: ' + $entry.Key) }
    }
    $source = Join-Path $work 'source'
    New-Item -ItemType Directory -Path $source | Out-Null
    foreach ($entry in $expected.GetEnumerator()) {
     & tar.exe -xzf (Join-Path $PSScriptRoot $entry.Key) -C $source
     if ($LASTEXITCODE -ne 0) { throw ('Dependency extraction failed: ' + $entry.Key) }
    }
    $sodium = Join-Path $source 'libsodium-1.0.22'
    $noise = Join-Path $source 'noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6'
    foreach ($headers in @('libsodium-1.0.22\src\libsodium\include', 'noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6\include')) {
     $verifiedHeaders = Join-Path $source $headers
     foreach ($header in Get-ChildItem -LiteralPath $verifiedHeaders -Filter '*.h' -File -Recurse) {
      $relative = $header.FullName.Substring($source.Length + 1)
      $publicHeader = Join-Path $PSScriptRoot $relative
      if (!(Test-Path -LiteralPath $publicHeader) -or (Get-FileHash -LiteralPath $header.FullName).Hash -ne (Get-FileHash -LiteralPath $publicHeader).Hash) {
       throw ('Public dependency header differs from pinned archive: ' + $relative)
      }
     }
    }
    function Write-Source([string]$path, [string]$content) {
     $normalized = $content -replace '\r?\n', "`r`n"
     if (!(Test-Path -LiteralPath $path) -or [IO.File]::ReadAllText($path) -cne $normalized) { [IO.File]::WriteAllText($path, $normalized, [Text.UTF8Encoding]::new($false)) }
    }
    $runtime = Join-Path $generated 'sodium-runtime.props'
    Write-Source $runtime '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemDefinitionGroup><ClCompile><RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary><DebugInformationFormat>OldStyle</DebugInformationFormat></ClCompile></ItemDefinitionGroup></Project>'
    & $MSBuild (Join-Path $sodium 'builds\msvc\vs2026\libsodium\libsodium.vcxproj') /t:Build /p:Configuration=ReleaseLIB /p:Platform=x64 ('/p:OutDir=' + $lib + '\') ('/p:IntDir=' + $work + '\obj\sodium\') ('/p:ForceImportBeforeCppTargets=' + $runtime) /p:PreferredToolArchitecture=x64 /m /v:minimal
    if ($LASTEXITCODE -ne 0) { throw 'libsodium build failed' }
    $dh = [IO.File]::ReadAllText((Join-Path $noise 'src\protocol\dhstate.c'))
    foreach ($algorithm in @('CURVE448','NEWHOPE')) {
     $pattern = '(?ms)^    case NOISE_DH_' + $algorithm + ':\r?\n        \*state = noise_\w+_new\(\);\r?\n        break;\r?\n'
     if ([regex]::Matches($dh, $pattern).Count -ne 1) { throw ('Unexpected pinned Noise source: ' + $algorithm) }
     $dh = [regex]::Replace($dh, $pattern, '')
    }
    Write-Source (Join-Path $generated 'dhstate.c') $dh
    $files = @(Get-ChildItem (Join-Path $noise 'src\protocol') -Filter '*.c' | Where-Object Name -NotIn @('dhstate.c','rand_os.c') | ForEach-Object FullName)
    $files += Join-Path $generated 'dhstate.c'
    $files += @(Get-ChildItem (Join-Path $noise 'src\backend\sodium') -Filter '*.c' | ForEach-Object FullName)
    $files += @('src\backend\ref\cipher-aesgcm.c','src\backend\ref\hash-blake2s.c','src\crypto\blake2\blake2s.c','src\crypto\aes\rijndael-alg-fst.c','src\crypto\ghash\ghash.c') | ForEach-Object { Join-Path $noise $_ }
    $items = [Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $files.Count; $i++) {
     $escaped = [Security.SecurityElement]::Escape($files[$i])
     $items.Add('<ClCompile Include="' + $escaped + '"><ObjectFileName>$(IntDir)' + $i + '.obj</ObjectFileName></ClCompile>')
    }
    $project = @"
    <Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <ItemGroup Label="ProjectConfigurations"><ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration></ItemGroup>
    <PropertyGroup Label="Globals"><ProjectGuid>{A059DC49-5180-4432-9073-D28F6C67A10F}</ProjectGuid><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
    <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
    <PropertyGroup Label="Configuration"><ConfigurationType>StaticLibrary</ConfigurationType><PlatformToolset>v145</PlatformToolset></PropertyGroup>
    <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.props" />
    <PropertyGroup><OutDir>$lib\</OutDir><IntDir>$work\obj\noise\</IntDir><TargetName>noiseprotocol</TargetName></PropertyGroup>
    <ItemDefinitionGroup><ClCompile><AdditionalIncludeDirectories>$noise\include;$noise\src;$noise\src\protocol;$sodium\src\libsodium\include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories><PreprocessorDefinitions>USE_LIBSODIUM=1;SODIUM_STATIC;WIN32;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions><RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary><Optimization>MaxSpeed</Optimization><WarningLevel>Level3</WarningLevel><DebugInformationFormat>OldStyle</DebugInformationFormat><CompileAs>CompileAsC</CompileAs><LanguageStandard_C>stdc11</LanguageStandard_C></ClCompile></ItemDefinitionGroup>
    <ItemGroup>$($items -join "`r`n")</ItemGroup>
    <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.targets" />
    </Project>
"@
    $projectPath = Join-Path $generated 'noiseprotocol.vcxproj'
    Write-Source $projectPath $project
    & $MSBuild $projectPath /t:Build /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /m /v:minimal
    if ($LASTEXITCODE -ne 0) { throw 'Noise-C build failed' }
    foreach ($name in @('libsodium.lib','noiseprotocol.lib')) { if (!(Test-Path -LiteralPath (Join-Path $lib $name))) { throw ('Missing library: ' + $name) } }
    Write-Output ('Protocol v2 static libraries: ' + $lib)
} finally {
    Remove-MigaBuildWorkspace $work
}
