param(
    [switch] $CreateKey,
    [switch] $RevealPassword
)

$ErrorActionPreference = 'Stop'
$privateDirectory = Join-Path $env:USERPROFILE '.miga\android-release'
$keyFile = Join-Path $privateDirectory 'release.p12'
$passwordFile = Join-Path $privateDirectory 'password.dpapi'
$keyAlias = 'miga-android'

if ($CreateKey -and $RevealPassword) { throw 'Choose only one action.' }

if ($CreateKey) {
    if ((Test-Path -LiteralPath $keyFile) -or (Test-Path -LiteralPath $passwordFile)) {
        throw 'Release signing material already exists; refusing to replace it.'
    }

    New-Item -ItemType Directory -Path $privateDirectory -Force | Out-Null
    $password = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
    $previousStorePassword = [Environment]::GetEnvironmentVariable('MIGA_RELEASE_STORE_PASSWORD', 'Process')
    $previousKeyPassword = [Environment]::GetEnvironmentVariable('MIGA_RELEASE_KEY_PASSWORD', 'Process')
    try {
        $env:MIGA_RELEASE_STORE_PASSWORD = $password
        $env:MIGA_RELEASE_KEY_PASSWORD = $password
        & keytool -genkeypair -alias $keyAlias -keyalg RSA -keysize 4096 -validity 10000 `
            -dname 'CN=M.I.G.A. Android' -storetype PKCS12 -keystore $keyFile `
            -storepass:env MIGA_RELEASE_STORE_PASSWORD -keypass:env MIGA_RELEASE_KEY_PASSWORD -noprompt
        if ($LASTEXITCODE -ne 0) { throw 'keytool failed to create the release key.' }

        $plainBytes = [Text.Encoding]::UTF8.GetBytes($password)
        try {
            $protectedBytes = [Security.Cryptography.ProtectedData]::Protect(
                $plainBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
            [IO.File]::WriteAllBytes($passwordFile, $protectedBytes)
        } finally {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        Write-Output "Release key created at $keyFile"
    } finally {
        [Environment]::SetEnvironmentVariable('MIGA_RELEASE_STORE_PASSWORD', $previousStorePassword, 'Process')
        [Environment]::SetEnvironmentVariable('MIGA_RELEASE_KEY_PASSWORD', $previousKeyPassword, 'Process')
        $password = $null
    }
    return
}

if (-not (Test-Path -LiteralPath $keyFile) -or -not (Test-Path -LiteralPath $passwordFile)) {
    throw 'Release key is missing. Run .\release.ps1 -CreateKey first.'
}

$protectedBytes = [IO.File]::ReadAllBytes($passwordFile)
$plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
    $protectedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
$environmentNames = @('MIGA_RELEASE_STORE_FILE', 'MIGA_RELEASE_STORE_PASSWORD', 'MIGA_RELEASE_KEY_ALIAS', 'MIGA_RELEASE_KEY_PASSWORD')
$previousEnvironment = @{}
$environmentWasSet = $false
try {
    $password = [Text.Encoding]::UTF8.GetString($plainBytes)
    if ($RevealPassword) {
        Write-Output $password
        return
    }
    foreach ($name in $environmentNames) {
        $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    $environmentWasSet = $true
    $env:MIGA_RELEASE_STORE_FILE = $keyFile
    $env:MIGA_RELEASE_STORE_PASSWORD = $password
    $env:MIGA_RELEASE_KEY_ALIAS = $keyAlias
    $env:MIGA_RELEASE_KEY_PASSWORD = $password
    & (Join-Path $PSScriptRoot 'gradlew.bat') -g (Join-Path $env:USERPROFILE '.gradle') --offline `
        :core:test :app:testDebugUnitTest :app:lintDebug :app:assembleRelease --console=plain
    if ($LASTEXITCODE -ne 0) { throw "Release build failed with exit code $LASTEXITCODE" }
} finally {
    [Array]::Clear($plainBytes, 0, $plainBytes.Length)
    $password = $null
    if ($environmentWasSet) {
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
        }
    }
}
