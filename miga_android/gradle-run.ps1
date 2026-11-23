. (Join-Path (Split-Path $PSScriptRoot -Parent) 'build-support.ps1')
$ErrorActionPreference = 'Stop'
$work = New-MigaBuildWorkspace (Split-Path $PSScriptRoot -Parent)
$previous = $env:MIGA_ANDROID_WORKSPACE
try {
    $env:MIGA_ANDROID_WORKSPACE = $work
    & (Join-Path $PSScriptRoot 'gradlew.bat') --project-cache-dir (Join-Path $work 'cache') --no-daemon "-Pkotlin.project.persistent.dir=$work\kotlin" @args
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        $artifacts = Join-Path (Split-Path $PSScriptRoot -Parent) 'Build\android'
        foreach ($module in @('app','core','devicechecks')) {
            $moduleWork = Join-Path $work $module
            foreach ($name in @('outputs\apk','outputs\bundle','outputs\mapping','libs')) {
                $folder = Join-Path $moduleWork $name
                if (!(Test-Path -LiteralPath $folder)) { continue }
                foreach ($file in Get-ChildItem -LiteralPath $folder -File -Recurse) {
                    if ($file.Extension -notin '.apk','.aab','.jar' -and $file.Name -ne 'mapping.txt') { continue }
                    $relative = $file.FullName.Substring($moduleWork.Length + 1)
                    $destination = Join-Path (Join-Path $artifacts $module) $relative
                    New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
                    Move-Item -LiteralPath $file.FullName -Destination $destination -Force
                }
            }
        }
        Write-Output $artifacts
    }
} finally {
    $env:MIGA_ANDROID_WORKSPACE = $previous
    Remove-MigaBuildWorkspace $work
}
exit $code
