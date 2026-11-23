function New-MigaBuildWorkspace([string]$RepositoryRoot) {
    $build = Join-Path $RepositoryRoot 'Build'
    $parent = Join-Path $build '.work'
    New-Item -ItemType Directory -Path $build -Force | Out-Null
    if ((Get-Item -LiteralPath $build -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Build directory is a link: $build" }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    foreach ($directory in @($build, $parent)) {
        if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Build directory is a link: $directory"
        }
    }
    $path = Join-Path $parent ([guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($path)
    return $path
}

function Remove-MigaBuildWorkspace([string]$Path) {
    if (!(Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    $parent = Split-Path $resolved -Parent
    if ($resolved -ne $Path -or (Split-Path $parent -Leaf) -ne '.work' -or
        (Split-Path (Split-Path $parent -Parent) -Leaf) -ne 'Build' -or
        (Split-Path $resolved -Leaf) -notmatch '^[a-f0-9]{32}$') {
        throw "Unexpected build workspace: $Path"
    }
    foreach ($directory in @((Split-Path $parent -Parent), $parent, $resolved)) {
        if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Build directory is a link: $directory"
        }
    }
    $link = Get-ChildItem -LiteralPath $resolved -Recurse -Force |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } | Select-Object -First 1
    if ($link) { throw "Build workspace contains a link: $Path" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    try { [IO.Directory]::Delete($parent, $false) } catch [IO.IOException] {}
}
