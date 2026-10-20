param([string]$Version = 'dev', [string]$TargetOS = 'windows', [string]$TargetArch = 'amd64', [switch]$SkipInstall)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.+_-]*$') { throw 'Version must be a simple release label' }
if ($TargetOS -notin @('windows', 'linux', 'darwin') -or $TargetArch -notin @('amd64', 'arm64')) { throw 'Unsupported release target' }
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
$previousOS, $previousArch, $previousCGO, $previousBuild = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED, $env:DRAFRP_BUILD_ID
try {
    $commit = (git rev-parse --short HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine Git revision' }
    $env:DRAFRP_BUILD_ID = "$Version+$commit"
    Push-Location web
    try {
        if (-not $SkipInstall) {
            npm ci --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Console build failed' }
    } finally { Pop-Location }
    $embeddedDir = [IO.Path]::GetFullPath((Join-Path $projectRoot 'internal/webui/dist'))
    $expectedEmbeddedDir = [IO.Path]::GetFullPath("$projectRoot/internal/webui/dist")
    if ($embeddedDir -ne $expectedEmbeddedDir) { throw 'Invalid embedded asset path' }
    if (Test-Path -LiteralPath $embeddedDir) { Remove-Item -LiteralPath $embeddedDir -Recurse -Force }
    New-Item -ItemType Directory -Force $embeddedDir | Out-Null
    Copy-Item -Path web/dist/* -Destination internal/webui/dist -Recurse -Force
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $TargetOS, $TargetArch, '0'
    $outputDir = Join-Path $projectRoot "bin/$Version/$TargetOS-$TargetArch"
    New-Item -ItemType Directory -Force $outputDir | Out-Null
    $suffix = if ($TargetOS -eq 'windows') { '.exe' } else { '' }
    foreach ($role in @('cloud', 'edge', 'client')) {
        $output = Join-Path $outputDir "drafrp-$role$suffix"
        go build -trimpath -tags release -ldflags "-s -w -X drafrp/internal/buildinfo.Version=$Version -X drafrp/internal/buildinfo.Commit=$commit" -o $output "./cmd/drafrp-$role"
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $role" }
    }
    $exampleOutput = Join-Path $outputDir 'examples'
    New-Item -ItemType Directory -Force $exampleOutput | Out-Null
    Copy-Item -Path examples/* -Destination $exampleOutput -Recurse -Force
    Copy-Item -LiteralPath README.md, IMPLEMENTATION.md, API-CONTRACT.md -Destination $outputDir -Force
    Get-ChildItem -Path (Join-Path $outputDir 'drafrp-*') -File | Sort-Object Name | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    } | Set-Content -LiteralPath (Join-Path $outputDir 'SHA256SUMS') -Encoding utf8NoBOM
    Write-Output $outputDir
} finally {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED, $env:DRAFRP_BUILD_ID = $previousOS, $previousArch, $previousCGO, $previousBuild
    Pop-Location
}
