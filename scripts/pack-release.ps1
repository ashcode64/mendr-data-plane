# Create mendr-edge release zip for manual client distribution.
# Usage: .\scripts\pack-release.ps1 [version]

param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ReleaseDir = Join-Path $Root "release"
$Out = Join-Path $ReleaseDir "mendr-edge-$Version.zip"

$files = @(
    (Join-Path $ReleaseDir "docker-compose.yml"),
    (Join-Path $ReleaseDir ".env.example"),
    (Join-Path $ReleaseDir "README.md")
)

foreach ($f in $files) {
    if (-not (Test-Path $f)) {
        throw "Missing required file: $f"
    }
}

if (Test-Path $Out) {
    Remove-Item $Out -Force
}

Compress-Archive -Path $files -DestinationPath $Out -Force
Write-Host "Created $Out"
