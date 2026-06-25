# Build and push Mendr data plane gateway image to Docker Hub.
# Usage: .\scripts\build-and-push.ps1 [version]
# Prerequisites: docker login (as teammendr), repo teammendr/themendr on Docker Hub.

param(
    [string]$Version = "1.0.0",
    [switch]$PushLatest
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Image = "teammendr/themendr:$Version"
$NginxDir = Join-Path $Root "infra\nginx"

Write-Host "Building $Image from $NginxDir ..."
docker build -t $Image $NginxDir

if ($PushLatest) {
    docker tag $Image "teammendr/themendr:latest"
}

Write-Host "Pushing $Image ..."
docker push $Image

if ($PushLatest) {
    docker push "teammendr/themendr:latest"
}

Write-Host "Done. Image published: $Image"
Write-Host "Clients can use release/docker-compose.yml or release/mendr-edge-$Version.zip"
