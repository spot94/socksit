# Builds the SocksIt MSI with WiX. Requires the WiX .NET tool:
#   dotnet tool install --global wix   (needs the .NET SDK)
# Usage (from repo root):
#   go build -o bin\socksit.exe .\cmd\socksit
#   pwsh build\build-msi.ps1
$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $PSScriptRoot 'stage'
$out   = Join-Path $PSScriptRoot 'SocksIt.msi'

New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item (Join-Path $root 'bin\socksit.exe')         (Join-Path $stage 'socksit.exe')  -Force
Copy-Item (Join-Path $root 'assets\bin\sing-box.exe') (Join-Path $stage 'sing-box.exe') -Force

& wix build (Join-Path $PSScriptRoot 'installer.wxs') -d "StageDir=$stage" -o $out
Write-Host "Built $out"
