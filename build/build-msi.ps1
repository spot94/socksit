# Builds the SocksIt MSI with WiX. Requires the WiX .NET tool:
#   dotnet tool install --global wix   (needs the .NET SDK)
# Usage (from repo root):
#   go build -o bin\socksit.exe .\cmd\socksit
#   pwsh build\build-msi.ps1
param(
  # MSI ProductVersion. Must increase for a major upgrade to replace the previous
  # install; CI passes the release version, local builds get a throwaway 0.0.0.
  [string]$Version = '0.0.0',
  # Directory holding socksit.exe + sing-box.exe. Defaults to the local build
  # layout; CI points it at dist/ so the SIGNED binaries go into the package.
  [string]$From
)
$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $PSScriptRoot 'stage'
$out   = Join-Path $PSScriptRoot 'SocksIt.msi'

New-Item -ItemType Directory -Force $stage | Out-Null
if ($From) {
  Copy-Item (Join-Path $From 'socksit.exe')  (Join-Path $stage 'socksit.exe')  -Force
  Copy-Item (Join-Path $From 'sing-box.exe') (Join-Path $stage 'sing-box.exe') -Force
} else {
  Copy-Item (Join-Path $root 'bin\socksit.exe')         (Join-Path $stage 'socksit.exe')  -Force
  Copy-Item (Join-Path $root 'assets\bin\sing-box.exe') (Join-Path $stage 'sing-box.exe') -Force
}

# WiX wants a 4-part version; a release is 3-part.
$msiVersion = if ($Version -match '^\d+(\.\d+){3}$') { $Version } else { "$Version.0" }
& wix build (Join-Path $PSScriptRoot 'installer.wxs') -d "StageDir=$stage" -d "Version=$msiVersion" -o $out
Write-Host "Built $out"
