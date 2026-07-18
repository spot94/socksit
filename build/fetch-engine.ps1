<#
.SYNOPSIS
  Downloads the pinned sing-box engine into assets/bin so it does not have to be
  committed to git. Run once after cloning (and whenever assets/bin/VERSION bumps).

.DESCRIPTION
  Reads the pinned version from assets/bin/VERSION (SINGBOX_VERSION=x.y.z),
  fetches the official windows-amd64 release from GitHub, verifies it, and
  extracts sing-box.exe + its LICENSE into assets/bin/.

  SocksIt's generated config uses only the socks outbound + TUN + fake-ip, so it
  does NOT need libcronet.dll (that ships only with special cronet/uTLS builds).
  If your engine build requires it, place libcronet.dll in assets/bin/ manually.

.EXAMPLE
  pwsh -File build/fetch-engine.ps1
#>
[CmdletBinding()]
param(
    [string]$Version # override the pinned version if set
)
$ErrorActionPreference = 'Stop'

$root    = Split-Path -Parent $PSScriptRoot
$binDir  = Join-Path $root 'assets/bin'
$verFile = Join-Path $binDir 'VERSION'

if (-not $Version) {
    if (-not (Test-Path $verFile)) { throw "VERSION file not found at $verFile" }
    $line = (Get-Content $verFile | Where-Object { $_ -match 'SINGBOX_VERSION=' } | Select-Object -First 1)
    if (-not $line) { throw "SINGBOX_VERSION not found in $verFile" }
    $Version = ($line -split '=', 2)[1].Trim()
}
if (-not $Version) { throw "could not determine sing-box version" }

$asset = "sing-box-$Version-windows-amd64"
$url   = "https://github.com/SagerNet/sing-box/releases/download/v$Version/$asset.zip"
Write-Host "Fetching sing-box $Version"
Write-Host "  $url"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "socksit-engine-$Version"
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zip = Join-Path $tmp "$asset.zip"

Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath $tmp -Force

$exe = Get-ChildItem -Path $tmp -Recurse -Filter 'sing-box.exe' | Select-Object -First 1
if (-not $exe) { throw "sing-box.exe not found in the downloaded archive" }
Copy-Item $exe.FullName (Join-Path $binDir 'sing-box.exe') -Force

$lic = Get-ChildItem -Path $tmp -Recurse -Include 'LICENSE','LICENSE.*' | Select-Object -First 1
if ($lic) { Copy-Item $lic.FullName (Join-Path $binDir 'sing-box.LICENSE') -Force }

Remove-Item -Recurse -Force $tmp
$size = [math]::Round((Get-Item (Join-Path $binDir 'sing-box.exe')).Length / 1MB, 1)
Write-Host "OK -> $binDir\sing-box.exe ($size MB)"
