<#
.SYNOPSIS
  Authenticode-sign SocksIt binaries (SHA-256 + RFC-3161 timestamp).

.NOTES
  Sign ONLY the binaries you build: socksit.exe / socksit-setup.exe (and an MSI if
  you make one). NEVER re-sign vendor files (sing-box.exe, libcronet.dll,
  wintun.dll) — they carry upstream signatures and re-signing can break them.
  EV is no longer required for SmartScreen (Microsoft removed the instant-reputation
  edge ~2024); use Azure Trusted Signing or an OV token/HSM cert. See plan U11/KTD9.

.EXAMPLES
  # Cert already in the local store (self-signed / token / imported) — by thumbprint:
  .\build\sign.ps1 -Thumbprint AB12CD... -Files bin\socksit.exe,socksit-setup.exe

  # Auto-pick the best code-signing cert in the store:
  .\build\sign.ps1 -Files socksit-setup.exe

  # PFX file (internal / self-signed):
  .\build\sign.ps1 -Pfx codesign.pfx -PfxPassword 'secret' -Files socksit-setup.exe

  # Azure Trusted Signing (managed, no token):
  .\build\sign.ps1 -TSDlib 'C:\acs\Azure.CodeSigning.Dlib.dll' -TSMetadata metadata.json -Files socksit-setup.exe
#>
param(
  [string[]]$Files = @("bin\socksit.exe"),
  [string]$Thumbprint,
  [string]$Pfx,
  [string]$PfxPassword,
  [string]$TSDlib,
  [string]$TSMetadata,
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"

function Find-SignTool {
  $c = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $bin = "C:\Program Files (x86)\Windows Kits\10\bin"
  if (Test-Path $bin) {
    foreach ($d in (Get-ChildItem $bin -Directory | Sort-Object Name -Descending)) {
      $p = Join-Path $d.FullName "x64\signtool.exe"
      if (Test-Path $p) { return $p }
    }
  }
  throw "signtool.exe not found. Install the Windows SDK (signing tools / App Certification Kit)."
}

$signtool = Find-SignTool
Write-Host "signtool: $signtool"

foreach ($f in $Files) {
  if (-not (Test-Path $f)) { throw "file not found: $f" }
  $a = @("sign", "/fd", "sha256", "/tr", $TimestampUrl, "/td", "sha256", "/v")
  if     ($Thumbprint) { $a += @("/sha1", $Thumbprint) }
  elseif ($Pfx)        { $a += @("/f", $Pfx); if ($PfxPassword) { $a += @("/p", $PfxPassword) } }
  elseif ($TSDlib)     { $a += @("/dlib", $TSDlib, "/dmdf", $TSMetadata) }
  else                 { $a += @("/a") }   # auto-select best cert in the store
  $a += $f
  Write-Host "Signing $f ..."
  & $signtool @a
}

Write-Host "`nVerifying (a self-signed cert not in a trusted root will fail here — expected):"
foreach ($f in $Files) { & $signtool verify /pa /v $f }
