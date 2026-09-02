<#
.SYNOPSIS
  Creates the self-signed code-signing certificate releases are signed with.

.DESCRIPTION
  A self-signed certificate buys exactly two things, and it is worth being clear
  about which:

  - Inside a perimeter where the public half is distributed (GPO -> Trusted Root
    + Trusted Publishers) the signature is fully valid: Windows shows a real
    publisher instead of nothing, and an antivirus policy can trust by publisher
    rather than by file path, which survives reinstalls and moved folders.
  - Outside it, nothing. SmartScreen accrues reputation per publicly trusted
    certificate, and this is not one — public downloads keep warning.

  It also makes the release pipeline real: when a trusted certificate arrives,
  only the certificate changes, not the process.

  The key is exportable on purpose: a build machine dies eventually, and
  re-issuing means every client's trust store has to be updated again.

.EXAMPLE
  pwsh build/make-selfsigned-cert.ps1 -Subject "CN=SocksIt, O=SciEntetiq"
#>
param(
  [string]$Subject = 'CN=SocksIt Code Signing, O=SocksIt',
  [int]$Years = 5,
  [string]$OutDir = 'build/keys',
  # Import into the machine's Trusted Root and Trusted Publishers so signatures
  # verify on THIS machine (release-local.ps1 verifies what it signs). Needs an
  # elevated shell.
  [switch]$TrustLocally,
  # Also write a password-protected .pfx: without a backup, a lost build machine
  # means a new certificate and a new trust rollout everywhere.
  [System.Security.SecureString]$BackupPassword
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force $OutDir | Out-Null

$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject $Subject `
  -CertStoreLocation Cert:\CurrentUser\My `
  -KeyUsage DigitalSignature `
  -KeyExportPolicy Exportable `
  -KeyLength 3072 `
  -HashAlgorithm SHA256 `
  -NotAfter (Get-Date).AddYears($Years)

$cer = Join-Path $OutDir 'socksit-codesign.cer'
Export-Certificate -Cert $cert -FilePath $cer | Out-Null

Write-Host "Certificate created" -ForegroundColor Green
Write-Host "  subject     : $($cert.Subject)"
Write-Host "  thumbprint  : $($cert.Thumbprint)"
Write-Host "  valid until : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  public half : $cer   (this is what goes into GPO)"

if ($BackupPassword) {
  $pfx = Join-Path $OutDir 'socksit-codesign.pfx'
  Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $BackupPassword | Out-Null
  Write-Host "  backup      : $pfx   (keep it somewhere that is not this machine)"
}

if ($TrustLocally) {
  foreach ($store in 'Root', 'TrustedPublisher') {
    Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
  }
  Write-Host "  trusted on this machine (LocalMachine\Root + TrustedPublisher)"
}

Write-Host @"

Next:
  1. Sign a release with it:
       pwsh build/release-local.ps1 -Version <x.y.z> -SelfSigned -Thumbprint $($cert.Thumbprint)
  2. Roll the public half out to the fleet by GPO — Computer Configuration ->
     Policies -> Windows Settings -> Security Settings -> Public Key Policies:
     socksit-codesign.cer into BOTH Trusted Root Certification Authorities and
     Trusted Publishers.
  3. Outside that perimeter the signature stays untrusted: SmartScreen will keep
     warning on public downloads. Only a publicly trusted certificate changes that.
"@ -ForegroundColor DarkGray
