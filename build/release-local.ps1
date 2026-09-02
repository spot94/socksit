<#
.SYNOPSIS
  Cuts a signed SocksIt release from this machine.

.DESCRIPTION
  Releases moved here from CI because a publicly trusted code-signing key cannot
  leave the machine it lives on: since June 2023 those keys sit on a token or in
  a cloud HSM (Certum SimplySign, DigiCert KeyLocker, …), so there is no .pfx to
  hand to a GitHub runner.

  The order of the steps is not cosmetic. The update manifest carries SHA-256
  hashes of the files it points at, and signing changes those bytes — so signing
  must happen BEFORE the manifest is built, and the installer must be packaged
  from already-signed binaries. Signing an artifact after publishing silently
  breaks every client's update check.

      build exe -> sign exe + engine -> build MSI -> sign MSI -> manifest -> upload

.PARAMETER Version
  Release version without the leading v, e.g. 0.3.2. A matching git tag must
  exist and point at HEAD: what is published has to be what is in the repository.

.PARAMETER Thumbprint
  Code-signing certificate in the Windows store. With a cloud certificate
  (SimplySign and friends) log into the vendor's desktop app first — the
  certificate then appears in the store like a smart card. Omit to let
  build/sign.ps1 pick the best available code-signing certificate.

.PARAMETER Unsigned
  Build without signing. For dry runs only — the whole point of this script is
  that releases are signed.

.EXAMPLE
  # dry run: everything except signing and publishing
  pwsh build/release-local.ps1 -Version 0.3.2 -Unsigned -NoPublish

.EXAMPLE
  # the real thing
  $env:GITHUB_TOKEN = '<token with repo scope>'
  pwsh build/release-local.ps1 -Version 0.3.2 -Proxy socks5h://172.16.0.2:1080
#>
param(
  [Parameter(Mandatory)][string]$Version,
  [string]$Thumbprint,
  [switch]$Unsigned,
  [switch]$NoPublish,
  # Only for dry runs. A published release without the installer would send
  # everyone back to the exe-swap update path.
  [switch]$SkipInstaller,
  [string]$SignKeyFile = 'build/keys/signing.key.b64',
  [string]$Repo = 'spot94/socksit',
  # GitHub is not reachable directly from every network this is run on.
  [string]$Proxy = $env:SOCKSIT_RELEASE_PROXY
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($msg) { Write-Host "`n=== $msg" -ForegroundColor Cyan }
function Note($msg) { Write-Host "    $msg" -ForegroundColor DarkGray }

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must look like 0.3.2, got '$Version'" }
$tag = "v$Version"

# ---------------------------------------------------------------- preconditions
Step "Checking the repository"
if (git status --porcelain) { throw "The working tree is dirty. Commit or stash first: a release must be reproducible from the tag." }
$tagged = git rev-parse -q --verify "refs/tags/$tag" 2>$null
if (-not $tagged) { throw "Tag $tag does not exist. Create it on the commit you are releasing: git tag $tag" }
if ($tagged.Trim() -ne (git rev-parse HEAD).Trim()) { throw "Tag $tag does not point at HEAD — check out the tagged commit." }
Note "tag $tag = $($tagged.Substring(0,9))"

$signKey = $env:SOCKSIT_SIGN_KEY
if (-not $signKey -and (Test-Path $SignKeyFile)) { $signKey = (Get-Content $SignKeyFile -Raw).Trim() }
if (-not $signKey) { throw "No update-manifest key. Put the base64 Ed25519 private key in $SignKeyFile or SOCKSIT_SIGN_KEY." }

if (-not $NoPublish -and -not $env:GITHUB_TOKEN) { throw "GITHUB_TOKEN is not set (needs 'repo' scope to create the release)." }

$dist = Join-Path $root 'dist'
Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $dist | Out-Null

# ------------------------------------------------------- version metadata (PE)
# A Go binary carries no VERSIONINFO unless one is embedded. Without it Windows
# shows an empty publisher and AV heuristics score the file worse.
Step "Stamping version metadata into the exe resource"
$vi = Get-Content 'cmd/socksit/versioninfo.json' -Raw | ConvertFrom-Json
$maj, $min, $pat = $Version.Split('.')
foreach ($f in 'FileVersion', 'ProductVersion') {
  $vi.FixedFileInfo.$f.Major = [int]$maj
  $vi.FixedFileInfo.$f.Minor = [int]$min
  $vi.FixedFileInfo.$f.Patch = [int]$pat
  $vi.FixedFileInfo.$f.Build = 0
  $vi.StringFileInfo.$f = "$Version.0"
}
$vi | ConvertTo-Json -Depth 8 | Set-Content 'cmd/socksit/versioninfo.json' -Encoding utf8
Push-Location 'cmd/socksit'
try {
  go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1 -64 -o rsrc_windows_amd64.syso versioninfo.json
  if ($LASTEXITCODE) { throw "goversioninfo failed" }
} finally { Pop-Location }
Note "FileVersion = $Version.0"

# ------------------------------------------------------------------- build
Step "Fetching the pinned engine"
pwsh -File build/fetch-engine.ps1

Step "Building socksit.exe"
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags "-H=windowsgui -s -w -X main.Version=$Version" -o "$dist/socksit.exe" ./cmd/socksit
if ($LASTEXITCODE) { throw "go build failed" }
Copy-Item 'assets/bin/sing-box.exe' "$dist/sing-box.exe" -Force
Note ("socksit.exe {0:N0} bytes" -f (Get-Item "$dist/socksit.exe").Length)

# ------------------------------------------------------------------- signing
# sing-box.exe is signed too: upstream ships it unsigned, so this adds a
# signature rather than replacing one, and the fleet stops carrying an unsigned
# 45 MB binary that our own updater downloads.
Step "Signing the binaries"
if ($Unsigned) {
  Write-Warning "-Unsigned: publishing files nobody vouches for. SmartScreen and AV will flag them."
} else {
  $signArgs = @{ Files = @("$dist/socksit.exe", "$dist/sing-box.exe") }
  if ($Thumbprint) { $signArgs.Thumbprint = $Thumbprint }
  & "$PSScriptRoot/sign.ps1" @signArgs
  if ($LASTEXITCODE) { throw "signing failed" }
}

# ----------------------------------------------------------------- installer
Step "Building the installer"
if ($SkipInstaller) {
  Write-Warning "-SkipInstaller: dry run only. A real release must ship SocksIt.msi — without it, machines fall back to the exe-swap update path that behavioural AV flags."
} else {
  if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "WiX is missing. Install the .NET SDK, then: dotnet tool install --global wix --version 5.0.2"
  }
  & "$PSScriptRoot/build-msi.ps1" -Version $Version -From $dist
  Move-Item "$PSScriptRoot/SocksIt.msi" "$dist/SocksIt.msi" -Force
  if (-not $Unsigned) {
    $msiArgs = @{ Files = @("$dist/SocksIt.msi") }
    if ($Thumbprint) { $msiArgs.Thumbprint = $Thumbprint }
    & "$PSScriptRoot/sign.ps1" @msiArgs
    if ($LASTEXITCODE) { throw "signing the installer failed" }
  }
  Note ("SocksIt.msi {0:N0} bytes" -f (Get-Item "$dist/SocksIt.msi").Length)
}

# ------------------------------------------------------------------ manifest
# Built last, over the signed files: it carries their hashes and clients refuse
# anything that does not match.
Step "Building and signing the update manifest"
$notes = & "$PSScriptRoot/changelog-notes.ps1" -Version $Version
$engineVersion = (Select-String -Path 'assets/bin/VERSION' -Pattern '^SINGBOX_VERSION=(.+)$').Matches.Groups[1].Value
$base = "https://github.com/$Repo/releases/download/$tag"

$mkArgs = @(
  'run', './cmd/mksign', 'build',
  '-app', "$dist/socksit.exe",
  '-engine', "$dist/sing-box.exe",
  '-engine-version', $engineVersion,
  '-version', $Version,
  '-channel', 'stable',
  '-base-url', $base,
  '-notes-en', $notes.En,
  '-notes-ru', $notes.Ru,
  '-out', $dist
)
if (-not $SkipInstaller) { $mkArgs += @('-msi', "$dist/SocksIt.msi") }
$env:SOCKSIT_SIGN_KEY = $signKey
try { & go @mkArgs; if ($LASTEXITCODE) { throw "mksign failed" } }
finally { Remove-Item Env:SOCKSIT_SIGN_KEY -ErrorAction SilentlyContinue }

Step "Artifacts"
Get-ChildItem $dist | ForEach-Object { '    {0,-18} {1,12:N0} bytes' -f $_.Name, $_.Length }

if ($NoPublish) {
  Write-Host "`nBuilt but not published (-NoPublish)." -ForegroundColor Yellow
  return
}

# ------------------------------------------------------------------- publish
Step "Publishing the GitHub release"
$curlProxy = if ($Proxy) { @('--proxy', $Proxy) } else { @() }
$auth = @('-H', "Authorization: Bearer $env:GITHUB_TOKEN", '-H', 'Accept: application/vnd.github+json')

$body = @{
  tag_name = $tag; name = "SocksIt $Version"; draft = $false; prerelease = $false
  generate_release_notes = $true
  body = if ($Unsigned) { '> **Unsigned build** — see docs/signing.md.' } else { '' }
} | ConvertTo-Json -Compress
$tmp = New-TemporaryFile
Set-Content $tmp $body -Encoding utf8
$created = & curl.exe -sS @curlProxy @auth -X POST "https://api.github.com/repos/$Repo/releases" --data-binary "@$tmp" | ConvertFrom-Json
Remove-Item $tmp -Force
if (-not $created.upload_url) { throw "Creating the release failed: $($created | ConvertTo-Json -Depth 4)" }
$upload = $created.upload_url -replace '\{.*$', ''
Note "release id $($created.id)"

foreach ($f in Get-ChildItem $dist) {
  Write-Host "    uploading $($f.Name)…"
  $r = & curl.exe -sS @curlProxy @auth -H 'Content-Type: application/octet-stream' `
    -X POST "$upload`?name=$($f.Name)" --data-binary "@$($f.FullName)" | ConvertFrom-Json
  if (-not $r.id) { throw "Uploading $($f.Name) failed: $($r | ConvertTo-Json -Depth 4)" }
}

Write-Host "`nPublished: $($created.html_url)" -ForegroundColor Green
Write-Host @"

Verify before telling anyone (checks the signature with the key baked into clients):
  go run ./cmd/mksign verify -endpoint https://github.com/$Repo/releases/latest/download
"@ -ForegroundColor DarkGray
