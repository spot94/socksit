<#
.SYNOPSIS
  Pulls release notes for one version out of CHANGELOG.md.

.DESCRIPTION
  The update manifest's notes are what the panel shows next to "Install update",
  and until now they said "see the commit history" — which is no answer to the
  only question the user has there: what changes if I click this. The changelog
  already contains the answer; this just lifts it.

  Only the bolded lead-in of each bullet is taken. A full section runs to
  hundreds of lines and would not fit in a dialog; the lead-ins are written as
  one-line summaries anyway.

  The changelog is Russian, so -En gets a short line plus a link rather than a
  machine translation nobody proofread.
#>
param(
  [Parameter(Mandatory)][string]$Version,
  [string]$Path = 'CHANGELOG.md',
  [string]$Repo = 'spot94/socksit',
  # Manifest notes land in a dialog, not a web page.
  [int]$MaxChars = 700
)

$ErrorActionPreference = 'Stop'
$lines = Get-Content $Path

$start = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
  if ($lines[$i] -match "^##\s*\[$([regex]::Escape($Version))\]") { $start = $i; break }
}
if ($start -lt 0) {
  # Not fatal: a release can be cut before the changelog is written, and a bad
  # note is better than a failed release. Say so loudly instead.
  Write-Warning "CHANGELOG.md has no section for $Version — falling back to a generic note."
  return @{
    Ru = "SocksIt $Version. Список изменений: https://github.com/$Repo/blob/main/CHANGELOG.md"
    En = "SocksIt $Version. Changes: https://github.com/$Repo/blob/main/CHANGELOG.md"
  }
}

$items = @()
for ($i = $start + 1; $i -lt $lines.Count; $i++) {
  if ($lines[$i] -match '^##\s') { break }          # next version section
  if ($lines[$i] -match '^\s*-\s+\*\*(.+?)\*\*') {  # bullet lead-in
    $items += $Matches[1].Trim().TrimEnd('.')
  }
}

$ru = if ($items) { ($items | ForEach-Object { "• $_" }) -join "`n" } else { "SocksIt $Version" }
if ($ru.Length -gt $MaxChars) {
  $ru = $ru.Substring(0, $MaxChars).TrimEnd() + "…`n" + "Полный список: https://github.com/$Repo/blob/main/CHANGELOG.md"
}

@{
  Ru = $ru
  En = "SocksIt $Version — $($items.Count) change(s). Full changelog (Russian): https://github.com/$Repo/blob/main/CHANGELOG.md"
}
