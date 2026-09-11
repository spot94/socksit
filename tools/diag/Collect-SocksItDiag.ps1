#Requires -Version 5.1
<#
.SYNOPSIS
  One-shot collector for "the app does not go through the proxy" reports.

.DESCRIPTION
  Everything needed to tell the three cases apart, in one file the user can hand
  over: (1) the upstream proxy refuses this client or this destination, (2) the
  tunnel never reaches the proxy, (3) the app resolves or connects outside the
  tunnel. The most decisive fact is in the connection dump: a healthy proxied
  connection carries a NAME (metadata.host set, destinationIP empty), so a fake
  198.18.x.x address in destinationIP means the upstream proxy is being asked to
  dial an address that exists only on this machine.

  Read-only except for two temporary changes, both reverted in a finally block
  and both reported in the file: the log level is raised to debug for the
  reproduce window, and curl.exe is added to the app list to test the tunnel
  end to end. Proxy credentials are scrubbed from the report.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Collect-SocksItDiag.ps1
#>
[CmdletBinding()]
param(
  # Where to write the report. Computed before elevation so the file lands in
  # the folder the person actually started from.
  [string]$Out,
  # How long to wait while the person reproduces the problem.
  [int]$WatchSeconds = 45,
  # Set on the elevated relaunch; do not pass by hand.
  [switch]$Elevated,
  # Skip putting curl.exe in the app list (leaves the config fully untouched).
  [switch]$NoTunnelTest,
  # No final prompt and no Explorer window: for unattended runs and self-tests.
  [switch]$NoPause
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'

# ---------------------------------------------------------------- output file
if (-not $Out) {
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $file = "socksit-diag-$env:COMPUTERNAME-$stamp.txt"
  $dir = $null
  foreach ($cand in @($PSScriptRoot, [Environment]::GetFolderPath('Desktop'), $env:TEMP)) {
    if (-not $cand) { continue }
    try {
      $probe = Join-Path $cand '.socksit-write-test'
      New-Item -ItemType File -Path $probe -Force -ErrorAction Stop | Out-Null
      Remove-Item $probe -Force -ErrorAction SilentlyContinue
      $dir = $cand
      break
    } catch { }
  }
  if (-not $dir) { $dir = $env:TEMP }
  $Out = Join-Path $dir $file
}

# -------------------------------------------------------------------- elevate
# Not strictly required - most of this reads fine as a plain user - but the
# service pipe and the log directory are friendlier to an admin, and a half
# empty report costs another round trip with the user.
if (-not $Elevated) {
  $me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
      $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', """$PSCommandPath""", '-Elevated', '-Out', """$Out""", '-WatchSeconds', $WatchSeconds)
      if ($NoTunnelTest) { $a += '-NoTunnelTest' }
      if ($NoPause) { $a += '-NoPause' }
      Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $a -ErrorAction Stop
      exit 0
    } catch {
      Write-Host 'Права администратора не выданы - соберу то, что доступно.' -ForegroundColor Yellow
    }
  }
}

# -------------------------------------------------------------------- helpers
$sb = New-Object System.Text.StringBuilder
function W([string]$s = '') { [void]$sb.AppendLine($s) }

# The config and the generated engine config carry the SOCKS credentials. They
# must never reach a chat, a ticket or a mail thread.
function Hide-Secrets([string]$t) {
  if (-not $t) { return $t }
  $t = $t -replace '(?im)^(\s*(?:username|password|secret|token|pubkey)\s*:\s*).+$', '$1<скрыто>'
  $t = $t -replace '(?i)("(?:username|password|secret|token)"\s*:\s*")[^"]*(")', '$1<скрыто>$2'
  $t = $t -replace '(?i)(socks5h?://)[^/@\s]+@', '$1<скрыто>@'
  return $t
}

function Section([string]$title) {
  W ''
  W ('=' * 78)
  W "== $title"
  W ('=' * 78)
  Write-Host "  $title" -ForegroundColor Cyan
}

function Step([string]$title, [scriptblock]$body) {
  W ''
  W "--- $title"
  try {
    $o = & $body 2>&1 | Out-String
    if ([string]::IsNullOrWhiteSpace($o)) { W '  (пусто)' } else { W (Hide-Secrets $o.TrimEnd()) }
  } catch {
    W ('  ОШИБКА: ' + $_.Exception.Message)
  }
}

# curl -v writes to stderr, and a merged stream turns each line into an
# ErrorRecord that PowerShell renders with a script trace. In a file a human
# reads, that noise buries the two lines that matter.
function Invoke-Text([scriptblock]$body) {
  # 'Continue', not 'SilentlyContinue': the latter makes PowerShell drop the
  # redirected stderr entirely, which is where curl -v puts the two lines that
  # decide the diagnosis ("Trying 198.18.x.x" and "Connected to").
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    (& $body 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }
      }) -join "`n"
  } finally { $ErrorActionPreference = $old }
}

# Keep only the lines of curl -v that say something about routing.
function Trim-Curl([string]$t) {
  ($t -split "`r?`n" | Where-Object {
    $_ -match 'Trying|Connected to|SOCKS|CONNECT|SSL connection|subject:|HTTP/|ip=|loc=|colo=|error|refused|timed out|timeout|Failed|Recv failure|\[http='
  }) -join "`n"
}

# --------------------------------------------------------------- locate things
$svc = Get-CimInstance Win32_Service -Filter "Name='socksit'" -ErrorAction SilentlyContinue
$exe = $null
if ($svc -and $svc.PathName -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
elseif ($svc -and $svc.PathName) { $exe = ($svc.PathName -split '\s+')[0] }
if (-not $exe -or -not (Test-Path $exe)) {
  $exe = $null
  foreach ($c in @("$env:ProgramFiles\SocksIt\socksit.exe", "${env:ProgramFiles(x86)}\SocksIt\socksit.exe")) {
    if (Test-Path $c) { $exe = $c; break }
  }
}
$dataDir = Join-Path $env:ProgramData 'SocksIt'
$yamlPath = Join-Path $dataDir 'socksit.yaml'
$jsonPath = Join-Path $dataDir 'config.json'
$logPath = Join-Path $dataDir 'socksit.log'

# Proxy address and control port come from the config, so the kit is not tied to
# one deployment.
$proxyHost = $null
$proxyPort = $null
$clash = '127.0.0.1:9797'
if (Test-Path $yamlPath) {
  $y = Get-Content $yamlPath -Raw
  if ($y -match '(?m)^proxy:\s*$([\s\S]*?)(?=^\S|\Z)') {
    $blk = $Matches[1]
    if ($blk -match '(?m)^\s*address:\s*(\S+)') { $proxyHost = $Matches[1] }
    if ($blk -match '(?m)^\s*port:\s*(\d+)') { $proxyPort = $Matches[1] }
  }
  if ($y -match '(?m)^\s*clash_api:\s*(\S+)') { $clash = $Matches[1] }
}
$proxy = $null
if ($proxyHost -and $proxyPort) { $proxy = "${proxyHost}:${proxyPort}" }

# Destinations worth probing. cdn-cgi/trace answers with the exit IP and country,
# which a plain page fetch does not; Cloudflare 403s curl's TLS fingerprint on
# the front page, and that false alarm has cost time before.
$targets = @(
  'https://chatgpt.com/cdn-cgi/trace',
  'https://claude.ai/cdn-cgi/trace',
  'https://api.openai.com/v1/models',
  'https://www.google.com/generate_204'
)
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'

function Get-Connections {
  $raw = & $curl -s --max-time 5 "http://$clash/connections" 2>$null
  if (-not $raw) { return $null }
  try { return ($raw | ConvertFrom-Json) } catch { return $null }
}

function Format-Connections($j) {
  if (-not $j) { return 'Clash API не ответил (движок остановлен?)' }
  $now = Get-Date
  $rows = @($j.connections | ForEach-Object {
      $m = $_.metadata
      $p = '?'
      if ($m.processPath) { $p = Split-Path $m.processPath -Leaf }
      [pscustomobject]@{
        age_s  = [int]($now - [datetime]$_.start).TotalSeconds
        proc   = $p
        host   = $m.host
        destIP = $m.destinationIP
        port   = $m.destinationPort
        net    = $m.network
        chain  = ($_.chains -join '<-')
        up     = $_.upload
        down   = $_.download
        rule   = $_.rule
      }
    })
  $t = "всего: $($rows.Count)   uploadTotal=$($j.uploadTotal)   downloadTotal=$($j.downloadTotal)`n`n"
  $t += ($rows | Sort-Object chain, host, age_s |
    Format-Table age_s, proc, host, destIP, port, net, chain, up, down -AutoSize |
    Out-String -Width 220)
  $t += "`nСработавшие правила маршрутизации:`n"
  $t += (($rows | Group-Object rule | Sort-Object Count -Descending |
      ForEach-Object { "  [$($_.Count)] $($_.Name)" }) -join "`n")
  return $t
}

# ============================================================================
Write-Host ''
Write-Host '  Сбор диагностики SocksIt' -ForegroundColor Green
Write-Host "  Отчёт: $Out"
Write-Host ''

W 'Диагностика SocksIt'
W "Собрано: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
W "Компьютер: $env:COMPUTERNAME   Пользователь: $env:USERNAME"
W 'Скрипт: Collect-SocksItDiag.ps1 v1'
W ''
W 'Логин и пароль прокси в этом файле скрыты. Всё остальное - как есть.'

Section '1. Система'
Step 'ОС' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime | Format-List }
Step 'Права' {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  'Администратор: ' + $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
Step 'Антивирус и защита' {
  Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
    Select-Object displayName, productState | Format-Table -AutoSize
}
Step 'Интересные процессы' {
  Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(ChatGPT|claude|codex|kimi|node|msedge|chrome|sing-box|socksit)' } |
    Select-Object Name, Id, @{n = 'Path'; e = { $_.Path } } | Sort-Object Name | Format-Table -AutoSize
}

Section '2. Служба и конфигурация SocksIt'
Step 'Служба' {
  Get-Service socksit -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-List
  if ($svc) { "ImagePath: $($svc.PathName)" }
}
Step 'Исполняемый файл' {
  if ($exe) {
    $exe
    (Get-Item $exe).VersionInfo | Format-List FileVersion, ProductVersion, CompanyName
  } else { 'socksit.exe не найден' }
}
if ($exe) {
  Step 'socksit version' { & $exe version }
  Step 'socksit status' { & $exe status }
  Step 'socksit doctor' { & $exe doctor }
  Step 'socksit proxytest' { & $exe proxytest }
}
Step 'socksit.yaml (пароли скрыты)' {
  if (Test-Path $yamlPath) { Get-Content $yamlPath -Raw } else { "нет файла $yamlPath" }
}
Step 'config.json движка (пароли скрыты)' {
  if (Test-Path $jsonPath) { Get-Content $jsonPath -Raw } else { "нет файла $jsonPath" }
}

Section '3. Сеть'
Step 'Адаптеры' { Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MtuSize | Format-Table -AutoSize }
Step 'Адреса IPv4' { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize }
Step 'Маршруты по умолчанию и туннель' {
  Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1') -or $_.DestinationPrefix -like '198.18.*' -or $_.DestinationPrefix -like '172.19.*' } |
    Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, InterfaceMetric | Format-Table -AutoSize
}
Step 'DNS-серверы' {
  Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object ServerAddresses | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
}
if ($proxyHost) {
  Step "Маршрут до прокси $proxyHost" {
    Find-NetRoute -RemoteIPAddress $proxyHost -ErrorAction SilentlyContinue |
      Select-Object -First 2 | Format-List InterfaceAlias, IPAddress, NextHop, DestinationPrefix
  }
  Step "TCP до прокси $proxy" {
    Test-NetConnection -ComputerName $proxyHost -Port ([int]$proxyPort) -WarningAction SilentlyContinue |
      Format-List ComputerName, RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded, InterfaceAlias
  }
}

Section '4. DNS: что получают приложения'
W ''
W 'При работающем SocksIt здесь ожидаются фейковые адреса 198.18.x.x - так имя'
W 'доезжает до прокси. Настоящий адрес означает, что приложение отдаст прокси IP.'
foreach ($n in @('chatgpt.com', 'claude.ai', 'api.openai.com', 'www.google.com')) {
  Step "Resolve $n" {
    $r = Resolve-DnsName $n -Type A -ErrorAction SilentlyContinue
    if ($r) {
      ($r | Where-Object IPAddress | Select-Object Name, IPAddress | Format-Table -AutoSize | Out-String).Trim()
    } else { 'не разрешилось' }
  }
}

Section '5. Прокси напрямую, мимо SocksIt'
W ''
W 'curl.exe не входит в список приложений, поэтому идёт к прокси в обход туннеля.'
W 'Этот раздел отвечает на вопрос: исправен ли прокси ДЛЯ ЭТОЙ машины.'
if (-not $proxy) {
  W ''
  W 'Адрес прокси не удалось прочитать из конфига - раздел пропущен.'
} else {
  foreach ($u in $targets) {
    Step "$u через $proxy" {
      $o = Invoke-Text { & $curl -s -m 20 --socks5-hostname $proxy -A $ua $u -w "`n[http=%{http_code} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total}]" }
      "exit=$LASTEXITCODE`n" + $o.Trim()
    }
  }
  Step 'Контроль: CONNECT по literal-IP, как в доктора' {
    $o = Invoke-Text { & $curl -s -o NUL -m 20 --socks5-hostname $proxy 'https://1.1.1.1/' -w 'http=%{http_code} connect=%{time_connect} total=%{time_total}' }
    "exit=$LASTEXITCODE  $($o.Trim())"
  }
  Step 'Контроль: --socks5 вместо --socks5-hostname' {
    $o = Invoke-Text { & $curl -s -o NUL -m 15 --socks5 $proxy 'https://www.google.com/generate_204' -w 'http=%{http_code} total=%{time_total}' }
    "exit=$LASTEXITCODE  $($o.Trim())`nНенулевой exit здесь - норма: curl резолвит сам и отдаёт прокси фейковый адрес."
  }
}

Section '6. Соединения до воспроизведения'
Step 'Clash API /connections' { Format-Connections (Get-Connections) }

# ======================================================= reproduce with debug
$addedCurl = $false
$prevLevel = $null
try {
  Section '7. Воспроизведение проблемы с debug-логом'
  if ($exe) {
    try {
      $prevLevel = (& $exe config log-level 2>&1 | Out-String).Trim()
      & $exe config log-level debug 2>&1 | Out-String | Out-Null
      W "Уровень лога временно поднят до debug (было: $prevLevel)."
    } catch { W "Не удалось поднять уровень лога: $($_.Exception.Message)" }
  }

  $logMark = 0
  if (Test-Path $logPath) { $logMark = (Get-Item $logPath).Length }

  Write-Host ''
  Write-Host '  ==============================================================' -ForegroundColor Yellow
  Write-Host '   СЕЙЧАС: откройте приложение (ChatGPT / Claude) и попробуйте' -ForegroundColor Yellow
  Write-Host '   отправить сообщение или обновить страницу.' -ForegroundColor Yellow
  Write-Host "   Идёт запись, $WatchSeconds секунд. Окно не закрывайте." -ForegroundColor Yellow
  Write-Host '  ==============================================================' -ForegroundColor Yellow
  W ''
  W "Окно воспроизведения: $WatchSeconds с, начало $(Get-Date -Format 'HH:mm:ss')."
  for ($i = $WatchSeconds; $i -gt 0; $i--) {
    Write-Host "`r   осталось $i с    " -NoNewline
    Start-Sleep -Seconds 1
  }
  Write-Host "`r   готово             "
  W "Конец окна: $(Get-Date -Format 'HH:mm:ss')."

  Section '8. Соединения после воспроизведения'
  Step 'Clash API /connections' { Format-Connections (Get-Connections) }

  Section '9. Лог за время воспроизведения'
  Step 'Новые строки socksit.log' {
    if (-not (Test-Path $logPath)) { return "нет файла $logPath" }
    $new = ''
    $fs = [System.IO.File]::Open($logPath, 'Open', 'Read', 'ReadWrite')
    try {
      if ($logMark -gt $fs.Length) { $logMark = 0 }   # log rotated mid-run
      [void]$fs.Seek($logMark, 'Begin')
      $sr = New-Object System.IO.StreamReader($fs)
      $new = $sr.ReadToEnd()
    } finally { $fs.Dispose() }
    if ([string]::IsNullOrWhiteSpace($new)) { 'за окно воспроизведения в лог ничего не добавилось' } else { $new }
  }

  Section '10. Запрос ЧЕРЕЗ туннель'
  if ($NoTunnelTest) {
    W 'Пропущено (-NoTunnelTest).'
  } elseif (-not $exe) {
    W 'socksit.exe не найден - пропущено.'
  } else {
    $list = (& $exe config app list 2>&1 | Out-String)
    if ($list -match '(?im)^\s*curl\.exe\s*$') {
      W 'curl.exe уже был в списке приложений - оставляю как есть.'
    } else {
      & $exe config app add curl.exe 2>&1 | Out-String | Out-Null
      $addedCurl = $true
      W 'curl.exe временно добавлен в список приложений, будет убран в конце.'
      Start-Sleep -Seconds 3   # let the engine reload
    }
    foreach ($u in @('https://chatgpt.com/cdn-cgi/trace', 'https://www.google.com/generate_204')) {
      Step "$u через туннель" {
        $o = Invoke-Text { & $curl -v -s -m 25 -A $ua $u -w "`n[http=%{http_code} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total}]" }
        "exit=$LASTEXITCODE`n" + (Trim-Curl $o)
      }
    }
    Step 'Соединения во время запроса через туннель' { Format-Connections (Get-Connections) }
  }
} finally {
  Section '11. Возврат временных изменений'
  if ($addedCurl -and $exe) {
    try {
      & $exe config app rm curl.exe 2>&1 | Out-String | Out-Null
      W 'curl.exe убран из списка приложений.'
    } catch {
      W "НЕ УДАЛОСЬ убрать curl.exe: $($_.Exception.Message)"
      W 'Уберите вручную: socksit config app rm curl.exe'
    }
  } else {
    W 'Список приложений не менялся.'
  }
  if ($prevLevel -and $exe) {
    $lvl = 'warn'
    if ($prevLevel -match '(trace|debug|info|warn|error)') { $lvl = $Matches[1] }
    try {
      & $exe config log-level $lvl 2>&1 | Out-String | Out-Null
      W "Уровень лога возвращён: $lvl."
    } catch {
      W 'НЕ УДАЛОСЬ вернуть уровень лога. Верните вручную: socksit config log-level warn'
    }
  }

  Section '12. Хвост логов'
  Step 'socksit.log, последние 200 строк' {
    if (Test-Path $logPath) { Get-Content $logPath -Tail 200 } else { "нет файла $logPath" }
  }
  Step 'Предыдущий файл лога, последние 60 строк' {
    $p = "$logPath.1"
    if (Test-Path $p) { Get-Content $p -Tail 60 } else { 'нет' }
  }
  Step 'Журнал Windows по службе за 3 дня' {
    Get-WinEvent -FilterHashtable @{LogName = 'Application'; StartTime = (Get-Date).AddDays(-3) } -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'socksit|sing-box' } |
      Select-Object -First 20 TimeCreated, LevelDisplayName, Message | Format-List
  }

  W ''
  W ('=' * 78)
  W 'Конец отчёта.'

  try {
    [System.IO.File]::WriteAllText($Out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
    Write-Host ''
    Write-Host '  Готово.' -ForegroundColor Green
    Write-Host "  Файл: $Out" -ForegroundColor Green
    Write-Host '  Отправьте этот файл тому, кто попросил диагностику.'
    if (-not $NoPause) {
      try { Set-Clipboard -Value $Out -ErrorAction SilentlyContinue } catch { }
      try { Start-Process explorer.exe "/select,""$Out""" } catch { }
    }
  } catch {
    Write-Host "  Не удалось записать отчёт: $($_.Exception.Message)" -ForegroundColor Red
  }
  if (-not $NoPause) {
    Write-Host ''
    Read-Host '  Нажмите Enter, чтобы закрыть'
  }
}
