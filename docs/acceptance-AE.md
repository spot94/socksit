# Приёмка датаплейна AE1–AE8 (owner-run, требует admin)

Эти сценарии требуют **прав администратора** и создания Wintun-TUN (только из-под SYSTEM),
поэтому выполняются владельцем на реальной Win10/11. Автономно (без admin) уже подтверждено:
конфиги проходят `sing-box check`, egress-IP меняется через прокси, UDP ASSOCIATE поддержан
(см. `docs/spikes/singbox-findings.md`). Ниже — то, что осталось прогнать вживую.

## Подготовка

```powershell
# из-под администратора, из корня репозитория
$env:CGO_ENABLED="0"; go build -o bin\socksit.exe .\cmd\socksit
bin\socksit.exe install         # LocalSystem-служба SocksIt, автозапуск
bin\socksit.exe tray            # (в обычной сессии) трей + пункт "Open app list…"
```

Конфиг `%ProgramData%\SocksIt\socksit.yaml`:

```yaml
proxy: { address: 192.0.2.10, port: 1080, udp: true }
apps: [ chrome.exe ]
mode: allowlist
kill_switch: true
```

Опорные IP для проверки (из спайка): прямой `176.106.249.19`, через прокси `213.155.13.17`.

## Сценарии

| AE | Действие | Ожидаемо (PASS) |
|----|----------|-----------------|
| **AE1** | Запустить Chrome (в allowlist), открыть whatismyipaddress + dnsleaktest | IP = адрес прокси (`213.155.13.17`), в DNS-leak-тесте нет локального резолвера |
| **AE2** | Открыть тот же сайт в приложении **вне** списка (например, Edge) | IP реальный (`176.106.249.19`) — трафик напрямую |
| **AE3** | Остановить службу (`sc stop SocksIt`) при поднятом Chrome | Chrome теряет связь (kill-switch, без утечки реального IP); Edge работает; после `sc start SocksIt` — Chrome снова через прокси |
| **AE4** | На работающем Chrome переключить сеть Wi-Fi↔Ethernet | После короткого блипа Chrome снова ходит через прокси (self-heal); постоянного отвала нет |
| **AE5** | Поднять WireGuard-VPN, режим `polite` | Непроксируемый трафик идёт через VPN, Chrome — через SOCKS5; VPN не сломан. В `greedy` — перехват шире, но VPN конфликтует (ожидаемо) |
| **AE6** | Жёстко убить процесс службы (Task Manager) | Watchdog поднимает движок за секунды; после ребута/рестарта осиротевший адаптер `socksit` вычищается, интернет системы восстановлен |
| **AE7** | UDP-приложение (QUIC/игра) в allowlist | UDP работает (сервер `192.0.2.10` поддерживает ASSOCIATE — подтверждено); при сервере без UDP — предупреждение и TCP-fallback |
| **AE8** | Через трей → "Open app list…" добавить приложение, Save | После автоперезагрузки приложение проксируется, без ручной правки YAML |

## Диагностика

- Аудит: `%ProgramData%\SocksIt\audit.log`.
- Статистика соединений/трафика по приложениям: GUI → "Statistics" (Clash API движка).
- Конфиг движка, который реально применён: `%ProgramData%\SocksIt\config.json`.
- Быстрая офлайн-проверка без TUN (не требует admin):
  `bin\socksit.exe check -c %ProgramData%\SocksIt\socksit.yaml`.
