# Как протестировать SocksIt сейчас

Всё запускается из корня репозитория `C:\Users\Eugene\PROJECTS\SocksIt` в PowerShell.
Готовый бинарник — `bin\socksit.exe`; движок — `assets\bin\sing-box.exe`. Пересобрать (если
нужно) можно при установленном Go: `$env:CGO_ENABLED="0"; go build -o bin\socksit.exe .\cmd\socksit`.

---

## Уровень 1 — без прав администратора (2 минуты, ничего не устанавливая)

Проверяет: генерацию/валидацию конфига и **реальное проксирование через SOCKS5** тем же
outbound-путём, что в бою (но без TUN и без per-app — это Уровень 2).

```powershell
# 1. бинарник жив
.\bin\socksit.exe version

# 2. генерация + валидация движком (должно вывести "OK: generated config passes sing-box check")
.\bin\socksit.exe check -c docs\socksit.example.yaml -engine assets\bin\sing-box.exe

# 3. реальный трафик через прокси. Сначала прямой внешний IP:
curl.exe -s https://api.ipify.org; ""

# 4. подними движок на loopback (окно 1 — оставь работать):
.\assets\bin\sing-box.exe run -c docs\loopback-test.json

# 5. в ДРУГОМ окне PowerShell — через прокси:
curl.exe -s --proxy socks5h://127.0.0.1:18080 https://api.ipify.org; ""
```

**PASS:** IP из шага 5 отличается от шага 3 (через прокси должно быть `213.155.13.17`, напрямую
`176.106.249.19` — у тебя могут быть другие, но они должны различаться). Останови движок в окне 1
через Ctrl+C.

---

## Уровень 2 — с правами администратора (реальный per-app перехват, AE1–AE8)

Требует admin: служба ставится через SCM, а Wintun-TUN открывается только из-под SYSTEM.

```powershell
# 1. положи движок рядом с socksit.exe, чтобы служба его нашла:
Copy-Item assets\bin\sing-box.exe, assets\bin\libcronet.dll bin\ -Force

# 2. PowerShell ОТ АДМИНИСТРАТОРА, из корня репозитория:
.\bin\socksit.exe install          # регистрирует службу SocksIt (LocalSystem, автозапуск)

# 3. настрой прокси и приложения (файл создаётся при первом старте службы):
notepad C:\ProgramData\SocksIt\socksit.yaml
```

Приведи `socksit.yaml` к виду:
```yaml
proxy: { address: 192.0.2.10, port: 1080, udp: true }
apps: [ chrome.exe ]
mode: allowlist
kill_switch: true
```
Сохрани — служба применит на лету (hot-reload).

```powershell
# 4. трей (в обычной, не-админской сессии):
.\bin\socksit.exe tray             # значок → "Open app list…" открывает GUI

# 5. проверки AE1–AE8 — по docs\acceptance-AE.md. Минимум:
#    открой Chrome → whatismyipaddress.com → должен показать IP прокси (213.155.13.17)
#    открой Edge (не в списке) → реальный IP
#    останови службу (Stop-Service SocksIt от админа) → Chrome теряет сеть (kill-switch), Edge жив

# 6. удалить (от администратора):
.\bin\socksit.exe uninstall
```

Полная матрица приёмки (AE1–AE8, self-heal, сосуществование с VPN, UDP) — в
[acceptance-AE.md](acceptance-AE.md).

---

## Если что-то не так

- `check` падает → покажи вывод; конфиг чинится по сообщению `sing-box`.
- Служба не стартует → `Get-EventLog Application -Source SocksIt -Newest 10` и лог
  `C:\ProgramData\SocksIt\` (audit.log, вывод движка).
- Chrome не проксируется в Уровне 2 → убедись, что имя процесса точное (`chrome.exe`, с `.exe`)
  и есть в `apps`, служба запущена (`Get-Service SocksIt`), и в `config.json`
  (`C:\ProgramData\SocksIt\config.json`) есть правило на `chrome.exe`. Для веб-приложений в
  браузере добавляй сам браузер (`chrome.exe`/`msedge.exe`) — маршрутизация по процессу, не по сайту.
