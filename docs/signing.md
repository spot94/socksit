# Подпись кода (Authenticode)

Подписанный exe не помечается как «unknown publisher», снижает трения SmartScreen,
а в домене ему можно доверять через GPO. Подписываем **только свои** сборки
(`socksit.exe`, `socksit-setup.exe`); вендорские `sing-box.exe`/`libcronet.dll`/`wintun.dll`
не трогаем — у них своя подпись.

## 1. Что нужно

- **Сертификат** для подписи кода (варианты ниже).
- **`signtool.exe`** — из Windows SDK (компонент *App Certification Kit / signing tools*).
  Обычно `C:\Program Files (x86)\Windows Kits\10\bin\<версия>\x64\signtool.exe`.
  Скрипт `build/sign.ps1` находит его сам.

## 2. Какой сертификат выбрать

- **Внутреннее распространение (скорее всего ваш случай).** Self-signed или сертификат
  внутреннего CA компании; публичную часть раскатать на клиентов через GPO. Покупать ничего
  не нужно. Нюанс: SmartScreen реагирует в основном на файлы с *Mark-of-the-Web* (скачанные
  из интернета); при раздаче по сети/копированием MOTW обычно нет — предупреждения не будет.
- **Публичное распространение.** Нужен сертификат публичного CA. С июня 2023 ключи (OV и EV)
  обязаны жить на HSM/токене или в облачном KMS. **EV с ~2024 не даёт мгновенной SmartScreen-
  репутации** (копится одинаково для OV и EV). Практично: **Azure Trusted Signing** (управляемый,
  без токена) или OV-сертификат на токене.

## 3. Внутренний путь: self-signed + доверие через GPO

Создать сертификат один раз на билд-машине:
```powershell
$c = New-SelfSignedCertificate -Type CodeSigningCert `
  -Subject "CN=SocksIt Code Signing, O=SciEntetiq" `
  -CertStoreLocation Cert:\CurrentUser\My `
  -KeyUsage DigitalSignature -KeyExportPolicy Exportable `
  -NotAfter (Get-Date).AddYears(5)
$c.Thumbprint                                                  # им и подписываем
Export-Certificate -Cert $c -FilePath socksit-codesign.cer     # публичная часть для GPO
```
Подписать:
```powershell
.\build\sign.ps1 -Thumbprint <thumbprint> -Files bin\socksit.exe,socksit-setup.exe
```
Раскатать доверие на клиентов — GPO: *Computer Configuration → Policies → Windows Settings →
Security Settings → Public Key Policies*:
- `socksit-codesign.cer` → **Trusted Root Certification Authorities** (доверенная цепочка),
- и в **Trusted Publishers** (чтобы не переспрашивал).

Локально для проверки:
```powershell
Import-Certificate -FilePath socksit-codesign.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath socksit-codesign.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

## 4. Публичный путь: Azure Trusted Signing

1. Завести Trusted Signing account в Azure (нужна верифицированная организация).
2. Скачать signing dlib и сделать `metadata.json` (`Endpoint`, `CodeSigningAccountName`,
   `CertificateProfileName`).
3. Подписать:
   ```powershell
   .\build\sign.ps1 -TSDlib "C:\acs\Azure.CodeSigning.Dlib.dll" -TSMetadata metadata.json -Files socksit-setup.exe
   ```
   (Нужен свежий signtool из Windows SDK ≥ 10.0.22621.755 для `/dlib`.)

## 5. Проверка

```powershell
signtool verify /pa /v socksit-setup.exe
```
Для self-signed без доверенного корня будет ошибка цепочки — это ожидаемо; проверяй на машине,
где сертификат уже в Trusted Root.

## 6. Подпись в CI (GitHub Release)

Воркфлоу `.github/workflows/release.yml` подписывает `socksit.exe`, `sing-box.exe` и
установщик `SocksIt.msi`, если в репозитории заданы два секрета. Если секретов нет,
шаги — no-op: всё публикуется **неподписанным**, в лог сборки идёт предупреждение,
а в описание релиза добавляется строка «Unsigned build» (без неё это выяснялось
только разбором PE-заголовка задним числом):

- `WINDOWS_CERT_PFX_BASE64` — ваш code-signing `.pfx` в base64;
- `WINDOWS_CERT_PASSWORD` — пароль к нему.

Подготовить base64 из `.pfx`:
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("codesign.pfx")) | Set-Clipboard
```
Затем: репозиторий → **Settings → Secrets and variables → Actions → New repository
secret** — добавить `WINDOWS_CERT_PFX_BASE64` (вставить base64) и
`WINDOWS_CERT_PASSWORD`.

Детали:
- Подписываются `socksit.exe`, `sing-box.exe` и `SocksIt.msi`. Движок подписывается
  **нашим** сертификатом сознательно: upstream публикует его **без подписи** (проверено),
  так что мы не заменяем чужую подпись, а добавляем свою — иначе по парку разъезжается
  45-мегабайтный неподписанный бинарь, который наш же апдейтер и скачивает. Мы фиксируем
  его версию и хеш в манифесте, то есть ручаемся ровно за то, что распространяем.
- Порядок шагов важен: бинари подписываются **до** сборки MSI (иначе в пакет попадут
  неподписанные файлы), MSI подписывается сразу после сборки, и только затем считается
  манифест обновлений.
- Шаг стоит **до** генерации манифеста: `mksign` считает хеш уже подписанного файла,
  иначе проверка обновлений на клиенте разъедется.
- В CI вызывается `build/sign.ps1 … -SkipVerify` — раннер GitHub не доверяет
  self-signed/внутренней CA-цепочке, поэтому финальную проверку цепочки пропускаем
  (сам факт успешной подписи проверяется по коду возврата `signtool sign`).
- Хранение `.pfx` в секрете подходит для self-signed / внутреннего CA. Для **Azure
  Trusted Signing** в CI — вместо PFX прокинуть `-TSDlib`/`-TSMetadata` и azure-login
  (можно добавить позже).

## Правила

- Всегда таймстамп (`/tr`) — подпись остаётся валидной после истечения сертификата
  (`build/sign.ps1` делает это всегда).
- SHA-256 (`/fd sha256 /td sha256`) — тоже уже в скрипте.
- Для self-contained сборки (`-tags "preset embed_engine"`): собрал `socksit-setup.exe` →
  подписал его.

## Чего подпись не лечит

Подпись даёт **идентичность**, а не доверие. Она снимает у SmartScreen «неизвестный
издатель» (мгновенно — только с EV; с обычным сертификатом репутация набирается по мере
скачиваний), но поведенческие детекторы вроде Kaspersky PDM (`PDM:Trojan.Win32.Generic`)
судят по действиям программы, а не по подписи. У SocksIt эти действия объективно совпадают
с малварью: служба под LocalSystem, создание виртуального адаптера, переписывание таблицы
маршрутизации, перехват DNS, запуск дочернего процесса под SYSTEM и — главное — скачивание
exe с подменой собственного работающего файла.

Поэтому вместе с подписью работают ещё три вещи:

1. **Установщик MSI** — обновление через `msiexec` вместо подмены своего exe (см.
   `chooseUpdateMethod` в `internal/service/updateapply_windows.go`): установку ведёт
   доверенный бинарь Microsoft, остановка и запуск службы объявлены декларативно, а
   неудачная установка откатывается сама.
2. **Метаданные версии** в самом бинаре (`cmd/socksit/versioninfo.json`) — безымянный PE
   без описания получает худший эвристический балл и показывает пустого издателя в
   диалогах Windows.
3. **Заявка на ложное срабатывание** в Kaspersky (и в MSRC для Defender/SmartScreen) —
   бесплатно и лечит именно поведенческий вердикт. Это единственное из перечисленного,
   что нельзя сделать кодом.
