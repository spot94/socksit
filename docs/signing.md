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

## Правила

- Всегда таймстамп (`/tr`) — подпись остаётся валидной после истечения сертификата
  (`build/sign.ps1` делает это всегда).
- SHA-256 (`/fd sha256 /td sha256`) — тоже уже в скрипте.
- Для self-contained сборки (`-tags "preset embed_engine"`): собрал `socksit-setup.exe` →
  подписал его (встроенный движок уже подписан вендором, отдельно не подписываем).
