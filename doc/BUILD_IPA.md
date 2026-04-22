# Сборка IPA (Windows + WSL + Theos)

## Что собираем

Скрипт `scripts/build_ipa_wsl.sh` собирает `dist/lara.ipa` **внутри WSL**, используя Theos toolchain и iOS SDK из `/opt/theos`.

На текущем этапе проект собирается **без Xcode**.

## Требования

### WSL

- WSL2 установлен
- Дистрибутив: `Ubuntu` (или другой Linux, но пути в командах ниже — под Ubuntu)

### Theos toolchain внутри WSL

Скрипт ожидает:

- `/opt/theos/toolchain/linux/iphone/bin/clang`
- `/opt/theos/toolchain/linux/iphone/bin/ldid`
- `/opt/theos/sdks/iPhoneOS16.5.sdk` (если нет — скрипт пытается найти последний `iPhoneOS*.sdk`)

## Entitlements

Скрипт подписывает бинарники через `ldid`.

По умолчанию он берёт entitlements из:

- `Config/lara.entitlements`

или из переменной окружения:

- `LARA_LDID_ENTITLEMENTS`

## Assets (bootstrap/tools)

Скрипт копирует ассеты в app bundle в `Payload/lara.app/assets`.

Обязательные пути в bundle (при `LARA_REQUIRE_BUNDLED_ASSETS=1`):

- `assets/bootstrap-ssh-iphoneos-arm64.tar.zst`
- `assets/tools/tar`
- `assets/tools/libiosexec.1.dylib`
- `assets/tools/libintl.8.dylib`

Нормализация ассетов делается функцией `prepare_root_assets_layout()` в `scripts/build_ipa_wsl.sh`.

Рекомендуемый layout исходников в репо:

- `assets/bootstrap-iphoneos-arm64.tar.zst` (скрипт сделает копию под `bootstrap-ssh-...`)
- `assets/tools/tar`
- `assets/tools/libiosexec.1.dylib`
- `assets/tools/libintl.8.dylib`

Также допускается `libintl.8.dylib` в корне репозитория: `libintl.8.dylib` — скрипт подхватит и скопирует в `assets/tools`.

## Third-party (XPF/ChOma)

Чтобы XPF реально работал (а не stub), в репозитории присутствуют папки:

- `XPF/`
- `ChOma/`

Скрипт `scripts/build_ipa_wsl.sh` собирает их в статические либы:

- `third_party/build/ios/lib/libxpf.a`
- `third_party/build/ios/lib/libchoma.a`

и кладёт заголовки в:

- `third_party/build/ios/include/xpf.h`
- `third_party/build/ios/include/choma/*`

## Команда сборки

Из PowerShell (в корне репозитория):

```powershell
wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/smolk/Documents/GitHub/lara && LARA_REQUIRE_BUNDLED_ASSETS=1 bash scripts/build_ipa_wsl.sh"
```

Результат:

- `dist/lara.ipa`

## Где смотреть логи

- `build/wsl/build.log` — stdout/stderr компиляции/линковки (создаётся скриптом).

