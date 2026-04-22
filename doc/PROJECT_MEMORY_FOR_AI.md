# PROJECT MEMORY FOR AI — Lara

Цель документа: дать другому ИИ/агенту полную картину проекта и текущего состояния сборки без контекста чата.

## 1) Коротко: что это за репозиторий

- Репозиторий собирает iOS-приложение `lara` и упаковывает его в `dist/lara.ipa`.
- Сборка делается **не через Xcode**, а через **WSL + Theos toolchain**.

## 2) Ключевые директории и файлы

- `scripts/build_ipa_wsl.sh`
  - Главный build-пайплайн IPA.
  - Делает `build/wsl/Payload/lara.app`, подписывает `ldid`, пакует `dist/lara.ipa`.
- `lara/Info.plist`
  - Базовый шаблон `Info.plist` для `.app` (копируется в bundle).
- `assets/`
  - Developer-provided payload (bootstrap/tools).
  - Скрипт нормализует layout (см. `prepare_root_assets_layout()`).
- `third_party/build/ios/`
  - Build-артефакты библиотек для линковки:
    - `lib/` (`libxpf.a`, `libchoma.a`, `libgrabkernel2.a`, `libzstd.a`, `libcurl.a`, `libcommoncrypto.a`)
    - `include/` (headers: `xpf.h`, `choma/*`, а также stub headers)
- `XPF/`, `ChOma/`
  - Реальные исходники XPF/ChOma.
  - Встроены в сборку через `scripts/build_ipa_wsl.sh` (статически).
- `stubs/`
  - Заглушки для сборки без некоторых SDK headers / зависимостей.
  - Важные:
    - `stubs/xpc/xpc.h` — расширен минимальными декларациями XPC dictionary API.
    - `stubs/CommonCrypto/*` — stub для SHA1/SHA256/SHA384 (нужен для сборки ChOma).
    - `stubs/zstd.h`, `stubs/zstd_stub.c`, `stubs/curl/*`, `stubs/xpf_stub.c` и т.д.
  - В идеале stubs должны уходить по мере подключения “настоящих” зависимостей.

## 3) Текущее состояние: сборка работает

На текущем этапе скрипт собирает `dist/lara.ipa` в строгом режиме:

- `LARA_REQUIRE_BUNDLED_ASSETS=1`

Состояние на **2026‑04‑22**:

- IPA собирается: `dist/lara.ipa` (≈38 MB)
- `XPF/ChOma` собираются “реальными” (static) в `third_party/build/ios/lib/`
- `libcurl` теперь **реальный** (static) и больше не является `curl_stub.o`
- Для `libcurl` используется **статический OpenSSL**, собранный под iOS arm64 и установленный в `third_party/build/ios/openssl/`

и внутри IPA присутствуют:

- `Payload/lara.app/assets/bootstrap-iphoneos-arm64.tar.zst`
- `Payload/lara.app/assets/bootstrap-ssh-iphoneos-arm64.tar.zst` (compat copy)
- `Payload/lara.app/assets/tools/tar`
- `Payload/lara.app/assets/tools/libiosexec.1.dylib`
- `Payload/lara.app/assets/tools/libintl.8.dylib`
- `Payload/lara.app/assets/tools/create_var_jb_helper` (если исходник существует)

## 4) Важные build-флаги и зависимости

### Theos/WSL пути

В `scripts/build_ipa_wsl.sh`:

- `THEOS_TC=/opt/theos/toolchain/linux/iphone`
- `SDK=/opt/theos/sdks/iPhoneOS16.5.sdk`
- target: `arm64-apple-ios15.0` (переменная `MIN_IOS="15.0"`)

Важно: третьи библиотеки могут быть собраны с меньшим `-target` (например iOS 14.0) — это допустимо, если бинарники совместимы по минимальной версии.

### XPF требует libcompression

Реальный XPF вызывает `compression_decode_buffer`, поэтому приложение при линковке добавляет:

- `-lcompression`

### XPF использует blocks

`XPF/src/*.c` использует block-колбэки (`^(...) {}`), поэтому компиляция `XPF` идёт с:

- `-fblocks`

## 5) Assets: как устроено

Скрипт копирует ассеты в app bundle в `sync_bundle_assets()`.

Сейчас он предпочитает:

- `PROJECT_DIR/assets/` (корень репозитория)

и только если там нет — берёт `lara/assets/` (app template).

Функция `prepare_root_assets_layout()` нормализует:

- копирует `assets/tar` → `assets/tools/tar` (если нужно)
- копирует `assets/bootstrap-iphoneos-arm64.tar.zst` → `assets/bootstrap-ssh-iphoneos-arm64.tar.zst` (compat)
- копирует `libintl.8.dylib` из корня репо в `assets/tools/libintl.8.dylib` (если присутствует)
- при необходимости может собирать `libiosexec.1.dylib` из исходников `assets/libiosexec-1.3.1/`

## 6) Что было исправлено/адаптировано в ходе работ

Важно для будущего агента:

- `scripts/build_ipa_wsl.sh` был существенно расширен:
  - support для реального `XPF/ChOma` (сборка `libxpf.a/libchoma.a`)
  - stub-линковка “missing only” (не перетирает реальный `libxpf`)
  - исключение компиляции мусорных деревьев (`tools/`, `ChOma/`, `XPF/`, `iPad8,9_Analysis/`, `rootless/`)
  - строгий режим ассетов через `LARA_REQUIRE_BUNDLED_ASSETS`
- `XPF/src/xpf.c` дополнили include’ами для `mmap/munmap` и файловых операций.
- `stubs/xpc/xpc.h` расширен декларациями:
  - `xpc_dictionary_create_empty`
  - `xpc_dictionary_set_uint64`
  - `xpc_release`
- `stubs/CommonCrypto/CommonDigest.h` расширен SHA1/SHA256/SHA384.
- **Реальный `libcurl` (вариант B)**:
  - `third_party/src/openssl` + `third_party/src/curl` добавлены как build inputs
  - OpenSSL собран статически под iOS arm64 и установлен в `third_party/build/ios/openssl`
  - `curl` собран статически под iOS arm64 с `--with-openssl=...` и установлен в `third_party/build/ios/lib/libcurl.a`

## 7) Как собирать IPA (коротко)

См. `doc/BUILD_IPA.md`.

## 8) Типовые проблемы (и решения)

- **`ldid: Unknown header magic`**:
  - почти всегда означает, что в `assets/tools/` лежит не Mach-O (например текстовая заглушка).
  - решение: заменить на реальный arm64 dylib/exec или убрать попытку подписи.
- **линковка XPF**:
  - если ошибка по `compression_decode_buffer` — добавить `-lcompression`.
- **подвисшие проверки в WSL**:
  - при вызове из PowerShell избегать `$VAR` внутри `bash -lc "..."` (PowerShell съедает `$...`).
  - использовать одинарные кавычки или фиксированные пути.

## 9) Что ещё “не хватает” для iOS 17.3.1 (важно)

Это список именно runtime‑рисков/дырок под **iOS 17.3.1**, даже если IPA “собирается”:

- **Offsets / PatchFinder**:
  - Проект содержит места, где логика завязана на iOS 17.3.1 (паттерны/оффсеты/гейты).
  - Нужно подтвердить, что для целевого устройства (например iPad8,9 / build 21D61) реальные адреса/патчи совпадают и не остались “примерными”.
- **Оставшиеся stubs (runtime не будет работать полноценно)**:
  - `libzstd` пока stub → распаковка `.tar.zst` bootstrap на устройстве может не работать.
  - `CommonCrypto` раньше был stub → теперь реализован через OpenSSL `libcrypto` (SHA1/SHA256/SHA384).
  - `libgrabkernel2` раньше был stub → теперь `grab_kernelcache()` реализован через `libcurl` (URL задаётся через `LARA_KERNELCACHE_URL`).
- **SDK 16.5 vs iOS 17.3.1**:
  - Сборка идёт на `/opt/theos/sdks/iPhoneOS16.5.sdk`. Это нормально для компиляции, но не гарантирует правильность runtime‑поведения на 17.3.1 (особенно для приватных API/энтропии оффсетов).
- **Assets в IPA**:
  - Теперь `assets/libiosexec-1.3.1/` не пакуется в IPA (build‑input), но нужно следить, чтобы `assets/tools/libiosexec.1.dylib` и `assets/tools/tar` действительно выполнялись на устройстве.

