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
- target: `arm64-apple-ios15.0`

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

