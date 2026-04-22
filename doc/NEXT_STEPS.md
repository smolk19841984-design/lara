# Next steps / техдолг

## 1) Привести документацию в соответствие реальности

Часть файлов в `docs/` и `docs/PROJECT_MAP.md` описывает старую структуру (например `jbdc/`), тогда как текущая WSL сборка компилирует root-sources и подключает `ChOma/XPF` отдельно.

Рекомендуется:

- обновить `README.md` в корне (сделать его главным входом)
- в `docs/PROJECT_MAP.md` отметить, что часть карты может быть устаревшей

## 2) Иконки

Сейчас в сборке:

- `scripts/generate_icon.py` отсутствует → `Иконка: SKIP`

Опции:

- добавить `scripts/generate_icon.py` (генерация `AppIcon*.png`)
- или положить готовые иконки в `lara/other/Assets.xcassets` (если появится этот каталог)

## 3) Stubs → реальные зависимости

Сейчас в проекте есть заглушки:

- `stubs/CommonCrypto/*` (SHA1/SHA384/…)
- `stubs/xpc/xpc.h` (декларации XPC)
- `stubs/zstd*`, `stubs/libgrabkernel2*` и т.п.

Если нужен реальный функционал (а не только линковка), нужно заменить stubs на реальные зависимости/SDK headers/линковку.

**Обновление (2026‑04‑22):**

- `libcurl` уже подключён как **реальный** (вариант B) и лежит в `third_party/build/ios/lib/libcurl.a` (с OpenSSL в `third_party/build/ios/openssl/`).
- Следующие “критичные” кандидаты на замену stub → real для iOS 17.3.1:
  - (уже сделано) `libzstd` → real (внутрипроцессная распаковка `.zst` через `ZSTD_*` теперь работает)
  - (уже сделано) `CommonCrypto` → real SHA через OpenSSL `libcrypto`
  - (уже сделано) `libgrabkernel2`: `grab_kernelcache()` качает через `libcurl` при заданном `LARA_KERNELCACHE_URL`

## 4) Assets cleanup

Сейчас в IPA могут попадать лишние исходники/каталоги внутри `assets/` (например исходники `libiosexec-1.3.1`).

Неплохо:

- сделать отдельный `assets_runtime/` (только то, что реально нужно на устройстве)
- а `assets/` оставить как “build inputs”

**Состояние (2026‑04‑22):** `assets/libiosexec-1.3.1/` больше не пакуется в IPA (убирается при упаковке), остаётся только `assets/tools/libiosexec.1.dylib`.

## 5) Проверка runtime

Сборка IPA проходит, но следующий шаг — проверить на устройстве:

- старт приложения
- доступность/исполнение `assets/tools/*`
- корректность bootstrap flow
- работа XPF (если используется для оффсетов/парсинга kernelcache)

