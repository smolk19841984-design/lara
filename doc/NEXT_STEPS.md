# Next steps / техдолг

## 1) Привести документацию в соответствие реальности

Часть файлов в `docs/` и `docs/PROJECT_MAP.md` описывает старую структуру (например `jbdc/`), тогда как текущая WSL сборка компилирует root-sources и подключает `ChOma/XPF` отдельно.

Рекомендуется:

- `README.md` в корне обновлён (минимальный вход + ссылки на `doc/`).
- в `docs/PROJECT_MAP.md` отметить, что часть карты может быть устаревшей

## 2) Иконки

Сейчас в сборке:

- `scripts/generate_icon.py` отсутствует → `Иконка: SKIP`

Опции:

- добавить `scripts/generate_icon.py` (генерация `AppIcon*.png`)
- или положить готовые иконки в `lara/other/Assets.xcassets` (если появится этот каталог)

## 3) Stubs → реальные зависимости

В репо остаются **только** те stubs, которые нужны как “последний шанс” для линковки, если нет iOS static libs.
Для “рабочего” сценария iOS 17.3.1 **нужны реальные** статические либы в `third_party/build/ios/lib/*` (см. `third_party/README.md` и `scripts/bootstrap_third_party_ios_wsl.sh`).

**Состояние (актуально):**

- `libcurl` + OpenSSL: собираются в WSL, линкуются статически
- `libzstd`: real static (для in‑process `.zst`)
- `CommonCrypto` shim: SHA через OpenSSL `libcrypto`
- `stubs/*` **не должны** попадать в “релизную” сборку незаметно: используй `LARA_STRICT_THIRD_PARTY=1` (см. `scripts/build_ipa_wsl.sh`)

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

## 6) 21D61 — что осталось по “железным” доказательствам (после harness)

Сейчас канон собирается офлайн (`iPad8,9_Analysis/21D61/verified_offsets.json`), sandbox‑цели **Verified** по сигнатурам + секции, а вот “серые” цели всё ещё требуют второго независимого доказательства:

- **`cs_enforcement_disable`**: сейчас в основном string evidence → остаётся `Unverified` и runtime‑гейт по `LARA_ENABLE_AMFI_PATCH` (пока не появится xref/symbol/signature proof).
- **`pmap_image4_trust_caches`**: сейчас в основном range‑map evidence → хорошо как геометрия адреса, но слабо как семантика (нужна проверка контекста/уникальности).
- **`_kernproc` / `_rootvnode` / `proc` size**: пока это “static fallbacks” из runtime кода — нужно подтвердить через `symbols.json` + доп. проверки.

