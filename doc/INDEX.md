# Lara — документация (индекс)

Эта папка содержит “собранную” документацию и память проекта для ИИ, чтобы другой агент мог быстро продолжить работу без контекста чата.

## Главное

- `PROJECT_MEMORY_FOR_AI.md` — **основной документ**: структура репо, что сделано, где что лежит, как собирается IPA, известные грабли.
- `BUILD_IPA.md` — пошаговая **инструкция сборки IPA** (Windows + WSL + Theos).
- `NEXT_STEPS.md` — список **следующих шагов** и техдолга.

## Актуальные изменения (2026‑04‑22)

- `libcurl` подключён как **реальный** (вариант B) и больше не является stub.
- Для `libcurl` используется статический OpenSSL (`third_party/build/ios/openssl/`).
- Упаковка IPA очищена от build‑inputs: `assets/libiosexec-1.3.1/` больше не попадает в `Payload/`.
- Оффсеты 21D61: добавлены офлайн harness + автоген header + зеркальная папка `offset/`; полный прогон одной командой: `scripts/rebuild_21D61_wsl.sh`.
- Детали/доказательства/ТЗ: `doc/OFFSETS_21D61_EVIDENCE.md`, `doc/ANALYSIS_21D61_REPORT.md`, `doc/AI_TASK_OFFSETS_21D61.md`.

## Исходные документы в репозитории (источники)

Эти файлы уже существуют в проекте и содержат исходные заметки/аналитику:

- `scripts/build_ipa_wsl.sh` — фактический build-пайплайн IPA.
- `docs/PROJECT_MAP.md` — карта проекта (может быть частично устаревшей).
- `docs/COMPLETION_STATUS.md` — статус/заметки (может быть частично устаревшей).
- `docs/IMPLEMENTATION_SUMMARY.md`
- `docs/PANIC_PROTECTION.md`
- `IMPLEMENTATION_REPORT.md`
- `iPad8,9_Analysis/analysis_outputs/*` — результаты анализа/отчёты.
- `tools/README_create_var_jb_helper.md` — заметки по helper’у (внутри есть команды под Xcode, которые в нашем WSL пайплайне заменены).

