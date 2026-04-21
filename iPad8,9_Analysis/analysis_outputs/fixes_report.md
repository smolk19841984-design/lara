# Fixes Report — детальный анализ ошибок (авто)

Ниже — автоматический краткий разбор ключевых ошибок, найденных в `log/lara.log` и `analysis_outputs/logs_summary.json`.

1) SKIP invalid tro: not a valid kernel pointer

  Примеры из логов:
  - "[init_remote_call:597] SKIP invalid tro: 0x0 (not a valid kernel pointer)"
  - Повторяется многократно — указывает на попытки использовать некорректные/несовпадающие указатели в runtime.

  Рекомендация: проверить соответствие runtime offsets (kernel_base/kernel_slide) и сопоставить их с `iPad8,9_Analysis/ОФФСЕТЫ.md`.

2) init_remote_call / exceptions

  Примеры:
  - "[init_remote_call:643] Valid threads: 0, Injected: 0"
  - "[init_remote_call:646] No exceptions injected. Aborting."
  - "[do_remote_call_stable:238] wait_exception (stable) failed for 'pthread_exit'"

  Рекомендация: сбор дополнительных runtime-артефактов (полный syslog) и сверка вызовов с тестовым устройством.

3) posix_spawn / helper execution

  Примеры:
  - "[var/jb TrustCache] Found helper in bundle: .../lara.app/assets/tools/create_var_jb_helper"
  - "[var/jb TrustCache] Launching helper: /var/tmp/create_var_jb_helper"
  - "[var/jb TrustCache] posix_spawn failed: 1 (Operation not permitted)"

  Что проверено автоматически:
  - IPA собран: `dist/lara.ipa` (размер ~25M).
  - `scripts/build_ipa_wsl.sh` в процессе сборки выполняет `chmod +x` и `ldid -S` для бандл-бинарников.
  - TrustCache: в сборке обнаружена попытка генерации `assets/trustcache.bin` (если утилита доступна).

  Рекомендация: убедиться, что на целевом устройстве есть соответствующая TrustCache/ldid конфигурация; выполнять запуск helper-ов только в изолированной тестовой среде.

4) Оффсеты

  Авто-вывод `analysis_outputs/offsets_report.json`:
  - `kernel_base`: 0xfffffff0246f4000
  - `kernel_slide`: 0x1d6f0000

  Рекомендация: сравнить эти значения с базой оффсетов и при необходимости пересобрать конфиги/rc_offsets.

---

Следующие автоматические шаги, которые я выполню дальше (без дополнительных вопросов):
- Сформирую таблицу несовпадений оффсетов и отмечу файлы, у которых нужно обновить значения.
- Сгенерирую чек-лист изолированного тестирования (backups, test device, fastSign/TrustCache проверки).

Файлы с результатами и отчётами:
- [iPad8,9_Analysis/analysis_outputs/logs_summary.json](iPad8,9_Analysis/analysis_outputs/logs_summary.json)
- [iPad8,9_Analysis/analysis_outputs/kernel_analysis.json](iPad8,9_Analysis/analysis_outputs/kernel_analysis.json)
- [iPad8,9_Analysis/analysis_outputs/offsets_report.json](iPad8,9_Analysis/analysis_outputs/offsets_report.json)
- [dist/lara.ipa](dist/lara.ipa)
- [iPad8,9_Analysis/analysis_outputs/fixes_suggestions.md](iPad8,9_Analysis/analysis_outputs/fixes_suggestions.md)
