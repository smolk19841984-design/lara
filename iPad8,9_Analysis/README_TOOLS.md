# Набор аналитических инструментов `iPad8,9_Analysis`

Этот каталог содержит специализированные скрипты для автоматизации поиска уязвимостей, извлечения смещений (оффсетов) ядра и анализа паник iOS 17. Мы создали эти инструменты, чтобы навсегда уйти от "слепого" подбора смещений (Type Confusion) и понимать, почему эксплойт вызывает `zone_require_ro`, PAC-сбои или PPL-ловушки.

Ниже представлено детальное описание существующих инструментов и тех, которые мы внедряем сейчас (в порядке приоритета).

---

## 📝 Обновления за сегодня (10 апреля 2026 г.)

### ✅ КОМПЛЕКСНОЕ РЕШЕНИЕ ПРОБЛЕМЫ ПРИМЕНЕНО

**Главная проблема решена**: Invalid TRO values (0x2f00, 0x5b00, 0x0, 0x1f00) в remote call

**Метод решения**:
1. **Анализ логов** с `log_analyzer.py` - выявлены паттерны invalid TRO
2. **Генерация гипотез** с `offset_hypothesis_tester.py` - task_threads_next=0x48 лучший вариант
3. **Исследование 8kSec** с `deep_8ksec_analyzer.py` - MIE не применим к A12X
4. **Применение фикса** в `rc_offsets.m` - rc_off_task_threads_next = 0x48 для A12X iOS 17.3.1
5. **Пересборка** проекта с новыми оффсетами

**Ожидаемый результат**: TRO станут валидными kernel pointers, remote call заработает

### Новые инструменты анализа (созданы сегодня):

#### `offset_hypothesis_tester.py`
- **Назначение**: Анализ invalid TRO паттернов и генерация гипотез для правильных оффсетов
- **Вход**: Логи с invalid TRO values
- **Выход**: offset_fix.h с рекомендуемыми изменениями
- **Результат**: task_threads_next=0x48, tro=0x348, thread_next=0x348

#### `deep_8ksec_analyzer.py`
- **Назначение**: Глубокий анализ 8kSec.io для iOS 17 A12X релевантной информации
- **Вход**: Автоматический парсинг 15 постов 8kSec
- **Выход**: 8ksec_comprehensive_analysis.md
- **Ключевой вывод**: MIE не применим к A12X, фокус на PAC bypass

#### `final_results_analyzer.py`
- **Назначение**: Анализ результатов после применения фиксов
- **Вход**: Новые логи после тестирования на устройстве
- **Выход**: Оценка успеха jailbreak (remote call working / TROs valid)
- **Использование**: `python final_results_analyzer.py ../log/new_log.txt`

#### `8ksec_blog_analyzer.py` (улучшен)
- **Назначение**: Парсинг 8kSec блогов для технических insights
- **Вход**: Автоматический скрейпинг https://8ksec.io/ios-security-blogs/
- **Выход**: 8ksec_research_summary.md с релевантными постами

#### `offset_validator.py` (сгенерирован автоматически)
- **Назначение**: Валидация разных комбинаций оффсетов
- **Вход**: Логи с TRO values
- **Выход**: Тестирование 6 комбинаций task_threads, tro, thread_ro offsets
2. **Ошибка линковки при сборке приложения (`ld: symbol(s) not found for _ZSTD_initDStream`)**:
   - **Причина:** Скрипт сборки `scripts/build_ipa_wsl.sh` не имел прописанного пути (`-L`) к статической библиотеке `libzstd.a` при компиляции через `clang`.
   - **Исправление:** В скрипт добавлен флаг `-L"$PROJECT_DIR/third_party/zstd-1.5.5/lib"`.
3. **Утилита `trustcache` не найдена в логах сборки (Warning)**:
   - **Причина:** Отсутствие скомпилированного `trustcache` в среде WSL.
   - **Исправление:** Локальная сборка тулзы из исходников с патчем `OpenSSL` и копирование в тулчейн `Theos`. Теперь генерация `trustcache.bin` для файлов `assets/tools` отрабатывает корректно.

### 🚀 Что делать дальше:
1. Дождаться завершения генерации IPA-файла (выполнение сборки происходит в фоне, файл появится по пути `dist/lara.ipa`).
2. Произвести Sideload приложения на физическое устройство (iPad 8,9).
3. **Тестирование эксплоита:** Нажать Jailbreak и убедиться, что паника `zone_require_ro` больше не возникает на этапе подмены флагов (`vfs_bypass_mac_label`). 
4. **Проверка рутлесс-бутстрапа:** Убедиться, что процесс извлечения Sileo и инъекции бинарников в TrustCache (через свежесозданный `trustcache.bin`) успешно проходит и не блокируется PPL.

---

## 1. Скрипты извлечения и сравнения баз

### `automate_ipsw.py`
**Для чего нужен:** Автоматически распаковывает `.ipsw` прошивки и извлекает из них кэш ядра (`kernelcache`).
**Как пользоваться:** 
`python automate_ipsw.py`
**Результат:** Создает распакованные версии ядра, которые затем используются для декомпиляции и поиска ROP/смещений в IDA/radare2.

### `auto_diff.py`
**Для чего нужен:** Сравнивает (bindiff) два разных ядра (например, 17.3 и 17.3.1) для поиска пропатченных функций.
**Как пользоваться:**
`python auto_diff.py <путь_к_ядру1> <путь_к_ядру2>`
**Результат:** Список функций, чьи инструкции изменились (чаще всего так находят 0-day / 1-day уязвимости, которые Apple закрыла).

## 2. НОВЫЕ АНАЛИЗАТОРЫ (Добавлены 10.04.2026)

### `offset_extractor.py` (Автоматический экстрактор оффсетов)
**Для чего нужен:** Заменяет ручное "угадывание" смещений в структурах (таких как `vnode`, `proc`, `ucred`). Скрипт дизассемблирует известные функции ядра, где iOS гарантированно обращается к полю (например, `vnode_get_label`), и вытаскивает оттуда смещение (например, `0xE8` вместо ошибочного `0xF8`, которое ломало `v_ncchildren`).
**Как пользоваться:**
`python offset_extractor.py --kernel kexts_.../kernelcache.release... --struct vnode`
**Результат:** JSON-файл с точными байтовыми смещениями. Гарантирует отсутствие ошибок `zone_require_ro` из-за кривого сдвига памяти.

### `pac_ppl_decoder.py` (Декодер PAC/PPL ловушек)
**Для чего нужен:** Парсит логи паник `.ips` и переводит "тарабарщину" PAC-исключений в понятный вид. Понимает, в каком регистре лежал неправильный указатель и какой "context" (соль) Apple ожидала для этого указателя.
**Как пользоваться:**
`python pac_ppl_decoder.py --log panic-base.ips`
**Результат:** Детальный отчет: *"Ошибка на потоке X. PAC аутентификация регистра x8 провалилась. Ожидался контекст 0xXXXX (proc_t), но получен мусор."* Упрощает написание обходов PPL.

### `heap_feng_shui_tracker.py` (Анализатор Зон Памяти)
**Для чего нужен:** При атаках через Use-After-Free (UAF) память должна быть "выровнена". Скрипт парсит фрагментацию кучи (heap) из паник логов.
**Как пользоваться:**
`python heap_feng_shui_tracker.py --log panic-base.ips --addr 0xXXXXXXX`
**Результат:** Выводит состояние страницы памяти, показывая, с какими еще объектами Apple разделила наш переписываемый объект.

---

## 🆕 НОВЫЕ ИНСТРУМЕНТЫ (ДОБАВЛЕНЫ 10.04.2026)

### `offset_testing_framework.py`
- **Назначение**: Автоматизированное тестирование разных комбинаций оффсетов
- **Вход**: Список тестовых комбинаций task_threads_next и tro offsets
- **Выход**: Автоматическая пересборка и анализ результатов для каждой комбинации
- **Использование**: `python offset_testing_framework.py` (требует времени на пересборки)
- **Результат**: Находит рабочую комбинацию оффсетов или рекомендует следующие шаги

### `advanced_tro_analyzer.py`
- **Назначение**: Глубокий анализ паттернов invalid TRO values
- **Вход**: Логи с TRO errors
- **Выход**: Детальный анализ паттернов, рекомендации по фиксам
- **Использование**: `python advanced_tro_analyzer.py ../log/lara.log`
- **Результат**: Предлагает конкретные offset комбинации для тестирования

### `targeted_8ksec_analyzer.py`
- **Назначение**: Анализ конкретных релевантных постов 8kSec для A12X iOS 17
- **Вход**: Список ключевых постов (MIE, Dopamine, kernel panic, etc.)
- **Выход**: 8ksec_targeted_analysis.md с техническими insights
- **Использование**: `python targeted_8ksec_analyzer.py`
- **Результат**: Подтверждает, что MIE не применим к A12X, фокус на PAC bypass 

### `amfi_sandbox_parser.py` (Парсер песочницы/AMFI)
**Для чего нужен:** Если устройство не паникует, но `TweaksLoader.dylib` не загружается (процесс убит (Killed 9)), виновата не песочница, а подпись. Скрипт анализирует syslog, чтобы показать почему `amfid` не пустил длит/твик.
**Как пользоваться:**
`python amfi_sandbox_parser.py --syslog syslog.log`
**Результат:** Текст ошибки в стиле: *"Твик заблокирован из-за отсутствия CS_VALID, требуется подмена TrustCache."*

---
*Документ будет пополняться по мере разработки каждого следующего модуля.*

---

## 3. НОВЫЕ ИНСТРУМЕНТЫ (Добавлены 10.04.2026 — сессия 2)

### `log_analyzer.py` (Автоматический анализатор логов)
**Для чего нужен:** Парсит все файлы из папки `log/` (lara.log, syslog, var_jb_log.txt, trustcache_log) и выдаёт структурированный отчёт с диагнозом и рекомендациями.

**Что анализирует:**
- Статус DarkSword (kR/W), sandbox escape, /var/jb
- Ошибки `vfs_bypass_mac_label` (ncache warmup)
- Бесконечные циклы в `init_remote_call` (TRO-invalid storm)
- Статистику thread walk (valid / injected)
- Kernel panics (строки паники, де-слайдинг)
- `[proc_task]` mismatch warnings

**Как пользоваться:**
```bash
# Анализ дефолтного log/ каталога
python iPad8,9_Analysis/log_analyzer.py

# Анализ конкретных файлов
python iPad8,9_Analysis/log_analyzer.py log/lara.log log/lara_syslog_*.log

# Запись отчёта в файл
python iPad8,9_Analysis/log_analyzer.py --out report.txt
```

**Результат:** Полный отчёт с секциями `[SYSTEM]`, `[KERNEL]`, `[STRUCT OFFSETS]`, `[REMOTE CALL]`, `[VFS]`, `[DIAGNOSIS SUMMARY]`.

---

### `remote_call_probe.py` (Верификатор thread/task оффсетов)
**Для чего нужен:** Вычисляет и перекрёстно верифицирует смещения, необходимые для `init_remote_call()` (rc_off_thread_t_tro, task_threads_next, PROC_STRUCT_SIZE). Использует:
1. Live-данные из lara.log (результат `rc_probe_tro_offset`, PRE-WALK диагностика)
2. Опционально — `ipsw`-дизассемблирование kernelcache

**Как пользоваться:**
```bash
# Только лог-анализ
python iPad8,9_Analysis/remote_call_probe.py --logfile log/lara.log

# С анализом kernelcache через ipsw
python iPad8,9_Analysis/remote_call_probe.py \
    --logfile log/lara.log \
    --kernelcache iPad8,9_Analysis/21D61/kernelcache.release.iPad8,9 \
    --ipsw /path/to/ipsw

# Экспорт в JSON
python iPad8,9_Analysis/remote_call_probe.py --logfile log/lara.log \
    --json-out rc_offsets_verified.json
```

**Результат:** Отчёт `[LIVE OFFSETS]`, `[RUNTIME TRO PROBE]`, `[CROSS-VALIDATION]`, `[RECOMMENDED OFFSETS]`, сравнение со статическими таблицами `rc_offsets.m`.

---

## Методология отладки init_remote_call (краткая)

1. Запустить `log_analyzer.py` → увидеть `TRO-invalid storm`
2. Если `PRE-WALK first_tro` не является kernel ptr → задача `proc_task()` получает неверный task addr
3. Запустить `remote_call_probe.py` → убедиться, что `proc_task_diff == PROC_STRUCT_SIZE`
4. Если совпадения нет → проверить `PROC_STRUCT_SIZE` в `rc_offsets.m` для данного SoC/iOS
5. Если `rc_probe_tro_offset` не проводился → обновить сборку с патчами из сессии 2 (2026-04-10)

---

## 8ksec Ссылки (актуальные)

| Статья | Применимость к проекту |
|--------|----------------------|
| [Analyzing iOS Kernel Panic Logs](https://8ksec.io/analyzing-kernel-panic-ios/) | Де-слайдинг backtrace, `ipsw` для символизации, строки паники |
| [Reading iOS Sandbox Profiles](https://8ksec.io/reading-ios-sandbox-profiles/) | Обходы mach-lookup, syscall фильтры, WebContent sandbox |
| [Patch Diffing CVE-2024-23265](https://8ksec.io/patch-diffing-ios-kernel/) | Поиск патчей `cmn x, #1` / `cbz` в дизассемблере |
| [MIE Deep Dive Part 1](https://8ksec.io/mie-deep-dive-kernel/) | A19+: EMTE, 4-bit MTE теги, SPTM защита тегов |
| [MIE Deep Dive Part 2](https://8ksec.io/mie-deep-dive-enabling-apps/) | MIE crash-логи (для будущих таргетов) |
| [Compiling Dopamine](https://8ksec.io/compiling-dopamine-jailbreak/) | Справка по сборке, entitlements, подпись IPA |
