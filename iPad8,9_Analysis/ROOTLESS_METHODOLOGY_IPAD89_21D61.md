# Методика полноценного rootless jailbreak — iPad8,9, iOS 17.3.1 (21D61)

**Версия документа:** 2026-04-12  
**Область:** одно устройство (`hw.machine` = `iPad8,9`), сборка ядра **21D61**, продукт **17.3.x**.  
**Статус методики:** готова к **офлайн-подготовке** и к **полевому тесту** на устройстве (раздел 9).

Этот файл **связывает** в одну процедуру:

- цепочку в коде (`jbdc/`: DarkSword → SBX → VFS → `/var/jb` → bootstrap);
- анализ песочницы в `Sandbox_Profiles/` (векторы, entitlements, отчёты);
- рекомендации по оффсетам/remote-call в `РЕКОМЕНДАЦИИ.md` и логам.

---

## 1. Определения: что считать «полноценным rootless»

| Критерий | Проверка |
|----------|----------|
| **Префикс jailbreak** | Существует доступный для записи корень rootless, принято **`/var/jb`** (симлинк или каталог под `/private/var`). |
| **Sandbox не блокирует пост-эксплуатацию** | После kernel R/W выполнены этапы SBX (strong: запись под `/var/tmp`), при необходимости PPL-запись слотов cred/label/sandbox (см. код). |
| **Пакетный менеджер** | `apt-get` / установка `.deb` из префикса или эквивалент (Sileo) после распаковки bootstrap. |
| **Без «полного rootful»** | Нет обязательного RW на весь `/`; только согласованный префикс и доверенные пути (rootless-модель). |

Если выполнены строки таблицы — методика для устройства считается **доказанной на устройстве**. До этого — только **офлайн-готовность** (сборка, ассеты, логирование).

---

## 2. Офлайн-подготовка (без устройства)

1. **Сборка IPA** из дерева `jbdc/` (актуальный путь: `scripts/build_ipa_wsl.sh` → `dist/lara.ipa`).  
2. **Bootstrap offline:** в бандле должен быть архив вроде `assets/bootstrap-ssh-iphoneos-arm64.tar.zst` (как в проекте); сеть — запасной путь.  
3. **Логирование:** включить экспорт `log/lara.log`, при панике — `.ips` из Analytics (как в `doc/AI_PANIC_DEBUGGING_GUIDE.md` / практике проекта).  
4. **Профиль устройства в приложении:** при старте применяется профиль под iPad8,9 + iOS 17.3.x (`LaraTargetProfile` в `jbdc/`): remote-call SBX выключен, не форсируется сокетный kwrite в sandbox object (ожидается PPL-трансплант при доступном MMIO).  
5. **Перечитать песочницу (аналитика, не подпись):**  
   - `Sandbox_Profiles/bypass_vectors_report.txt` — уровни обхода (TIER 1–2), операции `file-*`, `sandbox_extension_issue*`.  
   - `Sandbox_Profiles/entitlement_bypass_guide.txt` — связка entitlements ↔ векторы; **важно:** entitlements уровня *platform binary* **не** заменяют kernel-обход; они описывают *что* система умеет различать в политике.  
   - `Sandbox_Profiles/sandbox_analysis_summary.txt` — справочно по извлечённым строкам правил из kext-анализа.

---

## 3. Методика ядра (порядок не менять)

Цель — стабильный **kernel read/write** и валидные указатели для обходов ниже.

| Шаг | Компонент | Критерий успеха (по логам) |
|-----|-----------|----------------------------|
| 3.1 | **DarkSword** (`ds_run` / `darksword.m`) | `[PE] kernel r/w is ready!`, `kernel_base` / `kernel_slide` разумны. |
| 3.2 | **Оффсеты task/thread** (`rc_offsets.m`, `RemoteCall.m`) | Для post-exploit, если используется remote path: TRO как kernel pointers, не малые числа `0x2f00` — см. `РЕКОМЕНДАЦИИ.md`. |
| 3.3 | **Указатели** | PAC/`XPACI`, отсев `-1` / `0xffffffffffffffff` при обходе структур (`doc/KERNEL_POINTER_VALIDATION_iOS17.md`). |

**На 21D61 + arm64e:** ветка A18 (`iPhone17,`) **не** используется на iPad8,9 — остаётся путь `pe_v1()` (см. `darksword.m`).

---

## 4. Методика sandbox (связка с `Sandbox_Profiles`)

Политика приложения задаётся **профилем + extension_set + ucred/label**. Анализ в `Sandbox_Profiles/` классифицирует **типы** разрешений (например `file-write*`, `file-issue-extension`, исключения путей). В LARA это отражается так:

| Задача | Реализация в проекте | Замечание по политике |
|--------|----------------------|------------------------|
| Сильный выход (не только `/var/mobile`) | `sbx_verify_strong_escape` → `/var/tmp` | Соответствует тестам записи во «временные» пути из практики rootless. |
| Обход без разрушения политики | `sbx_escape_ex` / `sbx_escape_root_first`, `sbx_bypass_sandbox` | Трансплант donor sandbox — см. логи `[sbx_bypass]`; на iOS 17 arm64e запись в объект sandbox через сокет **не** приоритетна — PPL (`ppl.m`), если MMIO доступен. |
| Расширения | `sbx_ext.m`, `borrow_ext`, токены libsandbox | Согласуется с операциями `file-issue-extension` / Mach из отчётов. |
| Remote thread injection | `sbx_escape_via_remote_call` | **По умолчанию отключён** на iOS 17 arm64e (риск паник) — см. env в профиле запуска. |

**Важно:** файлы `bypass_entitlements_*.plist` в `Sandbox_Profiles/` — **справочные** сценарии для понимания классов entitlements; подпись приложения ими **не** заменяет цепочку ядра. Рабочий rootless строится на **kernel R/W + реальные изменения cred/sandbox/extension**, а не на подстановке plist без эксплойта.

---

## 5. VFS и `/var/jb`

| Шаг | Действие | Источник правды в репо |
|-----|----------|-------------------------|
| 5.1 | Инициализация VFS после SBX | `vfs.m`, порядок в `LaraManager` / Exploit UI. |
| 5.2 | Создание `/var/jb` | Несколько стратегий (chown, preboot, mkdir) — логи `var_jb_*.txt`. |
| 5.3 | Паники APFS inode | Уже учтены ограничения сканирования inode в `vfs.m` (см. историю паник в MEMORY/8KSEC отчётах). |

---

## 6. Bootstrap и менеджер пакетов (rootless)

1. После появления записываемого префикса `/var/jb` — распаковка bundled `tar.zst` (in-process libarchive или fallback).  
2. Preflight: наличие каталога, запись пробы, доступ к `apt`/`dpkg` по дизайну Sileo installer в `jbdc/views/`.  
3. Ошибки `apt-get not found` трактовать как **отсутствие распакованного bootstrap**, а не как «неуспех эксплойта», пока kernel/SBX не подтверждены логами.

---

## 7. Офлайн-проверки без железа (чеклист)

- [ ] IPA собирается, в бандле есть bootstrap-ассет (если задумано офлайн-first).  
- [ ] В логах симуляции/ревью кода: порядок DarkSword → SBX → VFS согласован с `MEMORY.md`.  
- [ ] Прочитаны `bypass_vectors_report.txt` и `entitlement_bypass_guide.txt` — понятно, **какие** операции sandbox различает (для интерпретации логов `sandbox` / `kernel`).  
- [ ] Готов экспорт логов с устройства после теста.

---

## 8. Матрица «симптом → куда смотреть»

| Симптом | Документ / место |
|---------|------------------|
| Паника `copy_validate` / `kaddr not in kernel` | `KERNEL_POINTER_VALIDATION_iOS17.md`, remote-call gate, указатели TRO. |
| Паника `pmap_enter` / illegal VA | Запись в sandbox object сокетным kwrite — PPL-путь, `sbx_bypass.m` / логи PPL. |
| Паника зона APFS inode | `vfs.m`, отчёты по inode в MEMORY. |
| Нет `/var/jb` | VFS стратегии, `var_jb` логи. |
| Bootstrap не стартует | Sileo installer preflight, bundled bash/tar, `doc/документы памяти` по bootstrap. |

---

## 9. Когда методика «разработана» и что делать на устройстве

**Методика разработана** в том смысле, что документ задаёт **единый порядок действий и критерии успеха** для iPad8,9 / 21D61, опираясь на ваши же артефакты в `iPad8,9_Analysis`.

**Нужно обязательно протестировать на устройстве:**

1. Установить свежий `dist/lara.ipa`.  
2. Выполнить полную цепочку из UI (Exploit → Sandbox escape → при необходимости Tools / установка).  
3. Сохранить: `log/lara.log`, фрагменты syslog, `var_jb_*.txt`, при сбое — `.ips`.  
4. Сверить с разделами **3–6** этого файла (ядро → sandbox strong → VFS → bootstrap).

Без шага **9** методика остаётся **проектной**; подтверждение rootless возможно только по логам и фактическому `apt`/префиксу на девайсе.

---

## 10. Ссылки на файлы в репозитории

| Назначение | Путь |
|------------|------|
| Векторы и отчёт sandbox | `iPad8,9_Analysis/Sandbox_Profiles/bypass_vectors_report.txt` |
| Entitlements (справочно) | `iPad8,9_Analysis/Sandbox_Profiles/entitlement_bypass_guide.txt`, `bypass_entitlements_*.plist` |
| Рекомендации по оффсетам / remote | `iPad8,9_Analysis/РЕКОМЕНДАЦИИ.md` |
| Сводка по kernelcache T8020 | `iPad8,9_Analysis/kernel_analysis/KERNEL_ANALYSIS_SUMMARY.md` |
| Память проекта | `MEMORY.md` |

---

*Конец методики. Дальнейшие правки — только по результатам полевых логов с iPad8,9 / 21D61.*
