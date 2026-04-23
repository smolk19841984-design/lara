## AI TASK (one doc): iPad8,9 iOS 17.3.1 (21D61) — офлайн‑валидация оффсетов и очистка проекта

### Цель

Сделать **один каноничный** набор адресов/оффсетов для iPad8,9 iOS 17.3.1 (build **21D61**), подтверждённый офлайн на дампах из `iPad8,9_Analysis/21D61`, и привести проект к состоянию:

- нет “двух правд” (несколько разных `KERNEL_BASE`, разные таблицы оффсетов)
- невалидные кандидаты **не используются**
- спорные цели помечены `Unverified` и не активируются без доказательств
- есть автоматическая генерация артефактов (`verified_offsets.json` → `kexploit/final_kernel_offsets.h`) и отчёт доказательств.

---

## 1) Входы (source of truth)

Использовать только офлайн‑данные из репозитория.

### Kernelcache (decompressed)

- `iPad8,9_Analysis/21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed`

### Kexts (decompressed)

- `iPad8,9_Analysis/21D61/kernelcache_decompressed/kexts/*`
- AMFI kext:
  - `iPad8,9_Analysis/21D61/kernelcache_decompressed/kexts/com.apple.driver.AppleMobileFileIntegrity`
- Sandbox kext (отдельно лежит в Sandbox_Profiles):
  - `iPad8,9_Analysis/Sandbox_Profiles/com.apple.security.sandbox.kext`

### Symbols

- `iPad8,9_Analysis/21D61/symbols/kernelcache.release.iPad8,9_10_11_12.symbols.json`

### Уже имеющиеся скрипты/прогоны (использовать как базу)

- `iPad8,9_Analysis/Sandbox_Profiles/*.py`
- результаты прогона:
  - `iPad8,9_Analysis/Sandbox_Profiles/sandbox_validation_results.json`
  - `iPad8,9_Analysis/analysis_outputs/*`
  - отчёт: `doc/ANALYSIS_21D61_REPORT.md`

WSL зависимости:

- `python3-capstone` (через `apt-get install python3-capstone`)

---

## 1.1) Обязательная “имитация iOS 17.3.1” офлайн (Python kernel-map harness)

Требование: **не доверять готовым JSON как источнику правды**. Любые “кандидаты/адреса” считаются лишь гипотезами,
пока не пройдут офлайн‑валидацию на дампах.

Нужно написать Python‑скрипт (один вход, один выход), который **эмулирует** ключевую часть поведения kread‑мира:

- загружает Mach‑O (kernelcache или kext)
- строит карту **VM ↔ fileoff** по сегментам/секциям
- предоставляет API:
  - `vm_read(vmaddr, size)` → bytes (как “kread” по дампу)
  - `vm_find(signature_bytes)` → список vmaddr/fileoff совпадений (по заданной области)
  - `vm_is_in_section(vmaddr, seg, sect)` → bool
- валидирует кандидаты: “по этому vmaddr байты совпадают с сигнатурой” + “адрес в ожидаемой секции”

Артефакт:

- `scripts/offline_ios17_kernelmap.py` (или аналог)
- он должен уметь принимать пути к:
  - kernelcache Mach‑O
  - одному или нескольким kext Mach‑O
  - symbols.json (опционально)
  - входной список целей (targets_needed)
  - и писать `iPad8,9_Analysis/21D61/verified_offsets.json`

Важно: это **статическая имитация** (без выполнения кода). Цель — “валидность адреса/оффсета/кандидата” через чтение байт и
структурные проверки (секции/диапазоны/уникальность), а не реальное выполнение iOS.

---

## 2) Что проект реально требует (targets_needed)

Это **минимальный список целей**, которые используются текущим runtime‑кодом.
Их нужно включить в каноничный `verified_offsets.json`.

### P0 (обязательно)

#### 2.1 Kernel base

- `kernel_base` (канонично один)

#### 2.2 Sandbox patches (используются в `kexploit/sandbox_patches.m`)

Источник требований: `kexploit/sandbox_patches.m` + `kexploit/final_kernel_offsets.h`.

- `sandbox_check` (`KOFFSET_SANDBOX_CHECK`, `KADDR_SANDBOX_CHECK`)
- `mac_label_update` (`KOFFSET_MAC_LABEL_UPDATE`, `KADDR_MAC_LABEL_UPDATE`)
- `sandbox_extension_create_or_consume` (`KOFFSET_SANDBOX_EXTENSION_CREATE`, `KADDR_SANDBOX_EXTENSION_CREATE`)
- `cs_enforcement_disable` (`KOFFSET_CS_ENFORCEMENT_DISABLE`, `KADDR_CS_ENFORCEMENT_DISABLE`)
  - **Примечание (repo state)**: AMFI‑патч сейчас **не применяется по умолчанию** (гейтинг через `LARA_ENABLE_AMFI_PATCH=1`),
    а `KOFFSET_CS_ENFORCEMENT_DISABLE`/`KADDR_CS_ENFORCEMENT_DISABLE` выставлены в `0` до офлайн‑верификации.

#### 2.3 TrustCache injection (используется в `kexploit/trustcache.m`)

- `pmap_image4_trust_caches` (`KOFFSET_PMAP_IMAGE4_TRUST_CACHES`, `KADDR_PMAP_IMAGE4_TRUST_CACHES`)

#### 2.4 Kernel symbol/struct resolution (используется в `kexploit/offsets.m`, `kexploit/vfs.m`)

Эти цели могут быть “symbol/offset”, но должны быть валидируемы по дампу:

- `_kernproc` (или `kernelSymbol.kernproc`)
- `_allproc` (fallback)
- `_rootvnode` (или `kernelSymbol.rootvnode`)
- `kernelStruct.proc.struct_size` (proc struct size)

Также поддерживаются ENV overrides (важно для диагностик):

- `DS_STATIC_KERNPROC_OFFSET`
- `DS_STATIC_ROOTVNODE_OFFSET`
- `DS_STATIC_PROCSIZE`

### P1 (желательно)

- `PE_i_can_has_debugger` (если патч/использование присутствует в runtime‑пути)

---

## 3) Правила валидации (что считать “валидным” офлайн)

Каждая цель в `verified_offsets.json` должна иметь:

- `addr_abs` (VM address)
- `offset_from_kernel_base`
- `source_file` (kernelcache или конкретный kext)
- `segment.section` + `fileoff` (если применимо)
- `status`: `Verified` / `Unverified` / `Rejected`
- `evidence[]`: список доказательств

### 3.1 Evidence types

- **Signature match**: сравнение 32+ байт через `vm_read()` (см. harness) в конкретном Mach‑O.
- **Symbol evidence**: из `symbols.json` (имя → адрес), плюс проверка диапазона/секции через harness.
- **XREF evidence**: ADRP+ADD/LDR или literal pointer + backtrack до prologue + signature (можно реализовать отдельным модулем).
- **String evidence**: допустимо как подсказка, но **не может быть единственным** доказательством для `Verified`.

### 3.2 Status rules

- `Verified`: есть signature OR symbol OR xref (и адрес “в разумном диапазоне”).
- `Unverified`: только string/эвристика, или xref не подтверждён.
- `Rejected`: сигнатура не совпала на дампе / конфликтные данные.

---

## 4) Известные проблемы в текущем репо (что нужно устранить)

### 4.1 Невалидные кандидаты sandbox

По `Sandbox_Profiles/sandbox_validation_results.json`:

- candidate **7**: `match=false` → `Rejected`
- candidate **8**: `match=false` → `Rejected`

Требование:

- кандидаты 7/8 не должны использоваться для маппинга “важных” целей
- при генерации таблиц/хедеров они должны быть исключены или явно marked Rejected

### 4.2 `cs_enforcement_disable` не подтверждён ADRP+XREF

Факты:

- `find_cs_enforcement.py` находит строки `cs_enforcement_disable` в AMFI `__TEXT.__cstring` (string evidence)
- `find_cs_xrefs_adrp.py` пишет: “No ADRP+ADD/LDR XREFs … found” (xref evidence отсутствует)

Требование:

- `cs_enforcement_disable` не может быть `Verified` без второго доказательства
- до валидации — статус `Unverified` и runtime‑патч должен быть gated/disabled

### 4.3 Несколько conflicting headers / разные KERNEL_BASE

В репо есть несколько файлов, где фигурируют разные `KERNEL_BASE`/оффсеты:

- `kexploit/final_kernel_offsets.h`
- `jbdc/patcher/final_kernel_offsets.h`
- `offsets_final_iPad8_9_17.3.1.h`
- плюс анализ‑хедеры в `iPad8,9_Analysis/Sandbox_Profiles/*`

Требование:

- должен быть **один** runtime‑header для приложения (предпочтительно `kexploit/final_kernel_offsets.h`)
- все остальные либо:
  - генерируются из одного `verified_offsets.json`, либо
  - перестают использоваться в runtime‑пути/сборке

---

## 5) Что сделать (пошагово)

### Step A — собрать каноничный `verified_offsets.json`

Сгенерировать `iPad8,9_Analysis/21D61/verified_offsets.json`:

- `meta`: build=21D61, device=iPad8,9, inputs paths, timestamps
- `targets`: только targets_needed (см. раздел 2)
- Для каждой цели заполнить `status` и `evidence[]`

Обязательная проверка:

- `addr_abs - kernel_base == offset_from_kernel_base`
- оффсет не выходит за диапазон ядра/кекстов

### Step B — обновить/сгенерировать `kexploit/final_kernel_offsets.h`

- header должен собираться только из `verified_offsets.json`
- не допускается ручная “плавающая” правка констант
- если цель `Unverified`:
  - в header оставить `#define` только если есть безопасный fallback
  - иначе `#define ... 0` и в runtime обязательно disable/gate

### Step C — зачистить проект от невалидных/конфликтных источников

- исключить candidate 7/8 из “используемых”
- выровнять `KERNEL_BASE` (одна правда)
- прекратить использование `jbdc/patcher/final_kernel_offsets.h` в runtime сборке (или синхронизировать генерацией)

### Step D — отчёт “что не совпадает”

Сгенерировать/обновить:

- `doc/OFFSETS_21D61_EVIDENCE.md`:
  - цель → addr/off → evidence → status
- `doc/ANALYSIS_21D61_REPORT.md`:
  - “что rejected”, “что unverified”, “что verified”

---

## 6) Acceptance criteria (готово когда…)

- Нет ни одной цели `Verified`, у которой единственное evidence = string.
- Candidate 7/8 не используются и помечены `Rejected`.
- В проекте один runtime‑header с оффсетами, остальные не участвуют или синхронизированы.
- Сборка IPA проходит.
- В логике патчей (sandbox/amfi/trustcache) присутствуют guard’ы: если адрес=0 или `Unverified`, патч не применяется.

