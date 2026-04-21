# Проверка смещений ядра: iOS 17.3.1 (21D61), A12 / A12X (iPad8,9)

**Дата:** 2026-04-14  
**Сборка:** 21D61 (`Darwin` / XNU соответствует ветке 17.3.x).  
**Цель:** отделить **стабильные offsetof** от **эвристик по сигнатурам**, которые нужно перепроверять на **конкретном** `kernelcache` при смене даже минорной версии iOS.

---

## 1. Артефакты в репозитории

| Файл / каталог | Назначение |
|----------------|------------|
| `iPad8,9_Analysis/21D61/` | Распакованный IPSW, в т.ч. `kernelcache.release.iPad8,9_*` |
| `prologue_scan_21D61.json` | Скан прологов функций в `__TEXT_EXEC` (для поиска сигнатур) |
| `kernel_symbols_21D61.json` | Символы / привязки из анализа |
| `funcs_ref_by_str_21D61.json` | Xref строк → функции |
| `pmap_*`, `disasm_*21D61*.txt` | PPL / pmap / XPRR контекст для 21D61 |
| `per_context_diffs/*21D61_vs_21E219*` | Сравнение с 17.4 — полезно для CVE-2024-23225 и соседних патчей |

Декомпрессированный Mach-O ядра — **единственный эталон** для проверки «сигнатурных» смещений; таблицы из upstream-проектов — **гипотезы**.

---

## 2. Классы смещений

### A. Стабильные (обычно совпадают с KDK / offsetof)

Получаются из структур `inpcb`, `socket`, `proc`, `proc_ro`, `ucred`, `task`, `filedesc`, `fileproc`, `fileglob`, `vnode`, `mount`, `namecache`, `ipc_*`, `vm_map*` — при **той же** версии XNU что у 21D61.

В коде: `third_party/darksword-kexploit-fun/.../kexploit/offsets.m` — много полей с комментарием `(lldb) p/x offsetof(...)`.

**Для 17.3.1:** сверить с заголовками XNU **10002.82.x** (версия из `uname` на устройстве), не с «похожим» macOS KDK.

### B. Зависят от SoC, но не от «магии» паттернов

Пример: разные ветки `off_thread_*` для A12 vs A13+ в той же iOS.

**Риск:** A12 vs **A12X (T8020)** — в `jbdc/kexploit/rc_offsets.m` для iPad8,9 используется **отдельная** ветка (8kSec / runtime), не обязательно совпадающая с «универсальной» таблицей A12 в `darksword-kexploit-fun`.

### C. Сигнатурные (обязательна проверка на 21D61)

В `offsets.m` помечены как **NOT POSSIBLE from KDK** или задаются через **hex / xref / prologue+N**:

- `thread.t_tro`, `thread.machine.upcb`, `thread.ctid`, `thread.options`, `thread.mutex...`, `thread.ast`, `thread.task_threads.next`, …
- часть `proc` (`p_fd`, `p_flag`, `p_textvp`, `p_name`) — через уникальные строки или паттерны.

**Любое** изменение компилятора/инлайна в патче 17.3.0 → 17.3.1 теоретически может сдвинуть **смещение внутри функции-якоря** (не только offsetof структуры).

---

## 3. Что перепроверить в первую очередь (RemoteCall / SBX)

Минимальный набор для **стабильного** `init_remote_call` и обходов:

| Переменная (lara) | Примечание |
|-------------------|------------|
| `rc_off_thread_t_tro` | Конфликт «универсальный A12 0x368» vs **T8020 0x348 / 0x348+формула** — только runtime / kernelcache |
| `rc_off_thread_task_threads_next` | Должен быть согласован с TRO на A12X (см. MEMORY / 8kSec) |
| `rc_off_thread_ctid` | Сигнатурный якорь в комментариях `offsets.m` |
| `rc_off_thread_mutex_lck_mtx_data` | То же |
| `rc_off_thread_ast` | Паттерн зависит от версии iOS (17.x отдельно) |
| `rc_off_thread_guard_exc_info_code` | Переименования `guard_exc` / `mach_exc` между версиями |

Остальные (`proc`, `ucred`, `task`, `filedesc`, `vnode`) — сверить offsetof на 21D61 при подозрении на регрессию после обновления прошивки.

---

## 4. Практическая процедура (kernelcache 21D61)

1. Взять **ровно** `kernelcache.release.iPad8,9` из IPSW **21D61** (уже под `iPad8,9_Analysis/21D61/` при наличии).
2. Убедиться в **slide = 0** для статического анализа или применить **kernel_slide** только при сравнении с live KVA.
3. Для каждого **сигнатурного** поля из §3:
   - найти якорную **строку** или **hex-последовательность** из комментария в `darksword-kexploit-fun/kexploit/offsets.m` (ветка **iOS 17.x**);
   - локализовать функцию в `kernelcache.decompressed`;
   - снять **смещение immediate** в нужной инструкции (LDR/ADD) → перевести в offsetof от базы `thread` (нужна ручная трассировка или скрипт).
4. Сравнить с текущими значениями в **`jbdc/kexploit/rc_offsets.m`**.
5. При расхождении — обновить **только** после подтверждения на устройстве (лог TRO / паника `bsd_kern`).

Инструменты: **Hopper / IDA / Ghidra**, скрипты под `prologue_scan_21D61.json`, `ipsw kernel disassemble` (если используется в проекте).

---

## 5. Связь с форком darksword-kexploit-fun

- Таблица в `third_party/darksword-kexploit-fun/.../kexploit/offsets.m` задаёт **iOS 17.1–17.3** для A12: `tro=0x368`, `task_threads_next=0x358` и т.д.
- В **lara** для **T8020 / iPad8,9** действует **другая** согласованность TRO/task_threads (см. `rc_offsets.m`, комментарии 8kSec).

Вывод: для 21D61 **нельзя** считать форк единственным источником истины по thread-полям; нужен **либо** разбор kernelcache, **либо** подтверждённый runtime на планшете.

---

## 6. PPL / pmap / CVE-2024-23225

Адреса вида `pmap_set_pte_xprr_perm` и поведение **expected_perm** версия-специфичны; для 21D61 vs 21E219 см. уже готовые **diff** в `iPad8,9_Analysis/per_context_diffs/` и разделы в `MEMORY.md` (CVE-2024-23225). Это **не** offsetof потока, но **обязательная** привязка к **конкретной** сборке kernelcache.

---

## 7. Краткий чеклист перед релизом IPA

- [ ] Kernelcache в анализе — **21D61**, не «17.3 generic».
- [ ] Сигнатурные hex из `offsets.m` **перепроверены** на этом файле или эквивалентном дампе.
- [ ] `rc_offsets.m` для A12X согласован с логами **init_remote_call** на устройстве.
- [ ] После микропатча Apple в той же 17.3.x — повторить §4 для затронутых якорей.
