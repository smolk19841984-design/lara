#!/usr/bin/env python3
"""
sandbox_bypass_vectors.py
Глубокий анализ bypass-векторов sandbox для iOS 17+ на iPad8,9
Анализирует: unenforced violations, entitlement-exceptions, writable paths,
             __TEXT.__const (SBPL bytecode tables), operation dispatch table
"""

import struct, sys, os, json, re
from collections import defaultdict

KEXT_PATH = r'c:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\Sandbox_Profiles\com.apple.security.sandbox.kext'

def read32(d, o): return struct.unpack_from('<I', d, o)[0]
def read64(d, o): return struct.unpack_from('<Q', d, o)[0]

def parse_sections(data):
    off = 32
    ncmds = read32(data, 16)
    sections = []
    for _ in range(ncmds):
        cmd = read32(data, off)
        csz = read32(data, off + 4)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = read32(data, off + 64)
            soff = off + 72
            for i in range(nsects):
                sname = data[soff:soff+16].rstrip(b'\x00').decode('utf-8', errors='replace')
                sgname = data[soff+16:soff+32].rstrip(b'\x00').decode('utf-8', errors='replace')
                s_addr = read64(data, soff+32)
                s_size = read64(data, soff+40)
                s_foff = read32(data, soff+48)
                sections.append({'sect': sname, 'seg': sgname, 'addr': s_addr, 'size': s_size, 'offset': s_foff})
                soff += 80
        off += csz
    return sections


def get_section_data(data, sections, segname, sectname=None):
    """Возвращает (offset, bytes) для секции"""
    for s in sections:
        if s['seg'] == segname and (sectname is None or s['sect'] == sectname):
            return s['offset'], data[s['offset']: s['offset'] + s['size']]
    return None, b''


def extract_null_strings(chunk):
    """Null-separated строки из секции __cstring / __const"""
    strings = []
    buf = bytearray()
    for b in chunk:
        if b == 0:
            if len(buf) >= 3:
                try: strings.append(buf.decode('utf-8'))
                except: pass
            buf = bytearray()
        elif 32 <= b < 127:
            buf += bytes([b])
        else:
            buf = bytearray()
    return strings


def analyze_const_section(data, sections):
    """
    __TEXT.__const содержит скомпилированные sandbox profile данные.
    Ищем: таблицы операций, entitlement lookup tables, path literals.
    """
    _, chunk = get_section_data(data, sections, '__TEXT', '__const')
    strings = extract_null_strings(chunk)

    # Категоризация
    categories = {
        'entitlements_private': [],
        'entitlements_rootless': [],
        'entitlements_developer': [],
        'entitlements_security': [],
        'paths_var': [],
        'paths_system': [],
        'paths_tmp': [],
        'operations': [],
        'bypass_candidates': [],
        'unenforced': [],
        'mach_services': [],
        'processes': [],
    }

    for s in strings:
        sl = s.lower()
        if 'unenforced' in sl:
            categories['unenforced'].append(s)
        elif 'com.apple.private' in s:
            categories['entitlements_private'].append(s)
        elif 'com.apple.rootless' in s:
            categories['entitlements_rootless'].append(s)
        elif 'com.apple.developer' in s:
            categories['entitlements_developer'].append(s)
        elif 'com.apple.security' in s:
            categories['entitlements_security'].append(s)
        elif s.startswith('/private/var') or s.startswith('/var'):
            categories['paths_var'].append(s)
        elif s.startswith('/tmp') or 'tmp' in sl:
            categories['paths_tmp'].append(s)
        elif s.startswith('/usr') or s.startswith('/bin') or s.startswith('/sbin') or s.startswith('/System'):
            categories['paths_system'].append(s)
        elif s.startswith('com.apple.') and not s.startswith('com.apple.private') and not s.startswith('com.apple.rootless'):
            categories['mach_services'].append(s)

    return categories, strings


def analyze_cstring_section(data, sections):
    """__TEXT.__cstring: ошибки, log-строки, sandbox ops"""
    _, chunk = get_section_data(data, sections, '__TEXT', '__cstring')
    strings = extract_null_strings(chunk)

    error_msgs = [s for s in strings if 'error' in s.lower() or 'fail' in s.lower() or 'denied' in s.lower()]
    log_msgs = [s for s in strings if 'sandbox' in s.lower() or 'violation' in s.lower() or 'policy' in s.lower()]
    ops = [s for s in strings if re.match(r'^(file|mach|process|network|sysctl|iokit|system|signal|ipc|appleevent)[-a-z*]+$', s)]
    bypass_hints = [s for s in strings if any(k in s.lower() for k in ['unenforced', 'exception', 'exempt', 'bypass', 'override', 'no-sandbox'])]

    return {
        'all': strings,
        'error_messages': error_msgs,
        'log_messages': log_msgs,
        'sandbox_operations': ops,
        'bypass_hints': bypass_hints,
    }


def analyze_oslog_section(data, sections):
    """__TEXT.__os_log: format strings для kernel logging - ценная информация"""
    _, chunk = get_section_data(data, sections, '__TEXT', '__os_log')
    # os_log формат: [size_byte][format_string_offset][category_offset]
    # Проще — просто ищем строки
    strings = []
    buf = bytearray()
    for b in chunk:
        if b == 0:
            if len(buf) >= 4:
                try: strings.append(buf.decode('utf-8'))
                except: pass
            buf = bytearray()
        elif 32 <= b < 127:
            buf += bytes([b])
        else:
            buf = bytearray()
    return strings


def find_path_patterns_in_const(chunk):
    """
    В __TEXT.__const ищем паттерны вида: <prefix_byte><path_string>
    Это типичный формат для Apple Sandbox path tables.
    Префикс: буква-код типа операции (R=read-only, L=read-write, etc.)
    """
    path_table = []
    i = 0
    while i < len(chunk) - 1:
        # Ищем ASCII букву-префикс перед ASCII путём
        b = chunk[i]
        if 64 <= b <= 126:  # @, буквы, цифры
            # Проверяем, что следующий байт — начало пути или имени энтайтлмента
            j = i + 1
            buf = bytearray()
            while j < len(chunk) and 32 <= chunk[j] < 127:
                buf += bytes([chunk[j]])
                j += 1
            if len(buf) >= 4:
                prefix = chr(b)
                path_str = buf.decode('utf-8', errors='ignore')
                if '/' in path_str or '.' in path_str:
                    path_table.append({'prefix': prefix, 'path': path_str, 'raw_offset': i})
        i += 1
    return path_table


def find_bypass_entitlements(all_entitlements):
    """
    Классифицируем entitlements по уровню bypass-возможностей.
    Tier 1 = полный обход
    Tier 2 = частичный (storage, path)
    Tier 3 = операционный (task_for_pid, debug)
    """
    tier1 = []
    tier2 = []
    tier3 = []

    tier1_patterns = [
        'no-sandbox', 'platform-application', 'platform-binary',
        'task_for_pid-allow', 'can-execute-cdhash',
    ]
    tier2_patterns = [
        'storage-exempt', 'exception.files', 'exception.mach',
        'exception.iokit', 'exception.sysctl', 'bindfs',
        'home-relative-path', 'absolute-path',
        'core-repair', 'OOPJit', 'oop-jit',
    ]
    tier3_patterns = [
        'get-task-allow', 'task_for_pid', 'private.security',
        'private.amfi', 'private.sandbox', 'heritable',
        'container-manager', 'system-task-ports',
    ]

    for e in all_entitlements:
        matched = False
        for p in tier1_patterns:
            if p in e:
                tier1.append({'entitlement': e, 'tier': 1, 'pattern': p})
                matched = True
                break
        if matched:
            continue
        for p in tier2_patterns:
            if p in e:
                tier2.append({'entitlement': e, 'tier': 2, 'pattern': p})
                matched = True
                break
        if matched:
            continue
        for p in tier3_patterns:
            if p in e:
                tier3.append({'entitlement': e, 'tier': 3, 'pattern': p})
                break

    return tier1, tier2, tier3


def main():
    out_dir = os.path.dirname(KEXT_PATH)
    print(f"[*] Загрузка {os.path.basename(KEXT_PATH)}...")
    with open(KEXT_PATH, 'rb') as f:
        data = f.read()

    sections = parse_sections(data)

    # ── 1. Анализ __TEXT.__const ──────────────────────────────────────────────
    print("[*] Анализ __TEXT.__const (sandbox policy tables)...")
    categories, const_strings = analyze_const_section(data, sections)
    print(f"  Всего строк в __const: {len(const_strings)}")
    for k, v in categories.items():
        if v:
            print(f"  {k}: {len(v)}")

    # ── 2. Анализ __TEXT.__cstring ────────────────────────────────────────────
    print("\n[*] Анализ __TEXT.__cstring (operations, errors, logs)...")
    cstr = analyze_cstring_section(data, sections)
    print(f"  Sandbox операции: {cstr['sandbox_operations']}")
    print(f"  Log/violation строки: {len(cstr['log_messages'])}")
    print(f"  Error строки: {len(cstr['error_messages'])}")
    print(f"  Bypass hints: {cstr['bypass_hints']}")

    # ── 3. Анализ __TEXT.__os_log ─────────────────────────────────────────────
    print("\n[*] Анализ __TEXT.__os_log (kernel log format strings)...")
    oslog = analyze_oslog_section(data, sections)
    violation_logs = [s for s in oslog if 'violation' in s.lower() or 'deny' in s.lower() or 'sandbox' in s.lower()]
    print(f"  Всего os_log строк: {len(oslog)}")
    print(f"  Violation/deny logs: {len(violation_logs)}")
    for v in violation_logs[:20]:
        print(f"    {v}")

    # ── 4. Path prefix table ──────────────────────────────────────────────────
    print("\n[*] Поиск path-prefix таблиц в __TEXT.__const...")
    _, const_chunk = get_section_data(data, sections, '__TEXT', '__const')
    path_table = find_path_patterns_in_const(const_chunk)
    path_table = [p for p in path_table if len(p['path']) > 5 and len(p['path']) < 200]
    print(f"  Записей в таблице путей: {len(path_table)}")
    prefix_map = defaultdict(list)
    for p in path_table:
        prefix_map[p['prefix']].append(p['path'])
    # Префиксы: R=read-only, L=read-write, W=write?, F=from?
    for prefix, paths in sorted(prefix_map.items()):
        if len(paths) > 0:
            print(f"  Prefix '{prefix}': {len(paths)} paths, examples: {paths[:3]}")

    # ── 5. Bypass entitlements classification ─────────────────────────────────
    print("\n[*] Классификация entitlements по bypass-уровням...")
    all_ents = categories['entitlements_private'] + categories['entitlements_security'] + \
               categories['entitlements_rootless'] + categories['entitlements_developer']
    t1, t2, t3 = find_bypass_entitlements(all_ents)
    print(f"  Tier 1 (полный обход): {len(t1)}")
    for e in t1:
        print(f"    [{e['pattern']}] {e['entitlement']}")
    print(f"  Tier 2 (частичный/storage): {len(t2)}")
    for e in t2[:20]:
        print(f"    [{e['pattern']}] {e['entitlement']}")
    print(f"  Tier 3 (операционный): {len(t3)}")
    for e in t3[:20]:
        print(f"    [{e['pattern']}] {e['entitlement']}")

    # ── 6. Unenforced violations ──────────────────────────────────────────────
    print("\n[*] Unenforced violations (потенциальные unpatched bypass):")
    for u in categories['unenforced']:
        print(f"  !! {u}")

    # ── Генерация итогового отчёта ────────────────────────────────────────────
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("SANDBOX BYPASS VECTOR ANALYSIS — iPad8,9 iOS 17+")
    report_lines.append("=" * 70)
    report_lines.append("")
    report_lines.append("── TIER 1: ПОЛНЫЙ ОБХОД SANDBOX ─────────────────────────────────────")
    report_lines.append("Эти entitlement дают полный обход всех sandbox-политик.")
    for e in t1:
        report_lines.append(f"  {e['entitlement']}")
        report_lines.append(f"    -> Вектор: добавить в entitlements.plist приложения")

    report_lines.append("")
    report_lines.append("── TIER 2: ЧАСТИЧНЫЙ ОБХОД (STORAGE / PATH EXCEPTIONS) ─────────────")
    report_lines.append("Эти entitlement дают доступ к конкретным путям вне sandbox.")
    for e in t2:
        report_lines.append(f"  [{e['pattern']}] {e['entitlement']}")

    report_lines.append("")
    report_lines.append("── ЗАПИСЫВАЕМЫЕ ПУТИ (доступны из sandbox или через bypass) ─────────")
    for p in (categories['paths_var'] + categories['paths_tmp'])[:30]:
        report_lines.append(f"  {p}")

    report_lines.append("")
    report_lines.append("── UNENFORCED VIOLATIONS (потенциально неисправленные пути) ─────────")
    report_lines.append("Apple сама логирует эти нарушения как 'unenforced' — т.е. sandbox")
    report_lines.append("ЗНАЕТ о нарушении, но НЕ БЛОКИРУЕТ его. Это bypass.")
    for u in categories['unenforced']:
        report_lines.append(f"  !! {u}")
        report_lines.append(f"     -> Вектор: попытаться воспроизвести условие нарушения")

    report_lines.append("")
    report_lines.append("── SANDBOX OPERATIONS (исчерпывающий список) ────────────────────────")
    for op in sorted(cstr['sandbox_operations']):
        report_lines.append(f"  {op}")

    report_lines.append("")
    report_lines.append("── LOG СТРОКИ (kernel messages при violations) ──────────────────────")
    for v in cstr['log_messages']:
        report_lines.append(f"  {v}")
    for v in violation_logs:
        report_lines.append(f"  [os_log] {v}")

    report_lines.append("")
    report_lines.append("── BYPASS METHODOLOGY ───────────────────────────────────────────────")
    report_lines.append("1. ENTITLEMENT INJECTION:")
    report_lines.append("   Добавить в lara.entitlements:")
    report_lines.append("   - com.apple.private.security.no-sandbox (если доступен в TrustCache)")
    report_lines.append("   - com.apple.security.exception.files.absolute-path.read-write")
    report_lines.append("   - com.apple.security.exception.files.absolute-path.read-only")
    report_lines.append("   - com.apple.private.security.storage-exempt.heritable")
    report_lines.append("   -> Подписать через ldid -S<entitlements.plist> в TrustCache pipeline")
    report_lines.append("")
    report_lines.append("2. UNENFORCED VIOLATION PATH:")
    report_lines.append("   - Попытаться получить доступ к путям через unenforced vector")
    report_lines.append("   - kernel sandbox логирует но НЕ блокирует (rdar://72823536)")
    report_lines.append("")
    report_lines.append("3. VFS MAC LABEL BYPASS:")
    report_lines.append("   - Использовать vfs_bypass_mac_label() из kernel exploit")
    report_lines.append("   - Снять MAC label с /var/jb до mkdir()") 
    report_lines.append("   - Комбинировать с entitlement injection")
    report_lines.append("")
    report_lines.append("4. TRUSTCACHE HELPER PATH:")
    report_lines.append("   - create_var_jb_helper встроен в bundle → /var/tmp → posix_spawn")
    report_lines.append("   - Требует: TrustCache entry + entitlements через ldid")
    report_lines.append("   - Writable paths: /var/tmp, /private/var/mobile/tmp")

    out_path = os.path.join(out_dir, 'bypass_vectors_report.txt')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report_lines))

    # JSON для дальнейших скриптов
    out_json = os.path.join(out_dir, 'bypass_vectors.json')
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump({
            'tier1_bypass': t1,
            'tier2_bypass': t2,
            'tier3_bypass': t3,
            'writable_paths': categories['paths_var'] + categories['paths_tmp'],
            'unenforced_violations': categories['unenforced'],
            'sandbox_operations': cstr['sandbox_operations'],
            'log_messages': cstr['log_messages'],
            'oslog_violations': violation_logs,
            'bypass_hints': cstr['bypass_hints'],
        }, f, ensure_ascii=False, indent=2)

    print(f"\n[+] Отчёт сохранён: {out_path}")
    print(f"[+] JSON данные: {out_json}")


if __name__ == '__main__':
    main()
