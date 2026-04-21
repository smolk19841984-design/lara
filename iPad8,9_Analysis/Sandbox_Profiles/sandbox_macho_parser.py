#!/usr/bin/env python3
"""
sandbox_macho_parser.py
Полный парсер Mach-O структуры com.apple.security.sandbox.kext
Извлекает: секции, сегменты, символы, строки, потенциальные bytecode SBPL
"""

import struct, sys, os, json, re

# ── Mach-O constants ──────────────────────────────────────────────────────────
MH_MAGIC_64   = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB     = 0x2
LC_DYSYMTAB   = 0xB
LC_UUID       = 0x1B
LC_BUILD_VERSION = 0x32

CPU_TYPE_ARM64 = 0x0100000C

def read32(data, off): return struct.unpack_from('<I', data, off)[0]
def read64(data, off): return struct.unpack_from('<Q', data, off)[0]
def reads(data, off):
    end = data.index(b'\x00', off)
    return data[off:end].decode('utf-8', errors='replace')


def parse_macho(data):
    magic = read32(data, 0)
    if magic != MH_MAGIC_64:
        print(f"[!] Unexpected magic: 0x{magic:08X}")
        return None

    cpu_type    = read32(data, 4)
    cpu_subtype = read32(data, 8)
    filetype    = read32(data, 12)
    ncmds       = read32(data, 16)
    sizeofcmds  = read32(data, 20)
    flags       = read32(data, 24)

    info = {
        'magic': f'0x{magic:08X}',
        'cpu_type': f'0x{cpu_type:08X}',
        'cpu_subtype': f'0x{cpu_subtype:08X}',
        'filetype': filetype,
        'ncmds': ncmds,
        'sizeofcmds': sizeofcmds,
        'flags': f'0x{flags:08X}',
        'segments': [],
        'sections': [],
        'uuid': None,
        'build_version': None,
    }

    off = 32  # header size for 64-bit
    for _ in range(ncmds):
        cmd  = read32(data, off)
        csz  = read32(data, off + 4)

        if cmd == LC_SEGMENT_64:
            segname = data[off+8:off+24].rstrip(b'\x00').decode('utf-8', errors='replace')
            vmaddr  = read64(data, off + 24)
            vmsize  = read64(data, off + 32)
            fileoff = read64(data, off + 40)
            filesz  = read64(data, off + 48)
            nsects  = read32(data, off + 64)

            seg = {
                'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                'fileoff': fileoff, 'filesz': filesz, 'nsects': nsects,
                'sections': []
            }

            sect_off = off + 72
            for i in range(nsects):
                sectname = data[sect_off:sect_off+16].rstrip(b'\x00').decode('utf-8', errors='replace')
                seg_n    = data[sect_off+16:sect_off+32].rstrip(b'\x00').decode('utf-8', errors='replace')
                s_addr   = read64(data, sect_off + 32)
                s_size   = read64(data, sect_off + 40)
                s_off    = read32(data, sect_off + 48)
                sect = {
                    'sectname': sectname, 'segname': seg_n,
                    'addr': s_addr, 'size': s_size, 'offset': s_off
                }
                seg['sections'].append(sect)
                info['sections'].append(sect)
                sect_off += 80

            info['segments'].append(seg)

        elif cmd == LC_UUID:
            uuid_bytes = data[off+8:off+24]
            info['uuid'] = '-'.join([
                uuid_bytes[0:4].hex(),
                uuid_bytes[4:6].hex(),
                uuid_bytes[6:8].hex(),
                uuid_bytes[8:10].hex(),
                uuid_bytes[10:16].hex(),
            ]).upper()

        elif cmd == LC_BUILD_VERSION:
            platform = read32(data, off + 8)
            minos    = read32(data, off + 12)
            sdk      = read32(data, off + 16)
            info['build_version'] = {
                'platform': platform,
                'minos': f'{(minos>>16)&0xFFFF}.{(minos>>8)&0xFF}.{minos&0xFF}',
                'sdk':   f'{(sdk>>16)&0xFFFF}.{(sdk>>8)&0xFF}.{sdk&0xFF}',
            }

        off += csz

    return info


def scan_for_sbpl_patterns(data, sections):
    """
    SBPL (Sandbox Profile Language) bytecode в Apple's sandbox kext
    обычно находится в секции __DATA или специальных секциях.
    Ищем паттерны: таблицы операций sandbox.
    """
    results = []

    # Sandbox operation names — встречаются в bctbl / operation-table
    sandbox_ops = [
        b'default', b'file-read-data', b'file-write-data',
        b'file-read-metadata', b'file-write-metadata',
        b'mach-lookup', b'mach-register', b'mach-priv-host-port',
        b'network-outbound', b'network-inbound',
        b'process-exec', b'process-fork', b'process-info*',
        b'signal', b'sysctl-read', b'sysctl-write',
        b'iokit-open', b'iokit-set-properties',
        b'system-privilege', b'system-socket',
        b'file-ioctl', b'file-read-xattr', b'file-write-xattr',
    ]

    for op in sandbox_ops:
        pos = 0
        while True:
            idx = data.find(op, pos)
            if idx == -1:
                break
            # Найдём секцию
            sec_name = '<raw>'
            for s in sections:
                end = s['offset'] + s['size']
                if s['offset'] <= idx < end:
                    sec_name = f"{s['segname']}.{s['sectname']}"
                    break
            results.append({'op': op.decode(), 'offset': idx, 'section': sec_name})
            pos = idx + 1

    return results


def extract_cstrings(data, sections):
    """Извлекаем строки из секции __TEXT.__cstring, __DATA.__cstring, __TEXT.__const"""
    strings = []
    for s in sections:
        if s['sectname'] in ('__cstring', '__oslogstring', '__const', '__objc_methnames', '__objc_classnames'):
            start = s['offset']
            end   = start + s['size']
            chunk = data[start:end]
            # Разбираем null-terminated строки
            current = bytearray()
            for b in chunk:
                if b == 0:
                    if len(current) >= 4:
                        strings.append({
                            'string': current.decode('utf-8', errors='replace'),
                            'section': f"{s['segname']}.{s['sectname']}"
                        })
                    current = bytearray()
                elif 32 <= b < 127:
                    current += bytes([b])
                else:
                    current = bytearray()
    return strings


def find_bypass_indicators(strings):
    """Ищем строки, указывающие на возможности обхода sandbox"""
    bypass_keywords = [
        'unenforced', 'Unenforced', 'bypass', 'exception', 'exempt',
        'no-sandbox', 'task_for_pid', 'get-task-allow', 'debug',
        'violation', 'override', 'skip', 'ignore', 'whitelist',
        'allow.*write', 'private.*security', 'bindfs', 'OOPJit',
        'can-execute-cdhash', 'storage-exempt', 'platform-binary',
        'cs-restrict', 'amfi', 'trustd'
    ]
    hits = []
    for entry in strings:
        s = entry['string']
        for kw in bypass_keywords:
            if re.search(kw, s, re.IGNORECASE):
                hits.append({'string': s, 'keyword': kw, 'section': entry['section']})
                break
    return hits


def find_writable_paths(strings):
    """Находим пути, к которым sandbox потенциально разрешает запись"""
    path_patterns = [
        r'/private/var/tmp',
        r'/var/tmp',
        r'/private/var/mobile',
        r'/private/var/root',
        r'/tmp',
        r'/private/tmp',
        r'/var/containers',
        r'OOPJit',
        r'CoreRepair',
        r'/var/jb',
        r'PersonaVolumes',
    ]
    found = []
    for entry in strings:
        for pat in path_patterns:
            if re.search(pat, entry['string'], re.IGNORECASE):
                found.append({'path': entry['string'], 'section': entry['section']})
                break
    return found


def find_entitlements(strings):
    """Все entitlement strings из бинарника"""
    ent_patterns = [
        r'com\.apple\.private',
        r'com\.apple\.security',
        r'com\.apple\.rootless',
        r'com\.apple\.developer',
        r'task_for_pid',
        r'get-task-allow',
        r'platform-application',
    ]
    found = []
    for entry in strings:
        s = entry['string']
        if any(re.search(p, s) for p in ent_patterns):
            found.append({'entitlement': s, 'section': entry['section']})
    return found


def main():
    kext = r'c:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\Sandbox_Profiles\com.apple.security.sandbox.kext'
    out_dir = os.path.dirname(kext)

    print(f"[*] Читаю {os.path.basename(kext)} ({os.path.getsize(kext)//1024} KB)...")
    with open(kext, 'rb') as f:
        data = f.read()

    print("[*] Парсинг Mach-O заголовка...")
    info = parse_macho(data)
    if not info:
        return

    print(f"  UUID: {info['uuid']}")
    if info['build_version']:
        bv = info['build_version']
        print(f"  Build: minOS={bv['minos']}, SDK={bv['sdk']}")
    print(f"  Сегментов: {len(info['segments'])}")
    print(f"  Секций: {len(info['sections'])}")
    for s in info['sections']:
        print(f"    [{s['segname']}.{s['sectname']}] offset=0x{s['offset']:X} size=0x{s['size']:X}")

    print("\n[*] Извлечение C-строк из секций...")
    cstrings = extract_cstrings(data, info['sections'])
    print(f"  Найдено строк: {len(cstrings)}")

    print("[*] Поиск SBPL операций...")
    sbpl_ops = scan_for_sbpl_patterns(data, info['sections'])
    print(f"  Найдено sandbox операций: {len(sbpl_ops)}")
    op_sections = {}
    for op in sbpl_ops:
        op_sections.setdefault(op['section'], set()).add(op['op'])
    for sec, ops in sorted(op_sections.items()):
        print(f"    {sec}: {sorted(ops)}")

    print("\n[*] Поиск bypass-индикаторов...")
    bypass = find_bypass_indicators(cstrings)
    print(f"  Найдено bypass-индикаторов: {len(bypass)}")
    for b in bypass[:30]:
        print(f"    [{b['section']}] {b['string'][:100]}")

    print("\n[*] Поиск записываемых путей...")
    paths = find_writable_paths(cstrings)
    print(f"  Найдено путей: {len(paths)}")
    for p in paths:
        print(f"    [{p['section']}] {p['path']}")

    print("\n[*] Поиск entitlements...")
    ents = find_entitlements(cstrings)
    print(f"  Найдено entitlements: {len(ents)}")

    # ── Сохраняем результаты ──────────────────────────────────────────────────
    result = {
        'header': info,
        'sections_summary': [{'name': f"{s['segname']}.{s['sectname']}", 'size': s['size'], 'offset': s['offset']} for s in info['sections']],
        'sbpl_operations': sbpl_ops[:500],
        'bypass_indicators': bypass,
        'writable_paths': paths,
        'entitlements': ents,
        'cstrings_count': len(cstrings),
    }

    out_json = os.path.join(out_dir, 'macho_analysis.json')
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    # Текстовый отчёт
    out_txt = os.path.join(out_dir, 'macho_analysis_report.txt')
    with open(out_txt, 'w', encoding='utf-8') as f:
        f.write("=== Mach-O ANALYSIS: com.apple.security.sandbox.kext ===\n\n")
        f.write(f"UUID: {info['uuid']}\n")
        if info['build_version']:
            bv = info['build_version']
            f.write(f"Build: minOS={bv['minos']}, SDK={bv['sdk']}\n")
        f.write(f"\n── СЕКЦИИ ──\n")
        for s in info['sections']:
            f.write(f"  [{s['segname']}.{s['sectname']}] offset=0x{s['offset']:X} size=0x{s['size']:X}\n")

        f.write(f"\n── BYPASS INDICATORS ({len(bypass)}) ──\n")
        for b in bypass:
            f.write(f"  [{b['keyword']}] [{b['section']}] {b['string']}\n")

        f.write(f"\n── WRITABLE PATHS ({len(paths)}) ──\n")
        for p in paths:
            f.write(f"  [{p['section']}] {p['path']}\n")

        f.write(f"\n── ENTITLEMENTS ({len(ents)}) ──\n")
        for e in ents:
            f.write(f"  [{e['section']}] {e['entitlement']}\n")

        f.write(f"\n── SBPL OPERATIONS ({len(sbpl_ops)}) ──\n")
        for sec, ops in sorted(op_sections.items()):
            f.write(f"  {sec}: {sorted(ops)}\n")

    print(f"\n[+] Результаты сохранены:")
    print(f"  {out_json}")
    print(f"  {out_txt}")


if __name__ == '__main__':
    main()
