#!/usr/bin/env python3
"""
find_ppl_ucred.py

Утилита для поиска в распакованном kernelcache/ Mach-O потенциальных
символов и строк, связанных с `ucred` и PPL (Protected Process Launch / PPL).

Поддерживает:
- поиск по таблице символов (если есть)
- поиск ASCII-строк внутри бинарника
- опциональный поиск вхождений 8-байтных указателей на найденные адреса

Пример использования:
  python find_ppl_ucred.py -i /path/to/kernelcache.release.iPad8,9 --scan-ptrs

Зависимости: чистый Python 3 (нет внешних пакетов).
"""

from __future__ import annotations
import argparse
import os
import struct
from typing import Dict, List, Optional

MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2


def read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def parse_macho(data: bytes):
    info = {'is_macho': False, 'segments': [], 'symtab': None}
    if len(data) < 4:
        return info
    try:
        magic = read_u32(data, 0)
    except Exception:
        return info
    if magic != MH_MAGIC_64:
        return info
    info['is_macho'] = True

    # mach_header_64 size = 32
    try:
        hdr = struct.unpack_from('<IiiIIIII', data, 0)
    except struct.error:
        return info
    _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = hdr
    off = 32
    for i in range(ncmds):
        if off + 8 > len(data):
            break
        try:
            cmd, cmdsize = struct.unpack_from('<II', data, off)
        except struct.error:
            break
        cmddata = data[off: off + cmdsize]
        if cmd == LC_SEGMENT_64:
            try:
                segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from('<16sQQQQiiii', cmddata, 0)
                segname = segname.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
                info['segments'].append({'segname': segname, 'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize})
            except struct.error:
                pass
        elif cmd == LC_SYMTAB:
            try:
                symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', cmddata, 8)
                info['symtab'] = {'symoff': symoff, 'nsyms': nsyms, 'stroff': stroff, 'strsize': strsize}
            except struct.error:
                pass
        off += cmdsize
    return info


def vm_to_fileoff(segments: List[Dict], vm: int) -> Optional[int]:
    for s in segments:
        va = s['vmaddr']; vs = s['vmsize']
        if vs == 0:
            continue
        if va <= vm < va + vs:
            return s['fileoff'] + (vm - va)
    return None


def fileoff_to_vm(segments: List[Dict], fo: int) -> Optional[int]:
    for s in segments:
        foff = s['fileoff']; fsz = s['filesize']
        if fsz == 0:
            continue
        if foff <= fo < foff + fsz:
            return s['vmaddr'] + (fo - foff)
    return None


def parse_symtab(data: bytes, symtab: Dict) -> Dict[str, int]:
    out = {}
    if not symtab:
        return out
    symoff = symtab['symoff']; nsyms = symtab['nsyms']; stroff = symtab['stroff']; strsize = symtab['strsize']
    if symoff + nsyms * 16 > len(data):
        # guard against corrupt counts
        nsyms = max(0, (len(data) - symoff) // 16)
    strings = data[stroff: stroff + strsize] if stroff + strsize <= len(data) else b''
    for i in range(nsyms):
        ent = symoff + i * 16
        try:
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<I B B H Q', data, ent)
        except struct.error:
            continue
        if n_strx != 0 and n_strx < len(strings):
            end = strings.find(b'\x00', n_strx)
            if end == -1:
                end = len(strings)
            name = strings[n_strx:end].decode('utf-8', errors='ignore')
            out[name] = n_value
    return out


def find_ascii_strings(data: bytes, minlen=4) -> Dict[int, str]:
    res = {}
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                try:
                    s = cur.decode('ascii', errors='ignore')
                    res[start] = s
                except Exception:
                    pass
            cur = bytearray()
    if len(cur) >= minlen:
        try:
            s = cur.decode('ascii', errors='ignore')
            res[start] = s
        except Exception:
            pass
    return res


def scan_for_addr_occurrences(data: bytes, addr: int, limit=200) -> List[int]:
    tgt = struct.pack('<Q', addr)
    hits = []
    off = 0
    while True:
        i = data.find(tgt, off)
        if i == -1:
            break
        hits.append(i)
        off = i + 1
        if len(hits) >= limit:
            break
    return hits


DEFAULT_KEYS = ['ucred', 'cr_label', 'cr_uid', 'cr_ruid', 'cr_groups', 'cr_ngroups', 'ppl', 'ppl_', 'ppl_cred']


def main():
    ap = argparse.ArgumentParser(description='Поиск PPL/ucred символов и строк в kernelcache')
    ap.add_argument('-i', '--input', required=True, help='путь к распакованному kernelcache/Mach-O')
    ap.add_argument('-k', '--keys', default=','.join(DEFAULT_KEYS), help='комма-разделённый список ключевых слов')
    ap.add_argument('--minstr', type=int, default=6, help='минимальная длина для поиска строк')
    ap.add_argument('--scan-ptrs', action='store_true', help='сканировать бинарник на вхождения 8-байтных указателей на найденные адреса')
    args = ap.parse_args()

    path = args.input
    if not os.path.isfile(path):
        print('Файл не найден:', path)
        return
    data = open(path, 'rb').read()
    info = parse_macho(data)

    print('Файл:', path)
    if info['is_macho']:
        print('Распознан Mach-O 64-bit; сегменты:')
        for s in info['segments']:
            print('  %-12s vm=0x%016x size=0x%x fileoff=0x%x fsize=0x%x' % (s['segname'], s['vmaddr'], s['vmsize'], s['fileoff'], s['filesize']))
    else:
        print('Не Mach-O или заголовок не распознан — выполню только поиск строк.')

    keys = [k.strip() for k in args.keys.split(',') if k.strip()]

    syms = {}
    if info.get('symtab'):
        syms = parse_symtab(data, info['symtab'])
        print('\nСимволов в таблице:', len(syms))
    else:
        print('\nТаблица символов не обнаружена.')

    found = {}
    if syms:
        for name, addr in syms.items():
            lname = name.lower()
            for k in keys:
                if k.lower() in lname:
                    fo = vm_to_fileoff(info['segments'], addr) if info['segments'] else None
                    found.setdefault(k, []).append({'type': 'sym', 'name': name, 'vm': addr, 'fileoff': fo})

    if not found:
        print('\nFallback: ищем ASCII-строки... (minlen=%d)' % args.minstr)
        strs = find_ascii_strings(data, minlen=args.minstr)
        for off, s in strs.items():
            ls = s.lower()
            for k in keys:
                if k.lower() in ls:
                    vm = fileoff_to_vm(info['segments'], off) if info['segments'] else None
                    found.setdefault(k, []).append({'type': 'str', 'text': s, 'fileoff': off, 'vm': vm})

    if not found:
        print('\nСовпадений не найдено. Попробуйте другие ключевые слова или уменьшите minstr.')
        return

    print('\nНайденные кандидаты:')
    for k, items in found.items():
        print('\n[ %s ]' % k)
        for it in items:
            if it['type'] == 'sym':
                print('  sym: %-40s vm=0x%016x fileoff=%s' % (it['name'], it['vm'], hex(it['fileoff']) if it['fileoff'] else 'N/A'))
            else:
                print('  str @ fileoff=0x%08x vm=%s text=%s' % (it['fileoff'], '0x%016x' % it['vm'] if it['vm'] else 'N/A', it['text']))

    if args.scan_ptrs:
        print('\nСканирование на вхождения 8-байтных указателей (ограничено)')
        for k, items in found.items():
            for it in items:
                vm = it.get('vm')
                if not vm:
                    continue
                hits = scan_for_addr_occurrences(data, vm, limit=200)
                if hits:
                    print('\n  Candidate %s (vm=0x%016x) referenced %d places:' % (k, vm, len(hits)))
                    for h in hits[:20]:
                        vm2 = fileoff_to_vm(info['segments'], h)
                        print('    fileoff=0x%08x vm=%s' % (h, '0x%016x' % vm2 if vm2 else 'N/A'))


if __name__ == '__main__':
    main()
