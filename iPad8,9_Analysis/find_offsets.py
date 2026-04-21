#!/usr/bin/env python3
"""
find_offsets.py

Утилита для быстрой проверки распакованного kernelcache / Mach-O на предмет
наличия символов и возможных адресов `rootvnode`, `allproc`, `proc`, `filedesc`, `vnode` и т.п.

Алгоритм:
- Попытка распарсить Mach-O 64-bit (LC_SEGMENT_64, LC_SYMTAB).
- Если есть таблица символов — вывести адреса символов, содержащих ключевые слова.
- Если символов нет — искать в бинарных строках и пытаться сопоставить fileoff ↔ vmaddr по сегментам.
- Опционально: найти в бинарных данных 8-байтные вхождения найденных vm-адресов (указатели).

Запуск:
  python find_offsets.py --input kernelcache.release.iPad8,9

Зависимости: чистый Python 3 (нет внешних пакетов).
"""

import sys
import struct
import argparse
import os
import io
from typing import List, Dict, Optional, Tuple


MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2


def read_u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def read_u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def parse_macho(data: bytes) -> Dict:
    out = {'segments': [], 'symtab': None, 'is_macho': False}
    if len(data) < 4:
        return out
    magic = read_u32(data, 0)
    if magic != MH_MAGIC_64:
        return out
    out['is_macho'] = True

    # mach_header_64: 8 * 4 = 32 bytes
    hdr = struct.unpack_from('<IiiIIIII', data, 0)
    _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = hdr
    off = 32

    for i in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        cmddata = data[off: off + cmdsize]
        if cmd == LC_SEGMENT_64:
            # segment_command_64: segname(16), vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags
            try:
                segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from('<16sQQQQiiii', cmddata, 0)
            except struct.error:
                segname = b''; vmaddr = vmsize = fileoff = filesize = 0; nsects = 0
            segname = segname.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
            out['segments'].append({'segname': segname, 'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize})
        elif cmd == LC_SYMTAB:
            # struct symtab_command: symoff, nsyms, stroff, strsize at offset 8
            try:
                symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', cmddata, 8)
                out['symtab'] = {'symoff': symoff, 'nsyms': nsyms, 'stroff': stroff, 'strsize': strsize}
            except struct.error:
                pass
        off += cmdsize

    return out


def fileoff_to_vm(segments: List[Dict], fileoff: int) -> Optional[int]:
    for s in segments:
        fo = s['fileoff']
        fs = s['filesize']
        if fs == 0:
            continue
        if fo <= fileoff < fo + fs:
            return s['vmaddr'] + (fileoff - fo)
    return None


def vm_to_fileoff(segments: List[Dict], vm: int) -> Optional[int]:
    for s in segments:
        va = s['vmaddr']
        vs = s['vmsize']
        if vs == 0:
            continue
        if va <= vm < va + vs:
            return s['fileoff'] + (vm - va)
    return None


def parse_symtab(data: bytes, symtab: Dict) -> Dict[str, int]:
    syms = {}
    if not symtab:
        return syms
    symoff = symtab['symoff']
    nsyms = symtab['nsyms']
    stroff = symtab['stroff']
    strsize = symtab['strsize']
    if symoff + nsyms * 16 > len(data):
        return syms
    strings = data[stroff: stroff + strsize]
    for i in range(nsyms):
        ent_off = symoff + i * 16
        try:
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IbbHQ', data, ent_off)
        except struct.error:
            continue
        name = b''
        if n_strx != 0 and n_strx < len(strings):
            name = strings[n_strx: strings.find(b'\x00', n_strx)] if b'\x00' in strings[n_strx:] else strings[n_strx:]
        try:
            name_s = name.decode('utf-8', errors='ignore')
        except Exception:
            name_s = ''
        if name_s:
            syms[name_s] = n_value
    return syms


def find_strings(data: bytes, minlen=4) -> Dict[int,str]:
    res = {}
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:  # printable ASCII
            if len(cur) == 0:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                try:
                    s = cur.decode('ascii', errors='ignore')
                except Exception:
                    s = ''
                if s:
                    res[start] = s
            cur = bytearray()
    if len(cur) >= minlen:
        try:
            s = cur.decode('ascii', errors='ignore')
        except Exception:
            s = ''
        if s: res[start] = s
    return res


def scan_for_addr_occurrences(data: bytes, addr: int) -> List[int]:
    hits = []
    target = struct.pack('<Q', addr)
    off = 0
    while True:
        idx = data.find(target, off)
        if idx == -1:
            break
        hits.append(idx)
        off = idx + 1
    return hits


DEFAULT_KEYWORDS = ['rootvnode', 'allproc', 'g_allproc', 'gAllProc', 'allproc', 'filedesc', 'fd_ofiles', 'fileproc', 'f_fglob', 'vnode', 'v_data', 'proc']


def main():
    ap = argparse.ArgumentParser(description='Find candidate kernel symbols/addresses in a Mach-O kernelcache')
    ap.add_argument('--input', '-i', required=True, help='путь к распакованному kernelcache/Mach-O')
    ap.add_argument('--keywords', '-k', help='комма-разделённый список ключевых слов', default=','.join(DEFAULT_KEYWORDS))
    ap.add_argument('--minstr', type=int, default=6, help='минимальная длина строк при поиске (по умолчанию 6)')
    ap.add_argument('--scan-ptrs', action='store_true', help='искать вхождения 8-байтных указателей на найденные адреса')
    args = ap.parse_args()

    path = args.input
    if not os.path.isfile(path):
        print('Файл не найден:', path)
        sys.exit(2)

    data = open(path, 'rb').read()
    info = parse_macho(data)

    print('Файл:', path)
    if not info['is_macho']:
        print('Внимание: файл не распознан как Mach-O 64-bit. Скрипт попытается искать строки.')

    if info['segments']:
        print('\nНайдены сегменты (vmaddr, vmsize, fileoff, filesize):')
        for s in info['segments']:
            print('  %-16s vm=0x%016x sz=0x%x off=0x%x fsz=0x%x' % (s['segname'], s['vmaddr'], s['vmsize'], s['fileoff'], s['filesize']))

    # Try symbol table
    syms = {}
    if info.get('symtab'):
        syms = parse_symtab(data, info['symtab'])
        print('\nСимволы: загружено %d символов' % len(syms))
    else:
        print('\nСимволы: не найдены (LC_SYMTAB отсутствует)')

    keywords = [k.strip() for k in args.keywords.split(',') if k.strip()]

    # Search symbol table for keywords
    found = {}
    if syms:
        for name, addr in syms.items():
            lname = name.lower()
            for kw in keywords:
                if kw.lower() in lname:
                    fileoff = vm_to_fileoff(info['segments'], addr)
                    found.setdefault(kw, []).append({'sym': name, 'vm': addr, 'fileoff': fileoff})

    # If none found in symbols, fallback to string search
    if not found:
        print('\nFallback: ищем ASCII-строки в бинарнике... (minlen=%d)' % args.minstr)
        strs = find_strings(data, minlen=args.minstr)
        for off, s in strs.items():
            ls = s.lower()
            for kw in keywords:
                if kw.lower() in ls:
                    vm = fileoff_to_vm(info['segments'], off) if info['segments'] else None
                    found.setdefault(kw, []).append({'string': s, 'fileoff': off, 'vm': vm})

    if not found:
        print('\nНе найдено совпадений по ключевым словам. Попробуйте уменьшить minstr или указать другие ключи.')
    else:
        print('\nНайденные кандидаты:')
        for kw, items in found.items():
            print('\n[ %s ]' % kw)
            for it in items:
                if 'sym' in it:
                    print('  symbol: %-40s vm=0x%016x fileoff=%s' % (it['sym'], it['vm'], hex(it['fileoff']) if it['fileoff'] else 'N/A'))
                else:
                    print('  string @ fileoff=0x%08x vm=%s  text=%s' % (it['fileoff'], '0x%016x' % it['vm'] if it['vm'] else 'N/A', it['string']))

    # Optionally scan for pointer occurrences
    if args.scan_ptrs and found:
        print('\nСканирование бинарника на вхождения 8-байтных указателей (может быть медленно)...')
        for kw, items in found.items():
            for it in items:
                vm = it.get('vm')
                if not vm:
                    continue
                hits = scan_for_addr_occurrences(data, vm)
                if hits:
                    print('\n  Candidate for %s (vm=0x%016x) referenced at %d places:' % (kw, vm, len(hits)))
                    for h in hits[:20]:
                        vm2 = fileoff_to_vm(info['segments'], h)
                        print('    fileoff=0x%08x vm=%s' % (h, '0x%016x' % vm2 if vm2 else 'N/A'))


if __name__ == '__main__':
    main()
