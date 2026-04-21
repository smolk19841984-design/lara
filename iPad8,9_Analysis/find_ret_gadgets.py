#!/usr/bin/env python3
"""Find gadgets that load from [sp] and are immediately followed by a `ret`.

Searches all .txt disassembly files under this folder and writes
`pmap_ret_gadgets.json` with found gadgets and context.
"""
from __future__ import annotations
import os
import re
import json
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'pmap_ret_gadgets.json')

line_re = re.compile(r'^\s*(0x[0-9a-fA-F]+):\s*(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\s*)?\s*(.*\S.*)$')
ldp_sp_re = re.compile(r'\bldp\s+(x\d+),\s*(x\d+),\s*\[sp', re.IGNORECASE)
ldr_sp_re = re.compile(r'\bldr\s+(x\d+),\s*\[sp', re.IGNORECASE)
blr_re = re.compile(r'\bblr\s+(x\d+)', re.IGNORECASE)
ret_re = re.compile(r'\b(ret|retab|retb)\b', re.IGNORECASE)


def find_disasm_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith('.txt'):
                yield os.path.join(dirpath, fn)


def parse_lines(path: str):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            raws = f.readlines()
    except Exception:
        return []
    items = []
    for i, raw in enumerate(raws):
        m = line_re.match(raw)
        if m:
            addr = m.group(1)
            instr = m.group(2).strip()
        else:
            addr = None
            instr = raw.strip()
        items.append({'addr': addr, 'instr': instr, 'raw': raw.rstrip('\n'), 'ln': i+1})
    return items


def scan_file(path: str, items: list, forward=6):
    found = []
    for i, it in enumerate(items):
        s = it['instr']
        if not s:
            continue
        m1 = ldp_sp_re.search(s)
        m2 = ldr_sp_re.search(s)
        m3 = blr_re.search(s)
        if not (m1 or m2 or m3):
            continue
        # scan ahead for a ret within forward instructions
        ret_idx = None
        for j in range(i+1, min(len(items), i+1+forward)):
            if ret_re.search(items[j]['instr']):
                ret_idx = j
                break
            # if we see an unconditional branch to elsewhere, stop scanning this seed
            if items[j]['instr'].startswith('b.') or items[j]['instr'].startswith('b\t'):
                break
        if ret_idx is None:
            continue
        context_start = max(0, i-6)
        context_end = min(len(items), ret_idx+3)
        context = [items[k]['raw'] for k in range(context_start, context_end)]
        found.append({
            'file': os.path.relpath(path, HERE).replace('\\','/'),
            'seed_addr': it['addr'],
            'seed_instr': it['instr'],
            'seed_ln': it['ln'],
            'ret_addr': items[ret_idx]['addr'],
            'ret_instr': items[ret_idx]['instr'],
            'ret_ln': items[ret_idx]['ln'],
            'context': context,
        })
    return found


def main():
    root = HERE
    all_found = []
    for f in find_disasm_files(root):
        items = parse_lines(f)
        if not items:
            continue
        res = scan_file(f, items)
        if res:
            all_found.extend(res)
    try:
        with open(OUT, 'w', encoding='utf-8') as of:
            json.dump({'count': len(all_found), 'gadgets': all_found}, of, ensure_ascii=False, indent=2)
    except Exception as e:
        print('Fail write:', e, file=sys.stderr)
        sys.exit(2)
    print(f'Found {len(all_found)} ret-terminated gadget(s), saved to {OUT}')


if __name__ == '__main__':
    main()
import struct

kernel_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
with open(kernel_path, 'rb') as f:
    data = f.read()

base_vm = 0xfffffff007004000

# Search for ldp x0, x1, [sp], #imm followed by ret within next 4 instructions
print('=== Searching for ldp x0, x1, [sp], #imm; ...; ret ===')
found = 0
for i in range(0, len(data) - 20, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    # ldp x0, x1, [sp], #imm
    if (instr0 & 0xFFC003FF) == 0xA8C003E0:
        imm = ((instr0 >> 15) & 0x7F) * 8
        # Check next 4 instructions for ret
        for j in range(1, 5):
            off = i + j * 4
            if off + 4 > len(data):
                break
            instr = struct.unpack('<I', data[off:off+4])[0]
            if instr == 0xD65F03C0:  # ret
                vm = base_vm + i
                fileoff = i
                print('  VM 0x%x (fileoff 0x%x) imm=%d ret_offset=%d' % (vm, fileoff, imm, j*4))
                found += 1
                if found >= 10:
                    break
        if found >= 10:
            break

if found == 0:
    print('  None found')

# Search for ldp x2, x3, [sp], #imm followed by ret
print('')
print('=== Searching for ldp x2, x3, [sp], #imm; ...; ret ===')
found = 0
for i in range(0, len(data) - 20, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    if (instr0 & 0xFFC003FF) == 0xA8C003E2:
        imm = ((instr0 >> 15) & 0x7F) * 8
        for j in range(1, 5):
            off = i + j * 4
            if off + 4 > len(data):
                break
            instr = struct.unpack('<I', data[off:off+4])[0]
            if instr == 0xD65F03C0:
                vm = base_vm + i
                fileoff = i
                print('  VM 0x%x (fileoff 0x%x) imm=%d ret_offset=%d' % (vm, fileoff, imm, j*4))
                found += 1
                if found >= 10:
                    break
        if found >= 10:
            break

if found == 0:
    print('  None found')

# Search for ldr x8, [sp, #imm] followed by ret
print('')
print('=== Searching for ldr x8, [sp, #imm]; ...; ret ===')
found = 0
for i in range(0, len(data) - 20, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    if (instr0 & 0xFFC003FF) == 0xF94003E8:
        imm = ((instr0 >> 10) & 0xFFF) * 8
        for j in range(1, 5):
            off = i + j * 4
            if off + 4 > len(data):
                break
            instr = struct.unpack('<I', data[off:off+4])[0]
            if instr == 0xD65F03C0:
                vm = base_vm + i
                fileoff = i
                print('  VM 0x%x (fileoff 0x%x) imm=%d ret_offset=%d' % (vm, fileoff, imm, j*4))
                found += 1
                if found >= 10:
                    break
        if found >= 10:
            break

if found == 0:
    print('  None found')

# Search for blr x8 followed by ret (unlikely but check)
print('')
print('=== Searching for blr x8; ...; ret ===')
found = 0
for i in range(0, len(data) - 20, 4):
    instr0 = struct.unpack('<I', data[i:i+4])[0]
    if (instr0 & 0xFFFFFC1F) == 0xD63F0100:  # blr x8
        for j in range(1, 5):
            off = i + j * 4
            if off + 4 > len(data):
                break
            instr = struct.unpack('<I', data[off:off+4])[0]
            if instr == 0xD65F03C0:
                vm = base_vm + i
                fileoff = i
                print('  VM 0x%x (fileoff 0x%x) ret_offset=%d' % (vm, fileoff, j*4))
                found += 1
                if found >= 10:
                    break
        if found >= 10:
            break

if found == 0:
    print('  None found')
