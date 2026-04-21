#!/usr/bin/env python3
"""Find functions in __TEXT_EXEC that reference given ASCII strings.

Algorithm:
 - locate string bytes in kernel file
 - compute string VM address using __LINKEDIT mapping
 - compute page = string_vm & ~0xfff
 - disassemble __TEXT_EXEC segment and find `adrp` instructions targeting that page
 - for each adrp match, search backwards for an ARM64 prologue and report function start

Outputs a JSON report with found functions and their file offsets / VM addresses.
"""
import argparse
import json
import struct
import os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


def read32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def read64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


PROLOGUES = [b"\xfd\x7b\xbf\xa9", b"\xff\xc3\x00\xd1", b"\xfd\x43\x00\x91"]


def find_prologue_back(data, idx, max_back=0x400):
    start = max(0, idx - max_back)
    seg = data[start:idx]
    best = seg.rfind(PROLOGUES[0])
    if best != -1:
        return start + best
    # try other prologues
    for p in PROLOGUES[1:]:
        i = seg.rfind(p)
        if i != -1:
            return start + i
    return None


def parse_segments(seg_json_path):
    with open(seg_json_path, 'r', encoding='utf-8') as f:
        info = json.load(f)
    return info['segments']


def find_string_offsets(data, s):
    res = []
    off = 0
    b = s.encode('utf-8')
    while True:
        idx = data.find(b, off)
        if idx == -1:
            break
        res.append(idx)
        off = idx + 1
    return res


def run(kernel_path, seg_json, strings, out):
    segs = parse_segments(seg_json)
    # find __LINKEDIT and __TEXT_EXEC
    link = next((s for s in segs if s['name'] == '__LINKEDIT'), None)
    text_exec = next((s for s in segs if s['name'] == '__TEXT_EXEC'), None)
    if not link or not text_exec:
        print('[!] __LINKEDIT or __TEXT_EXEC not found in segments')
        return

    data = open(kernel_path, 'rb').read()

    report = {'kernel': kernel_path, 'strings': []}

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    # disassemble __TEXT_EXEC once
    te_start = text_exec['fileoff']
    te_size = text_exec['filesz']
    te_vm = text_exec['vmaddr']
    te_bytes = data[te_start:te_start + te_size]

    instrs = list(md.disasm(te_bytes, te_vm))

    for s in strings:
        s_offs = find_string_offsets(data, s)
        rec = {'string': s, 'occurrences': []}
        for off in s_offs:
            str_vm = link['vmaddr'] + (off - link['fileoff'])
            page = str_vm & ~0xfff
            occ = {'fileoff': off, 'str_vm': hex(str_vm), 'page': hex(page), 'adrp_hits': []}

            # search for adrp targeting this page
            for insn in instrs:
                if insn.mnemonic == 'adrp':
                    # try to extract immediate
                    imm = None
                    try:
                        if insn.operands and len(insn.operands) >= 2:
                            imm = insn.operands[1].imm
                    except Exception:
                        imm = None
                    if imm is None:
                        # fallback: parse op_str for hex
                        if '0x' in insn.op_str:
                            try:
                                imm = int(insn.op_str.split('0x')[-1].split()[0], 16)
                            except Exception:
                                imm = None
                    if imm is None:
                        continue
                    # imm here is the target page as provided by capstone (it gives full address)
                    if (imm & ~0xfff) == page:
                        # record hit
                        hit = {'insn_vm': hex(insn.address), 'insn_bytes': insn.bytes.hex(), 'insn_text': f"{insn.mnemonic} {insn.op_str}"}
                        # find function prologue by scanning back in te_bytes
                        # compute file offset of insn: fo = text_exec.fileoff + (insn.address - te_vm)
                        insn_fileoff = text_exec['fileoff'] + (insn.address - te_vm)
                        # translate to te_bytes index
                        idx_in_te = insn_fileoff - te_start
                        pro = find_prologue_back(te_bytes, idx_in_te, max_back=0x400)
                        if pro is not None:
                            func_fileoff = te_start + pro
                            func_vm = te_vm + (pro)
                            hit['func_fileoff'] = hex(func_fileoff)
                            hit['func_vm'] = hex(func_vm)
                        occ['adrp_hits'].append(hit)

            rec['occurrences'].append(occ)
        report['strings'].append(rec)

    with open(out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('Wrote', out)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-i','--input', required=True)
    p.add_argument('-s','--segjson', required=True)
    p.add_argument('-S','--strings', nargs='+', required=True)
    p.add_argument('-o','--out', required=True)
    args = p.parse_args()
    run(args.input, args.segjson, args.strings, args.out)


if __name__ == '__main__':
    main()
