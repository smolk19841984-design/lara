#!/usr/bin/env python3
"""Disassemble ADRP+ADD candidates produced earlier and save per-candidate outputs.
Usage: run from workspace root or directly. Paths are set by defaults below.
"""
import os
import re
import json
import struct
from pathlib import Path

# Config — adjust if needed
KERNEL_PATH = r"C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed"
ADRP_OUTPUT_PATH = r"C:\Users\smolk\AppData\Roaming\Code\User\workspaceStorage\2876236d5a2488123aff328d6fbae810\GitHub.copilot-chat\chat-session-resources\39efcf71-e79a-4d8b-8261-e0db4fbb43f0\call_DXTZ7pIkJlIin8KuzrjnZvpG__vscode-1776066505629\content.txt"
OUT_DIR = r"C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\xprr_adrp_candidates"
BASE_VM = 0xfffffff007004000
RADIUS = 0x80  # bytes before/after candidate

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception:
    print("capstone not installed — please run: pip install capstone")
    raise

ADRP_RE = re.compile(r'ADRP\+ADD at VM 0x([0-9a-fA-F]+) \(fileoff 0x([0-9a-fA-F]+)\): page=0x([0-9a-fA-F]+) add_imm=0x([0-9a-fA-F]+)')
ADRP_RE2 = re.compile(r'ADRP\+ADD at VM 0x([0-9a-fA-F]+) \(fileoff 0x([0-9a-fA-F]+)\)')


def parse_adrp_file(path):
    candidates = []
    with open(path, 'r', errors='ignore') as f:
        for ln in f:
            m = ADRP_RE.search(ln)
            if m:
                vm = int(m.group(1), 16)
                fo = int(m.group(2), 16)
                page = int(m.group(3), 16)
                add = int(m.group(4), 16)
                candidates.append({'vm': vm, 'fileoff': fo, 'page': page, 'add_imm': add, 'line': ln.strip()})
    if not candidates:
        # fallback: looser match
        with open(path, 'r', errors='ignore') as f:
            for ln in f:
                m = ADRP_RE2.search(ln)
                if m:
                    vm = int(m.group(1), 16)
                    fo = int(m.group(2), 16)
                    candidates.append({'vm': vm, 'fileoff': fo, 'page': None, 'add_imm': None, 'line': ln.strip()})
    return candidates


def disasm_bytes(data, start, end, vm_addr):
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cs.detail = False
    code = data[start:end]
    out = []
    for i in cs.disasm(code, vm_addr):
        out.append((i.address, i.bytes.hex(), i.mnemonic, i.op_str))
    return out


def format_insns(insns):
    lines = []
    for a, hb, mnem, ops in insns:
        lines.append(f"0x{a:016x}: {hb}  {mnem}\t{ops}")
    return "\n".join(lines)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"Reading ADRP output from: {ADRP_OUTPUT_PATH}")
    candidates = parse_adrp_file(ADRP_OUTPUT_PATH)
    if not candidates:
        print("No ADRP+ADD candidates found in the ADRP output file.")
        return
    # dedupe by fileoff, keep first
    seen = set()
    uniq = []
    for c in candidates:
        fo = c['fileoff']
        if fo in seen:
            continue
        seen.add(fo)
        uniq.append(c)
    candidates = sorted(uniq, key=lambda x: x['fileoff'])
    print(f"Found {len(candidates)} unique ADRP+ADD candidates")

    # load kernel
    with open(KERNEL_PATH, 'rb') as f:
        data = f.read()

    index = []
    interesting = []
    for idx, c in enumerate(candidates, 1):
        fo = c['fileoff']
        vm = BASE_VM + fo
        start = max(0, fo - RADIUS)
        end = min(len(data), fo + RADIUS)
        insns = disasm_bytes(data, start, end, BASE_VM + start)
        text = f"; Candidate {idx}\n; {c['line']}\n\n" + format_insns(insns) + "\n"
        fname = f"vm_{vm:016x}_fo_{fo:08x}.txt"
        outpath = os.path.join(OUT_DIR, fname)
        with open(outpath, 'w', encoding='utf-8') as of:
            of.write(text)
        # scan for interesting mnemonics
        mnems = ' '.join([m for (_, _, m, _) in insns])
        notes = []
        if 'ubfx' in mnems:
            notes.append('ubfx')
        if 'bfi' in mnems:
            notes.append('bfi')
        if 'stxr' in mnems or 'stlxr' in mnems:
            notes.append('stx/strx')
        if 'ldr' in mnems and 'str' in mnems:
            notes.append('ldr+str nearby')
        entry = {'vm': hex(vm), 'fileoff': hex(fo), 'out': outpath, 'notes': notes}
        index.append(entry)
        if notes:
            interesting.append(entry)
        if idx % 50 == 0:
            print(f"Processed {idx}/{len(candidates)} candidates")

    # write index and report
    idxf = os.path.join(OUT_DIR, 'index.json')
    with open(idxf, 'w', encoding='utf-8') as jf:
        json.dump(index, jf, indent=2)

    rpt = os.path.join(OUT_DIR, 'report.txt')
    with open(rpt, 'w', encoding='utf-8') as rf:
        rf.write(f"ADRP+ADD disassembly report\nCandidates: {len(candidates)}\nInteresting: {len(interesting)}\n\n")
        for it in interesting:
            rf.write(f"{it['vm']} fileoff={it['fileoff']} notes={it['notes']} out={it['out']}\n")

    print(f"Done. Wrote per-candidate files to: {OUT_DIR}")
    print(f"Index: {idxf}")
    print(f"Report: {rpt}")

if __name__ == '__main__':
    main()
