#!/usr/bin/env python3
"""Find BL instructions and 8-byte pointer cross-references to target VMs.

Outputs JSON and text report listing BL sites, computed targets, and pointer refs.
"""
import sys
import os
import argparse
import struct
import json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


def parse_int(s):
    return int(s, 0)


def fileoff_to_vm(segs, fo):
    for seg in segs:
        sf = seg['fileoff']
        sz = seg['filesz']
        if fo >= sf and fo < sf + sz:
            return seg['vmaddr'] + (fo - sf)
    return None


def vm_to_fileoff(segs, vm):
    for seg in segs:
        va = seg['vmaddr']
        vs = seg['vmsize']
        if vm >= va and vm < va + vs:
            return seg['fileoff'] + (vm - va)
    return None


def find_bl_targets(data, segs, candidates, window=0x100):
    bl_mask = 0xFC000000
    bl_val = 0x94000000
    hits = []
    for off in range(0, len(data) - 4, 4):
        insn = struct.unpack_from('<I', data, off)[0]
        if (insn & bl_mask) == bl_val:
            imm26 = insn & 0x03FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            offset = imm26 << 2
            pc_vm = fileoff_to_vm(segs, off)
            if pc_vm is None:
                continue
            target = (pc_vm + offset) & ((1 << 64) - 1)
            for cand in candidates:
                if abs(target - cand) <= window:
                    hits.append({'instr_fileoff': off, 'instr_vm': pc_vm, 'target_vm': target, 'cand_vm': cand})
                    break
    return hits


def find_pointer_occurrences(data, candidates):
    hits = []
    for cand in candidates:
        pat = struct.pack('<Q', cand)
        off = 0
        while True:
            idx = data.find(pat, off)
            if idx == -1:
                break
            hits.append({'fileoff': idx, 'cand_vm': cand})
            off = idx + 1
    return hits


def disasm_context(data, off, vm_for_off, ctx_before=32, ctx_after=64):
    start = max(0, off - ctx_before)
    end = min(len(data), off + ctx_after)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    lines = []
    for insn in md.disasm(data[start:end], vm_for_off - (off - start)):
        lines.append(f"0x{insn.address:016x}: {insn.mnemonic}\t{insn.op_str}")
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-i', '--input', required=True)
    p.add_argument('-a', '--addrs', nargs='+', help='candidate VM addresses (hex)', required=True)
    p.add_argument('-o', '--out', required=True)
    p.add_argument('--window', default='0x100')
    args = p.parse_args()

    kernel = args.input
    candidates = [parse_int(x) for x in args.addrs]
    window = parse_int(args.window)

    # import local macho parser
    spath = os.path.join(os.path.dirname(kernel), '..', 'iPad8,9_Analysis', 'Sandbox_Profiles')
    # try current repo path as fallback
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    spath_1 = os.path.join(repo_root, 'iPad8,9_Analysis', 'Sandbox_Profiles')
    if os.path.isdir(spath_1):
        spath = spath_1
    sys.path.insert(0, spath)
    try:
        import sandbox_macho_parser as smp
    except Exception as e:
        print(f"[!] Failed to import sandbox_macho_parser from {spath}: {e}")
        return

    with open(kernel, 'rb') as f:
        data = f.read()

    info = smp.parse_macho(data)
    if not info:
        print('[!] parse_macho failed')
        return
    segs = info['segments']

    bl_hits = find_bl_targets(data, segs, candidates, window=window)
    ptr_hits = find_pointer_occurrences(data, candidates)

    report = {'kernel': kernel, 'candidates': candidates, 'window': window, 'bl_hits': bl_hits, 'ptr_hits': ptr_hits}

    out_json = args.out
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # write human-readable report
    txt = out_json.replace('.json', '.txt')
    with open(txt, 'w', encoding='utf-8') as f:
        f.write(f"Kernel: {kernel}\nCandidates: {', '.join(hex(x) for x in candidates)}\nWindow: {hex(window)}\n\n")
        f.write(f"BL hits: {len(bl_hits)}\n")
        for h in bl_hits:
            f.write(f"instr_fileoff=0x{h['instr_fileoff']:x} instr_vm=0x{h['instr_vm']:x} target_vm=0x{h['target_vm']:x} cand=0x{h['cand_vm']:x}\n")
            try:
                ctx = disasm_context(data, h['instr_fileoff'], h['instr_vm'])
                f.write(ctx + '\n\n')
            except Exception:
                pass

        f.write(f"Pointer hits: {len(ptr_hits)}\n")
        for p in ptr_hits:
            f.write(f"fileoff=0x{p['fileoff']:x} points_to=0x{p['cand_vm']:x}\n")

    print(f"Wrote {out_json} and {txt}")


if __name__ == '__main__':
    main()
