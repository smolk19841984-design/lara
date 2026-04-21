#!/usr/bin/env python3
"""Scan __TEXT_EXEC for ARM64 prologues and record BL targets.

Produces JSON with list of candidate functions (fileoff, vm, bl_count, bl_targets).
"""
import json, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


PROLOGUE = b"\xfd\x7b\xbf\xa9"


def scan(kernel_path, segjson, out, max_funcs=5000):
    segs = json.load(open(segjson))['segments']
    te = next(s for s in segs if s['name']=='__TEXT_EXEC')
    start = te['fileoff']
    size = te['filesz']
    vm = te['vmaddr']
    data = open(kernel_path,'rb').read()
    buf = data[start:start+size]

    # find prologues
    idx = 0
    hits = []
    while True:
        idx = buf.find(PROLOGUE, idx)
        if idx == -1:
            break
        func_fileoff = start + idx
        func_vm = vm + idx
        hits.append({'fileoff': func_fileoff, 'vm': func_vm, 'idx': idx})
        idx += 4
        if len(hits) >= max_funcs:
            break

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    results = []
    for h in hits:
        idx = h['idx']
        # disasm 0x400 bytes from idx
        code = buf[idx:idx+0x400]
        bl_targets = []
        for insn in md.disasm(code, vm + idx):
            if insn.mnemonic.startswith('bl'):
                # try to parse immediate from op_str
                op = insn.op_str
                tgt = None
                if '0x' in op:
                    try:
                        tgt = int(op.split('0x')[-1].split()[0],16)
                    except Exception:
                        tgt = None
                bl_targets.append(tgt)
        results.append({'func_fileoff': hex(h['fileoff']), 'func_vm': hex(h['vm']), 'bl_count': len(bl_targets), 'bl_targets': [hex(t) if t else None for t in bl_targets]})

    with open(out,'w',encoding='utf-8') as f:
        json.dump({'kernel': kernel_path, 'text_exec': te, 'functions': results}, f, indent=2)
    print('Wrote', out)


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-i','--input', required=True)
    p.add_argument('-s','--segjson', required=True)
    p.add_argument('-o','--out', required=True)
    args = p.parse_args()
    scan(args.input, args.segjson, args.out)


if __name__ == '__main__':
    main()
