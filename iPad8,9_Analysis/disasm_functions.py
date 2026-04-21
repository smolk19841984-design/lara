#!/usr/bin/env python3
"""Auto disassembler with prologue/epilogue detection for ARM64.

Usage examples:
  python disasm_functions.py -i /path/to/kernelcache -r 0x340d511,0x339695a 0x340d793,0x3396bdc -s 0x2000 -o out.txt

The script reads regions from the kernel file (fileoff,vm) and attempts to
find the function prologue by searching backwards for common ARM64 prologue
byte patterns. It then disassembles from the discovered start until a
`ret` instruction is found or the region end.
"""
import argparse
import os
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

PROLOGUES = [
    b"\xff\xc3\x00\xd1",  # sub sp, sp, #0x30
    b"\xfd\x7b\xbf\xa9",  # stp x29, x30, [sp, #-0x10]!
    b"\xfd\x43\x00\x91",  # add x29, sp, #0x10
]

EPILOGUES = [
    b"\xfd\x7b\xc1\xa8",  # ldp x29, x30, [sp], #0x10
    b"\xff\xc3\x00\x91",  # add sp, sp, #0x30
    b"\xc0\x03\x5f\xd6",  # ret
]


def parse_int(s):
    return int(s, 0)


def parse_region_token(tok):
    if "," not in tok:
        raise ValueError("Region tokens must be fileoff,vm")
    a, b = tok.split(",", 1)
    return parse_int(a), parse_int(b)


def find_prologue(data, region_idx, max_back=0x1000):
    start = max(0, region_idx - max_back)
    seg = data[start:region_idx]
    best = -1
    best_pat = None
    for p in PROLOGUES:
        i = seg.rfind(p)
        if i != -1:
            abs_i = start + i
            if abs_i > best:
                best = abs_i
                best_pat = p
    if best == -1:
        return None
    return best


def hexdump(data, addr, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexb = " ".join(f"{c:02x}" for c in chunk)
        ascii_repr = ''.join((chr(c) if 32 <= c < 127 else '.') for c in chunk)
        lines.append(f"{addr + i:08x}  {hexb:<{width*3}}  {ascii_repr}")
    return "\n".join(lines)


def disasm_from(data, offset, base_addr, max_bytes=None):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    out = []
    limit = len(data) if max_bytes is None else min(len(data), offset + max_bytes)
    for insn in md.disasm(data[offset:limit], base_addr + offset):
        b = insn.bytes.hex()
        out.append(f"0x{insn.address:016x}: {insn.mnemonic}\t{insn.op_str}\t; {b}")
        if insn.mnemonic == 'ret':
            out.append('--- RET (end of function) ---')
            break
        if insn.mnemonic.startswith('bl'):
            out.append(f"--- BL -> {insn.op_str} ---")
        if insn.mnemonic == 'ldp' and 'x29' in insn.op_str and 'x30' in insn.op_str:
            out.append('--- LDP x29,x30 (possible epilogue/prologue) ---')
    return out


def process_region(kernel_path, fileoff, vm_base, size=0x2000, back=0x1000, max_disasm=0x4000):
    fileoff = int(fileoff)
    vm_base = int(vm_base)
    size = int(size)
    back = int(back)
    with open(kernel_path, 'rb') as f:
        start = max(0, fileoff - back)
        end = fileoff + size
        f.seek(start)
        data = f.read(max(0, end - start))

    region_rel = fileoff - start
    prologue_idx = find_prologue(data, region_rel, max_back=back)
    func_start_rel = prologue_idx if prologue_idx is not None else region_rel
    base_vm_for_start = vm_base - (fileoff - start)

    header = []
    header.append(f"; region fileoff=0x{fileoff:x} size=0x{size:x} base_vm=0x{vm_base:016x}")
    header.append("; read file window:")
    header.append(f"; start_fileoff=0x{start:x} end_fileoff=0x{end:x} prologue_rel={prologue_idx}")
    # small hexdump around the provided fileoff
    dump_off = max(0, region_rel - 0x40)
    header.append("; hexdump around target:")
    header.append(hexdump(data[dump_off:dump_off + 0x80], start + dump_off))

    disasm = disasm_from(data, func_start_rel, base_vm_for_start, max_bytes=max_disasm)

    return "\n".join(header + ["; disassembly:"] + disasm)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-i', '--input', required=True, help='kernel file path')
    p.add_argument('-r', '--regions', nargs='+', help='regions as fileoff,vm pairs', required=True)
    p.add_argument('-s', '--size', default='0x2000', help='size to read from fileoff (default 0x2000)')
    p.add_argument('-b', '--back', default='0x1000', help='how many bytes to search backwards for prologue')
    p.add_argument('-m', '--max-disasm', default='0x4000', help='max disasm bytes\n+')
    p.add_argument('-o', '--out', required=True, help='output file')
    args = p.parse_args()

    kernel = args.input
    pairs = [parse_region_token(t) for t in args.regions]
    size = parse_int(args.size)
    back = parse_int(args.back)
    max_disasm = parse_int(args.max_disasm)

    out_lines = []
    for fileoff, vm in pairs:
        out_lines.append(process_region(kernel, fileoff, vm, size=size, back=back, max_disasm=max_disasm))
        out_lines.append('\n' + ('='*80) + '\n')

    with open(args.out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out_lines))

    print(f"Wrote disassembly output to {args.out}")


if __name__ == '__main__':
    main()
