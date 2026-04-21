#!/usr/bin/env python3
"""
disasm_regions.py

Дизассемблирует указанные регионы бинарного kernelcache (ARM64).

Использует Capstone (если доступен). Принимает список регионов в формате
`fileoff[,base_vm]` — например: `0x340d511,0x339695a`.

Пример:
  python disasm_regions.py -i kernelcache.release.iPad8,9_10_11_12 \
    -r 0x340d511,0x339695a 0x340d793,0x3396bdc -s 512 -o disasm.txt

"""
from __future__ import annotations
import argparse
import os
import struct
from typing import List, Optional, Tuple


def to_int(s: str) -> int:
    if s is None:
        raise ValueError('None')
    s = str(s).strip()
    if s.startswith(('0x', '0X')):
        return int(s, 16)
    return int(s, 0)


def parse_region_token(tok: str) -> Tuple[int, Optional[int]]:
    # token: fileoff or fileoff,base_vm
    if ',' in tok:
        a, b = tok.split(',', 1)
        return to_int(a), to_int(b)
    if ':' in tok:
        a, b = tok.split(':', 1)
        return to_int(a), to_int(b)
    return to_int(tok), None


def hexdump(buf: bytes, addr: int, width: int = 16) -> str:
    lines = []
    for i in range(0, len(buf), width):
        chunk = buf[i:i+width]
        hexs = ' '.join(f"{b:02x}" for b in chunk)
        ascii_ = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{addr + i:08x}  {hexs:<48}  {ascii_}")
    return '\n'.join(lines)


try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    HAVE_CS = True
except Exception:
    HAVE_CS = False


def disasm_chunk_arm64(chunk: bytes, base: int) -> List[str]:
    if not HAVE_CS:
        return ["; capstone not available - disassembly skipped"]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    out = []
    try:
        for insn in md.disasm(chunk, base):
            b = insn.bytes.hex()
            out.append(f"0x{insn.address:016x}: {b: <10} {insn.mnemonic} {insn.op_str}")
    except Exception as e:
        out.append(f"; capstone error: {e}")
    return out


def main():
    ap = argparse.ArgumentParser(description='Disassemble regions of an ARM64 kernelcache')
    ap.add_argument('-i', '--input', required=True, help='path to kernelcache file')
    ap.add_argument('-r', '--regions', nargs='+', required=True,
                    help='regions: fileoff[,base_vm] e.g. 0x340d511,0x339695a')
    ap.add_argument('-s', '--size', type=int, default=256, help='bytes to read per region')
    ap.add_argument('-o', '--output', help='output file (defaults to stdout)')
    args = ap.parse_args()

    path = args.input
    if not os.path.isfile(path):
        print('Input file not found:', path)
        return

    data = open(path, 'rb').read()
    results = []

    for tok in args.regions:
        try:
            fileoff, base = parse_region_token(tok)
        except Exception as e:
            results.append(f"; failed to parse region token '{tok}': {e}")
            continue

        if fileoff < 0 or fileoff >= len(data):
            results.append(f"; region fileoff 0x{fileoff:x} out of range (file size {len(data)})")
            continue

        size = min(args.size, len(data) - fileoff)
        chunk = data[fileoff:fileoff + size]

        header = [f"; region fileoff=0x{fileoff:x} size=0x{size:x} base_vm={('0x%016x' % base) if base else 'N/A'}"]
        results.extend(header)
        # hexdump (first 256 bytes or requested size)
        results.append('; hexdump:')
        results.append(hexdump(chunk[:args.size], fileoff))

        # disassemble
        results.append('; disassembly:')
        base_addr = base if base else fileoff
        dis_lines = disasm_chunk_arm64(chunk, base_addr)
        results.extend(dis_lines)
        results.append('\n')

    out_text = '\n'.join(results)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fo:
            fo.write(out_text)
        print('Disassembly saved to', args.output)
    else:
        print(out_text)


if __name__ == '__main__':
    main()
