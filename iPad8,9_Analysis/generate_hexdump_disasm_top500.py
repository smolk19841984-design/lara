#!/usr/bin/env python3
import json
import struct
from pathlib import Path
from find_offsets import parse_macho, vm_to_fileoff

KERNEL = Path('21D61') / 'kernelcache.decompressed'
INPUT = Path('pac_candidates_top500.json')
OUT = Path('top500_hexdump_disasm.jsonl')

def disasm_instruction(instr):
    # reuse small disasm from tools/analyze_top_candidates.py
    if instr == 0xD503201F:
        return 'nop'
    if instr == 0xD503237F:
        return 'pacibsp'
    if instr == 0xD65F0BFF:
        return 'retab'
    if instr == 0xD65F03C0:
        return 'ret'
    if (instr & 0x9F000000) == 0x90000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        return f'adrp x{rd}, #0x{imm:x}'
    if (instr & 0xFF8003FF) == 0x91000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'add x{rd}, x{rn}, #0x{imm12:x}'
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x03FFFFFF
        if imm & 0x02000000:
            imm = imm | 0xFC000000
        return f'bl #+0x{imm << 2:x}'
    return f'.word 0x{instr:08x}'

def hexdump(data: bytes) -> str:
    return data.hex()

def main():
    if not INPUT.exists():
        print('Input top500 not found:', INPUT)
        return
    kc = KERNEL
    if not kc.exists():
        print('Kernelcache not found at', kc)
        return

    kcdata = kc.read_bytes()
    info = parse_macho(kcdata)
    segments = info.get('segments', [])

    arr = json.loads(INPUT.read_text())
    outfh = OUT.open('w')

    for item in arr:
        vm_hex = item.get('vm') if isinstance(item, dict) else item
        try:
            vm = int(vm_hex, 16) if isinstance(vm_hex, str) else int(vm_hex)
        except Exception:
            continue
        fo = vm_to_fileoff(segments, vm)
        rec = {'vm': hex(vm), 'fileoff': None, 'hexdump': None, 'disasm': []}
        if fo is None:
            outfh.write(json.dumps(rec) + '\n')
            continue
        rec['fileoff'] = hex(fo)
        # read 256 bytes centered at fo (if possible)
        start = max(0, fo - 128)
        end = min(len(kcdata), fo + 128)
        chunk = kcdata[start:end]
        rec['hexdump'] = hexdump(chunk)
        # disasm up to 100 instructions starting at fo (word-aligned)
        disasm_lines = []
        max_ins = 100
        for i in range(max_ins):
            off = fo + i*4
            if off + 4 > len(kcdata):
                break
            instr = struct.unpack_from('<I', kcdata, off)[0]
            va = None
            # compute vm for this file offset
            for s in segments:
                fo_s = s['fileoff']
                fs = s['filesize']
                if fs and fo_s <= off < fo_s + fs:
                    va = s['vmaddr'] + (off - fo_s)
                    break
            disasm_lines.append({'va': hex(va) if va else None, 'instr': disasm_instruction(instr)})
        rec['disasm'] = disasm_lines
        outfh.write(json.dumps(rec) + '\n')

    outfh.close()
    print('Wrote', OUT)

if __name__ == '__main__':
    main()
