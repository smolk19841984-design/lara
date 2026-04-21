#!/usr/bin/env python3
import json
import struct
from pathlib import Path
from find_offsets import parse_macho, vm_to_fileoff
import argparse

def disasm_instruction(instr):
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', '-i', required=True, help='PAC top-N JSON')
    ap.add_argument('--n', type=int, default=200, help='Number of top candidates to process')
    ap.add_argument('--outdir', '-o', default='manual_re_topN', help='Output directory')
    args = ap.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print('Input missing:', input_path); return
    kc_path = Path('21D61') / 'kernelcache.decompressed'
    if not kc_path.exists():
        print('Kernelcache missing:', kc_path); return

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    kc = kc_path.read_bytes()
    info = parse_macho(kc)
    segs = info.get('segments', [])

    arr = json.loads(input_path.read_text())
    arr = arr[:args.n]
    for idx, item in enumerate(arr, start=1):
        vm_raw = item.get('vm') if isinstance(item, dict) else item
        try:
            vm = int(vm_raw, 16) if isinstance(vm_raw, str) else int(vm_raw)
        except Exception:
            continue
        fo = vm_to_fileoff(segs, vm)
        outfile = outdir / f'{idx:04d}_{vm:016x}.txt'
        with outfile.open('w') as f:
            f.write(f'VM: 0x{vm:016x}\n')
            f.write(f'Fileoff: {hex(fo) if fo else "N/A"}\n\n')
            if not fo:
                continue
            start = max(0, fo - 256)
            end = min(len(kc), fo + 256)
            f.write('Hexdump (centered 512 bytes):\n')
            f.write(kc[start:end].hex() + '\n\n')
            f.write('Disasm (up to 200 instr starting at fileoff):\n')
            for i in range(200):
                off = fo + i*4
                if off + 4 > len(kc): break
                instr = struct.unpack_from('<I', kc, off)[0]
                va = None
                for s in segs:
                    fo_s = s['fileoff']; fs = s['filesize']
                    if fs and fo_s <= off < fo_s + fs:
                        va = s['vmaddr'] + (off - fo_s); break
                f.write(f'{hex(va) if va else "N/A"}: {disasm_instruction(instr)}\n')

    print('Wrote manual RE files to', outdir)

if __name__ == '__main__':
    main()
