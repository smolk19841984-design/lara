#!/usr/bin/env python3
import re
import json
import sys
from pathlib import Path

try:
    import capstone as cs
except Exception:
    print("Missing capstone module; install with `pip install capstone`", file=sys.stderr)
    sys.exit(1)

from glob import glob

# Try to discover a kernelcache file automatically in the workspace; fall back
# to the historical path if none found.
def find_kernel():
    p = Path('.')
    # common name patterns
    patterns = ['**/kernelcache*', '**/*kernelcache*', '**/*kernel*decompressed*', '**/*kernel*']
    for pat in patterns:
        hits = list(p.rglob(pat.replace('**/','')))
        if hits:
            return hits[0]
    # fallback
    return Path("21D61/kernelcache.decompressed")

KERNEL_PATH = find_kernel()
OUT_PATH = Path("iPad8,9_Analysis/adrp_resolved_full.json")

HEX_RE = re.compile(r"0x[0-9a-fA-F]+")

def parse_imm_from_op_str(op_str):
    m = HEX_RE.search(op_str)
    if m:
        return int(m.group(0), 16)
    return None

def main():
    if not KERNEL_PATH.exists():
        print(f"Kernel file not found: {KERNEL_PATH}", file=sys.stderr)
        sys.exit(1)

    data = KERNEL_PATH.read_bytes()
    # Parse Mach-O load commands to find __TEXT segment file offset/size and vmaddr
    if len(data) < 64:
        print("Kernel file too small", file=sys.stderr)
        sys.exit(1)
    import struct
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0xfeedfacf:
        print(f"Unexpected Mach-O magic: 0x{magic:x}", file=sys.stderr)
    ncmds = struct.unpack_from('<I', data, 16)[0]
    sizeofcmds = struct.unpack_from('<I', data, 20)[0]
    offset = 32
    text_fileoff = None
    text_filesize = None
    text_vmaddr = None
    LC_SEGMENT_64 = 0x19
    for i in range(min(ncmds, 1000)):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from('<II', data, offset)
        if cmd == LC_SEGMENT_64:
            segname = data[offset+8:offset+24].split(b'\x00',1)[0]
            if segname == b'__TEXT':
                vmaddr = struct.unpack_from('<Q', data, offset+24)[0]
                vmsize = struct.unpack_from('<Q', data, offset+32)[0]
                fileoff = struct.unpack_from('<Q', data, offset+40)[0]
                filesize = struct.unpack_from('<Q', data, offset+48)[0]
                text_fileoff = fileoff
                text_filesize = filesize
                text_vmaddr = vmaddr
                break
        offset += cmdsize

    header_end = 32 + struct.unpack_from('<I', data, 20)[0]
    if text_fileoff is None:
        print("Could not find __TEXT segment; falling back to full-file disasm", file=sys.stderr)
        text_bytes = data
        BASE = 0xfffffff007004000
    else:
        # If fileoff==0 the Mach-O header occupies the first region; start after header
        start = text_fileoff
        if text_fileoff == 0:
            start = header_end
        # ensure bounds
        end = min(len(data), text_fileoff + text_filesize)
        if start >= end:
            start = text_fileoff
        text_bytes = data[start:end]
        BASE = text_vmaddr + (start - text_fileoff)

    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    md.detail = True

    results = []
    # Disassemble the text segment (or whole file) and look for ADRP patterns
    for insn in md.disasm(text_bytes, BASE):
        if insn.mnemonic == 'adrp':
            dst = insn.op_str.split(',')[0].strip()
            # try to get page immediate
            imm = None
            if insn.operands and len(insn.operands) >= 2:
                try:
                    imm = insn.operands[1].imm
                except Exception:
                    imm = None
            if imm is None:
                imm = parse_imm_from_op_str(insn.op_str)
            # search next few insns for add/ldr using the same dst register
            ctx = []
            lookahead = 6
            # collect next instructions by disassembling a slice starting from this insn address
            addr = insn.address + 4
            resolved = None
            for _ in range(lookahead):
                try:
                    next_insn = next(md.disasm(data[(addr-BASE):], addr))
                except StopIteration:
                    break
                except Exception:
                    break
                ctx.append({'addr': hex(next_insn.address), 'mnem': next_insn.mnemonic, 'op_str': next_insn.op_str})
                # format: add x?, x?, #imm  OR ldr x?, [dst, #off]
                if next_insn.mnemonic in ('add', 'adds'):
                    parts = [p.strip() for p in next_insn.op_str.split(',')]
                    if len(parts) >= 3 and parts[0] == dst and parts[1] == dst:
                        imm_add = parse_imm_from_op_str(next_insn.op_str)
                        if imm_add is not None and imm is not None:
                            page = imm & ~0xfff
                            resolved = page + imm_add
                            break
                if next_insn.mnemonic == 'ldr':
                    if '[' in next_insn.op_str and dst in next_insn.op_str.split('[')[1]:
                        off = parse_imm_from_op_str(next_insn.op_str)
                        if off is None:
                            off = 0
                        if imm is not None:
                            page = imm & ~0xfff
                            resolved = page + off
                            break
                addr = next_insn.address + 4

            entry = {
                'adrp_addr': hex(insn.address),
                'adrp_op': insn.op_str,
                'resolved_target': hex(resolved) if resolved is not None else None,
                'context': ctx,
            }
            results.append(entry)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({'base': hex(BASE), 'count': len(results), 'results': results}, indent=2))
    print(f"Wrote {OUT_PATH} ({len(results)} ADRP sites scanned)")

if __name__ == '__main__':
    main()
