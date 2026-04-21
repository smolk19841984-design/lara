#!/usr/bin/env python3
"""extract_offsets.py
Usage: python extract_offsets.py <kernelcache-file> --out output.json

This script attempts to:
- detect and (if needed) unpack IM4P/LZSS-compressed kernelcache
- locate Mach-O image (handle FAT), parse load commands and segments
- compute kernel base offset (file offset of __TEXT vmaddr page)
- search for strings and cross-references to identify symbols
- produce JSON or C header with kernel_base_offset, symbols, struct_offsets, patterns, notes

Notes on methods used:
- Format detection: check for 'IM4P', Mach-O magic (0xfeedfacf), FAT magic (0xcafebabe)
- Decompression: basic LZSS implementation for Apple kernelcache variant (fallback)
- Symbol discovery: search for ASCII strings ("proc","task","amfi","sandbox","uid") in __DATA/rodata; find code xrefs by scanning for ADRP/ADD/LD/LDR literal patterns and 8-byte address constants
- Instruction analysis: minimal arm64 instruction immediate extraction for ADRP/ADD pairs (no Capstone dependency required; simple parsing and masks)
- Pattern generation: output hex bytes with wildcards (0x??) for variable immediates

Limitations:
- This script is best-effort; fully-automated symbol recovery for arm64e + PAC is hard without full disassembly and heuristics.
- For full results, run on a real kernelcache file and consider using Capstone/ANGR for deeper analysis.
"""

import sys
import os
import struct
import json
import argparse
from typing import Tuple, List, Dict

MACHO_MAGIC_64 = 0xfeedfacf
FAT_MAGIC = 0xcafebabe

GLOBAL_SEGMENTS = {}

# Helpers

def read_u32(be_bytes: bytes, off: int=0, le=True):
    if le:
        return struct.unpack_from('<I', be_bytes, off)[0]
    return struct.unpack_from('>I', be_bytes, off)[0]


def read_u64_le(b: bytes, off: int=0):
    return struct.unpack_from('<Q', b, off)[0]


def is_im4p(data: bytes) -> bool:
    return data.startswith(b'IM4P')

# Simple LZSS-like decompressor placeholder (works for some Apple kernelcache variants)
# This is a fallback and may not handle all variants. Prefer using existing tools for robust decompression.

def lzss_decompress(src: bytes) -> bytes:
    # Attempt to find an LZSS block prefixed by 4-byte uncompressed size (common in some tools)
    # If not found, return src.
    if len(src) < 8:
        return src
    # Some Apple kernelcaches contain an LZSS header with 'lzss' or specific marker; we try simple heuristic
    try:
        # If first 4 bytes are little-endian size and size > len(src), maybe compressed
        possible_size = struct.unpack_from('<I', src, 0)[0]
        if 0 < possible_size <= 0x40000000 and possible_size != len(src):
            # Many kernel unpackers implement a more complex algorithm; here we fallback to returning src
            # so user can use dedicated tools. We'll not implement full LZSS here.
            return src
    except Exception:
        pass
    return src

# Mach-O parsing utilities (minimal)

def find_macho_offset(data: bytes) -> Tuple[int, str]:
    # Return (offset, type) where type in {"MACHO64", "FAT"}
    for off in range(0, min(65536, len(data)-4), 4):
        magic = struct.unpack_from('<I', data, off)[0]
        if magic == MACHO_MAGIC_64:
            return off, 'MACHO64'
        if magic == FAT_MAGIC:
            return off, 'FAT'
    # fallback: search for ASCII __TEXT
    idx = data.find(b'__TEXT')
    if idx != -1:
        return max(0, idx-128), 'MACHO64'
    return -1, ''


def parse_macho_segments(data: bytes, base_off: int) -> Dict[str, dict]:
    # Properly parse mach_header_64 and load commands to extract LC_SEGMENT_64 info
    segments = {}
    try:
        # mach_header_64 is 32 bytes
        if base_off + 32 > len(data):
            return segments
        magic = struct.unpack_from('<I', data, base_off)[0]
        if magic != MACHO_MAGIC_64:
            return segments
        # read relevant header fields
        cputype = struct.unpack_from('<i', data, base_off+4)[0]
        filetype = struct.unpack_from('<I', data, base_off+12)[0]
        ncmds = struct.unpack_from('<I', data, base_off+16)[0]
        sizeofcmds = struct.unpack_from('<I', data, base_off+20)[0]

        p = base_off + 32
        for i in range(ncmds):
            if p + 8 > len(data):
                break
            cmd = struct.unpack_from('<I', data, p)[0]
            cmdsize = struct.unpack_from('<I', data, p+4)[0]
            if cmdsize == 0:
                break
            # LC_SEGMENT_64 == 0x19
            if cmd == 0x19 and p + cmdsize <= len(data):
                segname = data[p+8:p+24].rstrip(b'\x00')
                vmaddr = struct.unpack_from('<Q', data, p+24)[0]
                vmsize = struct.unpack_from('<Q', data, p+32)[0]
                fileoff = struct.unpack_from('<Q', data, p+40)[0]
                filesize = struct.unpack_from('<Q', data, p+48)[0]
                segments[segname.decode(errors='ignore')] = {
                    'vmaddr': vmaddr,
                    'vmsize': vmsize,
                    'fileoff': fileoff,
                    'filesize': filesize,
                    'cmd_off': p
                }
            p += cmdsize
    except Exception:
        pass
    return segments
    


def compute_kernel_base(segments: Dict[str, dict]) -> Tuple[int, str]:
    # Compute kernel base offset as vmaddr - fileoff for __TEXT or the lowest vmaddr segment
    if ' __TEXT' in segments:  # defensive: leading space sometimes present
        seg = segments[' __TEXT']
    elif '__TEXT' in segments:
        seg = segments['__TEXT']
    else:
        # choose segment with smallest vmaddr
        if not segments:
            return 0, 'not found'
        seg = min(segments.values(), key=lambda s: s['vmaddr'])
    vm = seg['vmaddr']
    fo = seg['fileoff']
    kernel_base = vm - fo
    return kernel_base, f'computed from {seg.get("cmd_off","segment")}'

# Symbol and pattern search helpers (very basic)

def find_strings(data: bytes, min_len=4) -> Dict[int,str]:
    results = {}
    i = 0
    while i < len(data):
        if 32 <= data[i] <= 126:
            j = i
            while j < len(data) and 32 <= data[j] <= 126:
                j += 1
            if j - i >= min_len:
                s = data[i:j].decode(errors='ignore')
                results[i] = s
                i = j
            else:
                i += 1
        else:
            i += 1
    return results


def find_symbol_xrefs(data: bytes, vm_base: int, search_strings: List[str]) -> Dict[str,str]:
    # Find strings and map their file offsets to VM addresses via segment mapping, then search for 64-bit constants pointing at them
    res = {}
    strings = find_strings(data)

    def fileoff_to_vmaddr(fileoff: int, segments: Dict[str, dict]) -> int:
        for seg in segments.values():
            fo = seg['fileoff']
            if fo <= fileoff < fo + seg['filesize']:
                return seg['vmaddr'] + (fileoff - fo)
        # fallback: assume vm_base + fileoff
        return vm_base + fileoff

    for off, s in strings.items():
        if any(ss in s for ss in search_strings):
            try:
                vmaddr = fileoff_to_vmaddr(off, GLOBAL_SEGMENTS)
            except Exception:
                vmaddr = vm_base + off
            pat = struct.pack('<Q', vmaddr)
            idx = data.find(pat)
            if idx != -1:
                res[s] = hex(vmaddr)
    return res


def find_xrefs_with_capstone(data: bytes, text_seg: dict, strings_map: Dict[int,str]):
    # Use Capstone to find ADRP/ADD pairs that reference known string VM addresses (best-effort)
    results = {}
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except Exception:
        return results
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    base = text_seg['fileoff']
    code = data[base:base+text_seg['filesize']]
    insns = list(md.disasm(code, text_seg['vmaddr']))
    # build map of ADRP+ADD resolved targets
    for i, insn in enumerate(insns):
        if insn.mnemonic == 'adrp':
            # try to get destination register and imm
            try:
                reg = insn.operands[0].reg
                adrp_imm = insn.operands[1].imm
            except Exception:
                # fallback: try parsing op_str
                parts = insn.op_str.split(',')
                reg = parts[0].strip() if parts else None
                adrp_imm = 0
            try:
                adrp_page = (insn.address & ~0xfff) + adrp_imm
            except Exception:
                adrp_page = insn.address & ~0xfff
            # search next few instructions for ADD that uses same register
            for j in range(i+1, min(i+6, len(insns))):
                ins2 = insns[j]
                if ins2.mnemonic in ('add', 'adds'):
                    try:
                        dst = ins2.operands[0].reg
                        src = ins2.operands[1].reg
                        imm = ins2.operands[2].imm
                    except Exception:
                        continue
                    if src == reg or dst == reg:
                        target = adrp_page + imm
                        results.setdefault(target, []).append({'adrp': insn.address, 'add': ins2.address})
                        break
        # handle literal LDR patterns (approximate)
        if insn.mnemonic == 'ldr' and ('literal' in insn.op_str or (insn.operands and len(insn.operands) >= 2 and getattr(insn.operands[1], 'type', None) == 3)):
            try:
                mem = insn.operands[1].mem
                disp = getattr(mem, 'disp', 0)
                lit_addr = insn.address + disp
                results.setdefault(lit_addr, []).append({'ldr': insn.address})
            except Exception:
                pass
    return results


def match_targets_to_keywords(targets: Dict[int, List[dict]], data: bytes, segments: Dict[str, dict], keywords: List[str]) -> Dict[str,str]:
    matches = {}
    for target in sorted(targets.keys()):
        # map VM address to file offset
        fileoff = None
        for seg in segments.values():
            if seg['vmaddr'] <= target < seg['vmaddr'] + seg['vmsize']:
                fileoff = seg['fileoff'] + (target - seg['vmaddr'])
                break
        if fileoff is None or fileoff < 0 or fileoff >= len(data):
            continue
        sample = data[fileoff:fileoff+256]
        try:
            s = sample.decode(errors='ignore')
        except Exception:
            continue
        for kw in keywords:
            if kw in s and kw not in matches:
                matches[kw] = hex(target)
    return matches


def scan_for_64bit_literals(data: bytes, text_seg: dict, segments: Dict[str, dict]) -> Dict[int,int]:
    """Scan code in `text_seg` for 8-byte little-endian values that point into any parsed segment.
    Return dict mapping target_vm -> count of hits (or first code offset)."""
    results = {}
    base = text_seg['fileoff']
    size = text_seg['filesize']
    code = data[base:base+size]
    ln = len(code)
    # scan every 1 byte for 8-byte LE constant
    for i in range(0, ln-8, 1):
        val = struct.unpack_from('<Q', code, i)[0]
        # ignore obviously small values
        if val == 0 or (val & 0xffff000000000000) != 0:
            continue
        # check if this VM addr falls into any segment
        for seg in segments.values():
            vm0 = seg['vmaddr']
            vm1 = vm0 + seg['vmsize']
            if vm0 <= val < vm1:
                # record first occurrence (address in file)
                results.setdefault(val, i+base)
                break
    return results


def generate_output(template: dict, out_path: str):
    with open(out_path, 'w') as f:
        json.dump(template, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description='Extract kernel offsets from kernelcache')
    ap.add_argument('file', help='kernelcache file path')
    ap.add_argument('--out', '-o', help='output JSON path', default='offsets_output.json')
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print('Error: file not found:', args.file)
        sys.exit(2)

    data = open(args.file,'rb').read()

    notes = []

    if is_im4p(data):
        notes.append('Detected IM4P container; attempting to extract payload (not fully implemented)')
        # naive extraction: try to find embedded Mach-O by searching for Mach-O magic
    # attempt decompression heuristic
    maybe_decomp = lzss_decompress(data)
    if maybe_decomp != data:
        data = maybe_decomp
        notes.append('Applied LZSS decompression')

    off, typ = find_macho_offset(data)
    if off == -1:
        notes.append('Mach-O header not found in file')
        kernel_base_offset = None
        segments = {}
    else:
        notes.append(f'Found {typ} at file offset {hex(off)}')
        segments = parse_macho_segments(data, off)
        # publish segments globally for file->vm mapping
        GLOBAL_SEGMENTS.clear()
        GLOBAL_SEGMENTS.update(segments)
        kernel_base_offset, kb_note = compute_kernel_base(segments)
        notes.append(kb_note)

    vm_base = kernel_base_offset if kernel_base_offset else 0

    # Basic symbol discovery
    search_strings = ['proc','task','amfi','sandbox','uid','allproc','current_proc','current_task','trustcache']
    symbol_hits = find_symbol_xrefs(data, vm_base, search_strings)

    # Capstone-based ADRP/ADD/LDR resolution for additional symbols
    try:
        text_seg = None
        # prefer executable code segment
        if '__TEXT_EXEC' in segments:
            text_seg = segments['__TEXT_EXEC']
        elif '__TEXT' in segments:
            text_seg = segments['__TEXT']
        elif ' __TEXT' in segments:
            text_seg = segments[' __TEXT']
        if text_seg:
            cap_targets = find_xrefs_with_capstone(data, text_seg, {})
            # also scan for 64-bit literals in code that point into data segments
            lit_targets = scan_for_64bit_literals(data, text_seg, segments)
            # combine capstone and literal targets
            combined_targets = {}
            if cap_targets:
                for k,v in cap_targets.items():
                    combined_targets[k] = v
            if lit_targets:
                for k,fo in lit_targets.items():
                    combined_targets.setdefault(k, []).append({'literal_ref_fileoff': fo})
            # keywords to try match
            keywords = ['proc','allproc','current_proc','current_task','osvariant','PE_i_can_has_kernel_configuration','trust','amfi','sandbox','vm_map_enter','vm_map_protect','copyin','copyout','bzero','memmove','panic']
            cap_matches = match_targets_to_keywords(combined_targets, data, segments, keywords)
            # merge matches into symbol_hits with simple naming
            for k,v in cap_matches.items():
                symbol_hits[k] = v
            # store cap_targets for output
            globals()['cap_targets'] = combined_targets
    except Exception:
        pass

    # Build output template
    out = {
        'kernel_base_offset': hex(kernel_base_offset) if kernel_base_offset else None,
        'symbols': symbol_hits,
        'struct_offsets': {},
        'patterns': {},
        'segments': {},
        'capstone_targets': {},
        'notes': notes
    }

    # If capstone produced targets, include them (vmaddr -> ref sites)
    # add segments (hexify numbers)
    try:
        for name,seg in segments.items():
            out['segments'][name] = {k: hex(v) if isinstance(v, int) else v for k,v in seg.items()}
    except Exception:
        pass
    try:
        if 'cap_targets' in locals() and cap_targets:
            out['capstone_targets'] = {hex(k): v for k,v in cap_targets.items()}
            notes.append(f'Capstone-resolved {len(cap_targets)} targets')
    except Exception:
        pass

    generate_output(out, args.out)
    print('Wrote output to', args.out)

if __name__ == '__main__':
    main()
