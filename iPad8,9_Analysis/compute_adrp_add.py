#!/usr/bin/env python3
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import re

KC_PATH = Path(__file__).parent / '21D61' / 'kernelcache.decompressed'
OFF_JSON = Path(__file__).parent / 'offsets.json'

def parse_mach_segments(data):
    off = 32
    ncmds = struct.unpack('<I', data[off:off+4])[0]
    segments = {}
    cur = off
    for i in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack('<II', data[cur:cur+8])
        if cmd == 0x19:
            seg_name = data[cur+8:cur+24].decode('ascii', errors='ignore').rstrip('\x00')
            vmaddr = struct.unpack('<Q', data[cur+24:cur+32])[0]
            vmsize = struct.unpack('<Q', data[cur+32:cur+40])[0]
            fileoff = struct.unpack('<Q', data[cur+40:cur+48])[0]
            segments[seg_name] = {'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff}
        cur += cmdsize
    return segments

def vm_to_fileoff(segments, vm):
    for name, seg in segments.items():
        if seg['vmaddr'] <= vm < seg['vmaddr'] + seg['vmsize']:
            fo = seg['fileoff'] + (vm - seg['vmaddr'])
            return name, fo
    return None, None

def find_all_adrp_add_targets(data, seg_vm_base, seg_fileoff, seg_size):
    # disassemble the whole segment and find adrp+add pairs, return list of (target, adrp_addr, add_addr)
    start = seg_fileoff
    end = seg_fileoff + seg_size
    slice_ = data[start:end]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(slice_, seg_vm_base))
    results = []
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            op = ins.op_str
            m = re.search(r'#?0x[0-9a-fA-F]+', op)
            if not m:
                continue
            adrp_val = int(m.group(0).lstrip('#'), 16)
            # look ahead for add to same reg within next 8 instructions
            for j in range(1, 8):
                if i+j >= len(insns):
                    break
                ins2 = insns[i+j]
                if ins2.mnemonic == 'add' and ins2.op_str.split(',')[0].strip() == ins.op_str.split(',')[0].strip():
                    m2 = re.search(r'#?0x[0-9a-fA-F]+', ins2.op_str)
                    add_val = int(m2.group(0).lstrip('#'), 16) if m2 else 0
                    target = adrp_val + add_val
                    results.append((target, ins.address, ins2.address))
                    break
    return results

def main():
    data = KC_PATH.read_bytes()
    segments = parse_mach_segments(data)
    base = segments.get('__TEXT', {}).get('vmaddr')
    if not base:
        print('Cannot find __TEXT vmaddr')
        return
    offs = json.load(open(OFF_JSON))
    # compute VM for allproc_candidate_1 for reference
    c1 = int(offs.get('allproc_candidate_1_offset', '0'), 16)
    c1_vm = base + c1
    print(f"allproc_candidate_1 VM = 0x{c1_vm:x}")

    # scan __TEXT_EXEC for adrp+add targets
    text_exec = segments.get('__TEXT_EXEC') or segments.get('__TEXT')
    results = find_all_adrp_add_targets(data, text_exec['vmaddr'], text_exec['fileoff'], text_exec['vmsize'])
    match_found = False
    for target, adrp_addr, add_addr in results:
        if target == c1_vm:
            match_found = True
            print(f"Match: adrp@0x{adrp_addr:x} add@0x{add_addr:x} -> target VM 0x{target:x}")
            tseg, tfo = vm_to_fileoff(segments, target)
            print(f"Target maps to segment={tseg} fileoff={hex(tfo) if tfo is not None else None}")
            if tfo is not None:
                q = struct.unpack('<Q', data[tfo:tfo+8])[0]
                print(f"8-byte at target: 0x{q:x}")
    if not match_found:
        print('No adrp+add pair in __TEXT_EXEC resolves to allproc_candidate_1 VM')

if __name__ == '__main__':
    main()
