#!/usr/bin/env python3
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

KC_PATH = Path(__file__).parent / '21D61' / 'kernelcache.decompressed'
OFF_JSON = Path(__file__).parent / 'offsets.json'

def parse_mach_segments(data):
    off = 32
    ncmds = struct.unpack('<I', data[off:off+4])[0]
    sizeofcmds = struct.unpack('<I', data[off+4:off+8])[0]
    segments = {}
    cur = off
    for i in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack('<II', data[cur:cur+8])
        if cmd == 0x19:  # LC_SEGMENT_64
            seg_name = data[cur+8:cur+24].decode('ascii', errors='ignore').rstrip('\x00')
            vmaddr = struct.unpack('<Q', data[cur+24:cur+32])[0]
            vmsize = struct.unpack('<Q', data[cur+32:cur+40])[0]
            fileoff = struct.unpack('<Q', data[cur+40:cur+48])[0]
            filesize = struct.unpack('<Q', data[cur+48:cur+56])[0]
            segments[seg_name] = {'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize}
        cur += cmdsize
    return segments

def vm_to_fileoff(segments, vm):
    for name, seg in segments.items():
        if seg['vmaddr'] <= vm < seg['vmaddr'] + seg['vmsize']:
            fo = seg['fileoff'] + (vm - seg['vmaddr'])
            return name, fo
    return None, None

def hexdump(b):
    s = ''
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexs = ' '.join(f"{x:02x}" for x in chunk)
        ascii_ = ''.join((chr(x) if 32 <= x < 127 else '.') for x in chunk)
        s += f"{i:04x}: {hexs:<48}  {ascii_}\n"
    return s

def find_ascii(b, minlen=4):
    res = []
    cur = []
    for x in b:
        if 32 <= x < 127:
            cur.append(chr(x))
        else:
            if len(cur) >= minlen:
                res.append(''.join(cur))
            cur = []
    if len(cur) >= minlen:
        res.append(''.join(cur))
    return res

def disasm_window(data, start_vm, window_bytes):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    for i in md.disasm(window_bytes, start_vm):
        out.append(f"0x{i.address:x}:	{i.mnemonic}	{i.op_str}")
    return '\n'.join(out)

def main():
    data = KC_PATH.read_bytes()
    segments = parse_mach_segments(data)
    base = segments.get('__TEXT', {}).get('vmaddr')
    if not base:
        print('Cannot find __TEXT vmaddr')
        return

    with open(OFF_JSON, 'r') as f:
        offs = json.load(f)

    for k, v in offs.items():
        try:
            off_val = int(v, 16)
        except Exception:
            print(f"Skipping {k}: invalid hex")
            continue
        vm = base + off_val
        segname, fo = vm_to_fileoff(segments, vm)
        print('='*80)
        print(f"Candidate {k}: file offset 0x{off_val:x} -> VM 0x{vm:x} (segment={segname})")
        if fo is None:
            print('  Not inside any segment (cannot extract bytes)')
            continue
        start = max(0, fo - 0x100)
        end = min(len(data), fo + 0x100)
        window = data[start:end]
        print('\nHexdump around candidate (±256 bytes):')
        print(hexdump(window))
        strings = find_ascii(window)
        if strings:
            print('Nearby ASCII strings:')
            for s in strings:
                print('  ', s)
        else:
            print('No ASCII strings nearby.')

        print('\nScanning for 8-byte kernel-like pointers in window:')
        for i in range(0, len(window)-8, 8):
            q = struct.unpack('<Q', window[i:i+8])[0]
            if (q & 0xFFFFFFFF00000000) == 0xFFFFFFF000000000:
                addr = base + (start + i - segments.get('__TEXT', {}).get('fileoff',0))
                print(f"  possible ptr at +0x{i:x}: {hex(q)}")

        print('\nDisassembly around candidate (start VM = window base):')
        win_vm_base = segments[segname]['vmaddr'] + (start - segments[segname]['fileoff'])
        try:
            dis = disasm_window(data, win_vm_base, window)
            print(dis)
        except Exception as e:
            print('Disassembly failed:', e)

if __name__ == '__main__':
    main()
