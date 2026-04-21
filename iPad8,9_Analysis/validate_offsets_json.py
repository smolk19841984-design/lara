#!/usr/bin/env python3
import json
import struct
from pathlib import Path

KC_PATH = Path(__file__).parent / '21D61' / 'kernelcache.decompressed'
OFF_JSON = Path(__file__).parent / 'offsets.json'

def parse_mach_segments(data):
    # minimal Mach-O parsing for LC_SEGMENT_64
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

def read_u64_at(data, fo):
    if fo < 0 or fo + 8 > len(data):
        return None
    return struct.unpack('<Q', data[fo:fo+8])[0]

def is_kernel_ptr(x):
    return x is not None and (x & 0xFFFFFFFF00000000) == 0xFFFFFFF000000000

def main():
    data = KC_PATH.read_bytes()
    segments = parse_mach_segments(data)
    with open(OFF_JSON, 'r') as f:
        offs = json.load(f)

    base = segments.get('__TEXT', {}).get('vmaddr')
    if not base:
        print('Failed to find __TEXT vmaddr in kernelcache')
        return

    results = {}
    for k, v in offs.items():
        try:
            off_val = int(v, 16)
        except Exception:
            continue
        vm = base + off_val
        segname, fo = vm_to_fileoff(segments, vm)
        ptr = read_u64_at(data, fo) if fo is not None else None
        results[k] = {
            'offset_hex': hex(off_val),
            'vm_addr': hex(vm),
            'segment': segname,
            'file_offset': hex(fo) if fo is not None else None,
            'qword_at_addr': hex(ptr) if ptr is not None else None,
            'qword_is_kernel_ptr': bool(is_kernel_ptr(ptr))
        }

    # Pretty print
    for k, r in results.items():
        print(f"{k}: {r['offset_hex']} -> VM {r['vm_addr']} (seg={r['segment']} fileoff={r['file_offset']})")
        print(f"    qword at addr: {r['qword_at_addr']} kernel_ptr={r['qword_is_kernel_ptr']}")

if __name__ == '__main__':
    main()
