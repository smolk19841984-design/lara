#!/usr/bin/env python3
"""Verify kernel offsets for iOS 17.3.1 A12X through kernelcache analysis.

This is a prelinked kernel (not fileset). Structure:
- Main Mach-O header at offset 0
- __TEXT segment (header + load commands)
- __PRELINK_TEXT (embedded kexts + kernel)
- __DATA_CONST
- __TEXT_EXEC (main kernel code)
- __PRELINK_INFO (kext metadata/plists)
- __DATA
- __LINKEDIT

The kernel itself is at __TEXT_EXEC segment.
"""

import struct

KC_PATH = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'

def main():
    with open(KC_PATH, 'rb') as f:
        data = f.read()

    print('=== Kernelcache Segments ===')
    
    # Parse main Mach-O header
    off = 32
    ncmds = struct.unpack('<I', data[off:off+4])[0]
    sizeofcmds = struct.unpack('<I', data[off+4:off+8])[0]
    off = 32
    
    segments = {}
    for i in range(ncmds):
        cmd_data = data[off:off+8]
        if len(cmd_data) < 8:
            break
        cmd = struct.unpack('<I', cmd_data[0:4])[0]
        cmdsize = struct.unpack('<I', cmd_data[4:8])[0]
        
        if cmd == 0x19:  # LC_SEGMENT_64
            seg_name = data[off+8:off+24].decode('ascii', errors='ignore').strip('\x00')
            vmaddr = struct.unpack('<Q', data[off+24:off+32])[0]
            vmsize = struct.unpack('<Q', data[off+32:off+40])[0]
            fileoff = struct.unpack('<Q', data[off+40:off+48])[0]
            filesize = struct.unpack('<Q', data[off+48:off+56])[0]
            segments[seg_name] = {'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize}
            off += cmdsize
        else:
            off += cmdsize
    
    for name, seg in segments.items():
        print(f'{name:20s} VM: 0x{seg["vmaddr"]:016X} Size: 0x{seg["vmsize"]:08X} FileOff: 0x{seg["fileoff"]:08X}')
    
    print()
    print('=== Kernel Text Analysis ===')
    
    # __TEXT_EXEC contains the main kernel code
    if '__TEXT_EXEC' in segments:
        texe = segments['__TEXT_EXEC']
        print(f'__TEXT_EXEC:')
        print(f'  VM: 0x{texe["vmaddr"]:016X} - 0x{texe["vmaddr"] + texe["vmsize"]:016X}')
        print(f'  File: 0x{texe["fileoff"]:08X} - 0x{texe["fileoff"] + texe["filesize"]:08X}')
        print(f'  Size: {texe["vmsize"] / 1024 / 1024:.1f} MB')
        
        # Search for pmap_set_pte_xprr_perm string
        print()
        print('=== String Search ===')
        
        # Find the string in __TEXT segment
        text_seg = segments.get('__TEXT', {})
        text_start = text_seg.get('fileoff', 0)
        text_end = text_start + text_seg.get('filesize', 0)
        
        # Search for pmap_set_pte_xprr_perm string
        search_str = b'pmap_set_pte_xprr_perm'
        idx = data.find(search_str)
        if idx >= 0:
            print(f'Found "{search_str.decode()}" at file offset 0x{idx:X}')
            # Calculate VM address
            for name, seg in segments.items():
                if seg['fileoff'] <= idx < seg['fileoff'] + seg['filesize']:
                    str_vm = seg['vmaddr'] + (idx - seg['fileoff'])
                    print(f'  In segment: {name}')
                    print(f'  VM address: 0x{str_vm:016X}')
                    break
        else:
            print(f'String "{search_str.decode()}" not found')
        
        # Find invalid XPRR index string
        search_str2 = b'invalid XPRR index'
        idx2 = data.find(search_str2)
        if idx2 >= 0:
            print(f'Found "{search_str2.decode()}" at file offset 0x{idx2:X}')
            for name, seg in segments.items():
                if seg['fileoff'] <= idx2 < seg['fileoff'] + seg['filesize']:
                    str_vm = seg['vmaddr'] + (idx2 - seg['fileoff'])
                    print(f'  In segment: {name}')
                    print(f'  VM address: 0x{str_vm:016X}')
                    break
    
    print()
    print('=== Candidate 1 (pmap_set_pte_xprr_perm) ===')
    print('From binary diff analysis:')
    print('  17.3.1 base: 0xFFFFFFF007F2E930')
    print('  17.4 base:   0xFFFFFFF007F2EACC')
    print()
    print('To calculate runtime address:')
    print('  runtime = base + kernel_slide')
    print('  Example with slide 0xB63C000:')
    print('  runtime = 0xFFFFFFF007F2E930 + 0xB63C000 = 0xFFFFFFF01356A930')
    
    print()
    print('=== Kernel Base Verification ===')
    # The kernel base from panic log
    panic_base = 0xFFFFFFF026780000  # From panic-full-2026-04-14-220710.000.ips
    panic_slide = 0x000000001F77C000
    print(f'Panic session kernel base: 0x{panic_base:016X}')
    print(f'Panic session kernel slide: 0x{panic_slide:016X}')
    print(f'Unslid kernel base: 0x{panic_base - panic_slide:016X}')
    print(f'Expected unslid base:   0xFFFFFFF007004000')
    
    # Verify
    unslid = panic_base - panic_slide
    if unslid == 0xFFFFFFF007004000:
        print('✓ Kernel base verified correctly')
    else:
        print(f'✗ Mismatch! Got 0x{unslid:016X}')

if __name__ == '__main__':
    main()
