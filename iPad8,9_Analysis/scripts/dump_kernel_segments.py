import struct
import json
import os

KERNEL_PATH = os.path.join(os.path.dirname(__file__), '..', '21D61', 'kernelcache.decompressed')
OFFSETS_PATH = os.path.join(os.path.dirname(__file__), '..', 'analysis_outputs', 'offsets_report.json')


def parse_macho_segments(data):
    segments = []
    try:
        ncmds = struct.unpack_from('<I', data, 16)[0]
    except Exception:
        return segments
    off = 32
    for i in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == 0x19 and off + cmdsize <= len(data):
            segname = data[off+8:off+24].split(b'\x00',1)[0].decode('ascii', errors='replace')
            vmaddr = struct.unpack_from('<Q', data, off+32)[0]
            vmsize = struct.unpack_from('<Q', data, off+40)[0]
            fileoff = struct.unpack_from('<Q', data, off+48)[0]
            filesize = struct.unpack_from('<Q', data, off+56)[0]
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize if cmdsize > 0 else 4
    return segments


def main():
    with open(KERNEL_PATH, 'rb') as f:
        kc = f.read()

    segs = parse_macho_segments(kc)
    print('Parsed segments count:', len(segs))
    for s in segs:
        print(f"{s[0]:16s} vmaddr=0x{s[1]:x} vmsize=0x{s[2]:x} fileoff=0x{s[3]:x} filesize=0x{s[4]:x}")

    if os.path.exists(OFFSETS_PATH):
        with open(OFFSETS_PATH, 'r', encoding='utf-8') as f:
            off = json.load(f)
        print('\nOffsets report:')
        print('kernel_base:', off.get('kernel_base'))
        print('kernel_slide:', off.get('kernel_slide'))
    else:
        print('\nNo offsets_report.json found')


if __name__ == '__main__':
    main()
