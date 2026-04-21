import json
import struct
import os

KERNEL_PATH = os.path.join(os.path.dirname(__file__), '..', '21D61', 'kernelcache.decompressed')
CASES_PATH = os.path.join(os.path.dirname(__file__), '..', 'pmap_in_ppl_candidates_top10.json')
OUT_PATH = os.path.join(os.path.dirname(__file__), 'kread_offline_results.json')
OFFSETS_PATH = os.path.join(os.path.dirname(__file__), '..', 'analysis_outputs', 'offsets_report.json')


def parse_macho_segments(data):
    # minimal Mach-O 64 parsing for segname, vmaddr, vmsize, fileoff, filesize
    segments = []
    # number of commands at offset 16 (little-endian)
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        # LC_SEGMENT_64 == 0x19
        if cmd == 0x19:
            segname = data[off+8:off+24].split(b"\x00", 1)[0].decode('ascii', errors='replace')
            vmaddr = struct.unpack_from('<Q', data, off+32)[0]
            vmsize = struct.unpack_from('<Q', data, off+40)[0]
            fileoff = struct.unpack_from('<Q', data, off+48)[0]
            filesize = struct.unpack_from('<Q', data, off+56)[0]
            segments.append({'segname': segname, 'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize})
        off += cmdsize
    return segments


def va_to_fileoff(segments, va):
    # try direct Mach-O vmaddr match first
    for s in segments:
        vmaddr = s['vmaddr']
        vmsize = s['vmsize']
        if vmaddr <= va < vmaddr + vmsize:
            return s['fileoff'] + (va - vmaddr)
    # otherwise return None
    return None


def read_u64_at(data, fileoff):
    if fileoff is None or fileoff + 8 > len(data):
        return None
    return struct.unpack_from('<Q', data, fileoff)[0]


def main():
    with open(KERNEL_PATH, 'rb') as f:
        kc = f.read()

    segments = parse_macho_segments(kc)
    # read kernel_base if available and adjust matching
    kernel_base = None
    if os.path.exists(OFFSETS_PATH):
        try:
            with open(OFFSETS_PATH, 'r', encoding='utf-8') as f:
                off = json.load(f)
            kernel_base = int(off.get('kernel_base', '0'), 16)
        except Exception:
            kernel_base = None

    with open(CASES_PATH, 'r', encoding='utf-8') as f:
        cases = json.load(f)

    results = {}
    for item in cases.get('top', []):
        vm_str = item.get('vm')
        if not vm_str:
            continue
        vm = int(vm_str, 16)
        # try direct Mach-O vmaddr mapping
        fileoff = va_to_fileoff(segments, vm)
        fileoff_plus8 = va_to_fileoff(segments, vm + 8)
        # if not found, try using kernel_base + segment.vmaddr mapping
        if (fileoff is None or fileoff_plus8 is None) and kernel_base is not None:
            for s in segments:
                seg_vm_start = kernel_base + s['vmaddr']
                seg_vm_end = seg_vm_start + s['vmsize']
                if seg_vm_start <= vm < seg_vm_end:
                    fileoff = s['fileoff'] + (vm - seg_vm_start)
                if seg_vm_start <= vm + 8 < seg_vm_end:
                    fileoff_plus8 = s['fileoff'] + ((vm + 8) - seg_vm_start)
                if fileoff is not None and fileoff_plus8 is not None:
                    break
        val0 = read_u64_at(kc, fileoff) if fileoff is not None else None
        val8 = read_u64_at(kc, fileoff_plus8) if fileoff_plus8 is not None else None
        results[vm_str] = {
            'fileoff': hex(fileoff) if fileoff is not None else None,
            'fileoff_plus8': hex(fileoff_plus8) if fileoff_plus8 is not None else None,
            'val0': hex(val0) if val0 is not None else None,
            'val8': hex(val8) if val8 is not None else None,
        }

    with open(OUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print('Wrote', OUT_PATH)


if __name__ == '__main__':
    main()
