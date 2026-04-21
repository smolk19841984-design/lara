#!/usr/bin/env python3
"""Extract LC_SYMTAB / nlist_64 entries and map symbol VM -> fileoff using segments.

Usage:
  python extract_kernel_symbols.py -i <kernelcache> -o out.json --symbols _pmap_in_ppl _pmap_claim_reserved_ppl_page
"""
import struct
import argparse
import json
import os


def read32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def read64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
MH_MAGIC_64 = 0xFEEDFACF


def parse_macho_header(data):
    if len(data) < 32:
        raise ValueError('data too small')
    magic = read32(data, 0)
    if magic != MH_MAGIC_64:
        raise ValueError(f'bad magic: 0x{magic:08x}')
    cpu = read32(data, 4)
    ncmds = read32(data, 16)
    sizeofcmds = read32(data, 20)
    off = 32
    segments = []
    symtab = None

    for i in range(ncmds):
        cmd = read32(data, off)
        cmdsize = read32(data, off + 4)
        if cmd == LC_SEGMENT_64:
            segname = data[off+8:off+24].rstrip(b'\x00').decode('utf-8', errors='replace')
            vmaddr = read64(data, off + 24)
            vmsize = read64(data, off + 32)
            fileoff = read64(data, off + 40)
            filesz = read64(data, off + 48)
            segments.append({'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesz': filesz})
        elif cmd == LC_SYMTAB:
            symoff = read32(data, off + 8)
            nsyms = read32(data, off + 12)
            stroff = read32(data, off + 16)
            strsize = read32(data, off + 20)
            symtab = {'symoff': symoff, 'nsyms': nsyms, 'stroff': stroff, 'strsize': strsize}
        off += cmdsize

    return {'segments': segments, 'symtab': symtab}


def nlist64_iter(data, symoff, nsyms, stroff, strsize):
    res = []
    for i in range(nsyms):
        off = symoff + i * 16
        if off + 16 > len(data):
            break
        n_strx = read32(data, off)
        n_type = data[off+4]
        n_sect = data[off+5]
        n_desc = struct.unpack_from('<H', data, off+6)[0]
        n_value = read64(data, off+8)
        name = ''
        if n_strx != 0 and (stroff + n_strx) < len(data):
            end = data.find(b'\x00', stroff + n_strx)
            if end != -1:
                name = data[stroff + n_strx:end].decode('utf-8', errors='replace')
        res.append({'name': name, 'n_type': n_type, 'n_sect': n_sect, 'n_desc': n_desc, 'n_value': n_value})
    return res


def vm_to_fileoff(segments, vm):
    for seg in segments:
        va = seg['vmaddr']
        vs = seg['vmsize']
        if vm >= va and vm < va + vs:
            return seg['fileoff'] + (vm - va)
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-i', '--input', required=True)
    p.add_argument('-o', '--out', required=True)
    p.add_argument('--symbols', nargs='+', help='symbol names to lookup', required=False)
    args = p.parse_args()

    with open(args.input, 'rb') as f:
        data = f.read()

    info = parse_macho_header(data)
    segments = info['segments']
    symtab = info['symtab']

    out = {'segments': segments, 'symtab': symtab, 'symbols': []}

    if symtab is None:
        print('[!] No LC_SYMTAB found')
    else:
        nlist = nlist64_iter(data, symtab['symoff'], symtab['nsyms'], symtab['stroff'], symtab['strsize'])
        if args.symbols:
            names = set(args.symbols)
            for e in nlist:
                if e['name'] in names:
                    fo = vm_to_fileoff(segments, e['n_value'])
                    out['symbols'].append({'name': e['name'], 'n_value': e['n_value'], 'fileoff': fo})
        else:
            # dump first 200 symbols
            for e in nlist[:200]:
                fo = vm_to_fileoff(segments, e['n_value'])
                out['symbols'].append({'name': e['name'], 'n_value': e['n_value'], 'fileoff': fo})

    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2)

    print(f"Wrote {args.out}")


if __name__ == '__main__':
    main()
