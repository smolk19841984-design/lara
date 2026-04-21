#!/usr/bin/env python3
"""Highly experimental PAC unwrapping: try rotations, byte-swaps, XORs,
and many mask/clear combinations. Overwrites the expanded PAC JSON used by
downstream checks and also writes an experimental file.
"""
import json, struct, itertools
from collections import defaultdict

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates_experimental.json'
OUT_OVERWRITE = 'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json'

def load_segments():
    j = json.load(open(OFF_JSON))
    segs = {}
    for name,info in j.get('segments', {}).items():
        segs[name] = {'vmaddr': int(info['vmaddr'],16),'vmsize': int(info['vmsize'],16),'fileoff': int(info['fileoff'],16),'filesize': int(info['filesize'],16)}
    return segs

def in_kernel_vm(v, segments):
    for s in segments.values():
        if s['vmaddr'] <= v < s['vmaddr'] + s['vmsize']:
            return True
    return False

def vm_to_file(vm, segments):
    for seg in segments.values():
        if seg['vmaddr'] <= vm < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (vm - seg['vmaddr'])
    return None

def rol(val, bits, width=64):
    bits %= width
    return ((val << bits) & ((1<<width)-1)) | (val >> (width-bits))

def ror(val, bits, width=64):
    bits %= width
    return (val >> bits) | ((val << (width-bits)) & ((1<<width)-1))

def byteswap64(v):
    b = v.to_bytes(8,'little')
    return int.from_bytes(b[::-1],'little')

def experimental_transforms(val, kernel_base, segments):
    cands = set()
    # try rotations
    for r in range(1,16):
        v = ror(val, r)
        # try OR into canonical region
        cand = (v & ((1<<48)-1)) | 0xfffffff000000000
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + (v & ((1<<48)-1))
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)

    # try byte-swap
    bs = byteswap64(val)
    for base_try in (bs, bs & ((1<<48)-1)):
        cand = 0xfffffff000000000 | (base_try & ((1<<48)-1))
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + (base_try & ((1<<48)-1))
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)

    # try xor with common kernels/high constants
    xors = [0xfffffff000000000, 0x0000ffff00000000, 0x00000000ffffffff]
    for k in xors:
        v = val ^ k
        cand = 0xfffffff000000000 | (v & ((1<<48)-1))
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + (v & ((1<<48)-1))
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)

    # try clearing sliding 1-3 byte windows
    for start in range(0,8):
        for length in (1,2,3):
            mask = ((1<<(64 - 8*length)) - 1) & ~(((1<< (8*start))-1))
            v = val & mask
            cand = 0xfffffff000000000 | (v & ((1<<48)-1))
            if in_kernel_vm(cand, segments):
                cands.add(cand)
            cand2 = kernel_base + (v & ((1<<48)-1))
            if in_kernel_vm(cand2, segments):
                cands.add(cand2)

    # try sign-extend lower 48 bits
    low48 = val & ((1<<48)-1)
    if low48 & (1<<47):
        se = low48 | (~((1<<48)-1) & ((1<<64)-1))
    else:
        se = low48
    cand = 0xfffffff000000000 | (se & ((1<<48)-1))
    if in_kernel_vm(cand, segments):
        cands.add(cand)

    # try page +/- offsets
    for delta in (0,0x1000,0x2000,-0x1000):
        low = (val + delta) & ((1<<48)-1)
        cand = 0xfffffff000000000 | low
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + low
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)

    return sorted(cands)

def scan_data_pointers(data, segments, kernel_base):
    results = defaultdict(list)
    segs = [s for s in ('__DATA_CONST','__DATA','__CONST','__DATA_DIRTY') if s in segments]
    for segname in segs:
        s = segments[segname]
        base = s['fileoff']; size = s['filesize']
        for off in range(base, base+size-8, 8):
            val = struct.unpack_from('<Q', data, off)[0]
            if val == 0:
                continue
            cands = experimental_transforms(val, kernel_base, segments)
            for c in cands:
                results[c].append({'from_segment': segname, 'fileoff': hex(off), 'raw': hex(val)})
    return results

def sample_and_score(data, segments, candidates):
    out = {}
    for vm, refs in candidates.items():
        fo = vm_to_file(vm, segments)
        if fo is None or fo < 0 or fo >= len(data):
            continue
        sample = data[fo:fo+256]
        ascii_snip = ''.join([chr(b) if 32<=b<127 else '.' for b in sample])
        ptrs = 0
        for i in range(0, min(len(sample),64)-8,8):
            q = struct.unpack_from('<Q', sample, i)[0]
            if in_kernel_vm(q, segments):
                ptrs += 1
        smallints = []
        for i in range(0, min(len(sample),128)-4,4):
            x = struct.unpack_from('<I', sample, i)[0]
            if x < 10000:
                smallints.append({'off':hex(i),'val':x})
        score = ptrs*3 + (1 if smallints else 0)
        out[hex(vm)] = {'fileoff':hex(fo),'refs':refs,'ascii':ascii_snip[:200],'ptrs_in_sample':ptrs,'small_ints':smallints[:5],'score':score}
    return out

def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    kb = segments['__TEXT']['vmaddr'] - segments['__TEXT']['fileoff']
    print('Kernel base (unslid):', hex(kb))
    cand_map = scan_data_pointers(data, segments, kb)
    print('Experimental candidates:', len(cand_map))
    analyzed = sample_and_score(data, segments, cand_map)
    ranked = sorted(analyzed.items(), key=lambda kv: kv[1]['score'], reverse=True)
    out = {'kernel_base':hex(kb),'total_candidates':len(ranked),'ranked_candidates':[{ 'vm':k, **v } for k,v in ranked]}
    json.dump(out, open(OUT_JSON,'w'), indent=2)
    json.dump(out, open(OUT_OVERWRITE,'w'), indent=2)
    print('Wrote', OUT_JSON, 'and overwrote', OUT_OVERWRITE)

if __name__=='__main__':
    main()
