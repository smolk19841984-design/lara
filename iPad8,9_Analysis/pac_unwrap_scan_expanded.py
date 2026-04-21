#!/usr/bin/env python3
"""Expanded PAC-unwrapping scan with aggressive masks and tag-clearing combos.
Writes offsets_iPad8_9_17.3.1_pac_candidates_expanded.json
"""
import json, struct
from collections import defaultdict

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json'

def load_segments():
    j = json.load(open(OFF_JSON))
    segs = {}
    for name,info in j.get('segments', {}).items():
        segs[name] = {
            'vmaddr': int(info['vmaddr'],16),
            'vmsize': int(info['vmsize'],16),
            'fileoff': int(info['fileoff'],16),
            'filesize': int(info['filesize'],16),
        }
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

def try_masks(val, kernel_base, segments):
    cands = set()
    # try a broader range of mask widths
    for m in range(12, 60, 4):
        low = val & ((1 << m) - 1)
        # OR into canonical high kernel region
        cand_a = (0xfffffff000000000 & ~((1 << m) - 1)) | low
        if in_kernel_vm(cand_a, segments):
            cands.add(cand_a)
        # add kernel_base + low (unslid mapping)
        cand_b = kernel_base + low
        if in_kernel_vm(cand_b, segments):
            cands.add(cand_b)

    # try clearing varying numbers of top tag bytes
    for clear_bytes in range(1, 8):
        mask = (1 << (64 - 8 * clear_bytes)) - 1
        low = val & mask
        cand = low | 0xfffffff000000000
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + low
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)

    # try clearing and rotating small windows where PAC bits sometimes live
    for shift in range(0, 16, 4):
        mask = ~(((1 << 16) - 1) << shift) & ((1<<64)-1)
        low = val & mask
        cand = (low & ((1 << 48) - 1)) | 0xfffffff000000000
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + (low & ((1<<48)-1))
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)

    # try XOR/flip heuristics with kernel high bits
    xor_candidate = (val ^ 0xfffffff000000000) & ((1<<48)-1)
    cand_x = 0xfffffff000000000 | xor_candidate
    if in_kernel_vm(cand_x, segments):
        cands.add(cand_x)

    # zero out high half and try OR'ing into canonical high
    half = val & ((1<<32)-1)
    cand_h = 0xfffffff000000000 | half
    if in_kernel_vm(cand_h, segments):
        cands.add(cand_h)

    # try small adjustments +/- common page offsets
    for delta in (0, 0x1000, -0x1000, 0x2000):
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
    for segname in ('__DATA_CONST','__DATA','__CONST','__DATA_DIRTY'):
        if segname not in segments:
            continue
        s = segments[segname]
        base = s['fileoff']; size = s['filesize']
        for off in range(base, base+size-8, 8):
            val = struct.unpack_from('<Q', data, off)[0]
            if val == 0:
                continue
            cands = try_masks(val, kernel_base, segments)
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
        score = ptrs*2 + (1 if smallints else 0)
        out[hex(vm)] = {'fileoff':hex(fo),'refs':refs,'ascii':ascii_snip[:200],'ptrs_in_sample':ptrs,'small_ints':smallints[:5],'score':score}
    return out

def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    kb = segments['__TEXT']['vmaddr'] - segments['__TEXT']['fileoff']
    print('Kernel base (unslid):', hex(kb))
    cand_map = scan_data_pointers(data, segments, kb)
    print('Candidates after expanded PAC-mask heuristics:', len(cand_map))
    analyzed = sample_and_score(data, segments, cand_map)
    ranked = sorted(analyzed.items(), key=lambda kv: kv[1]['score'], reverse=True)
    out = {'kernel_base':hex(kb),'total_candidates':len(ranked),'ranked_candidates':[{ 'vm':k, **v } for k,v in ranked]}
    json.dump(out, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON)

if __name__=='__main__':
    main()
