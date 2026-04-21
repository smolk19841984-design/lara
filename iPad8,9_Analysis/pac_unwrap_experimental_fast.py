#!/usr/bin/env python3
"""Faster experimental PAC unwrapping with pre-filtering of qwords by
likely-tagged/high-bit patterns. Writes experimental PAC JSON and
overwrites expanded file used by downstream checks.
"""
import json, struct
from collections import defaultdict

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates_experimental_fast.json'
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

def try_quick_transforms(val, kernel_base, segments):
    # very small set of transforms but effective: clear top bytes, OR into kernel
    cands = set()
    low48 = val & ((1<<48)-1)
    cand = 0xfffffff000000000 | low48
    if in_kernel_vm(cand, segments):
        cands.add(cand)
    cand2 = kernel_base + low48
    if in_kernel_vm(cand2, segments):
        cands.add(cand2)
    # try clearing top 1-3 bytes
    for cb in (1,2,3):
        mask = (1 << (64 - 8*cb)) - 1
        low = val & mask
        cand = 0xfffffff000000000 | (low & ((1<<48)-1))
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + (low & ((1<<48)-1))
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)
    return sorted(cands)

def scan_filtered(data, segments, kernel_base):
    results = defaultdict(list)
    segs = [s for s in ('__DATA_CONST','__DATA','__CONST','__DATA_DIRTY') if s in segments]
    total_checked = 0
    for segname in segs:
        s = segments[segname]
        base = s['fileoff']; size = s['filesize']
        for off in range(base, base+size-8, 8):
            val = struct.unpack_from('<Q', data, off)[0]
            if val == 0:
                continue
            # quick filter: prefer values with high byte >= 0xf0 or nonzero high half
            hb = (val >> 56) & 0xff
            high16 = (val >> 48) & 0xffff
            if not (hb >= 0xf0 or high16 != 0):
                continue
            total_checked += 1
            cands = try_quick_transforms(val, kernel_base, segments)
            for c in cands:
                results[c].append({'from_segment': segname, 'fileoff': hex(off), 'raw': hex(val)})
    print('Filtered qwords checked:', total_checked)
    return results

def sample_and_score(data, segments, candidates):
    out = {}
    for vm, refs in candidates.items():
        vm_int = int(vm,16) if isinstance(vm, str) else vm
        fo = None
        for seg in segments.values():
            if seg['vmaddr'] <= vm_int < seg['vmaddr'] + seg['vmsize']:
                fo = seg['fileoff'] + (vm_int - seg['vmaddr'])
                break
        if fo is None or fo < 0 or fo >= len(data):
            continue
        sample = data[fo:fo+128]
        ptrs = 0
        for i in range(0, min(len(sample),64)-8,8):
            q = struct.unpack_from('<Q', sample, i)[0]
            if in_kernel_vm(q, segments):
                ptrs += 1
        out[hex(vm_int)] = {'fileoff':hex(fo),'refs':refs,'ptrs_in_sample':ptrs,'score':ptrs}
    return out

def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    kb = segments['__TEXT']['vmaddr'] - segments['__TEXT']['fileoff']
    print('Kernel base (unslid):', hex(kb))
    cand_map = scan_filtered(data, segments, kb)
    print('Filtered candidates:', len(cand_map))
    analyzed = sample_and_score(data, segments, cand_map)
    ranked = sorted(analyzed.items(), key=lambda kv: kv[1]['score'], reverse=True)
    out = {'kernel_base':hex(kb),'total_candidates':len(ranked),'ranked_candidates':[{ 'vm':k, **v } for k,v in ranked]}
    json.dump(out, open(OUT_JSON,'w'), indent=2)
    json.dump(out, open(OUT_OVERWRITE,'w'), indent=2)
    print('Wrote', OUT_JSON, 'and overwrote', OUT_OVERWRITE)

if __name__=='__main__':
    main()
