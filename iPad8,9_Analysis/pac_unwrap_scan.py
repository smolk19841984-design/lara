#!/usr/bin/env python3
"""PAC-unwrapping + CFG-pattern heuristics.
Scans __DATA_CONST/__DATA for tagged pointers, applies masking heuristics,
maps candidates into kernel VM and samples their memory for likely structures.
Writes offsets_iPad8_9_17.3.1_pac_candidates.json
"""
import json, struct
from collections import defaultdict

OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates.json'

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
    """Yield candidate VMs from val by applying several mask heuristics."""
    # try a wide range of mask widths and tag-stripping heuristics
    masks = [56,52,48,44,40,36]
    cands = set()
    for m in masks:
        low = val & ((1 << m) - 1)
        # OR into canonical high kernel region
        cand_a = (0xfffffff000000000 & ~((1 << m) - 1)) | low
        if in_kernel_vm(cand_a, segments):
            cands.add(cand_a)
        # add kernel_base + low (unslid mapping)
        cand_b = kernel_base + low
        if in_kernel_vm(cand_b, segments):
            cands.add(cand_b)

    # try clearing top bytes that may contain PAC tags
    for clear_bytes in (1,2,3):
        mask = (1 << (64 - 8 * clear_bytes)) - 1
        low = val & mask
        cand = low | 0xfffffff000000000
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        cand2 = kernel_base + low
        if in_kernel_vm(cand2, segments):
            cands.add(cand2)

    # try subtracting common high base then OR back
    try:
        sub = val - 0xfffffff000000000
        if 0 <= sub < (1 << 48):
            cand = 0xfffffff000000000 | sub
            if in_kernel_vm(cand, segments):
                cands.add(cand)
    except Exception:
        pass

    # try zeroing top 8-16 bits with different placements
    for top_clear in (0x00ffffffffffffff, 0x0000ffffffffffff, 0x000000ffffffffff):
        cand = val & top_clear
        if in_kernel_vm(cand, segments):
            cands.add(cand)
        # also try OR'ing into kernel high
        cand_k = (cand & ((1 << 48) - 1)) | 0xfffffff000000000
        if in_kernel_vm(cand_k, segments):
            cands.add(cand_k)

    return sorted(cands)

def scan_data_pointers(data, segments, kernel_base):
    results = defaultdict(list)
    for segname in ('__DATA_CONST','__DATA'):
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
        # ascii snippet
        ascii_snip = ''.join([chr(b) if 32<=b<127 else '.' for b in sample])
        # quick heuristics: count pointers in first 64 bytes
        ptrs = 0
        for i in range(0, min(len(sample),64)-8,8):
            q = struct.unpack_from('<Q', sample, i)[0]
            if in_kernel_vm(q, segments):
                ptrs += 1
        # look for small 32-bit ints (possible pid) within first 128 bytes
        smallints = []
        for i in range(0, min(len(sample),128)-4,4):
            x = struct.unpack_from('<I', sample, i)[0]
            if x < 10000:
                smallints.append({'off':hex(i),'val':x})
        score = ptrs + (1 if smallints else 0)
        out[hex(vm)] = {'fileoff':hex(fo),'refs':refs,'ascii':ascii_snip[:200],'ptrs_in_sample':ptrs,'small_ints':smallints[:5],'score':score}
    return out

def main():
    segments = load_segments()
    data = open(KERNEL_FILE,'rb').read()
    kb = segments['__TEXT']['vmaddr'] - segments['__TEXT']['fileoff']
    print('Kernel base (unslid):', hex(kb))
    cand_map = scan_data_pointers(data, segments, kb)
    print('Candidates after PAC-mask heuristics:', len(cand_map))
    analyzed = sample_and_score(data, segments, cand_map)
    # sort by score desc
    ranked = sorted(analyzed.items(), key=lambda kv: kv[1]['score'], reverse=True)
    out = {'kernel_base':hex(kb),'total_candidates':len(ranked),'ranked_candidates':[{ 'vm':k, **v } for k,v in ranked]}
    json.dump(out, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON)

if __name__=='__main__':
    main()
