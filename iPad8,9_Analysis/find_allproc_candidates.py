#!/usr/bin/env python3
"""Focused structural scan to detect possible `allproc` list-heads.
Uses top-N entries from `offsets_iPad8_9_17.3.1_pac_candidates.json` and
applies heuristics: dereference lh_first, sample proc_t candidate, look for
`kernel_task` string and small PID (0) near likely offsets.
Writes `offsets_iPad8_9_17.3.1_allproc_candidates.json`.
"""
import json, struct

PAC_JSON = 'offsets_iPad8_9_17.3.1_pac_candidates.json'
OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_allproc_candidates.json'
TOP_N = 200

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

def vm_to_file(vm, segments):
    for seg in segments.values():
        if seg['vmaddr'] <= vm < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (vm - seg['vmaddr'])
    return None

def in_kernel_vm(v, segments):
    for s in segments.values():
        if s['vmaddr'] <= v < s['vmaddr'] + s['vmsize']:
            return True
    return False

def scan():
    pac = json.load(open(PAC_JSON))
    off = json.load(open(OFF_JSON))
    segs = load_segments()
    data = open(KERNEL_FILE,'rb').read()

    ranked = pac.get('ranked_candidates', [])[:TOP_N]
    results = []

    for ent in ranked:
        vm_str = ent['vm']
        vm = int(vm_str,16)
        fo = vm_to_file(vm, segs)
        if fo is None:
            continue
        # treat candidate as list_head: first pointer = lh_first
        try:
            lh_first = struct.unpack_from('<Q', data, fo)[0]
        except Exception:
            continue
        score = 0
        details = {'candidate_vm':vm_str, 'candidate_fileoff':hex(fo), 'lh_first':hex(lh_first)}

        if not in_kernel_vm(lh_first, segs):
            details['note'] = 'lh_first not in kernel vm'
            results.append({'score':score, **details})
            continue

        # sample the pointed proc_t area
        p_fo = vm_to_file(lh_first, segs)
        if p_fo is None:
            details['note'] = 'lh_first file no-map'
            results.append({'score':score, **details})
            continue

        sample = data[p_fo:p_fo+512]
        ascii_snip = ''.join([chr(b) if 32<=b<127 else '.' for b in sample])
        details['proc_fileoff'] = hex(p_fo)
        details['ascii_snip'] = ascii_snip[:200]

        # heuristic: look for 'kernel_task' string
        if 'kernel_task' in ascii_snip:
            score += 10
            details['found_kernel_task'] = True

        # heuristic: look for small 32-bit values (pid==0) in first 256 bytes
        smalls = []
        for i in range(0, min(len(sample),256)-4,4):
            val = struct.unpack_from('<I', sample, i)[0]
            if val == 0:
                smalls.append(i)
        if smalls:
            score += 3
            details['zero_offsets'] = [hex(x) for x in smalls[:5]]

        # heuristic: count pointers in first 64 bytes that point into __TEXT
        text_vm = segs.get('__TEXT',{}).get('vmaddr',0)
        text_end = text_vm + segs.get('__TEXT',{}).get('vmsize',0)
        ptrs_into_text = 0
        for i in range(0, min(len(sample),64)-8,8):
            q = struct.unpack_from('<Q', sample, i)[0]
            if text_vm <= q < text_end:
                ptrs_into_text += 1
        if ptrs_into_text:
            score += ptrs_into_text
            details['ptrs_into_text'] = ptrs_into_text

        results.append({'score':score, **details})

    results = sorted(results, key=lambda x: x['score'], reverse=True)
    json.dump({'top_n':TOP_N, 'results':results}, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON, 'with', len(results), 'entries')

if __name__=='__main__':
    scan()
