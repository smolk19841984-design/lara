#!/usr/bin/env python3
"""Scan likely `p_pid` offsets across top allproc candidates.
Produces JSON with counts per offset and candidates where p_pid==0.
"""
import json, struct

ALLPROC_VER = 'offsets_iPad8_9_17.3.1_allproc_verified.json'
OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_pid_offset_scan.json'
TOP_N = 50

COMMON_OFFSETS = [0x10,0x14,0x18,0x1c,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,0x40,0x44,0x48,0x4c,0x50,0x60]

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

def main():
    segs = load_segments()
    j = json.load(open(ALLPROC_VER))
    top = j.get('results', [])[:TOP_N]
    data = open(KERNEL_FILE,'rb').read()
    stats = {hex(o): [] for o in COMMON_OFFSETS}
    for ent in top:
        cand = ent.get('candidate', {})
        lh = cand.get('lh_first')
        if not lh:
            continue
        try:
            lh_vm = int(lh,16)
        except Exception:
            continue
        p_fo = vm_to_file(lh_vm, segs)
        if p_fo is None:
            continue
        for off in COMMON_OFFSETS:
            try:
                val = struct.unpack_from('<I', data, p_fo + off)[0]
            except Exception:
                continue
            if val == 0:
                stats[hex(off)].append({'candidate_vm': cand.get('candidate_vm'), 'lh_first': lh, 'proc_fileoff': cand.get('proc_fileoff')})

    out = {'top_n':TOP_N, 'checked_offsets':[hex(x) for x in COMMON_OFFSETS], 'matches': {k:v for k,v in stats.items()}}
    json.dump(out, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON)

if __name__=='__main__':
    main()
