#!/usr/bin/env python3
"""Verify top allproc candidates by scanning proc_t memory for p_pid==0 and other heuristics."""
import json, struct

ALLPROC_JSON = 'offsets_iPad8_9_17.3.1_allproc_candidates.json'
OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_allproc_verified.json'
TOP_N = 20

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

def scan_proc_for_pid(data, p_fo, max_off=0x400):
    # Scan offsets for 32-bit PID == 0 and capture context
    findings = []
    end = min(len(data), p_fo + max_off)
    for off in range(p_fo, end-4, 4):
        try:
            val = struct.unpack_from('<I', data, off)[0]
        except Exception:
            continue
        if val == 0:
            # capture surrounding bytes
            ctx = data[max(p_fo, off-32):off+64]
            ascii_ctx = ''.join([chr(b) if 32<=b<127 else '.' for b in ctx])
            findings.append({'offset': hex(off - p_fo), 'fileoff': hex(off), 'ascii_context': ascii_ctx[:200]})
    return findings

def main():
    segs = load_segments()
    pac = json.load(open(ALLPROC_JSON))
    top = pac.get('results', [])[:TOP_N]
    data = open(KERNEL_FILE,'rb').read()
    results = []
    for ent in top:
        cand = {'candidate_vm': ent['candidate_vm'], 'candidate_fileoff': ent['candidate_fileoff'], 'lh_first': ent['lh_first']}
        try:
            lh = int(ent['lh_first'],16)
        except Exception:
            results.append({'candidate':cand, 'error':'invalid_lh_first'})
            continue
        p_fo = vm_to_file(lh, segs)
        if p_fo is None:
            cand['note'] = 'lh_first not mapped to file'
            results.append({'candidate':cand})
            continue
        cand['proc_fileoff'] = hex(p_fo)
        findings = scan_proc_for_pid(data, p_fo)
        cand['pid0_findings'] = findings
        # quick extra: look for 'kernel_task' ascii in nearby 1KB
        nearby = data[max(0,p_fo-512):p_fo+1024]
        ascii_nb = ''.join([chr(b) if 32<=b<127 else '.' for b in nearby])
        cand['nearby_ascii_kernel_task'] = 'kernel_task' in ascii_nb
        results.append({'candidate':cand})

    json.dump({'verified_top_n': TOP_N, 'results': results}, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON)

if __name__=='__main__':
    main()
