#!/usr/bin/env python3
"""Wider, fuzzy p_comm search across verified candidates.
Searches larger windows and looks for partial matches and ASCII-like strings.
Writes `offsets_iPad8_9_17.3.1_pcomm_wide.json`.
"""
import json, struct, re

ALLPROC_VER = 'offsets_iPad8_9_17.3.1_allproc_verified.json'
OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_pcomm_wide.json'

# window sizes to search for ASCII names
WINDOWS = [0x100, 0x200, 0x400]
PATTERNS = [re.compile(b'kernel_task', re.IGNORECASE), re.compile(b'kernel', re.IGNORECASE), re.compile(b'task', re.IGNORECASE)]

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

def is_printable_ascii(blob, min_run=4):
    # return True if there's a run of printable ascii of length >= min_run
    runs = re.findall(b'[\x20-\x7e]{%d,}' % (min_run,), blob)
    return runs

def scan():
    segs = load_segments()
    ver = json.load(open(ALLPROC_VER))
    data = open(KERNEL_FILE,'rb').read()
    out = []

    for ent in ver.get('results', [])[:200]:
        cand = ent.get('candidate', {})
        try:
            lh_vm = int(cand.get('lh_first','0'),16)
        except Exception:
            continue
        p_fo = vm_to_file(lh_vm, segs)
        if p_fo is None:
            continue
        record = {'candidate_vm': cand.get('candidate_vm'), 'lh_first': cand.get('lh_first'), 'proc_fileoff': cand.get('proc_fileoff'), 'matches': []}
        for w in WINDOWS:
            start = max(0, p_fo - w//2)
            sample = data[start:start + w]
            # check patterns
            for pat in PATTERNS:
                for m in pat.finditer(sample):
                    # capture context
                    s_off = start + m.start()
                    ctx = sample[max(0, m.start()-32):m.end()+32]
                    # decode printable sequences near match
                    runs = is_printable_ascii(ctx)
                    record['matches'].append({'pattern': pat.pattern.decode('ascii','ignore'), 'match_fileoff': hex(s_off), 'context_ascii_runs': [r.decode('ascii','ignore') for r in runs]})
            # also detect any printable ascii runs
            runs = is_printable_ascii(sample)
            if runs:
                record['matches'].append({'pattern':'printable_runs','runs':[r.decode('ascii','ignore') for r in runs][:5]})
        if record['matches']:
            out.append(record)

    json.dump({'results': out}, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON, 'with', len(out), 'candidates')

if __name__=='__main__':
    scan()
