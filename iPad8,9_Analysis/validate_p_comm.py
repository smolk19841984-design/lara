#!/usr/bin/env python3
"""Validate candidate proc_t structures: check p_pid at likely offsets and scan p_comm area for 'kernel_task'."""
import json, struct

ALLPROC_VER = 'offsets_iPad8_9_17.3.1_allproc_verified.json'
OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL_FILE = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'
OUT_JSON = 'offsets_iPad8_9_17.3.1_pcomm_validate.json'

CHECK_OFFSETS = [0x1c,0x30,0x34,0x44,0x4c]
PCOMM_SEARCH_R = range(0x80,0x140)  # region to search for p_comm strings

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

def scan():
    segs = load_segments()
    verified = json.load(open(ALLPROC_VER))
    data = open(KERNEL_FILE,'rb').read()
    results = []
    for ent in verified.get('results', [])[:50]:
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
        rec = {'candidate_vm': cand.get('candidate_vm'), 'lh_first': lh, 'proc_fileoff': cand.get('proc_fileoff'), 'checks': []}
        # test offsets
        for off in CHECK_OFFSETS:
            try:
                v = struct.unpack_from('<I', data, p_fo + off)[0]
            except Exception:
                continue
            entry = {'offset': hex(off), 'p_pid': v}
            # search p_comm region for kernel_task or 'kernel'
            found = False
            found_str = None
            for r in PCOMM_SEARCH_R:
                try:
                    snippet = data[p_fo + r:p_fo + r + 64]
                except Exception:
                    break
                s = ''.join([chr(b) if 32<=b<127 else '.' for b in snippet])
                if 'kernel_task' in s:
                    found = True; found_str = 'kernel_task'; pos = r; break
                if 'kernel' in s:
                    found = True; found_str = 'kernel'; pos = r; break
            if found:
                entry['p_comm_found'] = True
                entry['p_comm_type'] = found_str
                entry['p_comm_offset'] = hex(pos)
            rec['checks'].append(entry)
        results.append(rec)
    json.dump({'results': results}, open(OUT_JSON,'w'), indent=2)
    print('Wrote', OUT_JSON)

if __name__=='__main__':
    scan()
