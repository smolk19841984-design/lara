#!/usr/bin/env python3
import json, re, struct
from pathlib import Path

MATCHS = 'fine_disasm_top1000_matches.json'
PAC = 'pac_candidates_top2000.json'
OFF_JSON = 'offsets_iPad8_9_17.3.1.json'
KERNEL = '21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed'

def load_segments():
    j = json.load(open(OFF_JSON))
    segs = {}
    for name,info in j.get('segments', {}).items():
        segs[name] = {'vmaddr': int(info['vmaddr'],16),'vmsize': int(info['vmsize'],16),'fileoff': int(info['fileoff'],16),'filesize': int(info['filesize'],16)}
    return segs

def vm_to_fileoff(segments, vm):
    for s in segments.values():
        va = s['vmaddr']; vs = s['vmsize']
        if vs and va <= vm < va + vs:
            return s['fileoff'] + (vm - va)
    return None

def parse_adrp_page(op_str):
    m = re.search(r"#0x([0-9a-fA-F]+)", op_str)
    if m:
        return int('0x'+m.group(1), 16)
    return None

def resolve_target_from_match(m):
    # m has keys: adrp_addr, follow_type, add_imm or disp, context[0].op_str
    adrp_op = m['context'][0]['op_str']
    page = parse_adrp_page(adrp_op)
    if page is None:
        return None
    if m['follow_type'] == 'add':
        addv = m.get('add_imm') or 0
        return (page & ~0xfff) + addv
    if m['follow_type'] == 'ldr':
        disp = m.get('disp') or 0
        return (page & ~0xfff) + disp
    return None

def main():
    segs = load_segments()
    pac = [int(x.get('vm'),16) for x in json.load(open(PAC))]
    pac_set = set(pac)
    data = open(KERNEL,'rb').read()
    j = json.load(open(MATCHS))
    out = {'count':0,'hits':[]}
    for r in j.get('results', []):
        cand_vm = int(r['vm'],16)
        for m in r.get('matches', []):
            targ = resolve_target_from_match(m)
            if targ is None:
                m['resolved_target_vm'] = None
                continue
            m['resolved_target_vm'] = hex(targ)
            fo = vm_to_fileoff(segs, targ)
            m['resolved_fileoff'] = hex(fo) if fo else None
            if fo and fo + 8 <= len(data):
                val = struct.unpack_from('<Q', data, fo)[0]
                m['loaded_q'] = hex(val)
                if val in pac_set:
                    out['hits'].append({'candidate_vm': r['vm'], 'match': m, 'loaded_matches_pac': True})
                else:
                    # also check canonical kernel-high or masked
                    if (val & 0xFFFFFFFFFFFF) in (p & 0xFFFFFFFFFFFF for p in pac):
                        out['hits'].append({'candidate_vm': r['vm'], 'match': m, 'loaded_matches_pac_low': True})
            else:
                m['loaded_q'] = None
    out['count'] = len(out['hits'])
    open('deep_analyze_matches_results.json','w').write(json.dumps(out, indent=2))
    print('Wrote deep_analyze_matches_results.json  hits=', out['count'])

if __name__ == '__main__':
    import json
    main()
