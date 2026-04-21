#!/usr/bin/env python3
"""Compare ADRP-resolved targets with PAC-unwrapped candidate VMs.
Reads iPad8,9_Analysis/adrp_resolved_full.json and
offsets_iPad8_9_17.3.1_pac_candidates_expanded.json and emits matches.
"""
import json
from pathlib import Path

ADRPPATH = Path('iPad8,9_Analysis/adrp_resolved_full.json')
PACPATH = Path('offsets_iPad8_9_17.3.1_pac_candidates_expanded.json')
OUT = Path('iPad8,9_17.3.1_adrp_pac_matches.json')

def norm_hex(s):
    if s is None:
        return None
    return int(str(s), 16) if isinstance(s, str) else int(s)

def main():
    if not ADRPPATH.exists():
        print('Missing', ADRPPATH)
        return
    if not PACPATH.exists():
        print('Missing', PACPATH)
        return
    adr = json.load(open(ADRPPATH))
    pac = json.load(open(PACPATH))
    pac_vms = set()
    for entry in pac.get('ranked_candidates', []):
        try:
            pac_vms.add(int(entry.get('vm', '0'), 16))
        except Exception:
            pass

    matches = []
    for r in adr.get('results', []):
        rt = r.get('resolved_target')
        if rt is None:
            continue
        try:
            v = int(rt, 16)
        except Exception:
            continue
        if v in pac_vms:
            matches.append({'adrp_addr': r.get('adrp_addr'), 'resolved_target': rt, 'context': r.get('context')})

    OUT.write_text(json.dumps({'pac_count': len(pac_vms), 'adrp_sites': len(adr.get('results',[])), 'matches': matches}, indent=2))
    print('Wrote', OUT, 'matches=', len(matches))

if __name__=='__main__':
    main()
