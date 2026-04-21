#!/usr/bin/env python3
import json
from pathlib import Path

IN = Path('deep_analyze_matches_results.json')
OUT = Path('deep_hits_top20_summary.txt')

def score(h):
    s = 0
    if h.get('loaded_matches_pac'):
        s += 100
    if h.get('loaded_matches_pac_low'):
        s += 10
    mq = h.get('match', {}).get('loaded_q')
    if mq and mq != '0x0':
        s += 1
    return s

def main():
    j = json.loads(IN.read_text())
    hits = j.get('hits', [])
    hits_sorted = sorted(hits, key=score, reverse=True)
    top = hits_sorted[:20]
    lines = []
    for i,h in enumerate(top, start=1):
        m = h['match']
        lines.append(f"RANK {i}: candidate_vm={h.get('candidate_vm')}")
        lines.append(f"  resolved_target_vm={m.get('resolved_target_vm')} fileoff={m.get('resolved_fileoff')}")
        lines.append(f"  loaded_q={m.get('loaded_q')} exact_pac={h.get('loaded_matches_pac', False)} low_pac={h.get('loaded_matches_pac_low', False)}")
        lines.append('  context:')
        for c in m.get('context', []):
            lines.append(f"    {c.get('addr')}  {c.get('mnem')}  {c.get('op_str')}")
        lines.append('')
    OUT.write_text('\n'.join(lines))
    print('Wrote', OUT)

if __name__ == '__main__':
    main()
