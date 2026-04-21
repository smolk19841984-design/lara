#!/usr/bin/env python3
import json
from pathlib import Path
import zipfile

IN = Path('deep_analyze_matches_results.json')
OUTDIR = Path('manual_re_priority_top50')
OUTZIP = Path('manual_re_priority_top50.zip')

def score_hit(h):
    # prefer exact pac matches, then low-part matches
    m = h.get('match', {})
    s = 0
    if h.get('loaded_matches_pac'):
        s += 100
    if h.get('loaded_matches_pac_low'):
        s += 10
    # prefer non-zero loaded values
    if m.get('loaded_q') and m.get('loaded_q') != '0x0':
        s += 1
    return s

def make_text(h):
    m = h['match']
    lines = []
    lines.append(f"Candidate VM: {h.get('candidate_vm')}")
    lines.append(f"Resolved target VM: {m.get('resolved_target_vm')}")
    lines.append(f"Resolved fileoff: {m.get('resolved_fileoff')}")
    lines.append(f"Loaded qword: {m.get('loaded_q')}")
    lines.append(f"Match flags: loaded_matches_pac={h.get('loaded_matches_pac', False)} loaded_matches_pac_low={h.get('loaded_matches_pac_low', False)}")
    lines.append('\nContext:')
    for c in m.get('context', []):
        lines.append(f"  {c.get('addr')}  {c.get('mnem')}  {c.get('op_str')}")
    return '\n'.join(lines)

def main():
    if not IN.exists():
        print('Input not found:', IN)
        return
    j = json.loads(IN.read_text())
    hits = j.get('hits', [])
    hits_sorted = sorted(hits, key=score_hit, reverse=True)
    top = hits_sorted[:50]
    OUTDIR.mkdir(exist_ok=True)
    summaries = []
    for i,h in enumerate(top, start=1):
        name = f"{i:02d}_{h.get('candidate_vm').replace('0x','')}.txt"
        p = OUTDIR / name
        p.write_text(make_text(h))
        summaries.append({'rank': i, 'candidate_vm': h.get('candidate_vm'), 'file': str(p), 'score': score_hit(h)})

    (OUTDIR / 'summary.json').write_text(json.dumps(summaries, indent=2))
    # zip
    with zipfile.ZipFile(OUTZIP, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for f in OUTDIR.iterdir():
            z.write(f, arcname=f.name)
    print('Wrote', OUTDIR, 'and', OUTZIP)

if __name__ == '__main__':
    import json
    main()
