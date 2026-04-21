#!/usr/bin/env python3
import json
from pathlib import Path

BASE = Path('manual_review_top20')
OUT = BASE / 'annotations.txt'
TRIAGE = Path('triage_top200_summary.json')

def short_head(path, n=40):
    try:
        txt = path.read_text(errors='replace').splitlines()
        return '\n'.join(txt[:n])
    except Exception:
        return ''

def main():
    tri = {}
    if TRIAGE.exists():
        j = json.loads(TRIAGE.read_text())
        for c in j.get('candidates', []):
            tri[c.get('file')] = c

    out_lines = []
    files = sorted([p for p in BASE.iterdir() if p.is_file() and p.name.endswith('.txt')])
    for p in files:
        out_lines.append('FILE: ' + p.name)
        t = tri.get(p.name)
        if t:
            out_lines.append('SCORE: %s  ADRP:%s ADD:%s LDR:%s BL:%s' % (t.get('score'), t.get('adrp'), t.get('add'), t.get('ldr'), t.get('bl')))
        out_lines.append('--- SNIPPET ---')
        out_lines.append(short_head(p, n=40))
        out_lines.append('\n')

    OUT.write_text('\n'.join(out_lines))
    print('Wrote', OUT)

if __name__ == '__main__':
    main()
