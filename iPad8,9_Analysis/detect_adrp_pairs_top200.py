#!/usr/bin/env python3
import json
from pathlib import Path
import re
import argparse

ADR_RE = re.compile(r'adrp.*', re.IGNORECASE)
ADD_LDR_RE = re.compile(r'\b(add|adds|ldr)\b', re.IGNORECASE)

def analyze(p: Path):
    lines = p.read_text(errors='ignore').splitlines()
    hits = []
    for i, ln in enumerate(lines):
        if 'adrp' in ln.lower():
            # look ahead for add/ldr within next 12 lines
            found = None
            ctx = [ln]
            for j in range(1,13):
                if i+j >= len(lines): break
                ctx.append(lines[i+j])
                if re.search(r'\b(add|adds|ldr)\b', lines[i+j], re.IGNORECASE):
                    found = lines[i+j]
                    break
            if found:
                hits.append({'adrp': ln.strip(), 'follows': found.strip(), 'context': ctx})
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', '-d', default='manual_re_top200')
    ap.add_argument('--out', '-o', default='triage_top200_adrp_pairs.json')
    args = ap.parse_args()
    d = Path(args.dir)
    res = []
    for p in sorted(d.glob('*.txt')):
        hits = analyze(p)
        if hits:
            vm = None
            for l in p.read_text(errors='ignore').splitlines()[:8]:
                if 'VM:' in l:
                    vm = l.split('VM:')[1].strip(); break
            res.append({'file': p.name, 'vm': vm, 'hits': hits, 'count': len(hits)})
    Path(args.out).write_text(json.dumps({'count': len(res), 'files': res}, indent=2))
    print('Wrote', args.out)

if __name__ == '__main__':
    main()
