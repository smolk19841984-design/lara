#!/usr/bin/env python3
import json
from pathlib import Path
import re
import argparse

pat_adrp = re.compile(r'adrp', re.IGNORECASE)
pat_add = re.compile(r'\badd\b', re.IGNORECASE)
pat_ldr = re.compile(r'\bldr\b', re.IGNORECASE)
pat_bl = re.compile(r'\bbl\b|\bblr\b', re.IGNORECASE)

def analyze_file(p: Path):
    text = p.read_text(errors='ignore')
    stats = {'file': str(p.name), 'vm': None, 'fileoff': None, 'adrp': 0, 'add': 0, 'ldr': 0, 'bl': 0}
    for line in text.splitlines()[:8]:
        if 'VM:' in line:
            stats['vm'] = line.split('VM:')[1].strip()
        if 'Fileoff:' in line:
            stats['fileoff'] = line.split('Fileoff:')[1].strip()
    stats['adrp'] = len(pat_adrp.findall(text))
    stats['add'] = len(pat_add.findall(text))
    stats['ldr'] = len(pat_ldr.findall(text))
    stats['bl'] = len(pat_bl.findall(text))
    stats['score'] = stats['adrp']*5 + stats['ldr']*3 + stats['add']*2 + stats['bl']
    return stats

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', '-d', default='manual_re_top200')
    ap.add_argument('--out', '-o', default='triage_top200_summary.json')
    args = ap.parse_args()
    d = Path(args.dir)
    files = sorted(d.glob('*.txt'))
    out = [analyze_file(p) for p in files]
    out_sorted = sorted(out, key=lambda x: x['score'], reverse=True)
    Path(args.out).write_text(json.dumps({'count': len(out_sorted), 'candidates': out_sorted}, indent=2))
    print('Wrote', args.out)

if __name__ == '__main__':
    main()
