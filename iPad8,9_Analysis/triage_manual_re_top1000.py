#!/usr/bin/env python3
import json
from pathlib import Path
import re

DIR = Path('manual_re_top1000')
OUT_SUM = Path('triage_top1000_summary.json')

pat_adrp = re.compile(r'adrp', re.IGNORECASE)
pat_add = re.compile(r'\badd\b', re.IGNORECASE)
pat_ldr = re.compile(r'\bldr\b', re.IGNORECASE)
pat_bl = re.compile(r'\bbl\b|\bblr\b', re.IGNORECASE)

def analyze_file(p: Path):
    text = p.read_text(errors='ignore')
    stats = {'file': str(p), 'vm': None, 'fileoff': None, 'adrp': 0, 'add': 0, 'ldr': 0, 'bl': 0}
    # try to extract VM and fileoff from header
    for line in text.splitlines()[:8]:
        if 'VM:' in line:
            try:
                stats['vm'] = line.split('VM:')[1].strip()
            except Exception:
                pass
        if 'Fileoff:' in line:
            try:
                stats['fileoff'] = line.split('Fileoff:')[1].strip()
            except Exception:
                pass
    stats['adrp'] = len(pat_adrp.findall(text))
    stats['add'] = len(pat_add.findall(text))
    stats['ldr'] = len(pat_ldr.findall(text))
    stats['bl'] = len(pat_bl.findall(text))
    stats['score'] = stats['adrp']*5 + stats['ldr']*3 + stats['add']*2 + stats['bl']
    return stats

def main():
    files = sorted(DIR.glob('*.txt'))
    out = []
    for p in files:
        out.append(analyze_file(p))
    out_sorted = sorted(out, key=lambda x: x['score'], reverse=True)
    OUT_SUM.write_text(json.dumps({'count': len(out_sorted), 'candidates': out_sorted}, indent=2))
    print('Wrote', OUT_SUM)

if __name__ == '__main__':
    main()
