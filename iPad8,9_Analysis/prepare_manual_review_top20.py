#!/usr/bin/env python3
import json
from pathlib import Path
import shutil
import argparse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--triage', default='triage_top200_summary.json')
    ap.add_argument('--indir', default='manual_re_top200')
    ap.add_argument('--outdir', default='manual_review_top20')
    args = ap.parse_args()

    tri = Path(args.triage)
    if not tri.exists():
        print('Triage summary missing:', tri); return
    js = json.loads(tri.read_text())
    top = js.get('candidates', [])[:20]
    out = Path(args.outdir)
    out.mkdir(exist_ok=True)
    md = out / 'summary.md'
    with md.open('w') as mf:
        mf.write('# Manual review top 20\n\n')
        for i, c in enumerate(top, start=1):
            nm = c['file']
            src = Path(args.indir) / nm
            dst = out / nm
            if src.exists():
                shutil.copy2(src, dst)
            mf.write(f'## {i}. {nm}\n')
            mf.write(f'- VM: {c.get("vm")}\n')
            mf.write(f'- File: {dst.name}\n')
            mf.write(f'- ADRP: {c.get("adrp")}  ADD: {c.get("add")}  LDR: {c.get("ldr")}  BL: {c.get("bl")}\n\n')
            # include first 40 lines of disasm for quick glance
            if dst.exists():
                txt = dst.read_text(errors='ignore').splitlines()
                mf.write('```\n')
                for ln in txt[:40]:
                    mf.write(ln + '\n')
                mf.write('```\n\n')
    print('Prepared manual review dir:', out)

if __name__ == '__main__':
    main()
