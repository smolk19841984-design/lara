#!/usr/bin/env python3
import re
import sys
from pathlib import Path

TARGETS = [
    'pmap_image4_trust_caches',
    'pmap_trust_cache',
    'vn_open',
    'vn_write',
    'vn_close',
    'vfs_context_current',
    'vnode_put',
]

ROOT = Path(__file__).resolve().parents[1]

def scan_file(p: Path):
    try:
        text = p.read_text(errors='ignore')
    except Exception:
        return []
    lines = text.splitlines()
    results = []
    for i, L in enumerate(lines):
        for t in TARGETS:
            if t in L:
                # search backward up to 200 lines for prologue
                start = max(0, i-200)
                snippet = lines[start:i+5]
                for j, s in enumerate(reversed(snippet)):
                    if re.search(r'stp\s+x29,\s*x30|stp\s+x29, x30|stp\s+fp,\s+lr', s):
                        # determine prologue line index
                        rel = i - (start + (len(snippet)-1-j))
                        prologue_idx = start + (len(snippet)-1-j)
                        # collect next 8 lines as signature area
                        sig_lines = lines[prologue_idx:prologue_idx+8]
                        results.append({
                            'file': str(p.relative_to(ROOT)),
                            'target': t,
                            'line': i+1,
                            'prologue_line': prologue_idx+1,
                            'sig': '\n'.join(sig_lines),
                        })
                        break
                else:
                    # no prologue found, still record occurrence
                    context = '\n'.join(lines[max(0,i-4):i+4])
                    results.append({
                        'file': str(p.relative_to(ROOT)),
                        'target': t,
                        'line': i+1,
                        'prologue_line': None,
                        'sig': context,
                    })
    return results

def main():
    out = []
    for p in ROOT.rglob('*.txt'):
        out.extend(scan_file(p))
    for p in ROOT.rglob('*.json'):
        out.extend(scan_file(p))
    archive_dir = ROOT / '8ksec_archive'
    if archive_dir.exists():
        for p in archive_dir.rglob('*'):
            if p.is_file():
                out.extend(scan_file(p))

    if not out:
        print('NO_MATCHES')
        return
    import json
    print(json.dumps(out, indent=2))

if __name__ == '__main__':
    main()
