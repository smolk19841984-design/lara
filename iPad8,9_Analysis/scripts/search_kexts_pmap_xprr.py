#!/usr/bin/env python3
import os

ROOTS = [
    os.path.join(os.path.dirname(__file__), '..', '21D61', 'kexts'),
    os.path.join(os.path.dirname(__file__), '..', '21E219', 'kexts'),
]

PATTERNS = [b'pmap_set_pte_xprr', b'pmap_set_xprr', b'xprr_perm', b'pmap_in_ppl', b'pmap_set_pte_xprr_perm']

def search_file(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception:
        return []
    res = []
    for p in PATTERNS:
        idx = data.find(p)
        if idx >= 0:
            res.append((p.decode(errors='ignore'), idx))
    return res

def main():
    found = []
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            for fn in files:
                path = os.path.join(dirpath, fn)
                matches = search_file(path)
                if matches:
                    for m in matches:
                        found.append((root, os.path.relpath(path, root), m[0], m[1]))
    for r, p, s, off in found:
        print(f"{r}\t{p}\t{s}\t0x{off:x}")
    if not found:
        print('No matches in kexts')

if __name__ == '__main__':
    main()
