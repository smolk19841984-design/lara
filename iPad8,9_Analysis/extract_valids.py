#!/usr/bin/env python3
import sys
import json

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'ppl_ucred_analysis_21D61.json'
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    cand = data.get('candidates', [])
    valids = [c for c in cand if c.get('verdict') == 'valid']
    for i, v in enumerate(valids[:n], 1):
        name = v.get('name') or v.get('text') or ''
        vm = 'N/A' if v.get('vm') is None else hex(int(v.get('vm')))
        fo = 'N/A' if v.get('fileoff') is None else hex(int(v.get('fileoff')))
        print(f"{i}. key={v.get('key')} source={v.get('source')} name={name} vm={vm} fileoff={fo} refs={v.get('refs')} pd={v.get('pointer_density'):.3f} valid_ptrs={v.get('pointer_valid_count')}")

if __name__ == '__main__':
    main()
