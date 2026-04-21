#!/usr/bin/env python3
"""
scan_symbols_for_ppl.py

Ищет упоминания PPL/pmap/nvme_ppl в JSON-файле символов (стриминг/поиск).

Выводит JSON с найденными совпадениями (ключ, позиция, контекст).
"""

import argparse
import json
import os
from typing import List


def find_matches(text: str, keywords: List[str], context=120):
    matches = []
    for kw in keywords:
        start = 0
        while True:
            idx = text.find(kw, start)
            if idx == -1:
                break
            s = max(0, idx - context)
            e = min(len(text), idx + len(kw) + context)
            snippet = text[s:e].replace('\n', ' ').replace('\r', ' ')
            matches.append({'keyword': kw, 'index': idx, 'snippet': snippet})
            start = idx + len(kw)
    return matches


def main():
    ap = argparse.ArgumentParser(description='Scan symbol JSON for pmap/ppl keywords')
    ap.add_argument('-i','--input', required=True, help='path to symbols JSON')
    ap.add_argument('-o','--output', default='pmap_ppl_symbols.json', help='output JSON file')
    ap.add_argument('-k','--keywords', default='pmap,ppl,nvme_ppl,pmap_mark_page,pmap_claim_reserved,pmap_give_free_ppl', help='comma-separated keywords')
    args = ap.parse_args()

    inf = args.input
    if not os.path.isfile(inf):
        print('Input not found:', inf)
        return
    kws = [k.strip() for k in args.keywords.split(',') if k.strip()]

    # read whole file (symbols JSON usually textual)
    with open(inf, 'rb') as f:
        raw = f.read()
    try:
        text = raw.decode('utf-8')
    except Exception:
        text = raw.decode('utf-8', errors='replace')

    matches = find_matches(text, kws)

    out = {'input': inf, 'keywords': kws, 'matches_count': len(matches), 'matches': matches}
    with open(args.output, 'w', encoding='utf-8') as fo:
        json.dump(out, fo, indent=2, ensure_ascii=False)

    print('Found %d matches; saved to %s' % (len(matches), args.output))


if __name__ == '__main__':
    main()
