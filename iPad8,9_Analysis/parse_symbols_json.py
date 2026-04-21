#!/usr/bin/env python3
"""
parse_symbols_json.py

Парсер symbols JSON — пытается извлечь все символы, имя которых содержит заданные подстроки.
Сохраняет результат в JSON с парами (name, address, extra).
"""

import argparse
import json
import os
from typing import Any, Dict, List


def extract_from_obj(obj: Any, keywords: List[str]) -> List[Dict]:
    out = []
    def match_name(name: str) -> bool:
        ln = name.lower()
        for k in keywords:
            if k in ln:
                return True
        return False

    # Case 1: obj is dict mapping name->address
    if isinstance(obj, dict):
        # try common subkeys
        if 'symbols' in obj and isinstance(obj['symbols'], list):
            for ent in obj['symbols']:
                # try to find name/address fields
                if isinstance(ent, dict):
                    name = ent.get('name') or ent.get('symbol') or ent.get('n') or ent.get('sym')
                    addr = ent.get('address') or ent.get('value') or ent.get('addr') or ent.get('v')
                    if name and isinstance(name, str) and match_name(name):
                        out.append({'name': name, 'addr': addr, 'raw': ent})
        else:
            # assume top-level mapping name->addr
            for k, v in obj.items():
                # if value is a string, it may be the symbol name and key the address
                if isinstance(v, str):
                    name = v
                    addr = k
                    if isinstance(name, str) and match_name(name):
                        out.append({'name': name, 'addr': addr})
                else:
                    # fallback: key might be the symbol name
                    if isinstance(k, str) and match_name(k):
                        out.append({'name': k, 'addr': v})

    # Case 2: obj is list of symbols
    elif isinstance(obj, list):
        for ent in obj:
            if isinstance(ent, dict):
                name = ent.get('name') or ent.get('symbol') or ent.get('n')
                addr = ent.get('address') or ent.get('value') or ent.get('addr')
                if name and isinstance(name, str) and match_name(name):
                    out.append({'name': name, 'addr': addr, 'raw': ent})
            elif isinstance(ent, str):
                # unlikely
                if match_name(ent):
                    out.append({'name': ent, 'addr': None})

    return out


def main():
    ap = argparse.ArgumentParser(description='Parse symbols JSON and extract pmap/ppl symbols')
    ap.add_argument('-i','--input', required=True)
    ap.add_argument('-o','--output', default='pmap_ppl_parsed.json')
    ap.add_argument('-k','--keys', default='pmap,ppl,nvme_ppl', help='comma-separated keywords')
    args = ap.parse_args()

    inf = args.input
    if not os.path.isfile(inf):
        print('Input not found', inf)
        return

    with open(inf, 'r', encoding='utf-8', errors='replace') as f:
        try:
            obj = json.load(f)
        except Exception as e:
            print('JSON load failed:', e)
            # fallback: read as text and try to locate key-like entries
            text = f.read()
            print('Fallback: cannot parse JSON; no further parsing implemented.')
            return

    keys = [k.strip().lower() for k in args.keys.split(',') if k.strip()]
    res = extract_from_obj(obj, keys)
    with open(args.output, 'w', encoding='utf-8') as fo:
        json.dump({'input': inf, 'keywords': keys, 'count': len(res), 'items': res}, fo, indent=2, ensure_ascii=False)
    print('Extracted %d matching symbols -> %s' % (len(res), args.output))


if __name__ == '__main__':
    main()
