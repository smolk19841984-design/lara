#!/usr/bin/env python3
"""
export_and_filter_valids.py

Экспортирует `valid` кандидаты из анализа и фильтрует их по ключам.

Пример:
  python export_and_filter_valids.py -i ppl_ucred_analysis_21D61.json -o ppl_ucred_valids_21D61.json -f ucred,cr_

"""
import argparse
import json
import os
import re
from typing import List


def load_json(path: str):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(path: str, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def filter_valids(data: dict) -> List[dict]:
    return [c for c in data.get('candidates', []) if c.get('verdict') == 'valid']


def _normalize(s: str) -> str:
    if not s:
        return ''
    # split camelCase and non-word characters
    s = re.sub(r'([a-z])([A-Z])', r'\1 \2', s)
    s = re.sub(r'[^0-9a-zA-Z_]+', ' ', s)
    return s.lower()


def _tokenize(s: str) -> List[str]:
    s2 = _normalize(s)
    toks = []
    for part in s2.split():
        # also split on underscores
        toks.extend([p for p in part.split('_') if p])
    return toks


def semantic_filter(cands: List[dict], keys: List[str]) -> List[dict]:
    """Более семантический фильтр по полям `name`, `text`, `key`.

    Правила:
    - токенизируем название/текст/ключ кандидата
    - токенизируем ключи фильтра
    - считаем совпадением, если токен фильтра равен одному из токенов кандидата,
      либо является префиксом/суффиксом токена кандидата (для коротких ключей)
    """
    res = []
    key_tokens = [t for k in keys for t in _tokenize(k)]
    key_tokens = [k for k in key_tokens if k]

    for c in cands:
        # collect candidate text sources
        sources = []
        if 'name' in c and c.get('name'):
            sources.append(str(c.get('name')))
        if 'text' in c and c.get('text'):
            sources.append(str(c.get('text')))
        if 'key' in c and c.get('key'):
            sources.append(str(c.get('key')))

        all_toks = []
        for s in sources:
            all_toks.extend(_tokenize(s))

        matched = False
        for kt in key_tokens:
            if not kt:
                continue
            for tok in all_toks:
                if tok == kt:
                    matched = True
                    break
                # prefix/suffix match for short keys
                if len(kt) >= 3 and (tok.startswith(kt) or tok.endswith(kt)):
                    matched = True
                    break
                # contain check for moderately long tokens
                if len(kt) >= 4 and kt in tok:
                    matched = True
                    break
            if matched:
                res.append(c)
                break

    return res


def main():
    ap = argparse.ArgumentParser(description='Export and filter valid candidates from analysis JSON')
    ap.add_argument('-i','--input', default='ppl_ucred_analysis_21D61.json')
    ap.add_argument('-o','--output', default='ppl_ucred_valids_21D61.json')
    ap.add_argument('-f','--filter', default='proc,vfs,ucred_rw', help='comma-separated filter keywords')
    ap.add_argument('-fo','--filtered-output', default='ppl_ucred_valids_filtered_21D61.json')
    args = ap.parse_args()

    data = load_json(args.input)
    valids = filter_valids(data)
    save_json(args.output, {'source': args.input, 'valids_count': len(valids), 'valids': valids})

    keys = [k.strip() for k in args.filter.split(',') if k.strip()]
    # semantic token-based filtering
    filtered = semantic_filter(valids, keys)
    save_json(args.filtered_output, {'source': args.input, 'filter': keys, 'count': len(filtered), 'items': filtered})

    print('Exported %d valid candidates to %s' % (len(valids), args.output))
    print('Filtered %d candidates by %s -> %s' % (len(filtered), keys, args.filtered_output))


if __name__ == '__main__':
    main()
