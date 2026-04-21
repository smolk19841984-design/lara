#!/usr/bin/env python3
"""kernel_analyzer.py

Простой статический анализатор — извлекает printable-строки, считает вхождения ключевых слов и считает sha256 файла.
Не выполняет и не генерирует эксплойтов — только анализ и агрегирование совпадений.
"""

from __future__ import annotations
import argparse
import os
import re
import json
import hashlib
from datetime import datetime

KEYWORDS = ['ppl', 'memory integrity', 'mie', 'amfi', 'sandbox', 'cs_blob', 'codesign', 'ssl', 'pinning', 'panic', 'kernel']


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def extract_printable_strings(data: bytes, min_len: int = 6) -> list[str]:
    parts = re.findall(b'[\x20-\x7e]{%d,}' % min_len, data)
    out = []
    for p in parts:
        try:
            out.append(p.decode('utf-8', errors='replace'))
        except Exception:
            out.append(p.decode('latin-1', errors='replace'))
    return out


def analyze_file(path: str, min_size: int) -> dict | None:
    try:
        stat = os.stat(path)
    except Exception:
        return None
    if stat.st_size < min_size:
        return None
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception:
        return None

    strings = extract_printable_strings(data)
    low_join = ' '.join(strings).lower()
    matches = {}
    for kw in KEYWORDS:
        c = low_join.count(kw)
        if c:
            # collect up to 5 sample strings containing keyword
            samples = [s for s in strings if kw in s.lower()][:5]
            matches[kw] = {'count': c, 'samples': samples}

    return {
        'path': path,
        'size': stat.st_size,
        'mtime': datetime.utcfromtimestamp(stat.st_mtime).isoformat() + 'Z',
        'sha256': sha256_of(path),
        'matches': matches,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, help='Root directory to scan (use a narrow folder with saved kernels)')
    parser.add_argument('--out', required=True)
    parser.add_argument('--min-size', type=int, default=1024 * 50, help='Min file size to analyze (bytes)')
    args = parser.parse_args()

    results = []
    for root, _, files in os.walk(args.root):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                res = analyze_file(path, args.min_size)
                if res and res['matches']:
                    results.append(res)
            except Exception:
                continue

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'generated_at': datetime.utcnow().isoformat() + 'Z', 'results': results}, f, ensure_ascii=False, indent=2)
    print('Analyzed files with matches:', len(results), '->', args.out)


if __name__ == '__main__':
    main()
