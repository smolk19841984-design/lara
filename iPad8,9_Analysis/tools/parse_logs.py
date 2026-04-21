#!/usr/bin/env python3
"""parse_logs.py

Сканирует папку логов, извлекает метаданные и образцы строк (panic, kernel, crash и т.д.).
Использует только стандартную библиотеку Python и сохраняет JSON-отчёт.
"""

from __future__ import annotations
import argparse
import json
import os
import time
from datetime import datetime


def tail_lines(path: str, max_bytes: int = 200000) -> list[str]:
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            to_read = min(size, max_bytes)
            f.seek(size - to_read)
            data = f.read()
        text = data.decode('utf-8', errors='replace')
        return text.splitlines()
    except Exception:
        return []


def head_lines(path: str, max_lines: int = 50) -> list[str]:
    out = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                out.append(line.rstrip('\n'))
    except Exception:
        pass
    return out


KEYWORDS = ['panic', 'kernel', 'crash', 'exception', 'ppl', 'mie', 'amfi', 'sandbox', 'paniclog']


def scan_file(path: str) -> dict:
    stat = os.stat(path)
    first = head_lines(path, max_lines=40)
    last = tail_lines(path, max_bytes=200000)[-200:]
    sample = []
    counts = {}
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                low = line.lower()
                for kw in KEYWORDS:
                    if kw in low:
                        counts[kw] = counts.get(kw, 0) + 1
                        if len(sample) < 20:
                            sample.append({'line_no': i+1, 'text': line.strip()})
    except Exception:
        pass

    return {
        'path': path,
        'size_bytes': stat.st_size,
        'mtime': datetime.utcfromtimestamp(stat.st_mtime).isoformat() + 'Z',
        'first_lines': first,
        'last_lines': last,
        'keyword_counts': counts,
        'keyword_samples': sample,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--logdir', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--max-files', type=int, default=0, help='0 = all')
    args = parser.parse_args()

    logdir = args.logdir
    outpath = args.out
    results = []
    files_scanned = 0
    for root, _, files in os.walk(logdir):
        for fname in files:
            fpath = os.path.join(root, fname)
            if args.max_files and files_scanned >= args.max_files:
                break
            try:
                meta = scan_file(fpath)
                results.append(meta)
                files_scanned += 1
            except Exception:
                continue

    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump({'generated_at': time.time(), 'files': results}, f, ensure_ascii=False, indent=2)
    print('Scanned', files_scanned, 'files ->', outpath)


if __name__ == '__main__':
    main()
