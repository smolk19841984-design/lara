#!/usr/bin/env python3
"""offsets_checker.py

Извлекает `kernel_base` и `kernel_slide` из логов (`analysis_outputs/logs_summary.json` или `log/lara.log`) и сохраняет отчёт.
"""

from __future__ import annotations
import json
import os
import re
import argparse


def find_in_log_text(text: str):
    base = None
    slide = None
    m = re.search(r'kernel_base:\s*(0x[0-9a-fA-F]+)', text)
    if m:
        base = m.group(1)
    m2 = re.search(r'kernel_slide:\s*(0x[0-9a-fA-F]+)', text)
    if m2:
        slide = m2.group(1)
    # also try other formats
    if not base:
        m3 = re.search(r'kernel_base:\s*(0x[0-9a-fA-F]+)', text)
        if m3:
            base = m3.group(1)
    return base, slide


def from_logs_summary(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            j = json.load(f)
    except Exception:
        return None
    # search through last_lines and keyword_samples for kernel_base/slide
    candidates = []
    for item in j.get('files', []):
        for line in item.get('last_lines', []) + item.get('first_lines', []) + [s.get('text','') for s in item.get('keyword_samples', [])]:
            candidates.append(line)
    text = '\n'.join(candidates)
    return find_in_log_text(text)


def from_lara_log(path: str):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except Exception:
        return None
    return find_in_log_text(text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--logs-summary', default='iPad8,9_Analysis/analysis_outputs/logs_summary.json')
    parser.add_argument('--lara-log', default='log/lara.log')
    parser.add_argument('--out', default='iPad8,9_Analysis/analysis_outputs/offsets_report.json')
    args = parser.parse_args()

    base_slide = from_logs_summary(args.logs_summary) or (None, None)
    if not any(base_slide):
        base_slide = from_lara_log(args.lara_log) or (None, None)

    report = {'kernel_base': base_slide[0], 'kernel_slide': base_slide[1], 'source': None}
    if base_slide[0] or base_slide[1]:
        report['source'] = 'logs_summary' if any(from_logs_summary(args.logs_summary)) else 'lara.log'

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print('Offsets report saved ->', args.out)


if __name__ == '__main__':
    main()
