#!/usr/bin/env python3
"""aggregate_techniques.py

Агрегирует данные из архива 8ksec и mapping.json, генерирует сводку и черновой отчёт.
"""

from __future__ import annotations
import argparse
import json
import os
from collections import Counter
from datetime import datetime


def safe_load(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def build_summary(archive_dir: str, mapping_path: str):
    fetched = safe_load(os.path.join(archive_dir, 'fetched_index.json')) or []
    tags = Counter()
    titles = []
    for it in fetched:
        for t in it.get('tags', []):
            tags[t] += 1
        titles.append(it.get('title') or '')

    mapping = safe_load(mapping_path) or {}
    files_count = len(mapping.get('mapping', {}) if isinstance(mapping, dict) else mapping)

    top_tags = tags.most_common(20)
    return {'article_count': len(fetched), 'top_tags': top_tags, 'mapped_files_count': files_count}


def write_report(report_path: str, summary: dict, mapping_path: str):
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('# High-level Report (черновик)\n\n')
        f.write('Generated: ' + datetime.utcnow().isoformat() + 'Z\n\n')
        f.write('**Архив статей**: ' + str(summary.get('article_count', 0)) + '\n\n')
        f.write('**Топ меток (техник)**:\n')
        for tag, cnt in summary.get('top_tags', []):
            f.write(f'- {tag}: {cnt}\n')
        f.write('\n')
        f.write('**Файлов в репозитории, сопоставленных с техниками**: ' + str(summary.get('mapped_files_count', 0)) + '\n\n')
        f.write('**Рекомендации (безопасные, нефронтранные):**\n')
        f.write('- Продолжить статический анализ бинарных артефактов (строки, хэши, символы).\n')
        f.write('- Документировать найденные техники и пометить их как исследовательские артефакты.\n')
        f.write('- Планировать тестирование в изолированной среде с ответственными правилами и бэкапами.\n')
        f.write('\n')
        f.write('Mapping file: ' + mapping_path + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True)
    parser.add_argument('--mapping', required=True)
    parser.add_argument('--out', required=True, help='output json summary')
    parser.add_argument('--report', required=True, help='output markdown report')
    args = parser.parse_args()

    summary = build_summary(args.archive, args.mapping)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'generated_at': datetime.utcnow().isoformat() + 'Z', 'summary': summary}, f, ensure_ascii=False, indent=2)
    write_report(args.report, summary, args.mapping)
    print('Wrote summary ->', args.out)
    print('Wrote report ->', args.report)


if __name__ == '__main__':
    main()
