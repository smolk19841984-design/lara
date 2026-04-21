#!/usr/bin/env python3
"""map_techniques.py

Сопоставляет теги/ключевые слова из архива статей с файлами в репозитории.
Ищет в текстовом содержимом файлов совпадения по ключевым словам и сохраняет карту.

Пример:
  python iPad8,9_Analysis/tools/map_techniques.py --archive iPad8,9_Analysis/8ksec_archive --repo . --out iPad8,9_Analysis/8ksec_archive/mapping.json
"""

from __future__ import annotations
import argparse
import json
import os
import re


def load_tags(archive_dir: str):
    fetched = os.path.join(archive_dir, 'fetched_index.json')
    extra = ['frida','jailbreak','dopamine','ipsw','kernel','cve','mie','sandbox','ssl','pinning','deep','deeplink','panic','ppl','patch','diff','encryption']
    tags = set()
    keywords = set(extra)
    if os.path.exists(fetched):
        with open(fetched, 'r', encoding='utf-8') as f:
            items = json.load(f)
        for it in items:
            for t in it.get('tags', []):
                tags.add(t)
            title = it.get('title') or ''
            summary = it.get('summary') or ''
            for w in re.split(r"\W+", title + ' ' + summary):
                w = w.strip()
                if len(w) >= 3:
                    keywords.add(w.lower())
    return tags, keywords


def search_repo(repo_root: str, keywords: set[str]):
    mapping = {}
    for root, _, files in os.walk(repo_root):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                txt = data.decode('utf-8', errors='ignore').lower()
            except Exception:
                continue
            matches = []
            for kw in keywords:
                if kw in txt:
                    lines = []
                    for i, line in enumerate(txt.splitlines()):
                        if kw in line:
                            lines.append({'line_no': i+1, 'line': line.strip()})
                            if len(lines) >= 5:
                                break
                    matches.append({'keyword': kw, 'snippets': lines})
            if matches:
                mapping[path] = matches
    return mapping


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', default='iPad8,9_Analysis/8ksec_archive')
    parser.add_argument('--repo', default='.')
    parser.add_argument('--out', default='iPad8,9_Analysis/8ksec_archive/mapping.json')
    args = parser.parse_args()

    tags, keywords = load_tags(args.archive)
    print('Loaded tags:', sorted(tags))
    print('Keywords count:', len(keywords))

    mapping = search_repo(args.repo, keywords)

    # convert absolute paths to repo-relative paths
    repo_root_abs = os.path.abspath(args.repo)
    rel_mapping = {}
    for path, matches in mapping.items():
        try:
            rel = os.path.relpath(path, start=repo_root_abs)
        except Exception:
            rel = path
        rel_mapping[rel] = matches

    out_obj = {'tags': sorted(list(tags)), 'keywords': sorted(list(keywords)), 'mapping': rel_mapping}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(out_obj, f, ensure_ascii=False, indent=2)
    print('Saved mapping to', args.out)


if __name__ == '__main__':
    main()
