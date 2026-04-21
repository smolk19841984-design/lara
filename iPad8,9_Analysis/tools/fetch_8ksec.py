#!/usr/bin/env python3
"""fetch_8ksec.py

Простой индексатор и архиватор статей 8kSec iOS блогов.
Только стандартная библиотека Python — никаких внешних зависимостей.

Пример:
  python iPad8,9_Analysis/tools/fetch_8ksec.py --fetch-articles --outdir iPad8,9_Analysis/8ksec_archive --max 20
"""

from __future__ import annotations
import argparse
import json
import os
import time
import re
from urllib.request import Request, urlopen
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._in_a = False
        self._href = None
        self._text = ''

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self._in_a = True
            self._text = ''
            self._href = None
            for k, v in attrs:
                if k == 'href':
                    self._href = v

    def handle_endtag(self, tag):
        if tag == 'a' and self._href:
            self.links.append((self._href, self._text.strip()))
            self._in_a = False
            self._href = None

    def handle_data(self, data):
        if self._in_a:
            self._text += data


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._texts = []

    def handle_data(self, data):
        s = data.strip()
        if s:
            self._texts.append(s)

    def get_text(self):
        return ' '.join(self._texts)


def fetch_url(url: str, timeout: int = 20) -> str:
    req = Request(url, headers={'User-Agent': '8ksec-indexer/1.0'})
    with urlopen(req, timeout=timeout) as r:
        charset = r.headers.get_content_charset() or 'utf-8'
        return r.read().decode(charset, errors='replace')


def normalize_url(base: str, href: str | None) -> str | None:
    if not href:
        return None
    href = href.strip()
    if href.startswith('mailto:') or href.startswith('javascript:') or href.startswith('#'):
        return None
    return urljoin(base, href)


def parse_index(html: str, base: str):
    p = LinkExtractor()
    p.feed(html)
    out = []
    seen = set()
    for href, text in p.links:
        full = normalize_url(base, href)
        if not full:
            continue
        parsed = urlparse(full)
        if '8ksec.io' not in parsed.netloc:
            continue
        if full in seen:
            continue
        seen.add(full)
        out.append({'url': full, 'title': text})
    return out


def extract_text(html: str) -> str:
    p = TextExtractor()
    p.feed(html)
    return p.get_text()


def guess_tags(text: str):
    tags = set()
    low = text.lower()
    if 'frida' in low:
        tags.add('FRIDA')
    if 'jailbreak' in low or 'dopamine' in low:
        tags.add('JAILBREAK')
    if 'ipsw' in low:
        tags.add('IPSW')
    if 'kernel' in low or 'cve' in low or 'panic' in low:
        tags.add('KERNEL')
    if 'mie' in low or 'memory integrity' in low:
        tags.add('MIE')
    if 'sandbox' in low:
        tags.add('SANDBOX')
    if 'ssl' in low and 'pin' in low:
        tags.add('SSL_PINNING')
    if 'deep link' in low or 'deeplink' in low:
        tags.add('DEEPLINK')
    if 'encryption' in low:
        tags.add('ENCRYPTION')
    return sorted(tags)


def save_json(obj, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Index and archive 8kSec iOS blog articles (stdlib only).')
    parser.add_argument('--index-url', default='https://8ksec.io/ios-security-blogs/', help='Index page to crawl')
    parser.add_argument('--outdir', default='iPad8,9_Analysis/8ksec_archive', help='Output directory')
    parser.add_argument('--fetch-articles', action='store_true', help='Also fetch article pages')
    parser.add_argument('--max', type=int, default=0, help='Max articles to fetch (0 = all)')
    args = parser.parse_args()

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    print('Fetching index:', args.index_url)
    index_html = fetch_url(args.index_url)
    items = parse_index(index_html, args.index_url)
    print(len(items), 'links found on index (filtered by domain)')
    index_path = os.path.join(outdir, 'index.json')
    save_json(items, index_path)
    print('Saved index ->', index_path)

    if args.fetch_articles:
        maxn = args.max or len(items)
        fetched = []
        for i, item in enumerate(items[:maxn]):
            url = item['url']
            print(f'[{i+1}/{maxn}] Fetching', url)
            try:
                art_html = fetch_url(url)
            except Exception as e:
                print('  fetch failed:', e)
                continue
            text = extract_text(art_html)
            tags = guess_tags(text)
            summary = ' '.join(text.split()[:200])
            meta = {'url': url, 'title': item.get('title') or '', 'tags': tags, 'summary': summary}
            fname = f'article_{i+1:03d}.json'
            path = os.path.join(outdir, fname)
            save_json({'meta': meta, 'text': text}, path)
            fetched.append(meta)
            time.sleep(0.5)
        save_json(fetched, os.path.join(outdir, 'fetched_index.json'))
        print('Fetched', len(fetched), 'articles saved in', outdir)


if __name__ == '__main__':
    main()
