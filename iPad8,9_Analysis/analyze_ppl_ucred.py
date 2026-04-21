#!/usr/bin/env python3
"""
analyze_ppl_ucred.py

Углублённый анализ кандидатов PPL/ucred в распакованном kernelcache.

Процедура:
- использует функции из `find_ppl_ucred.py` для парсинга Mach-O и поиска строк/символов
- для каждого кандидата вычисляет: количество ссылок (references), плотность указателей рядом (pointer density)
- выдаёт вердикт: `valid` / `likely` / `unlikely`
- сохраняет результаты в JSON

Запуск примера:
  python analyze_ppl_ucred.py -i 21D61__iPad8,9/kernelcache.release.iPad8,9_10_11_12 -o ppl_ucred_analysis_21D61.json

"""

from __future__ import annotations
import os
import sys
import json
import argparse
import struct
from typing import List, Dict, Optional

# Ensure script directory is on path so we can import helper module
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    from find_ppl_ucred import parse_macho, parse_symtab, find_ascii_strings, vm_to_fileoff, fileoff_to_vm, scan_for_addr_occurrences
except Exception as e:
    print('Не удалось импортировать find_ppl_ucred:', e)
    raise


def is_pointer_in_segments(val: int, segments: List[Dict]) -> bool:
    for s in segments:
        va = s.get('vmaddr', 0)
        vs = s.get('vmsize', 0)
        if vs == 0:
            continue
        if va <= val < va + vs:
            return True
    return False


def pointer_density(data: bytes, fileoff: Optional[int], segments: List[Dict], max_bytes: int = 256) -> Dict:
    if fileoff is None:
        return {'density': 0.0, 'words': 0, 'valid': 0}
    if fileoff < 0 or fileoff >= len(data):
        return {'density': 0.0, 'words': 0, 'valid': 0}
    avail = len(data) - fileoff
    size = min(avail, max_bytes)
    if size < 8:
        return {'density': 0.0, 'words': 0, 'valid': 0}
    chunk = data[fileoff:fileoff+size]
    words = size // 8
    valid = 0
    for i in range(words):
        v = struct.unpack_from('<Q', chunk, i*8)[0]
        if is_pointer_in_segments(v, segments):
            valid += 1
    density = valid / words if words else 0.0
    return {'density': density, 'words': words, 'valid': valid}


def build_candidates(data: bytes, info: Dict, keys: List[str], minstr: int) -> List[Dict]:
    candidates: List[Dict] = []
    syms = {}
    if info.get('symtab'):
        syms = parse_symtab(data, info['symtab'])

    # symbols
    for name, addr in syms.items():
        lname = name.lower()
        for k in keys:
            if k in lname:
                fo = vm_to_fileoff(info.get('segments', []), addr) if info.get('segments') else None
                candidates.append({'key': k, 'source': 'sym', 'name': name, 'vm': int(addr), 'fileoff': fo})
                break

    # strings
    strs = find_ascii_strings(data, minlen=minstr)
    for off, s in strs.items():
        ls = s.lower()
        for k in keys:
            if k in ls:
                vm = fileoff_to_vm(info.get('segments', []), off) if info.get('segments') else None
                candidates.append({'key': k, 'source': 'str', 'text': s, 'fileoff': int(off), 'vm': vm})
                break

    # deduplicate by (vm,fileoff,name/text)
    seen = set()
    uniq = []
    for c in candidates:
        ident = (c.get('vm'), c.get('fileoff'), c.get('name') or c.get('text'))
        if ident in seen:
            continue
        seen.add(ident)
        uniq.append(c)
    return uniq


def analyze(path: str, outpath: str, keys: List[str], minstr: int, ref_thresh: int, density_thresh: float):
    data = open(path, 'rb').read()
    info = parse_macho(data)
    segments = info.get('segments', [])

    candidates = build_candidates(data, info, keys, minstr)

    results = {'input': path, 'candidates': []}

    for c in candidates:
        vm = c.get('vm')
        fileoff = c.get('fileoff')
        # refs
        refs = 0
        if vm:
            refs = len(scan_for_addr_occurrences(data, int(vm)))
        # density
        dens = pointer_density(data, fileoff, segments)

        # verdict heuristics
        verdict = 'unlikely'
        if (refs >= ref_thresh and dens['density'] >= density_thresh):
            verdict = 'valid'
        elif (refs >= 1 or dens['density'] >= 0.05):
            verdict = 'likely'

        entry = dict(c)
        entry.update({'refs': refs, 'pointer_density': dens['density'], 'pointer_words': dens['words'], 'pointer_valid_count': dens['valid'], 'verdict': verdict})
        results['candidates'].append(entry)

    # save json
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # print brief summary
    cnt = {'valid':0,'likely':0,'unlikely':0}
    for e in results['candidates']:
        cnt[e['verdict']] += 1
    print('Анализ завершён. Кандидатов: %d (valid=%d likely=%d unlikely=%d)' % (len(results['candidates']), cnt['valid'], cnt['likely'], cnt['unlikely']))
    print('Результаты сохранены в', outpath)


def main():
    ap = argparse.ArgumentParser(description='Углублённый анализ PPL/ucred кандидатов')
    ap.add_argument('-i','--input', required=True, help='путь к распакованному kernelcache/Mach-O')
    ap.add_argument('-o','--output', default='ppl_ucred_analysis.json', help='JSON файл с результатами')
    ap.add_argument('-k','--keys', default='ucred,ppl,cr_label,cr_uid,cr_ruid', help='комма-разделённые ключи')
    ap.add_argument('--minstr', type=int, default=6, help='минимальная длина строк для поиска')
    ap.add_argument('--ref-thresh', type=int, default=3, help='минимальное число ссылок для уверенного кандидата')
    ap.add_argument('--density-thresh', type=float, default=0.2, help='порог плотности валидных указателей')
    args = ap.parse_args()

    keys = [k.strip().lower() for k in args.keys.split(',') if k.strip()]
    analyze(args.input, args.output, keys, args.minstr, args.ref_thresh, args.density_thresh)


if __name__ == '__main__':
    main()
