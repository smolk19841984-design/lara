from pathlib import Path
import re
import json
import difflib

BASE = Path(__file__).resolve().parents[1]
OUT_JSON = BASE / 'scripts' / 'instr_diff_pmap_cs_report.json'
OUT_TXT = BASE / 'disasm_pmap_cs_instr_diff_summary.txt'

def parse_disasm(fpath):
    insts = []
    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.match(r'^0x[0-9a-fA-F]+\t(\S+)\t?(.*)$', line.strip())
            if m:
                mnemonic = m.group(1)
                op = m.group(2).strip()
                insts.append(f"{mnemonic} {op}".strip())
    return insts

def load_files(tag):
    p = BASE
    files = list((p).glob(f'disasm_pmap_cs_{tag}_*.txt'))
    out = {}
    for f in files:
        m = re.search(rf'disasm_pmap_cs_{tag}_(\w+)\.txt$', str(f))
        if not m:
            continue
        off = int(m.group(1), 16)
        out[off] = parse_disasm(f)
    return out

def pair_offsets(a_offsets, b_offsets):
    paired = []
    used = set()
    b_list = sorted(b_offsets)
    for a in sorted(a_offsets):
        best = None
        bestd = None
        for b in b_list:
            if b in used:
                continue
            d = abs(a - b)
            if best is None or d < bestd:
                best = b
                bestd = d
        if best is not None:
            paired.append((a, best))
            used.add(best)
    # add any remaining b as unmatched pairs
    for b in b_list:
        if b not in used:
            paired.append((None, b))
    return paired

def diff_insts(a, b, context=4):
    sm = difflib.SequenceMatcher(None, a, b)
    diffs = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        diffs.append({'tag': tag, 'a_range': [i1, i2], 'b_range': [j1, j2],
                      'a': a[i1:i2], 'b': b[j1:j2]})
    return diffs

def main():
    a = load_files('21D61')
    b = load_files('21E219')
    pairs = pair_offsets(list(a.keys()), list(b.keys()))

    report = {'pairs': [], 'counts': {'21D61': len(a), '21E219': len(b)}}

    for a_off, b_off in pairs:
        a_list = a.get(a_off, [])
        b_list = b.get(b_off, [])
        diffs = diff_insts(a_list, b_list)
        report['pairs'].append({'a_off': a_off and hex(a_off), 'b_off': b_off and hex(b_off),
                                'a_len': len(a_list), 'b_len': len(b_list),
                                'diff_count': len(diffs), 'diffs': diffs[:20]})

    with open(OUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    # write short text summary
    with open(OUT_TXT, 'w', encoding='utf-8') as t:
        t.write(f"Instruction diff summary for pmap_cs (21D61 vs 21E219)\n")
        t.write(f"21D61 files: {len(a)}; 21E219 files: {len(b)}\n\n")
        for p in report['pairs']:
            t.write(f"A: {p['a_off']}  B: {p['b_off']}  diffs: {p['diff_count']}  lengths: {p['a_len']}/{p['b_len']}\n")
            for d in p['diffs']:
                t.write(f"  - {d['tag']} A[{d['a_range'][0]}:{d['a_range'][1]}] B[{d['b_range'][0]}:{d['b_range'][1]}]\n")
                for i in d['a'][:5]:
                    t.write(f"     -A {i}\n")
                for j in d['b'][:5]:
                    t.write(f"     +B {j}\n")
            t.write('\n')

    print('Written', OUT_JSON, OUT_TXT)

if __name__ == '__main__':
    main()
