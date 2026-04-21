from pathlib import Path
import json
import difflib
import re

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    HAVE_CS = True
except Exception:
    cs = None
    HAVE_CS = False

BASE = Path(__file__).resolve().parents[1]
REPORT_IN = BASE / 'scripts' / 'find_functions_report.json'
F1 = BASE / '21D61' / 'kernelcache.decompressed'
F2 = BASE / '21E219' / 'kernelcache.decompressed'
OUT_JSON = BASE / 'scripts' / 'focus_funcs_diff_report.json'
OUT_TXT = BASE / 'focus_funcs_diff_summary.txt'

WINDOW = 0x200

TARGETS = ['pmap_cs_', 'pmap_enter', 'pmap_change_wiring']

def read_window(fpath, off, size=WINDOW):
    with open(fpath, 'rb') as f:
        f.seek(off)
        return f.read(size)

def disasm(data, base):
    if not HAVE_CS:
        # fallback hex lines
        return [data[i:i+4].hex() for i in range(0, len(data), 4)]
    out = []
    for i in cs.disasm(data, base):
        out.append(f"{i.mnemonic} {i.op_str}".strip())
    return out

def pair_offsets(a_offsets, b_offsets):
    a_sorted = sorted(a_offsets)
    b_sorted = sorted(b_offsets)
    pairs = []
    used = set()
    for a in a_sorted:
        best = None; bestd = None
        for b in b_sorted:
            if b in used: continue
            d = abs(a - b)
            if best is None or d < bestd:
                best = b; bestd = d
        if best is not None:
            pairs.append((a, best))
            used.add(best)
    # remaining b unmatched
    for b in b_sorted:
        if b not in used:
            pairs.append((None, b))
    return pairs

def hexlist(lst):
    return [hex(x) for x in lst]

def main():
    if not REPORT_IN.exists():
        print('Missing', REPORT_IN); return
    data = json.loads(REPORT_IN.read_text(encoding='utf-8'))
    a_map = data.get('21D61', {})
    b_map = data.get('21E219', {})

    out = {'targets': {}, 'have_capstone': HAVE_CS}

    for t in TARGETS:
        a_offs = [int(x['fileoff'],16) for x in a_map.get(t, [])]
        b_offs = [int(x['fileoff'],16) for x in b_map.get(t, [])]
        pairs = pair_offsets(a_offs, b_offs)
        recs = []
        for a_off, b_off in pairs:
            a_seq = []
            b_seq = []
            if a_off is not None:
                a_bytes = read_window(F1, a_off)
                a_seq = disasm(a_bytes, a_off)
            if b_off is not None:
                b_bytes = read_window(F2, b_off)
                b_seq = disasm(b_bytes, b_off)
            sm = difflib.SequenceMatcher(None, a_seq, b_seq)
            diffs = []
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == 'equal': continue
                diffs.append({'tag': tag, 'a_range':[i1,i2], 'b_range':[j1,j2], 'a': a_seq[i1:i2], 'b': b_seq[j1:j2]})
            recs.append({'a_off': a_off and hex(a_off), 'b_off': b_off and hex(b_off), 'a_len': len(a_seq), 'b_len': len(b_seq), 'diff_count': len(diffs), 'diffs': diffs})
        out['targets'][t] = {'a_offs': hexlist(a_offs), 'b_offs': hexlist(b_offs), 'pairs': recs}

    OUT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')

    # write summary
    lines = []
    for t,v in out['targets'].items():
        lines.append(f'Target {t}: a_offs={v["a_offs"]} b_offs={v["b_offs"]}')
        for p in v['pairs']:
            lines.append(f" A:{p['a_off']} B:{p['b_off']} diffs:{p['diff_count']} lenA:{p['a_len']} lenB:{p['b_len']}")
            for d in p['diffs'][:3]:
                lines.append(f"  - {d['tag']} A[{d['a_range'][0]}:{d['a_range'][1]}] B[{d['b_range'][0]}:{d['b_range'][1]}]")
    OUT_TXT.write_text('\n'.join(lines), encoding='utf-8')
    print('Wrote', OUT_JSON, OUT_TXT)

if __name__ == '__main__':
    main()
