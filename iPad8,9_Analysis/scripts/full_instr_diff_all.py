from pathlib import Path
import json
import difflib
from collections import namedtuple

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    HAVE_CS = True
except Exception:
    cs = None
    HAVE_CS = False

BASE = Path(__file__).resolve().parents[1]
F1 = BASE / '21D61' / 'kernelcache.decompressed'
F2 = BASE / '21E219' / 'kernelcache.decompressed'
OUT_JSON = BASE / 'scripts' / 'full_instr_diff_all_report.json'
OUT_TXT = BASE / 'full_instr_diff_all_summary.txt'

RANGE_PAD = 0x80
BLOCK = 0x1000
MAX_RANGES = 2000

Range = namedtuple('Range', ['start', 'end'])

def disasm_bytes(data, base_addr=0):
    if not HAVE_CS:
        return [f'HEX {data.hex()}']
    insts = []
    for i in cs.disasm(data, base_addr):
        insts.append(f"{i.mnemonic} {i.op_str}".strip())
    return insts

def find_diff_ranges(p1, p2):
    size = min(p1.stat().st_size, p2.stat().st_size)
    ranges = []
    with open(p1, 'rb') as a, open(p2, 'rb') as b:
        off = 0
        in_diff = False
        cur_start = None
        while off < size:
            a.seek(off); b.seek(off)
            da = a.read(BLOCK); db = b.read(BLOCK)
            if da != db:
                if not in_diff:
                    in_diff = True; cur_start = off
            else:
                if in_diff:
                    ranges.append(Range(cur_start, off))
                    in_diff = False; cur_start = None
            off += BLOCK
        if in_diff:
            ranges.append(Range(cur_start, min(size, off)))
    return ranges

def merge_ranges(ranges, max_gap=BLOCK):
    if not ranges: return []
    ranges = sorted(ranges, key=lambda r: r.start)
    out = [ranges[0]]
    for r in ranges[1:]:
        last = out[-1]
        if r.start - last.end <= max_gap:
            out[-1] = Range(last.start, r.end)
        else:
            out.append(r)
    return out

def main():
    if not F1.exists() or not F2.exists():
        print('Missing kernelcache files; paths:', F1, F2)
        return
    ranges = find_diff_ranges(F1, F2)
    ranges = merge_ranges(ranges)
    if len(ranges) > MAX_RANGES:
        ranges = ranges[:MAX_RANGES]

    report = {'ranges': [], 'counts': {'total_ranges': len(ranges), 'used_capstone': HAVE_CS}}

    with open(F1, 'rb') as a, open(F2, 'rb') as b:
        for r in ranges:
            s = max(0, r.start - RANGE_PAD)
            e = r.end + RANGE_PAD
            a.seek(s); b.seek(s)
            da = a.read(e - s)
            db = b.read(e - s)
            a_insts = disasm_bytes(da, s)
            b_insts = disasm_bytes(db, s)
            sm = difflib.SequenceMatcher(None, a_insts, b_insts)
            diffs = []
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == 'equal':
                    continue
                diffs.append({'tag': tag, 'a_range': [i1, i2], 'b_range': [j1, j2],
                              'a': a_insts[i1:i2], 'b': b_insts[j1:j2]})
            report['ranges'].append({'fileoff_start': hex(s), 'fileoff_end': hex(e), 'diffs_count': len(diffs), 'diffs': diffs[:30]})

    with open(OUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    with open(OUT_TXT, 'w', encoding='utf-8') as t:
        t.write(f'Full instruction diff summary between builds\nRanges compared: {len(report["ranges"])}\n')
        for r in report['ranges']:
            t.write(f"{r['fileoff_start']} - {r['fileoff_end']} diffs: {r['diffs_count']}\n")

    print('Wrote', OUT_JSON, OUT_TXT)

if __name__ == '__main__':
    main()
