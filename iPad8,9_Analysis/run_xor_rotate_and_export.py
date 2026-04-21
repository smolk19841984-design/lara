#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from collections import Counter
import argparse

MASK64 = (1 << 64) - 1

def ror(x, r):
    r %= 64
    return ((x >> r) | ((x << (64 - r)) & MASK64)) & MASK64

def collect_qwords(obj, out):
    if isinstance(obj, int):
        out.append(obj & MASK64)
    elif isinstance(obj, str):
        s = obj.strip()
        if s.startswith('0x'):
            try:
                out.append(int(s, 16) & MASK64)
            except Exception:
                pass
    elif isinstance(obj, list):
        for v in obj:
            collect_qwords(v, out)
    elif isinstance(obj, dict):
        for v in obj.values():
            collect_qwords(v, out)

def main():
    parser = argparse.ArgumentParser(description='Bounded XOR+rotate PAC candidate transformer and exporter')
    parser.add_argument('input', help='Input PAC candidates JSON')
    parser.add_argument('--max-qwords', type=int, default=20000, help='Max qwords to process')
    parser.add_argument('--top-n1', type=int, default=500)
    parser.add_argument('--top-n2', type=int, default=1000)
    parser.add_argument('--out-prefix', default='offsets_iPad8_9_17.3.1_pac_xor_more')
    args = parser.parse_args()

    p = Path(args.input)
    if not p.exists():
        print('Input not found:', args.input)
        sys.exit(2)

    print('Loading', p)
    data = json.loads(p.read_text())
    qwords = []
    collect_qwords(data, qwords)
    if not qwords:
        print('No numeric qwords found in input JSON')
        sys.exit(1)

    qwords = qwords[:args.max_qwords]
    print('Collected qwords:', len(qwords))

    xor_masks = [0xAAAAAAAAAAAAAAAA, 0x5555555555555555, 0xFFFF0000FFFF0000, 0xDEADBEEFDEADBEEF]
    rotations = [0,8,16,24,32,40,48,56]

    counter = Counter()
    kept = 0
    for q in qwords:
        for xm in xor_masks:
            x = q ^ xm
            for r in rotations:
                v = ror(x, r)
                # keep if high byte looks like kernel region
                if (v >> 56) >= 0xF0:
                    counter[v] += 1
                    kept += 1
                else:
                    # also try OR-ing into canonical kernel high
                    v2 = (0xFFFF_FFF0_0000_0000 & MASK64) | (v & 0x0000FFFFFFFFFFFF)
                    if (v2 >> 56) >= 0xF0:
                        counter[v2] += 1
                        kept += 1

    print('Transforms examined, kept candidates:', kept)

    out_prefix = Path(args.out_prefix)
    all_out = out_prefix.with_suffix('.json')
    top500 = Path('pac_candidates_top500.json')
    top1000 = Path('pac_candidates_top1000.json')

    # write full transformed list (as dict value->count)
    with all_out.open('w') as f:
        json.dump({hex(k): v for k, v in counter.items()}, f, indent=2)

    most = counter.most_common()
    def write_top(n, dest):
        arr = [{'vm': hex(k), 'count': c} for k, c in most[:n]]
        dest.write_text(json.dumps(arr, indent=2))

    write_top(args.top_n1, top500)
    write_top(args.top_n2, top1000)

    # short text report
    rpt = Path('pac_candidates_report.txt')
    with rpt.open('w') as f:
        f.write(f'Input: {p}\n')
        f.write(f'Qwords processed: {len(qwords)}\n')
        f.write(f'Transforms kept: {kept}\n')
        f.write(f'Unique transformed candidates: {len(counter)}\n')
        f.write(f'Top {args.top_n1} -> {top500}\n')
        f.write(f'Top {args.top_n2} -> {top1000}\n')
        if most:
            f.write('\nTop 10:\n')
            for k, c in most[:10]:
                f.write(f'{hex(k)}  count={c}\n')

    print('Wrote:', all_out, top500, top1000, rpt)

if __name__ == '__main__':
    main()
