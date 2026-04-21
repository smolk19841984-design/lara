#!/usr/bin/env python3
import json, sys
from pathlib import Path
from collections import Counter
import argparse, struct

MASK64 = (1 << 64) - 1

def ror(x, r):
    r %= 64
    return ((x >> r) | ((x << (64 - r)) & MASK64)) & MASK64

def rol(x, r):
    r %= 64
    return ((x << r) | (x >> (64 - r))) & MASK64

def bswap64(x):
    return struct.unpack('<Q', struct.pack('>Q', x))[0]

def generate_transforms(q):
    xor_masks = [
        0x0, 0xFFFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555,
        0xFFFF0000FFFF0000, 0x0000FFFF0000FFFF, 0xDEADBEEFDEADBEEF,
        0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x0F0F0F0F0F0F0F0F,
        0xF0F0F0F0F0F0F0F0, 0xCCCCCCCCCCCCCCCC, 0x3333333333333333,
        0xFFFFFFFF00000000, 0x00000000FFFFFFFF, 0xFFFF00000000FFFF
    ]
    # full rotations
    rotations = list(range(0,64,1))
    for xm in xor_masks:
        x = q ^ xm
        for r in rotations:
            yield ror(x, r)
            yield rol(x, r)
        yield bswap64(x)
        yield (~x) & MASK64
        # also try transformations on original q
        yield bswap64(q)
        yield (~q) & MASK64
    # small additive/subtractive tweaks
    for d in (0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024):
        yield (q + d) & MASK64
        yield (q - d) & MASK64

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
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('--max-qwords', type=int, default=50000)
    ap.add_argument('--top-n', type=int, default=2000)
    ap.add_argument('--limit-unique', type=int, default=5000000)
    ap.add_argument('--out-prefix', default='offsets_iPad8_9_17.3.1_pac_expanded_full')
    args = ap.parse_args()

    p = Path(args.input)
    if not p.exists():
        print('Input not found:', p)
        sys.exit(2)
    print('Loading', p)
    data = json.loads(p.read_text())
    qwords = []
    collect_qwords(data, qwords)
    if not qwords:
        print('No qwords found')
        sys.exit(1)
    qwords = qwords[:args.max_qwords]
    print('Processing qwords:', len(qwords))

    counter = Counter()
    kept = 0
    for i, q in enumerate(qwords, start=1):
        for v in generate_transforms(q):
            # accept kernel-high direct or OR into canonical kernel high
            if (v >> 56) >= 0xF0:
                counter[v] += 1
                kept += 1
            else:
                v2 = (0xFFFF_FFF0_0000_0000 & MASK64) | (v & 0x0000FFFFFFFFFFFF)
                if (v2 >> 56) >= 0xF0:
                    counter[v2] += 1
                    kept += 1
        if i % 5000 == 0:
            print('Processed', i, 'qwords  unique:', len(counter))
        if len(counter) >= args.limit_unique:
            print('Reached unique limit', args.limit_unique)
            break

    print('Transforms kept:', kept, 'unique:', len(counter))
    out_prefix = Path(args.out_prefix)
    all_out = out_prefix.with_suffix('.json')
    top_out = Path(f'pac_candidates_top{args.top_n}.json')
    with all_out.open('w') as f:
        json.dump({hex(k): v for k, v in counter.items()}, f)
    most = counter.most_common(args.top_n)
    arr = [{'vm': hex(k), 'count': c} for k, c in most]
    top_out.write_text(json.dumps(arr, indent=2))
    print('Wrote', all_out, top_out)

if __name__ == '__main__':
    main()
