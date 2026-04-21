#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from collections import Counter
import argparse
import struct

MASK64 = (1 << 64) - 1

def ror(x, r):
    r %= 64
    return ((x >> r) | ((x << (64 - r)) & MASK64)) & MASK64

def rol(x, r):
    r %= 64
    return ((x << r) | (x >> (64 - r))) & MASK64

def bswap64(x):
    return struct.unpack('<Q', struct.pack('>Q', x))[0]

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
    ap.add_argument('--max-qwords', type=int, default=100000)
    ap.add_argument('--top-n', type=int, default=1000)
    ap.add_argument('--out-prefix', default='offsets_iPad8_9_17.3.1_pac_xor_wide')
    args = ap.parse_args()

    p = Path(args.input)
    if not p.exists():
        print('Input not found:', p)
        sys.exit(2)
    data = json.loads(p.read_text())
    qwords = []
    collect_qwords(data, qwords)
    qwords = qwords[:args.max_qwords]
    print('Qwords to process:', len(qwords))

    # Wider mask set
    xor_masks = [0x0, 0xFFFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555,
                 0xFFFF0000FFFF0000, 0x0000FFFF0000FFFF, 0xDEADBEEFDEADBEEF,
                 0x0123456789ABCDEF, 0xFEDCBA9876543210]
    rotations = list(range(0,64,4))  # denser rotations but bounded
    counter = Counter()
    kept = 0

    for q in qwords:
        for xm in xor_masks:
            x = q ^ xm
            # apply plain, ror, rol, and bswap variants
            for r in rotations:
                v1 = ror(x, r)
                v2 = rol(x, r)
                v3 = bswap64(x)
                for v in (v1, v2, v3):
                    # accept if looks like kernel high or OR into canonical high
                    if (v >> 56) >= 0xF0:
                        counter[v] += 1
                        kept += 1
                    else:
                        v2k = (0xFFFF_FFF0_0000_0000 & MASK64) | (v & 0x0000FFFFFFFFFFFF)
                        if (v2k >> 56) >= 0xF0:
                            counter[v2k] += 1
                            kept += 1

    print('Transforms kept:', kept, 'unique:', len(counter))

    out_prefix = Path(args.out_prefix)
    all_out = out_prefix.with_suffix('.json')
    top_out = Path('pac_candidates_top{0}.json'.format(args.top_n))

    with all_out.open('w') as f:
        json.dump({hex(k): v for k, v in counter.items()}, f)

    most = counter.most_common(args.top_n)
    arr = [{'vm': hex(k), 'count': c} for k, c in most]
    top_out.write_text(json.dumps(arr, indent=2))

    print('Wrote', all_out, top_out)

if __name__ == '__main__':
    main()
