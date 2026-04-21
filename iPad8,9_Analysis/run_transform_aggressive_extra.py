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

def byte_permutations(x):
    # yield some byte-level permutations: reverse, swap pairs, swap nibbles per byte
    b = [(x >> (8*i)) & 0xff for i in range(8)]
    # reverse
    rev = 0
    for i in range(8): rev |= (b[7-i] << (8*i))
    yield rev & MASK64
    # swap adjacent pairs
    pairs = b[:]
    for i in range(0,8,2):
        pairs[i], pairs[i+1] = pairs[i+1], pairs[i]
    v=0
    for i in range(8): v |= (pairs[i] << (8*i))
    yield v & MASK64
    # nibble-swap within each byte
    nn=0
    for i in range(8):
        hi = (b[i] >> 4) & 0xF
        lo = b[i] & 0xF
        nn |= ((lo<<4 | hi) << (8*i))
    yield nn & MASK64

def nibble_rotate(x):
    # rotate nibbles (4-bit) across the 64-bit word by 1..15 nibbles
    for r in range(1,16):
        res = 0
        for i in range(16):
            nib = (x >> (4*i)) & 0xF
            newpos = (i + r) % 16
            res |= (nib << (4*newpos))
        yield res & MASK64

def sliding_xor_masks(x):
    # XOR with masks that slide a byte pattern across the word
    patterns = [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00, 0x0123456789ABCDEF]
    for p in patterns:
        for shift in range(0,8):
            mask = ((p << (8*shift)) & MASK64)
            yield x ^ mask

def generate_transforms(q):
    xor_masks = [0x0, 0xFFFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555, 0xDEADBEEFDEADBEEF]
    # full rotations but limited
    for xm in xor_masks:
        x = q ^ xm
        for r in (0,8,16,24,32,40,48,56):
            yield ror(x, r)
            yield rol(x, r)
        yield bswap64(x)
        yield (~x) & MASK64
        for p in byte_permutations(x):
            yield p
        for n in nibble_rotate(x):
            yield n
        for s in sliding_xor_masks(x):
            yield s
    # also try small arithmetic adjustments
    for d in (0,1,2,4,8,16,32,64,128,256):
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
    ap.add_argument('--limit-unique', type=int, default=10000000)
    ap.add_argument('--out-prefix', default='offsets_iPad8_9_17.3.1_pac_aggressive_extra')
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
