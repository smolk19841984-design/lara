#!/usr/bin/env python3
"""
Conservative XOR+rotate transformer for PAC candidate values.

Reads an existing PAC candidate JSON file (auto-detects common names),
applies a small set of XOR constants and rotate-left amounts, filters
results to kernel-high addresses and writes a deduplicated JSON output.

Output: offsets_iPad8_9_17.3.1_pac_candidates_xor_rotate.json
"""
import json
import os
import sys
from collections import OrderedDict

INPUT_CANDIDATES = [
    'offsets_iPad8_9_17.3.1_pac_candidates_experimental_fast.json',
    'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json',
    'offsets_iPad8_9_17.3.1_pac_candidates_experimental.json',
]
OUT_FILE = 'offsets_iPad8_9_17.3.1_pac_candidates_xor_rotate.json'

# Conservative constants to avoid combinatorial explosion
XOR_CONSTANTS = [
    0x0,
    0x5555555555555555,
    0xAAAAAAAAAAAAAAAA,
    0xFFFF000000000000,
    0x0000FFFF00000000,
]
ROT_AMOUNTS = [0, 8, 16, 24, 32, 40, 48]
KERNEL_HIGH_MASK = 0xfffffff000000000


def rol64(x, n):
    n %= 64
    return ((x << n) & ((1 << 64) - 1)) | ((x & ((1 << 64) - 1)) >> (64 - n))


def load_input():
    for p in INPUT_CANDIDATES:
        if os.path.exists(p):
            print(f'Using input candidates: {p}')
            try:
                with open(p, 'r') as f:
                    data = json.load(f)
                return data
            except Exception as e:
                print('Failed to load', p, '->', e)
    print('No input candidate file found. Expecting JSON array of numbers or dicts with "vm".')
    sys.exit(1)


def iter_values(data):
    # Accept multiple formats: array of ints, or dicts with 'vm'/'value' keys
    for item in data:
        if isinstance(item, int):
            yield item
        elif isinstance(item, str):
            try:
                yield int(item, 0)
            except Exception:
                continue
        elif isinstance(item, dict):
            for k in ('vm', 'value', 'addr'):
                if k in item:
                    try:
                        yield int(item[k], 0)
                    except Exception:
                        pass
                    break


def main():
    data = load_input()
    orig_values = list(iter_values(data))
    print(f'Loaded {len(orig_values)} input values')

    seen = OrderedDict()
    transforms_checked = 0

    for orig in orig_values:
        orig &= (1 << 64) - 1
        for xor in XOR_CONSTANTS:
            temp = orig ^ xor
            for rot in ROT_AMOUNTS:
                val = rol64(temp, rot)
                transforms_checked += 1
                if (val & KERNEL_HIGH_MASK) == KERNEL_HIGH_MASK:
                    key = val
                    if key not in seen:
                        seen[key] = {
                            'orig': hex(orig),
                            'transformed': hex(val),
                            'xor': hex(xor),
                            'rot': rot,
                        }

    out_list = list(seen.values())
    print(f'Checked {transforms_checked} transforms, kept {len(out_list)} kernel-high candidates')

    with open(OUT_FILE, 'w') as f:
        json.dump(out_list, f, indent=2)

    print('Wrote', OUT_FILE)


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

MASK64 = (1 << 64) - 1

def ror(x, r):
    r %= 64
    return ((x >> r) | ((x << (64 - r)) & MASK64)) & MASK64

def load_json(path):
    with open(path, 'rb') as f:
        return json.load(f)

def guess_qword_from_entry(e):
    # Try common shapes: int, dicts with likely keys, lists/tuples
    if isinstance(e, int):
        return e
    if isinstance(e, str):
        try:
            return int(e, 0)
        except Exception:
            return None
    if isinstance(e, dict):
        for k in ('qword','value','val','v','raw','q','qword_val','addr'):
            if k in e:
                try:
                    return int(e[k], 0)
                except Exception:
                    pass
        # fallback: pick first int-like value
        for v in e.values():
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                try:
                    return int(v, 0)
                except Exception:
                    pass
    if isinstance(e, (list, tuple)) and len(e) > 0:
        return guess_qword_from_entry(e[0])
    return None

def is_kernel_vm(v, kernel_base):
    # heuristic: top bytes 0xfffffff0.. or >= kernel_base
    return v >= 0xfffffff000000000 or v >= kernel_base

def main():
    root = Path('.')
    # input PAC candidates (prefer experimental_fast)
    # prefer the full ranked candidate file if present
    candidates_paths = [
        root / 'offsets_iPad8_9_17.3.1_pac_candidates.json',
        root / 'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json',
        root / 'offsets_iPad8_9_17.3.1_pac_candidates_experimental_fast.json'
    ]

    cand_path = None
    for p in candidates_paths:
        if p.exists():
            cand_path = p
            break
    if cand_path is None:
        print('No PAC candidate file found; exiting', file=sys.stderr)
        sys.exit(1)

    print('Loading PAC candidates from', cand_path)
    try:
        cand_data = load_json(cand_path)
    except Exception as e:
        print('Failed to load JSON:', e, file=sys.stderr)
        sys.exit(1)

    # attempt to find kernel base in offsets file
    kernel_base = 0xfffffff007004000
    offsets_file = root / 'offsets_iPad8_9_17.3.1.json'
    if offsets_file.exists():
        try:
            off = load_json(offsets_file)
            # common keys to check
            for k in ('base','unslid_base','kernel_base','text_vm'):
                if k in off:
                    kernel_base = int(off[k], 0) if isinstance(off[k], str) else int(off[k])
                    break
        except Exception:
            pass

    # flatten candidate list to ints with indices
    flat = []
    # detect common container keys used in generated PAC files
    if isinstance(cand_data, dict):
        for key in ('ranked_candidates','candidates','matches','results','items'):
            if key in cand_data and isinstance(cand_data[key], (list,tuple)):
                src = cand_data[key]
                break
        else:
            # fallback: if dict contains 'matches' as empty or list of dicts under different key
            # try to find the first list value
            found = False
            for v in cand_data.values():
                if isinstance(v, (list,tuple)):
                    src = v
                    found = True
                    break
            if not found:
                src = []
    else:
        src = cand_data

    for i, e in enumerate(src):
        q = guess_qword_from_entry(e)
        if q is None:
            continue
        flat.append((i, q))

    print('Total flattened qwords:', len(flat))

    # prefilter like experimental_fast: high byte >= 0xF0 or high16 != 0
    filtered = []
    for idx, q in flat:
        hb = (q >> 56) & 0xff
        hi16 = (q >> 48) & 0xffff
        if hb >= 0xF0 or hi16 != 0:
            filtered.append((idx, q))

    print('Filtered qwords to check:', len(filtered))

    xor_keys = [0x0, 0xffff000000000000, 0x0000ffff00000000, 0x00000000ffffffff, 0xaaaaaaaaaaaaaaaa, 0x5555555555555555]
    rots = [0,8,16,24,32,40,48]

    matches = []
    max_checks = 2000000
    checks = 0

    for idx, q in filtered:
        checks += 1
        if checks > max_checks:
            break
        for k in xor_keys:
            x = q ^ k
            for r in rots:
                t = ror(x, r)
                # direct candidate
                if is_kernel_vm(t, kernel_base):
                    matches.append({'index': idx, 'orig': hex(q), 'xor': hex(k), 'rot': r, 'result': hex(t)})
                # as low48 relative to kernel_base
                low48 = t & ((1 << 48) - 1)
                cand_vm = kernel_base + low48
                if is_kernel_vm(cand_vm, kernel_base):
                    matches.append({'index': idx, 'orig': hex(q), 'xor': hex(k), 'rot': r, 'result': hex(cand_vm), 'low48': True})

    out_fname = root / 'offsets_iPad8_9_17.3.1_pac_xor_rotate.json'
    print('Found matches:', len(matches))
    with open(out_fname, 'w') as f:
        json.dump({'kernel_base': hex(kernel_base), 'matches': matches}, f, indent=2)

    # also overwrite the experimental_fast name so downstream scripts pick it up
    try:
        dst = root / 'offsets_iPad8_9_17.3.1_pac_candidates_experimental_fast.json'
        with open(dst, 'w') as f:
            json.dump({'generated_from': str(cand_path), 'kernel_base': hex(kernel_base), 'matches': matches}, f, indent=2)
    except Exception:
        pass

    print('Wrote', out_fname)

if __name__ == '__main__':
    main()
