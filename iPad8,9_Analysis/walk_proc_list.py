#!/usr/bin/env python3
"""Walk the kernel proc list and print p_pid values found at candidate offsets.

Usage: python walk_proc_list.py [--api http://host:port] [--max 2000]
"""
import os
import sys
import time
import requests

KERNPROC_OFFSET = 0x96B928
TIMEOUT = 15.0
KREAD_RETRIES = 3
MAX_ITERS = 20000


def api_get(base, path):
    r = requests.get(base + path, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def api_post(base, path, json=None):
    r = requests.post(base + path, json=json, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def kread(base, addr, size):
    for _ in range(KREAD_RETRIES):
        try:
            r = api_post(base, '/api/v1/kread', json={'addr': hex(addr), 'size': size})
            if 'value' in r and isinstance(r['value'], str):
                return int(r['value'], 0)
            if 'data' in r:
                d = r['data']
                if isinstance(d, list):
                    return int.from_bytes(bytes(d), 'little')
                if isinstance(d, str):
                    return int(d, 0)
        except Exception as e:
            print('kread error', e)
            time.sleep(0.2)
    raise RuntimeError('kread failed')


def valid_kernel_ptr(x):
    try:
        return hex(x).startswith('0xffff')
    except Exception:
        return False


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--api', default=os.environ.get('API_BASE', 'http://192.168.1.5:8686'))
    p.add_argument('--max', type=int, default=2000)
    args = p.parse_args()
    base = args.api.rstrip('/')

    ds = api_get(base, '/api/v1/ds')
    if 'kernel_base' not in ds:
        print('kernel_base not present')
        return 2
    kernel_base = int(ds['kernel_base'], 0)
    kernproc_slot = kernel_base + KERNPROC_OFFSET
    print('kernel_base', hex(kernel_base))
    print('kernproc slot', hex(kernproc_slot))

    # read initial slot pointer
    slot_ptr = kread(base, kernproc_slot, 8)
    print('slot_ptr', hex(slot_ptr))
    cur = slot_ptr
    seen = set()
    it = 0
    while cur and it < args.max:
        if cur in seen:
            print('loop detected')
            break
        seen.add(cur)
        if not valid_kernel_ptr(cur):
            print('invalid ptr', hex(cur))
            break
        # try pid offsets
        pids = {}
        for off in (0x10, 0x18, 0x20, 0x28):
            try:
                v = kread(base, cur + off, 4)
            except Exception as e:
                v = None
            pids[off] = v
        # print all raw pid reads for inspection
        print(f'proc 0x{cur:016x} raw pids: ' + ', '.join(f'0x{off:x}=({pids[off]})' for off in pids))
        # next
        try:
            nxt = kread(base, cur + 0x0, 8)
            print(' next ptr read ->', hex(nxt))
        except Exception as e:
            print('next read failed', e)
            break
        cur = nxt
        it += 1

if __name__ == '__main__':
    main()
