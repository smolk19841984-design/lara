#!/usr/bin/env python3
"""Read 1024 bytes from ourproc and analyze for UID/PID/pointer patterns.

Usage: python deep_proc_dump.py [--api http://host:port]

Only reads; no writes.
"""
import os
import sys
import time
import requests
import argparse

TIMEOUT = 20.0
KREAD_RETRIES = 3
READ_SIZE = 1024


def api_get(base, path):
    r = requests.get(base + path, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def api_post(base, path, json=None):
    r = requests.post(base + path, json=json, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def parse_kread(resp):
    if 'value' in resp and isinstance(resp['value'], str):
        s = resp['value']
        if s.startswith('0x'):
            s = s[2:]
        if len(s) % 2:
            s = '0' + s
        return bytes.fromhex(s)
    if 'data' in resp:
        d = resp['data']
        if isinstance(d, str):
            s = d
            if s.startswith('0x'):
                s = s[2:]
            if len(s) % 2:
                s = '0' + s
            return bytes.fromhex(s)
        if isinstance(d, list):
            return bytes(d)
    raise RuntimeError('unsupported kread response format')


def kread_bytes(base, addr, size):
    last_exc = None
    for attempt in range(1, KREAD_RETRIES + 1):
        try:
            resp = api_post(base, '/api/v1/kread', json={'addr': hex(addr), 'size': size})
            return parse_kread(resp)
        except requests.exceptions.ConnectionError:
            print('[CRITICAL] Connection lost during kread. Aborting.')
            sys.exit(1)
        except Exception as e:
            last_exc = e
            print(f'kread attempt {attempt} failed: {e}')
            time.sleep(0.5)
    raise last_exc


def hexdump(addr, data, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        print(f'{addr + i:016x}: {hexs}')


def find_patterns(data):
    patterns = {
        'UID501': bytes.fromhex('f5010000'),
        'PID_~1000': bytes.fromhex('e8030000'),
    }
    matches = []
    for name, pat in patterns.items():
        idx = data.find(pat)
        while idx != -1:
            matches.append((name, idx))
            idx = data.find(pat, idx + 1)

    # scan for kernel-like pointers: sequences starting with ff ff ff e* or ff ff ff f*
    kp = []
    for i in range(0, len(data) - 7):
        b0, b1, b2, b3 = data[i], data[i+1], data[i+2], data[i+3]
        if b0 == 0xff and b1 == 0xff and b2 == 0xff and b3 >= 0xe0:
            kp.append(i)
    return matches, kp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', default=os.environ.get('API_BASE', 'http://127.0.0.1:8000'))
    args = parser.parse_args()
    base = args.api.rstrip('/')

    print('Reading /api/v1/ds for ourproc...')
    ds = api_get(base, '/api/v1/ds')
    if not ds or 'ourproc' not in ds:
        print('Failed to read ourproc from /api/v1/ds')
        sys.exit(2)
    ourproc = int(ds['ourproc'], 0) if isinstance(ds['ourproc'], str) else int(ds['ourproc'])
    print(f'ourproc = 0x{ourproc:016x}')

    print(f'Reading {READ_SIZE} bytes from ourproc...')
    data = kread_bytes(base, ourproc, READ_SIZE)
    if len(data) < READ_SIZE:
        print(f'Warning: read {len(data)} bytes (< {READ_SIZE})')

    print('\n--- HEX DUMP (16-byte rows) ---')
    hexdump(ourproc, data)

    print('\n--- Pattern analysis ---')
    matches, kps = find_patterns(data)
    if matches:
        for name, off in matches:
            print(f'Found {name} at offset 0x{off:03x} (absolute 0x{ourproc + off:016x})')
    else:
        print('No UID/PID patterns found (UID501 or PID~1000)')

    if kps:
        print(f'Found {len(kps)} kernel-like pointer(s) at offsets: ' + ', '.join(hex(x) for x in kps))
        for off in kps:
            absaddr = ourproc + off
            # show 8 bytes little-endian and big-endian interpretations
            seq = data[off:off+8]
            print(f'Offset 0x{off:03x} abs 0x{absaddr:016x} bytes: ' + ' '.join(f'{b:02x}' for b in seq))
    else:
        print('No kernel-like pointers detected in the 1KB window')


if __name__ == '__main__':
    main()
