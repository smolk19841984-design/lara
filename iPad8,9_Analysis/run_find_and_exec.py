#!/usr/bin/env python3
"""Helper: read ourproc PID then invoke find_our_real_proc.py with it."""
import os
import sys
import requests
import subprocess

BASE = os.environ.get('API_BASE', 'http://192.168.1.5:8686').rstrip('/')
TIMEOUT = 15

def get_ds():
    r = requests.get(BASE + '/api/v1/ds', timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def kread(addr, size=4):
    r = requests.post(BASE + '/api/v1/kread', json={'addr': hex(addr), 'size': size}, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def extract_val(resp):
    if 'value' in resp and isinstance(resp['value'], str):
        return int(resp['value'], 0)
    if 'data' in resp:
        d = resp['data']
        if isinstance(d, str):
            return int(d, 0)
        if isinstance(d, list):
            return int.from_bytes(bytes(d), 'little')
    raise ValueError('unknown kread format')

def main():
    ds = get_ds()
    if 'ourproc' not in ds:
        print('ourproc not in ds')
        return 2
    ourproc = int(ds['ourproc'], 0)
    print('ourproc =', hex(ourproc))
    for off in (0x10, 0x18, 0x20, 0x28):
        try:
            r = kread(ourproc + off, 4)
            v = extract_val(r)
            print(f'read pid {v} at offset 0x{off:x}')
            if 0 < v < 100000:
                pid = v
                print('FOUND PID', pid)
                cmd = [sys.executable, 'find_our_real_proc.py', '--pid', str(pid), '--api', BASE]
                return subprocess.call(cmd)
        except Exception as e:
            print('kread error at off', hex(off), e)
    print('No valid pid found in ourproc offsets')
    return 3

if __name__ == '__main__':
    sys.exit(main())
