#!/usr/bin/env python3
"""Probe ourproc: read next pointers at 0x0 and 0x8 and dump memory around ourproc."""
import os,sys,time,requests

BASE = os.environ.get('API_BASE','http://192.168.1.5:8686').rstrip('/')
TIMEOUT = 20

def get_ds():
    r = requests.get(BASE + '/api/v1/ds', timeout=TIMEOUT); r.raise_for_status(); return r.json()
def kread(addr, size):
    r = requests.post(BASE + '/api/v1/kread', json={'addr': hex(addr), 'size': size}, timeout=TIMEOUT); r.raise_for_status(); return r.json()

def extract_bytes(r):
    if 'value' in r and isinstance(r['value'], str):
        h = r['value'][2:] if r['value'].startswith('0x') else r['value']
        if len(h)%2: h='0'+h
        return bytes.fromhex(h)
    if 'data' in r:
        d = r['data']
        if isinstance(d, list): return bytes(d)
        if isinstance(d, str):
            h = d[2:] if d.startswith('0x') else d
            if len(h)%2: h='0'+h
            return bytes.fromhex(h)
    raise RuntimeError('unknown kread format')

def hexdump(addr, data, width=16):
    for i in range(0,len(data),width):
        chunk = data[i:i+width]
        print(f'{addr+i:016x}: ' + ' '.join(f'{b:02x}' for b in chunk))

def main():
    ds = get_ds()
    if 'ourproc' not in ds:
        print('no ourproc'); return 2
    ourproc = int(ds['ourproc'],0)
    print('ourproc', hex(ourproc))
    for off in (0x0, 0x8):
        try:
            b = extract_bytes(kread(ourproc+off, 8))
            print(f'next at 0x{off:x}:', b.hex())
        except Exception as e:
            print('read next failed', off, e)
    print('\nDump 256 bytes at ourproc:')
    try:
        d = extract_bytes(kread(ourproc, 256))
        hexdump(ourproc, d)
    except Exception as e:
        print('dump256 failed', e)
    print('\nDump 1024 bytes at ourproc:')
    try:
        d = extract_bytes(kread(ourproc, 1024))
        hexdump(ourproc, d[:512])
        print('...')
    except Exception as e:
        print('dump1024 failed', e)

if __name__=='__main__':
    main()
