#!/usr/bin/env python3
import os
import sys
import struct
import requests

API_BASE = os.environ.get('API_BASE', 'http://127.0.0.1:8000')
TIMEOUT = 5

# Allow overriding known addresses to avoid relying on /api/v1/ds
KERNEL_BASE_STR = os.environ.get('KERNEL_BASE', '0xfffffff011f68000')
OURPROC_STR = os.environ.get('OURPROC', '0xffffffe224f88aa0')

def post_kread(addr, size):
    url = API_BASE + '/api/v1/kread'
    try:
        r = requests.post(url, json={'addr': hex(addr), 'size': size}, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        print('Connection lost during kread:', e)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print('kread request failed:', e)
        sys.exit(1)
    try:
        data = r.json()
    except Exception as e:
        print('Failed to parse kread JSON response:', e)
        sys.exit(1)
    if 'value' in data:
        val = data['value']
        if isinstance(val, str) and val.startswith('0x'):
            raw = bytes.fromhex(val[2:])
        else:
            # fallback decimal
            raw = struct.pack('<Q', int(data.get('value_dec', 0)))
    elif 'data' in data:
        d = data['data']
        if isinstance(d, str):
            hexs = d[2:] if d.startswith('0x') else d
            raw = bytes.fromhex(hexs)
        elif isinstance(d, list):
            raw = bytes(d)
        else:
            print('kread: unsupported data field')
            sys.exit(1)
    else:
        print('kread: missing value/data in response')
        sys.exit(1)
    if len(raw) < size:
        raw = raw.ljust(size, b'\x00')
    return raw[:size]

def to_u64(b):
    return struct.unpack('<Q', b)[0]

def to_u32(b):
    return struct.unpack('<I', b)[0]

def looks_like_kernel_ptr(x):
    # check high bits
    return hex(x).startswith('0xffff')

def main():
    print('Starting step_by_step_probe')
    try:
        kernel_base = int(KERNEL_BASE_STR, 0)
    except Exception:
        print('Invalid KERNEL_BASE:', KERNEL_BASE_STR)
        sys.exit(1)
    try:
        ourproc = int(OURPROC_STR, 0)
    except Exception:
        print('Invalid OURPROC:', OURPROC_STR)
        sys.exit(1)

    # Step 1: PID at ourproc + 0x28
    pid_addr = ourproc + 0x28
    print(f'Step 1: PID Check at 0x{pid_addr:016x}...')
    b = post_kread(pid_addr, 4)
    pid = to_u32(b)
    ok = 'OK' if pid > 0 else 'FAIL'
    print(f'PID Check: [{ok}] (Value: {pid})')

    # Step 2: le_next candidates at +0x0 and +0x8
    ptr0_addr = ourproc + 0x0
    ptr8_addr = ourproc + 0x8
    print(f'Step 2: Next Proc Ptr (@+0x0) reading 8 bytes at 0x{ptr0_addr:016x}...')
    b0 = post_kread(ptr0_addr, 8)
    ptr0 = to_u64(b0)
    print(f'Next Proc Ptr (@+0x0): 0x{ptr0:016x}')
    print(f'Step 2: Next Proc Ptr (@+0x8) reading 8 bytes at 0x{ptr8_addr:016x}...')
    b8 = post_kread(ptr8_addr, 8)
    ptr8 = to_u64(b8)
    print(f'Next Proc Ptr (@+0x8): 0x{ptr8:016x}')
    if not looks_like_kernel_ptr(ptr0) and not looks_like_kernel_ptr(ptr8):
        print('Pointer structure mismatch')

    # Step 3: kernproc slot
    kernproc = kernel_base + 0x96B928
    kern_slot_addr = kernproc + 0x0
    print(f'Step 3: Kernproc slot at 0x{kern_slot_addr:016x} reading 8 bytes...')
    bs = post_kread(kern_slot_addr, 8)
    kern_slot = to_u64(bs)
    print(f'Kernproc Slot Content: 0x{kern_slot:016x}')

    # Step 4: PID at kern_slot + 0x28 if valid
    if not looks_like_kernel_ptr(kern_slot):
        print('Kernproc slot content is not a kernel pointer; aborting Step 4')
        sys.exit(1)
    first_pid_addr = kern_slot + 0x28
    print(f'Step 4: Reading PID at 0x{first_pid_addr:016x}...')
    bpid = post_kread(first_pid_addr, 4)
    first_pid = to_u32(bpid)
    print(f'First Process PID: {first_pid}')
    sys.exit(0)

if __name__ == '__main__':
    main()
