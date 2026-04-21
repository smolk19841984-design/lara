#!/usr/bin/env python3
TRO_PANIC_V2 = {
    'v1': {'tro': 0xffffffdce6834f40, 'points_back': 0xffffffdfe7cad168, 'expected': 0xffffffdfe7a87d70},
    'v2': {'tro': 0xffffffdd3994c580, 'points_back': 0xffffffde1bfb5580, 'expected': 0xffffffde1bfbdc28},
}

print('=' * 70)
print('TRO PANIC COMPARISON: Round 7 vs Round 8')
print('=' * 70)

for ver, d in TRO_PANIC_V2.items():
    print(f'\n[{ver.upper()}]')
    print(f'  TRO:           0x{d["tro"]:016x}')
    print(f'  Points back:   0x{d["points_back"]:016x}')
    print(f'  Expected:      0x{d["expected"]:016x}')
    diff = d['points_back'] - d['expected']
    print(f'  Diff:          0x{diff:x} ({diff} bytes)')
    implied = d['tro'] - 0x368
    print(f'  Implied thread (TRO-0x368): 0x{implied:016x}')
    print(f'  Match expected? {implied == d["expected"]}')

print('\n' + '=' * 70)
print('ANALYSIS:')
print('  Both panics show TRO->thread_ptr != expected thread')
print('  V1 diff: 0x2253f8 (2.2MB) - different thread')
print('  V2 diff: 0x7b58 (31.6KB) - CLOSER but still different thread')
print('  V2 diff is SMALLER - threads are closer but still mismatch')
print('  This means task_threads_next is STILL wrong for A12X iOS 17.3.1')
print('  The offset 0x48 gives threads that are 31KB apart')
print('  Need to try: 0x50, 0x58, 0x60')
print('=' * 70)
