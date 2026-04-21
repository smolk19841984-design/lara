#!/usr/bin/env python3
import sys
PANIC_DATA = {
    'tro_address': 0xffffffdce6834f40,
    'tro_points_back_to': 0xffffffdfe7cad168,
    'expected_thread': 0xffffffdfe7a87d70,
    'panic_caller': 0xfffffff01aae2600,
    'kernel_slide': 0x12650000,
}
A12X_OFFSETS = {'thread_t_tro': 0x368}
def pacstrip(p): return 0xFFFFFF0000000000 | (p & 0x0000FFFFFFFFFFFF)
def is_kptr(p): return p >= 0xffffff0000000000
def analyze():
    print('=' * 70)
    print('TRO PANIC ANALYSIS REPORT')
    print('=' * 70)
    slide = PANIC_DATA['kernel_slide']
    caller = PANIC_DATA['panic_caller']
    unslid = caller - slide
    tro = PANIC_DATA['tro_address']
    expected = PANIC_DATA['expected_thread']
    actual = PANIC_DATA['tro_points_back_to']
    tro_off = A12X_OFFSETS['thread_t_tro']
    print(f'\n[1] PANIC DETAILS')
    print(f'  TRO address:         0x{tro:016x}')
    print(f'  TRO points back to:  0x{actual:016x}')
    print(f'  Expected thread:     0x{expected:016x}')
    print(f'  Panic caller:        0x{caller:016x} (slid)')
    print(f'  Kernel slide:        0x{slide:016x}')
    print(f'  Unslid caller:       0x{unslid:016x}')
    diff = actual - expected
    print(f'\n[2] THREAD MISMATCH')
    print(f'  Actual TRO->thread:  0x{actual:016x}')
    print(f'  Expected thread:     0x{expected:016x}')
    print(f'  Difference:          0x{diff:x} ({diff} bytes)')
    print(f'\n[3] TRO OFFSET CHECK')
    implied_thread = tro - tro_off
    print(f'  thread->t_tro offset: 0x{tro_off:x}')
    print(f'  Implied thread (TRO - offset): 0x{implied_thread:016x}')
    print(f'  Expected thread:               0x{expected:016x}')
    print(f'  Match? {implied_thread == expected}')
    print(f'\n[4] ALTERNATIVE TRO OFFSETS')
    for test_off in [0x358, 0x360, 0x368, 0x370, 0x378, 0x380]:
        implied = tro - test_off
        match = 'MATCH' if implied == expected else ''
        print(f'  offset 0x{test_off:03x}: implied=0x{implied:016x} {match}')
    print(f'\n[5] REVERSE: expected_thread + offset = TRO?')
    for test_off in [0x358, 0x360, 0x368, 0x370, 0x378, 0x380]:
        computed = expected + test_off
        match = 'MATCH' if computed == tro else ''
        print(f'  thread + 0x{test_off:03x} = 0x{computed:016x} {match}')
    correct_offset = tro - expected
    print(f'\n[6] COMPUTED CORRECT TRO OFFSET')
    print(f'  TRO - expected_thread = 0x{tro:x} - 0x{expected:x}')
    print(f'  = 0x{correct_offset:x} ({correct_offset})')
    if correct_offset < 0:
        print(f'  NEGATIVE - TRO is BEFORE expected thread in memory')
        print(f'  TRO is NOT at thread+offset, but at a SEPARATE allocation')
    elif correct_offset > 0x1000:
        print(f'  Too large for struct offset - TRO is SEPARATE allocation')
    else:
        print(f'  Reasonable struct offset')
    print(f'\n[7] PAC ANALYSIS')
    tro_s = pacstrip(tro)
    exp_s = pacstrip(expected)
    act_s = pacstrip(actual)
    print(f'  TRO (stripped):          0x{tro_s:016x}')
    print(f'  Expected (stripped):     0x{exp_s:016x}')
    print(f'  Actual TRO->thread (s):  0x{act_s:016x}')
    print(f'\n[8] KERNEL POINTER VALIDATION')
    print(f'  TRO valid kptr:   {is_kptr(tro)}')
    print(f'  Expected valid:   {is_kptr(expected)}')
    print(f'  Actual valid:     {is_kptr(actual)}')
    print(f'\n[9] ROOT CAUSE')
    print(f'  sbx_escape_via_remote_call() calls init_remote_call()')
    print(f'  init_remote_call() finds SpringBoard threads')
    print(f'  set_exception_port_on_thread() modifies thread struct')
    print(f'  Kernel checks TRO->thread_ptr == thread')
    print(f'  MISMATCH detected -> PANIC at bsd_kern.c:140')
    print(f'')
    print(f'  KEY INSIGHT: TRO = Thread Read Only')
    print(f'  We CANNOT modify TRO thread_ptr after thread creation')
    print(f'  If we modify the wrong thread or wrong offset,')
    print(f'  the kernel detects the mismatch and panics')
    print(f'\n[10] RECOMMENDATIONS')
    print(f'  1. BLOCK sbx_escape_via_remote_call() - ALREADY done')
    print(f'  2. DO NOT use init_remote_call until TRO offset confirmed')
    print(f'  3. Find correct TRO offset via kernelcache analysis')
    print(f'  4. Verify rc_offsets.m A12X override block executes')
    print(f'  5. Alternative: use different injection method without TRO')
    print(f'\n' + '=' * 70)
    if correct_offset < 0 or correct_offset > 0x1000:
        print(f'CONCLUSION: TRO is NOT a field of thread struct!')
        print(f'TRO is a SEPARATE memory allocation.')
        print(f'Offset 0x368 is correct for accessing thread->t_tro,')
        print(f'but TRO->thread_ptr points to a DIFFERENT thread.')
        print(f'This means we are injecting into the WRONG thread.')
    else:
        print(f'CONCLUSION: TRO offset 0x{correct_offset:x} is correct')
    print(f'=' * 70)
analyze()
