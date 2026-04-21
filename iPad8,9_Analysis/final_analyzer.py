#!/usr/bin/env python3
"""
Final Remote Call Analyzer for iPad8,9 iOS 17.3.1
Analyzes test results and provides final offset corrections
"""

import re
import sys
from pathlib import Path

def analyze_test_results(logfile_path):
    """Analyze logs from device testing with task_threads_next debugging"""
    print("=== FINAL REMOTE CALL ANALYSIS ===\n")

    with open(logfile_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Find the task_threads_next debug output
    debug_matches = re.findall(
        r'DEBUG: Testing task_threads_next offsets.*?task_threads_next=(0x[0-9a-f]+): sentinel=(0x[0-9a-f]+) chain=(0x[0-9a-f]+)(?:\s+-> thread=(0x[0-9a-f]+) tro=(0x[0-9a-f]+) \((VALID|INVALID)\))?',
        content,
        re.DOTALL
    )

    if not debug_matches:
        print("No task_threads_next debug output found in log")
        return None

    print("Found task_threads_next debug output:")
    results = []

    for match in debug_matches:
        task_off = match[0]
        sentinel = match[1]
        chain = match[2]
        thread = match[3] if len(match) > 3 else None
        tro = match[4] if len(match) > 4 else None
        validity = match[5] if len(match) > 5 else None

        result = {
            'task_threads_next': task_off,
            'sentinel': sentinel,
            'chain': chain,
            'thread': thread,
            'tro': tro,
            'tro_valid': validity == 'VALID'
        }
        results.append(result)

        print(f"  {task_off}: chain={chain}, thread={thread}, tro={tro} ({validity})")

    # Find the best candidate
    valid_candidates = [r for r in results if r['tro_valid']]
    if valid_candidates:
        best = valid_candidates[0]  # First valid one
        print(f"\n✅ FOUND VALID OFFSET: rc_off_task_threads_next = {best['task_threads_next']}")
        print(f"   Chain: {best['chain']}, Thread: {best['thread']}, TRO: {best['tro']}")

        return best['task_threads_next']
    else:
        print("\n❌ No valid TRO found with any task_threads_next offset")
        print("Need to check TRO offset or thread_ro offsets")

        return None

def generate_final_fixes(correct_task_threads_next):
    """Generate the final code fixes"""
    fixes = []

    if correct_task_threads_next:
        fixes.append(f"""
// Fix 1: Update rc_offsets.m
In rc_offsets.m, change:
uint32_t rc_off_task_threads_next = 0x58;
To:
uint32_t rc_off_task_threads_next = {correct_task_threads_next};
""")

        fixes.append(f"""
// Fix 2: Update derived offsets in rc_probe_tro_offset
In rc_probe_tro_offset, the derived rc_off_thread_task_threads_next should be:
rc_off_thread_task_threads_next = tro_offset - 0x10;
// If tro_offset = 0x358, then 0x358 - 0x10 = 0x348 ✓
// But if task_threads_next changes, tro_offset may need adjustment too
""")

    fixes.append("""
// Fix 3: Remove debug code from RemoteCall.m
Remove the DEBUG: Testing task_threads_next offsets block
""")

    return fixes

def create_final_report(logfile_path):
    """Create comprehensive final report"""
    correct_offset = analyze_test_results(logfile_path)

    if correct_offset:
        fixes = generate_final_fixes(correct_offset)

        report = f"""
# FINAL REMOTE CALL FIX REPORT

## ✅ SOLUTION FOUND

Correct `rc_off_task_threads_next` = {correct_offset}

## Required Code Changes

{chr(10).join(fixes)}

## Testing Instructions

1. Apply the fixes above
2. Rebuild IPA: `python do_build.py`
3. Test on device
4. Verify remote call succeeds with valid TRO values

## Expected Log Output After Fix

```
[init_remote_call:597] Valid thread found: tro=0xffffffdfXXXXXXXX (VALID)
[init_remote_call:597] Injected exception ports into N threads
Remote call initialized successfully
```
"""
    else:
        report = """
# FINAL REMOTE CALL ANALYSIS - NO SOLUTION FOUND

## ❌ Analysis Results

No valid task_threads_next offset found in the tested range (0x48-0x70).

## Possible Next Steps

1. **Check TRO offset**: The rc_off_thread_t_tro = 0x358 may be wrong
2. **Check thread_ro offsets**: proc=0x10, task=0x18 may be wrong for A12X
3. **Manual kernelcache analysis**: Extract correct offsets from 21D61 kernelcache
4. **Alternative approach**: Use static offsets from known working A12X jailbreaks

## Debug Commands to Add

In RemoteCall.m, add more comprehensive debugging:

```c
// Test TRO offsets
for (uint32_t tro_test = 0x338; tro_test <= 0x3F8; tro_test += 8) {
    uint64_t test_tro = kread64(thread_addr + tro_test);
    if (_rc_is_kptr(test_tro)) {
        printf("VALID TRO at +0x%x: 0x%llx\\n", tro_test, test_tro);
    }
}
```
"""

    with open('iPad8,9_Analysis/final_remote_call_report.md', 'w') as f:
        f.write(report)

    print("Created final_remote_call_report.md")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python final_analyzer.py <lara.log>")
        sys.exit(1)

    logfile = sys.argv[1]
    create_final_report(logfile)