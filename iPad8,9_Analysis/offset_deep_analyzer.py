#!/usr/bin/env python3
"""
Advanced Remote Call Offset Analyzer for iPad8,9 iOS 17.3.1
Analyzes all possible thread_t/task_t offset combinations to find correct TRO and task_threads_next
"""

import re
import sys
from pathlib import Path

def analyze_log_file(logfile_path):
    """Parse lara.log for offset information and failure patterns"""
    print("=== REMOTE CALL OFFSET DEEP ANALYSIS ===\n")

    with open(logfile_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Extract key offsets from log
    offsets = {}

    # Find runtime offsets
    runtime_match = re.search(r'\[rc_offsets\].*?t1sz=(\w+).*?smr_base=(\w+).*?PAC=(\w+)', content)
    if runtime_match:
        offsets['t1sz'] = runtime_match.group(1)
        offsets['smr_base'] = runtime_match.group(2)
        offsets['pac'] = runtime_match.group(3)

    # Find TRO probe results
    tro_probe = re.search(r'\[rc_probe_tro\].*?corrected tro offset: 0x(\w+) -> 0x(\w+)', content)
    if tro_probe:
        offsets['tro_old'] = tro_probe.group(1)
        offsets['tro_new'] = tro_probe.group(2)

    # Find derived offsets
    derived = re.search(r'\[rc_probe_tro\].*?derived offsets: task_threads=0x(\w+) ctid=0x(\w+)', content)
    if derived:
        offsets['task_threads_derived'] = derived.group(1)
        offsets['ctid_derived'] = derived.group(2)

    # Find invalid TRO values
    invalid_tros = re.findall(r'SKIP invalid tro: (0x[0-9a-f]+)', content)
    invalid_tros = list(set(invalid_tros))  # unique

    print(f"Runtime Offsets: {offsets}")
    print(f"Invalid TRO Values: {invalid_tros[:10]}...")  # first 10

    # Analyze TRO patterns
    analyze_tro_patterns(invalid_tros)

    # Generate offset hypotheses
    hypotheses = generate_offset_hypotheses(offsets, invalid_tros)

    print("\n=== HYPOTHESIZED CORRECT OFFSETS ===")
    for i, hypo in enumerate(hypotheses[:5]):  # top 5
        print(f"{i+1}. {hypo}")

    return hypotheses

def analyze_tro_patterns(invalid_tros):
    """Analyze patterns in invalid TRO values to understand the bug"""
    print("\n=== TRO PATTERN ANALYSIS ===")

    # Convert to ints
    tro_vals = []
    for tro in invalid_tros:
        try:
            tro_vals.append(int(tro, 16))
        except:
            continue

    if not tro_vals:
        print("No valid TRO values to analyze")
        return

    # Look for patterns
    diffs = []
    for i in range(1, len(tro_vals)):
        diff = tro_vals[i] - tro_vals[i-1]
        diffs.append(diff)

    print(f"TRO values range: 0x{min(tro_vals):x} - 0x{max(tro_vals):x}")
    print(f"Common differences: {set(diffs)}")

    # Check if they follow arithmetic progression
    if len(set(diffs)) == 1:
        common_diff = list(set(diffs))[0]
        print(f"Arithmetic progression with difference 0x{common_diff:x}")
        print("This suggests wrong rc_off_thread_task_threads_next offset")

def generate_offset_hypotheses(offsets, invalid_tros):
    """Generate hypotheses for correct offsets based on patterns"""
    hypotheses = []

    # Hypothesis 1: task_threads_next is wrong
    # If TRO values are 0x2f00, 0x5b00, 0x0, 0x1f00
    # This looks like wrong offset calculation: chain - offset + offset_back
    # Where offset_back might be wrong

    # Common wrong calculations:
    # If rc_off_thread_task_threads_next should be 0x348 but is 0x58
    # Then chain - 0x58 + 0x58 = chain, but that's not what we see

    # Looking at invalid values: 0x2f00, 0x5b00, 0x0, 0x1f00
    # These look like small values, suggesting wrong base offset

    # Hypothesis: rc_off_task_threads_next is wrong
    # Standard is 0x58, but maybe for A12 it's different

    possible_task_threads_offsets = [0x48, 0x50, 0x58, 0x60, 0x68, 0x70]

    for task_off in possible_task_threads_offsets:
        hypotheses.append(f"rc_off_task_threads_next = 0x{task_off:x} (instead of 0x58)")

    # Hypothesis: TRO offset is wrong
    # Current probe finds 0x358, but maybe it's 0x368 or 0x348

    possible_tro_offsets = [0x348, 0x358, 0x368, 0x378, 0x388]
    for tro_off in possible_tro_offsets:
        hypotheses.append(f"rc_off_thread_t_tro = 0x{tro_off:x} (instead of probed 0x358)")

    # Hypothesis: thread_ro offsets are wrong
    possible_ro_proc = [0x8, 0x10, 0x18, 0x20]
    possible_ro_task = [0x10, 0x18, 0x20, 0x28]

    for proc_off in possible_ro_proc:
        for task_off in possible_ro_task:
            if proc_off < task_off:  # proc before task
                hypotheses.append(f"thread_ro: proc=0x{proc_off:x}, task=0x{task_off:x}")

    return hypotheses

def create_offset_test_script(hypotheses):
    """Create a test script to validate hypotheses"""
    script_content = '''#!/usr/bin/env python3
"""
Offset Validation Script for iPad8,9 iOS 17.3.1
Tests different offset combinations to find correct TRO/task_threads_next
"""

import sys
import os

# Add the analysis directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'iPad8,9_Analysis'))

def test_offset_combination(task_threads_next, tro_offset, ro_proc, ro_task):
    """
    Test a specific combination of offsets
    This would be called from within the jailbreak to validate
    """
    print(f"Testing: task_threads=0x{task_threads_next:x}, tro=0x{tro_offset:x}, ro_proc=0x{ro_proc:x}, ro_task=0x{ro_task:x}")

    # This function would be integrated into rc_kutils.m to test combinations
    # For now, just print the combination

    return False  # Placeholder

if __name__ == "__main__":
    # Test the top hypotheses
    hypotheses = [
        (0x58, 0x358, 0x10, 0x18),  # current
        (0x48, 0x358, 0x10, 0x18),  # task_threads -0x10
        (0x60, 0x358, 0x10, 0x18),  # task_threads +0x8
        (0x58, 0x368, 0x10, 0x18),  # tro +0x10
        (0x58, 0x348, 0x10, 0x18),  # tro -0x10
        (0x58, 0x358, 0x8, 0x10),   # ro offsets -0x8
        (0x58, 0x358, 0x18, 0x20),  # ro offsets +0x8
    ]

    for task_threads, tro, ro_proc, ro_task in hypotheses:
        test_offset_combination(task_threads, tro, ro_proc, ro_task)
'''

    with open('offset_validator.py', 'w') as f:
        f.write(script_content)

    print("Created offset_validator.py for testing hypotheses")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python offset_deep_analyzer.py <lara.log>")
        sys.exit(1)

    logfile = sys.argv[1]
    hypotheses = analyze_log_file(logfile)
    create_offset_test_script(hypotheses)