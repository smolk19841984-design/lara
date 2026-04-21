#!/usr/bin/env python3
"""
Advanced TRO Pattern Analyzer - Deep analysis of invalid TRO patterns
"""

import re
from collections import Counter

def analyze_tro_patterns(log_file):
    """Analyze TRO patterns to understand the root cause"""

    print("=== ADVANCED TRO PATTERN ANALYSIS ===\n")

    with open(log_file, 'r') as f:
        content = f.read()

    # Extract all TRO-related lines
    tro_lines = []
    for line in content.split('\n'):
        if 'tro' in line.lower() or 'invalid' in line.lower():
            tro_lines.append(line.strip())

    print(f"Found {len(tro_lines)} TRO-related lines")

    # Extract invalid TRO values
    invalid_tro_pattern = r'SKIP invalid tro:\s*(0x[0-9a-fA-F]+)'
    invalid_tros = re.findall(invalid_tro_pattern, content, re.IGNORECASE)

    # Extract valid TRO patterns if any
    valid_tro_pattern = r'Valid threads:\s*(\d+),\s*Injected:\s*(\d+)'
    valid_match = re.search(valid_tro_pattern, content)
    valid_threads = valid_injected = 0
    if valid_match:
        valid_threads = int(valid_match.group(1))
        valid_injected = int(valid_match.group(2))

    print(f"Invalid TROs: {len(invalid_tros)} instances")
    print(f"Valid threads: {valid_threads}, Injected: {valid_injected}")

    # Analyze TRO value patterns
    tro_counter = Counter(invalid_tros)
    print(f"\nTRO Value Distribution:")
    for tro_val, count in tro_counter.most_common():
        print(f"  {tro_val}: {count} times")

    # Analyze if there are patterns in TRO values
    tro_ints = [int(tro, 16) for tro in invalid_tros]
    tro_ints.sort()

    print(f"\nTRO Value Analysis:")
    print(f"  Range: 0x{min(tro_ints):x} - 0x{max(tro_ints):x}")
    print(f"  Unique values: {len(set(tro_ints))}")

    # Look for arithmetic patterns
    if len(tro_ints) > 1:
        diffs = [tro_ints[i+1] - tro_ints[i] for i in range(len(tro_ints)-1)]
        diff_counter = Counter(diffs)
        print(f"  Common differences: {dict(diff_counter.most_common(3))}")

    # Check for kernel pointer patterns
    kernel_pointers = [t for t in tro_ints if t >= 0xfffffff000000000]
    print(f"  Potential kernel pointers: {len(kernel_pointers)}")

    # Analyze thread walking patterns
    thread_walk_pattern = r'first_thread=0x([0-9a-fA-F]+).*first_tro=0x([0-9a-fA-F]+)'
    walk_matches = re.findall(thread_walk_pattern, content, re.IGNORECASE)

    if walk_matches:
        print(f"\nThread Walking Analysis ({len(walk_matches)} samples):")
        for thread_addr, tro_addr in walk_matches[:5]:  # Show first 5
            thread_int = int(thread_addr, 16)
            tro_int = int(tro_addr, 16)
            offset = tro_int - thread_int if tro_int > thread_int else 0
            print(f"  Thread: 0x{thread_addr} -> TRO: 0x{tro_addr} (offset: 0x{offset:x})")

    # Generate recommendations
    recommendations = []

    if valid_threads > 0 and valid_injected > 0:
        recommendations.append("✅ Remote call partially working - some threads valid")
    else:
        recommendations.append("❌ Remote call completely failing - no valid threads")

    if len(invalid_tros) > 100:
        recommendations.append("🔄 High invalid TRO count suggests systematic offset error")

    # Check for specific patterns
    if '0x2f00' in invalid_tros and '0x5b00' in invalid_tros:
        recommendations.append("🎯 TRO pattern (0x2f00, 0x5b00) suggests task_threads_next offset issue")

    if kernel_pointers:
        recommendations.append("💡 Some TROs are kernel pointers - partial success possible")

    return {
        'invalid_count': len(invalid_tros),
        'valid_threads': valid_threads,
        'valid_injected': valid_injected,
        'tro_distribution': dict(tro_counter),
        'recommendations': recommendations
    }

def generate_next_offset_fixes(analysis):
    """Generate specific offset fixes based on analysis"""

    fixes = []

    # Based on TRO patterns, suggest specific fixes
    if analysis['invalid_count'] > 100:
        fixes.append({
            'description': 'Test task_threads_next = 0x50 (between current 0x48 and 0x58)',
            'code': 'rc_off_task_threads_next = 0x50;'
        })

        fixes.append({
            'description': 'Test task_threads_next = 0x40 (lower than current fix)',
            'code': 'rc_off_task_threads_next = 0x40;'
        })

        fixes.append({
            'description': 'Test tro = 0x340 (lower than current 0x348)',
            'code': 'rc_off_thread_t_tro = 0x340; rc_off_thread_task_threads_next = 0x340;'
        })

    return fixes

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python advanced_tro_analyzer.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    analysis = analyze_tro_patterns(log_file)

    print(f"\n=== RECOMMENDATIONS ===")
    for rec in analysis['recommendations']:
        print(f"• {rec}")

    fixes = generate_next_offset_fixes(analysis)
    if fixes:
        print(f"\n=== SUGGESTED FIXES ({len(fixes)} options) ===")
        for i, fix in enumerate(fixes, 1):
            print(f"{i}. {fix['description']}")
            print(f"   Code: {fix['code']}\n")