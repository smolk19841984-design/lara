#!/usr/bin/env python3
"""
Offset Testing Framework - Automated testing of different offset combinations
"""

import os
import re
import subprocess
import time
import sys

def test_offset_combination(task_threads_offset, tro_offset, description):
    """Test a specific offset combination by rebuilding and analyzing"""

    print(f"\n🧪 TESTING: {description}")
    print(f"   task_threads_next = 0x{task_threads_offset:x}")
    print(f"   thread_t_tro = 0x{tro_offset:x}")

    # Update rc_offsets.m (robust block replacement using marker + brace counting)
    offsets_file = os.path.join(os.getcwd(), 'jbdc', 'kexploit', 'rc_offsets.m')

    if not os.path.exists(offsets_file):
        print(f"   ❌ Offsets file not found: {offsets_file}")
        return False

    with open(offsets_file, 'r', encoding='utf-8') as f:
        content = f.read()

    marker = '// A12X iOS 17.3.1 specific fix based on 8kSec research'

    # Try to find the if-block after the marker
    start_search = content.find(marker) if marker in content else 0
    pos_if = content.find('if (SYS_VER_GE(@"17.3") && !_isA13Above) {', start_search)
    if pos_if == -1:
        m = re.search(r'if\s*\(\s*SYS_VER_GE\s*\(\s*@"17\.3"\s*\)\s*&&\s*!_isA13Above\s*\)\s*\{', content)
        if m:
            pos_if = m.start()

    if pos_if == -1:
        print("   ❌ Could not find offset if-block to update")
        return False

    # locate matching closing brace for the if-block
    start_brace = content.find('{', pos_if)
    if start_brace == -1:
        print("   ❌ Malformed if-block (no opening brace)")
        return False

    i = start_brace + 1
    brace_count = 1
    while i < len(content) and brace_count > 0:
        if content[i] == '{':
            brace_count += 1
        elif content[i] == '}':
            brace_count -= 1
        i += 1

    if brace_count != 0:
        print("   ❌ Could not find matching closing brace for if-block")
        return False

    end_brace = i  # position after closing brace

    new_block = f'''if (SYS_VER_GE(@"17.3") && !_isA13Above) {{
            rc_off_task_threads_next           = {task_threads_offset};  // {description}
            rc_off_thread_t_tro                = {tro_offset}; // Adjusted for A12X
            rc_off_thread_task_threads_next    = {tro_offset}; // Consistent with tro
        }}'''

    new_content = content[:pos_if] + new_block + content[end_brace:]

    with open(offsets_file, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print("   ✅ Updated rc_offsets.m")

    # Rebuild project using current Python interpreter
    print("   🔨 Rebuilding project...")
    try:
        result = subprocess.run([sys.executable, 'do_build.py'], capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print("   ✅ Build successful")
            return True
        else:
            print("   ❌ Build failed")
            print(f"   Error: {result.stderr[-500:]}")  # Last 500 chars
            return False
    except subprocess.TimeoutExpired:
        print("   ⏰ Build timed out")
        return False

def analyze_build_results():
    """Analyze the results of the latest build"""

    log_file = "log/lara.log"
    if not os.path.exists(log_file):
        print("   ❌ No log file found")
        return None

    with open(log_file, 'r') as f:
        content = f.read()

    # Check for success indicators
    valid_pattern = r'Valid threads:\s*(\d+),\s*Injected:\s*(\d+)'
    valid_match = re.search(valid_pattern, content)

    invalid_count = len(re.findall(r'SKIP invalid tro:', content, re.IGNORECASE))

    if valid_match:
        valid_threads = int(valid_match.group(1))
        valid_injected = int(valid_match.group(2))
        print(f"   📊 Results: Valid threads: {valid_threads}, Injected: {valid_injected}, Invalid TROs: {invalid_count}")

        if valid_threads > 0 and valid_injected > 0 and invalid_count < 100:
            print("   🎉 SUCCESS! Remote call working!")
            return True
        elif valid_threads > 0:
            print("   ⚠️ Partial success - some threads valid")
            return "partial"
        else:
            print("   ❌ Still failing")
            return False
    else:
        print(f"   📊 Results: No valid threads found, Invalid TROs: {invalid_count}")
        return False

def run_offset_tests():
    """Run systematic testing of different offset combinations"""

    test_cases = [
        (0x50, 0x348, "Current fix from TRO analysis"),
        (0x48, 0x348, "Previous working candidate"),
        (0x58, 0x358, "Original iOS 17 values"),
        (0x40, 0x340, "Lower bounds test"),
        (0x60, 0x360, "Higher bounds test"),
        (0x50, 0x358, "Mixed combination 1"),
        (0x48, 0x358, "Mixed combination 2"),
    ]

    results = []

    for task_off, tro_off, desc in test_cases:
        success = test_offset_combination(task_off, tro_off, desc)
        if success:
            result = analyze_build_results()
            results.append({
                'task_threads': task_off,
                'tro': tro_off,
                'description': desc,
                'result': result
            })

            # If we found a working combination, stop
            if result is True:
                print(f"\n🎯 FOUND WORKING COMBINATION!")
                break
        else:
            results.append({
                'task_threads': task_off,
                'tro': tro_off,
                'description': desc,
                'result': 'build_failed'
            })

    # Generate summary
    print(f"\n=== OFFSET TESTING SUMMARY ({len(results)} tests) ===")

    working = [r for r in results if r['result'] is True]
    partial = [r for r in results if r['result'] == 'partial']

    if working:
        best = working[0]
        print(f"✅ WORKING: task_threads_next=0x{best['task_threads']:x}, tro=0x{best['tro']:x}")
        print("   This combination should be used for final build!")
    elif partial:
        best = partial[0]
        print(f"⚠️ PARTIAL: task_threads_next=0x{best['task_threads']:x}, tro=0x{best['tro']:x}")
        print("   Some threads work, may need further tuning")
    else:
        print("❌ No working combinations found yet")
        print("   Try different offset ranges or check for other issues")

    return results

if __name__ == "__main__":
    print("=== AUTOMATED OFFSET TESTING FRAMEWORK ===")
    print("This will test multiple offset combinations automatically")
    print("⚠️  This process takes time as each test requires a full rebuild")

    # Change to project root
    os.chdir("..")

    results = run_offset_tests()

    # Save results
    with open('iPad8,9_Analysis/offset_test_results.json', 'w') as f:
        import json
        json.dump(results, f, indent=2)

    print("\nResults saved to iPad8,9_Analysis/offset_test_results.json")