#!/usr/bin/env python3
"""
Final Results Analyzer - Analyze post-fix test results
"""

import re
import sys

def analyze_final_results(log_file):
    """Analyze logs after applying the offset fixes"""

    print("=== FINAL RESULTS ANALYSIS ===\n")

    try:
        with open(log_file, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ Log file {log_file} not found")
        return False

    # Check for successful remote call
    success_indicators = [
        r'Valid threads:\s*\d+,\s*Injected:\s*\d+',
        r'Remote call to SpringBoard successful',
        r'TWEAKS.*Remote call.*successful',
        r'init_remote_call.*OK'
    ]

    success_found = False
    for pattern in success_indicators:
        if re.search(pattern, content, re.IGNORECASE):
            print(f"✅ SUCCESS INDICATOR FOUND: {pattern}")
            success_found = True

    # Check for remaining invalid TROs
    invalid_tro_pattern = r'SKIP invalid tro:\s*(0x[0-9a-fA-F]+)'
    invalid_tros = re.findall(invalid_tro_pattern, content, re.IGNORECASE)

    if invalid_tros:
        print(f"❌ STILL HAS INVALID TROs: {len(invalid_tros)} instances")
        print(f"   Values: {list(set(invalid_tros))}")
        return False
    else:
        print("✅ NO INVALID TROs FOUND")

    # Check for /var/jb creation
    if 'mkdir /var/jb' in content and 'errno=13' not in content:
        print("✅ /var/jb CREATION SUCCESSFUL")
    elif 'errno=13' in content:
        print("❌ /var/jb CREATION FAILED (sandbox still blocking)")
        return False

    # Check for vfs bypass issues
    vfs_failures = re.findall(r'vfs_bypass_mac_label.*fail', content, re.IGNORECASE)
    if vfs_failures:
        print(f"⚠️  VFS BYPASS ISSUES: {len(vfs_failures)} failures")
    else:
        print("✅ NO VFS BYPASS ISSUES")

    # Overall assessment
    if success_found and not invalid_tros:
        print("\n🎉 JAILBREAK SUCCESS: Remote call working, TROs valid!")
        return True
    else:
        print("\n❌ JAILBREAK INCOMPLETE: Issues remain")
        return False

def generate_next_steps(success):
    """Generate next steps based on results"""

    print("\n=== NEXT STEPS ===")

    if success:
        print("1. ✅ Deploy to device - jailbreak should work")
        print("2. ✅ Test tweaks injection")
        print("3. ✅ Verify /var/jb persistence")
        print("4. ✅ Check for any remaining issues")
        print("\n🎯 TARGET ACHIEVED: 100% SUCCESS!")
    else:
        print("1. ❌ Analyze remaining invalid TROs")
        print("2. ❌ Run offset_validator.py on new logs")
        print("3. ❌ Test alternative offsets (0x50, 0x60, 0x68)")
        print("4. ❌ Check if MIE/PAC bypass needed")
        print("5. ❌ Review 8kSec research for additional techniques")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python final_results_analyzer.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    success = analyze_final_results(log_file)
    generate_next_steps(success)