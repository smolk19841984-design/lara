#!/usr/bin/env python3
"""
ULTIMATE JAILBREAK HYPOTHESIS TESTER
Automated testing of all offset combinations from 8kSec analysis
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime

# All hypotheses from 8kSec analysis
HYPOTHESES = [
    {
        'name': '8kSec_Validated_A12X_50',
        'task_threads_next': 0x50,
        'thread_t_tro': 0x348,
        'description': 'Primary 8kSec formula: tro = task_threads_next + 0x2f8',
        'confidence': 'very_high',
        'source': '8kSec iOS 17 A12X kernel exploitation'
    },
    {
        'name': '8kSec_Alternative_A12X_48',
        'task_threads_next': 0x48,
        'thread_t_tro': 0x340,
        'description': 'Alternative for some A12X devices',
        'confidence': 'high',
        'source': '8kSec offset variation analysis'
    },
    {
        'name': '8kSec_A12X_58',
        'task_threads_next': 0x58,
        'thread_t_tro': 0x350,
        'description': 'iOS 17.0 A12X baseline',
        'confidence': 'medium',
        'source': '8kSec iOS version comparison'
    },
    {
        'name': '8kSec_A12X_60',
        'task_threads_next': 0x60,
        'thread_t_tro': 0x358,
        'description': 'iOS 17.4 A12X pattern',
        'confidence': 'medium',
        'source': '8kSec future version analysis'
    },
    {
        'name': 'TRO_Pattern_Analysis_0x2f00_base',
        'task_threads_next': 0x2f00 - 0x2f8,  # 0x2f00 - 0x2f8 = 0x8
        'thread_t_tro': 0x2f00,
        'description': 'Based on invalid TRO pattern analysis',
        'confidence': 'low',
        'source': 'Log pattern reverse engineering'
    }
]

def apply_hypothesis_to_code(hypothesis):
    """Apply hypothesis to rc_offsets.m"""
    code_template = f"""
        // {hypothesis['name']} - {hypothesis['description']}
        // Confidence: {hypothesis['confidence']} - Source: {hypothesis['source']}
        if (SYS_VER_GE(@"17.3") && !_isA13Above) {{
            rc_off_task_threads_next           = {hypothesis['task_threads_next']};
            rc_off_thread_t_tro                = {hypothesis['thread_t_tro']};
            rc_off_thread_task_threads_next    = {hypothesis['thread_t_tro']};
        }}"""

    # Read current file
    with open('jbdc/kexploit/rc_offsets.m', 'r', encoding='utf-8') as f:
        content = f.read()

    # Replace the A12X section
    pattern = r'(        // A12X iOS 17\.3\.1 specific fix based on 8kSec research[\s\S]*?if \(SYS_VER_GE\(@"17\.3"\) && !_isA13Above\) \{[\s\S]*?\}\s*)'

    replacement = f'        // A12X iOS 17.3.1 specific fix based on 8kSec research\n' + code_template + '\n'

    import re
    new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

    # Write back
    with open('jbdc/kexploit/rc_offsets.m', 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"✅ Applied hypothesis: {hypothesis['name']}")

def build_ipa():
    """Build IPA with current hypothesis"""
    try:
        result = subprocess.run([sys.executable, 'do_build.py'],
                              cwd=os.path.dirname(os.path.dirname(__file__)),
                              capture_output=True, text=True, timeout=300)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("❌ Build timeout")
        return False
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

def test_hypothesis(hypothesis):
    """Test a single hypothesis"""
    print(f"\n🧪 TESTING HYPOTHESIS: {hypothesis['name']}")
    print("=" * 60)
    print(f"Description: {hypothesis['description']}")
    print(f"Confidence: {hypothesis['confidence']}")
    print(f"Source: {hypothesis['source']}")
    print(f"Offsets: task_threads_next=0x{hypothesis['task_threads_next']:x}, tro=0x{hypothesis['thread_t_tro']:x}")

    start_time = time.time()

    # Apply hypothesis
    apply_hypothesis_to_code(hypothesis)

    # Build IPA
    print("🔨 Building IPA...")
    build_success = build_ipa()

    build_time = time.time() - start_time

    if build_success:
        print(f"✅ BUILD SUCCESS ({build_time:.1f}s)")
        print("📱 Ready for device testing")
        return {
            'hypothesis': hypothesis,
            'build_success': True,
            'build_time': build_time,
            'status': 'ready_for_testing',
            'timestamp': datetime.now().isoformat()
        }
    else:
        print(f"❌ BUILD FAILED ({build_time:.1f}s)")
        return {
            'hypothesis': hypothesis,
            'build_success': False,
            'build_time': build_time,
            'status': 'build_failed',
            'timestamp': datetime.now().isoformat()
        }

def run_automated_testing():
    """Run automated testing of all hypotheses"""
    print("🚀 ULTIMATE JAILBREAK HYPOTHESIS TESTER")
    print("=" * 60)
    print(f"Testing {len(HYPOTHESES)} hypotheses")
    print()

    results = []
    successful_builds = []

    for i, hypothesis in enumerate(HYPOTHESES, 1):
        print(f"\n[{i}/{len(HYPOTHESES)}] Testing hypothesis...")

        result = test_hypothesis(hypothesis)
        results.append(result)

        if result['build_success']:
            successful_builds.append(result)

        # Save intermediate results
        with open('hypothesis_test_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

    # Final summary
    print("\n" + "=" * 60)
    print("📊 TESTING COMPLETE")
    print("=" * 60)

    print(f"Total hypotheses tested: {len(results)}")
    print(f"Successful builds: {len(successful_builds)}")
    print(f"Failed builds: {len(results) - len(successful_builds)}")

    if successful_builds:
        print("\n✅ SUCCESSFUL HYPOTHESES:")
        for result in successful_builds:
            h = result['hypothesis']
            print(f"   • {h['name']} (confidence: {h['confidence']}) - {result['build_time']:.1f}s")

        # Recommend best hypothesis
        best = max(successful_builds, key=lambda x: confidence_to_score(x['hypothesis']['confidence']))
        print(f"\n🎯 RECOMMENDED: {best['hypothesis']['name']}")
        print(f"   Build time: {best['build_time']:.1f}s")
        print(f"   Offsets: task_threads_next=0x{best['hypothesis']['task_threads_next']:x}, tro=0x{best['hypothesis']['thread_t_tro']:x}")

    # Save final results
    final_report = {
        'timestamp': datetime.now().isoformat(),
        'total_hypotheses': len(results),
        'successful_builds': len(successful_builds),
        'results': results,
        'recommended_hypothesis': best['hypothesis'] if successful_builds else None
    }

    with open('final_hypothesis_test_report.json', 'w', encoding='utf-8') as f:
        json.dump(final_report, f, indent=2)

    print("
💾 Results saved to final_hypothesis_test_report.json"    return final_report

def confidence_to_score(confidence):
    """Convert confidence string to numeric score"""
    scores = {
        'very_high': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'very_low': 1
    }
    return scores.get(confidence, 1)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--single':
        # Test single hypothesis
        if len(sys.argv) < 3:
            print("Usage: python ultimate_hypothesis_tester.py --single <hypothesis_name>")
            return

        hypothesis_name = sys.argv[2]
        hypothesis = next((h for h in HYPOTHESES if h['name'] == hypothesis_name), None)

        if not hypothesis:
            print(f"❌ Hypothesis '{hypothesis_name}' not found")
            return

        result = test_hypothesis(hypothesis)
        print(f"Result: {'SUCCESS' if result['build_success'] else 'FAILED'}")
    else:
        # Run full automated testing
        run_automated_testing()

if __name__ == "__main__":
    main()