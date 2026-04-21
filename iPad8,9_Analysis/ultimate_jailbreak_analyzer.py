#!/usr/bin/env python3
"""
Ultimate Jailbreak Analyzer - Final analysis after device testing
Combines all analysis tools for comprehensive jailbreak success evaluation
"""

import os
import sys
import subprocess
import json
from datetime import datetime

def run_complete_analysis(log_file):
    """Run all analysis tools on the new logs"""

    print("🚀 ULTIMATE JAILBREAK ANALYZER")
    print("=" * 50)
    print(f"Analyzing: {log_file}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    if not os.path.exists(log_file):
        print("❌ Log file not found!")
        return False

    # 1. Final Results Analysis
    print("📊 PHASE 1: Final Results Analysis")
    print("-" * 30)
    result = subprocess.run([sys.executable, 'final_results_analyzer.py', log_file],
                          capture_output=True, text=True, cwd=os.path.dirname(__file__))
    print(result.stdout)

    # 2. Advanced TRO Analysis
    print("🔍 PHASE 2: Advanced TRO Pattern Analysis")
    print("-" * 30)
    result = subprocess.run([sys.executable, 'advanced_tro_analyzer.py', log_file],
                          capture_output=True, text=True, cwd=os.path.dirname(__file__))
    print(result.stdout)

    # 3. Check for success indicators
    print("✅ PHASE 3: Success Validation")
    print("-" * 30)

    with open(log_file, 'r') as f:
        content = f.read()

    success_indicators = {
        'remote_call_success': 'Valid threads:' in content and 'Injected:' in content,
        'tweaks_success': 'TWEAKS.*Remote call.*successful' in content,
        'var_jb_created': 'mkdir /var/jb' in content and 'errno=13' not in content,
        'no_invalid_tros': 'SKIP invalid tro:' not in content,
        'kernel_pointers': '0xfffffff' in content
    }

    success_count = sum(success_indicators.values())
    total_indicators = len(success_indicators)

    print(f"Success Indicators: {success_count}/{total_indicators}")
    for indicator, passed in success_indicators.items():
        status = "✅" if passed else "❌"
        print(f"  {status} {indicator.replace('_', ' ').title()}")

    # 4. Generate final report
    print("\n📋 PHASE 4: Final Assessment")
    print("-" * 30)

    if success_count == total_indicators:
        print("🎉 COMPLETE SUCCESS! Jailbreak is 100% working!")
        print("✅ All indicators passed")
        print("✅ Remote call successful")
        print("✅ Tweaks injection working")
        print("✅ /var/jb created")
        print("✅ No invalid TROs")
        print("✅ Kernel pointers present")
        return True

    elif success_count >= total_indicators * 0.7:
        print("⚠️ PARTIAL SUCCESS! Jailbreak mostly working")
        print("✅ Most indicators passed")
        print("🔄 May need minor adjustments")
        return "partial"

    else:
        print("❌ ANALYSIS NEEDED! Jailbreak not working yet")
        print("❌ Most indicators failed")
        print("🔍 Need to investigate further")
        return False

def generate_action_plan(analysis_result):
    """Generate specific action plan based on analysis"""

    print("\n🎯 ACTION PLAN")
    print("=" * 30)

    if analysis_result is True:
        print("✅ JAILBREAK SUCCESSFUL!")
        print("📱 Ready for production use")
        print("🔄 Monitor for stability")
        print("📊 Consider performance optimization")

    elif analysis_result == "partial":
        print("⚠️ PARTIAL SUCCESS - NEEDS TUNING")
        print("🔍 Check which indicators failed")
        print("🔧 Fine-tune remaining offsets")
        print("📱 Test specific functionality")

    else:
        print("🔧 JAILBREAK NEEDS FIXES")
        print("1. 📊 Run: python advanced_tro_analyzer.py <new_log>")
        print("2. 🔄 If TRO pattern same: try offset_testing_framework.py")
        print("3. 🎯 Check: thread_ro offsets (0x10,0x18) may be wrong")
        print("4. 🔍 Analyze: proc_task() or task address resolution")
        print("5. 📚 Review: 8ksec_targeted_analysis.md for PAC bypass ideas")

def save_analysis_report(analysis_result, log_file):
    """Save comprehensive analysis report"""

    report = {
        'timestamp': datetime.now().isoformat(),
        'log_file': log_file,
        'analysis_result': analysis_result,
        'recommendations': []
    }

    if analysis_result is True:
        report['recommendations'] = [
            "Jailbreak fully successful",
            "Ready for deployment",
            "Monitor stability in production"
        ]
    elif analysis_result == "partial":
        report['recommendations'] = [
            "Partial success achieved",
            "Fine-tune remaining issues",
            "Test specific functionality"
        ]
    else:
        report['recommendations'] = [
            "Jailbreak needs fixes",
            "Run advanced_tro_analyzer.py",
            "Consider offset_testing_framework.py",
            "Check thread_ro offsets",
            "Review PAC bypass techniques"
        ]

    with open('ultimate_analysis_report.json', 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n💾 Report saved: ultimate_analysis_report.json")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ultimate_jailbreak_analyzer.py <log_file>")
        print("Example: python ultimate_jailbreak_analyzer.py ../log/new_lara.log")
        sys.exit(1)

    log_file = sys.argv[1]
    analysis_result = run_complete_analysis(log_file)
    generate_action_plan(analysis_result)
    save_analysis_report(analysis_result, log_file)

    print(f"\n🏁 Analysis complete. Result: {analysis_result}")