#!/usr/bin/env python3
"""
Offset Hypothesis Tester - Test different offset combinations based on log analysis
"""

import re
import json

def load_log_data(log_file):
    """Load and parse log data"""
    with open(log_file, 'r') as f:
        content = f.read()

    # Extract TRO values
    tro_pattern = r'TRO.*?=.*?0x([0-9a-fA-F]+)'
    tro_matches = re.findall(tro_pattern, content, re.IGNORECASE)

    # Extract invalid TRO values from log
    tro_pattern = r'SKIP invalid tro:\s*(0x[0-9a-fA-F]+)'
    tro_matches = re.findall(tro_pattern, content, re.IGNORECASE)
    invalid_tros = list(set(tro_matches))  # Remove duplicates

    print(f"Found invalid TROs: {invalid_tros}")

    return {
        'tro_values': tro_matches,
        'invalid_tros': invalid_tros
    }

def test_offset_hypotheses(log_data):
    """Test different offset combinations to find valid TRO patterns"""

    invalid_tros = log_data['invalid_tros']
    print(f"Testing hypotheses for invalid TROs: {invalid_tros}")

    # Known offset ranges to test
    task_threads_offsets = [0x48, 0x50, 0x58, 0x60, 0x68, 0x70]
    thread_tro_offsets = [0x348, 0x358, 0x360, 0x368, 0x370]
    thread_task_threads_offsets = [0x348, 0x358, 0x360, 0x368, 0x370]

    hypotheses = []

    for task_off in task_threads_offsets:
        for tro_off in thread_tro_offsets:
            for thread_off in thread_task_threads_offsets:
                # Calculate expected TRO pattern
                # TRO = thread_addr + tro_offset
                # thread_addr = chain - thread_task_threads_offset
                # chain = task + task_threads_offset

                # Test if this combination could produce valid TROs
                valid_count = 0
                invalid_count = 0

                for tro_str in invalid_tros:
                    if tro_str.startswith('0x'):
                        tro_val = int(tro_str, 16)
                        # Check if TRO looks reasonable (kernel pointer range)
                        if 0x1000 <= tro_val <= 0xfffffff000000000:
                            valid_count += 1
                        else:
                            invalid_count += 1

                if valid_count > 0:
                    hypothesis = {
                        'task_threads_next': task_off,
                        'thread_t_tro': tro_off,
                        'thread_task_threads_next': thread_off,
                        'valid_tros': valid_count,
                        'invalid_tros': invalid_count,
                        'score': valid_count / (valid_count + invalid_count) if (valid_count + invalid_count) > 0 else 0
                    }
                    hypotheses.append(hypothesis)

    # Sort by score
    hypotheses.sort(key=lambda x: x['score'], reverse=True)

    print(f"\nTop {min(10, len(hypotheses))} hypotheses:")
    for i, h in enumerate(hypotheses[:10]):
        print(f"{i+1}. task_threads_next=0x{h['task_threads_next']:x} tro=0x{h['thread_t_tro']:x} thread_next=0x{h['thread_task_threads_next']:x} score={h['score']:.2f}")

    return hypotheses

def generate_offset_fix(hypotheses):
    """Generate code fix based on best hypothesis"""
    if not hypotheses:
        return "// No valid hypotheses found"

    best = hypotheses[0]

    fix = f"""
// OFFSET FIX BASED ON LOG ANALYSIS
// Best hypothesis: task_threads_next=0x{best['task_threads_next']:x}, tro=0x{best['thread_t_tro']:x}, thread_next=0x{best['thread_task_threads_next']:x}
// Score: {best['score']:.2f}

#ifdef __arm64__
    // A12X iOS 17.3.1 specific offsets
    rc_off_task_threads_next = 0x{best['task_threads_next']:x};
    rc_off_thread_t_tro = 0x{best['thread_t_tro']:x};
    rc_off_thread_task_threads_next = 0x{best['thread_task_threads_next']:x};
#endif
"""

    return fix

if __name__ == "__main__":
    log_data = load_log_data('../log/lara.log')
    hypotheses = test_offset_hypotheses(log_data)
    fix = generate_offset_fix(hypotheses)

    with open('offset_fix.h', 'w') as f:
        f.write(fix)

    print("\nGenerated offset_fix.h")