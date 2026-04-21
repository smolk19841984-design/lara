#!/usr/bin/env python3
import sys
import os
import re
import json

def extract_ascii_strings(data, min_length=4):
    result = []
    current = b""
    for b in data:
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= min_length:
                result.append(current.decode('ascii', errors='ignore'))
            current = b""
    if len(current) >= min_length:
        result.append(current.decode('ascii', errors='ignore'))
    return result

def extract_sandbox_rules(strings):
    # Sandbox rules обычно содержат ключевые слова: allow, deny, require, regex, file, mach, sysctl, etc.
    keywords = [
        'allow', 'deny', 'require', 'regex', 'file', 'mach', 'sysctl', 'process', 'literal', 'vnode',
        'user', 'network', 'ipc', 'appleevent', 'preference', 'com.apple', 'container', 'extension',
        'read', 'write', 'execute', 'mount', 'unmount', 'fork', 'signal', 'launch', 'application',
        'sandbox', 'entitlement', 'profile', 'service', 'plist', 'bundle', 'path', 'class', 'type',
        'filter', 'exception', 'policy', 'operation', 'resource', 'access', 'audit', 'log', 'root',
        'system', 'kernel', 'kext', 'driver', 'plugin', 'framework', 'library', 'dylib', 'bin', 'sbin',
        'usr', 'var', 'tmp', 'dev', 'private', 'home', 'mobile', 'root', 'sandboxd', 'amfid', 'launchd'
    ]
    rules = [s for s in strings if any(k in s for k in keywords)]
    return rules

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_kext>")
        sys.exit(1)
    kext_path = sys.argv[1]
    if not os.path.exists(kext_path):
        print(f"File not found: {kext_path}")
        sys.exit(1)
    with open(kext_path, 'rb') as f:
        data = f.read()
    strings = extract_ascii_strings(data)
    rules = extract_sandbox_rules(strings)
    # Сохраняем все строки и правила в JSON
    out_dir = os.path.dirname(kext_path)
    with open(os.path.join(out_dir, 'sandbox_strings.json'), 'w', encoding='utf-8') as f:
        json.dump(strings, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, 'sandbox_rules.txt'), 'w', encoding='utf-8') as f:
        for rule in rules:
            f.write(rule + '\n')
    # Краткий вывод
    summary = []
    summary.append(f"Всего строк: {len(strings)}")
    summary.append(f"Обнаружено потенциальных sandbox-правил: {len(rules)}")
    summary.append("")
    summary.append("Примеры правил:")
    summary.extend(rules[:20])
    with open(os.path.join(out_dir, 'sandbox_analysis_summary.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(summary))
    print("[+] Извлечение завершено. Результаты сохранены в:")
    print(f"  - {os.path.join(out_dir, 'sandbox_strings.json')}")
    print(f"  - {os.path.join(out_dir, 'sandbox_rules.txt')}")
    print(f"  - {os.path.join(out_dir, 'sandbox_analysis_summary.txt')}")

if __name__ == "__main__":
    main()
