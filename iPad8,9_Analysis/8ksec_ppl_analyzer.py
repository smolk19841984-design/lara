#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# PPL / MIE Analyzer
# Inspired by 8kSec iOS Security Blogs (MIE Deep Dive Kernel / PPL Analysis)
#

import sys
import re
import argparse

def analyze_panic(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        print(f"[*] Анализ паники PPL (на базе знаний 8kSec): {file_path}")
        
        # Поиск PPL / MIE / zone_require_ro / Exception info
        trap_regex = re.search(r'(zone_require_ro failed.*|PPL trap|Memory Integrity Enforcement.*)', content, re.IGNORECASE)
        pc_lr_regex = re.search(r'PC=0x([0-9a-fA-F]+), LR=0x([0-9a-fA-F]+)', content)
        
        if trap_regex:
            trap_reason = trap_regex.group(1)
            print("[!] Найден потенциальный триггер PPL/MIE:")
            print(f"  --> {trap_reason}")
            print()
            
            if "zone_require_ro" in trap_reason.lower():
                print("[8kSec Insights]: Сработала защита MIE (Memory Integrity Enforcement, зона 'zone_require_ro').")
                print("[Рекомендация]: В iOS 17 структуры как proc_ro, ucred и thread ports защищены.")
                print("                Запрещена прямая модификация через kwrite. Для подмены параметров")
                print("                или портов потоков необходимо использовать Data-Only attacks: ")
                print("                (например, манипуляция разрешенными syscalls, поиск уязвимости")
                print("                виртуальной памяти либо 'legit' использования ROP под PPL-песочницей).")
            elif "ppl" in trap_reason.lower():
                print("[8kSec Insights]: Триггер Page Protection Layer.")
                print("[Рекомендация]: При попытке изменить защищенную страницу Page Table Entry без ключей из Secure Monitor.")
                print("                Проверьте SPRR конфигурации.")
        else:
            print("[8kSec Insights]: Явных PPL/MIE нарушений не обнаружено.")
            
        if pc_lr_regex:
            print(f"[*] Краш произошел: PC: 0x{pc_lr_regex.group(1)}, LR: 0x{pc_lr_regex.group(2)}")
            print("    Рекомендуется открыть kernelcache в IDA Pro и перейти к этому PC для")
            print("    определения функции, которая вызвала ловушку.")
            
    except Exception as e:
        print(f"[Ошибка] Не удалось прочитать {file_path}: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PPL/MIE Bypass Analyzer Tool (based on 8kSec)")
    parser.add_argument("--log", required=True, help="Путь к паник логу .ips")
    args = parser.parse_args()
    
    analyze_panic(args.log)