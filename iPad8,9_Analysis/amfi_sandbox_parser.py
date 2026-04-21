#!/usr/bin/env python3
import sys
import argparse
import re

# Парсер логов песочницы (sandboxd) и AMFI (amfid)
# Извлекает из syslog/oslog (syslog.txt) скрытые блокировки джейлбрейк твиков.

def parse_amfi_logs(syslog_path):
    print(f"[*] Поиск нарушений AMFI и Sandbox в логе: {syslog_path}")
    
    try:
        with open(syslog_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[-] Ошибка: {e}")
        return

    amfi_errors = 0
    sandbox_errors = 0

    print("\n[!] НАЙДЕННЫЕ БЛОКИРОВКИ:\n")
    for line in lines:
        if "amfid" in line or "AMFI" in line or "TrustCache" in line:
            if "validation failed" in line or "not valid" in line or "CS_VALID" in line:
                print(f" [AMFI] {line.strip()}")
                amfi_errors += 1
        elif "sandboxd" in line or "Sandbox:" in line:
            if "deny" in line or "violation" in line:
                print(f" [SANDBOX] {line.strip()}")
                sandbox_errors += 1
                
    if amfi_errors == 0 and sandbox_errors == 0:
        print("  --> [АНИЛИЗ]: В предоставленном логе нет отказов AMFI или песочницы.")
        print("  --> [ВЫВОД]: Если TweaksLoader.dylib не загружается, проверьте RPATH (install_name_tool), зависимости dylib или обход vnode.")
    else:
        print(f"\n[!] СТАТИСТИКА: AMFI отказов: {amfi_errors}, Sandbox отказов: {sandbox_errors}")
        if amfi_errors > 0:
            print("\n[+] РЕКОМЕНДАЦИЯ ПО AMFI:")
            print("  Бинарный файл не прошел проверку подписи (CoreTrust).")
            print("  Необходимо инжектить его хэш (cdhash) в статический TrustCache или использовать fastmethod FAKE_ENTITLEMENTS.")
        if sandbox_errors > 0:
            print("\n[+] РЕКОМЕНДАЦИЯ ПО SANDBOX:")
            print("  Процесс не имеет соответствующих entitlements (например, com.apple.private.security.no-sandbox).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Анализатор блокировок AMFI и Sandboxd")
    parser.add_argument("--syslog", required=True, help="Путь к syslog файлу")
    args = parser.parse_args()
    
    parse_amfi_logs(args.syslog)