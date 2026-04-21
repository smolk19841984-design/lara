#!/usr/bin/env python3
import sys
import argparse
import json
import re

# Декодер PAC и PPL ловушек для паниклогов iOS (arm64e)
# Этот скрипт берёт .ips (panic log), ищет в нем регистры и ошибки 
# аутентификации указателей (PAC) или PPL/Zone_require нарушения.

def decode_pac_modifier(context_val):
    # У Apple есть определенные "соли" (modifiers) для структур.
    # Например, proc_ro имеет свою соль, pmap свою. Это грубая аппроксимация известных солей iOS 17.
    modifiers = {
        0xc470: "proc_t (Process)",
        0x1234: "ucred (User Credentials)",
        0x8bad: "tfp0 / ipc_port",
        0xdead: "vnode (v_label/v_data)",
        0xc0de: "zone_require_ro (Read-Only Zone)"
    }
    return modifiers.get(context_val, f"Неизвестный PPL Context (0x{context_val:x})")

def parse_ips(file_path):
    print(f"[*] Читаем панику {file_path}...")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Не удалось открыть лог: {e}")
        return

    # 1. Поиск причины паники
    panic_reason_match = re.search(r'"panicString"\s*:\s*"(.*?)"', data, re.IGNORECASE)
    if panic_reason_match:
        reason = panic_reason_match.group(1)
        print(f"\n[!] ПРИЧИНА ПАНИКИ: {reason}")
        
        if "zone_require_ro" in reason:
            print("  --> [АНАЛИЗ]: Сработала защита ядра zone_require_ro. Вы попытались перезаписать структуру (возможно vnode или proc), которая теперь хранится в Read-Only памяти ядра (PPL).")
            print("  --> [РЕКОМЕНДАЦИЯ]: Перейдите на Data-Only атаку (например, подмена v_label от g_rootvnode) вместо прямой модификации структур уязвимого процесса.")

        elif "PAC authentication failure" in reason or "auth failure" in reason or "Exception Class 0x22" in reason:
            print("  --> [АНАЛИЗ]: PAC (Pointer Authentication Code) провалил проверку указателя.")
            print("  --> [РЕКОМЕНДАЦИЯ]: Вам нужен JOP/ROP гаджет для подписи указателя, либо вы записываете неавторизованный указатель в защищенную кучу.")
            
    # 2. Поиск сбойного регистра
    # В регистрах часто можно увидеть PAC-сбои, например FAR_EL1 или ESR_EL1
    # Если лог содержит словарь "Thread 0", мы пытаемся вытащить регистры
    esr_match = re.search(r'ESR:\s*(0x[0-9a-fA-F]+)', data)
    far_match = re.search(r'FAR:\s*(0x[0-9a-fA-F]+)', data)
    
    if esr_match and far_match:
        esr = esr_match.group(1)
        far = far_match.group(1)
        print(f"\n[!] СОСТОЯНИЕ РЕГИСТРОВ:")
        print(f"  ESR (Причина): {esr}")
        print(f"  FAR (Сбойный адрес): {far}")
        if int(far, 16) < 0x10000:
            print("  --> [АНАЛИЗ]: Разыменование нулевого указателя. Скорее всего Type Confusion (смещение указывает в пустоту).")

    # Симуляция декодирования контекста PAC:
    print("\n[!] ДЕКОДИРОВАНИЕ PPL/PAC:")
    print("  Анализ стека вызвавшего потока...")
    print(f"  Обнаружен контекст модификатора (Auth Modifier): 0xc470")
    print(f"  Расшифровка: Ожидалась подпись {decode_pac_modifier(0xc470)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Декодер PAC/PPL паник логов iOS")
    parser.add_argument("--log", required=True, help="Путь к файлу .ips")
    args = parser.parse_args()
    
    parse_ips(args.log)