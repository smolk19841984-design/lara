#!/usr/bin/env python3
"""
sandbox_entitlement_generator.py
Генерирует оптимальные entitlements.plist для обхода sandbox на iOS 17+
Основано на анализе com.apple.security.sandbox.kext:
  - Tier 1: com.apple.private.security.no-sandbox (полный обход)
  - Tier 2: absolute-path exceptions, storage-exempt, oop-jit
  - Tier 3: task_for_pid, get-task-allow, process-info

Выходные файлы:
  bypass_entitlements_full.plist   — максимальный набор (TrustCache required)
  bypass_entitlements_safe.plist   — только entitlements без no-sandbox
  lara_bypass_entitlements.plist   — готовый файл для подписи ldid
"""

import os, json, plistlib, shutil

ROOT = r'c:\Users\smolk\Documents\2\lara-main'
CONFIG_DIR = os.path.join(ROOT, 'Config')
OUT_DIR = os.path.join(ROOT, 'iPad8,9_Analysis', 'Sandbox_Profiles')

# ── ENTITLEMENTS SETS ─────────────────────────────────────────────────────────

# Tier 1: Обходят весь sandbox. Требуют TrustCache + platform-binary.
TIER1_ENTITLEMENTS = {
    # ПОЛНОЕ отключение sandbox для процесса
    'com.apple.private.security.no-sandbox': True,

    # AMFI: разрешает выполнение по CDHash (TrustCache bypass)
    'com.apple.private.amfi.can-execute-cdhash': True,
}

# Tier 2: Bypass specific restrictions (storage, paths, JIT)
TIER2_ENTITLEMENTS = {
    # Storage exempt — heritable (дочерние процессы тоже получают исключение)
    'com.apple.private.security.storage-exempt.heritable': True,

    # Absolute path access — READ+WRITE к ЛЮБОМУ пути на ФС
    # Значение: список путей (пустой список = all paths)
    'com.apple.security.exception.files.absolute-path.read-write': ['/'],
    'com.apple.security.exception.files.absolute-path.read-only': ['/'],

    # Home-relative path access
    'com.apple.security.exception.files.home-relative-path.read-write': ['/'],
    'com.apple.security.exception.files.home-relative-path.read-only': ['/'],

    # Mach exceptions
    'com.apple.security.exception.mach-lookup.global-name': [],
    'com.apple.security.exception.mach-lookup.local-name': [],

    # OOP JIT loader (allow JIT execution out-of-process)
    'com.apple.private.oop-jit.loader': True,

    # Core repair — доступ к /var/CoreRepair и protected areas
    'com.apple.private.core-repair': True,

    # BindFS — позволяет монтировать bind-filesystem (overlayfs-like)
    'com.apple.private.bindfs-allow': True,

    # Dynamic codesigning (MAP_JIT)
    'dynamic-codesigning': True,

    # Sandbox container-manager
    'com.apple.private.security.container-manager': True,
}

# Tier 3: Operational entitlements (debug, task ports, process info)
TIER3_ENTITLEMENTS = {
    # Debug позволяет attach debugger и получить task port
    'get-task-allow': True,

    # task_for_pid — позволяет вызвать task_for_pid(0) для любого процесса
    'task_for_pid-allow': True,

    # System task ports — доступ к host control port
    'com.apple.system-task-ports.control': True,
    'com.apple.system-task-ports': True,

    # Process info — полный доступ к информации о всех процессах
    'com.apple.private.process-info.full-access': True,

    # AMFI: bypass code signing checks
    'com.apple.private.amfi.bypass': True,

    # Heritable sandbox token
    'com.apple.private.security.storage-exempt.heritable': True,

    # Exception для pseudo-tty (/dev/ptmx)
    'com.apple.security.exception.pseudo-tty-access': True,
}

# Базовые entitlements из существующего lara.entitlements (сохраняем)
EXISTING_BASE = {
    'platform-application': True,
    'com.apple.springboard.launchapplication': True,
    'com.apple.private.skip-library-validation': True,
    'com.apple.private.security.no-container': True,
    'com.apple.private.persona-mgmt': True,
    'com.apple.runningboard.assertions.daemon': True,
}


def merge(*dicts):
    result = {}
    for d in dicts:
        result.update(d)
    return result


def write_plist(path, data):
    with open(path, 'wb') as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_XML)
    print(f"  [+] {os.path.basename(path)}")


def read_existing_entitlements():
    """Читаем существующий lara.entitlements"""
    ent_path = os.path.join(CONFIG_DIR, 'lara.entitlements')
    if os.path.exists(ent_path):
        with open(ent_path, 'rb') as f:
            return plistlib.load(f)
    return {}


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print("[*] Чтение существующих entitlements lara...")
    existing = read_existing_entitlements()
    print(f"  Существующих entitlements: {len(existing)}")
    for k, v in existing.items():
        print(f"    {k}: {v}")

    print("\n[*] Генерация entitlements файлов...")

    # 1. Максимальный набор (TrustCache pipeline)
    full = merge(existing, TIER1_ENTITLEMENTS, TIER2_ENTITLEMENTS, TIER3_ENTITLEMENTS)
    write_plist(os.path.join(OUT_DIR, 'bypass_entitlements_full.plist'), full)

    # 2. Безопасный набор (без no-sandbox, только exceptions + debug)
    safe = merge(existing, TIER2_ENTITLEMENTS, TIER3_ENTITLEMENTS)
    write_plist(os.path.join(OUT_DIR, 'bypass_entitlements_safe.plist'), safe)

    # 3. Минимальный bypass для /var/jb creation
    varjb = merge(existing, {
        'com.apple.security.exception.files.absolute-path.read-write': ['/var/jb', '/var', '/private/var'],
        'com.apple.security.exception.files.absolute-path.read-only': ['/'],
        'com.apple.private.security.storage-exempt.heritable': True,
        'com.apple.private.bindfs-allow': True,
    })
    write_plist(os.path.join(OUT_DIR, 'bypass_entitlements_varjb.plist'), varjb)

    # 4. Итоговый файл для lara — lara_bypass_entitlements.plist
    lara_bypass = merge(existing, TIER2_ENTITLEMENTS, TIER3_ENTITLEMENTS)
    write_plist(os.path.join(OUT_DIR, 'lara_bypass_entitlements.plist'), lara_bypass)

    # 5. Обновляем Config/lara.entitlements (делаем backup сначала)
    ent_path = os.path.join(CONFIG_DIR, 'lara.entitlements')
    backup_path = os.path.join(CONFIG_DIR, 'lara.entitlements.backup')
    if os.path.exists(ent_path) and not os.path.exists(backup_path):
        shutil.copy2(ent_path, backup_path)
        print(f"\n[*] Backup: {backup_path}")

    print("\n[*] Обновление Config/lara.entitlements с bypass entitlements...")
    write_plist(ent_path, lara_bypass)
    print(f"  Config/lara.entitlements обновлён ({len(lara_bypass)} entitlements)")

    # Генерируем текстовый отчёт
    report = []
    report.append("=" * 65)
    report.append("SANDBOX BYPASS ENTITLEMENTS — iPad8,9 iOS 17+")
    report.append("Сгенерировано на основе анализа com.apple.security.sandbox.kext")
    report.append("=" * 65)
    report.append("")
    report.append("── TIER 1: ПОЛНЫЙ ОБХОД (bypass_entitlements_full.plist)")
    report.append("   Требует: platform-binary в TrustCache + подпись ldid")
    for k, v in TIER1_ENTITLEMENTS.items():
        report.append(f"   {k} = {v}")
    report.append("")
    report.append("── TIER 2: PATH EXCEPTIONS (bypass_entitlements_safe.plist)")
    report.append("   Даёт read-write доступ к любому пути через entitlement exception")
    report.append("   com.apple.security.exception.files.absolute-path.read-write: ['/']")
    report.append("   -> Sandbox видит нарушение, ЛОГИРУЕТ, но НЕ БЛОКИРУЕТ")
    report.append("   -> Источник: os_log '%s is using absolute path exception entitlement'")
    for k, v in TIER2_ENTITLEMENTS.items():
        report.append(f"   {k} = {v}")
    report.append("")
    report.append("── TIER 3: DEBUG / TASK PORTS (всегда включаем)")
    for k, v in TIER3_ENTITLEMENTS.items():
        report.append(f"   {k} = {v}")
    report.append("")
    report.append("── КАК ПРИМЕНИТЬ ────────────────────────────────────────────")
    report.append("  МЕТОД А: ldid (WSL build pipeline)")
    report.append("    ldid -S<path>/lara_bypass_entitlements.plist <binary>")
    report.append("    Включено автоматически в: scripts/build_ipa_wsl.sh")
    report.append("")
    report.append("  МЕТОД Б: TrustCache pipeline (для helper binary)")
    report.append("    1. Собрать create_var_jb_helper с bypass_entitlements_varjb.plist")
    report.append("    2. ldid -Sbypass_entitlements_varjb.plist create_var_jb_helper")
    report.append("    3. Добавить в TrustCache (если trustcache утилита доступна)")
    report.append("    4. Запустить из приложения через posix_spawn")
    report.append("")
    report.append("  МЕТОД В: vfs_bypass_mac_label + entitlement combo")
    report.append("    1. Запустить kernel exploit (dsReady = YES)")
    report.append("    2. vfs_bypass_mac_label('/var/jb') — снимает MAC label")
    report.append("    3. mkdir('/var/jb', 0755) — должно пройти")
    report.append("    4. Если нет — использовать absolute-path exception entitlement")
    report.append("")
    report.append("── UNENFORCED ВЕКТОРЫ ────────────────────────────────────────")
    report.append("  Эти нарушения логируются sandbox но НЕ блокируются:")
    report.append("  - Unenforced user home directory access violation (rdar://72823536)")
    report.append("  - Unenforced REVERSE EDS access violation")
    report.append("  - Unenforced EDS access violation")
    report.append("  -> Вектор: попасть в home directory через любой незащищённый путь")
    report.append("")
    report.append("── ЗАПИСЫВАЕМЫЕ ПУТИ (доступны без bypass) ──────────────────")
    report.append("  /private/var/tmp         — writable из sandbox")
    report.append("  /private/var/mobile/tmp  — writable из sandbox")
    report.append("  Documents/               — app container (всегда доступен)")

    rpt_path = os.path.join(OUT_DIR, 'entitlement_bypass_guide.txt')
    with open(rpt_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))

    print(f"\n[+] Итого сгенерировано:")
    print(f"  bypass_entitlements_full.plist    — Tier1+2+3 (максимальный)")
    print(f"  bypass_entitlements_safe.plist    — Tier2+3 (без no-sandbox)")
    print(f"  bypass_entitlements_varjb.plist   — минимальный для /var/jb")
    print(f"  lara_bypass_entitlements.plist    — итоговый для lara")
    print(f"  lara.entitlements (updated)       — Config/lara.entitlements")
    print(f"  entitlement_bypass_guide.txt      — инструкция применения")
    print(f"\n  Следующий шаг: wsl bash scripts/build_ipa_wsl.sh")


if __name__ == '__main__':
    main()
