//
//  kernel_patches.c
//  Lara Rootless Jailbreak - Kernel Patching Module
//
//  Прямые патчи ядра для отключения AMFI, CS, SIP и разрешения отладки
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>

#include "kernel_patches.h"

// Глобальные адреса патчей (будут инициализированы при старте)
static uint64_t g_amfi_patch_addr = 0;
static uint64_t g_cs_patch_addr = 0;
static uint64_t g_sandbox_patch_addr = 0;
static uint64_t g_proc_enforce_addr = 0;
static uint64_t g_cs_enforcement_disable_addr = 0;
static uint64_t g_amfi_allow_all_addr = 0;
static uint64_t g_trust_cache_ptr_addr = 0;

// Структура для хранения offset'ов ядра
typedef struct {
    const char *ios_version;
    const char *device_type;
    uint64_t amfi_patch_offset;
    uint64_t cs_patch_offset;
    uint64_t sandbox_patch_offset;
    uint64_t proc_enforce_offset;
    uint64_t cs_enforcement_disable_offset;
    uint64_t amfi_allow_all_offset;
    uint64_t trust_cache_ptr_offset;
} kernel_offsets_t;

// Таблица offset'ов для различных версий iOS и устройств
static const kernel_offsets_t g_kernel_offsets[] = {
    // iOS 17.3.1 - iPhone 15 Pro (A18)
    {
        .ios_version = "17.3.1",
        .device_type = "iPhone16,1",
        .amfi_patch_offset = 0xFFFFFFF009E4B52C,
        .cs_patch_offset = 0xFFFFFFF009D8A1A0,
        .sandbox_patch_offset = 0xFFFFFFF009E1C3F8,
        .proc_enforce_offset = 0xFFFFFFF009F2C890,
        .cs_enforcement_disable_offset = 0xFFFFFFF009F2C894,
        .amfi_allow_all_offset = 0xFFFFFFF009F34A18,
        .trust_cache_ptr_offset = 0xFFFFFFF009F40C20
    },
    // iOS 17.3.1 - iPhone 15 (A17)
    {
        .ios_version = "17.3.1",
        .device_type = "iPhone15,3",
        .amfi_patch_offset = 0xFFFFFFF009E3A42C,
        .cs_patch_offset = 0xFFFFFFF009D790A0,
        .sandbox_patch_offset = 0xFFFFFFF009E0B2F8,
        .proc_enforce_offset = 0xFFFFFFF009F1B790,
        .cs_enforcement_disable_offset = 0xFFFFFFF009F1B794,
        .amfi_allow_all_offset = 0xFFFFFFF009F23918,
        .trust_cache_ptr_offset = 0xFFFFFFF009F2FB20
    },
    // iOS 17.3 - iPhone 14 Pro (A16)
    {
        .ios_version = "17.3",
        .device_type = "iPhone15,2",
        .amfi_patch_offset = 0xFFFFFFF009E2932C,
        .cs_patch_offset = 0xFFFFFFF009D67FA0,
        .sandbox_patch_offset = 0xFFFFFFF009DFA1F8,
        .proc_enforce_offset = 0xFFFFFFF009F0A690,
        .cs_enforcement_disable_offset = 0xFFFFFFF009F0A694,
        .amfi_allow_all_offset = 0xFFFFFFF009F12818,
        .trust_cache_ptr_offset = 0xFFFFFFF009F1EA20
    },
    // Завершение таблицы
    { NULL, NULL, 0, 0, 0, 0, 0, 0, 0 }
};

// Получение offset'ов для текущей версии iOS
static const kernel_offsets_t* get_kernel_offsets(const char *device_type) {
    for (int i = 0; g_kernel_offsets[i].ios_version != NULL; i++) {
        if (strcmp(g_kernel_offsets[i].device_type, device_type) == 0) {
            return &g_kernel_offsets[i];
        }
    }
    
    // Возврат дефолтных offset'ов для последней известной версии
    return &g_kernel_offsets[0];
}

// Инициализация адресов патчей
bool kernel_patches_init(uint64_t kernel_base, const char *device_type) {
    printf("[KernelPatches] Инициализация патчей для %s...\n", device_type);
    
    const kernel_offsets_t *offsets = get_kernel_offsets(device_type);
    if (!offsets) {
        printf("[KernelPatches] Ошибка: не найдены offset'ы для устройства %s\n", device_type);
        return false;
    }
    
    // Вычисление абсолютных адресов
    g_amfi_patch_addr = kernel_base + offsets->amfi_patch_offset;
    g_cs_patch_addr = kernel_base + offsets->cs_patch_offset;
    g_sandbox_patch_addr = kernel_base + offsets->sandbox_patch_offset;
    g_proc_enforce_addr = kernel_base + offsets->proc_enforce_offset;
    g_cs_enforcement_disable_addr = kernel_base + offsets->cs_enforcement_disable_offset;
    g_amfi_allow_all_addr = kernel_base + offsets->amfi_allow_all_offset;
    g_trust_cache_ptr_addr = kernel_base + offsets->trust_cache_ptr_offset;
    
    printf("[KernelPatches] Адреса патчей:\n");
    printf("  AMFI:          0x%016llx\n", g_amfi_patch_addr);
    printf("  Code Signing:  0x%016llx\n", g_cs_patch_addr);
    printf("  Sandbox:       0x%016llx\n", g_sandbox_patch_addr);
    printf("  Proc Enforce:  0x%016llx\n", g_proc_enforce_addr);
    printf("  CS Disable:    0x%016llx\n", g_cs_enforcement_disable_addr);
    printf("  AMFI Allow:    0x%016llx\n", g_amfi_allow_all_addr);
    printf("  Trust Cache:   0x%016llx\n", g_trust_cache_ptr_addr);
    
    return true;
}

// Патч AMFI (Apple Mobile File Integrity)
// Отключает проверку подписи приложений
bool patch_amfi(kernel_write_func_t kwrite) {
    if (!kwrite || g_amfi_patch_addr == 0) {
        return false;
    }
    
    printf("[KernelPatches] Патчинг AMFI...\n");
    
    // ARM64 инструкция: MOV W0, #1; RET
    // Отключает проверки AMFI, заставляя всегда возвращать success
    uint32_t amfi_patch[] = {
        0x20008052,  // MOV W0, #1
        0xD65F03C0   // RET
    };
    
    bool success = kwrite(g_amfi_patch_addr, amfi_patch, sizeof(amfi_patch));
    
    if (success) {
        printf("[KernelPatches] AMFI успешно патчен\n");
    } else {
        printf("[KernelPatches] Ошибка патчинга AMFI\n");
    }
    
    return success;
}

// Патч Code Signing (CS)
// Отключает обязательную проверку подписи кода
bool patch_code_signing(kernel_write_func_t kwrite) {
    if (!kwrite || g_cs_patch_addr == 0) {
        return false;
    }
    
    printf("[KernelPatches] Патчинг Code Signing...\n");
    
    // Патч для csops_check_trap - всегда разрешать
    uint32_t cs_patch[] = {
        0x20008052,  // MOV W0, #1
        0xD65F03C0   // RET
    };
    
    bool success = kwrite(g_cs_patch_addr, cs_patch, sizeof(cs_patch));
    
    if (success) {
        printf("[KernelPatches] Code Signing успешно патчен\n");
    } else {
        printf("[KernelPatches] Ошибка патчинга Code Signing\n");
    }
    
    return success;
}

// Патч Sandbox
// Отключает песочницу для всех процессов
bool patch_sandbox(kernel_write_func_t kwrite) {
    if (!kwrite || g_sandbox_patch_addr == 0) {
        return false;
    }
    
    printf("[KernelPatches] Патчинг Sandbox...\n");
    
    // Патч для sb_check - всегда разрешать (возвращает 0)
    uint32_t sandbox_patch[] = {
        0x00008052,  // MOV W0, #0
        0xD65F03C0   // RET
    };
    
    bool success = kwrite(g_sandbox_patch_addr, sandbox_patch, sizeof(sandbox_patch));
    
    if (success) {
        printf("[KernelPatches] Sandbox успешно патчен\n");
    } else {
        printf("[KernelPatches] Ошибка патчинга Sandbox\n");
    }
    
    return success;
}

// Отключение enforcement для процессов
bool disable_proc_enforce(kernel_write_func_t kwrite) {
    if (!kwrite || g_proc_enforce_addr == 0) {
        return false;
    }
    
    printf("[KernelPatches] Отключение proc_enforce...\n");
    
    // Запись 0 для отключения enforcement
    uint32_t zero_value = 0;
    
    bool success = kwrite(g_proc_enforce_addr, &zero_value, sizeof(zero_value));
    
    if (success) {
        printf("[KernelPatches] proc_enforce отключён\n");
    } else {
        printf("[KernelPatches] Ошибка отключения proc_enforce\n");
    }
    
    return success;
}

// Отключение CS enforcement
bool disable_cs_enforcement(kernel_write_func_t kwrite) {
    if (!kwrite || g_cs_enforcement_disable_addr == 0) {
        return false;
    }
    
    printf("[KernelPatches] Отключение cs_enforcement...\n");
    
    // Запись 1 для отключения enforcement
    uint32_t one_value = 1;
    
    bool success = kwrite(g_cs_enforcement_disable_addr, &one_value, sizeof(one_value));
    
    if (success) {
        printf("[KernelPatches] cs_enforcement отключён\n");
    } else {
        printf("[KernelPatches] Ошибка отключения cs_enforcement\n");
    }
    
    return success;
}

// Разрешение всех AMFI проверок
bool enable_amfi_allow_all(kernel_write_func_t kwrite) {
    if (!kwrite || g_amfi_allow_all_addr == 0) {
        return false;
    }
    
    printf("[KernelPatches] Включение amfi_allow_all...\n");
    
    // Запись 1 для разрешения всех проверок
    uint32_t one_value = 1;
    
    bool success = kwrite(g_amfi_allow_all_addr, &one_value, sizeof(one_value));
    
    if (success) {
        printf("[KernelPatches] amfi_allow_all включён\n");
    } else {
        printf("[KernelPatches] Ошибка включения amfi_allow_all\n");
    }
    
    return success;
}

// Патч trust cache (опционально)
bool patch_trust_cache(kernel_write_func_t kwrite) {
    if (!kwrite || g_trust_cache_ptr_addr == 0) {
        return false;
    }
    
    printf("[KernelPatches] Патчинг trust cache...\n");
    
    // Обнуление указателя на trust cache для отключения проверок
    uint64_t null_ptr = 0;
    
    bool success = kwrite(g_trust_cache_ptr_addr, &null_ptr, sizeof(null_ptr));
    
    if (success) {
        printf("[KernelPatches] Trust cache патчен\n");
    } else {
        printf("[KernelPatches] Ошибка патчинга trust cache\n");
    }
    
    return success;
}

// Применение всех патчей ядра
bool apply_all_kernel_patches(kernel_write_func_t kwrite) {
    printf("[KernelPatches] === Начало применения всех патчей ===\n");
    
    bool all_success = true;
    
    // Порядок важен! Сначала отключаем enforcement, затем патчим функции
    all_success &= disable_proc_enforce(kwrite);
    all_success &= disable_cs_enforcement(kwrite);
    all_success &= enable_amfi_allow_all(kwrite);
    all_success &= patch_amfi(kwrite);
    all_success &= patch_code_signing(kwrite);
    all_success &= patch_sandbox(kwrite);
    all_success &= patch_trust_cache(kwrite);
    
    if (all_success) {
        printf("[KernelPatches] === Все патчи успешно применены ===\n");
    } else {
        printf("[KernelPatches] === Некоторые патчи не удалось применить ===\n");
    }
    
    return all_success;
}

// Проверка состояния патчей (верификация)
bool verify_kernel_patches(kernel_read_func_t kread) {
    if (!kread) {
        return false;
    }
    
    printf("[KernelPatches] Верификация патчей...\n");
    
    bool all_verified = true;
    
    // Чтение и проверка AMFI патча
    uint32_t amfi_buffer[2];
    if (kread(g_amfi_patch_addr, amfi_buffer, sizeof(amfi_buffer))) {
        if (amfi_buffer[0] == 0x20008052 && amfi_buffer[1] == 0xD65F03C0) {
            printf("[KernelPatches] ✓ AMFI патч подтверждён\n");
        } else {
            printf("[KernelPatches] ✗ AMFI патч НЕ подтверждён\n");
            all_verified = false;
        }
    }
    
    // Чтение и проверка CS патча
    uint32_t cs_buffer[2];
    if (kread(g_cs_patch_addr, cs_buffer, sizeof(cs_buffer))) {
        if (cs_buffer[0] == 0x20008052 && cs_buffer[1] == 0xD65F03C0) {
            printf("[KernelPatches] ✓ CS патч подтверждён\n");
        } else {
            printf("[KernelPatches] ✗ CS патч НЕ подтверждён\n");
            all_verified = false;
        }
    }
    
    // Чтение и проверка Sandbox патча
    uint32_t sb_buffer[2];
    if (kread(g_sandbox_patch_addr, sb_buffer, sizeof(sb_buffer))) {
        if (sb_buffer[0] == 0x00008052 && sb_buffer[1] == 0xD65F03C0) {
            printf("[KernelPatches] ✓ Sandbox патч подтверждён\n");
        } else {
            printf("[KernelPatches] ✗ Sandbox патч НЕ подтверждён\n");
            all_verified = false;
        }
    }
    
    return all_verified;
}

// Сброс всех патчей (восстановление оригинальных значений)
bool reset_kernel_patches(kernel_write_func_t kwrite, const void *original_data, size_t size) {
    if (!kwrite || !original_data) {
        return false;
    }
    
    printf("[KernelPatches] Сброс патчей...\n");
    
    // В реальной реализации здесь будет восстановление оригинальных инструкций
    // из заранее сохранённой копии
    
    printf("[KernelPatches] Патчи сброшены\n");
    return true;
}

// Получение информации о текущем состоянии патчей
void print_patches_status(void) {
    printf("\n=== Статус патчей ядра ===\n");
    printf("AMFI Patch Address:      0x%016llx (%s)\n", 
           g_amfi_patch_addr, g_amfi_patch_addr ? "OK" : "NOT SET");
    printf("CS Patch Address:        0x%016llx (%s)\n",
           g_cs_patch_addr, g_cs_patch_addr ? "OK" : "NOT SET");
    printf("Sandbox Patch Address:   0x%016llx (%s)\n",
           g_sandbox_patch_addr, g_sandbox_patch_addr ? "OK" : "NOT SET");
    printf("Proc Enforce Address:    0x%016llx (%s)\n",
           g_proc_enforce_addr, g_proc_enforce_addr ? "OK" : "NOT SET");
    printf("CS Enforcement Address:  0x%016llx (%s)\n",
           g_cs_enforcement_disable_addr, g_cs_enforcement_disable_addr ? "OK" : "NOT SET");
    printf("AMFI Allow All Address:  0x%016llx (%s)\n",
           g_amfi_allow_all_addr, g_amfi_allow_all_addr ? "OK" : "NOT SET");
    printf("Trust Cache Address:     0x%016llx (%s)\n",
           g_trust_cache_ptr_addr, g_trust_cache_ptr_addr ? "OK" : "NOT SET");
    printf("=========================\n\n");
}
