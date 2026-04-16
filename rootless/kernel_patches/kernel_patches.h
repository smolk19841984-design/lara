//
//  kernel_patches.h
//  Lara Rootless Jailbreak - Kernel Patching Module
//

#ifndef kernel_patches_h
#define kernel_patches_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Типы функций для чтения/записи ядра
typedef bool (*kernel_write_func_t)(uint64_t addr, const void *buf, size_t size);
typedef bool (*kernel_read_func_t)(uint64_t addr, void *buf, size_t size);

// Инициализация модуля патчей
bool kernel_patches_init(uint64_t kernel_base, const char *device_type);

// Индивидуальные патчи
bool patch_amfi(kernel_write_func_t kwrite);
bool patch_code_signing(kernel_write_func_t kwrite);
bool patch_sandbox(kernel_write_func_t kwrite);
bool disable_proc_enforce(kernel_write_func_t kwrite);
bool disable_cs_enforcement(kernel_write_func_t kwrite);
bool enable_amfi_allow_all(kernel_write_func_t kwrite);
bool patch_trust_cache(kernel_write_func_t kwrite);

// Применение всех патчей
bool apply_all_kernel_patches(kernel_write_func_t kwrite);

// Верификация патчей
bool verify_kernel_patches(kernel_read_func_t kread);

// Сброс патчей
bool reset_kernel_patches(kernel_write_func_t kwrite, const void *original_data, size_t size);

// Статус патчей
void print_patches_status(void);

#endif /* kernel_patches_h */
