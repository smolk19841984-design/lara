//
//  get_root.h
//  Lara Rootless Jailbreak - Root Privileges Module
//

#ifndef get_root_h
#define get_root_h

#include <stdint.h>
#include <stdbool.h>

// Типы функций для чтения/записи ядра
typedef bool (*kernel_read_func_t)(uint64_t addr, void *buf, size_t size);
typedef bool (*kernel_write_func_t)(uint64_t addr, const void *buf, size_t size);

// Инициализация модуля
bool get_root_init(uint64_t kernel_base, const char *ios_version);

// Получение root-прав
bool become_root(kernel_read_func_t kread, kernel_write_func_t kwrite);

// Проверка статуса
bool check_root_status(void);

// Восстановление credentials
bool restore_credentials(kernel_write_func_t kwrite, uint64_t original_uid,
                        uint64_t original_ruid, uint64_t original_svuid);

// Информация о процессе
void print_process_info(kernel_read_func_t kread);

// Сидинг всех процессов
bool setuid_all_processes(kernel_read_func_t kread, kernel_write_func_t kwrite);

#endif /* get_root_h */
