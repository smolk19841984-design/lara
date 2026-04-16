//
//  daemon_loader.h
//  Lara Rootless Jailbreak - Daemon Loader Module
//

#ifndef daemon_loader_h
#define daemon_loader_h

#include <stdio.h>
#include <stddef.h>

// Инициализация
bool daemon_loader_init(void);

// Регистрация демонов
bool daemon_register_from_plist(const char *plist_path);
bool daemon_register(const char *label, const char *path, char **argv, int argc);

// Управление демонами
bool daemon_start(int index);
bool daemon_stop(int index);
bool daemon_restart(int index);
bool daemon_start_all(void);
bool daemon_stop_all(void);

// Мониторинг
void daemon_monitor(void);

// Сканирование директории
bool daemon_scan_directory(const char *dir_path);

// Статус
void daemon_get_status(int index, char *status_buf, size_t buf_size);
void daemon_print_status(void);

// Утилиты
bool daemon_create_simple(const char *label, const char *script_content);

// Очистка
void daemon_cleanup(void);

#endif /* daemon_loader_h */
