//
//  overlay_fs.c
//  Lara Rootless Jailbreak - OverlayFS Module
//
//  Реализация-overlay файловой системы для изменения FS без монтирования
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <dirent.h>
#include <errno.h>

#include "overlay_fs.h"

#define MAX_OVERLAY_PATHS 256
#define MAX_PATH_LENGTH 1024

// Структура для описания overlay пути
typedef struct {
    char original_path[MAX_PATH_LENGTH];
    char overlay_path[MAX_PATH_LENGTH];
    bool is_active;
    int priority; // Приоритет (чем выше, тем важнее)
} overlay_entry_t;

static overlay_entry_t g_overlay_entries[MAX_OVERLAY_PATHS];
static int g_overlay_count = 0;
static bool g_overlay_initialized = false;

// Базовая директория для overlay (в sandbox джейлбрейка)
static char g_overlay_base_path[MAX_PATH_LENGTH] = "/var/jb";

// Инициализация overlayfs
bool overlay_fs_init(const char *base_path) {
    if (g_overlay_initialized) {
        return true;
    }
    
    // Установка базовой директории
    if (base_path) {
        strncpy(g_overlay_base_path, base_path, MAX_PATH_LENGTH - 1);
        g_overlay_base_path[MAX_PATH_LENGTH - 1] = '\0';
    }
    
    // Создание базовой структуры директорий
    char path[MAX_PATH_LENGTH];
    
    snprintf(path, sizeof(path), "%s/Applications", g_overlay_base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/Library", g_overlay_base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/Library/MobileSubstrate", g_overlay_base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/Library/LaunchDaemons", g_overlay_base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/usr", g_overlay_base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/usr/bin", g_overlay_base_path);
    mkdir(path, 0755);
    
    snprintf(path, sizeof(path), "%s/usr/libexec", g_overlay_base_path);
    mkdir(path, 0755);
    
    // Инициализация массива overlay записей
    memset(g_overlay_entries, 0, sizeof(g_overlay_entries));
    g_overlay_count = 0;
    
    g_overlay_initialized = true;
    
    printf("[OverlayFS] Инициализировано. Base: %s\n", g_overlay_base_path);
    return true;
}

// Добавление overlay пути
bool overlay_add_path(const char *original, const char *overlay, int priority) {
    if (!g_overlay_initialized || !original || !overlay) {
        return false;
    }
    
    if (g_overlay_count >= MAX_OVERLAY_PATHS) {
        printf("[OverlayFS] Ошибка: достигнут лимит путей\n");
        return false;
    }
    
    // Проверка на дубликаты
    for (int i = 0; i < g_overlay_count; i++) {
        if (strcmp(g_overlay_entries[i].original_path, original) == 0) {
            // Обновление существующей записи
            strncpy(g_overlay_entries[i].overlay_path, overlay, MAX_PATH_LENGTH - 1);
            g_overlay_entries[i].priority = priority;
            g_overlay_entries[i].is_active = true;
            printf("[OverlayFS] Обновлено: %s -> %s (priority: %d)\n", 
                   original, overlay, priority);
            return true;
        }
    }
    
    // Добавление новой записи
    overlay_entry_t *entry = &g_overlay_entries[g_overlay_count];
    strncpy(entry->original_path, original, MAX_PATH_LENGTH - 1);
    strncpy(entry->overlay_path, overlay, MAX_PATH_LENGTH - 1);
    entry->priority = priority;
    entry->is_active = true;
    
    g_overlay_count++;
    
    printf("[OverlayFS] Добавлено: %s -> %s (priority: %d)\n",
           original, overlay, priority);
    
    return true;
}

// Удаление overlay пути
bool overlay_remove_path(const char *original) {
    if (!g_overlay_initialized || !original) {
        return false;
    }
    
    for (int i = 0; i < g_overlay_count; i++) {
        if (strcmp(g_overlay_entries[i].original_path, original) == 0) {
            g_overlay_entries[i].is_active = false;
            printf("[OverlayFS] Удалено: %s\n", original);
            return true;
        }
    }
    
    return false;
}

// Поиск overlay пути для данного оригинального пути
static const char* find_overlay_for_path(const char *original) {
    int best_match_idx = -1;
    int best_priority = -1;
    size_t best_match_len = 0;
    
    for (int i = 0; i < g_overlay_count; i++) {
        if (!g_overlay_entries[i].is_active) {
            continue;
        }
        
        size_t orig_len = strlen(g_overlay_entries[i].original_path);
        
        // Проверка на точное совпадение или префикс
        if (strncmp(original, g_overlay_entries[i].original_path, orig_len) == 0) {
            // Проверка что это полный компонент пути
            if (original[orig_len] == '\0' || original[orig_len] == '/') {
                if (g_overlay_entries[i].priority > best_priority ||
                    (g_overlay_entries[i].priority == best_priority && 
                     orig_len > best_match_len)) {
                    best_match_idx = i;
                    best_priority = g_overlay_entries[i].priority;
                    best_match_len = orig_len;
                }
            }
        }
    }
    
    if (best_match_idx >= 0) {
        return g_overlay_entries[best_match_idx].overlay_path;
    }
    
    return NULL;
}

// Построение полного overlay пути
static bool build_overlay_path(const char *original, char *result, size_t result_size) {
    const char *overlay_base = find_overlay_for_path(original);
    
    if (!overlay_base) {
        return false;
    }
    
    // Построение полного пути
    size_t overlay_base_len = strlen(overlay_base);
    size_t original_len = strlen(original);
    
    // Нахождение смещения относительно overlay_base
    int best_match_idx = -1;
    size_t best_match_len = 0;
    
    for (int i = 0; i < g_overlay_count; i++) {
        if (!g_overlay_entries[i].is_active) {
            continue;
        }
        
        size_t orig_len = strlen(g_overlay_entries[i].original_path);
        if (strncmp(original, g_overlay_entries[i].original_path, orig_len) == 0 &&
            (original[orig_len] == '\0' || original[orig_len] == '/')) {
            if (orig_len > best_match_len) {
                best_match_idx = i;
                best_match_len = orig_len;
            }
        }
    }
    
    if (best_match_idx < 0) {
        return false;
    }
    
    const char *rel_path = original + best_match_len;
    
    if (strlen(rel_path) == 0) {
        // Точное совпадение
        strncpy(result, overlay_base, result_size - 1);
        result[result_size - 1] = '\0';
    } else {
        snprintf(result, result_size, "%s%s", overlay_base, rel_path);
    }
    
    return true;
}

// Перехват open() с использованием overlay
int overlay_open(const char *path, int flags, ...) {
    char overlay_path[MAX_PATH_LENGTH];
    
    if (build_overlay_path(path, overlay_path, sizeof(overlay_path))) {
        // Проверка существования overlay файла
        struct stat st;
        if (stat(overlay_path, &st) == 0) {
            printf("[OverlayFS] open: %s -> %s\n", path, overlay_path);
            
            mode_t mode = 0;
            if (flags & O_CREAT) {
                va_list args;
                va_start(args, flags);
                mode = va_arg(args, mode_t);
                va_end(args);
            }
            
            return open(overlay_path, flags, mode);
        }
    }
    
    // Fallback к оригинальному пути
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    return open(path, flags, mode);
}

// Перехват access() с использованием overlay
int overlay_access(const char *path, int amode) {
    char overlay_path[MAX_PATH_LENGTH];
    
    if (build_overlay_path(path, overlay_path, sizeof(overlay_path))) {
        if (access(overlay_path, amode) == 0) {
            printf("[OverlayFS] access: %s -> %s (OK)\n", path, overlay_path);
            return 0;
        }
    }
    
    return access(path, amode);
}

// Перехват stat() с использованием overlay
int overlay_stat(const char *path, struct stat *buf) {
    char overlay_path[MAX_PATH_LENGTH];
    
    if (build_overlay_path(path, overlay_path, sizeof(overlay_path))) {
        if (stat(overlay_path, buf) == 0) {
            printf("[OverlayFS] stat: %s -> %s\n", path, overlay_path);
            return 0;
        }
    }
    
    return stat(path, buf);
}

// Перехват lstat() с использованием overlay
int overlay_lstat(const char *path, struct stat *buf) {
    char overlay_path[MAX_PATH_LENGTH];
    
    if (build_overlay_path(path, overlay_path, sizeof(overlay_path))) {
        if (lstat(overlay_path, buf) == 0) {
            printf("[OverlayFS] lstat: %s -> %s\n", path, overlay_path);
            return 0;
        }
    }
    
    return lstat(path, buf);
}

// Перехват opendir() с использованием overlay
DIR* overlay_opendir(const char *name) {
    char overlay_path[MAX_PATH_LENGTH];
    
    if (build_overlay_path(name, overlay_path, sizeof(overlay_path))) {
        DIR *dir = opendir(overlay_path);
        if (dir) {
            printf("[OverlayFS] opendir: %s -> %s\n", name, overlay_path);
            return dir;
        }
    }
    
    return opendir(name);
}

// Перехват readlink() с использованием overlay
ssize_t overlay_readlink(const char *path, char *buf, size_t bufsize) {
    char overlay_path[MAX_PATH_LENGTH];
    
    if (build_overlay_path(path, overlay_path, sizeof(overlay_path))) {
        ssize_t result = readlink(overlay_path, buf, bufsize);
        if (result != -1) {
            printf("[OverlayFS] readlink: %s -> %s\n", path, overlay_path);
            return result;
        }
    }
    
    return readlink(path, buf, bufsize);
}

// Создание symlink в overlay
int overlay_symlink(const char *target, const char *linkpath) {
    char overlay_linkpath[MAX_PATH_LENGTH];
    
    if (build_overlay_path(linkpath, overlay_linkpath, sizeof(overlay_linkpath))) {
        // Создание родительской директории если нужно
        char *last_slash = strrchr(overlay_linkpath, '/');
        if (last_slash && last_slash != overlay_linkpath) {
            *last_slash = '\0';
            mkdir(overlay_linkpath, 0755);
            *last_slash = '/';
        }
        
        int result = symlink(target, overlay_linkpath);
        if (result == 0) {
            printf("[OverlayFS] symlink: %s -> %s (в overlay)\n", target, overlay_linkpath);
        }
        return result;
    }
    
    return symlink(target, linkpath);
}

// Копирование файла в overlay
bool overlay_copy_file(const char *src, const char *dest_in_overlay) {
    if (!src || !dest_in_overlay) {
        return false;
    }
    
    char full_overlay_path[MAX_PATH_LENGTH];
    snprintf(full_overlay_path, sizeof(full_overlay_path), "%s%s", 
             g_overlay_base_path, dest_in_overlay);
    
    // Создание родительской директории
    char *last_slash = strrchr(full_overlay_path, '/');
    if (last_slash && last_slash != full_overlay_path) {
        *last_slash = '\0';
        mkdir(full_overlay_path, 0755);
        *last_slash = '/';
    }
    
    // Открытие исходного файла
    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        printf("[OverlayFS] Ошибка открытия %s: %s\n", src, strerror(errno));
        return false;
    }
    
    // Создание destination файла
    int dst_fd = open(full_overlay_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dst_fd < 0) {
        close(src_fd);
        printf("[OverlayFS] Ошибка создания %s: %s\n", full_overlay_path, strerror(errno));
        return false;
    }
    
    // Копирование данных
    char buffer[8192];
    ssize_t bytes_read;
    bool success = true;
    
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t bytes_written = write(dst_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            success = false;
            break;
        }
    }
    
    close(src_fd);
    close(dst_fd);
    
    if (success) {
        printf("[OverlayFS] Скопировано: %s -> %s\n", src, full_overlay_path);
    } else {
        printf("[OverlayFS] Ошибка копирования: %s -> %s\n", src, full_overlay_path);
    }
    
    return success;
}

// Регистрация стандартных overlay путей для jailbreak
bool overlay_setup_standard_paths(void) {
    if (!g_overlay_initialized) {
        return false;
    }
    
    printf("[OverlayFS] Настройка стандартных путей...\n");
    
    // /Applications -> /var/jb/Applications
    overlay_add_path("/Applications", "/var/jb/Applications", 100);
    
    // /Library/MobileSubstrate -> /var/jb/Library/MobileSubstrate
    overlay_add_path("/Library/MobileSubstrate", "/var/jb/Library/MobileSubstrate", 100);
    
    // /Library/LaunchDaemons -> /var/jb/Library/LaunchDaemons
    overlay_add_path("/Library/LaunchDaemons", "/var/jb/Library/LaunchDaemons", 100);
    
    // /usr/bin -> /var/jb/usr/bin
    overlay_add_path("/usr/bin", "/var/jb/usr/bin", 90);
    
    // /usr/libexec -> /var/jb/usr/libexec
    overlay_add_path("/usr/libexec", "/var/jb/usr/libexec", 90);
    
    // /System/Library/Themes -> /var/jb/Themes (для Anemone и т.д.)
    overlay_add_path("/System/Library/Themes", "/var/jb/Themes", 80);
    
    printf("[OverlayFS] Стандартные пути настроены\n");
    return true;
}

// Вывод информации об overlay
void overlay_print_status(void) {
    printf("\n=== OverlayFS Status ===\n");
    printf("Base Path: %s\n", g_overlay_base_path);
    printf("Active Entries: %d / %d\n\n", g_overlay_count, MAX_OVERLAY_PATHS);
    
    for (int i = 0; i < g_overlay_count; i++) {
        if (g_overlay_entries[i].is_active) {
            printf("  [%d] %s -> %s (priority: %d)\n",
                   i,
                   g_overlay_entries[i].original_path,
                   g_overlay_entries[i].overlay_path,
                   g_overlay_entries[i].priority);
        }
    }
    
    printf("========================\n\n");
}

// Очистка overlayfs
void overlay_cleanup(void) {
    memset(g_overlay_entries, 0, sizeof(g_overlay_entries));
    g_overlay_count = 0;
    g_overlay_initialized = false;
    
    printf("[OverlayFS] Очищено\n");
}
