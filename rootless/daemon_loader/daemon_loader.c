//
//  daemon_loader.c
//  Lara Rootless Jailbreak - Daemon Loader Module
//
//  Загрузчик демонов для фонового управления джейлбрейком
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <spawn.h>
#include <xpc/xpc.h>

#include "daemon_loader.h"

#define MAX_DAEMONS 32
#define MAX_PATH_LEN 512
#define MAX_LABEL_LEN 128

// Структура для описания демона
typedef struct {
    char label[MAX_LABEL_LEN];      // Launchd label
    char path[MAX_PATH_LEN];        // Путь к бинарнику
    char *argv[16];                 // Аргументы
    int argc;                       // Количество аргументов
    bool is_running;                // Статус запуска
    pid_t pid;                      // PID процесса
    bool should_restart;            // Авто-перезапуск при падении
    int restart_count;              // Счётчик перезапусков
} daemon_info_t;

static daemon_info_t g_daemons[MAX_DAEMONS];
static int g_daemon_count = 0;
static bool g_loader_initialized = false;

// Базовая директория для launchdaemons
static const char *g_launchdaemons_dir = "/var/jb/Library/LaunchDaemons";

// Инициализация загрузчика демонов
bool daemon_loader_init(void) {
    if (g_loader_initialized) {
        return true;
    }
    
    memset(g_daemons, 0, sizeof(g_daemons));
    g_daemon_count = 0;
    
    // Создание директории для launchdaemons если не существует
    mkdir(g_launchdaemons_dir, 0755);
    
    g_loader_initialized = true;
    printf("[DaemonLoader] Инициализировано\n");
    
    return true;
}

// Парсинг plist файла демона
static bool parse_launchd_plist(const char *plist_path, daemon_info_t *daemon) {
    // Упрощённый парсинг plist (в реальности нужно использовать libxml2 или CFPropertyList)
    FILE *fp = fopen(plist_path, "r");
    if (!fp) {
        return false;
    }
    
    char line[1024];
    char current_key[256] = {0};
    bool in_dict = false;
    
    while (fgets(line, sizeof(line), fp)) {
        // Поиск Label
        if (strstr(line, "<key>Label</key>")) {
            current_key[0] = 'L';
            current_key[1] = '\0';
        } else if (strcmp(current_key, "L") == 0 && strstr(line, "<string>")) {
            char *start = strstr(line, "<string>") + 8;
            char *end = strstr(start, "</string>");
            if (start && end) {
                size_t len = end - start;
                if (len < MAX_LABEL_LEN) {
                    strncpy(daemon->label, start, len);
                    daemon->label[len] = '\0';
                }
            }
            current_key[0] = '\0';
        }
        
        // Поиск ProgramArguments
        if (strstr(line, "<key>ProgramArguments</key>")) {
            in_dict = true;
        }
        
        // Парсинг аргументов
        if (in_dict && strstr(line, "<string>")) {
            char *start = strstr(line, "<string>") + 8;
            char *end = strstr(start, "</string>");
            if (start && end && daemon->argc < 15) {
                size_t len = end - start;
                daemon->argv[daemon->argc] = malloc(len + 1);
                if (daemon->argv[daemon->argc]) {
                    strncpy(daemon->argv[daemon->argc], start, len);
                    daemon->argv[daemon->argc][len] = '\0';
                    daemon->argc++;
                }
            }
        }
        
        if (strstr(line, "</array>")) {
            in_dict = false;
        }
    }
    
    fclose(fp);
    
    // Если argv пуст, используем path как первый аргумент
    if (daemon->argc == 0) {
        daemon->argv[0] = strdup(daemon->path);
        daemon->argc = 1;
    }
    
    daemon->argv[daemon->argc] = NULL; // NULL terminator для exec
    
    return strlen(daemon->label) > 0;
}

// Регистрация демона из plist файла
bool daemon_register_from_plist(const char *plist_path) {
    if (!g_loader_initialized || !plist_path) {
        return false;
    }
    
    if (g_daemon_count >= MAX_DAEMONS) {
        printf("[DaemonLoader] Ошибка: достигнут лимит демонов\n");
        return false;
    }
    
    daemon_info_t *daemon = &g_daemons[g_daemon_count];
    memset(daemon, 0, sizeof(*daemon));
    
    // Извлечение пути из имени plist
    char basename[MAX_PATH_LEN];
    const char *slash = strrchr(plist_path, '/');
    if (slash) {
        strncpy(basename, slash + 1, sizeof(basename) - 1);
    } else {
        strncpy(basename, plist_path, sizeof(basename) - 1);
    }
    
    // Замена .plist на путь к бинарнику
    char *dot = strstr(basename, ".plist");
    if (dot) {
        *dot = '\0';
    }
    
    snprintf(daemon->path, sizeof(daemon->path), "%s/%s", g_launchdaemons_dir, basename);
    
    // Парсинг plist
    if (!parse_launchd_plist(plist_path, daemon)) {
        printf("[DaemonLoader] Ошибка парсинга plist: %s\n", plist_path);
        return false;
    }
    
    daemon->is_running = false;
    daemon->pid = -1;
    daemon->should_restart = true;
    daemon->restart_count = 0;
    
    g_daemon_count++;
    
    printf("[DaemonLoader] Зарегистрирован демон: %s (%s)\n", 
           daemon->label, daemon->path);
    
    return true;
}

// Прямая регистрация демона
bool daemon_register(const char *label, const char *path, char **argv, int argc) {
    if (!g_loader_initialized || !label || !path) {
        return false;
    }
    
    if (g_daemon_count >= MAX_DAEMONS) {
        printf("[DaemonLoader] Ошибка: достигнут лимит демонов\n");
        return false;
    }
    
    daemon_info_t *daemon = &g_daemons[g_daemon_count];
    memset(daemon, 0, sizeof(*daemon));
    
    strncpy(daemon->label, label, MAX_LABEL_LEN - 1);
    strncpy(daemon->path, path, MAX_PATH_LEN - 1);
    
    daemon->argc = (argc < 15) ? argc : 15;
    for (int i = 0; i < daemon->argc; i++) {
        daemon->argv[i] = strdup(argv[i]);
    }
    daemon->argv[daemon->argc] = NULL;
    
    daemon->is_running = false;
    daemon->pid = -1;
    daemon->should_restart = true;
    daemon->restart_count = 0;
    
    g_daemon_count++;
    
    printf("[DaemonLoader] Зарегистрирован демон: %s (%s)\n", label, path);
    
    return true;
}

// Запуск одного демона
bool daemon_start(int index) {
    if (index < 0 || index >= g_daemon_count) {
        return false;
    }
    
    daemon_info_t *daemon = &g_daemons[index];
    
    if (daemon->is_running) {
        printf("[DaemonLoader] Демон %s уже запущен (PID: %d)\n", 
               daemon->label, daemon->pid);
        return true;
    }
    
    printf("[DaemonLoader] Запуск демона: %s\n", daemon->label);
    
    // Проверка существования файла
    struct stat st;
    if (stat(daemon->path, &st) != 0) {
        printf("[DaemonLoader] Файл не найден: %s\n", daemon->path);
        return false;
    }
    
    // Установка исполняемого флага
    chmod(daemon->path, 0755);
    
    // posix_spawn для запуска
    pid_t pid;
    extern char **environ;
    
    int status = posix_spawn(&pid, daemon->path, NULL, NULL, daemon->argv, environ);
    
    if (status == 0) {
        daemon->pid = pid;
        daemon->is_running = true;
        daemon->restart_count = 0;
        
        printf("[DaemonLoader] Демон %s запущен с PID %d\n", daemon->label, pid);
        return true;
    } else {
        printf("[DaemonLoader] Ошибка запуска %s: %s (%d)\n", 
               daemon->label, strerror(status), status);
        return false;
    }
}

// Остановка одного демона
bool daemon_stop(int index) {
    if (index < 0 || index >= g_daemon_count) {
        return false;
    }
    
    daemon_info_t *daemon = &g_daemons[index];
    
    if (!daemon->is_running) {
        return true;
    }
    
    printf("[DaemonLoader] Остановка демона: %s (PID: %d)\n", 
           daemon->label, daemon->pid);
    
    // Отправка SIGTERM
    kill(daemon->pid, SIGTERM);
    
    // Ожидание завершения
    usleep(100000); // 100ms
    
    // Принудительная остановка если ещё работает
    if (daemon->is_running) {
        kill(daemon->pid, SIGKILL);
    }
    
    daemon->is_running = false;
    daemon->pid = -1;
    
    printf("[DaemonLoader] Демон %s остановлен\n", daemon->label);
    return true;
}

// Запуск всех зарегистрированных демонов
bool daemon_start_all(void) {
    if (!g_loader_initialized) {
        return false;
    }
    
    printf("[DaemonLoader] Запуск всех демонов (%d)...\n", g_daemon_count);
    
    int started = 0;
    for (int i = 0; i < g_daemon_count; i++) {
        if (daemon_start(i)) {
            started++;
        }
        // Небольшая задержка между запусками
        usleep(50000);
    }
    
    printf("[DaemonLoader] Запущено %d из %d демонов\n", started, g_daemon_count);
    return started > 0;
}

// Остановка всех демонов
bool daemon_stop_all(void) {
    if (!g_loader_initialized) {
        return false;
    }
    
    printf("[DaemonLoader] Остановка всех демонов...\n");
    
    int stopped = 0;
    for (int i = 0; i < g_daemon_count; i++) {
        if (daemon_stop(i)) {
            stopped++;
        }
    }
    
    printf("[DaemonLoader] Остановлено %d демонов\n", stopped);
    return true;
}

// Перезапуск демона
bool daemon_restart(int index) {
    if (index < 0 || index >= g_daemon_count) {
        return false;
    }
    
    daemon_info_t *daemon = &g_daemons[index];
    
    daemon->restart_count++;
    
    if (daemon->restart_count > 5) {
        printf("[DaemonLoader] Демон %s превысил лимит перезапусков (5)\n", 
               daemon->label);
        return false;
    }
    
    daemon_stop(index);
    usleep(500000); // 500ms перед перезапуском
    return daemon_start(index);
}

// Мониторинг демонов (проверка и авто-перезапуск)
void daemon_monitor(void) {
    if (!g_loader_initialized) {
        return;
    }
    
    for (int i = 0; i < g_daemon_count; i++) {
        daemon_info_t *daemon = &g_daemons[i];
        
        if (daemon->is_running && daemon->should_restart) {
            // Проверка жив ли процесс
            if (kill(daemon->pid, 0) != 0) {
                // Процесс умер
                printf("[DaemonLoader] Демон %s упал (PID: %d)\n", 
                       daemon->label, daemon->pid);
                
                daemon->is_running = false;
                
                // Авто-перезапуск
                if (daemon->restart_count < 5) {
                    printf("[DaemonLoader] Авто-перезапуск %s...\n", daemon->label);
                    daemon_restart(i);
                }
            }
        }
    }
}

// Сканирование директории LaunchDaemons и регистрация всех plist
bool daemon_scan_directory(const char *dir_path) {
    if (!dir_path) {
        dir_path = g_launchdaemons_dir;
    }
    
    DIR *dir = opendir(dir_path);
    if (!dir) {
        printf("[DaemonLoader] Не удалось открыть директорию: %s\n", dir_path);
        return false;
    }
    
    struct dirent *entry;
    int registered = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".plist")) {
            char plist_path[MAX_PATH_LEN];
            snprintf(plist_path, sizeof(plist_path), "%s/%s", dir_path, entry->d_name);
            
            if (daemon_register_from_plist(plist_path)) {
                registered++;
            }
        }
    }
    
    closedir(dir);
    
    printf("[DaemonLoader] Зарегистрировано %d демонов из %s\n", 
           registered, dir_path);
    
    return registered > 0;
}

// Получение статуса демона
void daemon_get_status(int index, char *status_buf, size_t buf_size) {
    if (index < 0 || index >= g_daemon_count) {
        snprintf(status_buf, buf_size, "Invalid index");
        return;
    }
    
    daemon_info_t *daemon = &g_daemons[index];
    
    snprintf(status_buf, buf_size, 
             "Label: %s\n"
             "Path: %s\n"
             "Running: %s\n"
             "PID: %d\n"
             "Restarts: %d\n"
             "Auto-restart: %s\n",
             daemon->label,
             daemon->path,
             daemon->is_running ? "YES" : "NO",
             daemon->pid,
             daemon->restart_count,
             daemon->should_restart ? "YES" : "NO");
}

// Вывод статуса всех демонов
void daemon_print_status(void) {
    printf("\n=== Daemon Loader Status ===\n");
    printf("Total Daemons: %d / %d\n\n", g_daemon_count, MAX_DAEMONS);
    
    for (int i = 0; i < g_daemon_count; i++) {
        daemon_info_t *daemon = &g_daemons[i];
        printf("[%d] %s\n", i, daemon->label);
        printf("    Path: %s\n", daemon->path);
        printf("    Running: %s (PID: %d)\n", 
               daemon->is_running ? "YES" : "NO", daemon->pid);
        printf("    Restarts: %d\n", daemon->restart_count);
        printf("\n");
    }
    
    printf("============================\n\n");
}

// Очистка ресурсов
void daemon_cleanup(void) {
    printf("[DaemonLoader] Остановка и очистка демонов...\n");
    
    daemon_stop_all();
    
    // Освобождение памяти
    for (int i = 0; i < g_daemon_count; i++) {
        for (int j = 0; j < g_daemons[i].argc; j++) {
            if (g_daemons[i].argv[j]) {
                free(g_daemons[i].argv[j]);
            }
        }
    }
    
    memset(g_daemons, 0, sizeof(g_daemons));
    g_daemon_count = 0;
    g_loader_initialized = false;
    
    printf("[DaemonLoader] Очищено\n");
}

// Пример создания простого демона
bool daemon_create_simple(const char *label, const char *script_content) {
    if (!g_loader_initialized) {
        return false;
    }
    
    char script_path[MAX_PATH_LEN];
    snprintf(script_path, sizeof(script_path), "%s/%s.sh", g_launchdaemons_dir, label);
    
    // Запись скрипта
    FILE *fp = fopen(script_path, "w");
    if (!fp) {
        return false;
    }
    
    fprintf(fp, "#!/bin/sh\n%s\n", script_content);
    fclose(fp);
    
    chmod(script_path, 0755);
    
    // Создание argv
    char *argv[] = {"/bin/sh", script_path, NULL};
    
    return daemon_register(label, script_path, argv, 2);
}
