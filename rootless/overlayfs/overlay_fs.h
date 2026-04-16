//
//  overlay_fs.h
//  Lara Rootless Jailbreak - OverlayFS Module
//

#ifndef overlay_fs_h
#define overlay_fs_h

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

// Инициализация
bool overlay_fs_init(const char *base_path);

// Управление путями
bool overlay_add_path(const char *original, const char *overlay, int priority);
bool overlay_remove_path(const char *original);

// Перехваченные функции
int overlay_open(const char *path, int flags, ...);
int overlay_access(const char *path, int amode);
int overlay_stat(const char *path, struct stat *buf);
int overlay_lstat(const char *path, struct stat *buf);
DIR* overlay_opendir(const char *name);
ssize_t overlay_readlink(const char *path, char *buf, size_t bufsize);
int overlay_symlink(const char *target, const char *linkpath);

// Утилиты
bool overlay_copy_file(const char *src, const char *dest_in_overlay);
bool overlay_setup_standard_paths(void);

// Статус и очистка
void overlay_print_status(void);
void overlay_cleanup(void);

#endif /* overlay_fs_h */
