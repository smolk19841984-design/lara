//
//  offset_finder.h
//  Lara Jailbreak
//

#ifndef offset_finder_h
#define offset_finder_h

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    // Символы ядра
    uint64_t allproc;
    uint64_t current_task;
    uint64_t kernel_map;
    
    // Смещения структур
    uint64_t proc_p_pid;
    uint64_t proc_p_ucred;
    uint64_t task_itk_self;
    uint64_t ucred_cr_uid;
    uint64_t task_bsd_info;
    uint64_t proc_p_csflags;
    uint64_t proc_p_traced;
} kernel_offsets_t;

// Поиск всех оффсетов в kernelcache
bool find_kernel_offsets(uint64_t kernel_base);

// Получение кэшированных оффсетов
kernel_offsets_t get_kernel_offsets(void);

// Сброс кэша
void reset_kernel_offsets(void);

// Разрешение символа по имени
uint64_t resolve_symbol(const char *name);

#endif /* offset_finder_h */
