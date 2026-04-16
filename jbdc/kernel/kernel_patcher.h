//
//  kernel_patcher.h
//  Lara Jailbreak
//

#ifndef kernel_patcher_h
#define kernel_patcher_h

#include <stdbool.h>

// Применение всех патчей ядра
bool apply_kernel_patches(void);

// Получение root-прав
bool patch_root(void);

// Отключение AMFI
bool patch_amfi(void);

// Отключение Sandbox
bool patch_sandbox(void);

#endif /* kernel_patcher_h */
