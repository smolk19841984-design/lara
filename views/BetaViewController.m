//
//  BetaViewController.m
//  lara — тестирование всех модулей из third_party/darksword-kexploit-fun
//  Каждый модуль = отдельная кнопка с логированием
//  Все dsfun_* функции реализованы в dsfun_all_bridge.m через Lara API
//

#import "BetaViewController.h"
#import "../LaraManager.h"
#import "../Logger.h"
#import "kexploit/darksword.h"
#import "kexploit/ppl.h"
#import "kexploit/offsets.h"

// ── Все dsfun_* модули (из dsfun_all_bridge.m) ──────────────────────────────

// kexploit_opa334
extern int dsfun_kexploit_run(void);
extern bool dsfun_have_kernel_read(void);
extern bool dsfun_have_kernel_write(void);
extern uint64_t dsfun_g_kernel_slide;
extern uint64_t dsfun_g_kernel_base;

// krw
extern uint64_t dsfun_kread64(uint64_t addr);
extern uint32_t dsfun_kread32(uint64_t addr);
extern void dsfun_kwrite64(uint64_t addr, uint64_t val);
extern void dsfun_kwrite32(uint64_t addr, uint32_t val);
extern void dsfun_khexdump(uint64_t addr, size_t size);
extern void dsfun_kreadbuf(uint64_t addr, void *buf, size_t len);
extern void dsfun_kwritebuf(uint64_t addr, const void *buf, size_t len);
extern uint64_t dsfun_kread_ptr(uint64_t addr);
extern uint64_t dsfun_kread_smrptr(uint64_t addr);

// kutils
extern uint64_t dsfun_proc_self(void);
extern uint64_t dsfun_task_self(void);
extern uint64_t dsfun_proc_find(const char *name);
extern uint64_t dsfun_proc_task(uint64_t proc);
extern uint64_t dsfun_proc_get_p_name(uint64_t proc);
extern uint64_t dsfun_proc_get_cred_label(uint64_t proc);
extern uint64_t dsfun_label_get_sandbox(uint64_t label);
extern uint64_t dsfun_task_get_vm_map(uint64_t task);
extern uint64_t dsfun_task_get_ipc_port_kobject(uint64_t task, mach_port_name_t port);

// vnode
extern uint64_t dsfun_get_rootvnode(void);
extern uint64_t dsfun_get_vnode_for_path_by_chdir(const char *path);
extern uint64_t dsfun_get_vnode_for_path_by_open(const char *path);
extern uint64_t dsfun_get_vnode_by_fd(int fd);
extern uint64_t dsfun_vnode_redirect_folder(const char *to, const char *from);
extern uint64_t dsfun_vnode_fsnode(uint64_t vp);
extern uint64_t dsfun_vnode_get_child_vnode(uint64_t vp, const char *name);
extern uint64_t dsfun_vnode_apfs_chown(uint64_t vp, uint32_t uid, uint32_t gid);
extern uint64_t dsfun_vnode_apfs_chmod(uint64_t vp, uint16_t mode);
extern uint64_t dsfun_apfs_fsnode_set_uid(uint64_t vp, uint32_t uid);
extern uint64_t dsfun_apfs_fsnode_set_gid(uint64_t vp, uint32_t gid);
extern uint64_t dsfun_apfs_fsnode_set_mode(uint64_t vp, uint16_t mode);

// ppl_bypass
extern bool dsfun_ppl_init(void);
extern int dsfun_ppl_write_kernel64(uint64_t kva, uint64_t value);
extern uint64_t dsfun_ppl_read_kernel64(uint64_t kva);
extern bool dsfun_test_ppl_bypass(void);
extern bool dsfun_disable_ppl_checks(void);

// post_rw_hardening
extern bool dsfun_post_rw_hardening_init(void);
extern void dsfun_print_security_status(void);
extern uint64_t dsfun_safe_proc_find_by_name(const char *name);

// multi_vector_engine
extern bool dsfun_multi_vector_pre_exploit_check(void);
extern uint64_t dsfun_multi_vector_find_kernel_base(void);
extern void dsfun_multi_vector_print_stats(void);
extern bool dsfun_multi_vector_post_exploit_validate(void);
extern bool dsfun_multi_vector_validate_kernel_rw(void);

// utils/sandbox
extern int dsfun_patch_sandbox_ext(void);
extern int dsfun_check_sandbox_var_rw(void);

// utils/process
extern int dsfun_get_proc_list(uint64_t **out_list, int *out_count);
extern uint64_t dsfun_find_proc_by_name(const char *name);

// utils/file
extern int dsfun_file_exists(const char *path);
extern char *dsfun_read_file_contents(const char *path);
extern int dsfun_write_file_contents(const char *path, const char *content);

// utils/hexdump
extern void dsfun_hexdump(const void *buf, size_t len);

// phantom_ppl
extern int dsfun_phantom_ppl_init(void);

// exploit_stabilizer
extern int dsfun_exploit_stabilize(void);
extern int dsfun_exploit_stabilize_pre(void);
extern int dsfun_exploit_stabilize_post(void);

// kernel_panichandler
extern int dsfun_kernel_panichandler_init(void);
extern int dsfun_kernel_panichandler_check(void);

// arc_core
extern int dsfun_arc_core_init(void);
extern int dsfun_arc_core_run(void);

// alternative_exploits
extern int dsfun_alternative_exploit_run(void);

// patchfinder
extern int dsfun_patchfinder_init(void);

// research
extern int dsfun_amfi_research_init(void);
extern int dsfun_sandbox_research_init(void);
extern int dsfun_vnode_research_init(void);

// jailbreak_init
extern int dsfun_jailbreak_init(void);
extern bool dsfun_is_jailbreak_active(void);
extern int dsfun_jailbreak_cleanup(void);
extern void dsfun_jailbreak_print_info(void);

// VM functions
extern uint64_t dsfun_vm_map_get_header(uint64_t map);
extern uint64_t dsfun_vm_map_find_entry(uint64_t map, uint64_t address);

// ── Секции и строки ──────────────────────────────────────────────────────────

typedef void (^BetaAction)(void);

@interface BetaItem : NSObject
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *sub;
@property (nonatomic, copy) BetaAction action;
@end

@implementation BetaItem
@end

@interface BetaViewController ()
@property (nonatomic, copy) NSArray<NSArray<BetaItem *> *> *sections;
@property (nonatomic, copy) NSArray<NSString *> *sectionTitles;
@end

@implementation BetaViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        self.title = @"Beta";
        [self _buildSections];
    }
    return self;
}

- (void)_buildSections {
    NSMutableArray<NSMutableArray<BetaItem *> *> *secs = [NSMutableArray array];
    NSMutableArray<NSString *> *titles = [NSMutableArray array];

    // ── 1. Эксплойт (kexploit) ─────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Эксплойт (kexploit)"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"kexploit_run";
        i1.sub = @"Запуск ядра эксплойта";
        i1.action = ^{ [self _logBlock:@"kexploit_run" block:^{
            int r = dsfun_kexploit_run();
            return [NSString stringWithFormat:@"rc=%d kread=%d kwrite=%d",
                    r, dsfun_have_kernel_read() ? 1 : 0, dsfun_have_kernel_write() ? 1 : 0];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"kernel_base / slide";
        i2.sub = @"Базовый адрес и слайд ядра";
        i2.action = ^{ [self _logBlock:@"kernel_base" block:^{
            return [NSString stringWithFormat:@"base=0x%llx slide=0x%llx",
                    (unsigned long long)dsfun_g_kernel_base,
                    (unsigned long long)dsfun_g_kernel_slide];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"alternative_exploit_run";
        i3.sub = @"Альтернативный эксплойт";
        i3.action = ^{ [self _logBlock:@"alt_exploit" block:^{
            int r = dsfun_alternative_exploit_run();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i3];

        [secs addObject:s];
    }

    // ── 2. Kernel R/W (krw) ────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Kernel R/W (krw)"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"kread64(kernBase)";
        i1.sub = @"Чтение 64-бит из ядра";
        i1.action = ^{ [self _logBlock:@"kread64" block:^{
            uint64_t r = dsfun_kread64(dsfun_g_kernel_base);
            return [NSString stringWithFormat:@"0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"kread32(kernBase)";
        i2.sub = @"Чтение 32-бит из ядра";
        i2.action = ^{ [self _logBlock:@"kread32" block:^{
            uint32_t r = dsfun_kread32(dsfun_g_kernel_base);
            return [NSString stringWithFormat:@"0x%x", r];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"kread_ptr / kread_smrptr";
        i3.sub = @"Чтение указателя / SMR pointer";
        i3.action = ^{ [self _logBlock:@"kread_ptr" block:^{
            uint64_t p = dsfun_kread_ptr(dsfun_g_kernel_base);
            uint64_t s = dsfun_kread_smrptr(dsfun_g_kernel_base);
            return [NSString stringWithFormat:@"ptr=0x%llx smr=0x%llx",
                    (unsigned long long)p, (unsigned long long)s];
        }]; };
        [s addObject:i3];

        [secs addObject:s];
    }

    // ── 3. Sandbox ─────────────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Sandbox (utils)"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"patch_sandbox_ext";
        i1.sub = @"Патч sandbox extension";
        i1.action = ^{ [self _logBlock:@"patch_sandbox_ext" block:^{
            int r = dsfun_patch_sandbox_ext();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"check_sandbox_var_rw";
        i2.sub = @"Проверка записи в /private/var";
        i2.action = ^{ [self _logBlock:@"check_sandbox_var_rw" block:^{
            int r = dsfun_check_sandbox_var_rw();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i2];

        [secs addObject:s];
    }

    // ── 4. PPL Bypass ──────────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"PPL Bypass"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"ppl_init";
        i1.sub = @"Инициализация PPL bypass";
        i1.action = ^{ [self _logBlock:@"ppl_init" block:^{
            BOOL r = dsfun_ppl_init();
            return [NSString stringWithFormat:@"init=%d", r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"test_ppl_bypass";
        i2.sub = @"Тест PPL write + verify";
        i2.action = ^{ [self _logBlock:@"test_ppl_bypass" block:^{
            BOOL r = dsfun_test_ppl_bypass();
            return [NSString stringWithFormat:@"test=%d", r];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"disable_ppl_checks";
        i3.sub = @"Отключение проверок PPL";
        i3.action = ^{ [self _logBlock:@"disable_ppl" block:^{
            BOOL r = dsfun_disable_ppl_checks();
            return [NSString stringWithFormat:@"disabled=%d", r];
        }]; };
        [s addObject:i3];

        [secs addObject:s];
    }

    // ── 5. Phantom PPL ─────────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Phantom PPL"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"phantom_ppl_init";
        i1.sub = @"Phantom Page Table Injection";
        i1.action = ^{ [self _logBlock:@"phantom_ppl" block:^{
            int r = dsfun_phantom_ppl_init();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i1];

        [secs addObject:s];
    }

    // ── 6. Post-RW Hardening ───────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Post-RW Hardening"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"post_rw_hardening_init";
        i1.sub = @"Патчи после получения kR/W";
        i1.action = ^{ [self _logBlock:@"post_rw_hardening" block:^{
            BOOL r = dsfun_post_rw_hardening_init();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"print_security_status";
        i2.sub = @"Статус всех защит ядра";
        i2.action = ^{ [self _logBlock:@"security_status" block:^{
            dsfun_print_security_status();
            return @"logged (см. консоль)";
        }]; };
        [s addObject:i2];

        [secs addObject:s];
    }

    // ── 7. Vnode ───────────────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Vnode"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"get_rootvnode";
        i1.sub = @"Получить root vnode";
        i1.action = ^{ [self _logBlock:@"get_rootvnode" block:^{
            uint64_t r = dsfun_get_rootvnode();
            return [NSString stringWithFormat:@"rootvnode=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"get_vnode_for_path";
        i2.sub = @"Vnode для /private/var";
        i2.action = ^{ [self _logBlock:@"vnode_by_path" block:^{
            uint64_t r = dsfun_get_vnode_for_path_by_chdir("/private/var");
            return [NSString stringWithFormat:@"vnode=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"vnode_fsnode";
        i3.sub = @"Получить fsnode из vnode";
        i3.action = ^{ [self _logBlock:@"vnode_fsnode" block:^{
            uint64_t vp = dsfun_get_rootvnode();
            uint64_t r = dsfun_vnode_fsnode(vp);
            return [NSString stringWithFormat:@"fsnode=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i3];

        BetaItem *i4 = [BetaItem new];
        i4.title = @"vnode_apfs_chown";
        i4.sub = @"Сменить uid/gid через vnode";
        i4.action = ^{ [self _logBlock:@"vnode_chown" block:^{
            uint64_t vp = dsfun_get_vnode_for_path_by_chdir("/private/var");
            uint64_t r = dsfun_vnode_apfs_chown(vp, 0, 0);
            return [NSString stringWithFormat:@"rc=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i4];

        [secs addObject:s];
    }

    // ── 8. Process ─────────────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Process (kutils)"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"proc_self";
        i1.sub = @"Получить proc_self";
        i1.action = ^{ [self _logBlock:@"proc_self" block:^{
            uint64_t r = dsfun_proc_self();
            return [NSString stringWithFormat:@"proc_self=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"find_proc(launchd)";
        i2.sub = @"Найти proc launchd";
        i2.action = ^{ [self _logBlock:@"find_launchd" block:^{
            uint64_t r = dsfun_find_proc_by_name("launchd");
            return [NSString stringWithFormat:@"launchd=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"proc_task(proc_self)";
        i3.sub = @"Получить task из proc_self";
        i3.action = ^{ [self _logBlock:@"proc_task" block:^{
            uint64_t r = dsfun_proc_task(dsfun_proc_self());
            return [NSString stringWithFormat:@"task=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i3];

        BetaItem *i4 = [BetaItem new];
        i4.title = @"task_get_vm_map";
        i4.sub = @"Получить vm_map из task";
        i4.action = ^{ [self _logBlock:@"vm_map" block:^{
            uint64_t task = dsfun_proc_task(dsfun_proc_self());
            uint64_t r = dsfun_task_get_vm_map(task);
            return [NSString stringWithFormat:@"vm_map=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i4];

        [secs addObject:s];
    }

    // ── 9. Multi-Vector Engine ─────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Multi-Vector Engine"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"pre_exploit_check";
        i1.sub = @"multi_vector_pre_exploit_check";
        i1.action = ^{ [self _logBlock:@"multi_vector_pre_check" block:^{
            BOOL r = dsfun_multi_vector_pre_exploit_check();
            return [NSString stringWithFormat:@"ok=%d", r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"find_kernel_base";
        i2.sub = @"multi_vector_find_kernel_base";
        i2.action = ^{ [self _logBlock:@"multi_vector_kbase" block:^{
            uint64_t r = dsfun_multi_vector_find_kernel_base();
            return [NSString stringWithFormat:@"base=0x%llx", (unsigned long long)r];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"print_stats";
        i3.sub = @"multi_vector_print_stats";
        i3.action = ^{ [self _logBlock:@"multi_vector_stats" block:^{
            dsfun_multi_vector_print_stats();
            return @"stats logged";
        }]; };
        [s addObject:i3];

        [secs addObject:s];
    }

    // ── 10. Стабилизация ───────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Стабилизация"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"exploit_stabilize";
        i1.sub = @"Стабилизация после эксплойта";
        i1.action = ^{ [self _logBlock:@"exploit_stabilize" block:^{
            int r = dsfun_exploit_stabilize();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"kernel_panichandler_init";
        i2.sub = @"Инициализация обработчика паник";
        i2.action = ^{ [self _logBlock:@"panichandler" block:^{
            int r = dsfun_kernel_panichandler_init();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"arc_core_init";
        i3.sub = @"Adaptive Reliability Core";
        i3.action = ^{ [self _logBlock:@"arc_core" block:^{
            int r = dsfun_arc_core_init();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i3];

        [secs addObject:s];
    }

    // ── 11. Research ───────────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Research"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"amfi_research";
        i1.sub = @"Исследование AMFI";
        i1.action = ^{ [self _logBlock:@"amfi_research" block:^{
            int r = dsfun_amfi_research_init();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"sandbox_research";
        i2.sub = @"Исследование Sandbox";
        i2.action = ^{ [self _logBlock:@"sandbox_research" block:^{
            int r = dsfun_sandbox_research_init();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"vnode_research";
        i3.sub = @"Исследование Vnode";
        i3.action = ^{ [self _logBlock:@"vnode_research" block:^{
            int r = dsfun_vnode_research_init();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i3];

        [secs addObject:s];
    }

    // ── 12. File / Hexdump ─────────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"File / Hexdump"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"file_exists(/var)";
        i1.sub = @"Проверить /var";
        i1.action = ^{ [self _logBlock:@"file_exists" block:^{
            int r = dsfun_file_exists("/var");
            return [NSString stringWithFormat:@"exists=%d", r];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"read_file(/etc/hostname)";
        i2.sub = @"Прочитать файл";
        i2.action = ^{ [self _logBlock:@"read_file" block:^{
            char *r = dsfun_read_file_contents("/etc/hostname");
            NSString *res = r ? [NSString stringWithUTF8String:r] : @"(nil)";
            if (r) free(r);
            return res;
        }]; };
        [s addObject:i2];

        [secs addObject:s];
    }

    // ── 13. Полный Jailbreak ───────────────────────────────────────────────
    {
        NSMutableArray<BetaItem *> *s = [NSMutableArray array];
        [titles addObject:@"Полный Jailbreak"];

        BetaItem *i1 = [BetaItem new];
        i1.title = @"jailbreak_init";
        i1.sub = @"Полный цикл: kexploit → SBX → PPL → hardening";
        i1.action = ^{ [self _logBlock:@"jailbreak_init" block:^{
            int r = dsfun_jailbreak_init();
            return [NSString stringWithFormat:@"rc=%d active=%d", r, dsfun_is_jailbreak_active() ? 1 : 0];
        }]; };
        [s addObject:i1];

        BetaItem *i2 = [BetaItem new];
        i2.title = @"jailbreak_print_info";
        i2.sub = @"Информация о джейлбрейке";
        i2.action = ^{ [self _logBlock:@"jailbreak_info" block:^{
            dsfun_jailbreak_print_info();
            return @"info logged";
        }]; };
        [s addObject:i2];

        BetaItem *i3 = [BetaItem new];
        i3.title = @"jailbreak_cleanup";
        i3.sub = @"Очистка состояния";
        i3.action = ^{ [self _logBlock:@"jailbreak_cleanup" block:^{
            int r = dsfun_jailbreak_cleanup();
            return [NSString stringWithFormat:@"rc=%d", r];
        }]; };
        [s addObject:i3];

        [secs addObject:s];
    }

    self.sectionTitles = [titles copy];
    self.sections = [secs copy];
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return (NSInteger)self.sections.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return self.sectionTitles[(NSUInteger)section];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)self.sections[(NSUInteger)section].count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cid = @"beta";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cid];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cid];
        cell.textLabel.numberOfLines = 0;
        cell.detailTextLabel.numberOfLines = 0;
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    }
    BetaItem *item = self.sections[(NSUInteger)indexPath.section][(NSUInteger)indexPath.row];
    cell.textLabel.text = item.title;
    cell.detailTextLabel.text = item.sub;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    BetaItem *item = self.sections[(NSUInteger)indexPath.section][(NSUInteger)indexPath.row];
    if (item.action) item.action();
}

#pragma mark - Logging helper

- (void)_logBlock:(NSString *)module block:(NSString *(^)(void))block {
    LaraManager *mgr = [LaraManager shared];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *result = nil;
        @try {
            result = block();
        } @catch (NSException *e) {
            result = [NSString stringWithFormat:@"EXCEPTION: %@", e.reason];
        }
        NSString *msg = [NSString stringWithFormat:@"\n[Beta] %@ → %@\n", module, result ?: @"(nil)"];
        dispatch_async(dispatch_get_main_queue(), ^{
            [mgr logMessage:msg];
            [[Logger shared] log:msg];
            UIAlertController *a = [UIAlertController alertControllerWithTitle:module
                                                                       message:result
                                                                preferredStyle:UIAlertControllerStyleAlert];
            [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:a animated:YES completion:nil];
        });
    });
}

@end
