//
//  dsfun_koffsets.h
//  lara — KOFFSET enum и kgetoffset() для совместимости с third_party
//

#ifndef dsfun_koffsets_h
#define dsfun_koffsets_h

#include <stdint.h>

typedef enum {
    KOFFSET_KERNEL_BASE = 0,
    KOFFSET_TTBR0_EL1 = 1,
    KOFFSET_TTBR1_EL1 = 2,
    KOFFSET_PPL_ZONE = 3,
    KOFFSET_PPL_CHECK = 4,
    KOFFSET_VBAR_BASE = 5,
    KOFFSET_SCTLR_EL1 = 6,
    KOFFSET_EXCEPTION_TABLE = 7,
    KOFFSET_PROC_TASK = 8,
    KOFFSET_AMFI_ALLOW_UNSIGNED = 9,
    KOFFSET_AMFI_GET_OUT_OF_MY_WAY = 10,
    KOFFSET_CS_ENFORCEMENT = 11,
    KOFFSET_KEXT_SIGNATURE_VALID = 12,
    KOFFSET_OSBOUNDLE_SIGNATURE_REQUIRED = 13,
    KOFFSET_ALLPROC = 14,
    KOFFSET_PROC_P_NAME = 15,
    KOFFSET_TASK_CS_FLAGS = 16,
    KOFFSET_PROC_PID = 17,
    KOFFSET_SANDBOX_CACHE = 18,
    KOFFSET_PANICLOG_ENABLE = 19,
    KOFFSET_PANIC_LOG_WRITE = 20,
    KOFFSET_WATCHDOG_ENABLE = 21,
    KOFFSET_WATCHDOG_TICK = 22,
    KOFFSET_MACF_ENFORCE = 23,
    KOFFSET_PROC_P_FLAG = 24,
    KOFFSET_PROC_P_TEXTVP = 25,
    KOFFSET_PROC_P_FD = 26,
    KOFFSET_FILEDESC_FD_CDIR = 27,
    KOFFSET_VNODE_V_DATA = 28,
    KOFFSET_VNODE_V_PARENT = 29,
} KOffset;

uint32_t kgetoffset(KOffset off);
uint64_t kgetoffset_by_name(const char *name);

#endif /* dsfun_koffsets_h */
