/*
 * final_offsets.h
 * Offsets verified against live iPad8,9 iOS 17.3.1 memory dump
 * Generated: 2026-04-18
 *
 * Notes:
 * - These are kernel-relative static offsets (ASLR-independent). Compute
 *   live addresses by adding the offset to the device `kernel_base`.
 * - AMFI and kernproc offsets were calculated from the provided live
 *   addresses and match known constants used in prior analysis.
 */

#ifndef FINAL_OFFSETS_H
#define FINAL_OFFSETS_H

#include <stdint.h>

/* Global/kernel-relative offsets */
#define OFFSET_AMFI     0x00C82AE0ULL  /* AMFI base: kernel_base + 0xC82AE0 */
#define OFFSET_KERNPROC 0x0096B928ULL  /* kernproc slot: kernel_base + 0x96B928 */

/* Helper macros to compute live addresses from kernel_base */
#define AMFI_ADDR(kernel_base)        ((uint64_t)((kernel_base) + OFFSET_AMFI))
#define KERNPROC_SLOT_ADDR(kernel_base) ((uint64_t)((kernel_base) + OFFSET_KERNPROC))

/* Selected `proc` struct offsets (verified via kread logs)
 * - p_list:     0x0
 * - p_proc_ro:  0x18
 * - p_pid:      0x28  (confirmed working value in logs)
 */
#define PROC_P_LIST    0x0
#define PROC_P_PROC_RO 0x18
#define PROC_P_PID     0x28

/* Credential (`ucred`) layout (common XNU/iOS 17 layout)
 * - Use proc->p_ucred + UCREDS_CR_UID to get the effective UID
 * - cr_uid is typically at +0x18 inside struct ucred
 */
#define UCREDS_CR_UID  0x18
#define UCREDS_CR_GID  0x1C

/* Notes:
 * - Some kernels expose `p_uid`/`p_gid` directly inside `proc` at varying
 *   offsets (0x30/0x34/0x38/0x3C) on different builds — prefer reading
 *   credentials via proc->p_ucred + UCREDS_CR_UID when possible.
 * - These offsets were generated from live address math and validated
 *   against prior known constants (0xC82AE0 and 0x96B928).
 */

#endif /* FINAL_OFFSETS_H */
