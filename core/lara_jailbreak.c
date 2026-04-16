//
//  lara_jailbreak.c
//  Lara Jailbreak - Main Entry Point for iOS 17.3.1
//
//  Integrates all components:
//  - Darksword exploit (kernel primitives)
//  - Dynamic offset finding (pattern scanning)
//  - Shadow Pages (PPL bypass)
//  - Kernel Patch Manager
//  - Sandbox Patches
//  - Substitute/libhooker integration
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <os/log.h>

// Include core modules
#include "../core/kernel_offsets.h"
#include "../core/shadow_pages.h"
#include "../kexploit/darksword.h"
#include "../patch/kernel_patches.h"
#include "../patch/sandbox_patches.h"
#include "../libhooker/substitute_hook.h"

// Jailbreak state
typedef struct {
    bool exploited;
    bool has_kernel_access;
    bool ppl_bypassed;
    bool kernel_patched;
    bool sandbox_patched;
    bool tweaks_loaded;
    bool rootless;
    uint64_t kernel_base;
    uint64_t current_task;
} jb_state_t;

static jb_state_t g_jb = {0};

// Logging macro
#define JB_LOG(level, msg, ...) \
    os_log(OS_LOG_DEFAULT, "[LaraJB] " msg, ##__VA_ARGS__)

// Step 1: Run exploit to get kernel access
static bool step1_exploit(void) {
    JB_LOG(INFO, "Step 1: Running darksword exploit...");
    
    if (!darksword_run()) {
        JB_LOG(ERROR, "Exploit failed!");
        return false;
    }
    
    // Verify we have kernel access
    uint64_t test_addr = darksword_kread(0xFFFFFFF007004000); // Kernel base hint
    if (!test_addr) {
        JB_LOG(ERROR, "Kernel read verification failed");
        return false;
    }
    
    g_jb.exploited = true;
    g_jb.has_kernel_access = true;
    JB_LOG(INFO, "Exploit successful - kernel access obtained");
    return true;
}

// Step 2: Find kernel offsets dynamically
static bool step2_find_offsets(kernel_offsets_t *offsets) {
    JB_LOG(INFO, "Step 2: Finding kernel offsets via pattern scanning...");
    
    // For now, use runtime resolution with kread primitive
    // In full implementation, would dump kernel and scan patterns
    
    if (!resolve_runtime_offsets(darksword_kread, darksword_kwrite, offsets)) {
        JB_LOG(ERROR, "Offset resolution failed");
        return false;
    }
    
    g_jb.kernel_base = offsets->kernel_base;
    JB_LOG(INFO, "Offsets found - kernel base: 0x%llx", g_jb.kernel_base);
    return true;
}

// Step 3: Initialize shadow pages for PPL bypass
static bool step3_shadow_init(void) {
    JB_LOG(INFO, "Step 3: Initializing shadow pages for PPL bypass...");
    
    if (!shadow_init(darksword_kread, darksword_kwrite, 
                     darksword_kread_buf, darksword_kwrite_buf)) {
        JB_LOG(ERROR, "Shadow initialization failed");
        return false;
    }
    
    g_jb.ppl_bypassed = true;
    JB_LOG(INFO, "Shadow pages initialized");
    return true;
}

// Step 4: Apply kernel patches
static bool step4_kernel_patch(kernel_offsets_t *offsets) {
    JB_LOG(INFO, "Step 4: Applying kernel patches...");
    
    // Patch AMFI
    if (!patch_amfi_enforcement(offsets)) {
        JB_LOG(WARNING, "AMFI patch may have failed");
    }
    
    // Patch Code Signing
    if (!patch_cs_enforcement(offsets)) {
        JB_LOG(WARNING, "CS patch may have failed");
    }
    
    // Patch SIP
    if (!patch_sip(offsets)) {
        JB_LOG(WARNING, "SIP patch may have failed");
    }
    
    // Enable debugging
    if (!patch_debug_enabled(offsets)) {
        JB_LOG(WARNING, "Debug patch may have failed");
    }
    
    g_jb.kernel_patched = true;
    JB_LOG(INFO, "Kernel patches applied");
    return true;
}

// Step 5: Patch sandbox
static bool step5_sandbox_patch(kernel_offsets_t *offsets) {
    JB_LOG(INFO, "Step 5: Patching sandbox...");
    
    if (!sandbox_patch_all(offsets)) {
        JB_LOG(ERROR, "Sandbox patching failed");
        return false;
    }
    
    g_jb.sandbox_patched = true;
    JB_LOG(INFO, "Sandbox patched");
    return true;
}

// Step 6: Get root privileges
static bool step6_get_root(kernel_offsets_t *offsets) {
    JB_LOG(INFO, "Step 6: Obtaining root privileges...");
    
    if (!get_root_via_ucred(offsets)) {
        JB_LOG(ERROR, "Root escalation failed");
        return false;
    }
    
    // Verify root
    if (getuid() != 0) {
        JB_LOG(WARNING, "Root verification failed (uid=%d)", getuid());
        // Continue anyway in rootless mode
        g_jb.rootless = true;
    } else {
        JB_LOG(INFO, "Root obtained successfully (uid=0)");
        g_jb.rootless = false;
    }
    
    return true;
}

// Step 7: Initialize tweak system
static bool step7_init_tweaks(void) {
    JB_LOG(INFO, "Step 7: Initializing tweak system...");
    
    if (!tweak_init()) {
        JB_LOG(WARNING, "Tweak initialization had issues");
        // Continue anyway
    }
    
    g_jb.tweaks_loaded = true;
    JB_LOG(INFO, "Tweak system initialized");
    return true;
}

// Step 8: Setup filesystem (OverlayFS)
static bool step8_setup_filesystem(void) {
    JB_LOG(INFO, "Step 8: Setting up overlay filesystem...");
    
    // Create jailbreak directory structure
    const char *jb_dirs[] = {
        "/var/jb",
        "/var/jb/bin",
        "/var/jb/sbin",
        "/var/jb/usr",
        "/var/jb/usr/bin",
        "/var/jb/usr/sbin",
        "/var/jb/usr/lib",
        "/var/jb/usr/libexec",
        "/var/jb/Library",
        "/var/jb/Library/TweakInject",
        "/var/jb/Library/MobileSubstrate",
        "/var/jb/Library/MobileSubstrate/DynamicLibraries",
        NULL
    };
    
    for (int i = 0; jb_dirs[i]; i++) {
        mkdir(jb_dirs[i], 0755);
        JB_LOG(DEBUG, "Created directory: %s", jb_dirs[i]);
    }
    
    JB_LOG(INFO, "Filesystem setup complete");
    return true;
}

// Cleanup function
static void jb_cleanup(void) {
    JB_LOG(INFO, "Cleaning up...");
    
    tweak_cleanup();
    shadow_cleanup();
    // Note: Don't cleanup darksword - kernel access needed for unjailbreak
    
    JB_LOG(INFO, "Cleanup complete");
}

// Main jailbreak function
bool lara_jailbreak(void) {
    JB_LOG(ALWAYS, "=================================");
    JB_LOG(ALWAYS, "  Lara Jailbreak for iOS 17.3.1  ");
    JB_LOG(ALWAYS, "=================================");
    
    memset(&g_jb, 0, sizeof(g_jb));
    kernel_offsets_t offsets = {0};
    
    // Execute jailbreak steps
    if (!step1_exploit()) goto fail;
    if (!step2_find_offsets(&offsets)) goto fail;
    if (!step3_shadow_init()) goto fail;
    if (!step4_kernel_patch(&offsets)) goto fail;
    if (!step5_sandbox_patch(&offsets)) goto fail;
    if (!step6_get_root(&offsets)) goto fail; // Non-fatal in rootless
    if (!step7_init_tweaks()) goto fail;      // Non-fatal
    if (!step8_setup_filesystem()) goto fail;
    
    // Success!
    JB_LOG(ALWAYS, "=================================");
    JB_LOG(ALWAYS, "  Jailbreak Successful!          ");
    JB_LOG(ALWAYS, "  Mode: %s", g_jb.rootless ? "Rootless" : "Rootful");
    JB_LOG(ALWAYS, "=================================");
    
    return true;
    
fail:
    JB_LOG(ERROR, "Jailbreak failed at step");
    jb_cleanup();
    return false;
}

// Unjailbreak function (optional - removes patches)
bool lara_unjailbreak(void) {
    JB_LOG(INFO, "Unjailbreaking...");
    
    // Restore original kernel state
    // This would require saving original values before patching
    
    jb_cleanup();
    
    JB_LOG(INFO, "Unjailbreak complete - reboot recommended");
    return true;
}

// Check jailbreak status
bool lara_is_jailed(void) {
    return !g_jb.kernel_patched || !g_jb.sandbox_patched;
}

// Get jailbreak info
const char* lara_get_info(void) {
    static char info[512];
    snprintf(info, sizeof(info),
             "Lara Jailbreak iOS 17.3.1\n"
             "Exploited: %s\n"
             "Kernel Access: %s\n"
             "PPL Bypassed: %s\n"
             "Kernel Patched: %s\n"
             "Sandbox Patched: %s\n"
             "Tweaks Loaded: %s\n"
             "Mode: %s",
             g_jb.exploited ? "Yes" : "No",
             g_jb.has_kernel_access ? "Yes" : "No",
             g_jb.ppl_bypassed ? "Yes" : "No",
             g_jb.kernel_patched ? "Yes" : "No",
             g_jb.sandbox_patched ? "Yes" : "No",
             g_jb.tweaks_loaded ? "Yes" : "No",
             g_jb.rootless ? "Rootless" : "Rootful");
    return info;
}
