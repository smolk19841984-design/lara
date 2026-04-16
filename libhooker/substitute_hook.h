//
//  substitute_hook.h
//  Lara Jailbreak - Substitute/libhooker Integration
//
//  Tweak manager using Substitute hooking engine for iOS 17.3.1
//  Supports loading .dylib tweaks and hooking Objective-C/Swift methods
//

#ifndef substitute_hook_h
#define substitute_hook_h

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <os/log.h>

// Substitute function pointers (dynamically loaded)
typedef void (*substitute_init_t)(void);
typedef int (*substitute_inject_t)(const char *dylib_path, const char *target_process);
typedef void *(*substitute_hook_t)(void *original, void *replacement, const char *name);
typedef void (*substitute_call_original_t)(void *handle, ...);

static struct {
    void *handle;
    substitute_init_t init;
    substitute_inject_t inject;
    substitute_hook_t hook;
    substitute_call_original_t call_original;
    bool loaded;
} g_substitute = {0};

// Hook definition
typedef struct {
    const char *class_name;
    const char *method_name;
    const char *signature;
    void *original;
    void *replacement;
    bool is_class_method;
} tweak_hook_t;

// Tweak bundle info
typedef struct {
    char *name;
    char *version;
    char *executable_path;
    char **dependencies;
    size_t num_dependencies;
    bool loaded;
    bool enabled;
} tweak_bundle_t;

// Load Substitute library dynamically
static bool substitute_load(void) {
    if (g_substitute.loaded) {
        return true;
    }
    
    // Try multiple paths for Substitute
    const char *paths[] = {
        "/usr/lib/libsubstitute.dylib",
        "/var/jb/usr/lib/libsubstitute.dylib",
        "/usr/lib/TweakInject/libsubstitute.dylib",
        NULL
    };
    
    for (int i = 0; paths[i]; i++) {
        g_substitute.handle = dlopen(paths[i], RTLD_NOW | RTLD_LOCAL);
        if (g_substitute.handle) {
            os_log_info(OS_LOG_DEFAULT, "[Substitute] Loaded from %s", paths[i]);
            break;
        }
    }
    
    if (!g_substitute.handle) {
        os_log_error(OS_LOG_DEFAULT, "[Substitute] Failed to load library: %s", dlerror());
        return false;
    }
    
    // Load symbols
    g_substitute.init = (substitute_init_t)dlsym(g_substitute.handle, "substitute_init");
    g_substitute.hook = (substitute_hook_t)dlsym(g_substitute.handle, "MSHookFunction");
    g_substitute.call_original = (substitute_call_original_t)dlsym(g_substitute.handle, "MSCallOriginal");
    
    // Initialize
    if (g_substitute.init) {
        g_substitute.init();
    }
    
    g_substitute.loaded = true;
    os_log_info(OS_LOG_DEFAULT, "[Substitute] Initialized successfully");
    return true;
}

// HOOK macro for easy method hooking
#define HOOK_METHOD(cls, sel, repl) \
    do { \
        Class _cls = objc_getClass(cls); \
        SEL _sel = sel_registerName(sel); \
        Method _method = _cls ? (_isClassMethod ? class_getClassMethod(_cls, _sel) : class_getInstanceMethod(_cls, _sel)) : NULL; \
        if (_method) { \
            void *_orig = (void*)method_getImplementation(_method); \
            method_setImplementation(_method, (IMP)(repl)); \
            os_log_info(OS_LOG_DEFAULT, "[Tweak] Hooked %s.%s", cls, sel); \
        } \
    } while(0)

#define HOOK_CLASS_METHOD(cls, sel, repl) \
    do { \
        bool _isClassMethod = true; \
        HOOK_METHOD(cls, sel, repl); \
    } while(0)

#define HOOK_INSTANCE_METHOD(cls, sel, repl) \
    do { \
        bool _isClassMethod = false; \
        HOOK_METHOD(cls, sel, repl); \
    } while(0)

// MSHookFunction wrapper
static void *ms_hook_function(void *symbol, void *replace, void **result) {
    if (!g_substitute.loaded && !substitute_load()) {
        os_log_error(OS_LOG_DEFAULT, "[Substitute] Not loaded");
        return NULL;
    }
    
    if (g_substitute.hook) {
        return g_substitute.hook(symbol, replace, NULL);
    }
    
    // Fallback: direct method swizzling for ObjC
    return NULL;
}

// Find image by name
static const struct mach_header *find_image(const char *name) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);
        if (image_name && strstr(image_name, name)) {
            return _dyld_get_image_header(i);
        }
    }
    return NULL;
}

// Find symbol in image
static void *find_symbol_in_image(const struct mach_header *header, const char *symbol_name) {
    // Simplified symbol lookup - would need full Mach-O parsing in production
    return dlsym(RTLD_DEFAULT, symbol_name);
}

// Load tweak from dylib
static bool load_tweak_dylib(const char *path) {
    os_log_info(OS_LOG_DEFAULT, "[Tweak] Loading dylib: %s", path);
    
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        os_log_error(OS_LOG_DEFAULT, "[Tweak] Failed to load %s: %s", path, dlerror());
        return false;
    }
    
    // Look for initializer
    void (*init)(void) = (void (*)(void))dlsym(handle, "LaraTweakInitialize");
    if (init) {
        init();
        os_log_info(OS_LOG_DEFAULT, "[Tweak] Initialized %s", path);
    }
    
    return true;
}

// Scan and load tweaks from directory
static size_t load_tweaks_from_directory(const char *directory) {
    size_t loaded_count = 0;
    
    // In real implementation, this would use opendir/readdir
    // For now, we'll simulate with hardcoded paths
    
    const char *tweak_dirs[] = {
        "/var/jb/Library/TweakInject/",
        "/usr/lib/TweakInject/",
        NULL
    };
    
    for (int i = 0; tweak_dirs[i]; i++) {
        os_log_info(OS_LOG_DEFAULT, "[Tweak] Scanning %s", tweak_dirs[i]);
        
        // Would iterate through .dylib files here
        // Example: load_tweak_dylib("/var/jb/Library/TweakInject/example.dylib");
    }
    
    return loaded_count;
}

// Example tweak hooks
static void (*orig_sandbox_check)(void);
static void my_sandbox_check_hook(void) {
    os_log_info(OS_LOG_DEFAULT, "[Tweak] sandbox_check hooked - bypassing");
    // Don't call original - bypass sandbox check
}

static int (*orig_access)(const char *path, int amode);
static int my_access_hook(const char *path, int amode) {
    // Bypass file access checks
    os_log_debug(OS_LOG_DEFAULT, "[Tweak] access(%s) bypassed", path);
    return 0; // Success
}

static bool (*orig_file_exists)(const char *path);
static bool my_file_exists_hook(const char *path) {
    // Always report files exist for tweak compatibility
    return true;
}

// Apply common sandbox bypass hooks
static bool apply_sandbox_bypass_hooks(void) {
    os_log_info(OS_LOG_DEFAULT, "[Tweak] Applying sandbox bypass hooks");
    
    // Hook sandbox_check (libSystem.B.dylib)
    void *sandbox_check_sym = dlsym(RTLD_DEFAULT, "sandbox_check");
    if (sandbox_check_sym) {
        ms_hook_function(sandbox_check_sym, my_sandbox_check_hook, (void**)&orig_sandbox_check);
    }
    
    // Hook access()
    void *access_sym = dlsym(RTLD_DEFAULT, "access");
    if (access_sym) {
        ms_hook_function(access_sym, my_access_hook, (void**)&orig_access);
    }
    
    return true;
}

// Apply code signing bypass hooks
static bool apply_codesign_bypass_hooks(void) {
    os_log_info(OS_LOG_DEFAULT, "[Tweak] Applying codesign bypass hooks");
    
    // Hook various CS validation functions
    // These would be implemented based on iOS 17.3.1 specifics
    
    return true;
}

// Initialize tweak system
static bool tweak_init(void) {
    if (!substitute_load()) {
        os_log_warning(OS_LOG_DEFAULT, "[Tweak] Substitute not available, using fallback");
        // Continue without Substitute - use direct hooks
    }
    
    // Apply base hooks
    apply_sandbox_bypass_hooks();
    apply_codesign_bypass_hooks();
    
    // Load user tweaks
    size_t count = load_tweaks_from_directory("/var/jb/Library/TweakInject");
    os_log_info(OS_LOG_DEFAULT, "[Tweak] Loaded %zu tweaks", count);
    
    return true;
}

// Cleanup
static void tweak_cleanup(void) {
    if (g_substitute.handle) {
        dlclose(g_substitute.handle);
        g_substitute.handle = NULL;
        g_substitute.loaded = false;
    }
    os_log_info(OS_LOG_DEFAULT, "[Tweak] Cleanup complete");
}

#endif /* substitute_hook_h */
