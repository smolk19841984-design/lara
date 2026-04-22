// Minimal stub header for libgrabkernel2.
// Real implementations download/extract kernelcache; the stub keeps the app linkable.
#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif

#include <stdbool.h>

#ifdef __OBJC__
bool grab_kernelcache(NSString *outPath);
#else
bool grab_kernelcache(void *outPath);
#endif

