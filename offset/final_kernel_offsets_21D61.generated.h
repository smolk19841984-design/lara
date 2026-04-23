//
//  final_kernel_offsets_21D61.generated.h
//  Generated artifact for iPad8,9 iOS 17.3.1 (21D61)
//
//  Source of truth: offset/verified_offsets_21D61.json
//

#ifndef final_kernel_offsets_21D61_generated_h
#define final_kernel_offsets_21D61_generated_h

#include <stdint.h>

#define KERNEL_BASE 0xFFFFFFF007004000ULL

// P0 targets (runtime-used)
#define KOFFSET_SANDBOX_CHECK 0x02DFE3A8ULL
#define KADDR_SANDBOX_CHECK (KERNEL_BASE + KOFFSET_SANDBOX_CHECK)

#define KOFFSET_MAC_LABEL_UPDATE 0x02E02388ULL
#define KADDR_MAC_LABEL_UPDATE (KERNEL_BASE + KOFFSET_MAC_LABEL_UPDATE)

#define KOFFSET_SANDBOX_EXTENSION_CREATE 0x02E22A0CULL
#define KADDR_SANDBOX_EXTENSION_CREATE (KERNEL_BASE + KOFFSET_SANDBOX_EXTENSION_CREATE)

// cs_enforcement_disable is UNVERIFIED in repo artifacts (string-only evidence).
// Keep disabled by default in generated header.
#define KOFFSET_CS_ENFORCEMENT_DISABLE 0x0ULL
#define KADDR_CS_ENFORCEMENT_DISABLE 0x0ULL

#define KOFFSET_PMAP_IMAGE4_TRUST_CACHES 0x00ABE968ULL
#define KADDR_PMAP_IMAGE4_TRUST_CACHES (KERNEL_BASE + KOFFSET_PMAP_IMAGE4_TRUST_CACHES)

// Kernel symbol/struct resolution (static fallbacks observed in kexploit/offsets.m)
#define KOFFSET_KERNPROC 0x0096B928ULL
#define KADDR_KERNPROC (KERNEL_BASE + KOFFSET_KERNPROC)

#define KOFFSET_ROOTVNODE 0x03213640ULL
#define KADDR_ROOTVNODE (KERNEL_BASE + KOFFSET_ROOTVNODE)

// Canonical proc struct size fallback for build 21D61 (from kexploit/offsets.m)
#define SIZEOF_PROC 0x730ULL

#endif /* final_kernel_offsets_21D61_generated_h */

